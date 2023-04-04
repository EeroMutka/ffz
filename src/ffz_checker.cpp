
// The checker checks if the program is correct, and in doing so,
// computes and caches information about the program, such as which declarations
// identifiers are pointing to, what types do expressions have, constant evaluation, and so on.
// If the c succeeds, the program is valid and should compile with no errors.

#define F_INCLUDE_OS
#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#define TRY(x) { if ((x).ok == false) return ffzOk{false}; }

#define OPT(ptr) ptr

#define ERR(c, node, fmt, ...) { \
	c->error_cb.callback(c->parsers[node->parser_id], node, node->loc, f_aprint(c->alc, fmt, __VA_ARGS__), c->error_cb.userdata); \
	return ffzOk{false}; \
}

//#define CHILD(parent, child_access) _get_child_dbg(ffzNodeInst{ (parent)->child_access, (parent).polymorph }, (parent))
//#define CHILD(parent, child_access) ffzNodeInst{ (parent)->child_access, (parent).polymorph }
#define VALIDATE(x) f_assert(x)

typedef u32 InferFlags;
enum InferFlag {
	// we MUST receive an evaluated constant value.
	// maybe this should be a check the same way `verify_is_type_expression` is instead of an infer flag.
	//InferFlag_RequireConstant = 1 << 0,

	// When statement, the node must not be an expression.
	InferFlag_Statement = 1 << 1,

	// If the checker finds no type, it's okay with this flag. This could be that we're checking a statement
	// (which COULD still get a type, i.e. a procedure call), or that we're just peeking which type
	// an expression WOULD get given an infer target, if at all.

// If the checker finds no type, it's okay with this flag. This can be useful to just peek which type
// an expression WOULD get given an infer target, if at all.
InferFlag_TypeIsNotRequired_ = 1 << 2,

InferFlag_CacheOnlyIfGotType = 1 << 3,

InferFlag_NoTypesMatchCheck = 1 << 4,

// TODO: get rid of this
//InferFlag_TypeMeansDefaultValue = 1 << 5, // `int` will mean "the default value of int" instead of "the type int"

// We only allow undefined values in variable (not parameter) declarations.
InferFlag_AllowUndefinedValues = 1 << 6,
};

// ------------------------------

static bool is_basic_type_size(u32 size) { return size == 1 || size == 2 || size == 4 || size == 8; }
static void print_constant(ffzProject* p, fWriter* w, ffzConstant* constant);
static ffzOk check_node(ffzModule* c, ffzNode* node, OPT(ffzType*) require_type, InferFlags flags);

// ------------------------------

ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value) {
	return f_hash64_ex(enum_type->hash, value);
}

ffzNodeHash ffz_hash_node(ffzNode* node) {
	ffzTypeHash h = node->local_id;
	f_hash64_push(&h, node->parser_id);
	f_hash64_push(&h, node->module_id);
	return h;
}

ffzConstantHash ffz_hash_constant(ffzConstant constant) {
	// The type must be hashed into the constant, because otherwise i.e. `u64(0)` and `false` would have the same hash!
	ffzTypeHash h = constant.type->hash;
	switch (constant.type->tag) {
	case ffzTypeTag_Pointer: { f_trap(); } break;

		//case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: {
		f_hash64_push(&h, ffz_hash_node(constant.data->proc_node));
	} break;

		//case ffzTypeTag_PolyRecord: // fallthrough
	case ffzTypeTag_Record: { f_trap(); } break;

	case ffzTypeTag_Slice: { f_trap(); } break;
	case ffzTypeTag_FixedArray: {
		for (u32 i = 0; i < (u32)constant.type->FixedArray.length; i++) {
			ffzConstantData elem_data = ffz_constant_fixed_array_get(constant, i);
			ffzConstant elem = { &elem_data, constant.type->FixedArray.elem_type };
			f_hash64_push(&h, ffz_hash_constant(elem));
		}
	} break;

	case ffzTypeTag_Module: { f_hash64_push(&h, (u64)constant.data->module->self_id); } break;
	case ffzTypeTag_Type: { f_hash64_push(&h, constant.data->type->hash); } break;
	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Raw: // fallthrough
	case ffzTypeTag_Float: {
		f_hash64_push(&h, constant.data->u64_); // TODO: u128
	} break;
	default: f_trap();
	}
	return h;
}

ffzPolymorphHash ffz_hash_polymorph(ffzPolymorph poly) {
	ffzHash h = ffz_hash_node(poly.poly_def);
	for (uint i = 0; i < poly.parameters.len; i++) {
		f_hash64_push(&h, ffz_hash_constant(poly.parameters[i]));
	}
	return h;
}

u64 ffz_hash_definition_path(ffzDefinitionPath path) {
	u64 hash = f_hash64_str(path.name);
	if (path.parent_scope) f_hash64_push(&hash, ffz_hash_node(path.parent_scope));
	return hash;
}

static ffzConstantData* make_constant(ffzModule* c) {
	// TODO: we should deduplicate constants
	ffzConstantData* constant = f_mem_clone(ffzConstantData{}, c->alc);
	//if (constant == (void*)0x0000020000003a90) f_trap();
	return constant;
}

static ffzConstantData* make_constant_int(ffzModule* c, u64 u64_) {
	ffzConstantData* constant = make_constant(c);
	constant->u64_ = u64_;
	return constant;
}

ffzCheckInfo make_type_constant(ffzModule* c, ffzType* type) {
	ffzCheckInfo out;
	out.type = c->type_type;
	out.constant = make_constant(c);
	out.constant->type = type;
	return out;
}

ffzType* ffz_ground_type(ffzConstantData* constant, ffzType* type) {
	if (type->tag == ffzTypeTag_Type) {
		return constant->type;
	}
	return type;
}

bool ffz_type_is_concrete(ffzType* type) {
	if (type->tag == ffzTypeTag_Type) return false;
	if (type->tag == ffzTypeTag_FixedArray && type->FixedArray.length == -1) return false;
	if (type->tag == ffzTypeTag_Raw) return false;
	//if (type->tag == ffzTypeTag_PolyProc) return false;
	//if (type->tag == ffzTypeTag_PolyRecord) return false;
	if (type->tag == ffzTypeTag_Module) return false;
	return true;
}

// TODO: store this as a flag in ffzType
// hmm... shouldn't all types be comparable for equality?
bool ffz_type_is_comparable_for_equality(ffzType* type) {
	if (ffz_type_is_integer(type->tag)) return true;

	switch (type->tag) {
	case ffzTypeTag_Bool: return true;
	case ffzTypeTag_Pointer: return true;
	case ffzTypeTag_Proc: return true;
	case ffzTypeTag_Enum: return true;
	case ffzTypeTag_Record: {
		return false; // TODO: implement this in the backends
		//if (type->Record.is_union) return false;
		//
		//for (uint i = 0; i < type->record_fields.len; i++) {
		//	if (!ffz_type_can_be_checked_for_equality(type->record_fields[i].type)) return false;
		//}
	} return true;
	
	case ffzTypeTag_FixedArray: {
		return false; // TODO: implement this in the backends
		//return ffz_type_can_be_checked_for_equality(type->FixedArray.elem_type);
	}
	}
	return false;
}

bool ffz_type_is_comparable(ffzType* type) {
	return ffz_type_is_integer(type->tag) || type->tag == ffzTypeTag_Enum || ffz_type_is_float(type->tag);
}

void _write_type(ffzProject* p, fWriter* w, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Invalid: { f_print(w, "<invalid>"); } break;
	case ffzTypeTag_Module: { f_print(w, "<module>"); } break;
	//case ffzTypeTag_PolyProc: { f_print(w, "<poly-proc>"); } break;
	//case ffzTypeTag_PolyRecord: { f_print(w, "<poly-struct>"); } break;
		//case TypeTag_UninstantiatedPolyStruct: { str_print(builder, F_LIT("[uninstantiated polymorphic struct]")); } break;
	case ffzTypeTag_Type: {
		f_print(w, "<type>"); // maybe it'd be good to actually store the type type thing in the type
	} break;
	case ffzTypeTag_Bool: { f_print(w, "bool"); } break;
	case ffzTypeTag_Raw: { f_print(w, "raw"); } break;
	case ffzTypeTag_Pointer: {
		f_print(w, "^");
		_write_type(p, w, type->Pointer.pointer_to);
	} break;
	case ffzTypeTag_DefaultSint: { f_print(w, "int"); } break;
	case ffzTypeTag_DefaultUint: { f_print(w, "uint"); } break;
	case ffzTypeTag_Sint: {
		f_print(w, "s~u32", type->size * 8);
	} break;
	case ffzTypeTag_Uint: {
		f_print(w, "u~u32", type->size * 8);
	} break;
	case ffzTypeTag_Float: {
		f_print(w, "f~u32", type->size * 8);
	} break;
	case ffzTypeTag_Proc: {
		ffzNode* s = type->unique_node;
		fString name = ffz_get_parent_decl_name(s);
		if (name.len > 0) {
			f_prints(w, name);
		}
		else {
			f_print(w, "<anonymous-proc|line:~u32,col:~u32>",
				s->loc.start.line_num, s->loc.start.column_num);
		}

		//if (ffz_get_child_count(s->ProcType.polymorphic_parameters) > 0) {
		//	f_print(w, "[");
		//	for (uint i = 0; i < s.polymorph->parameters.len; i++) {
		//		if (i > 0) f_print(w, ", ");
		//		_write_type(p, w, s.polymorph->parameters[i].type);
		//	}
		//	f_print(w, "]");
		//}
		
		//str_print(builder, F_LIT("proc("));
		//for (uint i = 0; i < type->Proc.in_parameter_types.len; i++) {
		//	if (i != 0) str_print(builder, F_LIT(", "));
		//	_print_type(c, builder, type->Proc.in_parameter_types[i]);
		//}
		//str_print(builder, F_LIT(")"));
		//
		//if (type->Proc.out_param_type) {
		//	str_print(builder, F_LIT(" => "));
		//	_print_type(c, builder, type->Proc.out_param_type);
		//}
	} break;
	case ffzTypeTag_Enum: {
		ffzNode* n = type->unique_node;
		fString name = ffz_get_parent_decl_name(n);
		if (name.len > 0) {
			f_prints(w, name);
		}
		else {
			f_print(w, "[anonymous enum defined at line:~u32, col:~u32]", n->loc.start.line_num, n->loc.start.column_num);
		}
	} break;
	case ffzTypeTag_Record: {
		ffzNodeRecord* n = type->unique_node;
		fString name = ffz_get_parent_decl_name(n);
		if (name.len > 0) {
			f_prints(w, name);
		}
		else {
			f_print(w, "[anonymous ~c defined at line:~u32, col:~u32]",
				n->Record.is_union ? "union" : "struct", n->loc.start.line_num, n->loc.start.column_num);
		}

		//if (ffz_get_child_count(n->Record.polymorphic_parameters) > 0) {
		//	f_print(w, "[");
		//	
		//	for (uint i = 0; i < n.polymorph->parameters.len; i++) {
		//		if (i > 0) f_print(w, ", ");
		//		print_constant(p, w, n.polymorph->parameters[i]);
		//	}
		//	f_print(w, "]");
		//}
	} break;
	case ffzTypeTag_Slice: {
		f_print(w, "[]");
		_write_type(p, w, type->Slice.elem_type);
	} break;
	case ffzTypeTag_String: {
		f_print(w, "string");
	} break;
	case ffzTypeTag_FixedArray: {
		f_print(w, "[~i32]", type->FixedArray.length);
		_write_type(p, w, type->FixedArray.elem_type);
	} break;
	default: f_assert(false);
	}
}

static void print_constant(ffzProject* p, fWriter* w, ffzConstant constant) {
	if (constant.type->tag == ffzTypeTag_Type) {
		_write_type(p, w, constant.data->type);
	}
	else {
		f_trap();
	}
}

fString ffz_constant_to_string(ffzProject* p, ffzConstant constant) {
	fStringBuilder builder;
	f_init_string_builder(&builder, p->persistent_allocator);
	print_constant(p, builder.w, constant);
	return builder.buffer.slice;
}

fString ffz_type_to_string(ffzProject* p, ffzType* type) {
	fStringBuilder builder; f_init_string_builder(&builder, p->persistent_allocator);
	_write_type(p, builder.w, type);
	return builder.buffer.slice;
}

ffzNode* ffz_get_scope(ffzNode* node) {
	for (node = node->parent; node; node = node->parent) {
		// or hmm.. what if we have a procedure {} and we're recursing into the procedure type parameters.
		// in the parent, we need to know the type of the lhs first before knowing if it's a procedure scope or not.
		// So a procedure type should be able to be checked independently. I guess the procedure body should then add the definitions from the proc type as well.
		// so maybe before calling check_node() on the procedure body, call add_definitions()

		if (node->kind == ffzNodeKind_Scope) return node;

		if (node->kind == ffzNodeKind_PostCurlyBrackets &&
			node->checked.type && node->checked.type->tag == ffzTypeTag_Proc) return node;

		if (node->kind == ffzNodeKind_Record) return node;
	}
	f_trap();
	return NULL;
}

bool ffz_is_executable_scope(fOpt(ffzNode*) node) {
	if (node == NULL) return false;
	if (node->parent == NULL) return false; // root scope?

	if (node->kind == ffzNodeKind_Scope) {
		ffzNode* parent_scope = ffz_get_scope(node);
		return ffz_is_executable_scope(parent_scope);
	}
	
	if (node->kind == ffzNodeKind_PostCurlyBrackets &&
		node->checked.type && node->checked.type->tag == ffzTypeTag_Proc) return true;

	return false;
}

bool ffz_decl_is_local_variable(ffzNodeOpDeclare* decl) {
	fOpt(ffzNode*) scope = ffz_get_scope(decl);
	return ffz_is_executable_scope(scope) && !decl->Op.left->Identifier.is_constant;
}

bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl) {
	if (decl->Op.left->Identifier.is_constant) return false;
	return decl->parent->parent == NULL;
}

fOpt(ffzNodeIdentifier*) ffz_find_definition_in_scope(ffzProject* p, ffzNode* scope, fString name) {
	ffzModule* m = p->checkers[scope->module_id];
	ffzDefinitionPath def_path = { scope, name };

	ffzNodeIdentifier** def = f_map64_get(&m->definition_map, ffz_hash_definition_path(def_path));
	return def ? *def : NULL;
}

bool ffz_constant_is_zero(ffzConstantData constant) {
	u8 zeroes[sizeof(ffzConstantData)] = {};
	return memcmp(&constant, zeroes, sizeof(ffzConstantData)) == 0;
}

// hmm. TODO
//ffzConstantData* ffz_zero_value_constant(ffzModule* c, ffzType* t) {
//	const static ffzConstantData empty = {};
//	return (ffzConstantData*)&empty;
//}

ffzFieldHash ffz_hash_field(ffzType* type, fString member_name) {
	return f_hash64_ex(type->hash, f_hash64_str(member_name));
}

static ffzOk add_fields_to_field_from_name_map(ffzModule* c, ffzType* root_type, ffzType* parent_type, u32 offset_from_root = 0) {
	for (u32 i = 0; i < parent_type->record_fields.len; i++) {
		ffzField* field = &parent_type->record_fields[i];
		ffzTypeRecordFieldUse* field_use = f_mem_clone(ffzTypeRecordFieldUse{ field->type, offset_from_root + field->offset }, c->alc);

		auto insertion = f_map64_insert(&c->field_from_name_map, ffz_hash_field(root_type, field->name), field_use, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			ERR(c, field->decl, "`~s` is already declared before inside (TODO: print struct name) (TODO: print line)", field->name);
		}

		if (field->decl) {
			f_trap();//if (ffz_get_tag(c->project, field->decl, ffzKeyword_using)) {
			//	TRY(add_fields_to_field_from_name_map(c, root_type, field->type));
			//}
		}
	}
	return { true };
}

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out) {
	ffzModule* c = p->checkers[type->checker_id];
	if (ffzTypeRecordFieldUse** result = f_map64_get(&c->field_from_name_map, ffz_hash_field(type, name))) {
		*out = **result;
		return true;
	}
	return false;
}

static ffzOk verify_is_type_expression(ffzModule* c, ffzNode* node) {
	if (node->checked.type->tag != ffzTypeTag_Type) ERR(c, node, "Expected a type, but got a value.");
	return FFZ_OK;
}

static ffzOk verify_is_constant(ffzModule* c, ffzNode* node) {
	if (node->checked.constant == NULL) ERR(c, node, "Expression is not constant, but constant was expected.");
	return FFZ_OK;
}

// if this returns true, its ok to bit-cast between the types
static bool type_is_a_bit_by_bit(ffzProject* p, ffzType* src, ffzType* target) {
	if (src->tag == ffzTypeTag_DefaultUint && target->tag == ffzTypeTag_DefaultSint) return true; // allow implicit cast from uint -> int
	if (target->tag == ffzTypeTag_Raw) return true; // everything can cast to raw
	
	if (src->tag == ffzTypeTag_Pointer && target->tag == ffzTypeTag_Pointer) {
		// i.e. allow casting from ^int to ^raw
		return type_is_a_bit_by_bit(p, src->Pointer.pointer_to, target->Pointer.pointer_to);
	}

	return src->hash == target->hash;
}

static ffzOk check_types_match(ffzModule* c, ffzNode* node, ffzType* received, ffzType* expected, const char* message) {
	if (!type_is_a_bit_by_bit(c->project, received, expected)) {
		ERR(c, node, "~c\n    received: ~s\n    expected: ~s",
			message, ffz_type_to_string(c->project, received), ffz_type_to_string(c->project, expected));
	}
	return { true };
}

static ffzOk error_not_an_expression(ffzModule* c, ffzNode* node) {
	ERR(c, node, "Expected an expression, but got a statement or a procedure call with no return value.");
}

bool ffz_find_field_by_name(fSlice(ffzField) fields, fString name, u32* out_index) {
	for (u32 i = 0; i < fields.len; i++) {
		if (fields[i].name == name) {
			*out_index = i;
			return true;
		}
	}
	return false;
}

void ffz_get_arguments_flat(ffzNode* arg_list, fSlice(ffzField) fields, fSlice(ffzNode*)* out_arguments, fAllocator* alc) {
	*out_arguments = f_make_slice<ffzNode*>(fields.len, {}, alc);

	u32 i = 0;
	for FFZ_EACH_CHILD(arg, arg_list) {
		ffzNode* arg_value = arg;
		
		if (arg->kind == ffzNodeKind_Declare) {
			arg_value = arg->Op.right;
			fString name = ffz_decl_get_name(arg);
			ffz_find_field_by_name(fields, name, &i);
		}

		(*out_arguments)[i] = arg_value;
		i++;
	}
}

//static ffzOk check_argument_list(ffzModule* c, ffzNode* node, fSlice(ffzField) fields, fOpt(ffzCheckedInst*) record_literal) {
//	bool all_fields_are_constant = true;
//	fSlice(ffzConstantData) field_constants;
//	if (record_literal) field_constants = f_make_slice_garbage<ffzConstantData>(fields.len, c->alc);
//
//	fSlice(bool) field_is_given_a_value = f_make_slice<bool>(fields.len, false, c->alc);
//
//	bool has_used_named_argument = false;
//	u32 i = 0;
//	for FFZ_EACH_CHILD_INST(arg, inst) {
//		ffzNodeInst arg_value = arg;
//
//		if (arg->kind == ffzNodeKind_Declare) {
//			has_used_named_argument = true;
//			arg_value = CHILD(arg, Op.right);
//			fString name = ffz_decl_get_name(arg);
//
//			if (!ffz_find_field_by_name(fields, name, &i)) {
//				ERR(c, arg, "Parameter named \"~s\" does not exist.", name);
//			}
//			
//			if (field_is_given_a_value[i]) ERR(c, arg, "A value has been already given for parameter \"~s\".", name);
//		}
//		else if (has_used_named_argument) ERR(c, arg, "Using an unnamed argument after a named argument is not allowed.");
//
//		ffzCheckedInst chk;
//		TRY(check_node(c, arg_value, fields[i].type, 0, &chk));
//
//		if (record_literal) {
//			if (chk.const_val) field_constants[i] = *chk.const_val;
//			else all_fields_are_constant = false;
//		}
//
//		field_is_given_a_value[i] = true;
//		i++;
//	}
//
//	for (uint i = 0; i < fields.len; i++) {
//		if (!field_is_given_a_value[i]) {
//			if (!fields[i].has_default_value) {
//				ERR(c, inst, "An argument is missing for \"~s\".", fields[i].name);
//			}
//			if (record_literal) {
//				field_constants[i] = fields[i].default_value;
//			}
//		}
//	}
//
//	if (record_literal && all_fields_are_constant) {
//		record_literal->const_val = make_constant(c);
//		record_literal->const_val->record_fields = field_constants;
//	}
//
//	return FFZ_OK;
//}

//static ffzOk check_procedure_call(ffzModule* c, ffzNodeOpInst inst, OPT(ffzType*) require_type, InferFlags flags, OPT(ffzType*)* out_type) {
//	ffzNodeInst left = CHILD(inst, Op.left);
//	ffzCheckedInst left_chk;
//	TRY(check_node(c, left, NULL, 0, &left_chk));
//
//	ffzType* type = left_chk.type;
//	if (left_chk.type->tag != ffzTypeTag_Proc) {
//		ERR(c, left, "Attempted to call a non-procedure (~s)", ffz_type_to_string(c->project, left_chk.type));
//	}
//
//	*out_type = type->Proc.return_type;
//	TRY(check_argument_list(c, inst, type->Proc.in_params, NULL));
//	return { true };
//}

static bool uint_is_subtype_of(ffzType* type, ffzType* subtype_of) {
	if (ffz_type_is_unsigned_integer(type->tag) && ffz_type_is_unsigned_integer(subtype_of->tag) && type->size <= subtype_of->size) return true;
	return false;
}

//static ffzOk check_two_sided(ffzModule* c, ffzNodeInst left, ffzNodeInst right, OPT(ffzType*)* out_type) {
//	ffzCheckedInst left_chk, right_chk;
//
//	// Infer expressions, such as  `x: u32(1) + 50`  or  x: `2 * u32(552)`
//	
//	InferFlags child_flags = InferFlag_TypeIsNotRequired_ | InferFlag_CacheOnlyIfGotType;
//
//	for (int i = 0; i < 2; i++) {
//		TRY(check_node(c, left, NULL, child_flags, &left_chk));
//		TRY(check_node(c, right, NULL, child_flags, &right_chk));
//		if (left_chk.type && right_chk.type) break;
//		
//		child_flags = 0;
//		if (!left_chk.type && right_chk.type) {
//			TRY(check_node(c, left, right_chk.type, child_flags, &left_chk));
//			break;
//		}
//		else if (!right_chk.type && left_chk.type) {
//			TRY(check_node(c, right, left_chk.type, child_flags, &right_chk));
//			break;
//		}
//		continue;
//	}
//
//	OPT(ffzType*) result = NULL;
//	if (right_chk.type && left_chk.type) {
//		if (type_is_a_bit_by_bit(c->project, left_chk.type, right_chk.type))      result = right_chk.type;
//		else if (type_is_a_bit_by_bit(c->project, right_chk.type, left_chk.type)) result = left_chk.type;
//		else {
//			ERR(c, left->parent, "Types do not match.\n    left:    ~s\n    right:   ~s",
//				ffz_type_to_string(c->project, left_chk.type), ffz_type_to_string(c->project, right_chk.type));
//		}
//	}
//	*out_type = result;
//	return { true };
//}

u32 ffz_get_encoded_constant_size(ffzType* type) {
	return ffz_type_is_integer(type->tag) ? type->size : sizeof(ffzConstantData);
}

ffzConstantData ffz_constant_fixed_array_get(ffzConstant array, u32 index) {
	u32 elem_size = ffz_get_encoded_constant_size(array.type->FixedArray.elem_type);
	ffzConstantData result = {};
	if (array.data->fixed_array_elems) memcpy(&result, (u8*)array.data->fixed_array_elems + index*elem_size, elem_size);
	return result;
}

ffzOk add_definitions_to_scope(ffzModule* c, fOpt(ffzNode*) scope, ffzNode* from) {
	for FFZ_EACH_CHILD(n, from) {
		if (n->kind == ffzNodeKind_Declare) {
			
			fString name = ffz_decl_get_name(n);

			for (ffzNode* test_scope = scope; test_scope; test_scope = test_scope->parent) {
				ffzDefinitionPath path = { test_scope, name };
				if (ffzNodeIdentifier** existing = f_map64_get(&c->definition_map, ffz_hash_definition_path(path))) {
					ERR(c, n, "`~s` is already declared before (at line: ~u32)", name, (*existing)->loc.start.line_num);
				}
			}

			ffzDefinitionPath path = { scope, name };
			f_map64_insert(&c->definition_map, ffz_hash_definition_path(path), n->Op.left, fMapInsert_DoNotOverride);
		}
	}
	return { true };
}

#if 0
ffzOk ffz_instanceless_check(ffzModule* c, ffzNode* node) {
	//ffzCheckerScope scope;
	//
	//if (new_scope) {
	//	// when root level, we want the scope node to be NULL, instead of the parser root node!!!
	//	// This is so that declarations across multiple files/parsers will be placed in equal scope.
	//	scope = node->parent ? node : NULL;
	//	scope.parent = c->current_scope;
	//	c->current_scope = &scope;
	//}

	if (node->kind == ffzNodeKind_Record) {
		//TRY(_ffz_add_possible_definitions(c, node->Record.polymorphic_parameters));
	}
	else if (node->kind == ffzNodeKind_ProcType) {
		//TRY(_ffz_add_possible_definitions(c, node->ProcType.polymorphic_parameters));
		//if (node->ProcType.out_parameter) TRY(_ffz_add_possible_definition(c, node->ProcType.out_parameter));
	}
	else if (node->kind == ffzNodeKind_PostCurlyBrackets) {
		// If the procedure type is anonymous, add the parameters to this scope. Otherwise, the programmer must use the `in` and `out` keywords to access parameters.
		//if (node->Op.left->kind == ffzNodeKind_ProcType) {
		//	ffz_instanceless_check(c, node->Op.left);
		//	//TRY(_ffz_add_possible_definitions(c, derived->left));
		//	//OPT(ffzNode*) out_parameter = AS(derived->left,ProcType)->out_parameter; // :AddOutParamDeclaration
		//	//if (out_parameter) TRY(_ffz_add_possible_definition(c, out_parameter));
		//}
	}
	else if (node->kind == ffzNodeKind_For) {
		if (node->For.header_stmts[0]) { // e.g. `for i: 0, ...`
			TRY(_ffz_add_possible_definition(c, node->For.header_stmts[0]));
		}
	}

	for FFZ_EACH_CHILD(n, node) {
		TRY(_ffz_add_possible_definition(c, n));
	}

	if (recursive) {
		for FFZ_EACH_CHILD(n, node) {
			TRY(ffz_instanceless_check(c, n, recursive));
		}
	}

	//if (new_scope) {
	//	c->current_scope = c->current_scope->parent;
	//}
	return { true };
}
#endif

u32 get_alignment(ffzType* type, u32 pointer_size) {
	switch (type->tag) {
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Pointer: // fallthrough
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Slice: return pointer_size;
	case ffzTypeTag_Record: return type->align; // alignment is computed at :ComputeRecordAlignment
	case ffzTypeTag_FixedArray: return get_alignment(type->FixedArray.elem_type, pointer_size);
	}
	return type->size;
}

ffzTypeHash ffz_hash_type(ffzType* type) {
	ffzTypeHash h = f_hash64(type->tag);
	switch (type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Undefined: break;
	case ffzTypeTag_Module: break;
	case ffzTypeTag_PolyExpr: break;
	case ffzTypeTag_Type: break;
	case ffzTypeTag_String: break;

	case ffzTypeTag_Pointer: { f_hash64_push(&h, ffz_hash_type(type->Pointer.pointer_to)); } break;

	//case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: { f_hash64_push(&h, ffz_hash_node(type->unique_node)); } break;
	case ffzTypeTag_Enum: { f_hash64_push(&h, ffz_hash_node(type->unique_node)); } break; // :EnumFieldsShouldNotContributeToTypeHash

	//case ffzTypeTag_PolyRecord: // fallthrough
	case ffzTypeTag_Record: { f_hash64_push(&h, ffz_hash_node(type->unique_node)); } break;

	case ffzTypeTag_Slice: { f_hash64_push(&h, ffz_hash_type(type->Slice.elem_type)); } break;
	case ffzTypeTag_FixedArray: {
		f_hash64_push(&h, ffz_hash_type(type->FixedArray.elem_type));
		f_hash64_push(&h, type->FixedArray.length);
	} break;

	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Float: {
		// Note: we don't want record types to hash in the size of the type, because of :delayed_check_record
		f_hash64_push(&h, type->size);
		break;
	}
	default: f_trap();
	}
	return h;
}

ffzType* ffz_make_type(ffzModule* c, ffzType type_desc) {
	//F_HITS(_c, 35);
	//F_HITS(_c1, 416);
	type_desc.checker_id = c->self_id;
	type_desc.hash = ffz_hash_type(&type_desc);
	//if (type_desc.hash == 16688289346569842202) f_trap();
	//if (type_desc.hash == 14042532921040479959) f_trap();

	auto entry = f_map64_insert(&c->type_from_hash, type_desc.hash, (ffzType*)0, fMapInsert_DoNotOverride);
	if (entry.added) {
		ffzType* type_ptr = f_mem_clone(type_desc, c->alc);
		type_ptr->align = get_alignment(type_ptr, c->project->pointer_size); // cache the alignment
		*entry._unstable_ptr = type_ptr;
	}
	
	return *entry._unstable_ptr;
}

ffzType* ffz_make_type_ptr(ffzModule* c, ffzType* pointer_to) {
	ffzType type = { ffzTypeTag_Pointer, c->project->pointer_size };
	type.Pointer.pointer_to = pointer_to;
	return ffz_make_type(c, type);
}

OPT(ffzType*) ffz_builtin_type(ffzModule* c, ffzKeyword keyword) {
	return c->builtin_types[keyword];
}

struct ffzRecordBuilder {
	ffzModule* checker;
	ffzType* record;
	fArray(ffzField) fields;
};

static ffzRecordBuilder ffz_record_builder_init(ffzModule* c, ffzType* record, uint fields_cap) {
	f_assert(record->size == 0);
	return { c, record, f_array_make_cap<ffzField>(fields_cap, c->alc) };
}

static void ffz_record_builder_add_field(ffzRecordBuilder* b, fString name, ffzType* field_type,
	fOpt(ffzConstantData*) default_value, fOpt(ffzNodeOpDeclare*) decl)
{
	bool is_union = b->record->tag == ffzTypeTag_Record && b->record->Record.is_union;

	ffzField field;
	field.name = name;
	field.offset = is_union ? 0 : F_ALIGN_UP_POW2(b->record->size, field_type->align);
	field.type = field_type;
	field.decl = decl;
	field.has_default_value = default_value != NULL;
	field.default_value = default_value != NULL ? *default_value : ffzConstantData{};
	f_array_push(&b->fields, field);

	// the alignment of a record is that of the largest field  :ComputeRecordAlignment
	b->record->align = F_MAX(b->record->align, field_type->align);
	b->record->size = field.offset + field_type->size;
}

static ffzOk ffz_record_builder_finish(ffzRecordBuilder* b) {
	b->record->record_fields = b->fields.slice;
	b->record->size = F_ALIGN_UP_POW2(b->record->size, b->record->align); // Align the size up to the largest member alignment
	TRY(add_fields_to_field_from_name_map(b->checker, b->record, b->record));
	return FFZ_OK;
}

ffzType* ffz_make_type_slice(ffzModule* c, ffzType* elem_type) {
	ffzType type = { ffzTypeTag_Slice };
	type.Slice.elem_type = elem_type;
	ffzType* out = ffz_make_type(c, type);

	if (out->record_fields.len == 0) { // this type hasn't been made before
		ffzConstantData zero = {};
		ffzRecordBuilder b = ffz_record_builder_init(c, out, 2);
		ffz_record_builder_add_field(&b, F_LIT("ptr"), ffz_make_type_ptr(c, elem_type), &zero, {});
		ffz_record_builder_add_field(&b, F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), &zero, {});
		ffz_record_builder_finish(&b);
	}
	return out;
}

ffzType* ffz_make_type_fixed_array(ffzModule* c, ffzType* elem_type, s32 length) {
	ffzType array_type = { ffzTypeTag_FixedArray };
	if (length >= 0) array_type.size = (u32)length * elem_type->size;

	array_type.FixedArray.elem_type = elem_type;
	array_type.FixedArray.length = length;
	ffzType* out = ffz_make_type(c, array_type);

	if (length > 0 && length <= 4 && out->record_fields.len == 0) { // this type hasn't been made before
		const static fString fields[] = { F_LIT("x"), F_LIT("y"), F_LIT("z"), F_LIT("w") };
		
		// We can't use the ffzRecordBuilder here, because we don't want it to build the size of the type.
		out->record_fields = f_make_slice_garbage<ffzField>(length, c->alc);
		for (u32 i = 0; i < (u32)length; i++) {
			out->record_fields[i] = { fields[i], {}, {}, false, elem_type->size * i, elem_type };
		}
		add_fields_to_field_from_name_map(c, out, out, 0);
	}
	return out;
}

//static ffzNodeOpInst code_stmt_get_parent_proc(ffzProject* p, ffzNode* node, ffzType** out_type) {
//	ffzNodeInst parent = inst;
//	parent = parent->parent;
//	for (; parent; parent = parent->parent) {
//		if (parent->kind == ffzNodeKind_PostCurlyBrackets) {
//			ffzType* type = ffz_get_type(p, parent);
//
//			// Kind of a hack, but since we can call this function from inside the checker,
//			// the parent expression type might not have been cached yet. But procedures are delay-checked so 
//			// their types should be available.
//			if (type && type->tag == ffzTypeTag_Proc) {
//				*out_type = type;
//				return parent;
//			}
//		}
//	}
//	f_assert(false);
//	return {};
//}

static bool type_can_be_casted_to(ffzProject* p, ffzType* from, ffzType* to) {
	// allow pointer-sized-int/ptr <-> pointer-sized-int/ptr
	if ((ffz_type_is_pointer_sized_integer(p, from) || ffz_type_is_pointer_ish(from->tag)) &&
		(ffz_type_is_pointer_sized_integer(p, to) || ffz_type_is_pointer_ish(to->tag))) return true;

	if (ffz_type_is_slice_ish(from->tag) && ffz_type_is_slice_ish(to->tag)) return true;
	
	// allow int/float <-> int/float
	if ((ffz_type_is_integer(from->tag) || ffz_type_is_float(from->tag)) &&
		(ffz_type_is_integer(to->tag) || ffz_type_is_float(to->tag))) return true;

	return false;
}

//static ffzOk check_post_round_brackets(ffzModule* c, ffzNode* node, ffzType* require_type, InferFlags flags) {
//	ffzNode* left = node->Op.left;
//	bool fall = true;
//	if (left->kind == ffzNodeKind_Keyword) {
//		ffzKeyword keyword = left->Keyword.keyword;
//		if (ffz_keyword_is_bitwise_op(keyword)) {
//			if (ffz_get_child_count(node) != (keyword == ffzKeyword_bit_not ? 1 : 2)) {
//				ERR(c, node, "Incorrect number of arguments to a bitwise operation.");
//			}
//			
//			ffzNode* first = ffz_get_child(node, 0);
//			if (keyword == ffzKeyword_bit_not) {
//				TRY(check_node(c, first, require_type, flags));
//				node->checked.type = first->checked.type;
//			}
//			else {
//				ffzNodeInst second = ffz_get_child_inst(inst, 1);
//				TRY(check_two_sided(c, first, second, &result->type));
//			}
//
//			if (result->type && !is_basic_type_size(result->type->size)) {
//				ERR(c, inst, "bitwise operations only allow sizes of 1, 2, 4 or 8; Received: ~u32", result->type->size);
//			}
//
//			fall = false;
//		}
//		else if (keyword == ffzKeyword_size_of || keyword == ffzKeyword_align_of) {
//			if (ffz_get_child_count(inst) != 1) {
//				ERR(c, inst, "Incorrect number of arguments to ~s.", ffz_keyword_to_string(keyword));
//			}
//
//			ffzCheckedInst chk;
//			ffzNodeInst first = ffz_get_child_inst(inst, 0);
//			TRY(check_node(c, first, NULL, 0, &chk));
//			ffzType* type = _ffz_ground_type(chk);
//			
//			result->type = ffz_builtin_type(c, ffzKeyword_uint);
//			result->const_val = make_constant_int(c, keyword == ffzKeyword_align_of ? type->align : type->size);
//			fall = false;
//		}
//		else if (keyword == ffzKeyword_import) {
//			result->type = c->module_type;
//			result->const_val = make_constant(c);
//
//			ffzModule* node_module = ffz_checker_from_inst(c->project, inst);
//			result->const_val->module = *f_map64_get(&node_module->imported_modules, inst->id.global_id);
//			fall = false;
//		}
//	}
//	if (fall) {
//		ffzCheckedInst left_chk;
//		TRY(check_node(c, left, NULL, 0, &left_chk));
//
//		if (left_chk.type->tag == ffzTypeTag_Type) {
//			// ffzType casting
//			result->type = left_chk.const_val->type;
//			if (ffz_get_child_count(inst) != 1) ERR(c, inst, "Incorrect number of arguments in type initializer.");
//
//			ffzNodeInst arg = ffz_get_child_inst(inst, 0);
//			ffzCheckedInst chk;
//
//			// check the expression, but do not enforce the type inference, as the type inference rules are
//			// more strict than a manual cast. For example, an integer cannot implicitly cast to a pointer, but when inside a cast it can.
//			
//			TRY(check_node(c, arg, result->type, InferFlag_NoTypesMatchCheck, &chk));
//			f_assert(chk.type); //if (chk.type == NULL) ERR(c, inst, "Invalid cast.");
//
//			bool is_undefined = chk.type->tag == ffzTypeTag_Type && chk.const_val->type->tag == ffzTypeTag_Undefined;
//			if (!(flags & InferFlag_AllowUndefinedValues) && is_undefined) {
//				ERR(c, arg, "Invalid place for an undefined value. Undefined values are only allowed in variable declarations.");
//			}
//			
//			if (!is_undefined && !ffz_type_is_pointer_ish(result->type->tag) && !ffz_type_is_pointer_ish(chk.type->tag)) {
//				// the following shouldn't be allowed:
//				// #foo: false
//				// #bar: uint(&foo)
//				// This is because given a constant integer, we want to be able to trivially ask what its value is.
//				result->const_val = chk.const_val;
//			}
//
//			if (!is_undefined && !type_can_be_casted_to(c->project, chk.type, result->type)) {
//				TRY(check_types_match(c, inst, chk.type, result->type, "The received type cannot be casted to the expected type:"));
//			}
//		}
//		else {
//			check_procedure_call(c, inst, require_type, flags, &result->type);
//		}
//	}
//	return FFZ_OK;
//}

//static ffzOk check_post_curly_brackets(ffzModule* c, ffzNodeInst inst, OPT(ffzType*) require_type, InferFlags flags, bool* delayed_check_proc, ffzCheckedInst* result) {
//	ffzNodeInst left = CHILD(inst, Op.left);
//
//	ffzCheckedInst left_chk;
//	TRY(check_node(c, left, NULL, 0, &left_chk));
//	TRY(verify_is_type_expression(c, inst, left_chk));
//	
//	// if the left type is PolyProc type and we're currently instantiating this procedure,
//	// we should also instantiate the proc type!
//	// i.e.
//	// #AdderProc: proc[T](a: T, b: T)
//	// #adder: AdderProc { dbgbreak }
//	// adder[int](50, 60)
//	//
//	if (left_chk.const_val->type->tag == ffzTypeTag_PolyProc &&
//		(inst.polymorph && inst.polymorph->node == inst))
//	{
//		ffzPolymorph poly = {};
//		poly.checker = c;
//		poly = left_chk.const_val->type->unique_node;
//		poly.parameters = inst.polymorph->parameters;
//		
//		// @copypaste
//		poly.hash = ffz_hash_poly(poly);
//		auto entry = f_map64_insert(&c->poly_from_hash, poly.hash, (ffzPolymorph*)0, fMapInsert_DoNotOverride);
//		if (entry.added) {
//			*entry._unstable_ptr = f_mem_clone(poly, c->alc);
//		}
//		ffzPolymorph* poly_dedup = *entry._unstable_ptr;
//		
//		f_map64_insert(&c->poly_instantiation_sites, ffz_hash_node_inst(inst), poly_dedup);
//		TRY(check_node(c, ffzNodeInst{ poly, poly_dedup }, NULL, 0, &left_chk));
//	}
//
//	f_assert(left_chk.type->tag == ffzTypeTag_Type);
//	result->type = left_chk.const_val->type;
//
//	if (result->type->tag == ffzTypeTag_Proc || result->type->tag == ffzTypeTag_PolyProc) {
//		result->const_val = make_constant(c);
//		result->const_val->proc_node = inst;
//		if (result->type->tag != ffzTypeTag_PolyProc) {
//			*delayed_check_proc = true;
//		}
//	}
//	else if (/*result->type->tag == ffzTypeTag_Slice || */result->type->tag == ffzTypeTag_FixedArray) {
//		// Array initialization
//		ffzType* elem_type = result->type->tag == ffzTypeTag_Slice ? result->type->Slice.elem_type : result->type->FixedArray.elem_type;
//
//		fArray(ffzCheckedInst) elems_chk = f_array_make<ffzCheckedInst>(f_temp_alc());
//		bool all_elems_are_constant = true;
//
//		for FFZ_EACH_CHILD_INST(n, inst) {
//			ffzCheckedInst chk;
//			TRY(check_node(c, n, elem_type, 0, &chk));
//			f_array_push(&elems_chk, chk);
//			all_elems_are_constant = all_elems_are_constant && chk.const_val;
//		}
//
//		if (result->type->tag == ffzTypeTag_FixedArray) {
//			s32 expected = result->type->FixedArray.length;
//			if (expected < 0) { // make a new type if [?]
//				result->type = ffz_make_type_fixed_array(c, elem_type, (s32)elems_chk.len);
//			}
//			else if (elems_chk.len != expected) {
//				ERR(c, inst, "Incorrect number of array initializer arguments. Expected ~u32, got ~u32", expected, (u32)elems_chk.len);
//			}
//
//			if (all_elems_are_constant) {
//				u32 elem_size = ffz_get_encoded_constant_size(elem_type);
//				void* ptr = f_mem_alloc(elem_size * elems_chk.len, c->alc);
//				for (uint i = 0; i < elems_chk.len; i++) {
//					memcpy((u8*)ptr + elem_size * i, elems_chk[i].const_val, elem_size);
//				}
//				result->const_val = make_constant(c);
//				result->const_val->fixed_array_elems = ptr;
//			}
//		}
//	}
//	else if (result->type->tag == ffzTypeTag_Record || ffz_type_is_slice_ish(result->type->tag)) {
//		ffzType* type = result->type;
//		if (result->type->tag == ffzTypeTag_Record && type->Record.is_union) {
//			ERR(c, inst, "Union initialization with {} is not currently supported.");
//		}
//		
//		// TODO: see what happens if you try to declare normally `123: 5215`
//		TRY(check_argument_list(c, inst, type->record_fields, result));
//	}
//	else {
//		ERR(c, inst, "{}-initializer is not allowed for `~s`.", ffz_type_to_string(c->project, result->type));
//	}
//	return FFZ_OK;
//}

// maybe we should let the visitor return a break / recurse code to control the tree visit
// TODO: recursive walker
//static void ffz_walk(ffzNode* node, void(*visitor)(ffzNode* node, void* userdata), void* userdata) {
//
//}

static void ffz_deep_copy(ffzModule* c, fOpt(ffzNode*)* p_node) {
	if (*p_node == NULL) return;

	ffzNode* new_node = f_mem_clone(**p_node, c->alc);

	ffzNode** link_to_next = &new_node->first_child;
	for (ffzNode* child = new_node->first_child; child; child = child->next) {

		f_assert(child == *link_to_next);
		ffz_deep_copy(c, link_to_next);
		child->parent = new_node;

		link_to_next = &child->next;
	}
	
	if (ffz_node_is_operator(new_node->kind)) {
		ffz_deep_copy(c, &new_node->Op.left);
		ffz_deep_copy(c, &new_node->Op.right);
	}
	else switch (new_node->kind) {
	case ffzNodeKind_Blank: break;
	case ffzNodeKind_Identifier: break;
	case ffzNodeKind_PolyExpr: {
		ffz_deep_copy(c, &new_node->PolyExpr.expr);
	} break;
	case ffzNodeKind_Keyword: break;
	case ffzNodeKind_ThisValueDot: break;
	case ffzNodeKind_ProcType: {
		ffz_deep_copy(c, &new_node->ProcType.out_parameter);
	} break;
	case ffzNodeKind_Record: break;
	case ffzNodeKind_Enum: break;
	case ffzNodeKind_Return: {
		ffz_deep_copy(c, &new_node->Return.value);
	} break;
	case ffzNodeKind_If: {
		ffz_deep_copy(c, &new_node->If.condition);
		ffz_deep_copy(c, &new_node->If.true_scope);
		ffz_deep_copy(c, &new_node->If.else_scope);
	} break;
	case ffzNodeKind_For: {
		for (int i=0; i<3; i++) ffz_deep_copy(c, &new_node->For.header_stmts[i]);
		ffz_deep_copy(c, &new_node->For.scope);
	} break;
	case ffzNodeKind_Scope: break;
	case ffzNodeKind_IntLiteral: break;
	case ffzNodeKind_StringLiteral: break;
	case ffzNodeKind_FloatLiteral: break;
	default: f_trap();
	}

	*p_node = new_node;
}

static ffzOk check_post_square_brackets(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {

	TRY(check_node(c, node->Op.left, NULL, 0));

	ffzCheckInfo left_chk = node->Op.left->checked;
	if (left_chk.type->tag == ffzTypeTag_Type && left_chk.constant->type->tag == ffzTypeTag_PolyExpr) {

		// so per node, should we store the polymorph source index?

		fArray(ffzConstant) params = f_array_make<ffzConstant>(c->alc);

		for FFZ_EACH_CHILD(arg, node) {
			TRY(check_node(c, arg, NULL, 0));
			TRY(verify_is_constant(c, arg));
			f_array_push(&params, ffzConstant{ arg->checked.constant, arg->checked.type });
		}

		ffzPolymorph poly = {};
		poly.poly_def = left_chk.constant->type->unique_node;
		poly.parameters = params.slice;

		ffzPolymorphHash hash = ffz_hash_polymorph(poly);
		auto entry = f_map64_insert(&c->poly_from_hash, hash, (ffzPolymorphID)0, fMapInsert_DoNotOverride);
		if (entry.added) {
			*entry._unstable_ptr = (ffzPolymorphID)c->polymorphs.len;
			f_array_push(&c->polymorphs, poly);
		}
		
		ffzNode* poly_def_parent = poly.poly_def->parent;

		ffzPolymorphID poly_id = *entry._unstable_ptr;
		
		// Deep copy the poly-def node into a global declaration, then replace this post-square-brackets node with an identifier referring to it.
		// After the checking stage, we will still have the poly-def nodes, but no actual node will be referring to them anymore.

		ffzNode* poly_inst_decl = f_mem_clone(ffzNode{}, c->alc); // :NewNode
		poly_inst_decl->kind = ffzNodeKind_Declare;
		poly_inst_decl->module_id = c->self_id;
			
		ffzNode* def = f_mem_clone(ffzNode{}, c->alc); // :NewNode
		def->kind = ffzNodeKind_Identifier;
		def->module_id = c->self_id;
		def->Identifier.name = f_tprint("~s__polyid_~u32", ffz_decl_get_name(poly_def_parent), poly_id);
		def->Identifier.is_constant = true;

		poly_inst_decl->Op.left = def;
		poly_inst_decl->Op.right = poly.poly_def->PolyExpr.expr;
		ffz_deep_copy(c, &poly_inst_decl->Op.right);
		
		// NOTE: we're pushing a top-level node to the end of the root node while iterating through them at the bottom of
		// the callstack. But that's totally fine.
		ffz_module_add_top_level_node(c, poly_inst_decl);

		// Modify node from polymorph instantiator into an identifier. :InPlaceNodeModification
		node->kind = ffzNodeKind_Identifier;
		node->Identifier = {};
		node->Identifier.name = def->Identifier.name;
		node->Identifier.chk_definition = def;

		// lastly, check the instantiated declaration and take the results.

		TRY(check_node(c, poly_inst_decl, NULL, 0));
		*result = poly_inst_decl->Op.right->checked;

		//f_map64_insert(&c->poly_instantiation_sites, ffz_hash_node_inst(inst), poly_dedup);
	}
	else {
		// Array subscript
		f_trap();
#if 0

		if (!(left_chk.type->tag == ffzTypeTag_Slice || left_chk.type->tag == ffzTypeTag_FixedArray)) {
			ERR(c, inst->Op.left,
				"Expected an array, a slice, or a polymorphic type as the target of 'post-square-brackets'.\n    received: ~s",
				ffz_type_to_string(c->project, left_chk.type));
		}

		ffzType* elem_type = left_chk.type->tag == ffzTypeTag_Slice ? left_chk.type->Slice.elem_type : left_chk.type->FixedArray.elem_type;

		u32 child_count = ffz_get_child_count(inst);
		if (child_count == 1) {
			ffzNodeInst index = ffz_get_child_inst(inst, 0);

			ffzCheckedInst index_chk;
			TRY(check_node(c, index, NULL, 0, &index_chk));

			if (!ffz_type_is_integer(index_chk.type->tag)) {
				ERR(c, index, "Incorrect type with a slice index; should be an integer.\n    received: ~s",
					ffz_type_to_string(c->project, index_chk.type));
			}

			result->type = elem_type;
		}
		else if (child_count == 2) {
			ffzNodeInst lo = ffz_get_child_inst(inst, 0);
			ffzNodeInst hi = ffz_get_child_inst(inst, 1);

			ffzCheckedInst lo_chk, hi_chk;
			if (lo->kind != ffzNodeKind_Blank) {
				TRY(check_node(c, lo, NULL, 0, &lo_chk));
				if (!ffz_type_is_integer(lo_chk.type->tag)) ERR(c, lo, "Expected an integer.");
			}
			if (hi->kind != ffzNodeKind_Blank) {
				TRY(check_node(c, hi, NULL, 0, &hi_chk));
				if (!ffz_type_is_integer(hi_chk.type->tag)) ERR(c, hi, "Expected an integer.");
			}

			result->type = ffz_make_type_slice(c, elem_type);
		}
		else {
			ERR(c, inst, "Incorrect number of arguments inside subscript/slice operation.");
		}
#endif
	}
	return FFZ_OK;
}

//static ffzOk check_member_access(ffzModule* c, ffzNodeInst inst, ffzCheckedInst* result) {
//	ffzNodeInst left = CHILD(inst, Op.left);
//	ffzNodeInst right = CHILD(inst, Op.right);
//	if (right->kind != ffzNodeKind_Identifier) {
//		ERR(c, inst, "Invalid member access; the right side was not an identifier.");
//	}
//
//	//F_HITS(_c, 955);
//	// Maybe we shouldn't even have the 'in' keyword?
//	// since in  V3{x = 1, y = 2, z = 3}  the fields are added to the namespace, why not in
//	// MyAdderProc{ ret a + b }  as well? I guess the main thing is "where does this variable come from?"
//	// In struct instance it's obvious (since you can't declare/assign to your own variables!)
//
//	fString member_name = right->Identifier.name;
//	fString lhs_name = {};
//	bool found = false;
//	if (left->kind == ffzNodeKind_Identifier && left->Identifier.name == F_LIT("in")) {
//		lhs_name = F_LIT("procedure input parameter list");
//
//		ffzType* proc_type;
//		ffzNodeOpInst parent_proc = code_stmt_get_parent_proc(c->project, inst, &proc_type);
//		if (parent_proc->Op.left->kind == ffzNodeKind_ProcType) {
//			ERR(c, left, "`in` is not allowed when the procedure parameters are accessible by name.");
//		}
//
//		for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
//			ffzField* param = &proc_type->Proc.in_params[i];
//			if (param->name == member_name) {
//				found = true;
//				result->type = param->type;
//			}
//		}
//	}
//	else {
//		ffzCheckedInst left_chk;
//		TRY(check_node(c, left, NULL, 0, &left_chk));
//
//		if (left_chk.type->tag == ffzTypeTag_Module) {
//			ffzModule* left_module = left_chk.const_val->module;
//			f_trap();//lhs_name = left_module->_dbg_module_import_name; // TODO: we should get an actual name for the module
//
//			ffzNodeOpDeclareInst decl;
//			if (ffz_find_top_level_declaration(left_module, member_name, &decl)) {
//				*result = ffz_get_checked(c->project, decl);
//				found = true;
//			}
//		}
//		else if (left_chk.type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_Enum) {
//			ffzType* enum_type = left_chk.const_val->type;
//			lhs_name = ffz_type_to_string(c->project, enum_type);
//
//			ffzModule* enum_type_module = ffz_checker_from_inst(c->project, enum_type->unique_node);
//			ffzFieldHash member_key = ffz_hash_field(left_chk.const_val->type, member_name);
//
//			if (u64* val = f_map64_get(&enum_type_module->enum_value_from_name, member_key)) {
//				result->type = left_chk.const_val->type;
//				result->const_val = make_constant_int(c, *val);
//				found = true;
//			}
//		}
//		else {
//			ffzType* dereferenced_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;
//			lhs_name = ffz_type_to_string(c->project, dereferenced_type);
//
//			ffzTypeRecordFieldUse field;
//			if (ffz_type_find_record_field_use(c->project, dereferenced_type, member_name, &field)) {
//				result->type = field.type;
//				found = true;
//			}
//		}
//	}
//
//	if (!found) ERR(c, right, "Declaration not found for '~s' inside '~s'", member_name, lhs_name);
//
//	return FFZ_OK;
//}

//ffzOk ffz_check_toplevel_statement(ffzModule* c, ffzNode* node) {
//	switch (node->kind) {
//	case ffzNodeKind_Declare: {
//		ffzNodeIdentifier* name = node->Op.left;
//		ffzNodeInst inst = ffz_get_toplevel_inst(c, node);
//		
//		TRY(check_node(c, inst, NULL, InferFlag_Statement, NULL));
//		
//		// first check the tags...
//		bool is_global = ffz_get_tag(c->project, inst, ffzKeyword_global) != NULL;
//		if (!name->Identifier.is_constant && !is_global) {
//			ERR(c, name, "Top-level declaration must be constant, or @*global, but got a non-constant.");
//		}
//	} break;
//	default: ERR(c, node, "Top-level node must be a declaration, but got: ~s", ffz_node_kind_to_string(node->kind));
//	}
//	return { true };
//}

//static ffzOk check_tag(ffzModule* c, ffzNodeInst tag) {
//	ffzCheckedInst chk;
//	TRY(check_node(c, tag, NULL, InferFlag_RequireConstant | InferFlag_TypeMeansDefaultValue, &chk));
//	if (chk.type->tag != ffzTypeTag_Record) {
//		ERR(c, tag, "Tag was not a struct literal.", "");
//	}
//
//	if (chk.type == ffz_builtin_type(c, ffzKeyword_extern)) {
//		fString library = chk.const_val->record_fields[0].string_zero_terminated;
//		f_array_push(&c->extern_libraries, library);
//	}
//	//else if (chk.type == ffz_builtin_type(c, ffzKeyword_extern_sys)) {
//	//	fString library = chk.const_val->record_fields[0].string_zero_terminated;
//	//	f_array_push(&c->extern_sys_libraries, library);
//	//}
//
//	auto tags = f_map64_insert(&c->all_tags_of_type, chk.type->hash, {}, fMapInsert_DoNotOverride);
//	if (tags.added) *tags._unstable_ptr = f_array_make<ffzNodeInst>(c->alc);
//	f_array_push(tags._unstable_ptr, tag);
//	return FFZ_OK;
//}

//static ffzOk check_tags(ffzModule* c, ffzNodeInst inst) {
//	for (ffzNode* tag_n = inst->first_tag; tag_n; tag_n = tag_n->next) {
//		ffzNodeInst tag = { tag_n, inst.polymorph };
//		TRY(check_tag(c, tag));
//	}
//	return { true };
//}


//static ffzNodeInst ffz_make_pseudo_node(ffzModule* c) {
//	ffzNode* n = f_mem_clone(ffzNode{}, c->alc);
//	n->id.global_id = --c->next_pseudo_node_idx; // this is supposed to underflow and to not collide with real nodes
//	return { n, NULL };
//}
//
//static ffzType* ffz_make_pseudo_record_type(ffzModule* c) {
//	ffzType t = { ffzTypeTag_Record }; // hmm... maybe PseudoRecordType should be its own type tag / call it BuiltinRecord
//	t.unique_node = ffz_make_pseudo_node(c); // NOTE: ffz_hash_node_inst looks at the id of the unique node for record types
//	return ffz_make_type(c, t);
//}

ffzModule* ffz_project_add_module(ffzProject* p, fArena* module_arena) {
	fAllocator* alc = &module_arena->alc;

	ffzModule* c = f_mem_clone(ffzModule{}, alc);	
	c->project = p;
	c->self_id = (ffzModuleID)f_array_push(&p->checkers, c);
	c->alc = alc;
	c->checked_identifiers = f_map64_make_raw(0, c->alc);
	c->definition_map = f_map64_make<ffzNodeIdentifier*>(c->alc);
	//c->cache = f_map64_make<ffzCheckedInst>(c->alc);
	//c->poly_instantiation_sites = f_map64_make<ffzPolymorph*>(c->alc);
	c->field_from_name_map = f_map64_make<ffzTypeRecordFieldUse*>(c->alc);
	c->enum_value_from_name = f_map64_make<u64>(c->alc);
	c->enum_value_is_taken = f_map64_make<ffzNode*>(c->alc);
	c->imported_modules = f_map64_make<ffzModule*>(c->alc);
	c->type_from_hash = f_map64_make<ffzType*>(c->alc);
	//c->all_tags_of_type = f_map64_make<fArray(ffzNodeInst)>(c->alc);
	c->poly_from_hash = f_map64_make<ffzPolymorphID>(c->alc);
	c->polymorphs = f_array_make<ffzPolymorph>(c->alc);
	c->parsers = f_array_make<ffzParser*>(c->alc);
	c->extern_libraries = f_array_make<fString>(c->alc);
	
	c->root = f_mem_clone(ffzNode{}, c->alc); // :NewNode
	c->root->kind = ffzNodeKind_Scope;
	c->root->module_id = c->self_id;

	{
		c->builtin_types[ffzKeyword_u8] = ffz_make_type(c, { ffzTypeTag_Uint, 1 });
		c->builtin_types[ffzKeyword_u16] = ffz_make_type(c, { ffzTypeTag_Uint, 2 });
		c->builtin_types[ffzKeyword_u32] = ffz_make_type(c, { ffzTypeTag_Uint, 4 });
		c->builtin_types[ffzKeyword_u64] = ffz_make_type(c, { ffzTypeTag_Uint, 8 });
		c->builtin_types[ffzKeyword_s8] = ffz_make_type(c, { ffzTypeTag_Sint, 1 });
		c->builtin_types[ffzKeyword_s16] = ffz_make_type(c, { ffzTypeTag_Sint, 2 });
		c->builtin_types[ffzKeyword_s32] = ffz_make_type(c, { ffzTypeTag_Sint, 4 });
		c->builtin_types[ffzKeyword_s64] = ffz_make_type(c, { ffzTypeTag_Sint, 8 });
		c->builtin_types[ffzKeyword_f32] = ffz_make_type(c, { ffzTypeTag_Float, 4 });
		c->builtin_types[ffzKeyword_f64] = ffz_make_type(c, { ffzTypeTag_Float, 8 });
		c->builtin_types[ffzKeyword_uint] = ffz_make_type(c, { ffzTypeTag_DefaultUint, p->pointer_size });
		c->builtin_types[ffzKeyword_int] = ffz_make_type(c, { ffzTypeTag_DefaultSint, p->pointer_size });
		c->builtin_types[ffzKeyword_raw] = ffz_make_type(c, { ffzTypeTag_Raw });
		c->builtin_types[ffzKeyword_bool] = ffz_make_type(c, { ffzTypeTag_Bool, 1 });
		
		//_ = foo
		//c->builtin_types[ffzKeyword_Eater] = ffz_make_type(c, { ffzTypeTag_Eater });
		c->builtin_types[ffzKeyword_Undefined] = ffz_make_type(c, { ffzTypeTag_Undefined });

		c->module_type = ffz_make_type(c, { ffzTypeTag_Module });
		c->type_type = ffz_make_type(c, { ffzTypeTag_Type });

		{
			ffzType* string = ffz_make_type(c, { ffzTypeTag_String });
			c->builtin_types[ffzKeyword_string] = string;

			ffzConstantData zero = {};
			ffzRecordBuilder b = ffz_record_builder_init(c, c->builtin_types[ffzKeyword_string], 2);
			ffz_record_builder_add_field(&b, F_LIT("ptr"), ffz_make_type_ptr(c, ffz_builtin_type(c, ffzKeyword_u8)), &zero, {});
			ffz_record_builder_add_field(&b, F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), &zero, {});
			ffz_record_builder_finish(&b);
		}

		//{
		//	c->builtin_types[ffzKeyword_extern] = ffz_make_pseudo_record_type(c);
		//	ffzRecordBuilder b = ffz_record_builder_init(c, c->builtin_types[ffzKeyword_extern], 1);
		//	ffz_record_builder_add_field(&b, F_LIT("library"), ffz_builtin_type(c, ffzKeyword_string), NULL, {});
		//	ffz_record_builder_finish(&b);
		//}
		//
		//c->builtin_types[ffzKeyword_using] = ffz_make_pseudo_record_type(c);
		//c->builtin_types[ffzKeyword_global] = ffz_make_pseudo_record_type(c);
		//c->builtin_types[ffzKeyword_module_defined_entry] = ffz_make_pseudo_record_type(c);
	}

	return c;
}

//bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee) {
//	// TODO: we need to check for procedure boundaries.
//	for (ffzNode* p = dot->parent; p; p = p->parent) {
//		if (p->kind == ffzNodeKind_Assign) {
//			*out_assignee = { p->Op.left, dot.polymorph };
//			return true;
//		}
//	}
//	return false;
//}

ffzConstantData* ffz_get_tag_of_type(ffzProject* p, ffzNode* node, ffzType* tag_type) {
	for (ffzNode* tag_n = node->first_tag; tag_n; tag_n = tag_n->next) {
		f_assert(tag_n->has_checked);
		if (type_is_a_bit_by_bit(p, tag_n->checked.type, tag_type)) {
			return tag_n->checked.constant;
		}
	}
	return NULL;
}

//static ffzOk check_enum(ffzModule* c, ffzNodeInst inst, ffzCheckedInst* result) {
//	ffzCheckedInst type_chk;
//	TRY(check_node(c, CHILD(inst, Enum.internal_type), NULL, 0, &type_chk));
//
//	if (type_chk.type->tag != ffzTypeTag_Type || !ffz_type_is_integer(type_chk.const_val->type->tag)) {
//		ERR(c, inst->Enum.internal_type, "Invalid enum type; expected an integer.");
//	}
//
//	ffzType enum_type = { ffzTypeTag_Enum };
//	enum_type.Enum.internal_type = type_chk.const_val->type;
//	enum_type.size = enum_type.Enum.internal_type->size;
//	enum_type.unique_node = inst;
//	enum_type.Enum.fields = f_make_slice_garbage<ffzTypeEnumField>(ffz_get_child_count(inst), c->alc);
//
//	// :EnumFieldsShouldNotContributeToTypeHash
//	// Note that we're making the enum type pointer BEFORE populating all of the fields
//	ffzType* enum_type_ptr = ffz_make_type(c, enum_type);
//
//	//CheckInfer decl_infer = infer_no_help_constant(infer);
//	//decl_infer.infer_decl_type = enum_type.Enum.internal_type;
//
//	uint i = 0;
//	for FFZ_EACH_CHILD_INST(n, inst) {
//		if (n->kind != ffzNodeKind_Declare) ERR(c, n, "Expected a declaration; got: [~s]", ffz_node_kind_to_string(n->kind));
//
//		// NOTE: Infer the declaration from the enum internal type!
//		ffzCheckedInst chk;
//		TRY(check_node(c, n, enum_type.Enum.internal_type, InferFlag_Statement, &chk));
//
//		u64 val = chk.const_val->u64_;
//		
//		ffzFieldHash key = ffz_hash_field(enum_type_ptr, ffz_decl_get_name(n));
//		f_map64_insert(&c->enum_value_from_name, key, val);
//
//		enum_type.Enum.fields[i] = ffzTypeEnumField{ ffz_decl_get_name(n), val };
//
//		auto val_taken = f_map64_insert(&c->enum_value_is_taken, ffz_hash_enum_value(enum_type_ptr, val), n, fMapInsert_DoNotOverride);
//		if (!val_taken.added) {
//			fString taken_by = ffz_decl_get_name((*val_taken._unstable_ptr));
//			ERR(c, n->Op.right, "The enum value `~u64` is already taken by `~s`.", val, taken_by);
//		}
//		i++;
//	}
//	*result = make_type_constant(c, enum_type_ptr);
//	return FFZ_OK;
//}

//static ffzOk check_proc_type(ffzModule* c, ffzNodeInst inst, ffzCheckedInst* result) {
//	ffzType proc_type = { ffzTypeTag_Proc };
//	proc_type.unique_node = inst;
//	ffzNodeInst out_param = CHILD(inst,ProcType.out_parameter);
//	
//	if (ffz_get_child_count(inst->ProcType.polymorphic_parameters) > 0 &&
//		(!inst.polymorph || inst.polymorph->node != inst))
//	{
//		proc_type.tag = ffzTypeTag_PolyProc;
//	}
//	else {
//		proc_type.size = c->project->pointer_size;
//	
//		ffzNodePolyParamListInst poly_params = CHILD(inst,ProcType.polymorphic_parameters);
//		for FFZ_EACH_CHILD_INST(n, poly_params) {
//			TRY(check_node(c, n, NULL, 0, NULL));
//		}
//		
//		fArray(ffzField) in_parameters = f_array_make<ffzField>(c->alc);
//		for FFZ_EACH_CHILD_INST(param, inst) {
//			if (param->kind != ffzNodeKind_Declare) ERR(c, param, "Expected a declaration.");
//			ffzCheckedInst chk;
//			TRY(check_node(c, param, NULL, InferFlag_Statement, &chk));
//			
//			// Since the parameter is a runtime value, we need to access the rhs of it to
//			// distinguish between a type expression and a default value
//			ffzCheckedInst rhs_chk = ffz_get_checked(c->project, CHILD(param, Op.right));
//
//			// access the rhs node
//			ffzField field = {};
//			field.decl = param;
//			field.name = ffz_decl_get_name(param);
//
//			if (rhs_chk.type->tag == ffzTypeTag_Type) {
//				field.type = rhs_chk.const_val->type;
//			} else {
//				field.type = rhs_chk.type;
//				field.has_default_value = true;
//				field.default_value = *rhs_chk.const_val;
//			}
//
//			f_array_push(&in_parameters, field);
//		}
//		proc_type.Proc.in_params = in_parameters.slice;
//	
//		if (out_param) {
//			ffzCheckedInst chk;
//			TRY(check_node(c, out_param, NULL, 0, &chk));
//			TRY(verify_is_type_expression(c, inst, chk));
//			proc_type.Proc.return_type = chk.const_val->type;
//		}
//	}
//	
//	ffzNodeInst parent = ffz_parent_inst(c->project, inst);
//	if (ffz_get_tag(c->project, parent, ffzKeyword_extern)) {
//		if (proc_type.tag == ffzTypeTag_PolyProc) ERR(c, inst, "Polymorphic procedures cannot be @extern.");
//	
//		// if it's an extern proc, then don't turn it into a type type!!
//		result->type = ffz_make_type(c, proc_type);
//		result->const_val = make_constant(c);
//		result->const_val->proc_node = inst;
//	}
//	else {
//		*result = make_type_constant(c, ffz_make_type(c, proc_type));
//	}
//	return FFZ_OK;
//}

/*
	#AdderType: proc[T](first: T, second: T)
	#adder: AdderType { dbgbreak }
	#demo: proc() { adder[int](5, 6) }
*/

/*
	#B: import("basic")
	#adder: proc[T](first: T, second: T) {
		B.test()
	}
	#demo: proc() { adder[int](5, 6) }
*/

static ffzOk check_identifier(ffzModule* c, ffzNodeIdentifier* node, ffzCheckInfo* result) {
	fString name = node->Identifier.name;

	ffzNodeIdentifier* def = NULL;
	
	for (fOpt(ffzNode*) scope = ffz_get_scope(node); scope; scope = ffz_get_scope(scope)) {
		def = ffz_find_definition_in_scope(c->project, scope, node->Identifier.name);
		if (def != NULL) break;
	}

	if (def == NULL) {
		ERR(c, node, "Definition not found for an identifier: \"~s\"", name);
	}
	
	node->Identifier.chk_definition = def;

	ffzNode* decl = def->parent;
	f_assert(decl->kind == ffzNodeKind_Declare);
	
	//if (def->parent->kind == ffzNodeKind_PolyParamList) {
	//	*result = def.polymorph->parameters[ffz_get_child_index(def)];
	//}
	//else {

	// TODO: check for circular definitions
	//fMapInsertResult circle_chk = f_map64_insert_raw(&c->checked_identifiers, ffz_hash_node_inst(inst), NULL, fMapInsert_DoNotOverride);
	//if (!circle_chk.added) ERR(c, inst, "Circular definition!"); // TODO: elaborate

	// Sometimes we need to access a constant declaration that's ahead of us that we haven't yet checked.
	// In that case we need to completely reset the context back to the declaration's scope, then evaluate the
	// thing we need real quick, and then come back as if nothing had happened.

	TRY(check_node(c, decl, NULL, InferFlag_Statement));
	*result = decl->checked;

	if (def != node && ffz_decl_is_variable(decl) && decl->local_id > node->local_id) {
		ERR(c, node, "Variable is being used before it is declared.");
	}

	//result = ffz_decl_get_checked(c->project, decl_inst);
	//}
	return FFZ_OK;
}

//static ffzOk check_return(ffzModule* c, ffzNodeInst inst, ffzCheckedInst* result) {
//	ffzNodeInst return_val = CHILD(inst, Return.value);
//	ffzType* proc_type;
//	ffzNodeOpInst proc_node = code_stmt_get_parent_proc(c->project, inst, &proc_type);
//	
//	fOpt(ffzType*) ret_type = proc_type->Proc.return_type;
//	if (!return_val && ret_type) ERR(c, inst, "Expected a return value, but got none.");
//	if (return_val && !ret_type) ERR(c, return_val, "Expected no return value, but got one.");
//	
//	if (return_val) {
//		TRY(check_node(c, return_val, ret_type, 0, NULL));
//	}
//	return FFZ_OK;
//}

//static ffzOk check_assign(ffzModule* c, ffzNodeInst inst, ffzCheckedInst* result) {
//	ffzNodeInst lhs = CHILD(inst, Op.left);
//	ffzNodeInst rhs = CHILD(inst, Op.right);
//	ffzCheckedInst lhs_chk, rhs_chk;
//	
//	TRY(check_node(c, lhs, NULL, 0, &lhs_chk));
//	
//	bool is_void_assignment = ffz_node_is_keyword(lhs, ffzKeyword_Eater);
//	if (!is_void_assignment) f_assert(ffz_type_is_concrete(lhs_chk.type));
//
//	TRY(check_node(c, rhs, lhs_chk.type, 0, &rhs_chk));
//	
//	TRY(check_types_match(c, rhs, rhs_chk.type, lhs_chk.type, "Incorrect type with assignment:"));
//	
//	bool is_code_scope = inst->parent->kind == ffzNodeKind_Scope || inst->parent->kind == ffzNodeKind_ProcType;
//	if (is_code_scope && lhs_chk.type->tag != ffzTypeTag_Raw && !is_lvalue(c, lhs)) {
//		ERR(c, lhs, "Attempted to assign to a non-assignable value.");
//	}
//	return FFZ_OK;
//}

//static ffzOk check_pre_square_brackets(ffzModule* c, ffzNodeInst inst, ffzCheckedInst* result) {
//	ffzCheckedInst right_chk;
//	TRY(check_node(c, CHILD(inst, Op.right), NULL, 0, &right_chk));
//	TRY(verify_is_type_expression(c, inst, right_chk));
//	
//	if (ffz_get_child_count(inst) == 0) {
//		*result = make_type_constant(c, ffz_make_type_slice(c, right_chk.const_val->type));
//	}
//	else if (ffz_get_child_count(inst) == 1) {
//		ffzNode* child = ffz_get_child(inst, 0);
//		s32 length = -1;
//		if (child->kind == ffzNodeKind_IntLiteral) {
//			length = (s32)child->IntLiteral.value;
//		}
//		else if (ffz_node_is_keyword(child, ffzKeyword_QuestionMark)) {}
//		else ERR(c, inst, "Unexpected value inside the brackets of an array type; expected an integer literal or `?`");
//	
//		ffzType* array_type = ffz_make_type_fixed_array(c, right_chk.const_val->type, length);
//		*result = make_type_constant(c, array_type);
//	}
//	else ERR(c, inst, "Unexpected value inside the brackets of an array type; expected an integer literal or `_`");
//	return FFZ_OK;
//}

static bool integer_is_negative(void* bits, u32 size) {
	switch (size) {
	case 1: return *(s8*)bits < 0;
	case 2: return *(s16*)bits < 0;
	case 4: return *(s32*)bits < 0;
	case 8: return *(s64*)bits < 0;
	default: f_trap();
	}
	return false;
}

static ffzOk check_node(ffzModule* c, ffzNode* node, OPT(ffzType*) require_type, InferFlags flags) {
	if (node->has_checked) return FFZ_OK;
	
	//check_tags(c, inst);

	F_HITS(_c, 0);

	ffzCheckInfo result = {};
	
	bool delayed_check_record = false;
	bool delayed_check_proc = false;
	bool delayed_check_decl_lhs = false;

	switch (node->kind) {
	case ffzNodeKind_Declare: {
		ffzNode* rhs = node->Op.right;

		bool is_variable = ffz_decl_is_variable(node);
		bool is_parameter = ffz_decl_is_parameter(node);

		InferFlags rhs_flags = 0;
		if (is_variable && !is_parameter) {
			rhs_flags |= InferFlag_AllowUndefinedValues;
		}
		
		// sometimes we want to pass `require_type` down to the rhs, namely with enum field declarations
		TRY(check_node(c, rhs, require_type, rhs_flags));
		TRY(verify_is_constant(c, rhs));

		result = rhs->checked; // Declarations cache the value of the right-hand-side
		
		if (is_variable) {
			if (is_parameter) {
				// if the parameter is a type expression, then this declaration has that type
				result.type = ffz_ground_type(result.constant, result.type);
			}

			result.constant = NULL; // runtime variables shouldn't store the constant value that the rhs expression might have

			if (!ffz_type_is_concrete(result.type)) {
				ERR(c, node, "Variable has a non-concrete type, the type being ~s.", ffz_type_to_string(c->project, result.type));
			}
		}

		// The lhs identifier will recurse into this same declaration,
		// at which point we should have cached the result for this node to cut the loop.
		delayed_check_decl_lhs = true;
	} break;

	//case ffzNodeKind_Assign: { TRY(check_assign(c, inst, &result)); } break;
	// case ffzNodeKind_Return: { TRY(check_return(c, inst, &result)); } break;

	case ffzNodeKind_Scope: {
		TRY(add_definitions_to_scope(c, node, node));

		for FFZ_EACH_CHILD(stmt, node) {
			TRY(check_node(c, stmt, NULL, InferFlag_Statement));
		}
	} break;

	case ffzNodeKind_PolyExpr: {
		// When you say `#foo: poly[T] T(100)`, you're declaring foo as a new type, more specifically a polymorphic expression type.
		// It's the same thing as if foo was i.e. a struct type.
		
		if (node->parent->kind != ffzNodeKind_Declare) {
			ERR(c, node, "Polymorphic expression must be the right-hand-side of a constant declaration.");
		}

		ffzType type = { ffzTypeTag_PolyExpr };
		type.unique_node = node;
		result = make_type_constant(c, ffz_make_type(c, type));
	} break;

	//case ffzNodeKind_PostRoundBrackets: {
	//	TRY(check_post_round_brackets(c, inst, require_type, flags, &result));
	//} break;

	//case ffzNodeKind_If: {
	//	TRY(check_node(c, CHILD(inst, If.condition), ffz_builtin_type(c, ffzKeyword_bool), 0, NULL));
	//	TRY(check_node(c, CHILD(inst, If.true_scope), NULL, InferFlag_Statement, NULL));
	//	if (inst->If.else_scope) {
	//		TRY(check_node(c, CHILD(inst, If.else_scope), NULL, InferFlag_Statement, NULL));
	//	}
	//} break;
	//
	//case ffzNodeKind_For: {
	//	for (uint i = 0; i < 3; i++) {
	//		if (inst->For.header_stmts[i]) {
	//			if (i == 1) {
	//				TRY(check_node(c, CHILD(inst, For.header_stmts[i]), ffz_builtin_type(c, ffzKeyword_bool), 0, NULL));
	//			}
	//			else {
	//				TRY(check_node(c, CHILD(inst, For.header_stmts[i]), NULL, InferFlag_Statement, NULL));
	//			}
	//		}
	//	}
	//	
	//	TRY(check_node(c, CHILD(inst, For.scope), NULL, InferFlag_Statement, NULL));
	//} break;

	case ffzNodeKind_Keyword: {
		ffzKeyword keyword = node->Keyword.keyword;
		OPT(ffzType*) type_expr = ffz_builtin_type(c, keyword);
		if (type_expr) {
			result = make_type_constant(c, type_expr);
		}
		else {
			switch (keyword) {
			case ffzKeyword_dbgbreak: {} break;
			case ffzKeyword_false: {
				const static ffzConstantData _false = { 0 };
				result.type = ffz_builtin_type(c, ffzKeyword_bool);
				result.constant = (ffzConstantData*)&_false;
			} break;
			case ffzKeyword_true: {
				const static ffzConstantData _true = { 1 };
				result.type = ffz_builtin_type(c, ffzKeyword_bool);
				result.constant = (ffzConstantData*)&_true;
			} break;
			
			// the type of an eater is 'raw'
			case ffzKeyword_Eater: {
				result.type = ffz_builtin_type(c, ffzKeyword_raw);
			} break;
	
			default: f_assert(false);
			}
		}
	} break;

	//case ffzNodeKind_ThisValueDot: {
	//	ffzNodeInst assignee;
	//	if (!ffz_dot_get_assignee(inst, &assignee)) {
	//		ERR(c, inst, "`.` catcher must be used within an assignment, but no assignment was found.");
	//	}
	//	result.type = ffz_get_type(c->project, assignee); // when checking assignments, the assignee/lhs is always checked first, so this should be ok.
	//} break;

	case ffzNodeKind_Identifier: {
		TRY(check_identifier(c, node, &result));
	} break;

	//case ffzNodeKind_Record: {
	//	ffzType struct_type = { ffzTypeTag_Record };
	//	struct_type.unique_node = inst;
	//
	//	if (ffz_get_child_count(inst->Record.polymorphic_parameters) > 0 &&
	//		(!inst.polymorph || inst.polymorph->node != inst))
	//	{
	//		struct_type.tag = ffzTypeTag_PolyRecord;
	//	}
	//	else {
	//		delayed_check_record = true;
	//	}
	//	result = make_type_constant(c, ffz_make_type(c, struct_type));
	//} break;
	
	//case ffzNodeKind_FloatLiteral: {
	//	if (require_type && require_type->tag == ffzTypeTag_Float) {
	//		result.type = require_type;
	//		result.const_val = make_constant(c);
	//		
	//		f64 val = inst->FloatLiteral.value;
	//		if (require_type->size == 4) result.const_val->f32_ = (f32)val;
	//		else if (require_type->size == 8) result.const_val->f64_ = val;
	//		else f_trap();
	//	}
	//} break;

	//case ffzNodeKind_IntLiteral: {
	//	if (!(flags & InferFlag_TypeIsNotRequired_)) {
	//		result.type = ffz_builtin_type(c, ffzKeyword_uint);
	//		result.const_val = make_constant_int(c, inst->IntLiteral.value);
	//	}
	//} break;

	//case ffzNodeKind_StringLiteral: {
	//	// pointers aren't guaranteed to be valid / non-null, but optional pointers are expected to be null.
	//	result.type = ffz_builtin_type(c, ffzKeyword_string);
	//	result.const_val = make_constant(c);
	//	result.const_val->string_zero_terminated = inst->StringLiteral.zero_terminated_string;
	//} break;

	//case ffzNodeKind_UnaryMinus: // fallthrough
	//case ffzNodeKind_UnaryPlus: {
	//	ffzCheckedInst right_chk;
	//	TRY(check_node(c, CHILD(inst, Op.right), require_type, flags, &right_chk));
	//	
	//	if (!ffz_type_is_integer(right_chk.type->tag) && !ffz_type_is_float(right_chk.type->tag)) {
	//		ERR(c, inst->Op.right, "Incorrect arithmetic type; should be an integer or a float.\n    received: ~s",
	//			ffz_type_to_string(c->project, right_chk.type));
	//	}
	//	result.type = right_chk.type;
	//} break;
	//
	//case ffzNodeKind_PreSquareBrackets: { TRY(check_pre_square_brackets(c, inst, &result)); } break;
	//
	//case ffzNodeKind_PointerTo: {
	//	ffzCheckedInst right_chk;
	//	TRY(check_node(c, CHILD(inst, Op.right), NULL, 0, &right_chk));
	//	TRY(verify_is_type_expression(c, inst, right_chk));
	//	
	//	result = make_type_constant(c, ffz_make_type_ptr(c, right_chk.const_val->type));
	//} break;
	//
	//case ffzNodeKind_ProcType: { TRY(check_proc_type(c, inst, &result)); } break;
	//
	//case ffzNodeKind_Enum: { TRY(check_enum(c, inst, &result)); } break;
	
	//case ffzNodeKind_PostCurlyBrackets: {
	//	TRY(check_post_curly_brackets(c, inst, require_type, flags, &delayed_check_proc, &result));
	//} break;
	//
	case ffzNodeKind_PostSquareBrackets: {
		TRY(check_post_square_brackets(c, node, &result));
	} break;
	//
	//case ffzNodeKind_MemberAccess: { TRY(check_member_access(c, inst, &result)); } break;
	//
	//case ffzNodeKind_LogicalNOT: {
	//	result.type = ffz_builtin_type(c, ffzKeyword_bool);
	//	TRY(check_node(c, CHILD(inst,Op.right), result.type, 0, NULL));
	//} break;
	//
	//case ffzNodeKind_LogicalAND: // fallthrough
	//case ffzNodeKind_LogicalOR: {
	//	result.type = ffz_builtin_type(c, ffzKeyword_bool);
	//	TRY(check_node(c, CHILD(inst,Op.left), result.type, 0, NULL));
	//	TRY(check_node(c, CHILD(inst,Op.right), result.type, 0, NULL));
	//} break;
	//
	//case ffzNodeKind_AddressOf: {
	//	ffzCheckedInst right_chk;
	//	TRY(check_node(c, CHILD(inst, Op.right), NULL, 0, &right_chk));
	//	result.type = ffz_make_type_ptr(c, right_chk.type);
	//} break;
	//
	//case ffzNodeKind_Dereference: {
	//	ffzCheckedInst left_chk;
	//	TRY(check_node(c, CHILD(inst, Op.left), NULL, 0, &left_chk));
	//	if (left_chk.type->tag != ffzTypeTag_Pointer) ERR(c, inst, "Attempted to dereference a non-pointer.");
	//	result.type = left_chk.type->Pointer.pointer_to;
	//} break;
	//
	//case ffzNodeKind_Equal: case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
	//case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater: case ffzNodeKind_GreaterOrEqual: {
	//	OPT(ffzType*) type;
	//	TRY(check_two_sided(c, CHILD(inst,Op.left), CHILD(inst,Op.right), &type));
	//	
	//	bool is_equality_check = inst->kind == ffzNodeKind_Equal || inst->kind == ffzNodeKind_NotEqual;
	//	if (ffz_type_is_comparable(type) || (is_equality_check && ffz_type_is_comparable_for_equality(type))) {
	//		result.type = ffz_builtin_type(c, ffzKeyword_bool);
	//	}
	//	else {
	//		ERR(c, inst, "Operator '~s' is not defined for type '~s'",
	//			ffz_node_kind_to_op_string(inst->kind), ffz_type_to_string(c->project, type));
	//	}
	//} break;
	//
	//case ffzNodeKind_Add: case ffzNodeKind_Sub: case ffzNodeKind_Mul:
	//case ffzNodeKind_Div: case ffzNodeKind_Modulo: {
	//	OPT(ffzType*) type;
	//	TRY(check_two_sided(c, CHILD(inst,Op.left), CHILD(inst,Op.right), &type));
	//	
	//	if (inst->kind == ffzNodeKind_Modulo) {
	//		if (type && !ffz_type_is_integer(type->tag)) {
	//			ERR(c, inst, "Incorrect type with modulo operator; expected an integer.\n    received: ~s", ffz_type_to_string(c->project, type));
	//		}
	//	}
	//	else {
	//		if (type && !ffz_type_is_integer(type->tag) && !ffz_type_is_float(type->tag)) {
	//			ERR(c, inst, "Incorrect arithmetic type; expected an integer or a float.\n    received: ~s", ffz_type_to_string(c->project, type));
	//		}
	//	}
	//
	//	result.type = type;
	//} break;

	default: f_trap();
	}

	//if ((flags & InferFlag_RequireConstant) && !result.constant) {
	//	ERR(c, node, "Expression is not constant, but constant was expected.");
	//}

	if (flags & InferFlag_Statement) {
		// NOTE: we cache the types of declarations even though they are statements.
		if (node->kind != ffzNodeKind_Declare && result.type) {
			ERR(c, node, "Expected a statement or a declaration, but got an expression.\n  HINT: An expression can be turned into a statement, i.e. `_ = foo()`");
		}
	}
	else {
		if (node->kind == ffzNodeKind_Declare) ERR(c, node, "Expected an expression, but got a declaration.");

		if (!(flags & InferFlag_TypeIsNotRequired_)) { // type is required
			if (!result.type) {
				ERR(c, node, "Expression has no type, or it cannot be inferred.");
			}
		}
	}

	if (!(flags & InferFlag_NoTypesMatchCheck)) {
		
		// NOTE: we're ignoring the constant type-casts with InferFlag_NoTypesMatchCheck, because explicit type-casts are allowed to overflow
		if (require_type && result.constant) { // constant downcast
			// TODO: automatic casting for signed integers
			if (ffz_type_is_integer(require_type->tag) && ffz_type_is_integer(result.type->tag)) {
				if (require_type->size <= result.type->size) {
					f_assert(is_basic_type_size(result.type->size));
					f_assert(is_basic_type_size(require_type->size));

					u64 src = ffz_type_is_signed_integer(result.type->tag) ? (u64)-1 : 0;
					u64 masked = src;
					memcpy(&src, &result.constant->u64_, result.type->size);
					memcpy(&masked, &result.constant->u64_, require_type->size);
					
					bool src_is_negative = ffz_type_is_signed_integer(result.type->tag) && integer_is_negative(&src, result.type->size);
					bool masked_is_negative = ffz_type_is_signed_integer(require_type->tag) && integer_is_negative(&masked, require_type->size);
					
					bool ok = masked == src && (src_is_negative == masked_is_negative) && (ffz_type_is_signed_integer(require_type->tag) || !src_is_negative);
					if (!ok) {
						if (ffz_type_is_signed_integer(result.type->tag)) {
							ERR(c, node, "Constant type-cast failed; value '~u64' can't be represented in type '~s'.", src, ffz_type_to_string(c->project, require_type));
						} else {
							ERR(c, node, "Constant type-cast failed; value '~u64' can't be represented in type '~s'.", src, ffz_type_to_string(c->project, require_type));
						}
					}
					// NOTE: we don't need to make a new constant value, as the encoding for it would be exactly the same.
					result.type = require_type;
				}
			}
		}

		// If `require_type` is specified and we found a type for this instance, the type of the expression must match it.
		if (require_type && result.type) {
			TRY(check_types_match(c, node, result.type, require_type, "Unexpected type with an expression:"));
		}
	}

	//if (result.type && result.type->tag == ffzTypeTag_Type && (flags & InferFlag_TypeMeansDefaultValue)) {
	//	result.type = ffz_ground_type(result.constant, result.type);
	//	result.const_val = ffz_zero_value_constant(c, result.type);
	//}

	// Say you have `#X: struct { a: ^X }`
	// When checking it the first time, when we get to the identifier after the pointer-to-operator,
	// it will recurse back into the declaration node and check it.
	// When we come back to the outer declaration check, it has already been checked and cached for us.
	// Let the children do the work for us!

	bool child_already_fully_checked_us = false;
	if (!(flags & InferFlag_CacheOnlyIfGotType) || result.type) {
		if (node->has_checked) {
			child_already_fully_checked_us = true;
		}
		else {
			node->has_checked = true;
			node->checked = result;
		}
	}

	if (!child_already_fully_checked_us) {
		if (delayed_check_decl_lhs) {
			TRY(check_node(c, node->Op.left, NULL, 0));
		}
		else if (delayed_check_proc) {
			TRY(add_definitions_to_scope(c, node, node));
			
			if (node->Op.left->kind == ffzNodeKind_ProcType) {
				TRY(add_definitions_to_scope(c, node, node->Op.left)); // Add parameters if they're visible (not needing the `in` keyword)
			}
			
			// only check the procedure body when we have a physical procedure instance (not polymorphic)
			// and after the proc type has been cached.

			for FFZ_EACH_CHILD(n, node) {
				TRY(check_node(c, n, NULL, InferFlag_Statement));
			}
		}
		else if (delayed_check_record) {
			TRY(add_definitions_to_scope(c, node, node));

			// Add the record fields only after the type has been registered in the cache. This is to avoid
			// infinite loops when checking.

			// IMPORTANT: We're modifying the type AFTER it was created and hash-deduplicated. So, the things we modify must not change the type hash!
			ffzType* record_type = result.constant->type;
			ffzRecordBuilder b = ffz_record_builder_init(c, record_type, 0);

			for FFZ_EACH_CHILD(n, node) {
				if (n->kind != ffzNodeKind_Declare) ERR(c, n, "Expected a declaration.");
				fString name = ffz_decl_get_name(n);
				
				TRY(check_node(c, n, NULL, InferFlag_Statement));
				TRY(verify_is_constant(c, n));
				
				ffzType* field_type = n->checked.type->tag == ffzTypeTag_Type ? n->checked.constant->type : n->checked.type;
				fOpt(ffzConstantData*) default_value = n->checked.type->tag == ffzTypeTag_Type ? NULL : n->checked.constant;
				
				ffz_record_builder_add_field(&b, name, field_type, default_value, n);
			}
			TRY(ffz_record_builder_finish(&b));
		}
	}

	return { true };
}


ffzProject* ffz_init_project(fArena* arena, fString modules_directory) {
	ffzProject* p = f_mem_clone(ffzProject{}, &arena->alc);
	p->persistent_allocator = &arena->alc;

	p->modules_directory = modules_directory;
	//if (modules_directory.len > 0) {
	//	fString modules_dir_canonical;
	//	if (f_files_path_to_canonical(fString{}, modules_directory, p->persistent_allocator, &modules_dir_canonical)) {
	//		p->modules_directory = modules_dir_canonical;
	//	}
	//}
	
	p->checkers = f_array_make<ffzModule*>(p->persistent_allocator);
	p->checkers_dependency_sorted = f_array_make<ffzModule*>(p->persistent_allocator);
	p->link_libraries = f_array_make<fString>(p->persistent_allocator);
	p->link_system_libraries = f_array_make<fString>(p->persistent_allocator);
	p->filesystem_helpers.module_from_directory = f_map64_make<ffzModule*>(p->persistent_allocator);
	p->pointer_size = 8;

	{
		// initialize constant lookup tables

		p->keyword_from_string = f_map64_make<ffzKeyword>(p->persistent_allocator);
		for (uint i = 0; i < ffzKeyword_COUNT; i++) {
			f_map64_insert(&p->keyword_from_string,
				f_hash64_str(ffz_keyword_to_string((ffzKeyword)i)), (ffzKeyword)i, fMapInsert_DoNotOverride);
		}
	}
	return p;
}


ffzParser* ffz_module_add_parser(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb) {
	ffzParser* parser = f_mem_clone(ffzParser{}, m->alc);
	parser->module = m;
	parser->alc = m->alc;
	parser->self_id = (ffzParserID)f_array_push(&m->parsers, parser);
	parser->source_code = code;
	parser->source_code_filepath = filepath;
	parser->keyword_from_string = &m->project->keyword_from_string;
	parser->error_cb = error_cb;
	parser->module_imports = f_array_make<ffzNodeKeyword*>(parser->alc);
	parser->top_level_nodes = f_array_make<ffzNode*>(parser->alc);
	return parser;
}

void ffz_module_add_top_level_node(ffzModule* m, ffzNode* node) {
	VALIDATE(node->parent == NULL);

	if (m->root_last_child) m->root_last_child->next = node;
	else m->root->first_child = node;

	node->parent = m->root;
	m->root_last_child = node;
}

//bool ffz_module_add_code_string(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb) {
//	//parser->report_error = [](ffzParser* parser, ffzLocRange at, fString error) {
//	//	ffz_log_pretty_error(parser, F_LIT("Syntax error "), at, error, true);
//	//	f_trap();
//	//};
//
//	ffzOk ok = ffz_parse(parser);
//	if (!ok.ok) return false;
//
//	return true;
//}

bool ffz_module_resolve_imports(ffzModule* m, ffzModule*(*module_from_path)(fString path, void* userdata), void* userdata, ffzErrorCallback error_cb) {
	VALIDATE(!m->checked);

	for (uint i = 0; i < m->pending_imports.len; i++) {
		ffzNodeKeyword* import_keyword = m->pending_imports[i];

		ffzNodeOp* import_op = import_keyword->parent;
		f_assert(import_op && import_op->kind == ffzNodeKind_PostRoundBrackets && ffz_get_child_count(import_op) == 1); // TODO

		ffzNode* import_name_node = ffz_get_child(import_op, 0);
		f_assert(import_name_node->kind == ffzNodeKind_StringLiteral); // TODO
		fString import_path = import_name_node->StringLiteral.zero_terminated_string;
			
		fOpt(ffzModule*) imported_module = module_from_path(import_path, userdata);
		if (!imported_module) return false;

		f_map64_insert(&m->imported_modules, (u64)import_op, imported_module);
	}
	
	m->pending_imports.len = 0;
	return true;
}

bool ffz_module_check_single(ffzModule* m, ffzErrorCallback error_cb) {
	VALIDATE(!m->checked);
	m->error_cb = error_cb;

	// We need to first add top-level declarations from all files before proceeding  :EarlyTopLevelDeclarations
	//for (uint i = 0; i < module->parsers.len; i++) {
	//	ffzParser* parser = module->parsers[i];
	//
	//	if (!ffz_instanceless_check(module, parser->root, false).ok) {
	//		return false;
	//	}
	//}
	
	ffzOk ok = add_definitions_to_scope(m, m->root, m->root);
	if (!ok.ok) return false;

	for (ffzNode* n = m->root->first_child; n; n = n->next) {

		// This is a bit dumb way to do this, but right now standalone tags are only checked at top-level. We should
		// probably check them recursively in instanceless_check() or something. :StandaloneTagTopLevel
		if (n->flags & ffzNodeFlag_IsStandaloneTag) {
			f_trap(); //if (!check_tag(module, inst).ok) {
			//	return false;
			//}
			continue;
		}
		
		// TODO: make sure it's a constant declaration or global...
		ffzOk ok = check_node(m, n, NULL, InferFlag_Statement);
		if (!ok.ok) return false;
			
		//if (!ffz_check_toplevel_statement(module, n).ok) {
		//	f_trap();
		//	return false;
		//}
	}

	//for (uint i = 0; i < module->extern_libraries.len; i++) {
	//	fString input = module->extern_libraries[i];
	//	if (input == F_LIT("?")) continue;
	//
	//	if (f_str_cut_start(&input, F_LIT(":"))) {
	//		f_array_push(&project->link_system_libraries, input);
	//	}
	//	else {
	//		f_assert(f_files_path_to_canonical(directory, input, f_temp_alc(), &input));
	//		f_array_push(&project->link_libraries, input);
	//	}
	//}

	m->checked = true;
	f_array_push(&m->project->checkers_dependency_sorted, m);
	return true;
}


ffzModule* ffz_project_add_module_from_filesystem(ffzProject* p, fString directory, fArena* module_arena, ffzErrorCallback error_cb) {
	
	// Canonicalize the path to deduplicate modules that have the same absolute path, but were imported with different path strings.
	if (!f_files_path_to_canonical({}, directory, f_temp_alc(), &directory)) {
		return NULL;
	}

	auto module_exists = f_map64_insert(&p->filesystem_helpers.module_from_directory, f_hash64_str_ex(directory, 0), (ffzModule*)0, fMapInsert_DoNotOverride);
	if (!module_exists.added) {
		return *module_exists._unstable_ptr;
	}
	
	ffzModule* module = ffz_project_add_module(p, module_arena);
	*module_exists._unstable_ptr = module;

	struct FileVisitData {
		fArray(fString) files;
		fString directory;
	} visit;
	visit.files = f_array_make<fString>(f_temp_alc());
	visit.directory = directory;

	if (!f_files_visit_directory(directory,
		[](const fVisitDirectoryInfo* info, void* userptr) -> fVisitDirectoryResult {
			FileVisitData* visit = (FileVisitData*)userptr;

			if (!info->is_directory && f_str_path_extension(info->name) == F_LIT("ffz") && info->name.data[0] != '!') {
				fString filepath = f_str_join_il(visit->files.alc, { visit->directory, F_LIT("\\"), info->name });
				f_array_push(&visit->files, filepath);
			}

			return fVisitDirectoryResult_Continue;
		}, &visit))
	{
		return NULL;
	}

	// hmm... this should be multithreaded. Idk if we should provide a threading abstraction. Probably not??? I feel like
	// threads should be fully left to the user of the library to handle.
	// Or maybe we restrict the threading to a very limited part, i.e. the filesystem helpers.

	for (uint i = 0; i < visit.files.len; i++) {
		fString file_contents;
		f_assert(f_files_read_whole(visit.files[i], &module_arena->alc, &file_contents));

		ffzParser* parser = ffz_module_add_parser(module, file_contents, visit.files[i], error_cb);
		ffzOk ok = ffz_parse(parser);

		// so... each ffzNode needs to be part of a Parser. Why? because we have a
		// local index for the nodes that is used to check local variable usage.
		
		// but what if you want to generate your own nodes?
		// hmm, but the error reporting procedures expect source code and source file.
		// let's just say for now, there is always a parser.
		

		// What we could then do is have a queue for top-level nodes that need to be (re)checked.
		// When expanding polymorph nodes, push those nodes to the end of the queue. Or if the
		// user wants to modify the tree, they can push the modified nodes to the end of the queue
		// to be re-checked.

		for (uint i = 0; i < parser->top_level_nodes.len; i++) {
			ffz_module_add_top_level_node(module, parser->top_level_nodes[i]);
		}

		f_array_push_n(&module->pending_imports, parser->module_imports.slice);

		if (!ok.ok) return NULL;

		//if (!ffz_module_add_code_string(module, file_contents, visit.files[i], error_cb)) {
		//	return NULL;
		//}
	}
	
	return module;
}
