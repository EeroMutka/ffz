
// The checker checks if the program is correct, and in doing so,
// computes and caches information about the program, such as which declarations
// identifiers are pointing to, what types do expressions have, constant evaluation, and so on.
// If the c succeeds, the program is valid and should compile with no errors.

#define F_INCLUDE_OS
#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include "tracy/tracy/Tracy.hpp"

#define TRY(x) { if ((x).ok == false) return ffzOk{false}; }

#define OPT(ptr) ptr

static void report_module_error(ffzNode* node, fString msg) {
	ffzModule* m = ffz_module_of_node(node);
	m->error.node = node;
	m->error.message = msg;
	m->error.source = node->loc_source;
	m->error.location = node->loc;
	//f_trap();
}

#define ERR(node, fmt, ...) { \
	report_module_error(node, f_aprint(ffz_module_of_node(node)->alc, fmt, __VA_ARGS__)); \
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

	// TODO: make it return the default value instead
	InferFlag_TypeMeansZeroValue = 1 << 5, // `int` will mean "the zero value of int" instead of "the type int"

	// We only allow undefined values in variable (not parameter) declarations.
	InferFlag_AllowUndefinedValues = 1 << 6,
};

// ------------------------------

static bool is_basic_type_size(u32 size) { return size == 1 || size == 2 || size == 4 || size == 8; }
//static void print_constant(ffzProject* p, fWriter* w, ffzConstant* constant);
static ffzOk check_node(ffzModule* c, ffzNode* node, OPT(ffzType*) require_type, InferFlags flags);

// ------------------------------

ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, enum_type->hash);
	f_hasher_add(&h, value);
	return f_hasher_end(&h);
}



ffzNodeHash ffz_hash_node(ffzNode* node) {
	return (ffzNodeHash)node;
	//fHasher h = f_hasher_begin();
	//f_hasher_add(&h, node->local_id);
	//f_hasher_add(&h, node->source_id);
	//f_hasher_add(&h, node->module_id);
	//return f_hasher_end(&h);
}

ffzConstantHash ffz_hash_constant(ffzConstant constant) {
	fHasher h = f_hasher_begin();
	// The type must be hashed into the constant, because otherwise i.e. `u64(0)` and `false` would have the same hash!
	f_hasher_add(&h, constant.type->hash);
	switch (constant.type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Pointer: { f_trap(); } break;

		//case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: {
		ffzNode* node = constant.data->node;
		f_hasher_add(&h, ffz_hash_expression(node));
	} break;

		//case ffzTypeTag_PolyRecord: // fallthrough
	case ffzTypeTag_Record: { f_trap(); } break;

	case ffzTypeTag_Slice: { f_trap(); } break;
	case ffzTypeTag_FixedArray: {
		for (u32 i = 0; i < (u32)constant.type->FixedArray.length; i++) {
			ffzConstantData elem_data = ffz_constant_fixed_array_get(constant, i);
			ffzConstant elem = { constant.type->FixedArray.elem_type, &elem_data };
			f_hasher_add(&h, ffz_hash_constant(elem));
		}
	} break;

	case ffzTypeTag_Module: { f_hasher_add(&h, (u64)constant.data->module->self_id); } break;
	case ffzTypeTag_Type: { f_hasher_add(&h, constant.data->type->hash); } break;
	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Float: {
		f_hasher_add(&h, constant.data->_uint); // TODO: u128
	} break;
	default: f_trap();
	}
	return f_hasher_end(&h);
}

ffzPolymorphHash ffz_hash_polymorph(ffzPolymorph poly) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, ffz_hash_expression(poly.poly_def));
	for (uint i = 0; i < poly.parameters.len; i++) {
		f_hasher_add(&h, ffz_hash_constant(poly.parameters[i]));
	}
	return f_hasher_end(&h);
}

FFZ_CAPI ffzExpressionHash ffz_hash_expression(ffzNode* node) {
	if (node->is_instantiation_root_of_poly != FFZ_POLYMORPH_ID_NONE) {
		ffzPolymorph polymorph = ffz_module_of_node(node)->polymorphs[node->is_instantiation_root_of_poly];
		return ffz_hash_polymorph(polymorph); // @speed: store the hash this in ffzPolymorph itself
	}
	return ffz_hash_node(node);
}

u64 ffz_hash_definition_path(ffzDefinitionPath path) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, f_hash64_str(path.name));
	if (path.parent_scope) {
		f_hasher_add(&h, ffz_hash_node(path.parent_scope));
	}
	return f_hasher_end(&h);
}

ffzConstantData* ffz_zero_value_constant() {
	const static ffzConstantData zeroes = {};
	return (ffzConstantData*)&zeroes;
}

static ffzConstantData* make_constant(ffzModule* c) {
	// TODO: we should deduplicate constants
	ffzConstantData* constant = f_mem_clone(*ffz_zero_value_constant(), c->alc);
	return constant;
}

static ffzConstantData* make_constant_int(ffzModule* c, u64 _uint) {
	ffzConstantData* constant = make_constant(c);
	constant->_uint = _uint;
	return constant;
}

inline ffzCheckInfo ffzCheckInfo_default() { ffzCheckInfo x = {}; /*x.instantiation_root_of_poly = FFZ_POLYMORPH_ID_NONE; */return x; }

ffzCheckInfo make_type_constant(ffzModule* c, ffzType* type) {
	ffzCheckInfo out = ffzCheckInfo_default();
	out.type = c->type_type;
	out.constant = make_constant(c);
	out.constant->type = type;
	return out;
}

ffzType* ffz_ground_type(ffzConstantData* constant, ffzType* type) {
	return type->tag == ffzTypeTag_Type ? constant->type : type;
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
	default: return false;
	}
}

bool ffz_type_is_comparable(ffzType* type) {
	return ffz_type_is_integer(type->tag) || type->tag == ffzTypeTag_Enum || ffz_type_is_float(type->tag);
}

void print_type(ffzProject* p, fWriter* w, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Invalid: { f_print(w, "<invalid>"); } break;
	case ffzTypeTag_Raw: { f_print(w, "raw"); } break;
	case ffzTypeTag_Undefined: { f_print(w, "<undefined>"); } break;
	case ffzTypeTag_Type: { f_print(w, "<type>"); } break;
	case ffzTypeTag_PolyExpr: { f_print(w, "<polymorphic expression>"); } break;
	case ffzTypeTag_Module: { f_print(w, "<module>"); } break;
	case ffzTypeTag_Bool: { f_print(w, "bool"); } break;
	case ffzTypeTag_Pointer: {
		f_print(w, "^");
		print_type(p, w, type->Pointer.pointer_to);
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
		fString name = ffz_get_parent_decl_pretty_name(s);
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
		fString name = ffz_get_parent_decl_pretty_name(n);
		if (name.len > 0) {
			f_prints(w, name);
		}
		else {
			f_print(w, "[anonymous enum defined at line:~u32, col:~u32]", n->loc.start.line_num, n->loc.start.column_num);
		}
	} break;
	case ffzTypeTag_Record: {
		ffzNodeRecord* n = type->unique_node;
		fString name = ffz_get_parent_decl_pretty_name(n);
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
		print_type(p, w, type->Slice.elem_type);
	} break;
	case ffzTypeTag_String: {
		f_print(w, "string");
	} break;
	case ffzTypeTag_FixedArray: {
		f_print(w, "[~i32]", type->FixedArray.length);
		print_type(p, w, type->FixedArray.elem_type);
	} break;
	default: f_assert(false);
	}
}

// Print the constant as valid FFZ source code
static void print_constant(ffzProject* p, fWriter* w, ffzConstant constant) {
	switch (constant.type->tag) {
	//ffzTypeTag_Raw,
	//ffzTypeTag_Undefined,
	case ffzTypeTag_Type: { print_type(p, w, constant.data->type); } break;
	//case ffzTypeTag_PolyExpr:
	//case ffzTypeTag_Module:

	case ffzTypeTag_Bool: { f_print(w, constant.data->_bool ? "true" : "false"); } break;
	case ffzTypeTag_Pointer: {
		f_trap(); // TODO
	} break;
	
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Sint: { f_print_int(w, constant.data->_sint, 10); } break; // :PackConstantTroubles
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Uint: { f_print_uint(w, constant.data->_uint, 10); } break; // :PackConstantTroubles
	case ffzTypeTag_Float: {
		if (constant.type->size == 4)      f_print_float(w, constant.data->_f32);
		else if (constant.type->size == 8) f_print_float(w, constant.data->_f64);
		else f_trap();
	} break;  // :PackConstantTroubles
	case ffzTypeTag_Proc: {
		f_trap(); // TODO
	} break;
	case ffzTypeTag_Record: {
		f_trap(); // TODO
	} break;
	case ffzTypeTag_Enum: {
		f_trap(); // TODO
	} break;
	case ffzTypeTag_Slice: {
		f_trap(); // TODO
	} break;
	case ffzTypeTag_String: {
		f_trap(); // TODO
	} break;
	case ffzTypeTag_FixedArray: {
		f_trap(); // TODO
	} break;
	default: f_trap();
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
	print_type(p, builder.w, type);
	return builder.buffer.slice;
}

fOpt(ffzNode*) ffz_get_parent_proc(ffzNode* node) {
	for (node = node->parent; node; node = node->parent) {
		if (node->checked.type && node->checked.type->tag == ffzTypeTag_Proc) return node;
	}
	return NULL;
}

//fOpt(ffzNode*) ffz_get_scope(ffzNode* node) {
//	for (node = node->parent; node; node = node->parent) {
//		f_assert(node->has_checked);
//
//		if (node->kind == ffzNodeKind_Scope) return node;
//		//if (node->kind == ffzNodeKind_Enum) return node;
//		if (node->kind == ffzNodeKind_Record) return node;
//		if (node->checked.type && node->checked.type->tag == ffzTypeTag_Proc) return node;
//	}
//	return NULL;
//}

bool ffz_decl_is_local_variable(ffzNodeOpDeclare* decl) {
	f_assert(decl->has_checked);
	return decl->checked.is_local_variable;
}

bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl) {
	if (decl->Op.left->Identifier.is_constant) return false;
	return decl->parent->parent == NULL;
}

fOpt(ffzNodeIdentifier*) ffz_find_definition_in_scope(ffzNode* scope, fString name) {
	ffzDefinitionPath def_path = { scope, name };

	ffzNodeIdentifier** def = f_map64_get(&ffz_module_of_node(scope)->definition_map, ffz_hash_definition_path(def_path));
	return def ? *def : NULL;
}

bool ffz_constant_is_zero(ffzConstantData constant) {
	u8 zeroes[sizeof(ffzConstantData)] = {};
	return memcmp(&constant, zeroes, sizeof(ffzConstantData)) == 0;
}

ffzFieldHash ffz_hash_field(ffzType* type, fString member_name) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, type->hash);
	f_hasher_add(&h, f_hash64_str(member_name));
	return f_hasher_end(&h);
}

static ffzOk add_fields_to_field_from_name_map(ffzModule* c, ffzType* root_type, ffzType* parent_type, u32 offset_from_root = 0) {
	for (u32 i = 0; i < parent_type->record_fields.len; i++) {
		ffzField* field = &parent_type->record_fields[i];
		ffzTypeRecordFieldUse* field_use = f_mem_clone(ffzTypeRecordFieldUse{ field->type, offset_from_root + field->offset }, c->alc);

		auto insertion = f_map64_insert(&c->field_from_name_map, ffz_hash_field(root_type, field->name), field_use, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			ERR(field->decl, "`~s` is already declared before inside (TODO: print struct name) (TODO: print line)", field->name);
		}

		if (field->decl) {
			if (ffz_get_tag(c->project, field->decl, ffzKeyword_using)) {
				TRY(add_fields_to_field_from_name_map(c, root_type, field->type));
			}
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
	if (node->checked.type->tag != ffzTypeTag_Type) ERR(node, "Expected a type, but got a value.");
	return FFZ_OK;
}

static ffzOk verify_is_constant(ffzModule* c, ffzNode* node) {
	f_assert(!node->checked.is_undefined);
	if (node->checked.constant == NULL) ERR(node, "Expression is not constant, but constant was expected.");
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
	//F_HITS(_c, 196);
	if (!type_is_a_bit_by_bit(c->project, received, expected)) {
		ERR(node, "~c\n    received: ~s\n    expected: ~s",
			message, ffz_type_to_string(c->project, received), ffz_type_to_string(c->project, expected));
	}
	return { true };
}

//static ffzOk error_not_an_expression(ffzModule* c, ffzNode* node) {
//	ERR(node, "Expected an expression, but got a statement or a procedure call with no return value.");
//}

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

static ffzOk check_argument_list(ffzModule* c, ffzNode* node, fSlice(ffzField) fields, fOpt(ffzCheckInfo*) record_literal) {
	bool all_fields_are_constant = true;
	fSlice(ffzConstantData) field_constants;
	if (record_literal) field_constants = f_make_slice_garbage<ffzConstantData>(fields.len, c->alc);

	fSlice(bool) field_is_given_a_value = f_make_slice<bool>(fields.len, false, c->alc);

	bool has_used_named_argument = false;
	u32 i = 0;
	for FFZ_EACH_CHILD(arg, node) {
		ffzNode* arg_value = arg;

		if (arg->kind == ffzNodeKind_Declare) {
			has_used_named_argument = true;
			arg_value = arg->Op.right;
			fString name = ffz_decl_get_name(arg);

			if (!ffz_find_field_by_name(fields, name, &i)) {
				ERR(arg, "Parameter named \"~s\" does not exist.", name);
			}
			
			if (field_is_given_a_value[i]) ERR(arg, "A value has been already given for parameter \"~s\".", name);
		}
		else if (has_used_named_argument) ERR(arg, "Using an unnamed argument after a named argument is not allowed.");

		if (i >= fields.len) ERR(arg, "Received too many arguments.");

		TRY(check_node(c, arg_value, fields[i].type, 0));

		if (record_literal) {
			if (arg_value->checked.constant) field_constants[i] = *arg_value->checked.constant;
			else all_fields_are_constant = false;
		}

		field_is_given_a_value[i] = true;
		i++;
	}

	for (uint i = 0; i < fields.len; i++) {
		if (!field_is_given_a_value[i]) {
			if (!fields[i].has_default_value) {
				ERR(node, "An argument is missing for \"~s\".", fields[i].name);
			}
			if (record_literal) {
				field_constants[i] = fields[i].default_value;
			}
		}
	}

	if (record_literal && all_fields_are_constant) {
		record_literal->constant = make_constant(c);
		record_literal->constant->record_fields = field_constants;
	}

	return FFZ_OK;
}

//static bool uint_is_subtype_of(ffzType* type, ffzType* subtype_of) {
//	if (ffz_type_is_unsigned_integer(type->tag) && ffz_type_is_unsigned_integer(subtype_of->tag) && type->size <= subtype_of->size) return true;
//	return false;
//}

static ffzOk check_two_sided(ffzModule* c, ffzNode* left, ffzNode* right, OPT(ffzType*)* out_type) {
	// Infer expressions, such as  `x: u32(1) + 50`  or  x: `2 * u32(552)`
	
	InferFlags child_flags = InferFlag_TypeIsNotRequired_ | InferFlag_CacheOnlyIfGotType;
	
	for (int i = 0; i < 2; i++) {
		TRY(check_node(c, left, NULL, child_flags));
		TRY(check_node(c, right, NULL, child_flags));
		if (left->checked.type && right->checked.type) break;
		
		child_flags = 0;
		if (!left->checked.type && right->checked.type) {
			TRY(check_node(c, left, right->checked.type, child_flags));
			break;
		}
		else if (!right->checked.type && left->checked.type) {
			TRY(check_node(c, right, left->checked.type, child_flags));
			break;
		}
		continue;
	}

	OPT(ffzType*) result = NULL;
	if (right->checked.type && left->checked.type) {
		if (type_is_a_bit_by_bit(c->project, left->checked.type, right->checked.type))      result = right->checked.type;
		else if (type_is_a_bit_by_bit(c->project, right->checked.type, left->checked.type)) result = left->checked.type;
		else {
			ERR(left->parent, "Types do not match.\n    left:    ~s\n    right:   ~s",
				ffz_type_to_string(c->project, left->checked.type), ffz_type_to_string(c->project, right->checked.type));
		}
	}
	*out_type = result;
	return { true };
}

u32 ffz_get_encoded_constant_size(ffzType* type) {
	return ffz_type_is_integer(type->tag) ? type->size : sizeof(ffzConstantData);
}

ffzConstantData ffz_constant_fixed_array_get(ffzConstant array, u32 index) {
	u32 elem_size = ffz_get_encoded_constant_size(array.type->FixedArray.elem_type);
	ffzConstantData result = *ffz_zero_value_constant();
	if (array.data->fixed_array_elems) memcpy(&result, (u8*)array.data->fixed_array_elems + index*elem_size, elem_size);
	return result;
}

ffzOk try_to_add_definition_to_scope(ffzModule* c, fOpt(ffzNode*) scope, ffzNodeIdentifier* def) {
	fString name = def->Identifier.name;

	for (ffzNode* test_scope = scope; test_scope; test_scope = test_scope->parent) {
		ffzDefinitionPath path = { test_scope, name };
		ffzNodeIdentifier** existing = f_map64_get(&c->definition_map, ffz_hash_definition_path(path));
		if (existing) {
			ERR(def, "`~s` is already declared before (at line: ~u32)", name, (*existing)->loc.start.line_num);
		}
	}

	ffzDefinitionPath path = { scope, name };
	f_map64_insert(&c->definition_map, ffz_hash_definition_path(path), def, fMapInsert_DoNotOverride);
	return FFZ_OK;
}

ffzOk add_possible_definition_to_scope(ffzModule* c, fOpt(ffzNode*) scope, fOpt(ffzNode*) node) {
	if (node && node->kind == ffzNodeKind_Declare) {
		// NOTE: we need to do this check here, because this function can be called on the node BEFORE having checked the node.
		if (node->Op.left->kind != ffzNodeKind_Identifier) {
			ERR(node->Op.left, "The left-hand side of a declaration must be an identifier.");
		}
		TRY(try_to_add_definition_to_scope(c, scope, node->Op.left));
	}
	return FFZ_OK;
}

ffzOk add_possible_definitions_to_scope(ffzModule* c, fOpt(ffzNode*) scope, ffzNode* from_children) {
	for FFZ_EACH_CHILD(n, from_children) {
		TRY(add_possible_definition_to_scope(c, scope, n));
	}
	return FFZ_OK;
}

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
	default: return type->size;
	}
}

ffzTypeHash ffz_hash_type(ffzProject* p, ffzType* type) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, type->tag);
	
	switch (type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Undefined: break;
	case ffzTypeTag_Module: break;
	case ffzTypeTag_Type: break;
	case ffzTypeTag_String: break;
	case ffzTypeTag_PolyExpr: break;

	case ffzTypeTag_Pointer: { f_hasher_add(&h, ffz_hash_type(p, type->Pointer.pointer_to)); } break;

	case ffzTypeTag_Proc:     // fallthrough
	case ffzTypeTag_Enum:     // fallthrough   :EnumFieldsShouldNotContributeToTypeHash
	case ffzTypeTag_Record: {
		// If the node is an instantiation of a polymorphic definition, we need to use the polymorph hash instead of the
		// unique node hash, because different modules can contain an identical polymorphic instantiation.
		f_hasher_add(&h, ffz_hash_expression(type->unique_node));
	} break;

	case ffzTypeTag_Slice: { f_hasher_add(&h, ffz_hash_type(p, type->Slice.elem_type)); } break;
	case ffzTypeTag_FixedArray: {
		f_hasher_add(&h, ffz_hash_type(p, type->FixedArray.elem_type));
		f_hasher_add(&h, type->FixedArray.length);
	} break;

	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Float: {
		// Note: we don't want record types to hash in the size of the type, because of :delayed_check_record
		f_hasher_add(&h, type->size);
		break;
	}
	default: f_trap();
	}
	//if (h == 9900648307514547948) f_trap();
	return f_hasher_end(&h);
}

ffzType* ffz_make_type(ffzModule* c, ffzType type_desc) {
	//F_HITS(_c, 35);
	//F_HITS(_c1, 416);
	type_desc.checker_id = c->self_id;
	type_desc.hash = ffz_hash_type(c->project, &type_desc);
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

// NOTE: default_value is copied
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
	field.default_value = default_value != NULL ? *default_value : *ffz_zero_value_constant();
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
		ffzRecordBuilder b = ffz_record_builder_init(c, out, 2);
		ffz_record_builder_add_field(&b, F_LIT("ptr"), ffz_make_type_ptr(c, elem_type), ffz_zero_value_constant(), {});
		ffz_record_builder_add_field(&b, F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), ffz_zero_value_constant(), {});
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

static ffzOk check_post_round_brackets(ffzModule* c, ffzNode* node, ffzType* require_type, InferFlags flags, ffzCheckInfo* result) {
	ffzNode* left = node->Op.left;
	bool fall = true;
	if (left->kind == ffzNodeKind_Keyword) {
		ffzKeyword keyword = left->Keyword.keyword;
		if (ffz_keyword_is_bitwise_op(keyword)) {
			if (ffz_get_child_count(node) != (keyword == ffzKeyword_bit_not ? 1 : 2)) {
				ERR(node, "Incorrect number of arguments to a bitwise operation.");
			}
			
			ffzNode* first = ffz_get_child(node, 0);
			if (keyword == ffzKeyword_bit_not) {
				TRY(check_node(c, first, require_type, flags));
				node->checked.type = first->checked.type;
			}
			else {
				ffzNode* second = ffz_get_child(node, 1);
				TRY(check_two_sided(c, first, second, &result->type));
			}
			
			if (result->type && !is_basic_type_size(result->type->size)) {
				ERR(node, "bitwise operations only allow sizes of 1, 2, 4 or 8; Received: ~u32", result->type->size);
			}
			
			fall = false;
		}
		else if (keyword == ffzKeyword_size_of || keyword == ffzKeyword_align_of) {
			if (ffz_get_child_count(node) != 1) {
				ERR(node, "Incorrect number of arguments to ~s.", ffz_keyword_to_string(keyword));
			}

			ffzNode* first = ffz_get_child(node, 0);
			TRY(check_node(c, first, NULL, 0));
			ffzType* type = ffz_ground_type(first->checked.constant, first->checked.type);
			
			result->type = ffz_builtin_type(c, ffzKeyword_uint);
			result->constant = make_constant_int(c, keyword == ffzKeyword_align_of ? type->align : type->size);
			fall = false;
		}
		else if (keyword == ffzKeyword_import) {
			result->type = c->module_type;
			result->constant = make_constant(c);

			// `ffz_module_resolve_imports` already makes sure that the import node is part of a declaration
			ffzNode* import_decl = node->parent;
			result->constant->module = *f_map64_get(&c->module_from_import_decl, (u64)import_decl);
			fall = false;
		}
	}
	if (fall) {
		TRY(check_node(c, left, NULL, 0));
		ffzType* left_type = left->checked.type;

		if (left_type->tag == ffzTypeTag_Type) {
			// ffzType casting
			result->type = left->checked.constant->type;
			if (ffz_get_child_count(node) != 1) ERR(node, "Incorrect number of arguments in type initializer.");

			ffzNode* arg = ffz_get_child(node, 0);
			
			// check the expression, but do not enforce the type inference, as the type inference rules are
			// more strict than a manual cast. For example, an integer cannot implicitly cast to a pointer, but when inside a cast it can.
			
			TRY(check_node(c, arg, result->type, InferFlag_NoTypesMatchCheck));
			
			result->is_undefined = arg->checked.type->tag == ffzTypeTag_Type && arg->checked.constant->type->tag == ffzTypeTag_Undefined;
			if (!(flags & InferFlag_AllowUndefinedValues) && result->is_undefined) {
				ERR(arg, "Invalid place for an undefined value. Undefined values are only allowed in variable declarations.");
			}
			
			if (!result->is_undefined && /*!ffz_type_is_pointer_ish(result->type->tag) && */
				!ffz_type_is_pointer_ish(arg->checked.type->tag)) {
				// the following shouldn't be allowed:
				// #foo: false
				// #bar: uint(&foo)
				// This is because given a constant integer, we want to be able to trivially ask what its value is.
				// However, the other way is allowed (i.e. ^int(0))
				
				// NOTE: when casting integer constants to pointer constants, we use the integer constant directly. This is ok,
				// because their layouts are identical. :ReinterpretIntegerConstantAsPointer
				result->constant = arg->checked.constant;
			}

			if (!result->is_undefined && !type_can_be_casted_to(c->project, arg->checked.type, result->type)) {
				TRY(check_types_match(c, node, arg->checked.type, result->type, "Invalid type cast:"));
			}
		}
		else {
			// Procedure call
			if (left_type->tag != ffzTypeTag_Proc) {
				ERR(left, "Attempted to call a non-procedure (~s)", ffz_type_to_string(c->project, left_type));
			}

			result->type = left_type->Proc.return_type;
			TRY(check_argument_list(c, node, left_type->Proc.in_params, NULL));
		}
	}
	return FFZ_OK;
}

static ffzOk check_initializer(ffzModule* c, ffzType* type, ffzNode* node, ffzCheckInfo* result) {
	result->type = type;

	if (type->tag == ffzTypeTag_Proc) {
		result->constant = make_constant(c);
		result->constant->node = node;
	}
	else if (type->tag == ffzTypeTag_FixedArray) {
		// Array literal
		ffzType* elem_type = type->FixedArray.elem_type;

		fArray(ffzNode*) elems = f_array_make<ffzNode*>(f_temp_alc());
		bool all_elems_are_constant = true;

		for FFZ_EACH_CHILD(n, node) {
			TRY(check_node(c, n, elem_type, 0));
			f_array_push(&elems, n);
			all_elems_are_constant = all_elems_are_constant && n->checked.constant != NULL;
		}
		
		s32 expected = type->FixedArray.length;
		if (expected < 0) { // make a new type if [?]
			result->type = ffz_make_type_fixed_array(c, elem_type, (s32)elems.len);
		}
		else if (elems.len != expected) {
			ERR(node, "Incorrect number of array initializer arguments. Expected ~u32, got ~u32", expected, (u32)elems.len);
		}

		if (all_elems_are_constant) {
			u32 elem_size = ffz_get_encoded_constant_size(elem_type);
			void* ptr = f_mem_alloc(elem_size * elems.len, c->alc);
			for (uint i = 0; i < elems.len; i++) {
				memcpy((u8*)ptr + elem_size * i, elems[i]->checked.constant, elem_size);
			}
			result->constant = make_constant(c);
			result->constant->fixed_array_elems = ptr;
		}
	}
	else if (type->tag == ffzTypeTag_Record || ffz_type_is_slice_ish(type->tag)) {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) {
			ERR(node, "Union initialization with {} is not currently supported.");
		}
		
		// TODO: see what happens if you try to declare normally `123: 5215`
		TRY(check_argument_list(c, node, type->record_fields, result));
	}
	else {
		ERR(node, "{}-initializer is not allowed for `~s`.", ffz_type_to_string(c->project, type));
	}
	return FFZ_OK;
}


//
// When you instantiate a polymorphic thing from another module, you yoink the nodes into your own module.
// The thing is, just copy-pasting code from a module into your own module won't work, because of identifiers to nodes
// defined inside the module. So these identifiers need to be patched with a ModuleName.xxx prefix.
// 
// we need to get the import name of the node's module inside `m`.
// There should be only one import name for a module.
// 
struct InstantiateDeepCopyPolyContext {
	ffzModule* copy_into_module;
	fMap64(ffzNode*) poly_param_name_to_generated_constant_ident;
	ffzNode* root;
};

// Deep copies the polymorphic expression while replacing identifiers to
// polymorphic parameters to generated constants
static void instantiate_deep_copy_poly(InstantiateDeepCopyPolyContext* ctx, ffzCursor cursor) {
	fOpt(ffzNode*) old_node = ffz_get_node_at_cursor(&cursor);
	if (!old_node) return;

	ffzNode* new_node = ffz_clone_node(ctx->copy_into_module, old_node);
	ffz_replace_node(&cursor, new_node);

	
	// OLD COMMENT, DOESN'T MATTER ANYMORE:
	// First copy special children, then copy regular children.
	// This distinction matters, because in case of a procedure, we want to first recurse into the procedure type and copy the parameters,
	// and only after that recurse into the procedure body. This way the parameter's `local_id` will be smaller than the usage sites,
	// and we can still use this field to check for use-before-define errors.

	if (ffz_node_is_operator(new_node->kind)) {
		instantiate_deep_copy_poly(ctx, ffz_cursor_op_left(new_node));
		instantiate_deep_copy_poly(ctx, ffz_cursor_op_right(new_node));
	}
	else switch (new_node->kind) {
	case ffzNodeKind_Blank: break;
	case ffzNodeKind_Identifier: {

		fOpt(ffzNode**) new_name = f_map64_get(&ctx->poly_param_name_to_generated_constant_ident, f_hash64_str(new_node->Identifier.name));
		if (new_name) {
			new_node->Identifier.name        = (*new_name)->Identifier.name;
			new_node->Identifier.pretty_name = (*new_name)->Identifier.pretty_name;
		}
		else {
			ffzModule* original_module = ffz_module_of_node(ctx->root);
			if (original_module != ctx->copy_into_module) {
				// hmm... ffz_find_definition doesn't work here because we haven't checked the node tree yet.
				// Actually we can use this to our advantage! ffz_find_definition will give us the definition if HAS been checked,
				// and thus not part of the poly tree, and will fail if hasn't been checked.

				//ffzProject* p = ctx->copy_into_module->project;

				fOpt(ffzNodeIdentifier*) def = ffz_find_definition(old_node);
				if (def) {
					// add module prefix if the definition is not part of the poly tree (and thus is a global)
					
					ffzNode* accessor = ffz_new_node(ctx->copy_into_module, ffzNodeKind_MemberAccess);
					ffz_replace_node(&cursor, accessor);

					ffzNode* module_ident = ffz_new_node(ctx->copy_into_module, ffzNodeKind_Identifier);
					module_ident->Identifier.name = ffz_get_import_name(ctx->copy_into_module, original_module);
					f_assert(module_ident->Identifier.name.len > 0);

					accessor->Op.left = module_ident; module_ident->parent = accessor;
					accessor->Op.right = new_node; new_node->parent = accessor;
				}
			}
		}
	} break;
	case ffzNodeKind_PolyExpr: {
		instantiate_deep_copy_poly(ctx, ffz_cursor_poly_expr(new_node));
	} break;
	case ffzNodeKind_Keyword: break;
	case ffzNodeKind_ThisDot: break;
	case ffzNodeKind_ProcType: {
		instantiate_deep_copy_poly(ctx, ffz_cursor_proc_type_out_parameter(new_node));
	} break;
	case ffzNodeKind_Record: break;
	case ffzNodeKind_Enum: break;
	case ffzNodeKind_Return: {
		instantiate_deep_copy_poly(ctx, ffz_cursor_ret_value(new_node));
	} break;
	case ffzNodeKind_If: {
		instantiate_deep_copy_poly(ctx, ffz_cursor_if_condition(new_node));
		instantiate_deep_copy_poly(ctx, ffz_cursor_if_true_scope(new_node));
		instantiate_deep_copy_poly(ctx, ffz_cursor_if_false_scope(new_node));
	} break;
	case ffzNodeKind_For: {
		for (int i = 0; i < 3; i++) instantiate_deep_copy_poly(ctx, ffz_cursor_for_header_stmt(new_node, i));
		instantiate_deep_copy_poly(ctx, ffz_cursor_for_scope(new_node));
	} break;
	case ffzNodeKind_Scope: break;
	case ffzNodeKind_IntLiteral: break;
	case ffzNodeKind_StringLiteral: break;
	case ffzNodeKind_FloatLiteral: break;
	default: f_trap();
	}

	// Deep copy tags
	{
		ffzNode** link_to_next = &new_node->first_tag;
		while (*link_to_next != NULL) {
			ffzCursor cursor = { new_node, link_to_next };
			instantiate_deep_copy_poly(ctx, cursor);
			
			link_to_next = &ffz_get_node_at_cursor(&cursor)->next;
		}
	}

	// Deep copy main children
	{
		ffzNode** link_to_next = &new_node->first_child;
		while (*link_to_next != NULL) {
			ffzCursor cursor = { new_node, link_to_next };
			instantiate_deep_copy_poly(ctx, cursor);
			
			link_to_next = &ffz_get_node_at_cursor(&cursor)->next;
		}
	}
	//ffzNode** link_to_next = &new_node->first_child;
	//for (ffzNode* child = new_node->first_child; child; child = child->next) {
	//	instantiate_deep_copy_poly(ctx, ffzCursor{ new_node, link_to_next });
	//	child = *link_to_next;
	//
	//	link_to_next = &child->next;
	//}
}


FFZ_CAPI ffzNode* ffz_constant_to_node(ffzModule* m, ffzNode* parent, ffzConstant constant) {
	// For simplicity, let's print the constant and parse it. I think we should change this to a direct translation. @speed
	fString constant_string = ffz_constant_to_string(m->project, constant);
	
	ffzParseResult result = ffz_parse_node(m, constant_string, F_LIT("<CONSTANT>"));
	f_assert(result.node != NULL);
	result.node->parent = parent;
	return result.node;
}

static ffzOk check_post_square_brackets(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* left = node->Op.left;
	TRY(check_node(c, left, NULL, 0));

	ffzCheckInfo left_chk = left->checked;
	if (left_chk.type->tag == ffzTypeTag_PolyExpr) {
		fArray(ffzConstant) params = f_array_make<ffzConstant>(c->alc);

		for FFZ_EACH_CHILD(arg, node) {
			TRY(check_node(c, arg, NULL, 0));
			TRY(verify_is_constant(c, arg));
			f_array_push(&params, ffzConstant{ arg->checked.type, arg->checked.constant });
		}

		ffzPolymorph poly = {};
		poly.poly_def = left_chk.constant->node;
		poly.parameters = params.slice;

		ffzPolymorphHash hash = ffz_hash_polymorph(poly);
		auto entry = f_map64_insert(&c->poly_from_hash, hash, (ffzPolymorphID)0, fMapInsert_DoNotOverride);
		if (entry.added) {
			*entry._unstable_ptr = (ffzPolymorphID)c->polymorphs.len;
			f_array_push(&c->polymorphs, poly);
		}
		
		ffzNode* poly_def_parent = poly.poly_def->parent;
		ffzPolymorphID poly_id = *entry._unstable_ptr;
		
		//  Example:
		// 
		// #Foo: poly[T] T(1) + T(2)
		// #Bar: Foo[int]
		// 
		//  Will be expanded into:
		// 
		// #Foo: poly[T] T(1) + T(2)
		// #Bar: Foo__poly_0
		// #Foo__poly_0_T: int
		// #Foo__poly_0: Foo__poly_0_T(1) + Foo__poly_0_T(2)
		//
		
		// Modify node from polymorph instantiator into an identifier. :InPlaceNodeModification
		
		fString pretty_name = ffz_node_to_string(c->project, node, true, c->alc);
		node->kind = ffzNodeKind_Identifier;
		node->Identifier = {};
		node->Identifier.name = f_aprint(c->alc, "~s__poly_~u32", ffz_decl_get_name(poly_def_parent), poly_id);
		node->Identifier.pretty_name = pretty_name;
//		if (node->Identifier.name == F_LIT("Array__poly_0")) f_trap();
		f_assert(pretty_name.len > 0);
	//	if (node == (void*)0x0000020000080d60) f_trap();
		
		//node->Identifier.chk_definition = def;

		if (entry.added) {
			InstantiateDeepCopyPolyContext deep_copy_ctx = {};
			deep_copy_ctx.copy_into_module = c;
			deep_copy_ctx.poly_param_name_to_generated_constant_ident = f_map64_make<ffzNode*>(f_temp_alc());

			// add parameters as decls
			for (u32 i = 0; i < poly.parameters.len; i++) {
				fString param_name = ffz_get_child(poly.poly_def, i)->Identifier.name;
				fString expanded_name = f_aprint(c->alc, "~s__poly_~u32_~s", ffz_decl_get_name(poly_def_parent), poly_id, param_name);

				ffzNode* arg_decl = ffz_new_node(c, ffzNodeKind_Declare);
				ffzNode* arg_def = ffz_new_node(c, ffzNodeKind_Identifier);
				
				arg_def->parent = arg_decl;
				arg_def->Identifier.name = expanded_name;
				arg_def->Identifier.pretty_name = param_name;
				arg_def->Identifier.is_constant = true;
				
				f_map64_insert(&deep_copy_ctx.poly_param_name_to_generated_constant_ident, f_hash64_str(param_name), arg_def);

				arg_decl->Op.left = arg_def;
				arg_decl->Op.right = ffz_constant_to_node(c, arg_decl, poly.parameters[i]);
				
				TRY(ffz_module_add_top_level_node_(c, arg_decl));
			}

			ffzNode* inst_decl = ffz_new_node(c, ffzNodeKind_Declare);
			//inst_decl->source_id = node->source_id;
			
			ffzNode* inst_def = ffz_new_node(c, ffzNodeKind_Identifier);
			//inst_def->source_id = node->source_id;
			inst_def->parent = inst_decl;
			inst_def->Identifier.name        = node->Identifier.name;
			inst_def->Identifier.pretty_name = node->Identifier.pretty_name;
			inst_def->Identifier.is_constant = true;

			// hmm... there still could be a name collision.
			// Imagine you expand the program once, then add another polymorph instance, then compile the program again.
			// The newly expanded names will collide with the previously expanded names!!
			// Maybe we could do a smart thing and include the hash in the name, then look if that identifier already exists and rewrite it if it does.
			// That would allow for the full roundtrip multiple times.

			ffzNode* poly_expr = poly.poly_def->PolyExpr.expr;
			deep_copy_ctx.root = poly_expr;
			
			inst_decl->Op.left = inst_def;
			inst_decl->Op.right = poly_expr;
			
			instantiate_deep_copy_poly(&deep_copy_ctx, ffz_cursor_op_right(inst_decl));

			ffzNode* poly_expr_new = inst_decl->Op.right;
			poly_expr_new->is_instantiation_root_of_poly = poly_id;
			
			// hmm.....   poly_from_hash checker is different for the different modules.
			// so even though the hashes are the same, it still uniquely adds it every time.
			//if (inst_decl->Op.right == (void*)0x0000020000080d90) f_trap();
			//if (inst_decl->Op.right == (void*)0x00000200000a12d0) f_trap();

			// NOTE: we're pushing a top-level node to the end of the root node while iterating through them at the bottom of
			// the callstack. But that's totally fine.
			TRY(ffz_module_add_top_level_node_(c, inst_decl));
			
			// lastly, check the instantiated declaration and take the results.

			TRY(check_node(c, inst_decl, NULL, InferFlag_Statement));
			*result = poly_expr_new->checked;
		}
		else {
			fOpt(ffzNodeIdentifier*) def = ffz_find_definition(node);
			*result = def->parent->Op.right->checked;
		}
	}
	else {
		// Array subscript
		
		if (!(left_chk.type->tag == ffzTypeTag_Slice || left_chk.type->tag == ffzTypeTag_FixedArray)) {
			ERR(left,
				"Expected an array, a slice, or a polymorphic expression before [].\n    received: ~s",
				ffz_type_to_string(c->project, left_chk.type));
		}

		ffzType* elem_type = left_chk.type->tag == ffzTypeTag_Slice ? left_chk.type->Slice.elem_type : left_chk.type->FixedArray.elem_type;

		u32 child_count = ffz_get_child_count(node);
		if (child_count == 1) {
			ffzNode* index = ffz_get_child(node, 0);

			TRY(check_node(c, index, NULL, 0));

			if (!ffz_type_is_integer(index->checked.type->tag)) {
				ERR(index, "Incorrect type with a slice index; should be an integer.\n    received: ~s",
					ffz_type_to_string(c->project, index->checked.type));
			}

			result->type = elem_type;
		}
		else if (child_count == 2) {
			ffzNode* lo = ffz_get_child(node, 0);
			ffzNode* hi = ffz_get_child(node, 1);

			if (lo->kind != ffzNodeKind_Blank) {
				TRY(check_node(c, lo, NULL, 0));
				if (!ffz_type_is_integer(lo->checked.type->tag)) ERR(lo, "Expected an integer.");
			}
			if (hi->kind != ffzNodeKind_Blank) {
				TRY(check_node(c, hi, NULL, 0));
				if (!ffz_type_is_integer(hi->checked.type->tag)) ERR(hi, "Expected an integer.");
			}

			result->type = ffz_make_type_slice(c, elem_type);
		}
		else {
			ERR(node, "Incorrect number of arguments inside subscript/slice operation.");
		}
	}
	return FFZ_OK;
}

fString ffz_get_import_name(ffzModule* m, ffzModule* imported_module) {
	fOpt(ffzNode**) module_import_decl = f_map64_get(&m->import_decl_from_module, (u64)imported_module);
	if (module_import_decl) {
		return (*module_import_decl)->Op.left->Identifier.name;
	}
	return {};
}

static ffzOk check_member_access(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* left = node->Op.left;
	ffzNode* right = node->Op.right;
	if (right->kind != ffzNodeKind_Identifier) {
		ERR(node, "Invalid member access; the right side was not an identifier.");
	}

	//F_HITS(_c, 955);
	// Maybe we shouldn't even have the 'in' keyword?
	// since in  V3{x = 1, y = 2, z = 3}  the fields are added to the namespace, why not in
	// MyAdderProc{ ret a + b }  as well? I guess the main thing is "where does this variable come from?"
	// In struct instance it's obvious (since you can't declare/assign to your own variables!)

	fString member_name = right->Identifier.name;
	fString lhs_name = {};
	bool found = false;
	if (left->kind == ffzNodeKind_Identifier && left->Identifier.name == F_LIT("in")) {
		lhs_name = F_LIT("procedure input parameter list");

		fOpt(ffzNode*) parent_proc = ffz_get_parent_proc(node);
		f_assert(parent_proc != NULL);
		ffzType* proc_type = parent_proc->checked.type;
		
		if (parent_proc->Op.left->kind == ffzNodeKind_ProcType) {
			ERR(left, "`in` is not allowed when the procedure parameters are accessible by name.");
		}

		for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
			ffzField* param = &proc_type->Proc.in_params[i];
			if (param->name == member_name) {
				found = true;
				result->type = param->type;
			}
		}
	}
	else {
		TRY(check_node(c, left, NULL, 0));
		ffzType* left_type = left->checked.type;
		ffzConstantData* left_constant = left->checked.constant;
		
		if (left_type->tag == ffzTypeTag_Module) {
			ffzModule* left_module = left_constant->module;
			lhs_name = ffz_get_import_name(c, left_module);

			fOpt(ffzNode*) def = ffz_find_definition_in_scope(left_module->root, member_name);
			if (def && def->parent->kind == ffzNodeKind_Declare) {
				*result = def->parent->checked;
				found = true;
			}
		}
		else if (left_type->tag == ffzTypeTag_Type && left_constant->type->tag == ffzTypeTag_Enum) {
			ffzType* enum_type = left_constant->type;
			lhs_name = ffz_type_to_string(c->project, enum_type);

			ffzModule* enum_type_module = c->project->checkers[enum_type->checker_id];
			ffzFieldHash member_key = ffz_hash_field(left_constant->type, member_name);

			if (u64* val = f_map64_get(&enum_type_module->enum_value_from_name, member_key)) {
				result->type = left_constant->type;
				result->constant = make_constant_int(c, *val);
				found = true;
			}
		}
		else {
			ffzType* dereferenced_type = left_type->tag == ffzTypeTag_Pointer ? left_type->Pointer.pointer_to : left_type;
			lhs_name = ffz_type_to_string(c->project, dereferenced_type);

			ffzTypeRecordFieldUse field;
			if (ffz_type_find_record_field_use(c->project, dereferenced_type, member_name, &field)) {
				result->type = field.type;
				found = true;
			}
		}
	}

	if (!found) ERR(right, "Declaration not found for '~s' inside '~s'", member_name, lhs_name);

	return FFZ_OK;
}

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
//			ERR(name, "Top-level declaration must be constant, or @*global, but got a non-constant.");
//		}
//	} break;
//	default: ERR(node, "Top-level node must be a declaration, but got: ~s", ffz_node_kind_to_string(node->kind));
//	}
//	return { true };
//}

static ffzOk check_tag(ffzModule* c, ffzNode* tag) {
	TRY(check_node(c, tag, NULL, InferFlag_TypeMeansZeroValue));
	TRY(verify_is_constant(c, tag));
	if (tag->checked.type->tag != ffzTypeTag_Record) {
		ERR(tag, "Tag was not a struct literal.", "");
	}

	if (tag->checked.type == ffz_builtin_type(c, ffzKeyword_extern)) {
		fString library = tag->checked.constant->record_fields[0].string_zero_terminated;
		f_map64_insert(&c->extern_libraries, f_hash64_str(library), library, fMapInsert_DoNotOverride);
	}
	
	auto tags = f_map64_insert(&c->all_tags_of_type, tag->checked.type->hash, {}, fMapInsert_DoNotOverride);
	if (tags.added) *tags._unstable_ptr = f_array_make<ffzNode*>(c->alc);
	f_array_push(tags._unstable_ptr, tag);
	return FFZ_OK;
}

static ffzType* ffz_make_pseudo_record_type(ffzModule* c) {
	ffzType t = { ffzTypeTag_Record };
	t.unique_node = ffz_new_node(c, ffzNodeKind_Record); // NOTE: ffz_hash_node looks at the hash of the unique node for record types
	return ffz_make_type(c, t);
}

FFZ_CAPI ffzModule* ffz_project_add_module(ffzProject* p, fArena* module_arena) {
	fAllocator* alc = &module_arena->alc;

	ffzModule* c = f_mem_clone(ffzModule{}, alc);	
	c->project = p;
	c->self_id = (ffzModuleID)f_array_push(&p->checkers, c);
	c->alc = alc;
	c->checked_identifiers = f_map64_make_raw(0, c->alc);
	c->definition_map = f_map64_make<ffzNodeIdentifier*>(c->alc);
	c->field_from_name_map = f_map64_make<ffzTypeRecordFieldUse*>(c->alc);
	c->enum_value_from_name = f_map64_make<u64>(c->alc);
	c->enum_value_is_taken = f_map64_make<ffzNode*>(c->alc);
	c->import_decl_from_module = f_map64_make<ffzNode*>(c->alc);
	c->module_from_import_decl = f_map64_make<ffzModule*>(c->alc);
	c->type_from_hash = f_map64_make<ffzType*>(c->alc);
	c->pending_import_keywords = f_array_make<ffzNode*>(c->alc);
	c->all_tags_of_type = f_map64_make<fArray(ffzNode*)>(c->alc);
	c->poly_from_hash = f_map64_make<ffzPolymorphID>(c->alc);
	c->polymorphs = f_array_make<ffzPolymorph>(c->alc);
	c->extern_libraries = f_map64_make<fString>(c->alc);
	
	c->root = ffz_new_node(c, ffzNodeKind_Scope);
	//c->root = f_mem_clone(ffzNode{}, c->alc); // :NewNode
	//c->root->kind = ffzNodeKind_Scope;
	//c->root->module_id = c->self_id;

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

		ffzConstantData* zero = ffz_zero_value_constant();
		{
			ffzType* string = ffz_make_type(c, { ffzTypeTag_String });
			c->builtin_types[ffzKeyword_string] = string;

			ffzRecordBuilder b = ffz_record_builder_init(c, c->builtin_types[ffzKeyword_string], 2);
			ffz_record_builder_add_field(&b, F_LIT("ptr"), ffz_make_type_ptr(c, ffz_builtin_type(c, ffzKeyword_u8)), zero, {});
			ffz_record_builder_add_field(&b, F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), zero, {});
			ffz_record_builder_finish(&b);
		}

		{
			c->builtin_types[ffzKeyword_extern] = ffz_make_pseudo_record_type(c);
			ffzRecordBuilder b = ffz_record_builder_init(c, c->builtin_types[ffzKeyword_extern], 1);
			ffz_record_builder_add_field(&b, F_LIT("library"), ffz_builtin_type(c, ffzKeyword_string), NULL, {});
			ffz_record_builder_add_field(&b, F_LIT("name_prefix"), ffz_builtin_type(c, ffzKeyword_string), zero, {});
			ffz_record_builder_finish(&b);
		}
		
		c->builtin_types[ffzKeyword_using] = ffz_make_pseudo_record_type(c);
		c->builtin_types[ffzKeyword_global] = ffz_make_pseudo_record_type(c);
		c->builtin_types[ffzKeyword_module_defined_entry] = ffz_make_pseudo_record_type(c);
		c->builtin_types[ffzKeyword_build_option] = ffz_make_pseudo_record_type(c);
	}

	return c;
}

fOpt(ffzNode*) ffz_this_dot_get_assignee(ffzNodeThisValueDot* dot) {
	for (ffzNode* p = dot->parent; p; p = p->parent) {
		if (p->checked.type && p->checked.type->tag == ffzTypeTag_Proc) break;
		if (p->kind == ffzNodeKind_Assign) {
			return p->Op.left;
		}
	}
	return NULL;
}

fOpt(ffzConstantData*) ffz_get_tag_of_type(ffzProject* p, ffzNode* node, ffzType* tag_type) {
	for (ffzNode* tag_n = node->first_tag; tag_n; tag_n = tag_n->next) {
		f_assert(tag_n->has_checked);
		if (type_is_a_bit_by_bit(p, tag_n->checked.type, tag_type)) {
			return tag_n->checked.constant;
		}
	}
	return NULL;
}

fOpt(ffzConstantData*) ffz_get_tag(ffzProject* p, ffzNode* node, ffzKeyword tag) {
	ffzType* type = ffz_builtin_type(ffz_module_of_node(node), tag);
	return ffz_get_tag_of_type(p, node, type);
}

static ffzOk post_check_enum(ffzModule* c, ffzNode* node) {
	ffzType* enum_type = node->checked.constant->type;

	TRY(add_possible_definitions_to_scope(c, node, node));

	fArray(ffzTypeEnumField) fields = f_array_make<ffzTypeEnumField>(c->alc);
	
	for FFZ_EACH_CHILD(n, node) {
		if (n->kind != ffzNodeKind_Declare) ERR(n, "Expected a declaration; got: [~s]", ffz_node_kind_to_string(n->kind));

		// NOTE: Infer the declaration from the enum internal type!
		TRY(check_node(c, n, enum_type->Enum.internal_type, InferFlag_Statement));

		u64 val = n->checked.constant->_uint;
		
		ffzFieldHash key = ffz_hash_field(enum_type, ffz_decl_get_name(n));
		f_map64_insert(&c->enum_value_from_name, key, val);

		f_array_push(&fields, ffzTypeEnumField{ ffz_decl_get_name(n), val });

		auto val_taken = f_map64_insert(&c->enum_value_is_taken, ffz_hash_enum_value(enum_type, val), n, fMapInsert_DoNotOverride);
		if (!val_taken.added) {
			fString taken_by = ffz_decl_get_name((*val_taken._unstable_ptr));
			ERR(n->Op.right, "The enum value `~u64` is already taken by `~s`.", val, taken_by);
		}
	}
	
	enum_type->Enum.fields = fields.slice;
	return FFZ_OK;
}

static ffzOk check_proc_type(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {
	ffzType proc_type = { ffzTypeTag_Proc };
	proc_type.unique_node = node;
	proc_type.size = c->project->pointer_size;
	
	//F_HITS(_c, 3);
	ffzNode* parameter_scope = node->parent->kind == ffzNodeKind_PostCurlyBrackets ? node->parent : node;
	TRY(add_possible_definitions_to_scope(c, parameter_scope, node));

	fArray(ffzField) in_parameters = f_array_make<ffzField>(c->alc);
	for FFZ_EACH_CHILD(param, node) {
		if (param->kind != ffzNodeKind_Declare) ERR(param, "Expected a declaration.");
		
		TRY(check_node(c, param, NULL, InferFlag_Statement));
		
		// Since the parameter is a runtime value, we need to access the rhs of it to
		// distinguish between a type expression and a default value
		ffzNode* rhs = param->Op.right;
		
		ffzField field = {};
		field.decl = param;
		field.name = ffz_decl_get_name(param);

		if (rhs->checked.type->tag == ffzTypeTag_Type) {
			field.type = rhs->checked.constant->type;
		} else {
			field.type = rhs->checked.type;
			field.has_default_value = true;
			field.default_value = *rhs->checked.constant;
		}

		f_array_push(&in_parameters, field);
	}
	proc_type.Proc.in_params = in_parameters.slice;

	ffzNode* out_param = node->ProcType.out_parameter;
	if (out_param) {
		TRY(check_node(c, out_param, NULL, 0));
		TRY(verify_is_type_expression(c, out_param));
		proc_type.Proc.return_type = out_param->checked.constant->type;
	}
	
	if (ffz_get_tag(c->project, node->parent, ffzKeyword_extern)) {
		// if it's an extern proc, then don't turn it into a type type!!
		result->type = ffz_make_type(c, proc_type);
		result->constant = make_constant(c);
		result->constant->node = node;
	}
	else {
		*result = make_type_constant(c, ffz_make_type(c, proc_type));
	}
	return FFZ_OK;
}

// TODO: take in the ident's module instead of ffzProject and assert that it's correct
fOpt(ffzNodeIdentifier*) ffz_find_definition(ffzNodeIdentifier* ident) {
	for (fOpt(ffzNode*) scope = ident; scope; scope = scope->parent) {
		fOpt(ffzNodeIdentifier*) def = ffz_find_definition_in_scope(scope, ident->Identifier.name);
		if (def) {
			return def;
		}
	}
	return NULL;
}

static ffzOk check_identifier(ffzModule* c, ffzNodeIdentifier* node, ffzCheckInfo* result) {
	fString name = node->Identifier.name;
//	if (name == F_LIT("foo")) f_trap();

	fOpt(ffzNodeIdentifier*) def = ffz_find_definition(node);
	if (def == NULL) {
		ERR(node, "Definition not found for an identifier: \"~s\"", name);
	}
	
	bool def_comes_before_this = def->has_checked;
	//node->Identifier.chk_definition = def;

	ffzNode* decl = def->parent;
	f_assert(decl->kind == ffzNodeKind_Declare);

	// TODO: check for circular definitions
	//fMapInsertResult circle_chk = f_map64_insert_raw(&c->checked_identifiers, ffz_hash_node_inst(inst), NULL, fMapInsert_DoNotOverride);
	//if (!circle_chk.added) ERR(inst, "Circular definition!"); // TODO: elaborate

	TRY(check_node(c, decl, NULL, InferFlag_Statement));
	*result = decl->checked;

	if (def != node && ffz_decl_is_variable(decl) && !def_comes_before_this /*decl->local_id > node->local_id*/) {
		ERR(node, "Variable is being used before it is declared.");
	}
	
	return FFZ_OK;
}

static ffzOk check_return(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* return_val = node->Return.value;
	
	ffzNode* proc = ffz_get_parent_proc(node);
	f_assert(proc->checked.type);
	
	fOpt(ffzType*) ret_type = proc->checked.type->Proc.return_type;
	if (!return_val && ret_type) ERR(node, "Expected a return value, but got none.");
	if (return_val && !ret_type) ERR(return_val, "Expected no return value, but got one.");
	
	if (return_val) {
		TRY(check_node(c, return_val, ret_type, 0));
	}
	return FFZ_OK;
}

static ffzOk check_assign(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* lhs = node->Op.left;
	ffzNode* rhs = node->Op.right;
	
	TRY(check_node(c, lhs, NULL, 0));
	
	bool eat_expression = ffz_node_is_keyword(lhs, ffzKeyword_Eater);
	if (!eat_expression) f_assert(ffz_type_is_concrete(lhs->checked.type));

	TRY(check_node(c, rhs, lhs->checked.type, 0));
	
	TRY(check_types_match(c, rhs, rhs->checked.type, lhs->checked.type, "Incorrect type with assignment:"));
	
	//ffzNode* parent = node->parent;
	//bool is_code_scope = parent->kind == ffzNodeKind_Scope || parent->kind == ffzNodeKind_ProcType;
	// TODO: check lvalue
	//if (is_code_scope && lhs->checked.type->tag != ffzTypeTag_Raw && !is_lvalue(c, lhs)) {
	//	ERR(lhs, "Attempted to assign to a non-assignable value.");
	//}
	return FFZ_OK;
}

static ffzOk check_pre_square_brackets(ffzModule* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* rhs = node->Op.right;
	TRY(check_node(c, rhs, NULL, 0));
	TRY(verify_is_type_expression(c, rhs));
	
	if (ffz_get_child_count(node) == 0) {
		*result = make_type_constant(c, ffz_make_type_slice(c, rhs->checked.constant->type));
	}
	else if (ffz_get_child_count(node) == 1) {
		ffzNode* child = ffz_get_child(node, 0);
		s32 length = -1;
		if (child->kind == ffzNodeKind_IntLiteral) {
			length = (s32)child->IntLiteral.value;
		}
		else if (ffz_node_is_keyword(child, ffzKeyword_QuestionMark)) {}
		else ERR(node, "Unexpected value inside the brackets of an array type; expected an integer literal or `?`");
	
		ffzType* array_type = ffz_make_type_fixed_array(c, rhs->checked.constant->type, length);
		*result = make_type_constant(c, array_type);
	}
	else ERR(node, "Unexpected value inside the brackets of an array type; expected an integer literal or `_`");
	return FFZ_OK;
}

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
	ZoneScoped;
	
	for (ffzNode* tag_n = node->first_tag; tag_n; tag_n = tag_n->next) {
		TRY(check_tag(c, tag_n));
	}

	//F_HITS(_c, 357);

	ffzCheckInfo result = ffzCheckInfo_default();

	switch (node->kind) {
	case ffzNodeKind_Declare: {
//		if (node->loc.start.line_num == 11) f_trap();
		ffzNode* lhs = node->Op.left;
		ffzNode* rhs = node->Op.right;
		if (lhs->kind != ffzNodeKind_Identifier) ERR(lhs, "The left-hand side of a declaration must be an identifier.");
		
		// When checking a procedure type, we can't know the procedure type until we have checked all its children.
		// so checking a declaration shouldn't require the parent to be checked.
		// How can we know if this declaration is a local variable or not?
		// (passing this information down the callstack isn't possible, because `check_identifier` breaks that context information).
		//
		// We need to use `get_scope` to determine if we're in a procedure scope.
		// `get_scope` however requires the parent to be checked. So only do this when we know it's not a parameter.
		// For all other cases, except for parameters, the parent has already been checked.

//		F_HITS(__c, 489);

		bool is_parameter = ffz_decl_is_parameter(node);
		bool is_local = false;
		bool is_global_variable = ffz_decl_is_global_variable(node);

		if (!is_parameter && !lhs->Identifier.is_constant) {
			// check if this declaration is a local variable

			for (ffzNode* n = node->parent; n; n = n->parent) {
				f_assert(n->has_checked);

				if (n->kind == ffzNodeKind_Enum) break;
				if (n->kind == ffzNodeKind_Record) break;
				
				if (n->kind == ffzNodeKind_Scope) continue;
				if (n->kind == ffzNodeKind_If) continue;
				if (n->kind == ffzNodeKind_For) continue;
				is_local = n->checked.type && n->checked.type->tag == ffzTypeTag_Proc;
				break;
			}
		}

		InferFlags rhs_flags = 0;
		if (is_local || is_global_variable) {
			rhs_flags |= InferFlag_AllowUndefinedValues;
		}
		
		// sometimes we want to pass `require_type` down to the rhs, namely with enum field declarations
		TRY(check_node(c, rhs, require_type, rhs_flags));

		result = rhs->checked; // Declarations cache the value of the right-hand side
		result.is_local_variable = is_local;

		
		if (is_local || is_parameter || is_global_variable) {
			if (is_parameter) {
				// if the parameter is a type expression, then this declaration has that type
				result.type = ffz_ground_type(result.constant, result.type);
			}

			result.constant = NULL; // runtime variables shouldn't store the constant value that the rhs expression might have

			if (!ffz_type_is_concrete(result.type)) {
				ERR(node, "Variable has a non-concrete type, the type being ~s.", ffz_type_to_string(c->project, result.type));
			}
		}
		
		if (!is_local && !rhs->checked.is_undefined) {
			TRY(verify_is_constant(c, rhs));
		}

		// The lhs identifier will recurse into this same declaration,
		// at which point we should have cached the result for this node to cut the loop.
		//delayed_check_decl_lhs = true;
	} break;

	case ffzNodeKind_Assign: { TRY(check_assign(c, node, &result)); } break;
	case ffzNodeKind_Return: { TRY(check_return(c, node, &result)); } break;

	case ffzNodeKind_Scope: {
		if (require_type == NULL) {
			TRY(add_possible_definitions_to_scope(c, node, node));
			// post-check the scope
		}
		else {
			// type-inferred initializer
			TRY(check_initializer(c, require_type, node, &result));
		}
	} break;

	case ffzNodeKind_PolyExpr: {
		// When you say `#foo: poly[T] T(100)`, you're declaring foo as a new type, more specifically a polymorphic expression type.
		// It's the same thing as if foo was i.e. a struct type.
		
		for FFZ_EACH_CHILD(n, node) {
			if (n->kind != ffzNodeKind_Identifier) ERR(n, "Expected a polymorphic parameter definition.");
			TRY(try_to_add_definition_to_scope(c, node, n));
		}

		if (node->parent->kind != ffzNodeKind_Declare) {
			ERR(node, "Polymorphic expression must be the right-hand side of a constant declaration.");
		}

		ffzType type = { ffzTypeTag_PolyExpr };
		result.type = ffz_make_type(c, type);
		result.constant = make_constant(c);
		result.constant->node = node;
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		TRY(check_post_round_brackets(c, node, require_type, flags, &result));
	} break;

	case ffzNodeKind_If: break; // post-check
	case ffzNodeKind_For: break; // post-check
	
	case ffzNodeKind_Enum: {
		ffzNode* type_node = node->Enum.internal_type;
		TRY(check_node(c, type_node, NULL, 0));

		if (type_node->checked.type->tag != ffzTypeTag_Type || !ffz_type_is_integer(type_node->checked.constant->type->tag)) {
			ERR(type_node, "Invalid enum type; expected an integer.");
		}

		ffzType enum_type = { ffzTypeTag_Enum };
		enum_type.Enum.internal_type = type_node->checked.constant->type;
		enum_type.size = enum_type.Enum.internal_type->size;
		enum_type.unique_node = node;

		// :EnumFieldsShouldNotContributeToTypeHash
		// Note that we're making the enum type pointer BEFORE populating all of the fields
		result = make_type_constant(c, ffz_make_type(c, enum_type));
		
		// The children are post-checked
	} break;
	
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

	case ffzNodeKind_ThisDot: {
		fOpt(ffzNode*) assignee = ffz_this_dot_get_assignee(node);
		if (assignee == NULL) {
			ERR(node, "this-value-dot must be used within an assignment, but no assignment was found.");
		}
		// When checking assignments, the assignee/lhs is always checked first, so this should be ok.
		result.type = assignee->checked.type;
	} break;

	case ffzNodeKind_Identifier: { TRY(check_identifier(c, node, &result)); } break;

	case ffzNodeKind_Record: {
		ffzType struct_type = { ffzTypeTag_Record };
		struct_type.unique_node = node;
		//delayed_check_record = true;
		result = make_type_constant(c, ffz_make_type(c, struct_type));
	} break;
	
	case ffzNodeKind_FloatLiteral: {
		if (require_type && require_type->tag == ffzTypeTag_Float) {
			result.type = require_type;
			result.constant = make_constant(c);
			if (require_type->size == 4)      result.constant->_f32 = (f32)node->FloatLiteral.value;
			else if (require_type->size == 8) result.constant->_f64 = node->FloatLiteral.value;
			else f_trap();
		}
	} break;

	case ffzNodeKind_IntLiteral: {
		if (!(flags & InferFlag_TypeIsNotRequired_)) {
			result.type = ffz_builtin_type(c, ffzKeyword_uint);
			result.constant = make_constant_int(c, node->IntLiteral.value);
		}
	} break;

	case ffzNodeKind_StringLiteral: {
		// pointers aren't guaranteed to be valid / non-null, but optional pointers are expected to be null.
		result.type = ffz_builtin_type(c, ffzKeyword_string);
		result.constant = make_constant(c);
		result.constant->string_zero_terminated = node->StringLiteral.zero_terminated_string;
	} break;

	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_UnaryPlus: {
		ffzNode* rhs = node->Op.right;
		TRY(check_node(c, rhs, require_type, flags));

		// hmm... the TypeIsNotRequired flag is a bit weird. It makes us not trust that we got a type.
		if (rhs->checked.type) {
			if (!ffz_type_is_integer(rhs->checked.type->tag) && !ffz_type_is_float(rhs->checked.type->tag)) {
				ERR(rhs, "Incorrect arithmetic type; should be an integer or a float.\n    received: ~s",
					ffz_type_to_string(c->project, rhs->checked.type));
			}
		}
		result.type = rhs->checked.type;
	} break;
	
	case ffzNodeKind_PreSquareBrackets: { TRY(check_pre_square_brackets(c, node, &result)); } break;
	
	case ffzNodeKind_PointerTo: {
		ffzNode* rhs = node->Op.right;
		TRY(check_node(c, rhs, NULL, 0));
		TRY(verify_is_type_expression(c, rhs));
		result = make_type_constant(c, ffz_make_type_ptr(c, rhs->checked.constant->type));
	} break;
	
	case ffzNodeKind_ProcType: { TRY(check_proc_type(c, node, &result)); } break;
	
	case ffzNodeKind_PostCurlyBrackets: {
		ffzNode* left = node->Op.left;
		TRY(check_node(c, left, NULL, 0));
		TRY(verify_is_type_expression(c, left));
		TRY(check_initializer(c, left->checked.constant->type, node, &result));
	} break;
	
	case ffzNodeKind_PostSquareBrackets: {
		TRY(check_post_square_brackets(c, node, &result));
	} break;
	
	case ffzNodeKind_MemberAccess: { TRY(check_member_access(c, node, &result)); } break;
	
	case ffzNodeKind_LogicalNOT: {
		result.type = ffz_builtin_type(c, ffzKeyword_bool);
		TRY(check_node(c, node->Op.right, result.type, 0));
	} break;
	
	case ffzNodeKind_LogicalAND: // fallthrough
	case ffzNodeKind_LogicalOR: {
		result.type = ffz_builtin_type(c, ffzKeyword_bool);
		TRY(check_node(c, node->Op.left, result.type, 0));
		TRY(check_node(c, node->Op.right, result.type, 0));
	} break;
	
	case ffzNodeKind_AddressOf: {
		ffzNode* rhs = node->Op.right;
		TRY(check_node(c, rhs, NULL, 0));
		result.type = ffz_make_type_ptr(c, rhs->checked.type);
	} break;
	
	case ffzNodeKind_Dereference: {
		ffzNode* lhs = node->Op.left;
		TRY(check_node(c, lhs, NULL, 0));
		if (lhs->checked.type->tag != ffzTypeTag_Pointer) ERR(node, "Attempted to dereference a non-pointer.");
		result.type = lhs->checked.type->Pointer.pointer_to;
	} break;
	
	case ffzNodeKind_Equal: case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
	case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater: case ffzNodeKind_GreaterOrEqual: {
		OPT(ffzType*) type;
		TRY(check_two_sided(c, node->Op.left, node->Op.right, &type));
		f_assert(type); // TODO
		
		bool is_equality_check = node->kind == ffzNodeKind_Equal || node->kind == ffzNodeKind_NotEqual;
		if (ffz_type_is_comparable(type) || (is_equality_check && ffz_type_is_comparable_for_equality(type))) {
			result.type = ffz_builtin_type(c, ffzKeyword_bool);
		}
		else {
			ERR(node, "Operator '~s' is not defined for type '~s'",
				ffz_node_kind_to_op_string(node->kind), ffz_type_to_string(c->project, type));
		}
	} break;
	
	case ffzNodeKind_Add: case ffzNodeKind_Sub: case ffzNodeKind_Mul:
	case ffzNodeKind_Div: case ffzNodeKind_Modulo: {
		OPT(ffzType*) type;
		TRY(check_two_sided(c, node->Op.left, node->Op.right, &type));
		f_assert(type); // TODO
		
		if (node->kind == ffzNodeKind_Modulo) {
			if (type && !ffz_type_is_integer(type->tag)) {
				ERR(node, "Incorrect type with modulo operator; expected an integer.\n    received: ~s", ffz_type_to_string(c->project, type));
			}
		}
		else {
			if (type && !ffz_type_is_integer(type->tag) && !ffz_type_is_float(type->tag)) {
				ERR(node, "Incorrect arithmetic type; expected an integer or a float.\n    received: ~s", ffz_type_to_string(c->project, type));
			}
		}
	
		result.type = type;
	} break;

	default: f_trap();
	}

	if (flags & InferFlag_Statement) {
		// NOTE: we cache the types of declarations even though they are statements.
		if (node->kind != ffzNodeKind_Declare && result.type) {
			ERR(node, "Expected a statement or a declaration, but got an expression.\n  HINT: An expression can be turned into a statement, i.e. `_ = foo()`");
		}
	}
	else {
		if (node->kind == ffzNodeKind_Declare) ERR(node, "Expected an expression, but got a declaration.");
		
		if (!(flags & InferFlag_TypeIsNotRequired_)) { // type is required
			if (!result.type) {
				ERR(node, "Expression has no type, or it cannot be inferred.");
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
					memcpy(&src, &result.constant->_uint, result.type->size);
					memcpy(&masked, &result.constant->_uint, require_type->size);
					
					bool src_is_negative = ffz_type_is_signed_integer(result.type->tag) && integer_is_negative(&src, result.type->size);
					bool masked_is_negative = ffz_type_is_signed_integer(require_type->tag) && integer_is_negative(&masked, require_type->size);
					
					bool ok = masked == src && (src_is_negative == masked_is_negative) && (ffz_type_is_signed_integer(require_type->tag) || !src_is_negative);
					if (!ok) {
						if (ffz_type_is_signed_integer(result.type->tag)) {
							ERR(node, "Constant type-cast failed; value '~u64' can't be represented in type '~s'.", src, ffz_type_to_string(c->project, require_type));
						} else {
							ERR(node, "Constant type-cast failed; value '~u64' can't be represented in type '~s'.", src, ffz_type_to_string(c->project, require_type));
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

	//if (result.constant == (void*)0x000002000005f430) f_trap();
	if (result.type && result.type->tag == ffzTypeTag_Type && (flags & InferFlag_TypeMeansZeroValue)) {
		result.type = ffz_ground_type(result.constant, result.type);
		result.constant = ffz_zero_value_constant();
	}
	

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


	// post-check. The idea is to check the children AFTER we have cached the CheckInfo for this node.
	// This gives more freedom to the children to use utilities, such as get_scope() which requires the parents to be checked.
	
	if (!child_already_fully_checked_us) {
		switch (node->kind) {
		case ffzNodeKind_Scope: {
			if (require_type == NULL) {
				for FFZ_EACH_CHILD(n, node) {
					TRY(check_node(c, n, NULL, flags));
				}
			}
		} break;
		
		case ffzNodeKind_If: {
			TRY(check_node(c, node->If.condition, ffz_builtin_type(c, ffzKeyword_bool), 0));
			TRY(check_node(c, node->If.true_scope, NULL, InferFlag_Statement));

			fOpt(ffzNode*) false_scope = node->If.false_scope;
			if (false_scope) {
				TRY(check_node(c, false_scope, NULL, InferFlag_Statement));
			}
		} break;
		
		case ffzNodeKind_Enum: {
			TRY(post_check_enum(c, node));
		} break;
		
		case ffzNodeKind_For: {
			TRY(add_possible_definition_to_scope(c, node, node->For.header_stmts[0]));

			for (u32 i = 0; i < 3; i++) {
				fOpt(ffzNode*) stmt = node->For.header_stmts[i];
				if (stmt) {
					if (i == 1) {
						TRY(check_node(c, stmt, ffz_builtin_type(c, ffzKeyword_bool), 0));
					}
					else {
						TRY(check_node(c, stmt, NULL, InferFlag_Statement));
					}
				}
			}

			TRY(check_node(c, node->For.scope, NULL, InferFlag_Statement));
		} break;
		
		case ffzNodeKind_Declare: {
			TRY(check_node(c, node->Op.left, NULL, 0));
		} break;

		case ffzNodeKind_Record: {
			//if (node->loc.start.line_num == 254) f_trap();
			TRY(add_possible_definitions_to_scope(c, node, node));

			// Add the record fields only after the type has been registered in the cache. This is to avoid
			// infinite loops when checking.

			// IMPORTANT: We're modifying the type AFTER it was created and hash-deduplicated. So, the things we modify must not change the type hash!
			ffzType* record_type = result.constant->type;
			ffzRecordBuilder b = ffz_record_builder_init(c, record_type, 0);

			for FFZ_EACH_CHILD(n, node) {
				if (n->kind != ffzNodeKind_Declare) ERR(n, "Expected a declaration.");
				fString name = ffz_decl_get_name(n);

				TRY(check_node(c, n, NULL, InferFlag_Statement));
				TRY(verify_is_constant(c, n));

				ffzType* field_type = n->checked.type->tag == ffzTypeTag_Type ? n->checked.constant->type : n->checked.type;
				fOpt(ffzConstantData*) default_value = n->checked.type->tag == ffzTypeTag_Type ? NULL : n->checked.constant;

				ffz_record_builder_add_field(&b, name, field_type, default_value, n);
			}
			TRY(ffz_record_builder_finish(&b));
		} break;

		default:
			if (node->checked.type && node->checked.type->tag == ffzTypeTag_Proc) {
				// ignore extern procs.
				// It's a bit weird how the extern tag turns a type declaration into a value declaration. Maybe this should be changed.
				if (node->kind != ffzNodeKind_ProcType) {
					TRY(add_possible_definitions_to_scope(c, node, node));

					// only check the procedure body when we have a physical procedure instance (not polymorphic)
					// and after the proc type has been cached.

					for FFZ_EACH_CHILD(n, node) {
						TRY(check_node(c, n, NULL, InferFlag_Statement));
					}
				}
			}
		}
	}

	return { true };
}


FFZ_CAPI ffzProject* ffz_init_project(fArena* arena, fString modules_directory) {
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
	p->sources = f_array_make<ffzSource*>(p->persistent_allocator);
	p->checkers_dependency_sorted = f_array_make<ffzModule*>(p->persistent_allocator);
	p->link_libraries = f_array_make<fString>(p->persistent_allocator);
	p->link_system_libraries = f_array_make<fString>(p->persistent_allocator);
	p->filesystem_helpers.module_from_directory = f_map64_make<ffzModule*>(p->persistent_allocator);
	p->pointer_size = 8;

	{
		// initialize constant lookup tables

		p->keyword_from_string = f_map64_make<ffzKeyword>(p->persistent_allocator);
		for (uint i = 1; i < ffzKeyword_COUNT; i++) {
			f_map64_insert(&p->keyword_from_string,
				f_hash64_str(ffz_keyword_to_string((ffzKeyword)i)), (ffzKeyword)i, fMapInsert_DoNotOverride);
		}
	}
	return p;
}


FFZ_CAPI ffzOk ffz_module_add_top_level_node_(ffzModule* m, ffzNode* node) {
	f_assert(node->parent == NULL);
	
	if (m->root_last_child) m->root_last_child->next = node;
	else m->root->first_child = node;

	node->parent = m->root;
	m->root_last_child = node;

	// maybe this shouldn't be in here, and be a separate call?
	TRY(add_possible_definition_to_scope(m, m->root, node));

	return FFZ_OK;
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

FFZ_CAPI ffzOk ffz_module_resolve_imports_(ffzModule* m, ffzModule*(*module_from_path)(fString path, void* userdata), void* userdata) {
	VALIDATE(!m->checked);

	for (uint i = 0; i < m->pending_import_keywords.len; i++) {
		ffzNode* import_keyword = m->pending_import_keywords[i];
		
		ffzNodeOp* import_op = import_keyword->parent;
		f_assert(import_op && import_op->kind == ffzNodeKind_PostRoundBrackets && ffz_get_child_count(import_op) == 1); // TODO: error report

		ffzNode* import_decl = import_op->parent;
		f_assert(import_decl && import_decl->kind == ffzNodeKind_Declare); // TODO: error report

		ffzNode* import_name_node = ffz_get_child(import_op, 0);
		f_assert(import_name_node->kind == ffzNodeKind_StringLiteral); // TODO: error report
		fString import_path = import_name_node->StringLiteral.zero_terminated_string;
			
		fOpt(ffzModule*) imported_module = module_from_path(import_path, userdata);
		if (!imported_module) {
			ERR(import_op, "Imported module contains errors.");
		}

		f_map64_insert(&m->module_from_import_decl, (u64)import_decl, imported_module, fMapInsert_AssertUnique);
		f_map64_insert(&m->import_decl_from_module, (u64)imported_module, import_decl, fMapInsert_AssertUnique); // TODO: error report
	}
	
	m->pending_import_keywords.len = 0;
	return FFZ_OK;
}

FFZ_CAPI ffzOk ffz_module_check_single_(ffzModule* m) {
	ZoneScoped;
	VALIDATE(!m->checked);
	//m->error_cb = error_cb;
	m->error = {};

	ffzCheckInfo checked = ffzCheckInfo_default();
	m->root->has_checked = true;
	m->root->checked = checked;

	for (ffzNode* n = m->root->first_child; n; n = n->next) {

		// This is a bit dumb way to do this, but right now standalone tags are only checked at top-level. We should
		// probably check them recursively in instanceless_check() or something. :StandaloneTagTopLevel
		if (n->flags & ffzNodeFlag_IsStandaloneTag) {
			TRY(check_tag(m, n));
			continue;
		}
		
		// TODO: make sure it's a constant declaration or global...
		TRY(check_node(m, n, NULL, InferFlag_Statement));
	}

	fString* p_library;
	for f_map64_each_raw(&m->extern_libraries, _key, &p_library) {
		fString library = *p_library;
		if (library == F_LIT("?")) continue;
		
		if (f_str_cut_start(&library, F_LIT(":"))) {
			f_array_push(&m->project->link_system_libraries, library);
		}
		else {
			f_assert(f_files_path_to_canonical(m->directory, library, f_temp_alc(), &library)); // TODO: error checking
			f_array_push(&m->project->link_libraries, library);
		}
	}

	m->checked = true;
	f_array_push(&m->project->checkers_dependency_sorted, m);
	return FFZ_OK;
}


FFZ_CAPI fOpt(ffzModule*) ffz_project_add_module_from_filesystem(ffzProject* p, fString directory, fArena* module_arena, ffzError* out_error) {

	// Canonicalize the path to deduplicate modules that have the same absolute path, but were imported with different path strings.
	if (!f_files_path_to_canonical({}, directory, f_temp_alc(), &directory)) {
		return NULL; // TODO: error report
	}

	auto module_exists = f_map64_insert(&p->filesystem_helpers.module_from_directory, f_hash64_str_ex(directory, 0), (ffzModule*)0, fMapInsert_DoNotOverride);
	if (!module_exists.added) {
		return *module_exists._unstable_ptr;
	}
	
	ffzModule* module = ffz_project_add_module(p, module_arena);
	*module_exists._unstable_ptr = module;
	module->directory = directory;

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
				fString filepath = f_str_join(visit->files.alc, visit->directory, F_LIT("\\"), info->name);
				f_array_push(&visit->files, filepath);
			}

			return fVisitDirectoryResult_Continue;
		}, &visit))
	{
		return NULL; // TODO: error report
	}

	// hmm... this should be multithreaded. Idk if we should provide a threading abstraction. Probably not??? I feel like
	// threads should be fully left to the user of the library to handle.
	// Or maybe we restrict the threading to a very limited part, i.e. the filesystem helpers.

	for (uint i = 0; i < visit.files.len; i++) {
		fString file_contents;
		f_assert(f_files_read_whole(visit.files[i], &module_arena->alc, &file_contents));

		ffzParseResult parse_result = ffz_parse_scope(module, file_contents, visit.files[i]);
		if (parse_result.node == NULL) {
			*out_error = parse_result.error;
			return NULL;
		}

		// OLD COMMENT:
		// so... each ffzNode needs to be part of a Parser. Why? because we have a
		// local index for the nodes that is used to check local variable usage.
		
		// but what if you want to generate your own nodes?
		// hmm, but the error reporting procedures expect source code and source file.
		// let's just say for now, there is always a parser.

		// What we could then do is have a queue for top-level nodes that need to be (re)checked.
		// When expanding polymorph nodes, push those nodes to the end of the queue. Or if the
		// user wants to modify the tree, they can push the modified nodes to the end of the queue
		// to be re-checked.

		for (ffzNode* n = parse_result.node->first_child; n; n = n->next) {
			n->parent = NULL; // ffz_module_add_top_level_node requires the parent to be NULL
			if (!ffz_module_add_top_level_node_(module, n).ok) {
				*out_error = module->error;
				return {};
			}
		}

		f_array_push_n(&module->pending_import_keywords, parse_result.import_keywords);
	}
	
	return module;
}
