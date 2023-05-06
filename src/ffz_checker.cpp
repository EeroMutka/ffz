
// The checker checks if the program is correct, and in doing so,
// computes and caches information about the program, such as which declarations
// identifiers are pointing to, what types do expressions have, constant evaluation, and so on.
// If the c succeeds, the program is valid and should compile with no errors.

#define F_DEF_INCLUDE_OS
#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include "tracy/tracy/Tracy.hpp"

#define TRY(x) { if ((x).ok == false) return ffzOk{false}; }

#define OPT(ptr) ptr

#define FFZ_CAPI extern "C"

static void report_module_error(ffzModule* m, fOpt(ffzNode*) node, fString msg) {
	f_trap();//m->error.node = node;
	//m->error.message = msg;
	//if (node) {
	//	m->error.source = node->loc_source;
	//	m->error.location = node->loc;
	//}
}

#define ERR_NO_NODE(m, fmt, ...) \
	report_module_error(m, NULL, f_aprint(m->alc, fmt, __VA_ARGS__)); \
	return ffzOk{false};

#define ERR(node, fmt, ...) { \
	report_module_error(ffz_module_of_node(node), node, f_aprint(ffz_module_of_node(node)->alc, fmt, __VA_ARGS__)); \
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

	//InferFlag_CacheOnlyIfGotType = 1 << 3,

	InferFlag_NoTypesMatchCheck = 1 << 4,

	// TODO: make it return the default value instead
	InferFlag_TypeMeansZeroValue = 1 << 5, // `int` will mean "the zero value of int" instead of "the type int"

	// We only allow undefined values in variable (not parameter) declarations.
	InferFlag_AllowUndefinedValues = 1 << 6,
	
	// RequireConstant verifies that the node has a constant or an undefined value.
	InferFlag_RequireConstant = 1 << 7,
};

// ------------------------------

static bool is_basic_type_size(u32 size) { return size == 1 || size == 2 || size == 4 || size == 8; }
//static void print_constant(ffzProject* p, fWriter* w, ffzConstant* constant);
static ffzOk check_node(ffzCheckerContext* c, ffzNode* node, OPT(ffzType*) require_type, InferFlags flags, fOpt(ffzCheckInfo*) out_result);

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

	case ffzTypeTag_Proc: {
		ffzNode* node = constant.data->node;
		f_hasher_add(&h, ffz_hash_expression(node));
	} break;

	case ffzTypeTag_Record: {
		f_assert(constant.type->Record.is_union == false);
		for (uint i = 0; i < constant.type->record_fields.len; i++) {
			ffzConstant elem = {constant.type->record_fields[i].type, &constant.data->record_fields[i]};
			f_hasher_add(&h, ffz_hash_constant(elem));
		}
	} break;

	case ffzTypeTag_Slice: { f_trap(); } break;
	case ffzTypeTag_FixedArray: {
		for (u32 i = 0; i < (u32)constant.type->FixedArray.length; i++) {
			ffzConstantData elem_data = ffz_constant_array_get_elem(constant, i);
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
	//if (node->is_instantiation_root_of_poly != FFZ_POLYMORPH_ID_NONE) {
	//	ffzPolymorph polymorph = ffz_module_of_node(node)->polymorphs[node->is_instantiation_root_of_poly];
	//	return ffz_hash_polymorph(polymorph); // @speed: store the hash this in ffzPolymorph itself
	//}
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

FFZ_CAPI ffzConstantData* ffz_zero_value_constant() {
	const static ffzConstantData zeroes = {};
	return (ffzConstantData*)&zeroes;
}

static ffzConstantData* make_constant(ffzProject* p) {
	// TODO: we should deduplicate constants
	ffzConstantData* constant = f_mem_clone(*ffz_zero_value_constant(), p->persistent_allocator);
	return constant;
}

static ffzConstantData* make_constant_int(ffzProject* p, u64 _uint) {
	ffzConstantData* constant = make_constant(p);
	constant->_uint = _uint;
	return constant;
}

ffzCheckInfo make_type_constant(ffzProject* p, ffzType* type) {
	ffzCheckInfo out = {};
	out.type = p->type_type;
	out.constant = make_constant(p);
	out.constant->type = type;
	return out;
}

ffzType* ffz_ground_type(ffzConstantData* constant, ffzType* type) {
	return type->tag == ffzTypeTag_Type ? constant->type : type;
}

//bool ffz_type_is_concrete(ffzType* type) {
//	return type->is_concrete;
//	if (type->tag == ffzTypeTag_Type) return false;
//	if (type->tag == ffzTypeTag_FixedArray && type->FixedArray.length == -1) return false;
//	if (type->tag == ffzTypeTag_Module) return false;
//	if (type->tag == ffzTypeTag_Raw) return false;
//	
//	// hmm... non-concrete types should propagate up, even
//	for (uint i = 0; i < type->record_fields.len; i++) {
//		if (!ffz_type_is_concrete(type->record_fields[i].type)) {
//			return false;
//		}
//	}
//
//	return true;
//}

// TODO: store this as a flag in ffzType
// hmm... shouldn't all types be comparable for equality?
FFZ_CAPI bool ffz_type_is_comparable_for_equality(ffzType* type) {
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

FFZ_CAPI bool ffz_type_is_comparable(ffzType* type) {
	return ffz_type_is_integer(type->tag) || type->tag == ffzTypeTag_Enum || ffz_type_is_float(type->tag);
}

void print_type(fWriter* w, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Invalid: { f_print(w, "<invalid>"); } break;
	case ffzTypeTag_Raw: { f_print(w, "raw"); } break;
	case ffzTypeTag_Undefined: { f_print(w, "<undefined>"); } break;
	case ffzTypeTag_Type: { f_print(w, "<type>"); } break;
	case ffzTypeTag_PolyDef: { f_print(w, "<polymorphic expression>"); } break;
	case ffzTypeTag_Module: { f_print(w, "<module>"); } break;
	case ffzTypeTag_Bool: { f_print(w, "bool"); } break;
	case ffzTypeTag_Pointer: {
		f_print(w, "^");
		print_type(w, type->Pointer.pointer_to);
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
		//ffzNode* s = type->unique_node;
		//fString name = ffz_get_parent_decl_pretty_name(s);
		//if (name.len > 0) {
		//	f_prints(w, name);
		//}
		//else {
		//f_print(w, "<anonymous-proc|line:~u32,col:~u32>",
		//	s->loc.start.line_num, s->loc.start.column_num);
		//}
		f_print(w, "proc(");
		for (uint i = 0; i < type->Proc.in_params.len; i++) {
			if (i > 0) f_print(w, ", ");
			print_type(w, type->Proc.in_params[i].type);
		}
		f_print(w, ")");
		
		if (type->Proc.return_type) {
			f_print(w, " => ");
			print_type(w, type->Proc.return_type);
		}
	} break;
	case ffzTypeTag_Enum: {
		f_trap();
		//ffzNode* n = type->unique_node;
		//fString name = ffz_get_parent_decl_pretty_name(n);
		//if (name.len > 0) {
		//	f_prints(w, name);
		//}
		//else {
		//	f_print(w, "[anonymous enum defined at line:~u32, col:~u32]", n->loc.start.line_num, n->loc.start.column_num);
		//}
	} break;
	case ffzTypeTag_Record: {
		//ffzNodeRecord* n = type->unique_node;
		//fString name = ffz_get_parent_decl_pretty_name(n);
		//if (name.len > 0) {
		//	f_prints(w, name);
		//}
		//else {
		//	f_print(w, "[anonymous ~c defined at line:~u32, col:~u32]",
		//		n->Record.is_union ? "union" : "struct", n->loc.start.line_num, n->loc.start.column_num);
		//}
		f_print(w, "struct{");
		for (uint i = 0; i < type->record_fields.len; i++) {
			if (i > 0) f_print(w, ", ");
			print_type(w, type->record_fields[i].type);
		}
		f_print(w, "}");

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
		print_type(w, type->Slice.elem_type);
	} break;
	case ffzTypeTag_String: {
		f_print(w, "string");
	} break;
	case ffzTypeTag_FixedArray: {
		f_print(w, "[~i32]", type->FixedArray.length);
		print_type(w, type->FixedArray.elem_type);
	} break;
	default: f_assert(false);
	}
}

// Print the constant as valid FFZ source code
/*
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
*/


FFZ_CAPI fString ffz_constant_to_string(ffzProject* p, ffzConstant constant) {
	f_trap(); // TODO: make a temporary ffz_constant_to_node() thing

	//fStringBuilder builder;
	//f_init_string_builder(&builder, p->persistent_allocator);
	//print_constant(p, builder.w, constant);
	//return builder.buffer.slice;
	return {};
}

FFZ_CAPI ffzNode* ffz_type_to_node(ffzModule* m, ffzType* type) {
	// TODO: node builder procedures that we can also use in the parser, such as ffz_new_node_keyword(...)
	ffzNode* result = NULL;
	switch (type->tag) {
	//case ffzTypeTag_Invalid: { f_print(w, "<invalid>"); } break;
	//case ffzTypeTag_Raw: { f_print(w, "raw"); } break;
	//case ffzTypeTag_Undefined: { f_print(w, "<undefined>"); } break;
	//case ffzTypeTag_Type: { f_print(w, "<type>"); } break;
	//case ffzTypeTag_PolyExpr: { f_print(w, "<polymorphic expression>"); } break;
	//case ffzTypeTag_Module: { f_print(w, "<module>"); } break;
	//case ffzTypeTag_Bool: { f_print(w, "bool"); } break;
	//case ffzTypeTag_Pointer: {
	//	f_print(w, "^");
	//	print_type(p, w, type->Pointer.pointer_to);
	//} break;
	case ffzTypeTag_DefaultSint: {
		result = ffz_new_node(m, ffzNodeKind_Keyword);
		result->Keyword.keyword = ffzKeyword_int;
	} break;
	case ffzTypeTag_DefaultUint: {
		result = ffz_new_node(m, ffzNodeKind_Keyword);
		result->Keyword.keyword = ffzKeyword_uint;
	} break;
	case ffzTypeTag_Sint: {
		ffzKeyword kw;
		switch (type->size) {
		case 1: { kw = ffzKeyword_s8; } break;
		case 2: { kw = ffzKeyword_s16; } break;
		case 4: { kw = ffzKeyword_s32; } break;
		case 8: { kw = ffzKeyword_s64; } break;
		default: f_trap();
		}
		result = ffz_new_node(m, ffzNodeKind_Keyword);
		result->Keyword.keyword = kw;
	} break;
	case ffzTypeTag_Uint: {
		ffzKeyword kw;
		switch (type->size) {
		case 1: { kw = ffzKeyword_u8; } break;
		case 2: { kw = ffzKeyword_u16; } break;
		case 4: { kw = ffzKeyword_u32; } break;
		case 8: { kw = ffzKeyword_u64; } break;
		default: f_trap();
		}
		result = ffz_new_node(m, ffzNodeKind_Keyword);
		result->Keyword.keyword = kw;
	} break;
	//case ffzTypeTag_Float: {
	//	f_print(w, "f~u32", type->size * 8);
	//} break;
	//case ffzTypeTag_Proc: {
	//	ffzNode* s = type->unique_node;
	//	fString name = ffz_get_parent_decl_pretty_name(s);
	//	if (name.len > 0) {
	//		f_prints(w, name);
	//	}
	//	else {
	//		f_print(w, "<anonymous-proc|line:~u32,col:~u32>",
	//			s->loc.start.line_num, s->loc.start.column_num);
	//	}
	//} break;
	//case ffzTypeTag_Enum: {
	//	ffzNode* n = type->unique_node;
	//	fString name = ffz_get_parent_decl_pretty_name(n);
	//	if (name.len > 0) {
	//		f_prints(w, name);
	//	}
	//	else {
	//		f_print(w, "[anonymous enum defined at line:~u32, col:~u32]", n->loc.start.line_num, n->loc.start.column_num);
	//	}
	//} break;
	//case ffzTypeTag_Record: {
	//	ffzNodeRecord* n = type->unique_node;
	//	fString name = ffz_get_parent_decl_pretty_name(n);
	//	if (name.len > 0) {
	//		f_prints(w, name);
	//	}
	//	else {
	//		f_print(w, "[anonymous ~c defined at line:~u32, col:~u32]",
	//			n->Record.is_union ? "union" : "struct", n->loc.start.line_num, n->loc.start.column_num);
	//	}
	//} break;
	//case ffzTypeTag_Slice: {
	//	f_print(w, "[]");
	//	print_type(p, w, type->Slice.elem_type);
	//} break;
	//case ffzTypeTag_String: {
	//	f_print(w, "string");
	//} break;
	//case ffzTypeTag_FixedArray: {
	//	f_print(w, "[~i32]", type->FixedArray.length);
	//	print_type(p, w, type->FixedArray.elem_type);
	//} break;
	default: f_trap();
	}
	f_assert(result != NULL);
	return result;
}

FFZ_CAPI fString ffz_type_to_string(ffzType* type, fAllocator* alc) {
	// TODO: remove `print_type` and instead use  type_to_node() and AST printing. For that, we need to be able to make dummy modules easily.
	//f_trap();
	fStringBuilder builder; f_init_string_builder(&builder, alc);
	print_type(builder.w, type);
	return builder.buffer.slice;
}

fOpt(ffzNode*) ffz_checked_get_parent_proc(ffzCheckerContext* ctx, ffzNode* node) {
	for (node = node->parent; node; node = node->parent) {
		fOpt(ffzType*) type = ffz_checked_get_info(ctx, node).type;
		if (type && type->tag == ffzTypeTag_Proc) {
			return node;
		}
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

FFZ_CAPI bool ffz_checked_decl_is_local_variable(ffzCheckerContext* ctx, ffzNodeOpDeclare* decl) {
	return ffz_checked_get_info(ctx, decl).is_local_variable;
}

FFZ_CAPI bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl) {
	if (decl->Op.left->Identifier.is_constant) return false;
	return ffz_node_is_top_level(decl);
}

fOpt(ffzNodeIdentifier*) ffz_find_definition_in_scope(ffzCheckerContext* ctx, ffzNode* scope, fString name) {
	ffzDefinitionPath def_path = { scope, name };

	ffzNodeIdentifier** def = f_map64_get(&ctx->definition_map, ffz_hash_definition_path(def_path));
	return def ? *def : NULL;
}

FFZ_CAPI bool ffz_constant_is_zero(ffzConstantData constant) {
	u8 zeroes[sizeof(ffzConstantData)] = {};
	return memcmp(&constant, zeroes, sizeof(ffzConstantData)) == 0;
}

ffzFieldHash ffz_hash_field(ffzType* type, fString member_name) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, type->hash);
	f_hasher_add(&h, f_hash64_str(member_name));
	return f_hasher_end(&h);
}

static ffzOk add_fields_to_field_from_name_map(ffzCheckerContext* c, ffzType* root_type, ffzType* parent_type,
	fOpt(fArray(u32)*) index_path = NULL, u32 offset_from_root = 0)
{
	fArray(u32) _index_path;
	if (index_path == NULL) {
		index_path = &_index_path;
		_index_path = f_array_make<u32>(c->mod->alc);
	}

	for (u32 i = 0; i < parent_type->record_fields.len; i++) {
		ffzField* field = &parent_type->record_fields[i];
		f_array_push(index_path, i);
		
		ffzTypeRecordFieldUse field_use = { field, offset_from_root + field->offset, f_clone_slice(index_path->slice, c->mod->alc) };
		auto insertion = f_map64_insert(&c->field_from_name_map, ffz_hash_field(root_type, field->name), field_use, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			f_trap();//ERR_NO_NODE(c, "`~s` is already declared before inside (TODO: print struct name) (TODO: print line)", field->name);
		}

		// NOTE: add leaves first, to make sure index_path will be as big as it gets by the time we start taking slices to it
		if (field->has_using) {
			TRY(add_fields_to_field_from_name_map(c, root_type, field->type, index_path));
		}

		f_array_pop(index_path);
	}
	return { true };
}

FFZ_CAPI bool ffz_type_find_record_field_use(ffzCheckerContext* ctx, ffzType* type, fString name, ffzTypeRecordFieldUse* out) {
	if (ffzTypeRecordFieldUse* result = f_map64_get(&ctx->field_from_name_map, ffz_hash_field(type, name))) {
		*out = *result;
		return true;
	}
	return false;
}

static ffzOk verify_is_type_expression(ffzCheckerContext* c, ffzNode* node, ffzType* type) {
	if (type->tag != ffzTypeTag_Type) ERR(node, "Expected a type, but got a value.");
	return FFZ_OK;
}

// if this returns true, its ok to bit-cast between the types
static bool type_is_a_bit_by_bit(ffzType* src, ffzType* target) {
	if (src->tag == ffzTypeTag_DefaultUint && target->tag == ffzTypeTag_DefaultSint) return true; // allow implicit cast from uint -> int
	if (target->tag == ffzTypeTag_Raw) return true; // everything can cast to raw
	
	if (src->tag == ffzTypeTag_Pointer && target->tag == ffzTypeTag_Pointer) {
		// i.e. allow casting from ^int to ^raw
		return type_is_a_bit_by_bit(src->Pointer.pointer_to, target->Pointer.pointer_to);
	}

	return src->hash == target->hash;
}

static ffzOk check_types_match(ffzCheckerContext* c, ffzNode* node, ffzType* received, ffzType* expected, const char* message) {
	if (!type_is_a_bit_by_bit(received, expected)) {
		ERR(node, "~c\n    received: ~s\n    expected: ~s",
			message, ffz_type_to_string(received, c->mod->alc), ffz_type_to_string(expected, c->mod->alc));
	}
	return { true };
}

FFZ_CAPI bool ffz_find_field_by_name(fSlice(ffzField) fields, fString name, u32* out_index) {
	for (u32 i = 0; i < fields.len; i++) {
		if (fields[i].name == name) {
			*out_index = i;
			return true;
		}
	}
	return false;
}

FFZ_CAPI void ffz_get_arguments_flat(ffzNode* arg_list, fSlice(ffzField) fields, fSlice(ffzNode*)* out_arguments, fAllocator* alc) {
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

static ffzOk check_argument_list(ffzCheckerContext* c, ffzNode* node, fSlice(ffzField) fields, fOpt(ffzCheckInfo*) record_literal) {
	bool all_fields_are_constant = true;
	fSlice(ffzConstantData) field_constants;
	if (record_literal) field_constants = f_make_slice_garbage<ffzConstantData>(fields.len, c->mod->alc);

	fSlice(bool) field_is_given_a_value = f_make_slice<bool>(fields.len, false, c->mod->alc);

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

		if (i >= fields.len) {
			ERR(arg, "Received too many arguments.");
		}

		ffzCheckInfo checked;
		TRY(check_node(c, arg_value, fields[i].type, 0, &checked));

		if (record_literal) {
			if (checked.constant) field_constants[i] = *checked.constant;
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
		record_literal->constant = make_constant(c->project);
		record_literal->constant->record_fields = field_constants;
	}

	return FFZ_OK;
}

//static bool uint_is_subtype_of(ffzType* type, ffzType* subtype_of) {
//	if (ffz_type_is_unsigned_integer(type->tag) && ffz_type_is_unsigned_integer(subtype_of->tag) && type->size <= subtype_of->size) return true;
//	return false;
//}

static ffzOk check_two_sided(ffzCheckerContext* c, ffzNode* left, ffzNode* right, OPT(ffzType*)* out_type) {
	// Infer expressions, such as  `x: u32(1) + 50`  or  x: `2 * u32(552)`
	f_trap();
#if 0
	InferFlags child_flags = InferFlag_TypeIsNotRequired_ /*| InferFlag_CacheOnlyIfGotType*/;
	ffzCheckInfo left_chk, right_chk;
	
	for (int i = 0; i < 2; i++) {
		TRY(check_node(c, left, NULL, child_flags, &left_chk));
		TRY(check_node(c, right, NULL, child_flags, &right_chk));
		if (left_chk.type && right_chk.type) break;
		
		child_flags = 0;
		if (!left_chk.type && right_chk.type) {
			TRY(check_node(c, left, right_chk.type, child_flags, &left_chk));
			break;
		}
		else if (!right_chk.type && left_chk.type) {
			TRY(check_node(c, right, left_chk.type, child_flags, &right_chk));
			break;
		}
		continue;
	}

	OPT(ffzType*) result = NULL;
	if (right_chk.type && left_chk.type) {
		if (type_is_a_bit_by_bit(c->project, left_chk.type, right_chk.type))      result = right_chk.type;
		else if (type_is_a_bit_by_bit(c->project, right_chk.type, left_chk.type)) result = left_chk.type;
		else {
			ERR(left->parent, "Types do not match.\n    left:    ~s\n    right:   ~s",
				ffz_type_to_string(c->project, left_chk.type), ffz_type_to_string(c->project, right_chk.type));
		}
	}
	*out_type = result;
#endif
	return { true };
}

FFZ_CAPI u32 ffz_get_encoded_constant_size(ffzType* type) {
	return ffz_type_is_integer(type->tag) ? type->size : sizeof(ffzConstantData);
}

FFZ_CAPI ffzConstantData ffz_constant_array_get_elem(ffzConstant array, u32 index) {
	u32 elem_size = ffz_get_encoded_constant_size(array.type->FixedArray.elem_type);
	ffzConstantData result = *ffz_zero_value_constant();
	//if (array.data->array_elems)
	memcpy(&result, (u8*)array.data->array_elems.data + index*elem_size, elem_size);
	return result;
}

ffzOk try_to_add_definition_to_scope(ffzCheckerContext* c, fOpt(ffzNode*) scope, ffzNodeIdentifier* def) {
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

ffzOk add_possible_definition_to_scope(ffzCheckerContext* c, fOpt(ffzNode*) scope, fOpt(ffzNode*) node) {
	if (node && node->kind == ffzNodeKind_Declare) {
		// NOTE: we need to do this check here, because this function can be called on the node BEFORE having checked the node.
		if (node->Op.left->kind != ffzNodeKind_Identifier) {
			ERR(node->Op.left, "The left-hand side of a declaration must be an identifier.");
		}
		TRY(try_to_add_definition_to_scope(c, scope, node->Op.left));
	}
	return FFZ_OK;
}

ffzOk add_possible_definitions_to_scope(ffzCheckerContext* c, fOpt(ffzNode*) scope, ffzNode* from_children) {
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
	case ffzTypeTag_PolyDef: break;
	case ffzTypeTag_Extra: { f_hasher_add(&h, type->Extra.id); } break;

	case ffzTypeTag_Pointer: { f_hasher_add(&h, ffz_hash_type(p, type->Pointer.pointer_to)); } break;

	case ffzTypeTag_Proc: {
		for (uint i = 0; i < type->Proc.in_params.len; i++) {
			f_hasher_add(&h, ffz_hash_type(p, type->Proc.in_params[i].type));
		}
		f_hasher_add(&h, 0); // We must have this hash 'separator' to distinguish between hashing in a parameter type vs return type
		if (type->Proc.return_type) {
			f_hasher_add(&h, ffz_hash_type(p, type->Proc.return_type));
		}
	} break;

	case ffzTypeTag_Enum: { f_trap(); } break; // fallthrough   :EnumFieldsShouldNotContributeToTypeHash
	case ffzTypeTag_Record: {
		for (uint i = 0; i < type->record_fields.len; i++) {
			f_hasher_add(&h, ffz_hash_type(p, type->record_fields[i].type));
		}
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

ffzType* ffz_make_type(ffzProject* p, ffzType type_desc) {
	//type_desc.checker_id = c->self_id;
	type_desc.hash = ffz_hash_type(p, &type_desc);
	
	auto entry = f_map64_insert(&p->type_from_hash, type_desc.hash, (ffzType*)0, fMapInsert_DoNotOverride);
	if (entry.added) {
		ffzType* type_ptr = f_mem_clone(type_desc, p->persistent_allocator);
		type_ptr->align = get_alignment(type_ptr, p->pointer_size); // cache the alignment
		*entry._unstable_ptr = type_ptr;
	}
	
	return *entry._unstable_ptr;
}

static ffzType* ffz_make_basic_type(ffzProject* p, ffzTypeTag tag, u32 size, bool is_concrete) {
	ffzType type = { tag };
	type.size = size;
	type.is_concrete.x = is_concrete;
	return ffz_make_type(p, type);
}

ffzType* ffz_make_type_ptr(ffzProject* p, ffzType* pointer_to) {
	ffzType type = { ffzTypeTag_Pointer };
	type.size = p->pointer_size;
	type.is_concrete.x = true;
	type.Pointer.pointer_to = pointer_to;
	return ffz_make_type(p, type);
}

struct ffzRecordBuilder {
	ffzProject* p;
	u32 size;
	u32 align;
	bool is_concrete;
	fArray(ffzField) fields;
};

static ffzRecordBuilder ffz_record_builder_init(ffzProject* p, uint fields_cap) {
	//f_assert(record->size == 0);
	return { p, 0, 1, true, f_array_make_cap<ffzField>(fields_cap, p->persistent_allocator) };
}

// NOTE: default_value is copied
static void ffz_record_builder_add_member(ffzRecordBuilder* b, fString name, ffzType* field_type,
	fOpt(ffzConstantData*) default_value, fOpt(ffzNodeOpDeclare*) decl)
{
	//bool is_union = b->record->tag == ffzTypeTag_Record && b->record->Record.is_union;

	ffzField field;
	field.name = name;
	field.offset = F_ALIGN_UP_POW2(b->size, field_type->align);
	field.type = field_type;
	//field.decl = decl;
	field.has_using = decl != NULL && ffz_checked_get_tag(decl, ffzKeyword_using) != NULL;
	field.has_default_value = default_value != NULL;
	field.default_value = default_value != NULL ? *default_value : *ffz_zero_value_constant();
	f_array_push(&b->fields, field);

	// If the field has a non-concrete type, then this record type will also be non-concrete, i.e. struct{foo: type}
	b->is_concrete = b->is_concrete && field_type->is_concrete.x;

	// the alignment of a record is that of the largest field  :ComputeRecordAlignment
	b->align = F_MAX(b->align, field_type->align);
	b->size = field.offset + field_type->size;
}

static void ffz_record_builder_pre_finish(ffzRecordBuilder* b) {
	b->size = F_ALIGN_UP_POW2(b->size, b->align); // Align the size up to the largest member alignment
}

static ffzOk ffz_record_builder_finish(ffzRecordBuilder* b, ffzType** out_type) {
	ffz_record_builder_pre_finish(b);

	f_trap();//ffzType type_desc = { ffzTypeTag_Record };
	//type_desc.record_fields = b->fields.slice;
	//type_desc.is_concrete.x = b->is_concrete;
	//type_desc.size = b->size;
	//type_desc.align = b->align;
	//*out_type = ffz_make_type(b->checker, type_desc);
	//TRY(add_fields_to_field_from_name_map(b->checker, *out_type, *out_type));

	return FFZ_OK;
}

static ffzOk ffz_record_builder_finish_to_existing(ffzRecordBuilder* b, ffzType* type) {
	ffz_record_builder_pre_finish(b);

	f_trap();//type->record_fields = b->fields.slice;
	//type->is_concrete.x = b->is_concrete;
	//type->size = b->size;
	//type->align = b->align;
	//TRY(add_fields_to_field_from_name_map(b->checker, type, type));

	return FFZ_OK;
}

ffzType* ffz_make_type_slice(ffzProject* p, ffzType* elem_type) {
	ffzType type = { ffzTypeTag_Slice };
	type.is_concrete.x = true;
	type.Slice.elem_type = elem_type;
	ffzType* out = ffz_make_type(p, type);

	if (out->record_fields.len == 0) { // this type hasn't been made before
		f_trap();//ffzRecordBuilder b = ffz_record_builder_init(c, 2);
		//ffz_record_builder_add_member(&b, F_LIT("ptr"), ffz_make_type_ptr(c, elem_type), ffz_zero_value_constant(), {});
		//ffz_record_builder_add_member(&b, F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), ffz_zero_value_constant(), {});
		//ffz_record_builder_finish_to_existing(&b, out);
	}
	return out;
}

ffzType* ffz_make_type_fixed_array(ffzProject* p, ffzType* elem_type, s32 length) {
	ffzType array_type = { ffzTypeTag_FixedArray };
	if (length >= 0) array_type.size = (u32)length * elem_type->size;

	array_type.FixedArray.elem_type = elem_type;
	array_type.FixedArray.length = length;
	ffzType* out = ffz_make_type(p, array_type);

	if (length > 0 && length <= 4 && out->record_fields.len == 0) { // this type hasn't been made before
		//const static fString fields[] = { F_LIT("x"), F_LIT("y"), F_LIT("z"), F_LIT("w") };
		//
		//// We can't use the ffzRecordBuilder here, because we don't want it to build the size of the type.
		//out->record_fields = f_make_slice_garbage<ffzField>(length, c->alc);
		//for (u32 i = 0; i < (u32)length; i++) {
		//	out->record_fields[i] = { fields[i], {}, {}, false, elem_type->size * i, elem_type };
		//}
		//add_fields_to_field_from_name_map(c, out, out, 0);
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

static ffzOk check_post_round_brackets(ffzCheckerContext* c, ffzNode* node, ffzType* require_type, InferFlags flags, ffzCheckInfo* result) {
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
				ffzCheckInfo checked;
				TRY(check_node(c, first, require_type, flags, &checked));
				result->type = checked.type;
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
			f_trap();//if (ffz_get_child_count(node) != 1) {
			//	ERR(node, "Incorrect number of arguments to ~s.", ffz_keyword_to_string(keyword));
			//}
			//
			//ffzCheckInfo first_checked;
			//TRY(check_node(c, ffz_get_child(node, 0), NULL, 0, &first_checked));
			//ffzType* type = ffz_ground_type(first_checked.constant, first_checked.type);
			//
			//result->type = ffz_builtin_type(c, ffzKeyword_uint);
			//result->constant = make_constant_int(c, keyword == ffzKeyword_align_of ? type->align : type->size);
			//fall = false;
		}
		else if (keyword == ffzKeyword_import) {
			//result->type = c->module_type;
			//result->constant = make_constant(c);
			//
			//// `ffz_module_resolve_imports` already makes sure that the import node is part of a declaration
			//ffzNode* import_decl = node->parent;
			//result->constant->module = *f_map64_get(&c->module_from_import_decl, (u64)import_decl);
			f_trap();//fall = false;
		}
	}
	if (fall) {
		ffzCheckInfo left_chk;
		TRY(check_node(c, left, NULL, 0, &left_chk));
		ffzType* left_type = left_chk.type;

		if (left_type->tag == ffzTypeTag_Type) { // Type cast
#if 0
			if (left->checked.constant == NULL) ERR(left, "Target type for type-cast was not a constant.");

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
#endif
			f_trap();
		}
		else {
			// Procedure call

			// hmm, so we need to inspect the polymorphic AST tree, because we don't want to duplicate the nodes yet.
			// That means that we don't want to write to anything. Only analyze.
			// Only AFTER we have figured out the poly-args, we may deep copy or (use existing copy for this argument set) nodes, similarly to doing it explicitly.

			if (left_type->tag == ffzTypeTag_PolyDef) {
				// implicit polymorphic instantiation
				ffzNode* poly_expr = left_chk.constant->node;
				f_assert(poly_expr->kind == ffzNodeKind_PostCurlyBrackets);

				ffzNode* proc_type_node = poly_expr->Op.left;
				f_assert(proc_type_node->kind == ffzNodeKind_ProcType);

				f_trap();
				//for FFZ_EACH_CHILD(param, proc_type_node) {
				//	// we wanna check this node
				//	//InferFlag_TypeIsNotRequired_
				//	TRY(check_node(c, param, NULL));
				//}
				
			}

			if (left_type->tag != ffzTypeTag_Proc) {
				ERR(left, "Attempted to call a non-procedure (~s)", ffz_type_to_string(left_type, c->mod->alc));
			}

			result->type = left_type->Proc.return_type;
			TRY(check_argument_list(c, node, left_type->Proc.in_params, NULL));
		}
	}
	return FFZ_OK;
}

static ffzOk check_curly_initializer(ffzCheckerContext* c, ffzType* type, ffzNode* node, InferFlags flags, ffzCheckInfo* result) {
	result->type = type;
#if 0
	if (type->tag == ffzTypeTag_Proc) {
		// Procedure initializer, e.g. proc{dbgbreak}
		result->constant = make_constant(c);
		result->constant->node = node;
	}
	else if (type->tag == ffzTypeTag_Slice || type->tag == ffzTypeTag_FixedArray) {
		// Array or slice initializer, e.g. []int{1, 2, 3} or [3]int{1, 2, 3}

		ffzType* elem_type = type->tag == ffzTypeTag_Slice ? type->Slice.elem_type : type->FixedArray.elem_type;
		fArray(ffzNode*) elems = f_array_make<ffzNode*>(f_temp_alc());
		bool all_elems_are_constant = true;

		for FFZ_EACH_CHILD(n, node) {
			TRY(check_node(c, n, elem_type, 0));
			f_array_push(&elems, n);
			all_elems_are_constant = all_elems_are_constant && n->checked.constant != NULL;
		}

		if (type->tag == ffzTypeTag_FixedArray) {
			s32 expected = type->FixedArray.length;
			if (expected < 0) { // make a new type if [?]
				result->type = ffz_make_type_fixed_array(c, elem_type, (s32)elems.len);
			}
			else if (elems.len != expected) {
				ERR(node, "Incorrect number of array initializer arguments. Expected ~u32, got ~u32", expected, (u32)elems.len);
			}
		}

		// For slices, we don't want to give the node a constant value if it's a local/temporary
		// to make sure a stack copy is made of the data.
		bool allow_constant = type->tag != ffzTypeTag_Slice || (flags & InferFlag_RequireConstant);

		if (all_elems_are_constant && allow_constant) {
			u32 elem_size = ffz_get_encoded_constant_size(elem_type);
			void* data = f_mem_alloc(elem_size * elems.len, c->alc);
			for (uint i = 0; i < elems.len; i++) {
				memcpy((u8*)data + elem_size * i, elems[i]->checked.constant, elem_size);
			}
			result->constant = make_constant(c);
			result->constant->array_elems.data = data;
			result->constant->array_elems.len = (u32)elems.len;
		}
	}
	else if (type->tag == ffzTypeTag_Record) {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) {
			ERR(node, "Union initialization with {} is not currently supported.");
		}
		
		// TODO: see what happens if you try to declare normally `123: 5215`
		TRY(check_argument_list(c, node, type->record_fields, result));
	}
	else {
		ERR(node, "{}-initializer is not allowed for `~s`.", ffz_type_to_string(c->project, type));
	}
#endif
	f_trap();
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
#if 0
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
	case ffzNodeKind_PolyDef: {
		instantiate_deep_copy_poly(ctx, ffz_cursor_poly_def(new_node));
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
#endif

FFZ_CAPI fOpt(ffzNode*) ffz_constant_to_node(ffzModule* m, ffzConstant constant) {
	// For simplicity, let's print the constant and parse it. I think we should change this to a direct translation. @speed
	//fString constant_string = ffz_constant_to_string(m->project, constant);
	ffzNode* result = NULL;
	switch (constant.type->tag) {
	case ffzTypeTag_Invalid: { f_trap(); } break;
	//case ffzTypeTag_Raw: {} break;
	//case ffzTypeTag_Undefined: {} break;
	case ffzTypeTag_Type: {
		result = ffz_type_to_node(m, constant.data->type);
	} break;
	//case ffzTypeTag_PolyExpr: {} break;
	//case ffzTypeTag_Module: {} break;
	//case ffzTypeTag_Bool: {} break;
	//case ffzTypeTag_Pointer: {} break;
	//case ffzTypeTag_Sint: {} break;
	//case ffzTypeTag_Uint: {} break;
	//case ffzTypeTag_DefaultSint: {} break;
	//case ffzTypeTag_DefaultUint: {} break;
	//case ffzTypeTag_Float: {} break;
	//case ffzTypeTag_Proc: {} break;
	case ffzTypeTag_Record: {
		// hmm. This is starting to get ugly. We need to generate a reference to
		// the record type.
		// so what if we generate an identifier with the name?
		
		//- how can I 
		result = ffz_new_node(m, ffzNodeKind_PostCurlyBrackets);
		for (uint i = 0; i < constant.type->record_fields.len; i++) {
		}
	} break;
	//case ffzTypeTag_Enum: {} break;
	//case ffzTypeTag_Slice: {} break;
	//case ffzTypeTag_String: {} break;
	//case ffzTypeTag_FixedArray: {} break;
	//default: f_trap();
	}
	//ffzNode* node = ffz_new_node(m, ffzNodeKind_
	//ffzParseResult result = ffz_parse_node(m, constant_string, F_LIT("<CONSTANT>"));
	//f_assert(result.node != NULL);
	//result.node->parent = parent;
	f_assert(result != NULL);
	return result;// result.node;
}

FFZ_CAPI bool ffz_find_subscriptable_base_type(ffzType* type, ffzTypeRecordFieldUse* out) {
	bool found = false;
	f_for_array(ffzField, type->record_fields, it) {
		if (it.elem.type->tag == ffzTypeTag_Slice || it.elem.type->tag == ffzTypeTag_FixedArray) {
			//if (it.elem.decl && ffz_get_tag(it.elem.decl, ffzKeyword_using)) {
			if (it.elem.has_using) {
				if (found) {
					return false;
				}
				*out = {&type->record_fields[it.i], it.elem.offset};
				found = true;
			}
		}
	}
	return found;
}

static ffzOk check_post_square_brackets(ffzCheckerContext* c, ffzNode* node, ffzCheckInfo* result) {
#if 0
	ffzNode* left = node->Op.left;
	TRY(check_node(c, left, NULL, 0));

	ffzCheckInfo left_chk = left->checked;
	if (left_chk.type->tag == ffzTypeTag_PolyDef) {
		fArray(ffzConstant) params = f_array_make<ffzConstant>(c->alc);

		for FFZ_EACH_CHILD(arg, node) {
			TRY(check_node(c, arg, NULL, InferFlag_RequireConstant));
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
				arg_decl->Op.right = ffz_constant_to_node(c, poly.parameters[i]);
				arg_decl->Op.right->parent = arg_decl;
				
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

			ffzNode* poly_expr = poly.poly_def->PolyDef.expr;
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
		
		ffzType* left_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type; // NOTE: allow implicit dereferencing

		fOpt(ffzType*) subscriptable_type = NULL;
		if (left_type->tag == ffzTypeTag_Slice || left_type->tag == ffzTypeTag_FixedArray) {
			subscriptable_type = left_type;
		} else {
			ffzTypeRecordFieldUse subscriptable_field;
			if (ffz_find_subscriptable_base_type(left_type, &subscriptable_field)) {
				subscriptable_type = subscriptable_field.src_field->type;
			}
		}
		
		if (subscriptable_type == NULL) {
			ERR(left, "Expected an array, a slice, or a polymorphic expression before [].\n    received: ~s",
				ffz_type_to_string(c->project, left_type));
		}

		ffzType* elem_type = subscriptable_type->tag == ffzTypeTag_Slice ? subscriptable_type->Slice.elem_type : subscriptable_type->FixedArray.elem_type;

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
#endif
	f_trap();
	return FFZ_OK;
}

FFZ_CAPI fString ffz_get_import_name(ffzModule* m, ffzModule* imported_module) {
	fOpt(ffzNode**) module_import_decl = f_map64_get(&m->import_decl_from_module, (u64)imported_module);
	if (module_import_decl) {
		return (*module_import_decl)->Op.left->Identifier.name;
	}
	return {};
}

static ffzOk check_member_access(ffzCheckerContext* c, ffzNode* node, ffzCheckInfo* result) {
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
	
	if (left->kind == ffzNodeKind_Identifier && left->Identifier.name == F_LIT("in")) {
		f_trap();
#if 0
		fOpt(ffzNode*) parent_proc = ffz_checked_get_parent_proc(node);
		f_assert(parent_proc != NULL);
		ffzType* proc_type = parent_proc->checked.type;
		
		if (parent_proc->Op.left->kind == ffzNodeKind_ProcType) {
			ERR(left, "`in` is not allowed when the procedure parameters are accessible by name.");
		}

		bool found = false;
		for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
			ffzField* param = &proc_type->Proc.in_params[i];
			if (param->name == member_name) {
				result->type = param->type;
				found = true;
				break;
			}
		}
		
		if (!found) {
			ERR(right, "Declaration not found for '~s' inside procedure input parameter list.", member_name);
		}
#endif
	}
	else {
		f_trap();
#if 0
		TRY(check_node(c, left, NULL, 0));
		ffzType* left_type = left->checked.type;
		fOpt(ffzConstantData*) left_constant = left->checked.constant;
		
		if (left_type->tag == ffzTypeTag_Module) {
			ffzModule* left_module = left_constant->module;

			fOpt(ffzNode*) def = ffz_find_definition_in_scope(left_module->root, member_name);
			if (def && def->parent->kind == ffzNodeKind_Declare) {
				*result = def->parent->checked;
			}
			else {
				ERR(right, "Declaration not found for '~s' inside '~s'", member_name, ffz_get_import_name(c, left_module));
			}
		}
		else if (left_type->tag == ffzTypeTag_Type && left_constant->type->tag == ffzTypeTag_Enum) {
			ffzType* enum_type = left_constant->type;

			ffzModule* enum_type_module = c->project->checkers[enum_type->checker_id];
			ffzFieldHash member_key = ffz_hash_field(left_constant->type, member_name);

			if (u64* val = f_map64_get(&enum_type_module->enum_value_from_name, member_key)) {
				result->type = left_constant->type;
				result->constant = make_constant_int(c, *val);
			}
			else {
				ERR(right, "Declaration not found for '~s' inside '~s'", member_name, ffz_type_to_string(c->project, enum_type));
			}
		}
		else {
			ffzType* dereferenced_type = left_type->tag == ffzTypeTag_Pointer ? left_type->Pointer.pointer_to : left_type;
			ffzTypeRecordFieldUse field;
			if (ffz_type_find_record_field_use(c->project, dereferenced_type, member_name, &field)) {
				result->type = field.src_field->type;
				
				// Find the constant value for this member
				if (left_constant != NULL) {
					result->constant = left_constant;
					for (u32 i = 0; i < field.index_path.len; i++) {
						u32 member_idx = field.index_path[i];
						result->constant = &result->constant->record_fields[member_idx];
					}
				}
			}
			else {
				ERR(right, "Declaration not found for '~s' inside '~s'", member_name, ffz_type_to_string(c->project, dereferenced_type));
			}
		}
#endif
	}

	return FFZ_OK;
}

static ffzOk check_tag(ffzCheckerContext* c, ffzNode* tag) {
	f_trap();
#if 0
	TRY(check_node(c, tag, NULL, InferFlag_TypeMeansZeroValue | InferFlag_RequireConstant));
	if (tag->checked.type->tag != ffzTypeTag_Record) {
		ERR(tag, "Tag was not a struct literal.", "");
	}

	auto tags = f_map64_insert(&c->all_tags_of_type, tag->checked.type->hash, {}, fMapInsert_DoNotOverride);
	if (tags.added) *tags._unstable_ptr = f_array_make<ffzNode*>(c->alc);
	f_array_push(tags._unstable_ptr, tag);
#endif
	return FFZ_OK;
}

static ffzType* ffz_make_extra_type(ffzProject* p) {
	ffzType t = { ffzTypeTag_Extra };
	t.Extra.id = p->next_extra_type_id++;
	return ffz_make_type(p, t);
}

ffzCheckerContext ffz_make_checker_ctx(ffzModule* mod) {
	ffzCheckerContext c = {};
	c.project = mod->project;
	c.mod = mod;
	c.definition_map = f_map64_make<ffzNodeIdentifier*>(mod->alc);
	c.field_from_name_map = f_map64_make<ffzTypeRecordFieldUse>(mod->alc);
	c.enum_value_from_name = f_map64_make<u64>(mod->alc);
	c.enum_value_is_taken = f_map64_make<ffzNode*>(mod->alc);
	c.pending_import_keywords = f_array_make<ffzNode*>(mod->alc);
	c.all_tags_of_type = f_map64_make<fArray(ffzNode*)>(mod->alc);
	c.poly_from_hash = f_map64_make<ffzPolymorphID>(mod->alc);
	c.polymorphs = f_array_make<ffzPolymorph>(mod->alc);
	c._extern_libraries = f_array_make<ffzNode*>(mod->alc);
	return c;
}

FFZ_CAPI ffzModule* ffz_project_add_module(ffzProject* p, fArena* module_arena) {
	fAllocator* alc = &module_arena->alc;

	ffzModule* c = f_mem_clone(ffzModule{}, alc);	
	c->project = p;
	c->self_id = (ffzModuleID)f_array_push(&p->checkers, c);
	c->alc = alc;
	//c->checked_identifiers = f_map64_make_raw(0, c->alc);
	
	c->import_decl_from_module = f_map64_make<ffzNode*>(c->alc);
	c->module_from_import_decl = f_map64_make<ffzModule*>(c->alc);
	
	
	c->root = ffz_new_node(c, ffzNodeKind_Scope);
	//c->root = f_mem_clone(ffzNode{}, c->alc); // :NewNode
	//c->root->kind = ffzNodeKind_Scope;
	//c->root->module_id = c->self_id;

	return c;
}

FFZ_CAPI fOpt(ffzNode*) ffz_checked_this_dot_get_assignee(ffzNodeThisValueDot* dot) {
	f_trap();//for (ffzNode* p = dot->parent; p; p = p->parent) {
	//	if (p->checked.type && p->checked.type->tag == ffzTypeTag_Proc) break;
	//	if (p->kind == ffzNodeKind_Assign) {
	//		return p->Op.left;
	//	}
	//}
	return NULL;
}

FFZ_CAPI fOpt(ffzConstantData*) ffz_checked_get_tag_of_type(ffzNode* node, ffzType* tag_type) {
	f_trap();//for (ffzNode* tag_n = node->first_tag; tag_n; tag_n = tag_n->next) {
	//	f_assert(tag_n->has_checked);
	//	if (type_is_a_bit_by_bit(node->_module->project, tag_n->checked.type, tag_type)) {
	//		return tag_n->checked.constant;
	//	}
	//}
	return NULL;
}

FFZ_CAPI fOpt(ffzConstantData*) ffz_checked_get_tag(ffzNode* node, ffzKeyword tag) {
	ffzType* type = ffz_builtin_type(node->_module->project, tag);
	return ffz_checked_get_tag_of_type(node, type);
}

static ffzOk post_check_enum(ffzCheckerContext* c, ffzNode* node) {
	f_trap();
#if 0
	ffzType* enum_type = node->checked.constant->type;

	TRY(add_possible_definitions_to_scope(c, node, node));

	fArray(ffzTypeEnumField) fields = f_array_make<ffzTypeEnumField>(c->alc);
	
	for FFZ_EACH_CHILD(n, node) {
		if (n->kind != ffzNodeKind_Declare) ERR(n, "Expected a declaration; got: [~s]", ffz_node_kind_to_string(n->kind));

		// NOTE: Infer the declaration from the enum internal type!
		TRY(check_node(c, n, enum_type->Enum.internal_type, InferFlag_Statement | InferFlag_RequireConstant));

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
#endif
	return FFZ_OK;
}

static ffzOk check_proc_type(ffzCheckerContext* c, ffzNode* node, ffzCheckInfo* result) {
	ffzType proc_type = { ffzTypeTag_Proc };
	proc_type.is_concrete.x = true;
	//proc_type.unique_node = node;
	proc_type.size = c->project->pointer_size;
	
	ffzNode* parameter_scope = node->parent->kind == ffzNodeKind_PostCurlyBrackets ? node->parent : node;
	TRY(add_possible_definitions_to_scope(c, parameter_scope, node));

	fArray(ffzField) in_parameters = f_array_make<ffzField>(c->project->persistent_allocator);
	for FFZ_EACH_CHILD(param, node) {
		if (param->kind != ffzNodeKind_Declare) ERR(param, "Expected a declaration.");
		
		ffzCheckInfo param_chk;
		TRY(check_node(c, param, NULL, InferFlag_Statement, &param_chk));
		
		// TODO: figure out default values for parameters again
#if 0
		// Since the parameter is a runtime value, we need to access the rhs of it to
		// distinguish between a type expression and a default value
		ffzNode* rhs = param->Op.right;
		
		ffzField field = {};
		field.name = ffz_decl_get_name(param);

		if (rhs->checked.type->tag == ffzTypeTag_Type) {
			field.type = rhs->checked.constant->type;
		} else {
			field.type = rhs->checked.type;
			field.has_default_value = true;
			field.default_value = *rhs->checked.constant;
		}
#endif
		ffzField field = {};
		field.name = ffz_decl_get_name(param);
		field.type = param_chk.type;

		f_array_push(&in_parameters, field);
	}
	proc_type.Proc.in_params = in_parameters.slice;

	fOpt(ffzNode*) out_param = node->ProcType.out_parameter;
	if (out_param) {
		ffzCheckInfo return_value_chk;
		TRY(check_node(c, out_param, NULL, 0, &return_value_chk));
		TRY(verify_is_type_expression(c, out_param, return_value_chk.type));
		proc_type.Proc.return_type = return_value_chk.constant->type;
	}
	
	if (ffz_checked_get_tag(node->parent, ffzKeyword_extern)) {
		// if it's an extern proc, then don't turn it into a type type!!
		result->type = ffz_make_type(c->project, proc_type);
		result->constant = make_constant(c->project);
		result->constant->node = node;
	}
	else {
		*result = make_type_constant(c->project, ffz_make_type(c->project, proc_type));
	}
	return FFZ_OK;
}

FFZ_CAPI fOpt(ffzNodeIdentifier*) ffz_find_definition(ffzCheckerContext* c, ffzNodeIdentifier* ident) {
	f_assert(c->mod == ident->_module);
	for (fOpt(ffzNode*) scope = ident; scope; scope = scope->parent) {
		fOpt(ffzNodeIdentifier*) def = ffz_find_definition_in_scope(c, scope, ident->Identifier.name);
		if (def) {
			return def;
		}
	}
	return NULL;
}

FFZ_CAPI ffzCheckInfo ffz_checked_get_info(ffzCheckerContext* ctx, ffzNode* node) {
	ffzCheckInfo* info = f_map64_get(&ctx->infos, (u64)node);
	f_assert(info != NULL);
	return *info;
}

static ffzOk check_identifier(ffzCheckerContext* c, ffzNodeIdentifier* node, ffzCheckInfo* result) {
	fString name = node->Identifier.name;
//	if (name == F_LIT("foo")) f_trap();

	fOpt(ffzNodeIdentifier*) def = ffz_find_definition(c, node);
	if (def == NULL) {
		ERR(node, "Definition not found for an identifier: \"~s\"", name);
	}
	
	bool def_comes_before_this = f_map64_get(&c->infos, (u64)def) != NULL;

	ffzNode* decl = def->parent;
	f_assert(decl->kind == ffzNodeKind_Declare);

	// TODO: check for circular definitions
	//fMapInsertResult circle_chk = f_map64_insert_raw(&c->checked_identifiers, ffz_hash_node_inst(inst), NULL, fMapInsert_DoNotOverride);
	//if (!circle_chk.added) ERR(inst, "Circular definition!"); // TODO: elaborate

	TRY(check_node(c, decl, NULL, InferFlag_Statement, result));

	if (def != node && ffz_checked_decl_is_variable(c, decl) && !def_comes_before_this /*decl->local_id > node->local_id*/) {
		ERR(node, "Variable is being used before it is declared.");
	}
	
	return FFZ_OK;
}

static ffzOk check_return(ffzCheckerContext* c, ffzNode* node, ffzCheckInfo* result) {
	f_trap();//ffzNode* return_val = node->Return.value;
	//
	//ffzNode* proc = ffz_checked_get_parent_proc(node);
	//f_assert(proc->checked.type);
	//
	//fOpt(ffzType*) ret_type = proc->checked.type->Proc.return_type;
	//if (!return_val && ret_type) ERR(node, "Expected a return value, but got none.");
	//if (return_val && !ret_type) ERR(return_val, "Expected no return value, but got one.");
	//
	//if (return_val) {
	//	TRY(check_node(c, return_val, ret_type, 0));
	//}
	return FFZ_OK;
}

static ffzOk check_assign(ffzCheckerContext* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* lhs = node->Op.left;
	ffzNode* rhs = node->Op.right;
	
	ffzCheckInfo lhs_chk;
	TRY(check_node(c, lhs, NULL, 0, &lhs_chk));
	
	bool eat_expression = ffz_node_is_keyword(lhs, ffzKeyword_Eater);
	if (!eat_expression) f_assert(ffz_type_is_concrete(lhs_chk.type));

	ffzCheckInfo rhs_chk;
	TRY(check_node(c, rhs, lhs_chk.type, 0, &rhs_chk));
	
	TRY(check_types_match(c, rhs, rhs_chk.type, lhs_chk.type, "Incorrect type with assignment:"));
	
	//ffzNode* parent = node->parent;
	//bool is_code_scope = parent->kind == ffzNodeKind_Scope || parent->kind == ffzNodeKind_ProcType;
	// TODO: check lvalue
	//if (is_code_scope && lhs->checked.type->tag != ffzTypeTag_Raw && !is_lvalue(c, lhs)) {
	//	ERR(lhs, "Attempted to assign to a non-assignable value.");
	//}
	return FFZ_OK;
}

static ffzOk check_pre_square_brackets(ffzCheckerContext* c, ffzNode* node, ffzCheckInfo* result) {
	f_trap();//ffzNode* rhs = node->Op.right;
	//TRY(check_node(c, rhs, NULL, 0));
	//TRY(verify_is_type_expression(c, rhs));
	//
	//if (ffz_get_child_count(node) == 0) {
	//	*result = make_type_constant(c, ffz_make_type_slice(c, rhs->checked.constant->type));
	//}
	//else if (ffz_get_child_count(node) == 1) {
	//	ffzNode* child = ffz_get_child(node, 0);
	//	s32 length = -1;
	//	if (child->kind == ffzNodeKind_IntLiteral) {
	//		length = (s32)child->IntLiteral.value;
	//	}
	//	else if (ffz_node_is_keyword(child, ffzKeyword_QuestionMark)) {}
	//	else ERR(node, "Unexpected value inside the brackets of an array type; expected an integer literal or `?`");
	//
	//	ffzType* array_type = ffz_make_type_fixed_array(c, rhs->checked.constant->type, length);
	//	*result = make_type_constant(c, array_type);
	//}
	//else ERR(node, "Unexpected value inside the brackets of an array type; expected an integer literal or `_`");
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

static ffzOk check_node(ffzCheckerContext* c, ffzNode* node, OPT(ffzType*) require_type, InferFlags flags, fOpt(ffzCheckInfo*) out_result) {
	ZoneScoped;
	if (fOpt(ffzCheckInfo*) existing = f_map64_get(&c->infos, (u64)node)) {
		*out_result = *existing;
		return FFZ_OK;
	}
	
	for (ffzNode* tag_n = node->first_tag; tag_n; tag_n = tag_n->next) {
		TRY(check_tag(c, tag_n));
	}

	//F_HITS(_c, 357);

	ffzCheckInfo result = {};

	switch (node->kind) {
	case ffzNodeKind_Declare: {
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

		bool is_parameter = ffz_decl_is_parameter(node);
		bool is_local = false;
		bool is_global_variable = ffz_decl_is_global_variable(node);

		if (!is_parameter && !lhs->Identifier.is_constant) {
			// check if this declaration is a local variable

			for (ffzNode* n = node->parent; n; n = n->parent) {
				ffzCheckInfo n_chk = ffz_checked_get_info(c, n);

				if (n->kind == ffzNodeKind_Enum) break;
				if (n->kind == ffzNodeKind_Record) break;
				
				if (n->kind == ffzNodeKind_Scope) continue;
				if (n->kind == ffzNodeKind_If) continue;
				if (n->kind == ffzNodeKind_For) continue;
				is_local = n_chk.type && n_chk.type->tag == ffzTypeTag_Proc;
				break;
			}
		}

		InferFlags rhs_flags = 0;
		if (is_local || is_global_variable) {
			rhs_flags |= InferFlag_AllowUndefinedValues;
		}
		if (!is_local) {
			rhs_flags |= InferFlag_RequireConstant;
		}

		// NOTE: sometimes we want to pass `require_type` down to the rhs, namely with enum field declarations
		ffzCheckInfo rhs_chk;
		TRY(check_node(c, rhs, require_type, rhs_flags, &rhs_chk));
		
		result = rhs_chk; // Declarations cache the value of the right-hand side
		result.is_local_variable = is_local;
		
		if (is_local || is_parameter || is_global_variable) {
			if (is_parameter) {
				// if the parameter is a type expression, then this declaration has that type
				result.type = ffz_ground_type(result.constant, result.type);
			}

			result.constant = NULL; // runtime variables shouldn't store the constant value that the rhs expression might have

			if (!ffz_type_is_concrete(result.type)) {
				ERR(node, "Variable has a non-concrete type: `~s`.", ffz_type_to_string(result.type, c->mod->alc));
			}
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
			
			if (node->loc.start.line_num == node->loc.end.line_num && node->first_child != NULL) {
				ERR(node, "A non-empty scope must span over multiple lines.\n"
					"  (This restriction is currently here to improve debuggability and\n  to simplify the compiler / debug info generation.)");
			}
			// post-check the scope
		}
		else {
			// type-inferred initializer
			TRY(check_curly_initializer(c, require_type, node, flags, &result));
		}
	} break;

	case ffzNodeKind_PolyDef: {
		// When you say `#foo: poly[T] T(100)`, you're declaring foo as a new type, more specifically a polymorphic expression type.
		// It's the same thing as if foo was i.e. a struct type.
		
		for FFZ_EACH_CHILD(n, node) {
			if (n->kind != ffzNodeKind_Identifier) ERR(n, "Expected a polymorphic parameter definition.");
			TRY(try_to_add_definition_to_scope(c, node, n));
		}

		if (node->parent->kind != ffzNodeKind_Declare) {
			ERR(node, "Polymorphic expression must be the right-hand side of a constant declaration.");
		}

		ffzType type = { ffzTypeTag_PolyDef };
		result.type = ffz_make_type(c->project, type);
		result.constant = make_constant(c->project);
		result.constant->node = node;
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		TRY(check_post_round_brackets(c, node, require_type, flags, &result));
	} break;

	case ffzNodeKind_If: break; // post-check
	case ffzNodeKind_For: break; // post-check
	
	case ffzNodeKind_Enum: {
		f_trap();
#if 0
		if (node->parent->kind == ffzNodeKind_Declare && !ffz_node_is_top_level(node->parent)) {
			ERR(node, "A named enum must be defined at the top-level scope, but was not.");
		}

		ffzNode* type_node = node->Enum.internal_type;
		TRY(check_node(c, type_node, NULL, 0));

		if (type_node->checked.type->tag != ffzTypeTag_Type || !ffz_type_is_integer(type_node->checked.constant->type->tag)) {
			ERR(type_node, "Invalid enum type; expected an integer.");
		}

		ffzType enum_type = { ffzTypeTag_Enum };
		enum_type.Enum.internal_type = type_node->checked.constant->type;
		enum_type.size = enum_type.Enum.internal_type->size;
		f_trap(); //enum_type._unique_node = node;

		// :EnumFieldsShouldNotContributeToTypeHash
		// Note that we're making the enum type pointer BEFORE populating all of the fields
		result = make_type_constant(c, ffz_make_type(c, enum_type));
#endif
		// The children are post-checked
	} break;
	
	case ffzNodeKind_Keyword: {
		ffzKeyword keyword = node->Keyword.keyword;
		OPT(ffzType*) type_expr = ffz_builtin_type(c->project, keyword);
		
		if (keyword == ffzKeyword_extern) {
			f_array_push(&c->_extern_libraries, node);
		}

		if (type_expr) {
			result = make_type_constant(c->project, type_expr);
		}
		else {
			switch (keyword) {
			case ffzKeyword_dbgbreak: {} break;
			case ffzKeyword_false: {
				const static ffzConstantData _false = { 0 };
				result.type = ffz_builtin_type(c->project, ffzKeyword_bool);
				result.constant = (ffzConstantData*)&_false;
			} break;
			case ffzKeyword_true: {
				const static ffzConstantData _true = { 1 };
				result.type = ffz_builtin_type(c->project, ffzKeyword_bool);
				result.constant = (ffzConstantData*)&_true;
			} break;
			
			// the type of an eater is 'raw'
			case ffzKeyword_Eater: {
				result.type = ffz_builtin_type(c->project, ffzKeyword_raw);
			} break;
	
			default: f_assert(false);
			}
		}
	} break;

	case ffzNodeKind_ThisDot: {
		f_trap();//fOpt(ffzNode*) assignee = ffz_checked_this_dot_get_assignee(node);
		//if (assignee == NULL) {
		//	ERR(node, "this-value-dot must be used within an assignment, but no assignment was found.");
		//}
		//// When checking assignments, the assignee/lhs is always checked first, so this should be ok.
		//result.type = assignee->checked.type;
	} break;

	case ffzNodeKind_Identifier: { TRY(check_identifier(c, node, &result)); } break;

	case ffzNodeKind_Record: {
		if (node->parent->kind == ffzNodeKind_Declare && !ffz_node_is_top_level(node->parent)) {
			ERR(node, "A named struct must be defined at the top-level scope, but was not.");
		}
		// NOTE: post-check the body
	} break;
	
	case ffzNodeKind_FloatLiteral: {
		if (require_type && require_type->tag == ffzTypeTag_Float) {
			result.type = require_type;
			result.constant = make_constant(c->project);
			if (require_type->size == 4)      result.constant->_f32 = (f32)node->FloatLiteral.value;
			else if (require_type->size == 8) result.constant->_f64 = node->FloatLiteral.value;
			else f_trap();
		}
	} break;

	case ffzNodeKind_IntLiteral: {
		if (!(flags & InferFlag_TypeIsNotRequired_)) {
			result.type = ffz_builtin_type(c->project, ffzKeyword_uint);
			result.constant = make_constant_int(c->project, node->IntLiteral.value);
		}
	} break;

	case ffzNodeKind_StringLiteral: {
		// pointers aren't guaranteed to be valid / non-null, but optional pointers are expected to be null.
		result.type = ffz_builtin_type(c->project, ffzKeyword_string);
		result.constant = make_constant(c->project);
		result.constant->string_zero_terminated = node->StringLiteral.zero_terminated_string;
	} break;

	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_UnaryPlus: {
		f_trap();//ffzNode* rhs = node->Op.right;
		//TRY(check_node(c, rhs, require_type, flags));
		//
		//// hmm... the TypeIsNotRequired flag is a bit weird. It makes us not trust that we got a type.
		//if (rhs->checked.type) {
		//	if (!ffz_type_is_integer(rhs->checked.type->tag) && !ffz_type_is_float(rhs->checked.type->tag)) {
		//		ERR(rhs, "Incorrect arithmetic type; should be an integer or a float.\n    received: ~s",
		//			ffz_type_to_string(c->project, rhs->checked.type));
		//	}
		//}
		//result.type = rhs->checked.type;
	} break;
	
	case ffzNodeKind_PreSquareBrackets: { TRY(check_pre_square_brackets(c, node, &result)); } break;
	
	case ffzNodeKind_PointerTo: {
		ffzNode* rhs = node->Op.right;
		ffzCheckInfo rhs_chk;
		TRY(check_node(c, rhs, NULL, 0, &rhs_chk));
		TRY(verify_is_type_expression(c, rhs, rhs_chk.type));
		result = make_type_constant(c->project, ffz_make_type_ptr(c->project, rhs_chk.constant->type));
	} break;
	
	case ffzNodeKind_ProcType: { TRY(check_proc_type(c, node, &result)); } break;
	
	case ffzNodeKind_PostCurlyBrackets: {
		f_trap();//ffzNode* left = node->Op.left;
		//TRY(check_node(c, left, NULL, 0));
		//TRY(verify_is_type_expression(c, left));
		//TRY(check_curly_initializer(c, left->checked.constant->type, node, flags, &result));
	} break;
	
	case ffzNodeKind_PostSquareBrackets: {
		TRY(check_post_square_brackets(c, node, &result));
	} break;
	
	case ffzNodeKind_MemberAccess: { TRY(check_member_access(c, node, &result)); } break;
	
	case ffzNodeKind_LogicalNOT: {
		f_trap();//result.type = ffz_builtin_type(c, ffzKeyword_bool);
		f_trap();//TRY(check_node(c, node->Op.right, result.type, 0));
	} break;
	
	case ffzNodeKind_LogicalAND: // fallthrough
	case ffzNodeKind_LogicalOR: {
		f_trap();//result.type = ffz_builtin_type(c, ffzKeyword_bool);
		f_trap();//TRY(check_node(c, node->Op.left, result.type, 0));
		f_trap();//TRY(check_node(c, node->Op.right, result.type, 0));
	} break;
	
	case ffzNodeKind_AddressOf: {
		f_trap();//ffzNode* rhs = node->Op.right;
		f_trap();//TRY(check_node(c, rhs, NULL, 0));
		f_trap();//result.type = ffz_make_type_ptr(c, rhs->checked.type);
	} break;
	
	case ffzNodeKind_Dereference: {
		f_trap();//ffzNode* lhs = node->Op.left;
		f_trap();//TRY(check_node(c, lhs, NULL, 0));
		f_trap();//if (lhs->checked.type->tag != ffzTypeTag_Pointer) ERR(node, "Attempted to dereference a non-pointer.");
		f_trap();//result.type = lhs->checked.type->Pointer.pointer_to;
	} break;
	
	case ffzNodeKind_Equal: case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
	case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater: case ffzNodeKind_GreaterOrEqual: {
		f_trap();//OPT(ffzType*) type;
		f_trap();//TRY(check_two_sided(c, node->Op.left, node->Op.right, &type));
		f_trap();//f_assert(type); // TODO
		f_trap();//
		f_trap();//bool is_equality_check = node->kind == ffzNodeKind_Equal || node->kind == ffzNodeKind_NotEqual;
		f_trap();//if (ffz_type_is_comparable(type) || (is_equality_check && ffz_type_is_comparable_for_equality(type))) {
		f_trap();//	result.type = ffz_builtin_type(c, ffzKeyword_bool);
		f_trap();//}
		f_trap();//else {
		f_trap();//	ERR(node, "Operator '~s' is not defined for type '~s'",
		f_trap();//		ffz_node_kind_to_op_string(node->kind), ffz_type_to_string(c->project, type));
		f_trap();//}
	} break;
	
	case ffzNodeKind_Add: case ffzNodeKind_Sub: case ffzNodeKind_Mul:
	case ffzNodeKind_Div: case ffzNodeKind_Modulo: {
		f_trap();//OPT(ffzType*) type;
		f_trap();//TRY(check_two_sided(c, node->Op.left, node->Op.right, &type));
		f_trap();//f_assert(type); // TODO
		f_trap();//
		f_trap();//if (node->kind == ffzNodeKind_Modulo) {
		f_trap();//	if (type && !ffz_type_is_integer(type->tag)) {
		f_trap();//		ERR(node, "Incorrect type with modulo operator; expected an integer.\n    received: ~s", ffz_type_to_string(c->project, type));
		f_trap();//	}
		f_trap();//}
		f_trap();//else {
		f_trap();//	if (type && !ffz_type_is_integer(type->tag) && !ffz_type_is_float(type->tag)) {
		f_trap();//		ERR(node, "Incorrect arithmetic type; expected an integer or a float.\n    received: ~s", ffz_type_to_string(c->project, type));
		f_trap();//	}
		f_trap();//}
		f_trap();//
		f_trap();//result.type = type;
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


#if 0
	// I think we need to introduce 'untyped integer' types to allow for e.g. array_push(&my_u32_array, 1230)
	// or max(0, my_u32)

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
#endif

	if (result.type && result.type->tag == ffzTypeTag_Type && (flags & InferFlag_TypeMeansZeroValue)) {
		result.type = ffz_ground_type(result.constant, result.type);
		result.constant = ffz_zero_value_constant();
	}
	
	if (flags & InferFlag_RequireConstant && !result.is_undefined) {
		if (result.constant == NULL) ERR(node, "Expression is not constant, but constant is required.");
	}

	// Say you have `#X: struct { a: ^X }`
	// When checking it the first time, when we get to the identifier after the ^,
	// it will recurse back into the declaration node and check it.
	// When we come back to the outer declaration check, it has already been checked and cached for us.
	// Let the children do the work for us!

	bool child_already_fully_checked_us = false;
	//if (!(flags & InferFlag_CacheOnlyIfGotType) || result.type) {
	{
		//if (node->has_checked) {
		//	child_already_fully_checked_us = true;
		//}
		//else {
		//	node->has_checked = true;
		//	node->checked = result;
		//}
		f_map64_insert(&c->infos, (u64)node, result);
	}

	// post-check. The idea is to check the children AFTER we have cached the CheckInfo for this node.
	// This gives more freedom to the children to use utilities, such as get_scope() which requires the parents to be checked.
	
	if (!child_already_fully_checked_us) {
		if (result.type && result.type->tag == ffzTypeTag_Proc) { // post-check procedure bodies
			// ignore extern procs.
			// It's a bit weird how the extern tag turns a type declaration into a value declaration. Maybe this should be changed.
			if (node->kind != ffzNodeKind_ProcType) {
				TRY(add_possible_definitions_to_scope(c, node, node));

				// only check the procedure body when we have a physical procedure instance (not polymorphic)
				// and after the proc type has been cached.

				for FFZ_EACH_CHILD(n, node) {
					TRY(check_node(c, n, NULL, InferFlag_Statement, NULL));
				}
			}
		}
		else switch (node->kind) {
		case ffzNodeKind_Scope: {
			if (require_type == NULL) {
				for FFZ_EACH_CHILD(n, node) {
					TRY(check_node(c, n, NULL, flags, NULL));
				}
			}
		} break;
		
		case ffzNodeKind_If: {
			//TRY(check_node(c, node->If.condition, ffz_builtin_type(c, ffzKeyword_bool), 0, NULL));
			//TRY(check_node(c, node->If.true_scope, NULL, InferFlag_Statement, NULL));
			//
			//fOpt(ffzNode*) false_scope = node->If.false_scope;
			//if (false_scope) {
			//	TRY(check_node(c, false_scope, NULL, InferFlag_Statement));
			f_trap();//}
		} break;
		
		case ffzNodeKind_Enum: {
			TRY(post_check_enum(c, node));
		} break;
		
		case ffzNodeKind_For: {
			f_trap();//TRY(add_possible_definition_to_scope(c, node, node->For.header_stmts[0]));
			//
			//for (u32 i = 0; i < 3; i++) {
			//	fOpt(ffzNode*) stmt = node->For.header_stmts[i];
			//	if (stmt) {
			//		if (i == 1) {
			//			TRY(check_node(c, stmt, ffz_builtin_type(c, ffzKeyword_bool), 0));
			//		}
			//		else {
			//			TRY(check_node(c, stmt, NULL, InferFlag_Statement));
			//		}
			//	}
			//}
			//
			//TRY(check_node(c, node->For.scope, NULL, InferFlag_Statement));
		} break;
		
		case ffzNodeKind_Declare: {
			TRY(check_node(c, node->Op.left, NULL, 0, NULL));
		} break;

		case ffzNodeKind_Record: {
#if 0
			TRY(add_possible_definitions_to_scope(c, node, node));

			// Add the record fields only after the type has been registered in the cache. This is to avoid
			// infinite loops when checking.

			// IMPORTANT: We're modifying the type AFTER it was created and hash-deduplicated. So, the things we modify must not change the type hash!
			ffzRecordBuilder b = ffz_record_builder_init(c, 0);

			for FFZ_EACH_CHILD(n, node) {
				if (n->kind != ffzNodeKind_Declare) ERR(n, "Expected a declaration.");
				fString name = ffz_decl_get_name(n);

				TRY(check_node(c, n, NULL, InferFlag_Statement | InferFlag_RequireConstant));

				ffzType* field_type = n->checked.type->tag == ffzTypeTag_Type ? n->checked.constant->type : n->checked.type;
				fOpt(ffzConstantData*) default_value = n->checked.type->tag == ffzTypeTag_Type ? NULL : n->checked.constant;

				ffz_record_builder_add_member(&b, name, field_type, default_value, n);
			}
			
			ffzType* record_type;
			TRY(ffz_record_builder_finish(&b, &record_type));

			//ffzType struct_type = { ffzTypeTag_Record };
			//// we can't create the type yet
			result = make_type_constant(c, ffz_make_type(c, struct_type));
#endif
			f_trap();
		} break;
		}
	}

	*out_result = result;
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
	p->pointer_size = 8;
	
	p->checkers = f_array_make<ffzModule*>(p->persistent_allocator);
	p->sources = f_array_make<ffzSource*>(p->persistent_allocator);
	//p->checkers_dependency_sorted = f_array_make<ffzModule*>(p->persistent_allocator);
	p->link_libraries = f_array_make<fString>(p->persistent_allocator);
	p->link_system_libraries = f_array_make<fString>(p->persistent_allocator);
	p->filesystem_helpers.module_from_directory = f_map64_make<ffzModule*>(p->persistent_allocator);
	
	p->type_from_hash = f_map64_make<ffzType*>(p->persistent_allocator);

	{
		// initialize constant lookup tables and built in types

		p->keyword_from_string = f_map64_make<ffzKeyword>(p->persistent_allocator);
		for (uint i = 1; i < ffzKeyword_COUNT; i++) {
			f_map64_insert(&p->keyword_from_string,
				f_hash64_str(ffz_keyword_to_string((ffzKeyword)i)), (ffzKeyword)i, fMapInsert_DoNotOverride);
		}

		{
			p->builtin_types[ffzKeyword_u8] = ffz_make_basic_type(p, ffzTypeTag_Uint, 1, true);
			p->builtin_types[ffzKeyword_u16] = ffz_make_basic_type(p, ffzTypeTag_Uint, 2, true);
			p->builtin_types[ffzKeyword_u32] = ffz_make_basic_type(p, ffzTypeTag_Uint, 4, true);
			p->builtin_types[ffzKeyword_u64] = ffz_make_basic_type(p, ffzTypeTag_Uint, 8, true);
			p->builtin_types[ffzKeyword_s8] = ffz_make_basic_type(p, ffzTypeTag_Sint, 1, true);
			p->builtin_types[ffzKeyword_s16] = ffz_make_basic_type(p, ffzTypeTag_Sint, 2, true);
			p->builtin_types[ffzKeyword_s32] = ffz_make_basic_type(p, ffzTypeTag_Sint, 4, true);
			p->builtin_types[ffzKeyword_s64] = ffz_make_basic_type(p, ffzTypeTag_Sint, 8, true);
			p->builtin_types[ffzKeyword_f32] = ffz_make_basic_type(p, ffzTypeTag_Float, 4, true);
			p->builtin_types[ffzKeyword_f64] = ffz_make_basic_type(p, ffzTypeTag_Float, 8, true);
			p->builtin_types[ffzKeyword_uint] = ffz_make_basic_type(p, ffzTypeTag_DefaultUint, p->pointer_size, true);
			p->builtin_types[ffzKeyword_int] = ffz_make_basic_type(p, ffzTypeTag_DefaultSint, p->pointer_size, true);
			p->builtin_types[ffzKeyword_bool] = ffz_make_basic_type(p, ffzTypeTag_Bool, 1, true);

			// non-concrete types
			p->builtin_types[ffzKeyword_type] = ffz_make_basic_type(p, ffzTypeTag_Type, 0, false);
			p->builtin_types[ffzKeyword_raw] = ffz_make_basic_type(p, ffzTypeTag_Raw, 0, false);
			p->builtin_types[ffzKeyword_Undefined] = ffz_make_basic_type(p, ffzTypeTag_Undefined, 0, false);
			p->module_type = ffz_make_basic_type(p, ffzTypeTag_Module, 0, false);
			p->type_type = ffz_make_basic_type(p, ffzTypeTag_Type, 0, false);

			ffzConstantData* zero = ffz_zero_value_constant();
			{
				ffzType* string = ffz_make_basic_type(p, ffzTypeTag_String, 16, true);
				p->builtin_types[ffzKeyword_string] = string;

				ffzRecordBuilder b = ffz_record_builder_init(p, 2);
				ffz_record_builder_add_member(&b, F_LIT("ptr"), ffz_make_type_ptr(p, ffz_builtin_type(p, ffzKeyword_u8)), zero, {});
				ffz_record_builder_add_member(&b, F_LIT("len"), ffz_builtin_type(p, ffzKeyword_uint), zero, {});
				ffz_record_builder_finish_to_existing(&b, string);
			}

			{
				ffzRecordBuilder b = ffz_record_builder_init(p, 1);
				ffz_record_builder_add_member(&b, F_LIT("library"), ffz_builtin_type(p, ffzKeyword_string), NULL, {});
				ffz_record_builder_add_member(&b, F_LIT("name_prefix"), ffz_builtin_type(p, ffzKeyword_string), zero, {});
				ffz_record_builder_finish(&b, &p->builtin_types[ffzKeyword_extern]);
			}

			p->builtin_types[ffzKeyword_using] = ffz_make_extra_type(p);
			p->builtin_types[ffzKeyword_global] = ffz_make_extra_type(p);
			p->builtin_types[ffzKeyword_module_defined_entry] = ffz_make_extra_type(p);
			p->builtin_types[ffzKeyword_build_option] = ffz_make_extra_type(p);
		}
	}

	return p;
}

FFZ_CAPI void ffz_module_add_top_level_node_(ffzModule* m, ffzNode* node) {
	f_assert(node->parent == NULL);
	
	if (m->root_last_child) m->root_last_child->next = node;
	else m->root->first_child = node;

	node->parent = m->root;
	m->root_last_child = node;

	// maybe this shouldn't be in here, and be a separate call?
	//TRY(add_possible_definition_to_scope(m, m->root, node));
	//return FFZ_OK;
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

	//for (uint i = 0; i < m->checker_ctx.pending_import_keywords.len; i++) {
	//	ffzNode* import_keyword = m->checker_ctx.pending_import_keywords[i];
	//	
	//	ffzNodeOp* import_op = import_keyword->parent;
	//	f_assert(import_op && import_op->kind == ffzNodeKind_PostRoundBrackets && ffz_get_child_count(import_op) == 1); // TODO: error report
	//
	//	ffzNode* import_decl = import_op->parent;
	//	f_assert(import_decl && import_decl->kind == ffzNodeKind_Declare); // TODO: error report
	//
	//	ffzNode* import_name_node = ffz_get_child(import_op, 0);
	//	f_assert(import_name_node->kind == ffzNodeKind_StringLiteral); // TODO: error report
	//	fString import_path = import_name_node->StringLiteral.zero_terminated_string;
	//		
	//	fOpt(ffzModule*) imported_module = module_from_path(import_path, userdata);
	//	if (!imported_module) {
	//		ERR(import_op, "Imported module contains errors.");
	//	}
	//
	//	f_map64_insert(&m->module_from_import_decl, (u64)import_decl, imported_module, fMapInsert_AssertUnique);
	//	f_map64_insert(&m->import_decl_from_module, (u64)imported_module, import_decl, fMapInsert_AssertUnique); // TODO: error report
	//}
	//
	//m->checker_ctx.pending_import_keywords.len = 0;
	return FFZ_OK;
}

FFZ_CAPI ffzOk ffz_module_check_single_(ffzModule* m, ffzCheckerContext* out_checker_ctx) {
	ZoneScoped;
	VALIDATE(!m->checked);
	//m->error_cb = error_cb;
	//m->error = {};
	ffzCheckerContext ctx = ffz_make_checker_ctx(m);

	ffzCheckInfo checked = {};
	//m->root->has_checked = true;
	//m->root->checked = checked;

	for (ffzNode* n = m->root->first_child; n; n = n->next) {

		// This is a bit dumb way to do this, but right now standalone tags are only checked at top-level. We should
		// probably check them recursively in instanceless_check() or something. :StandaloneTagTopLevel
		if (n->flags & ffzNodeFlag_IsStandaloneTag) {
			TRY(check_tag(&ctx, n));
			continue;
		}
		
		// TODO: make sure it's a constant declaration or global...
		TRY(check_node(&ctx, n, NULL, InferFlag_Statement, NULL));
	}

	f_for_array(ffzNode*, ctx._extern_libraries, it) {
		ffzNode* lit = it.elem->parent;
		ffzCheckInfo lit_info = ffz_checked_get_info(&ctx, lit);
		if (lit_info.constant == NULL) ERR(lit, "`extern` has no {} after it.");
		
		fString library = lit_info.constant->record_fields[0].string_zero_terminated;
		if (library == F_LIT("?")) continue;
		
		if (f_str_cut_start(&library, F_LIT(":"))) {
			f_array_push(&m->project->link_system_libraries, library);
		}
		else {
			if (!f_files_path_to_canonical(m->directory, library, f_temp_alc(), &library)) {
				ERR(lit, "Failed to import external library \"~s\" relative to module base directory \"~s\"", library, m->directory);
			}
			f_array_push(&m->project->link_libraries, library);
		}
	}

	m->checked = true;
	//f_array_push(&m->project->checkers_dependency_sorted, m);
	*out_checker_ctx = ctx;
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

		// What we could then do is have a queue for top-level nodes that need to be (re)checked.
		// When expanding polymorph nodes, push those nodes to the end of the queue. Or if the
		// user wants to modify the tree, they can push the modified nodes to the end of the queue
		// to be re-checked.

		for (ffzNode* n = parse_result.node->first_child; n; n = n->next) {
			n->parent = NULL; // ffz_module_add_top_level_node requires the parent to be NULL
			ffz_module_add_top_level_node_(module, n);
		}

		//f_array_push_n(&module->pending_import_keywords, parse_result.import_keywords);
	}
	
	return module;
}
