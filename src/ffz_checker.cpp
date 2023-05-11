
// The checker checks if the program is correct, and in doing so,
// computes and caches information about the program, such as which declarations
// identifiers are pointing to, what types do expressions have, constant evaluation, and so on.
// If the c succeeds, the program is valid and should compile with no errors.

#define F_DEF_INCLUDE_OS
#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include "tracy/tracy/Tracy.hpp"

#define TRY(x) FFZ_TRY(x)

#define FFZ_CAPI extern "C"

#define PTR2HASH(x) ((u64)x)

static ffzError* make_error(fOpt(ffzNode*) node, fString msg, fAllocator* alc) {
	ffzError* err = f_mem_clone(ffzError{}, alc);
	err->node = node;
	err->message = msg;
	if (node) {
		err->source = node->loc_source;
		err->location = node->loc;
	}
	return err;
}

#define ERR(c, node, fmt, ...) return make_error(node, f_aprint((c)->alc, fmt, __VA_ARGS__), (c)->alc);

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
	//InferFlag_TypeIsNotRequired_ = 1 << 2,
	
	InferFlag_IgnoreUncertainTypes = 1 << 2,

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
static fOpt(ffzError*) check_node(ffzModuleChecker* c, ffzNode* node, fOpt(ffzType*) require_type, InferFlags flags, fOpt(ffzCheckInfo*) out_result);

// ------------------------------

ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, PTR2HASH(enum_type));
	f_hasher_add(&h, value);
	return f_hasher_end(&h);
}

// A ffzNode* by itself shouldn't be associated with semantic info - rather, the semantic info is attached to the checker context, per node.
ffzNodeHash ffz_hash_node(ffzModuleChecker* c, ffzNode* node) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, c->id);
	f_hasher_add(&h, (u64)node);
	return f_hasher_end(&h);
}

// NOTE: if the constant refers to a node, `ctx` must be set
ffzConstantHash ffz_hash_constant(fOpt(ffzModuleChecker*) ctx, ffzConstant constant) {
	fHasher h = f_hasher_begin();
	
	// The type must be hashed into the constant, because otherwise i.e. `u64(0)` and `false` would have the same hash!
	f_hasher_add(&h, PTR2HASH(constant.type));

	switch (constant.type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Pointer: {
		if (constant.value->ptr.as_ptr_to_constant != NULL) f_trap();
		f_hasher_add(&h, constant.value->ptr.as_integer);
	} break;

	case ffzTypeTag_String: {
		f_hasher_add(&h, f_hash64_str(constant.value->string_zero_terminated));
	} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_FixedArray: {
		ffzType* elem_type = constant.type->tag == ffzTypeTag_FixedArray ? constant.type->FixedArray.elem_type : constant.type->Slice.elem_type;
		
		for (u32 i = 0; i < (u32)constant.value->array_elems.len; i++) {
			ffzConstantData elem_data = ffz_constant_array_get_elem(constant, i);
			ffzConstant elem = { elem_type, &elem_data };
			f_hasher_add(&h, ffz_hash_constant(ctx, elem));
		}
	} break;

	case ffzTypeTag_Module: { f_hasher_add(&h, (u64)constant.value->module->self_id); } break;
	case ffzTypeTag_Type: { f_trap(); } break;//{ f_hasher_add(&h, PTR2HASH(constant.value)); } break;
	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Float: {
		u64 val = 0;
		memcpy(&val, constant.value, constant.type->size);
		f_hasher_add(&h, val);
	} break;

	// -- For the following, `ctx` must be set-------------

	case ffzTypeTag_PolyDef: // fallthrough
	case ffzTypeTag_Proc: {
		ffzNode* node = constant.value->node;
		f_hasher_add(&h, ffz_hash_node(ctx, node));
	} break;

	case ffzTypeTag_Record: {
		f_assert(constant.type->Record.is_union == false);
		for (uint i = 0; i < constant.type->record_fields.len; i++) {
			ffzConstant elem = {constant.type->record_fields[i].type, &constant.value->record_fields[i]};
			f_hasher_add(&h, ffz_hash_constant(ctx, elem));
		}
	} break;

	default: f_trap();
	}
	return f_hasher_end(&h);
}

ffzPolymorphHash ffz_hash_polymorph(ffzModuleChecker* c, ffzPolymorph poly) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, ffz_hash_node(c, poly.poly_def));
	for (uint i = 0; i < poly.parameters.len; i++) {
		f_hasher_add(&h, PTR2HASH(poly.parameters[i].value));
	}
	return f_hasher_end(&h);
}

u64 ffz_hash_definition_path(ffzModuleChecker* c, ffzDefinitionPath path) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, f_hash64_str(path.name));
	if (path.parent_scope) {
		f_hasher_add(&h, ffz_hash_node(c, path.parent_scope));
	}
	return f_hasher_end(&h);
}

FFZ_CAPI ffzConstantData* ffz_zero_value_constant() {
	const static ffzConstantData zeroes = {};
	return (ffzConstantData*)&zeroes;
}

static ffzConstant ffz_make_constant_ex(ffzProject* p, fOpt(ffzModuleChecker*) ctx, ffzConstantData value, ffzType* type) {
	ffzConstantHash hash = ffz_hash_constant(ctx, ffzConstant{ type, &value });

	auto entry = f_map64_insert(&p->bank.constant_from_hash, hash, (ffzConstantData*)0, fMapInsert_DoNotOverride);
	if (entry.added) {
		ffzConstantData* constant_ptr = f_mem_clone(value, p->bank.alc);
		*entry._unstable_ptr = constant_ptr;
	}

	return ffzConstant{ type, *entry._unstable_ptr };
}

static ffzConstant make_constant_int(ffzProject* p, u64 _uint, ffzType* type) {
	ffzConstantData constant;
	constant._uint = _uint;
	return ffz_make_constant_ex(p, NULL, constant, type);
}

static void set_result_constant(ffzCheckInfo* info, ffzConstant constant) {
	info->type = constant.type;
	info->const_val = constant.value;
}

ffzType* ffz_ground_type(ffzConstantData* constant, ffzType* type) {
	return type->tag == ffzTypeTag_Type ? ffz_as_type(constant) : type;
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
	case ffzTypeTag_PolyDef: { f_print(w, "<poly-def>"); } break;
	case ffzTypeTag_PolyParam: { f_print(w, "<poly-param>"); } break;
	case ffzTypeTag_Module: { f_print(w, "<module>"); } break;
	//case ffzTypeTag_Extra: { f_print(w, "<extra>"); } break;
	//case ffzTypeTag_Bool: { f_print(w, "bool"); } break;
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
		f_print(w, "[TODO: print length]", type->FixedArray.length);
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

FFZ_CAPI fOpt(ffzCheckInfo*) ffz_maybe_get_checked_info(ffzNode* node) {
	ffzModuleChecker* c = ffz_get_checker(node);
	return f_map64_get(&c->infos, (u64)node);
}

fOpt(ffzNode*) ffz_checked_get_parent_proc(ffzNode* node) {
	for (node = node->parent; node; node = node->parent) {
		fOpt(ffzCheckInfo*) info = ffz_maybe_get_checked_info(node); // Sometimes the parent hasn't been checked yet, i.e. when checking an argument into an implicit polymorphic call
		if (info && info->type && info->type->tag == ffzTypeTag_Proc) {
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

FFZ_CAPI bool ffz_checked_decl_is_local_variable(ffzNodeOpDeclare* decl) {
	return ffz_checked_get_info(decl).is_local_variable;
}

FFZ_CAPI bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl) {
	if (decl->Op.left->Identifier.is_constant) return false;
	return ffz_node_is_top_level(decl);
}

fOpt(ffzNodeIdentifier*) ffz_checked_find_definition_in_scope(ffzNode* scope, fString name) {
	ffzModuleChecker* c = ffz_get_checker(scope);
	ffzDefinitionPath def_path = { scope, name };

	ffzNodeIdentifier** def = f_map64_get(&c->definition_map, ffz_hash_definition_path(c, def_path));
	return def ? *def : NULL;
}

FFZ_CAPI bool ffz_constant_is_zero(ffzConstantData constant) {
	u8 zeroes[sizeof(ffzConstantData)] = {};
	return memcmp(&constant, zeroes, sizeof(ffzConstantData)) == 0;
}

ffzFieldHash ffz_hash_field(ffzType* type, fString member_name) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, PTR2HASH(type));
	f_hasher_add(&h, f_hash64_str(member_name));
	return f_hasher_end(&h);
}

static fOpt(ffzError*) add_fields_to_field_from_name_map(ffzProject* p, ffzType* root_type, ffzType* parent_type,
	fOpt(fArray(u32)*) index_path = NULL, u32 offset_from_root = 0)
{
	fArray(u32) _index_path;
	if (index_path == NULL) {
		index_path = &_index_path;
		_index_path = f_array_make<u32>(p->bank.alc);
	}

	for (u32 i = 0; i < parent_type->record_fields.len; i++) {
		ffzField* field = &parent_type->record_fields[i];
		f_array_push(index_path, i);
		
		ffzTypeRecordFieldUse field_use = { field, offset_from_root + field->offset, f_clone_slice(index_path->slice, p->bank.alc) };
		auto insertion = f_map64_insert(&p->bank.field_from_name_map, ffz_hash_field(root_type, field->name), field_use, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			f_trap();//ERR_NO_NODE(c, "`~s` is already declared before inside (TODO: print struct name) (TODO: print line)", field->name);
		}

		// NOTE: add leaves first, to make sure index_path will be as big as it gets by the time we start taking slices to it
		if (field->has_using) {
			TRY(add_fields_to_field_from_name_map(p, root_type, field->type, index_path));
		}

		f_array_pop(index_path);
	}
	return NULL;
}

FFZ_CAPI bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out) {
	if (ffzTypeRecordFieldUse* result = f_map64_get(&p->bank.field_from_name_map, ffz_hash_field(type, name))) {
		*out = *result;
		return true;
	}
	return false;
}

static fOpt(ffzError*) verify_is_type_expression(ffzModuleChecker* c, ffzNode* node, ffzType* type) {
	if (type->tag != ffzTypeTag_Type && type->tag != ffzTypeTag_PolyParam) {
		ERR(c, node, "Expected a type, but got a value.");
	}
	return NULL;
}

// if this returns true, its ok to bit-cast between the types
static bool types_match(ffzType* src, ffzType* target) {
	if ((src->tag == ffzTypeTag_DefaultUint || src->tag == ffzTypeTag_DefaultSint) &&
		(target->tag == ffzTypeTag_DefaultUint || target->tag == ffzTypeTag_DefaultSint)) return true; // Allow implicit cast between uint and int

	if (src->tag == ffzTypeTag_Raw || target->tag == ffzTypeTag_Raw) return true; // everything can implicitly cast to-and-from raw

	return src == target; // :InternedConstants
}

static bool ffz_constants_match(ffzConstantData* a, ffzConstantData* b) {
	return a == b; // :InternedConstants
}

static fOpt(ffzError*) check_types_match(ffzModuleChecker* c, ffzNode* node, ffzType* received, ffzType* expected, const char* message) {
	if (!types_match(received, expected)) {
		ERR(c, node, "~c\n    received: ~s\n    expected: ~s", message, ffz_type_to_string(received, c->alc), ffz_type_to_string(expected, c->alc));
	}
	return NULL;
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

static fOpt(ffzError*) check_argument_list(ffzModuleChecker* c, ffzNode* node, fSlice(ffzField) fields,
	fOpt(ffzCheckInfo*) record_literal, bool no_infer, InferFlags flags)
{
	bool all_fields_are_constant = true;
	fSlice(ffzConstantData) field_constants;
	if (record_literal) field_constants = f_make_slice_undef<ffzConstantData>(fields.len, c->alc);

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
				ERR(c, arg, "Parameter named \"~s\" does not exist.", name);
			}
			
			if (field_is_given_a_value[i]) ERR(c, arg, "A value has been already given for parameter \"~s\".", name);
		}
		else if (has_used_named_argument) ERR(c, arg, "Using an unnamed argument after a named argument is not allowed.");

		if (i >= fields.len) {
			ERR(c, arg, "Received too many arguments.");
		}

		ffzCheckInfo checked;
		TRY(check_node(c, arg_value, no_infer ? NULL : fields[i].type, flags, &checked));

		if (record_literal) {
			if (checked.const_val) field_constants[i] = *checked.const_val;
			else all_fields_are_constant = false;
		}

		field_is_given_a_value[i] = true;
		i++;
	}

	for (uint i = 0; i < fields.len; i++) {
		if (!field_is_given_a_value[i]) {
			if (!fields[i].has_default_value) {
				ERR(c, node, "An argument is missing for \"~s\".", fields[i].name);
			}
			if (record_literal) {
				field_constants[i] = fields[i].default_value;
			}
		}
	}

	if (record_literal && all_fields_are_constant) {
		ffzConstantData constant;
		constant.record_fields = field_constants;
		record_literal->const_val = ffz_make_constant_ex(c->project, c, constant, record_literal->type).value;
	}

	return NULL;
}

//static bool uint_is_subtype_of(ffzType* type, ffzType* subtype_of) {
//	if (ffz_type_is_unsigned_integer(type->tag) && ffz_type_is_unsigned_integer(subtype_of->tag) && type->size <= subtype_of->size) return true;
//	return false;
//}

inline bool has_non_poly_type(fOpt(ffzType*) type) { return type && type->tag != ffzTypeTag_PolyParam; }

static fOpt(ffzError*) check_two_sided(ffzModuleChecker* c, ffzNode* left, ffzNode* right, fOpt(ffzType*) require_type, InferFlags flags, fOpt(ffzType*)* out_type) {
	// Infer expressions, such as  `x: u32(1) + 50`  or  x: `2 * u32(552)`
	
	// First try to check if we can get a concrete integer type
	ffzCheckInfo left_chk, right_chk;
	TRY(check_node(c, left, NULL, InferFlag_IgnoreUncertainTypes, &left_chk));
	TRY(check_node(c, right, NULL, InferFlag_IgnoreUncertainTypes, &right_chk));

	if (left_chk.type && right_chk.type) {}
	else if (!left_chk.type && right_chk.type) {
		TRY(check_node(c, left, right_chk.type, 0, &left_chk));
	}
	else if (!right_chk.type && left_chk.type) {
		TRY(check_node(c, right, left_chk.type, 0, &right_chk));
	}
	else if (!(flags & InferFlag_IgnoreUncertainTypes)) {
		TRY(check_node(c, left, require_type, 0, &left_chk));
		TRY(check_node(c, right, require_type, 0, &right_chk));
	}

	fOpt(ffzType*) result = NULL;
	if (has_non_poly_type(right_chk.type) && has_non_poly_type(left_chk.type)) {
		if (types_match(left_chk.type, right_chk.type)) {
			result = left_chk.type;
		}
		else {
			ERR(c, left->parent, "Types do not match.\n    left:    ~s\n    right:   ~s",
				ffz_type_to_string(left_chk.type, c->alc), ffz_type_to_string(right_chk.type, c->alc));
		}
	}
	*out_type = result;
	return NULL;
}

FFZ_CAPI u32 ffz_get_encoded_constant_size(ffzType* type) {
	return ffz_type_is_integer(type->tag) ? type->size : sizeof(ffzConstantData);
}

FFZ_CAPI ffzConstantData ffz_constant_array_get_elem(ffzConstant array, u32 index) {
	u32 elem_size = ffz_get_encoded_constant_size(array.type->FixedArray.elem_type);
	ffzConstantData result = *ffz_zero_value_constant();
	//if (array.data->array_elems)
	memcpy(&result, (u8*)array.value->array_elems.data + index*elem_size, elem_size);
	return result;
}

fOpt(ffzError*) try_to_add_definition_to_scope(ffzModuleChecker* c, fOpt(ffzNode*) scope, ffzNodeIdentifier* def) {
	fString name = def->Identifier.name;

	for (ffzNode* test_scope = scope; test_scope; test_scope = test_scope->parent) {
		ffzDefinitionPath path = { test_scope, name };
		ffzNodeIdentifier** existing = f_map64_get(&c->definition_map, ffz_hash_definition_path(c, path));
		if (existing) {
			ERR(c, def, "`~s` is already declared before (at line: ~u32)", name, (*existing)->loc.start.line_num);
		}
	}

	ffzDefinitionPath path = { scope, name };
	f_map64_insert(&c->definition_map, ffz_hash_definition_path(c, path), def, fMapInsert_DoNotOverride);
	return NULL;
}

fOpt(ffzError*) add_possible_definition_to_scope(ffzModuleChecker* c, fOpt(ffzNode*) scope, fOpt(ffzNode*) node) {
	if (node && node->kind == ffzNodeKind_Declare) {
		// NOTE: we need to do this check here, because this function can be called on the node BEFORE having checked the node.
		if (node->Op.left->kind != ffzNodeKind_Identifier) {
			ERR(c, node->Op.left, "The left-hand side of a declaration must be an identifier.");
		}
		TRY(try_to_add_definition_to_scope(c, scope, node->Op.left));
	}
	return NULL;
}

fOpt(ffzError*) add_possible_definitions_to_scope(ffzModuleChecker* c, fOpt(ffzNode*) scope, ffzNode* from_children) {
	for FFZ_EACH_CHILD(n, from_children) {
		TRY(add_possible_definition_to_scope(c, scope, n));
	}
	return NULL;
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

/*
 NOTE: if the type contains a reference to a node, then `ctx` must be set
*/
ffzTypeHash ffz_hash_type(fOpt(ffzModuleChecker*) ctx, ffzType* type) {
	fHasher h = f_hasher_begin();
	f_hasher_add(&h, type->tag);
	
	switch (type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Undefined: break;
	case ffzTypeTag_Module: break;
	case ffzTypeTag_Type: break;
	case ffzTypeTag_String: break;
	case ffzTypeTag_PolyDef: break;
	//case ffzTypeTag_Extra: { f_hasher_add(&h, type->Extra.id); } break;

	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_Record: {
		f_hasher_add(&h, type->tag);
		f_hasher_add(&h, PTR2HASH(type->polymorphed_from));
		f_hasher_add(&h, ffz_hash_node(ctx, type->distinct_node));
	} break;

	case ffzTypeTag_Pointer: { f_hasher_add(&h, PTR2HASH(type->Pointer.pointer_to)); } break;

	case ffzTypeTag_PolyParam: { f_hasher_add(&h, ffz_hash_node(ctx, type->PolyParam.param_node)); } break;

	case ffzTypeTag_Proc: {
		for (uint i = 0; i < type->Proc.in_params.len; i++) {
			f_hasher_add(&h, PTR2HASH(type->Proc.in_params[i].type));
		}
		f_hasher_add(&h, 0); // We must have this hash 'separator' to distinguish between hashing in a parameter type vs return type
		if (type->Proc.return_type) {
			f_hasher_add(&h, PTR2HASH(type->Proc.return_type));
		}
	} break;
	
	case ffzTypeTag_Slice: { f_hasher_add(&h, PTR2HASH(type->Slice.elem_type)); } break;
	case ffzTypeTag_FixedArray: {
		f_hasher_add(&h, PTR2HASH(type->FixedArray.elem_type));
		f_hasher_add(&h, PTR2HASH(type->FixedArray.length.value));
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
	return f_hasher_end(&h);
}

ffzType* ffz_make_type_ex(ffzProject* p, fOpt(ffzModuleChecker*) ctx, ffzType type_desc) {
	ffzTypeHash hash = ffz_hash_type(ctx, &type_desc);

	auto entry = f_map64_insert(&p->bank.type_from_hash, hash, (ffzType*)0, fMapInsert_DoNotOverride);
	if (entry.added) {
		ffzType* type_ptr = f_mem_clone(type_desc, p->bank.alc);
		type_ptr->align = get_alignment(type_ptr, p->pointer_size); // cache the alignment
		*entry._unstable_ptr = type_ptr;
	}

	return *entry._unstable_ptr;
}

inline ffzType* make_type(ffzModuleChecker* ctx, ffzType type_desc) { return ffz_make_type_ex(ctx->project, ctx, type_desc); }
inline ffzConstant make_constant(ffzModuleChecker* ctx, ffzConstantData value, ffzType* type) { return ffz_make_constant_ex(ctx->project, ctx, value, type); }

static ffzType* ffz_make_basic_type(ffzProject* p, ffzTypeTag tag, u32 size, bool is_concrete) {
	ffzType type = { tag };
	type.size = size;
	type.is_concrete.x = is_concrete;
	return ffz_make_type_ex(p, NULL, type);
}

ffzType* ffz_make_type_ptr(ffzProject* p, ffzType* pointer_to) {
	ffzType type = { ffzTypeTag_Pointer };
	type.size = p->pointer_size;
	type.is_concrete.x = true;
	type.Pointer.pointer_to = pointer_to;
	return ffz_make_type_ex(p, NULL, type);
}

struct ffzRecordBuilder {
	ffzProject* project;
	u32 size;
	u32 align;
	bool is_concrete;
	fArray(ffzField) fields;
};

static ffzRecordBuilder ffz_record_builder_init(ffzProject* p, uint fields_cap) {
	//f_assert(record->size == 0);
	return { p, 0, 1, true, f_array_make_cap<ffzField>(fields_cap, p->bank.alc) };
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

static fOpt(ffzError*) ffz_record_builder_finish(ffzRecordBuilder* b, ffzType* type) {
	ffz_record_builder_pre_finish(b);

	type->record_fields = b->fields.slice;
	type->is_concrete.x = b->is_concrete;
	type->size = b->size;
	type->align = b->align;
	TRY(add_fields_to_field_from_name_map(b->project, type, type));

	return NULL;
}

ffzType* ffz_make_type_slice(ffzProject* p, ffzType* elem_type) {
	ffzType type = { ffzTypeTag_Slice };
	type.is_concrete.x = true;
	type.Slice.elem_type = elem_type;
	ffzType* out = ffz_make_type_ex(p, NULL, type);

	if (out->record_fields.len == 0) { // this type hasn't been made before
		ffzRecordBuilder b = ffz_record_builder_init(p, 2);
		ffz_record_builder_add_member(&b, F_LIT("ptr"), ffz_make_type_ptr(p, elem_type), ffz_zero_value_constant(), {});
		ffz_record_builder_add_member(&b, F_LIT("len"), ffz_builtin_type(p, ffzKeyword_uint), ffz_zero_value_constant(), {});
		ffz_record_builder_finish(&b, out);
	}
	return out;
}

ffzType* ffz_make_type_fixed_array(ffzProject* p, ffzType* elem_type, ffzConstant length) {
	//f_assert(ffz_type_is_integer(length->type->tag) || length->type->tag == ffzTypeTag_PolyParam);
	
	ffzType array_type = { ffzTypeTag_FixedArray };
	if (length.type->tag != ffzTypeTag_PolyParam) {
		array_type.size = (u32)length.value->_uint * elem_type->size;
	}

	array_type.is_concrete.x = elem_type->is_concrete.x;
	array_type.FixedArray.elem_type = elem_type;
	array_type.FixedArray.length = length;
	ffzType* out = ffz_make_type_ex(p, NULL, array_type);

	//if (length > 0 && length <= 4 && out->record_fields.len == 0) { // this type hasn't been made before
	//	const static fString fields[] = { F_LIT("x"), F_LIT("y"), F_LIT("z"), F_LIT("w") };
	//	
	//	// We can't use the ffzRecordBuilder here, because we don't want it to build the size of the type.
	//	out->record_fields = f_make_slice_garbage<ffzField>(length, c->alc);
	//	for (u32 i = 0; i < (u32)length; i++) {
	//		out->record_fields[i] = { fields[i], {}, {}, false, elem_type->size * i, elem_type };
	//	}
	//	add_fields_to_field_from_name_map(c, out, out, 0);
	//}
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


/*
 Replace the node at `cursor` with a deep copy of itself, while optionally replacing identifiers with generated constants
*/
static void deep_copy(ffzModule* copy_to_module, ffzCursor cursor, fOpt(fMap64(ffzConstant)*) ident_to_constant) {
	fOpt(ffzNode*) old_node = ffz_get_node_at_cursor(cursor);
	if (!old_node) return;

	ffzNode* new_node = ffz_clone_node(copy_to_module, old_node);
	ffz_replace_node(cursor, new_node);

	// OLD COMMENT, DOESN'T MATTER ANYMORE:
	// First copy special children, then copy regular children.
	// This distinction matters, because in case of a procedure, we want to first recurse into the procedure type and copy the parameters,
	// and only after that recurse into the procedure body. This way the parameter's `local_id` will be smaller than the usage sites,
	// and we can still use this field to check for use-before-define errors.

	if (ffz_node_is_operator(new_node->kind)) {
		deep_copy(copy_to_module, ffz_cursor_op_left(new_node), ident_to_constant);
		deep_copy(copy_to_module, ffz_cursor_op_right(new_node), ident_to_constant);
	}
	else switch (new_node->kind) {
	case ffzNodeKind_Blank: break;
	case ffzNodeKind_Identifier: {
		if (ident_to_constant) {
			fOpt(ffzConstant*) constant = f_map64_get(ident_to_constant, f_hash64_str(new_node->Identifier.name));
			if (constant) {
				new_node->kind = ffzNodeKind_GeneratedConstant;
				new_node->GeneratedConstant.constant = *constant;
			}
		}
	} break;
	case ffzNodeKind_PolyDef: {
		deep_copy(copy_to_module, ffz_cursor_poly_def(new_node), ident_to_constant);
	} break;
	case ffzNodeKind_Keyword: break;
	case ffzNodeKind_ThisDot: break;
	case ffzNodeKind_ProcType: {
		deep_copy(copy_to_module, ffz_cursor_proc_type_out_parameter(new_node), ident_to_constant);
	} break;
	case ffzNodeKind_Record: break;
	case ffzNodeKind_Enum: break;
	case ffzNodeKind_Return: {
		deep_copy(copy_to_module, ffz_cursor_ret_value(new_node), ident_to_constant);
	} break;
	case ffzNodeKind_If: {
		deep_copy(copy_to_module, ffz_cursor_if_condition(new_node), ident_to_constant);
		deep_copy(copy_to_module, ffz_cursor_if_true_scope(new_node), ident_to_constant);
		deep_copy(copy_to_module, ffz_cursor_if_false_scope(new_node), ident_to_constant);
	} break;
	case ffzNodeKind_For: {
		for (int i = 0; i < 3; i++) deep_copy(copy_to_module, ffz_cursor_for_header_stmt(new_node, i), ident_to_constant);
		deep_copy(copy_to_module, ffz_cursor_for_scope(new_node), ident_to_constant);
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
			deep_copy(copy_to_module, cursor, ident_to_constant);

			link_to_next = &ffz_get_node_at_cursor(cursor)->next;
		}
	}

	// Deep copy main children
	{
		ffzNode** link_to_next = &new_node->first_child;
		while (*link_to_next != NULL) {
			ffzCursor cursor = { new_node, link_to_next };
			deep_copy(copy_to_module, cursor, ident_to_constant);

			link_to_next = &ffz_get_node_at_cursor(cursor)->next;
		}
	}
}

static fOpt(ffzError*) instantiate_poly_def(ffzModuleChecker* c, ffzNode* poly_def, fSlice(ffzConstant) args, ffzPolymorph** out_poly) {
	ffzPolymorph poly = {};
	poly.poly_def = poly_def;
	poly.parameters = args;
	auto entry = f_map64_insert(&c->poly_from_hash, ffz_hash_polymorph(c, poly), (ffzPolymorph*)0, fMapInsert_DoNotOverride);
	if (entry.added) {
		*entry._unstable_ptr = f_mem_clone(poly, c->alc);
	}

	ffzPolymorph* poly_ptr = *entry._unstable_ptr;

	if (entry.added) {
		// we want to deep copy the poly expr and check it. When checking it, we want to magically store the poly-parameter constants into
		// the check infos.

		fMap64(ffzConstant) ident_to_constant = f_map64_make<ffzConstant>(c->alc);

		u32 i = 0;
		for FFZ_EACH_CHILD(poly_param, poly.poly_def) {
			f_assert(poly_param->kind == ffzNodeKind_Identifier);
			f_map64_insert(&ident_to_constant, f_hash64_str(poly_param->Identifier.name), args[i]);
			i++;
		}

		// If we're in module X instantiating polymorphic definition Y defined in module Z, then
		// the instantiation should see the definitions from module Z. But, we want to copy the nodes into module X, because
		// we want to check it using the checker of module X (module Z has already been checked).
		// We can easily solve this with a weird trick, where the nodes are copied into X, but the instation's parent node points
		// to the scope in module Z - this works, since ffz_find_definition works by walking up the nodes and looking at cached
		// definitions from those nodes.  :PolyInstantiationWeirdTrick

		ffzNode* poly_expr = poly.poly_def->PolyDef.expr;
		ffzNode* poly_expr_parent = poly_expr->parent;
		deep_copy(c->mod, ffzCursor{ NULL, &poly_expr }, &ident_to_constant);
		
		poly_expr->parent = poly_expr_parent; // NOTE: don't modify the parent!!
		//poly_expr->parent = c->mod->root; // The copied node will be an "invisible" top-level node

		poly_ptr->instantiated_node = poly_expr;
		
		{
			c->instantiating_poly = poly_ptr;
			TRY(check_node(c, poly_expr, NULL, 0, NULL));
			c->instantiating_poly = NULL;
		}
	}
	*out_poly = poly_ptr;
	return NULL;
}

static fOpt(ffzError*) infer_poly_param(ffzModuleChecker* c, ffzConstant known, ffzConstant unknown, fMap64(ffzConstant)* poly_param_to_constant, ffzNode* err_node) {

	if (unknown.type->tag == ffzTypeTag_PolyParam) {
		ffzNode* poly_param = unknown.type->PolyParam.param_node;
		
		fOpt(ffzConstant*) deduced = f_map64_get(poly_param_to_constant, (u64)poly_param);
		if (deduced == NULL) {
			f_map64_insert(poly_param_to_constant, (u64)poly_param, known);
		}
		else {
			if (!ffz_constants_match(deduced->value, known.value)) {
				ERR(c, err_node, "Multiple mismatching values for polymorphic parameter `~s` were inferred from the procedure call site.", poly_param->Identifier.name);
			}
		}
	}

	if (unknown.type->tag == ffzTypeTag_Type && known.type->tag == ffzTypeTag_Type) {
		ffzType* known_t = ffz_as_type(known.value);
		ffzType* unknown_t = ffz_as_type(unknown.value);
		
		if (unknown_t->tag == ffzTypeTag_PolyParam) {
			TRY(infer_poly_param(c, known, {unknown_t, unknown.value}, poly_param_to_constant, err_node));
		}

		if (known_t->tag == unknown_t->tag) {

			fOpt(ffzPolymorph*) source_poly = known_t->polymorphed_from;
			fOpt(ffzPolymorph*) target_poly = unknown_t->polymorphed_from;
			if (source_poly && target_poly && source_poly->poly_def == target_poly->poly_def) {
				f_assert(source_poly->parameters.len == target_poly->parameters.len);
				for (uint i=0; i < source_poly->parameters.len; i++) {
					TRY(infer_poly_param(c, source_poly->parameters[i], target_poly->parameters[i], poly_param_to_constant, err_node));
				}
			}

			switch (unknown_t->tag) {
			default: break;
			case ffzTypeTag_Pointer: {
				TRY(infer_poly_param(c, ffz_as_constant(known_t->Pointer.pointer_to), ffz_as_constant(unknown_t->Pointer.pointer_to), poly_param_to_constant, err_node));
			} break;
			case ffzTypeTag_FixedArray: {
				TRY(infer_poly_param(c, known_t->FixedArray.length, unknown_t->FixedArray.length, poly_param_to_constant, err_node));
				TRY(infer_poly_param(c, ffz_as_constant(known_t->FixedArray.elem_type), ffz_as_constant(unknown_t->FixedArray.elem_type), poly_param_to_constant, err_node));
			} break;
			}
		}
	}
	return NULL;
}

static fOpt(ffzError*) check_call(ffzModuleChecker* c, ffzNode* node, ffzNode* left, ffzCheckInfo left_info, ffzCheckInfo* result) {

	// hmm, so we need to inspect the polymorphic AST tree, because we don't want to duplicate the nodes yet.
	// That means that we don't want to write to anything. Only analyze.
	// Only AFTER we have figured out the poly-args, we may deep copy or (use existing copy for this argument set) nodes, similarly to doing it explicitly.

	ffzType* proc_type = left_info.type;

	if (proc_type->tag == ffzTypeTag_PolyDef) {
		// implicit polymorphic instantiation

		// Simple strategy:
		// 1. check the arguments with no infer targets.
		// 2. infer poly params: loop through/recurse into the parameters, while keeping track of the correct type according to the argument.
		//    If we hit a poly-parameter identifier, then assign the constant to it if it hasn't been assigned yet, otherwise make sure that it matches.
		// 
		// This works, but the problem is with integer literals: how do we deal with i.e. `max(0, my_u32_value)`? If we give `0` the type
		// `int`, then the arguments would have mismatching types.
		// 
		// So, more complicated strategy:
		// 1. Check the argument list with InferFlag_IgnoreUncertainTypes flag
		// 2. infer poly params
		// 3. If there's a poly param missing, then check the argument list again without the flag and infer again.
		// Note that after all of this, we're still checking the arguments once more, so if there were any uncertain types, those will be decided then.

		fMap64(ffzConstant) poly_param_to_constant = f_map64_make<ffzConstant>(c->alc);

		for (int i=0;; i++) {
			ffzNode* poly_def = left_info.const_val->node;
			ffzCheckInfo poly_expr_info = ffz_checked_get_info(poly_def->PolyDef.expr);
			if (poly_expr_info.type->tag != ffzTypeTag_Proc) {
				ERR(c, left, "Attempted to call a non-procedure (~s)", ffz_type_to_string(proc_type, c->alc));
			}

			fSlice(ffzField) param_fields = poly_expr_info.type->Proc.in_params;
			TRY(check_argument_list(c, node, param_fields, NULL, true, i == 0 ? InferFlag_IgnoreUncertainTypes : 0));

			// Loop through the procedure call arguments and try to infer the polymorphic parameters from them

			u32 arg_i = 0;
			for FFZ_EACH_CHILD(arg, node) {
				if (ffz_checked_has_info(arg)) {
					ffzConstant unknown = ffz_as_constant(param_fields[arg_i].type); // there's no way to go from here to the poly param...

					ffzConstant known = ffz_as_constant(ffz_checked_get_info(arg).type);

					// we can get the checked constant
					TRY(infer_poly_param(c, known, unknown, &poly_param_to_constant, node));
				}
				arg_i++;
			}

			// Now we know the parameter types and we can instantiate the polymorph!

			fArray(ffzConstant) args = f_array_make<ffzConstant>(c->alc);
			bool inferred_all = true;
			
			for FFZ_EACH_CHILD(param, poly_def) {
				fOpt(ffzConstant*) deduced = f_map64_get(&poly_param_to_constant, (u64)param);
				if (deduced == NULL) {
					if (i == 0) {
						inferred_all = false;
						break;
					}
					ERR(c, node, "Polymorphic argument `~s` could not be inferred from the procedure call site.", param->Identifier.name);
				}
				else {
					f_array_push(&args, *deduced);
				}
			}
			
			if (!inferred_all) {
				continue; // Try again without InferFlag_IgnoreUncertainTypes
			}

			ffzPolymorph* poly;
			TRY(instantiate_poly_def(c, poly_def, args.slice, &poly));
			proc_type = ffz_checked_get_info(poly->instantiated_node).type;

			result->call_implicit_poly = poly;
			break;
		}
	}

	if (proc_type->tag != ffzTypeTag_Proc) {
		ERR(c, left, "Attempted to call a non-procedure (~s)", ffz_type_to_string(proc_type, c->alc));
	}

	result->type = proc_type->Proc.return_type;
	TRY(check_argument_list(c, node, proc_type->Proc.in_params, NULL, false, 0));
	return NULL;
}

static fOpt(ffzError*) check_post_round_brackets(ffzModuleChecker* c, ffzNode* node, ffzType* require_type, InferFlags flags, ffzCheckInfo* result) {
	ffzNode* left = node->Op.left;
	bool fall = true;
	if (left->kind == ffzNodeKind_Keyword) {
		ffzKeyword keyword = left->Keyword.keyword;
		if (ffz_keyword_is_bitwise_op(keyword)) {
			if (ffz_get_child_count(node) != (keyword == ffzKeyword_bit_not ? 1 : 2)) {
				ERR(c, node, "Incorrect number of arguments to a bitwise operation.");
			}
			
			ffzNode* first = ffz_get_child(node, 0);
			if (keyword == ffzKeyword_bit_not) {
				ffzCheckInfo checked;
				TRY(check_node(c, first, require_type, flags, &checked));
				result->type = checked.type;
			}
			else {
				ffzNode* second = ffz_get_child(node, 1);
				TRY(check_two_sided(c, first, second, require_type, 0, &result->type));
			}
			
			if (result->type && !is_basic_type_size(result->type->size)) {
				ERR(c, node, "bitwise operations only allow sizes of 1, 2, 4 or 8; Received: ~u32", result->type->size);
			}
			
			fall = false;
		}
		else if (keyword == ffzKeyword_size_of || keyword == ffzKeyword_align_of) {
			if (ffz_get_child_count(node) != 1) {
				ERR(c, node, "Incorrect number of arguments to ~s.", ffz_keyword_to_string(keyword));
			}
			
			ffzCheckInfo first_checked;
			TRY(check_node(c, ffz_get_child(node, 0), NULL, 0, &first_checked));
			ffzType* type = ffz_ground_type(first_checked.const_val, first_checked.type);
			
			result->type = ffz_builtin_type(c->project, ffzKeyword_uint);
			result->const_val = make_constant_int(c->project, keyword == ffzKeyword_align_of ? type->align : type->size, result->type).value;
			fall = false;
		}
		else if (keyword == ffzKeyword_import) {
			result->type = c->project->type_module;
			//ffzNode* import_decl = node->parent;
			//constant.module = *f_map64_get(&c->module_from_import_decl, (u64)import_decl);
			
			ffzConstantData constant;
			constant.module = c->module_from_import(c->mod, node);
			
			for (uint i=0; i<c->imported_modules.len; i++) {
				if (c->imported_modules[i] == constant.module) f_trap(); // modules should be imported only once!!
			}

			f_array_push(&c->imported_modules, constant.module);

			f_assert(constant.module != NULL);
			result->const_val = make_constant(c, constant, result->type).value;
			fall = false;
		}
	}
	if (fall) {
		ffzCheckInfo left_info;
		TRY(check_node(c, left, NULL, 0, &left_info));
		ffzType* left_type = left_info.type;

		if (left_type->tag == ffzTypeTag_Type) { // Type cast
			if (left_info.const_val == NULL) ERR(c, left, "Target type for type-cast was not a constant.");

			result->type = ffz_as_type(left_info.const_val);
			if (ffz_get_child_count(node) != 1) ERR(c, node, "Incorrect number of arguments in type-cast; should be 1.");

			ffzNode* arg = ffz_get_child(node, 0);
			
			// check the expression, but do not enforce the type inference, as the type inference rules are
			// more strict than a manual cast. For example, an integer cannot implicitly cast to a pointer, but when inside a cast it can.
			
			ffzCheckInfo arg_info;
			TRY(check_node(c, arg, result->type, InferFlag_NoTypesMatchCheck, &arg_info));
			
			result->is_undefined = arg_info.type->tag == ffzTypeTag_Type && ffz_as_type(arg_info.const_val)->tag == ffzTypeTag_Undefined;
			if (!(flags & InferFlag_AllowUndefinedValues) && result->is_undefined) {
				ERR(c, arg, "Invalid place for an undefined value. Undefined values are only allowed in variable declarations.");
			}
			
			/*
			 Constant cast - For now, let's only allow constant cast from integer to pointer.
			*/
			if (!result->is_undefined && arg_info.const_val &&
				ffz_type_is_integer(result->type->tag) && !ffz_type_is_pointer_ish(arg_info.type->tag))
			{
				ffzConstantData ptr_constant;
				ptr_constant.ptr = { arg_info.const_val->_uint, NULL };
				result->const_val = make_constant(c, ptr_constant, result->type).value;
			}

			if (!result->is_undefined && !type_can_be_casted_to(c->project, arg_info.type, result->type)) {
				TRY(check_types_match(c, node, arg_info.type, result->type, "Invalid type cast:"));
			}
		}
		else {
			TRY(check_call(c, node, left, left_info, result));
		}
	}
	return NULL;
}

static fOpt(ffzError*) check_curly_initializer(ffzModuleChecker* c, ffzType* type, ffzNode* node, InferFlags flags, ffzCheckInfo* result) {
	result->type = type;

	if (type->tag == ffzTypeTag_Proc) {
		// Procedure initializer, e.g. proc{dbgbreak}
		ffzConstantData constant = {};
		constant.node = node;
		result->const_val = ffz_make_constant_ex(c->project, c, constant, type).value;
	}
	else if (type->tag == ffzTypeTag_Slice || type->tag == ffzTypeTag_FixedArray) {
		// Array or slice initializer, e.g. []int{1, 2, 3} or [3]int{1, 2, 3}

		ffzType* elem_type = type->tag == ffzTypeTag_Slice ? type->Slice.elem_type : type->FixedArray.elem_type;
		fArray(ffzConstantData*) elems = f_array_make<ffzConstantData*>(f_temp_alc());
		bool all_elems_are_constant = true;

		for FFZ_EACH_CHILD(n, node) {
			ffzCheckInfo n_info;
			TRY(check_node(c, n, elem_type, 0, &n_info));
			f_array_push(&elems, n_info.const_val);
			all_elems_are_constant = all_elems_are_constant && n_info.const_val != NULL;
		}

		if (type->tag == ffzTypeTag_FixedArray && type->FixedArray.length.type->tag != ffzTypeTag_PolyParam) {
			uint expected = type->FixedArray.length.value->_uint;
			if (elems.len != expected) {
				ERR(c, node, "Incorrect number of array initializer arguments. Expected ~u32, got ~u32", expected, (u32)elems.len);
			}
		}

		// For slices, we don't want to give the node a constant value if it's a local/temporary
		// to make sure a stack copy is made of the data.
		bool allow_constant = type->tag != ffzTypeTag_Slice || (flags & InferFlag_RequireConstant);

		if (all_elems_are_constant && allow_constant) {
			u32 elem_size = ffz_get_encoded_constant_size(elem_type);
			void* data = f_mem_alloc(elem_size * elems.len, c->project->bank.alc);
			for (uint i = 0; i < elems.len; i++) {
				memcpy((u8*)data + elem_size * i, elems[i], elem_size);
			}
			ffzConstantData constant;
			constant.array_elems.data = data;
			constant.array_elems.len = (u32)elems.len;
			result->const_val = ffz_make_constant_ex(c->project, c, constant, result->type).value;
		}
	}
	else if (type->tag == ffzTypeTag_Record) {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) {
			ERR(c, node, "Union initialization with {} is not currently supported.");
		}
		
		// TODO: see what happens if you try to declare normally `123: 5215`
		TRY(check_argument_list(c, node, type->record_fields, result, false, 0));
	}
	else {
		ERR(c, node, "{}-initializer is not allowed for `~s`.", ffz_type_to_string(type, c->alc));
	}

	return NULL;
}

#if 0
FFZ_CAPI fOpt(ffzNode*) ffz_constant_to_node(ffzModule* m, ffzConstant constant) {
	// For simplicity, let's print the constant and parse it. I think we should change this to a direct translation. @speed
	//fString constant_string = ffz_constant_to_string(m->project, constant);
	ffzNode* result = NULL;
	switch (constant.type->tag) {
	case ffzTypeTag_Invalid: { f_trap(); } break;
	//case ffzTypeTag_Raw: {} break;
	//case ffzTypeTag_Undefined: {} break;
	case ffzTypeTag_Type: {
		result = ffz_type_to_node(m, constant.value->type);
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
#endif

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

static fOpt(ffzError*) check_post_square_brackets(ffzModuleChecker* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* left = node->Op.left;
	ffzCheckInfo left_chk;
	TRY(check_node(c, left, NULL, 0, &left_chk));

	if (left_chk.type->tag == ffzTypeTag_PolyDef) {
		fArray(ffzConstant) args = f_array_make<ffzConstant>(c->alc);

		for FFZ_EACH_CHILD(arg, node) {
			ffzCheckInfo arg_chk;
			TRY(check_node(c, arg, NULL, InferFlag_RequireConstant, &arg_chk));
			f_array_push(&args, ffzConstant{ arg_chk.type, arg_chk.const_val });
		}

		ffzPolymorph* poly;
		TRY(instantiate_poly_def(c, left_chk.const_val->node, args.slice, &poly));

		*result = ffz_checked_get_info(poly->instantiated_node);
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
			ERR(c, left, "Expected an array, a slice, or a polymorphic expression before [].\n    received: ~s", ffz_type_to_string(left_type, c->alc));
		}

		ffzType* elem_type = subscriptable_type->tag == ffzTypeTag_Slice ? subscriptable_type->Slice.elem_type : subscriptable_type->FixedArray.elem_type;

		u32 child_count = ffz_get_child_count(node);
		if (child_count == 1) {
			ffzNode* index = ffz_get_child(node, 0);

			ffzCheckInfo index_info;
			TRY(check_node(c, index, NULL, 0, &index_info));

			if (!ffz_type_is_integer(index_info.type->tag)) {
				ERR(c, index, "Incorrect type with a slice index; should be an integer.\n    received: ~s", ffz_type_to_string(index_info.type, c->alc));
			}

			result->type = elem_type;
		}
		else if (child_count == 2) {
			ffzNode* lo = ffz_get_child(node, 0);
			ffzNode* hi = ffz_get_child(node, 1);

			if (lo->kind != ffzNodeKind_Blank) {
				ffzCheckInfo lo_info;
				TRY(check_node(c, lo, NULL, 0, &lo_info));
				if (!ffz_type_is_integer(lo_info.type->tag)) ERR(c, lo, "Expected an integer.");
			}
			if (hi->kind != ffzNodeKind_Blank) {
				ffzCheckInfo hi_info;
				TRY(check_node(c, hi, NULL, 0, &hi_info));
				if (!ffz_type_is_integer(hi_info.type->tag)) ERR(c, hi, "Expected an integer.");
			}

			result->type = ffz_make_type_slice(c->project, elem_type);
		}
		else {
			ERR(c, node, "Incorrect number of arguments inside subscript/slice operation.");
		}
	}
	return NULL;
}

FFZ_CAPI fString ffz_get_import_name(ffzModule* m, ffzModule* imported_module) {
	f_trap();//fOpt(ffzNode**) module_import_decl = f_map64_get(&c->import_decl_from_module, (u64)imported_module);
	//if (module_import_decl) {
	//	return (*module_import_decl)->Op.left->Identifier.name;
	//}
	return {};
}

static fOpt(ffzError*) check_member_access(ffzModuleChecker* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* left = node->Op.left;
	ffzNode* right = node->Op.right;
	if (right->kind != ffzNodeKind_Identifier) {
		ERR(c, node, "Invalid member access; the right side was not an identifier.");
	}

	//F_HITS(_c, 955);
	// Maybe we shouldn't even have the 'in' keyword?
	// since in  V3{x = 1, y = 2, z = 3}  the fields are added to the namespace, why not in
	// MyAdderProc{ ret a + b }  as well? I guess the main thing is "where does this variable come from?"
	// In struct instance it's obvious (since you can't declare/assign to your own variables!)

	fString member_name = right->Identifier.name;
	
	if (left->kind == ffzNodeKind_Identifier && left->Identifier.name == F_LIT("in")) {
		fOpt(ffzNode*) parent_proc = ffz_checked_get_parent_proc(node);
		f_assert(parent_proc != NULL);
		ffzType* proc_type = ffz_checked_get_info(parent_proc).type;

		if (parent_proc->Op.left->kind == ffzNodeKind_ProcType) {
			ERR(c, left, "`in` is not allowed when the procedure parameters are accessible by name.");
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
			ERR(c, right, "Declaration not found for '~s' inside procedure input parameter list.", member_name);
		}
	}
	else {
		ffzCheckInfo left_info;
		TRY(check_node(c, left, NULL, 0, &left_info));
		fOpt(ffzConstantData*) left_constant = left_info.const_val;
		
		if (left_info.type->tag == ffzTypeTag_Module) {
			ffzModule* left_module = left_constant->module;
			// we also need a way to go from module to checker context...

			fOpt(ffzNode*) def = ffz_checked_find_definition_in_scope(left_module->root, member_name);
			if (def && def->parent->kind == ffzNodeKind_Declare) {
				*result = ffz_checked_get_info(def->parent);
			}
			else {
				ERR(c, right, "Declaration not found for '~s' inside '~s'", member_name, ffz_get_import_name(c->mod, left_module));
			}
		}
		else if (left_info.type->tag == ffzTypeTag_Type && ffz_as_type(left_constant)->tag == ffzTypeTag_Enum) {
			ffzType* enum_type = ffz_as_type(left_constant);

			// hmm, what to do with crap like this? Maybe store the map in the enum type itself. But by pointer, to not pollute the size.
			// Or just store a pointer to the ffzCheckerContext...?
			// But then again, we're storing a pointer in the type to the `unique_node`. And from there, we can get the module.
			// So maybe we ask for a `ffzModule*` -> `ffzCheckerContext*` callback?

			f_trap(); //ffzModule* enum_type_module = c->project->checkers[enum_type->checker_id];
			//ffzFieldHash member_key = ffz_hash_field(left_constant->type, member_name);
			//
			//if (u64* val = f_map64_get(&enum_type_module->enum_value_from_name, member_key)) {
			//	result->type = left_constant->type;
			//	result->constant = make_constant_int(c, *val);
			//}
			//else {
			//	ERR(c, right, "Declaration not found for '~s' inside '~s'", member_name, ffz_type_to_string(c->project, enum_type));
			//}
		}
		else {
			ffzType* dereferenced_type = left_info.type->tag == ffzTypeTag_Pointer ? left_info.type->Pointer.pointer_to : left_info.type;
			ffzTypeRecordFieldUse field;
			if (ffz_type_find_record_field_use(c->project, dereferenced_type, member_name, &field)) {
				result->type = field.src_field->type;
				
				// Find the constant value for this member
				if (left_constant != NULL) {
					result->const_val = left_constant;
					for (u32 i = 0; i < field.index_path.len; i++) {
						u32 member_idx = field.index_path[i];
						result->const_val = &result->const_val->record_fields[member_idx];
					}
				}
			}
			else {
				ERR(c, right, "Declaration not found for '~s' inside '~s'", member_name, ffz_type_to_string(dereferenced_type, c->alc));
			}
		}
	}

	return NULL;
}

static fOpt(ffzError*) check_tag(ffzModuleChecker* c, ffzNode* tag) {
	ffzCheckInfo info;
	TRY(check_node(c, tag, NULL, InferFlag_TypeMeansZeroValue | InferFlag_RequireConstant, &info));
	if (info.type->tag != ffzTypeTag_Record) {
		ERR(c, tag, "Tag was not a struct literal.", "");
	}

	auto tags = f_map64_insert(&c->all_tags_of_type, PTR2HASH(info.type), {}, fMapInsert_DoNotOverride);
	if (tags.added) *tags._unstable_ptr = f_array_make<ffzNode*>(c->alc);
	f_array_push(tags._unstable_ptr, tag);
	return NULL;
}

static ffzType* ffz_make_extra_type(ffzProject* p) {
	// NOTE: we're not interning this type using `ffz_make_type_ex`, because we always want an unique instance.
	return f_mem_clone(ffzType{ ffzTypeTag_Record }, p->bank.alc);
}

FFZ_CAPI ffzModuleChecker* make_checker_ctx(ffzModule* mod, fOpt(ffzModule*)(*module_from_import)(ffzModule*, ffzNode*), fAllocator* alc) {
	ffzModuleChecker* c = f_mem_clone(ffzModuleChecker{}, alc);
	c->mod = mod;
	c->project = mod->project;
	c->id = mod->next_checker_ctx_id++;
	c->module_from_import = module_from_import;
	c->alc = alc;
	c->infos = f_map64_make<ffzCheckInfo>(alc);
	c->definition_map = f_map64_make<ffzNodeIdentifier*>(alc);
	c->enum_value_from_name = f_map64_make<u64>(alc);
	c->enum_value_is_taken = f_map64_make<ffzNode*>(alc);
	c->imported_modules = f_array_make<ffzModule*>(alc);
	//c.pending_import_keywords = f_array_make<ffzNode*>(c.alc);
	c->all_tags_of_type = f_map64_make<fArray(ffzNode*)>(alc);
	c->poly_from_hash = f_map64_make<ffzPolymorph*>(alc);
	//c.polymorphs = f_array_make<ffzPolymorph>(c.alc); f_array_push(&c.polymorphs, {}); // FFZ_POLYMORPH_ID_NONE
	//c->_extern_libraries = f_array_make<ffzNode*>(alc);
	//c.import_decl_from_module = f_map64_make<ffzNode*>(c.alc);
	//c.module_from_import_decl = f_map64_make<ffzModule*>(c.alc);
	return c;
}

FFZ_CAPI ffzModule* ffz_new_module(ffzProject* p, fAllocator* alc) {
	ffzModule* c = f_mem_clone(ffzModule{}, alc);
	c->self_id = p->next_module_id++;
	c->project = p;
	c->alc = alc;
	c->root = ffz_new_node(c, ffzNodeKind_Scope);
	return c;
}

FFZ_CAPI fOpt(ffzNode*) ffz_checked_this_dot_get_assignee(ffzNodeThisValueDot* dot) {
	for (ffzNode* p = dot->parent; p; p = p->parent) {
		//fOpt(ffzCheckInfo*) info = ffz_maybe_get_checked_info(p); // Sometimes the parent hasn't been checked yet, i.e. when checking an argument into an implicit polymorphic call
		if (p->kind == ffzNodeKind_Assign) {
			return p->Op.left;
		}
	}
	return NULL;
}

FFZ_CAPI fOpt(ffzConstantData*) ffz_checked_get_tag_of_type(ffzNode* node, ffzType* tag_type) {
	for (ffzNode* tag_n = node->first_tag; tag_n; tag_n = tag_n->next) {
		ffzCheckInfo info = ffz_checked_get_info(tag_n);
		if (types_match(info.type, tag_type)) {
			return info.const_val;
		}
	}
	return NULL;
}

FFZ_CAPI fOpt(ffzConstantData*) ffz_checked_get_tag(ffzNode* node, ffzKeyword tag) {
	ffzType* type = ffz_builtin_type(node->_module->project, tag);
	return ffz_checked_get_tag_of_type(node, type);
}

static fOpt(ffzError*) post_check_enum(ffzModuleChecker* c, ffzNode* node) {
	f_trap();
#if 0
	ffzType* enum_type = node->checked.constant->type;

	TRY(add_possible_definitions_to_scope(c, node, node));

	fArray(ffzTypeEnumField) fields = f_array_make<ffzTypeEnumField>(c->alc);
	
	for FFZ_EACH_CHILD(n, node) {
		if (n->kind != ffzNodeKind_Declare) ERR(c, n, "Expected a declaration; got: [~s]", ffz_node_kind_to_string(n->kind));

		// NOTE: Infer the declaration from the enum internal type!
		TRY(check_node(c, n, enum_type->Enum.internal_type, InferFlag_Statement | InferFlag_RequireConstant));

		u64 val = n->checked.constant->_uint;
		
		ffzFieldHash key = ffz_hash_field(enum_type, ffz_decl_get_name(n));
		f_map64_insert(&c->enum_value_from_name, key, val);

		f_array_push(&fields, ffzTypeEnumField{ ffz_decl_get_name(n), val });

		auto val_taken = f_map64_insert(&c->enum_value_is_taken, ffz_hash_enum_value(enum_type, val), n, fMapInsert_DoNotOverride);
		if (!val_taken.added) {
			fString taken_by = ffz_decl_get_name((*val_taken._unstable_ptr));
			ERR(c, n->Op.right, "The enum value `~u64` is already taken by `~s`.", val, taken_by);
		}
	}
	
	enum_type->Enum.fields = fields.slice;
#endif
	return NULL;
}

static fOpt(ffzError*) check_proc_type(ffzModuleChecker* c, ffzNode* node, ffzCheckInfo* result) {
	ffzType proc_type = { ffzTypeTag_Proc };
	proc_type.is_concrete.x = true;
	//proc_type.unique_node = node;
	proc_type.size = c->project->pointer_size;
	
	ffzNode* parameter_scope = node->parent->kind == ffzNodeKind_PostCurlyBrackets ? node->parent : node;
	TRY(add_possible_definitions_to_scope(c, parameter_scope, node));

	fArray(ffzField) in_parameters = f_array_make<ffzField>(c->alc);
	for FFZ_EACH_CHILD(param, node) {
		if (param->kind != ffzNodeKind_Declare) ERR(c, param, "Expected a declaration.");
		
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
		proc_type.Proc.return_type = ffz_as_type(return_value_chk.const_val);
	}
	
	ffzType* type = make_type(c, proc_type);
	if (ffz_checked_get_tag(node->parent, ffzKeyword_extern)) {
		// if it's an extern proc, then don't turn it into a type type!!
		ffzConstantData constant;
		constant.node = node;
		set_result_constant(result, make_constant(c, constant, type));
	}
	else {
		set_result_constant(result, ffz_as_constant(type));
	}
	return NULL;
}

FFZ_CAPI fOpt(ffzNodeIdentifier*) ffz_find_definition(ffzNodeIdentifier* ident) {
	for (fOpt(ffzNode*) scope = ident; scope; scope = scope->parent) {
		fOpt(ffzNodeIdentifier*) def = ffz_checked_find_definition_in_scope(scope, ident->Identifier.name);
		if (def) {
			return def;
		}
	}
	return NULL;
}

FFZ_CAPI bool ffz_checked_has_info(ffzNode* node) {
	ffzModuleChecker* c = ffz_get_checker(node);
	return f_map64_get(&c->infos, (u64)node) != NULL;
}

FFZ_CAPI ffzCheckInfo ffz_checked_get_info(ffzNode* node) {
	ffzModuleChecker* c = ffz_get_checker(node);
	ffzCheckInfo* info = f_map64_get(&c->infos, (u64)node);
	f_assert(info != NULL);
	return *info;
}

static fOpt(ffzError*) check_identifier(ffzModuleChecker* c, ffzNodeIdentifier* node, ffzCheckInfo* result) {
	fString name = node->Identifier.name;
//	if (name == F_LIT("foo")) f_trap();

	fOpt(ffzNodeIdentifier*) def = ffz_find_definition(node);
	if (def == NULL) {
		ERR(c, node, "Definition not found for an identifier: \"~s\"", name);
	}
	
	bool def_comes_before_this = f_map64_get(&c->infos, (u64)def) != NULL;

	if (def->parent->kind == ffzNodeKind_PolyDef) {
		if (def == node) {
			// The PolyParam type is weird. The value that it stores is its own type.
			ffzType type_desc = {ffzTypeTag_PolyParam};
			type_desc.PolyParam.param_node = node;
			result->type = make_type(c, type_desc);
			result->const_val = ffz_as_constant(result->type).value;
		}
		else {
			*result = ffz_checked_get_info(def);
		}
	}
	else {
		ffzNode* decl = def->parent;
		f_assert(decl->kind == ffzNodeKind_Declare);

		// TODO: check for circular definitions
		//fMapInsertResult circle_chk = f_map64_insert_raw(&c->checked_identifiers, ffz_hash_node_inst(inst), NULL, fMapInsert_DoNotOverride);
		//if (!circle_chk.added) ERR(c, inst, "Circular definition!"); // TODO: elaborate

		bool was_inside_poly = c->is_inside_polymorphic_node;
		c->is_inside_polymorphic_node = ffz_node_is_polymorphic(decl);

		TRY(check_node(c, decl, NULL, InferFlag_Statement, result));

		c->is_inside_polymorphic_node = was_inside_poly;

		if (def != node && ffz_checked_decl_is_variable(decl) && !def_comes_before_this /*decl->local_id > node->local_id*/) {
			ERR(c, node, "Variable is being used before it is declared.");
		}
	}
	
	return NULL;
}

static fOpt(ffzError*) check_return(ffzModuleChecker* c, ffzNode* node) {
	ffzNode* return_val = node->Return.value;
	
	ffzNode* proc = ffz_checked_get_parent_proc(node);
	ffzCheckInfo proc_info = ffz_checked_get_info(proc);

	fOpt(ffzType*) ret_type = proc_info.type->Proc.return_type;
	if (!return_val && ret_type) ERR(c, node, "Expected a return value, but got none.");
	if (return_val && !ret_type) ERR(c, return_val, "Expected no return value, but got one.");
	
	if (return_val) {
		TRY(check_node(c, return_val, ret_type, 0, NULL));
	}
	return NULL;
}

static fOpt(ffzError*) check_assign(ffzModuleChecker* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* lhs = node->Op.left;
	ffzNode* rhs = node->Op.right;
	
	ffzCheckInfo lhs_chk;
	TRY(check_node(c, lhs, NULL, 0, &lhs_chk));
	
	bool eat_expression = ffz_node_is_keyword(lhs, ffzKeyword_Eater);
	if (!eat_expression && lhs_chk.type) f_assert(ffz_type_is_concrete(lhs_chk.type));

	ffzCheckInfo rhs_chk;
	TRY(check_node(c, rhs, lhs_chk.type, 0, &rhs_chk));
	
	if (!c->is_inside_polymorphic_node) {
		TRY(check_types_match(c, rhs, rhs_chk.type, lhs_chk.type, "Incorrect type with assignment:"));
	}

	//ffzNode* parent = node->parent;
	//bool is_code_scope = parent->kind == ffzNodeKind_Scope || parent->kind == ffzNodeKind_ProcType;
	// TODO: check lvalue
	//if (is_code_scope && lhs->checked.type->tag != ffzTypeTag_Raw && !is_lvalue(c, lhs)) {
	//	ERR(c, lhs, "Attempted to assign to a non-assignable value.");
	//}
	return NULL;
}

FFZ_CAPI bool ffz_node_is_polymorphic(ffzNode* node) {
	for (node = node->parent; node; node = node->parent) {
		if (node->kind == ffzNodeKind_PolyDef) return true;
	}
	return false;
}

static fOpt(ffzError*) check_pre_square_brackets(ffzModuleChecker* c, ffzNode* node, ffzCheckInfo* result) {
	ffzNode* rhs = node->Op.right;
	ffzCheckInfo rhs_info;
	TRY(check_node(c, rhs, NULL, 0, &rhs_info));
	TRY(verify_is_type_expression(c, rhs, rhs_info.type));
	
	if (ffz_get_child_count(node) == 0) {
		ffzType* slice_type = ffz_make_type_slice(c->project, ffz_as_type(rhs_info.const_val));
		set_result_constant(result, ffz_as_constant(slice_type));
	}
	else if (ffz_get_child_count(node) == 1) {
		ffzNode* child = ffz_get_child(node, 0);
		ffzCheckInfo child_info;
		TRY(check_node(c, child, NULL, InferFlag_RequireConstant, &child_info));
		
		if (!ffz_type_is_integer(child_info.type->tag) && child_info.type->tag != ffzTypeTag_PolyParam) {
			ERR(c, node, "Array length must be an integer.");
		}
		
		ffzType* array_type = ffz_make_type_fixed_array(c->project,
			ffz_as_type(rhs_info.const_val), { child_info.type, child_info.const_val });
		set_result_constant(result, ffz_as_constant(array_type));
	}
	else ERR(c, node, "Unexpected value inside the brackets of an array type; expected an integer literal or `_`");
	return NULL;
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

static fOpt(ffzError*) check_node(ffzModuleChecker* c, ffzNode* node, fOpt(ffzType*) require_type, InferFlags flags, fOpt(ffzCheckInfo*) out_result) {
	ZoneScoped;

	// NOTE: we're must use `ffz_maybe_get_checked_info` instead of `f_map64_get(&c->infos, (u64)node)`, because of a weird trick with polymorphs :PolyInstantiationWeirdTrick
	// If we used c->infos, nothing would be cached into `c` when instantiating a poly-def from another module.
	if (fOpt(ffzCheckInfo*) existing = ffz_maybe_get_checked_info(node)) {
		if (out_result) *out_result = *existing;
		return NULL;
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
		if (lhs->kind != ffzNodeKind_Identifier) ERR(c, lhs, "The left-hand side of a declaration must be an identifier.");
		
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

			for (ffzNode* n = node->parent; n && n->parent; n = n->parent) {
				ffzCheckInfo n_chk = ffz_checked_get_info(n);

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

		//if (lhs->Identifier.name == F_LIT("foo")) f_trap();
		// NOTE: sometimes we want to pass `require_type` down to the rhs, namely with enum field declarations
		ffzCheckInfo rhs_chk;
		TRY(check_node(c, rhs, require_type, rhs_flags, &rhs_chk));
		
		result = rhs_chk; // Declarations cache the value of the right-hand side
		result.is_local_variable = is_local;
		
		if (is_local || is_parameter || is_global_variable) {
			if (is_parameter) {
				// if the parameter is a type expression, then this declaration has that type
				result.type = ffz_ground_type(result.const_val, result.type);
			}

			result.const_val = NULL; // runtime variables shouldn't store the constant value that the rhs expression might have

			if (!c->is_inside_polymorphic_node && !ffz_type_is_concrete(result.type)) {
				ERR(c, node, "Variable has a non-concrete type: `~s`.", ffz_type_to_string(result.type, c->alc));
			}
		}

		// The lhs identifier will recurse into this same declaration,
		// at which point we should have cached the result for this node to cut the loop.
		//delayed_check_decl_lhs = true;
	} break;

	case ffzNodeKind_Assign: { TRY(check_assign(c, node, &result)); } break;
	case ffzNodeKind_Return: { TRY(check_return(c, node)); } break;

	case ffzNodeKind_Scope: {
		if (require_type == NULL) {
			TRY(add_possible_definitions_to_scope(c, node, node));
			
			if (node->loc.start.line_num == node->loc.end.line_num && node->first_child != NULL) {
				ERR(c, node, "A non-empty scope must span over multiple lines.\n"
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
			if (n->kind != ffzNodeKind_Identifier) ERR(c, n, "Polymorphic parameter must be an identifier.");
			TRY(try_to_add_definition_to_scope(c, node, n));
			TRY(check_node(c, n, NULL, 0, NULL));
		}

		if (node->parent->kind != ffzNodeKind_Declare) {
			ERR(c, node, "Polymorphic expression must be the right-hand side of a constant declaration.");
		}

		bool was_inside_poly = c->is_inside_polymorphic_node;
		c->is_inside_polymorphic_node = true;

		ffzCheckInfo expr_info;
		TRY(check_node(c, node->PolyDef.expr, NULL, 0, &expr_info));
		
		if (node->PolyDef.expr->kind != ffzNodeKind_Record && expr_info.type->tag != ffzTypeTag_Proc) {
			ERR(c, node, "Only struct/union types and procedures are allowed as polymorphic expressions.");
		}
		
		c->is_inside_polymorphic_node = was_inside_poly;

		ffzConstantData constant;
		constant.node = node;
		set_result_constant(&result, make_constant(c, constant, c->project->type_poly_def));
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
			ERR(c, node, "A named enum must be defined at the top-level scope, but was not.");
		}

		ffzNode* type_node = node->Enum.internal_type;
		TRY(check_node(c, type_node, NULL, 0));

		if (type_node->checked.type->tag != ffzTypeTag_Type || !ffz_type_is_integer(type_node->checked.constant->type->tag)) {
			ERR(c, type_node, "Invalid enum type; expected an integer.");
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
		fOpt(ffzType*) type_expr = ffz_builtin_type(c->project, keyword);
		
		//if (keyword == ffzKeyword_extern) {
		//	f_array_push(&c->_extern_libraries, node);
		//}

		if (type_expr) {
			set_result_constant(&result, ffz_as_constant(type_expr));
		}
		else {
			switch (keyword) {
			case ffzKeyword_dbgbreak: {} break;
			case ffzKeyword_false: {
				const static ffzConstantData _false = { 0 };
				result.type = ffz_builtin_type(c->project, ffzKeyword_bool);
				result.const_val = (ffzConstantData*)&_false;
			} break;
			case ffzKeyword_true: {
				const static ffzConstantData _true = { 1 };
				result.type = ffz_builtin_type(c->project, ffzKeyword_bool);
				result.const_val = (ffzConstantData*)&_true;
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
		fOpt(ffzNode*) assignee = ffz_checked_this_dot_get_assignee(node);
		if (assignee == NULL) {
			ERR(c, node, "this-value-dot must be used within an assignment, but no assignment was found.");
		}
		// When checking assignments, the assignee/lhs is always checked first, so this should be ok.
		result.type = ffz_checked_get_info(assignee).type;
	} break;

	case ffzNodeKind_Identifier: { TRY(check_identifier(c, node, &result)); } break;

	case ffzNodeKind_Record: {
		ffzType struct_type = { ffzTypeTag_Record };
		struct_type.distinct_node = node;

		if (c->instantiating_poly && c->instantiating_poly->instantiated_node == node) {
			struct_type.polymorphed_from = c->instantiating_poly;
		}

		set_result_constant(&result, ffz_as_constant(make_type(c, struct_type)));
		// NOTE: post-check the body
	} break;
	
	case ffzNodeKind_FloatLiteral: {
		if (require_type && require_type->tag == ffzTypeTag_Float) {
			ffzConstantData constant;
			if (require_type->size == 4)      constant._f32 = (f32)node->FloatLiteral.value;
			else if (require_type->size == 8) constant._f64 = node->FloatLiteral.value;
			else f_trap();
			set_result_constant(&result, make_constant(c, constant, require_type));
		}
	} break;

	case ffzNodeKind_IntLiteral: {
		if (require_type && ffz_type_is_integer(require_type->tag)) {
			ffzConstant constant = make_constant_int(c->project, node->IntLiteral.value, require_type);
			set_result_constant(&result, constant);
		}
		else {
			if (!(flags & InferFlag_IgnoreUncertainTypes)) {
				ffzConstant constant = make_constant_int(c->project, node->IntLiteral.value, ffz_builtin_type(c->project, ffzKeyword_int));
				set_result_constant(&result, constant);
			}
		}
	} break;

	case ffzNodeKind_StringLiteral: {
		// pointers aren't guaranteed to be valid / non-null, but optional pointers are expected to be null.
		ffzConstantData constant;
		constant.string_zero_terminated = node->StringLiteral.zero_terminated_string;
		set_result_constant(&result, make_constant(c, constant, ffz_builtin_type(c->project, ffzKeyword_string)));
	} break;

	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_UnaryPlus: {
		ffzNode* rhs = node->Op.right;
		ffzCheckInfo rhs_info;
		TRY(check_node(c, rhs, require_type, flags, &rhs_info));
		
		if (rhs_info.type) {
			if (!ffz_type_is_integer(rhs_info.type->tag) && !ffz_type_is_float(rhs_info.type->tag)) {
				ERR(c, rhs, "Incorrect arithmetic type; should be an integer or a float.\n    received: ~s", ffz_type_to_string(rhs_info.type, c->alc));
			}
		}
		result.type = rhs_info.type;
	} break;
	
	case ffzNodeKind_PreSquareBrackets: { TRY(check_pre_square_brackets(c, node, &result)); } break;
	
	case ffzNodeKind_PointerTo: {
		ffzNode* rhs = node->Op.right;
		ffzCheckInfo rhs_chk;
		TRY(check_node(c, rhs, NULL, 0, &rhs_chk));
		TRY(verify_is_type_expression(c, rhs, rhs_chk.type));
		
		ffzType* result_type = ffz_make_type_ptr(c->project, ffz_as_type(rhs_chk.const_val));
		set_result_constant(&result, ffz_as_constant(result_type));
	} break;
	
	case ffzNodeKind_ProcType: { TRY(check_proc_type(c, node, &result)); } break;
	
	case ffzNodeKind_PostCurlyBrackets: {
		ffzNode* left = node->Op.left;
		ffzCheckInfo left_info;
		TRY(check_node(c, left, NULL, 0, &left_info));
		TRY(verify_is_type_expression(c, left, left_info.type));
		TRY(check_curly_initializer(c, ffz_as_type(left_info.const_val), node, flags, &result));
	} break;
	
	case ffzNodeKind_PostSquareBrackets: {
		TRY(check_post_square_brackets(c, node, &result));
	} break;
	
	case ffzNodeKind_MemberAccess: { TRY(check_member_access(c, node, &result)); } break;
	
	case ffzNodeKind_LogicalNOT: {
		result.type = ffz_builtin_type(c->project, ffzKeyword_bool);
		TRY(check_node(c, node->Op.right, result.type, 0, NULL));
	} break;
	
	case ffzNodeKind_LogicalAND: // fallthrough
	case ffzNodeKind_LogicalOR: {
		f_trap();//result.type = ffz_builtin_type(c, ffzKeyword_bool);
		f_trap();//TRY(check_node(c, node->Op.left, result.type, 0));
		f_trap();//TRY(check_node(c, node->Op.right, result.type, 0));
	} break;
	
	case ffzNodeKind_AddressOf: {
		ffzNode* rhs = node->Op.right;
		ffzCheckInfo rhs_info;
		TRY(check_node(c, rhs, NULL, 0, &rhs_info));
		result.type = ffz_make_type_ptr(c->project, rhs_info.type);
	} break;
	
	case ffzNodeKind_Dereference: {
		ffzNode* lhs = node->Op.left;
		ffzCheckInfo lhs_info;
		TRY(check_node(c, lhs, NULL, 0, &lhs_info));
		
		if (!c->is_inside_polymorphic_node) {
			if (lhs_info.type->tag != ffzTypeTag_Pointer) {
				ERR(c, node, "Attempted to dereference a non-pointer.");
			}
			result.type = lhs_info.type->Pointer.pointer_to;
		}
	} break;
	
	case ffzNodeKind_Equal: case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
	case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater: case ffzNodeKind_GreaterOrEqual: {
		fOpt(ffzType*) type;
		TRY(check_two_sided(c, node->Op.left, node->Op.right, require_type, flags, &type));
		
		if (type) { // hmm, maybe we shouldn't allow propagating NULL types from check_two_sided.
			bool is_equality_check = node->kind == ffzNodeKind_Equal || node->kind == ffzNodeKind_NotEqual;
			if (ffz_type_is_comparable(type) || (is_equality_check && ffz_type_is_comparable_for_equality(type))) {
				result.type = ffz_builtin_type(c->project, ffzKeyword_bool);
			}
			else {
				ERR(c, node, "Operator '~s' is not defined for type '~s'",
					ffz_node_kind_to_op_string(node->kind), ffz_type_to_string(type, c->alc));
			}
		}
	} break;
	
	case ffzNodeKind_Add: case ffzNodeKind_Sub: case ffzNodeKind_Mul:
	case ffzNodeKind_Div: case ffzNodeKind_Modulo: {
		fOpt(ffzType*) type;
		TRY(check_two_sided(c, node->Op.left, node->Op.right, require_type, flags, &type));
		
		if (node->kind == ffzNodeKind_Modulo) {
			if (type && !ffz_type_is_integer(type->tag)) {
				ERR(c, node, "Incorrect type with modulo operator; expected an integer.\n    received: ~s", ffz_type_to_string(type, c->alc));
			}
		}
		else {
			if (type && !ffz_type_is_integer(type->tag) && !ffz_type_is_float(type->tag)) {
				ERR(c, node, "Incorrect arithmetic type; expected an integer or a float.\n    received: ~s", ffz_type_to_string(type, c->alc));
			}
		}
		
		result.type = type;
	} break;

	case ffzNodeKind_GeneratedConstant: {
		result.const_val = node->GeneratedConstant.constant.value;
		result.type = node->GeneratedConstant.constant.type;
	} break;

	default: f_trap();
	}

	if (flags & InferFlag_Statement) {
		// NOTE: we cache the types of declarations even though they are statements.
		if (node->kind != ffzNodeKind_Declare && result.type) {
			ERR(c, node, "Expected a statement or a declaration, but got an expression.\n  HINT: An expression can be turned into a statement, i.e. `_ = foo()`");
		}
	}
	else {
		if (node->kind == ffzNodeKind_Declare) ERR(c, node, "Expected an expression, but got a declaration.");

		if (!result.type && !c->is_inside_polymorphic_node && !(flags & InferFlag_IgnoreUncertainTypes)) {
			ERR(c, node, "Expression has no type, or it cannot be inferred.");
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
#endif

	if (result.type && result.type->tag == ffzTypeTag_Type && (flags & InferFlag_TypeMeansZeroValue)) {
		result.type = ffz_ground_type(result.const_val, result.type);
		result.const_val = ffz_zero_value_constant();
	}
	
	if (flags & InferFlag_RequireConstant && !result.is_undefined) {
		if (result.const_val == NULL/* && result.type->tag != ffzTypeTag_PolyParam*/) {
			ERR(c, node, "Expression is not constant, but constant is required.");
		}
	}

	// Say you have `#X: struct { a: ^X }`
	// When checking it the first time, when we get to the identifier after the ^,
	// it will recurse back into the declaration node and check it.
	// When we come back to the outer declaration check, it has already been checked and cached for us.
	// Let the children do the work for us!

	bool child_already_fully_checked_us = false;
	if (!(flags & InferFlag_IgnoreUncertainTypes) || result.type) {
		auto insertion = f_map64_insert(&c->infos, (u64)node, result, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			child_already_fully_checked_us = true;
		}
		//if (node->has_checked) {
		//}
		//else {
		//	//node->has_checked = true;
		//	//node->checked = result;
		//}
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
			TRY(check_node(c, node->If.condition, ffz_builtin_type(c->project, ffzKeyword_bool), 0, NULL));
			TRY(check_node(c, node->If.true_scope, NULL, InferFlag_Statement, NULL));
			
			fOpt(ffzNode*) false_scope = node->If.false_scope;
			if (false_scope) {
				TRY(check_node(c, false_scope, NULL, InferFlag_Statement, NULL));
			}
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
			TRY(add_possible_definitions_to_scope(c, node, node));

			// Add the record fields only after the type has been cached. This is to avoid
			// infinite loops when checking.

			// IMPORTANT: We're modifying the type AFTER it was created and hash-deduplicated. So, the things we modify must not change the type hash!
			ffzRecordBuilder b = ffz_record_builder_init(c->project, 0);

			for FFZ_EACH_CHILD(n, node) {
				if (n->kind != ffzNodeKind_Declare) ERR(c, n, "Expected a declaration.");
				fString name = ffz_decl_get_name(n);

				ffzCheckInfo n_info;
				TRY(check_node(c, n, NULL, InferFlag_Statement | InferFlag_RequireConstant, &n_info));

				ffzType* field_type = n_info.type->tag == ffzTypeTag_Type ? ffz_as_type(n_info.const_val) : n_info.type;
				fOpt(ffzConstantData*) default_value = n_info.type->tag == ffzTypeTag_Type ? NULL : n_info.const_val;

				ffz_record_builder_add_member(&b, name, field_type, default_value, n);
			}
			
			TRY(ffz_record_builder_finish(&b, ffz_as_type(result.const_val)));
		} break;
		}
	}

	if (out_result) {
		*out_result = result;
	}
	return NULL;
}

ffzType* ffz_builtin_type_type() {
	static const ffzType tt = { ffzTypeTag_Type, {false} };
	return (ffzType*)&tt;
}

FFZ_CAPI ffzProject* ffz_init_project(fArena* arena) {
	fAllocator* alc = &arena->alc;
	ffzProject* p = f_mem_clone(ffzProject{}, alc);
	//p->persistent_allocator = &arena->alc;
	//p->modules_directory = modules_directory;

	//if (modules_directory.len > 0) {
	//	fString modules_dir_canonical;
	//	if (f_files_path_to_canonical(fString{}, modules_directory, p->persistent_allocator, &modules_dir_canonical)) {
	//		p->modules_directory = modules_dir_canonical;
	//	}
	//}
	p->pointer_size = 8;
	
	//p->checkers = f_array_make<ffzModule*>(p->persistent_allocator);
	//p->sources = f_array_make<ffzSource*>(p->persistent_allocator);
	//p->checkers_dependency_sorted = f_array_make<ffzModule*>(p->persistent_allocator);
	//p->link_libraries = f_array_make<fString>(p->persistent_allocator);
	//p->link_system_libraries = f_array_make<fString>(p->persistent_allocator);
	//p->filesystem_helpers.
	
	p->bank.alc = alc;
	p->bank.type_from_hash = f_map64_make<ffzType*>(p->bank.alc);
	p->bank.constant_from_hash = f_map64_make<ffzConstantData*>(p->bank.alc);
	p->bank.field_from_name_map = f_map64_make<ffzTypeRecordFieldUse>(p->bank.alc);

	{
		// initialize constant lookup tables and built in types

		p->keyword_from_string = f_map64_make<ffzKeyword>(alc);
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
			p->builtin_types[ffzKeyword_type] = ffz_builtin_type_type();
			p->builtin_types[ffzKeyword_raw] = ffz_make_basic_type(p, ffzTypeTag_Raw, 0, false);
			p->builtin_types[ffzKeyword_Undefined] = ffz_make_basic_type(p, ffzTypeTag_Undefined, 0, false);
			p->type_module = ffz_make_basic_type(p, ffzTypeTag_Module, 0, false);
			p->type_poly_def = ffz_make_basic_type(p, ffzTypeTag_PolyDef, 0, false);

			ffzConstantData* zero = ffz_zero_value_constant();
			
			{
				p->builtin_types[ffzKeyword_string] = ffz_make_basic_type(p, ffzTypeTag_String, 16, true);
			
				ffzRecordBuilder b = ffz_record_builder_init(p, 2);
				ffz_record_builder_add_member(&b, F_LIT("ptr"), ffz_make_type_ptr(p, ffz_builtin_type(p, ffzKeyword_u8)), zero, {});
				ffz_record_builder_add_member(&b, F_LIT("len"), ffz_builtin_type(p, ffzKeyword_uint), zero, {});
				ffz_record_builder_finish(&b, p->builtin_types[ffzKeyword_string]);
			}

			{
				p->builtin_types[ffzKeyword_extern] = ffz_make_extra_type(p);
				ffzRecordBuilder b = ffz_record_builder_init(p, 1);
				ffz_record_builder_add_member(&b, F_LIT("library"), ffz_builtin_type(p, ffzKeyword_string), NULL, {});
				ffz_record_builder_add_member(&b, F_LIT("name_prefix"), ffz_builtin_type(p, ffzKeyword_string), zero, {});
				ffz_record_builder_finish(&b, p->builtin_types[ffzKeyword_extern]);
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
	//return NULL;
}

//bool ffz_module_add_code_string(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb) {
//	//parser->report_error = [](ffzParser* parser, ffzLocRange at, fString error) {
//	//	ffz_log_pretty_error(parser, F_LIT("Syntax error "), at, error, true);
//	//	f_trap();
//	//};
//
//	fOpt(ffzError*) ok = ffz_parse(parser);
//	if (!ok.ok) return false;
//
//	return true;
//}

FFZ_CAPI fOpt(ffzError*) ffz_module_resolve_imports_(ffzModule* m, ffzModule*(*module_from_path)(fString path, void* userdata), void* userdata) {

	//for (uint i = 0; i < m->checker_ctx.pending_import_keywords.len; i++) {
	//	ffzNode* import_keyword = m->checker_ctx.pending_import_keywords[i];
	//	
	//}
	//
	//m->checker_ctx.pending_import_keywords.len = 0;
	return NULL;
}

FFZ_CAPI fOpt(ffzError*) ffz_check_module(ffzModule* mod, fOpt(ffzModule*)(*module_from_import)(ffzModule*, ffzNode*), fAllocator* alc) {
	ZoneScoped;

	VALIDATE(mod->checker == NULL);
	ffzModuleChecker* c = make_checker_ctx(mod, module_from_import, alc);
	mod->checker = c;
	
	ffzNode* root = mod->root;
	TRY(add_possible_definitions_to_scope(c, root, root));
	
	for (ffzNode* n = root->first_child; n; n = n->next) {

		// This is a bit dumb way to do this, but right now standalone tags are only checked at top-level. We should
		// probably check them recursively in instanceless_check() or something. :StandaloneTagTopLevel
		if (n->flags & ffzNodeFlag_IsStandaloneTag) {
			TRY(check_tag(c, n));
			continue;
		}
		
		// TODO: make sure it's a constant declaration or global...
		TRY(check_node(c, n, NULL, InferFlag_Statement, NULL));
	}

	//f_array_push(&m->project->checkers_dependency_sorted, m);
	c->finished = true;
	return NULL;
}

fOpt(ffzNode*) ffz_call_get_constant_target_procedure(ffzNode* call) {
	VALIDATE(call->kind = ffzNodeKind_PostRoundBrackets);
	ffzCheckInfo left_info = ffz_checked_get_info(call->Op.left);
	if (left_info.type->tag == ffzTypeTag_Proc) {
		return left_info.const_val ? left_info.const_val->node : NULL;
	}
	VALIDATE(left_info.type->tag == ffzTypeTag_PolyDef);

	ffzCheckInfo info = ffz_checked_get_info(call);
	return info.call_implicit_poly->instantiated_node;
}
