// The checker checks if the program is correct, and in doing so,
// computes and caches information about the program, such as which declarations
// identifiers are pointing to, what types do expressions have, constant evaluation, and so on.
// If the c succeeds, the program is valid and should compile with no errors.

#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"
#include <string.h> // for memcpy
#include <stdio.h>

bool ffz_backend_gen_executable_gmmc(ffzProject* project);
bool ffz_backend_gen_executable_tb(ffzProject* project);

#define TRY(x) { if ((x).ok == false) return ffzOk{false}; }

#define OPT(ptr) ptr

#define ERR(c, node, fmt, ...) { \
	c->report_error(c, {}, node, f_str_format(c->alc, fmt, __VA_ARGS__)); \
	return ffzOk{false}; \
}

// Helper macros

inline ffzNodeInst _get_child_dbg(ffzNodeInst inst, ffzNode* parent) {
	if (inst.node) F_ASSERT(inst.node->parent == parent);
	return inst;
}

#define CHILD(parent, child_access) _get_child_dbg(ffzNodeInst{ (parent).node->child_access, (parent).polymorph }, (parent).node)
//#define CHILD(parent, child_access) ffzNodeInst{ (parent).node->child_access, (parent).polymorph }
#define VALIDATE(x) F_ASSERT(x)

//#define AS(node,kind) FFZ_AS(node, kind)
//#define (ffzNode*)node FFZ_(ffzNode*)node
//#define node FFZ_INST_AS(node, kind)
//#define node FFZ_INST_(ffzNode*)node 
//#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).polymorph }

ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value) {
	return f_hash64_ex(enum_type->hash, value);
}

static bool is_basic_type_size(u32 size) { return size == 1 || size == 2 || size == 4 || size == 8; }

ffzPolymorphHash ffz_hash_poly(ffzPolymorph inst) {
	ffzHash seed = ffz_hash_node_inst(inst.node);//inst.node->id.global_id;
	for (uint i = 0; i < inst.parameters.len; i++) {
		f_hash64_push(&seed, ffz_hash_constant(inst.parameters[i]));
	}
	return seed;
}

ffzConstantHash ffz_hash_constant(ffzCheckedExpr constant) {
	// The type must be hashed into the constant, because otherwise `u64(0)` and `false` would have the same hash!
	ffzTypeHash h = constant.type->hash;
	switch (constant.type->tag) {
	case ffzTypeTag_Pointer: { F_BP; } break;

	case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: {
		f_hash64_push(&h, ffz_hash_node_inst(constant.const_val->proc_node));
	} break;

	case ffzTypeTag_PolyRecord: // fallthrough
	case ffzTypeTag_Record: { F_BP; } break;

	case ffzTypeTag_Slice: { F_BP; } break;
	case ffzTypeTag_FixedArray: {
		for (u32 i = 0; i < (u32)constant.type->FixedArray.length; i++) {
			ffzConstant elem = ffz_constant_fixed_array_get(constant.type, constant.const_val, i);
			f_hash64_push(&h, ffz_hash_constant({ constant.type->FixedArray.elem_type, &elem }));
		}
	} break;

	case ffzTypeTag_Module: { f_hash64_push(&h, (u64)constant.const_val->module->id); } break;
	case ffzTypeTag_Type: { f_hash64_push(&h, constant.const_val->type->hash); } break;
	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Raw: // fallthrough
	case ffzTypeTag_Float: {
		f_hash64_push(&h, constant.const_val->u64_); // TODO: u128
	} break;
	default: F_BP;
	}
	return h;
}

u64 ffz_hash_declaration_path(ffzDefinitionPath path) {
	u64 hash = f_hash64_str(path.name);
	if (path.parent_scope) f_hash64_push(&hash, path.parent_scope->id.global_id);
	return hash;
}

static ffzOk _add_unique_definition(ffzChecker* c, ffzNodeIdentifier* def) {
	fString name = def->Identifier.name;
	
	for (ffzCheckerScope* scope = c->current_scope; scope; scope = scope->parent) {
		ffzDefinitionPath path = { scope->node, name };
		if (ffzNodeIdentifier** existing = f_map64_get(&c->definition_map, ffz_hash_declaration_path(path))) {
			ERR(c, def, "`%s` is already declared before (at line: %u)",
				f_str_to_cstr(name, c->alc),
				(*existing)->loc.start.line_num);
		}
	}
	
	//printf("TODO: have a `ffz_get_scope()` function\n");
	ffzDefinitionPath path = { c->current_scope->node, name };
	f_map64_insert(&c->definition_map, ffz_hash_declaration_path(path), def, fMapInsert_DoNotOverride);
	return { true };
}



static ffzConstant* make_constant(ffzChecker* c) {
	// TODO: we should deduplicate constants
	ffzConstant* constant = f_mem_clone(ffzConstant{}, c->alc);
	return constant;
}

static ffzConstant* make_constant_int(ffzChecker* c, u64 u64_) {
	ffzConstant* constant = make_constant(c);
	constant->u64_ = u64_;
	return constant;
}

//ffzType* get_type_type() { const static ffzType type_type = { ffzTypeTag_Type }; return (ffzType*)&type_type; }
//ffzType* get_type_module() { const static ffzType type_module = { ffzTypeTag_Module }; return (ffzType*)&type_module; }
//ffzType* type_type;
// ffzType* module_type;

ffzCheckedExpr make_type_constant(ffzChecker* c, ffzType* type) {
	ffzCheckedExpr out;
	out.type = c->type_type;
	out.const_val = make_constant(c);
	out.const_val->type = type;
	return out;
}
//
////@cleanup 
//ffzCheckedExpr _make_type_type(ffzChecker* c, ffzNodeInst node, ffzType* type) { return make_type_type(c, type);}

ffzType* ffz_ground_type(ffzCheckedExpr checked) {
	if (checked.type->tag == ffzTypeTag_Type) {
		//ASSERT(checked.type->type.t->tag != ffzTypeTag_Type);
		return checked.const_val->type;
	}
	return checked.type;
}

bool ffz_type_is_grounded(ffzType* type) {
	if (type->tag == ffzTypeTag_Type) return false;
	if (type->tag == ffzTypeTag_FixedArray && type->FixedArray.length == -1) return false;
	if (type->tag == ffzTypeTag_Raw) return false;
	if (type->tag == ffzTypeTag_PolyProc) return false;
	if (type->tag == ffzTypeTag_PolyRecord) return false;
	if (type->tag == ffzTypeTag_Module) return false;
	return true;
}

// TODO: store this as a flag in ffzType
bool ffz_type_can_be_checked_for_equality(ffzType* type) {
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

void _print_constant(ffzProject* p, fArray(u8)* b, ffzCheckedExpr constant);

void _print_type(ffzProject* p, fArray(u8)* b, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Invalid: { f_str_printf(b, "<invalid>"); } break;
	case ffzTypeTag_Module: { f_str_printf(b, "<module>"); } break;
	case ffzTypeTag_PolyProc: { f_str_printf(b, "<poly-proc>"); } break;
	case ffzTypeTag_PolyRecord: { f_str_printf(b, "<poly-struct>"); } break;
		//case TypeTag_UninstantiatedPolyStruct: { str_print(builder, F_LIT("[uninstantiated polymorphic struct]")); } break;
	case ffzTypeTag_Type: {
		f_str_printf(b, "<type>"); // maybe it'd be good to actually store the type type thing in the type
	} break;
	case ffzTypeTag_Bool: { f_str_printf(b, "bool"); } break;
	case ffzTypeTag_Raw: { f_str_printf(b, "raw"); } break;
	case ffzTypeTag_Pointer: {
		f_str_printf(b, "^");
		_print_type(p, b, type->Pointer.pointer_to);
	} break;
	case ffzTypeTag_DefaultSint: { f_str_printf(b, "int"); } break;
	case ffzTypeTag_DefaultUint: { f_str_printf(b, "uint"); } break;
	case ffzTypeTag_Sint: {
		f_str_printf(b, "s%u", type->size * 8);
	} break;
	case ffzTypeTag_Uint: {
		f_str_printf(b, "u%u", type->size * 8);
	} break;
	case ffzTypeTag_Float: {
		f_str_printf(b, "f%u", type->size * 8);
	} break;
	case ffzTypeTag_Proc: {
		ffzNodeInst s = type->unique_node;
		fString name = ffz_get_parent_decl_name(s.node);
		if (name.len > 0) {
			f_str_print(b, name);
		}
		else {
			f_str_printf(b, "<anonymous-proc|line:%u,col:%u>",
				s.node->loc.start.line_num, s.node->loc.start.column_num);
		}

		if (ffz_get_child_count(s.node->ProcType.polymorphic_parameters) > 0) {
			f_str_printf(b, "[");
			for (uint i = 0; i < s.polymorph->parameters.len; i++) {
				if (i > 0) f_str_printf(b, ", ");
				_print_type(p, b, s.polymorph->parameters[i].type);
			}
			f_str_printf(b, "]");
		}
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
		ffzNodeInst n = type->unique_node;
		fString name = ffz_get_parent_decl_name(n.node);
		if (name.len > 0) {
			f_str_print(b, name);
		}
		else {
			f_str_printf(b, "[anonymous enum defined at line:%u, col:%u]", n.node->loc.start.line_num, n.node->loc.start.column_num);
		}
	} break;
	case ffzTypeTag_Record: {
		ffzNodeRecordInst n = type->unique_node;
		fString name = ffz_get_parent_decl_name(n.node);
		if (name.len > 0) {
			f_str_print(b, name);
		}
		else {
			f_str_printf(b, "[anonymous %s defined at line:%u, col:%u]",
				n.node->Record.is_union ? "union" : "struct", n.node->loc.start.line_num, n.node->loc.start.column_num);
		}

		if (ffz_get_child_count(n.node->Record.polymorphic_parameters) > 0) {
			f_str_printf(b, "[");
			
			for (uint i = 0; i < n.polymorph->parameters.len; i++) {
				if (i > 0) f_str_printf(b, ", ");
				_print_constant(p, b, n.polymorph->parameters[i]);
			}
			f_str_printf(b, "]");
		}
	} break;
	case ffzTypeTag_Slice: {
		f_str_printf(b, "[]");
		_print_type(p, b, type->Slice.elem_type);
	} break;
	case ffzTypeTag_String: {
		f_str_printf(b, "string");
	} break;
	case ffzTypeTag_FixedArray: {
		f_str_printf(b, "[%u]", type->FixedArray.length);
		_print_type(p, b, type->FixedArray.elem_type);
	} break;
	default: F_ASSERT(false);
	}
}

void _print_constant(ffzProject* p, fArray(u8)* b, ffzCheckedExpr constant) {
	if (constant.type->tag == ffzTypeTag_Type) {
		_print_type(p, b, constant.const_val->type);
	}
	else {
		F_BP;
	}
}

fString ffz_constant_to_string(ffzProject* p, ffzCheckedExpr constant) {
	fArray(u8) builder = f_array_make_cap<u8>(32, p->persistent_allocator);
	_print_constant(p, &builder, constant);
	return builder.slice;
}

const char* ffz_constant_to_cstring(ffzProject* p, ffzCheckedExpr constant) {
	F_BP;
	return NULL;
}

fString ffz_type_to_string(ffzProject* p, ffzType* type) {
	fArray(u8) builder = f_array_make_cap<u8>(32, p->persistent_allocator);
	_print_type(p, &builder, type);
	return builder.slice;
}

const char* ffz_type_to_cstring(ffzProject* p, ffzType* type) {
	fArray(u8) builder = f_array_make_cap<u8>(32, p->persistent_allocator);
	_print_type(p, &builder, type);
	f_array_push(&builder, (u8)0);
	return (const char*)builder.data;
}

//bool ffz_get_decl_if_definition(ffzNodeIdentifierInst node, ffzNodeOpDeclareInst* out_decl) {
//	if (node.node->parent->kind != ffzNodeKind_Declare) return false;
//	
//	*out_decl = { node.node->parent, node.polymorph };
//	return out_decl->node->Op.left == node.node;
//}

bool ffz_decl_is_runtime_variable(ffzNodeOpDeclare* decl) {
	if (decl->parent->kind == ffzNodeKind_Record) return false;
	if (decl->parent->kind == ffzNodeKind_Enum) return false;
	if (decl->parent->kind == ffzNodeKind_PolyParamList) return false;
	if (decl->Op.left->Identifier.is_constant) return false;
	return true;
}

//bool ffz_is_child_of(ffzNode* node, OPT(ffzNode*) parent) {
//	for (;node; node = node->parent) {
//		if (node->parent == parent) return true;
//	}
//	return false;
//}

ffzNodeIdentifierInst ffz_get_definition(ffzProject* project, ffzNodeIdentifierInst ident) {
	ffzChecker* base_module = ffz_checker_from_node(project, (ffzNode*)ident.node);
	
	for (ffzNodeInst n = ident; n.node; n = ffz_parent_inst(project, n)) {
		ffzDefinitionPath decl_path = { n.node->parent, ident.node->Identifier.name };
		if (ffzNodeIdentifier** found = f_map64_get(&base_module->definition_map, ffz_hash_declaration_path(decl_path))) {
			return { *found, n.polymorph };
		}
	}

	//ffzPolymorph* poly = ident.polymorph;
	//for (ffzNode* n = (ffzNode*)ident.node; n; n = n->parent) { // we want to check even with a NULL scope node
	//	
	//	ffzDefinitionPath decl_path = { n->parent, ident.node->Identifier.name };
	//	if (ffzNodeIdentifier** found = f_map64_get(&base_module->definition_map, ffz_hash_declaration_path(decl_path))) {
	//		
	//		for (; poly && ffz_is_child_of(poly->node.node, n->parent);) {
	//			poly = poly->node.polymorph; // move to a higher-up polymorph until its no longer a child of the scope
	//		}
	//
	//		return { *found, poly };
	//	}
	//}

	return {};
}


ffzConstant* ffz_get_default_value_for_type(ffzChecker* c, ffzType* t) {
	const static ffzConstant empty = {};
	return (ffzConstant*)&empty;
}

ffzCheckedExpr ffz_expr_get_checked(ffzProject* p, ffzNodeInst node) {
	ffzChecker* c = ffz_checker_from_inst(p, node);
	ffzCheckedExpr* out = f_map64_get(&c->cache, ffz_hash_node_inst(node));
	return out ? *out : ffzCheckedExpr{};
}
// TODO: merge
ffzCheckedExpr ffz_decl_get_checked(ffzProject* p, ffzNodeOpDeclareInst decl) {
	ffzChecker* c = ffz_checker_from_inst(p, decl);
	ffzCheckedExpr* out = f_map64_get(&c->cache, ffz_hash_node_inst(decl));
	return out ? *out : ffzCheckedExpr{};
}

bool ffz_find_top_level_declaration(ffzChecker* c, fString name, ffzNodeOpDeclareInst* out_decl) {
	ffzNodeIdentifier** def = f_map64_get(&c->definition_map, ffz_hash_declaration_path({ {}, name }));
	if (def) {
		*out_decl = { (*def)->parent, NULL };
		return true;
	}
	return false;
}

ffzFieldHash ffz_hash_field(ffzType* type, fString member_name) {
	return f_hash64_ex(type->hash, f_hash64_str(member_name));
}

ffzNodeInstHash ffz_hash_node_inst(ffzNodeInst inst) {
	ffzNodeInstHash hash = inst.node->id.global_id;
	if (inst.polymorph) f_hash64_push(&hash, inst.polymorph->hash);
	return hash;
}

static ffzOk add_fields_to_field_from_name_map(ffzChecker* c, ffzType* root_type, ffzType* parent_type, u32 offset_from_root = 0) {
	for (u32 i = 0; i < parent_type->record_fields.len; i++) {
		ffzTypeRecordField* field = &parent_type->record_fields[i];
		ffzTypeRecordFieldUse* field_use = f_mem_clone(ffzTypeRecordFieldUse{ field->type, offset_from_root + field->offset }, c->alc);

		auto insertion = f_map64_insert(&c->field_from_name_map, ffz_hash_field(root_type, field->name), field_use, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			ERR(c, field->decl.node, "`%s` is already declared before inside (TODO: print struct name) (TODO: print line)",
				f_str_to_cstr(field->name, c->alc)); // (*insertion._unstable_ptr)->name->start_pos.line_number);
		}

		if (field->decl.node) {
			if (ffz_get_tag(c->project, field->decl, ffzKeyword_using)) {
				TRY(add_fields_to_field_from_name_map(c, root_type, field->type));
			}
		}
	}
	return { true };
}

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out) {
	ffzChecker* c = p->checkers[type->checker_id];
	if (ffzTypeRecordFieldUse** result = f_map64_get(&c->field_from_name_map, ffz_hash_field(type, name))) {
		*out = **result;
		return true;
	}
	return false;
}

typedef u32 InferFlags;
enum InferFlag {
	InferFlag_RequireConstant = 1 << 0, // we MUST receive an evaluated constant value.
	
	// If the checker finds no type, it's okay with this flag. This could be that we're checking a statement
	// (which COULD still get a type, i.e. a procedure call), or that we're just peeking which type
	// an expression WOULD get given an infer target, if at all.
	InferFlag_TypeIsNotRequired = 1 << 1,
	
	InferFlag_CacheOnlyIfGotType = 1 << 2,
	
	InferFlag_NoTypesMatchCheck = 1 << 3,
	
	InferFlag_TypeMeansDefaultValue = 1 << 4, // `int` will mean "the default value of int" instead of "the type int"
};

static ffzOk check_node(ffzChecker* c, ffzNodeInst inst, OPT(ffzType*) require_type, InferFlags flags, OPT(ffzCheckedExpr*) out);

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

static ffzOk check_types_match(ffzChecker* c, ffzNode* node, ffzType* received, ffzType* expected, const char* message) {
	if (!type_is_a_bit_by_bit(c->project, received, expected)) {
		ERR(c, node, "%s\n    received: %s\n    expected: %s",
			message, ffz_type_to_cstring(c->project, received), ffz_type_to_cstring(c->project, expected));
	}
	return { true };
}

static ffzOk error_not_an_expression(ffzChecker* c, ffzNode* node) {
	ERR(c, node, "Expected an expression, but got a statement or a procedure call with no return value.");
}

static ffzOk check_procedure_call(ffzChecker* c, ffzNodeOpInst inst, OPT(ffzType*) require_type, InferFlags flags, OPT(ffzType*)* out_type) {	
	ffzNodeInst left = CHILD(inst, Op.left);
	ffzCheckedExpr left_chk;
	TRY(check_node(c, left, NULL, 0, &left_chk));

	ffzType* type = left_chk.type;
	if (left_chk.type->tag != ffzTypeTag_Proc) {
		ERR(c, left.node, "Attempted to call a non-procedure (%s)", ffz_type_to_cstring(c->project, left_chk.type));
	}

	*out_type = type->Proc.out_param ? type->Proc.out_param->type : NULL;

	if (ffz_get_child_count(inst.node) != type->Proc.in_params.len) {
		ERR(c, inst.node, "Incorrect number of procedure arguments. (expected %u, got %u)",
			type->Proc.in_params.len, ffz_get_child_count(inst.node));
	}

	uint i = 0;
	for FFZ_EACH_CHILD_INST(arg, inst) {
		ffzType* param_type = type->Proc.in_params[i].type;
		ffzCheckedExpr arg_chk;
		TRY(check_node(c, arg, param_type, 0, &arg_chk));
		TRY(check_types_match(c, arg.node, arg_chk.type, param_type, "Incorrect type with a procedure call argument:"));
		i++;
	}
	return { true };
}

static bool uint_is_subtype_of(ffzType* type, ffzType* subtype_of) {
	if (ffz_type_is_unsigned_integer(type->tag) && ffz_type_is_unsigned_integer(subtype_of->tag) && type->size <= subtype_of->size) return true;
	return false;
}

static ffzOk check_two_sided(ffzChecker* c, ffzNodeInst left, ffzNodeInst right, OPT(ffzType*)* out_type) {
	ffzCheckedExpr left_chk, right_chk;

	// Infer expressions, such as  `x: u32(1) + 50`  or  x: `2 * u32(552)`
	
	InferFlags child_flags = InferFlag_TypeIsNotRequired | InferFlag_CacheOnlyIfGotType;

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
			ERR(c, left.node->parent, "Types do not match.\n    left:    %s\n    right:   %s",
				ffz_type_to_cstring(c->project, left_chk.type), ffz_type_to_cstring(c->project, right_chk.type));
		}
	}
	*out_type = result;
	return { true };
}

ffzNodeInst ffz_get_child_inst(ffzNodeInst parent, u32 idx) {
	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, parent) {
		if (i == idx) return n;
		i++;
	}
	F_ASSERT(false);
	return {};
}

// Do we need this? why do some expressions default to uint but some others not?
//static ffzOk check_expression_defaulting_to_uint(ffzChecker* c, CheckInfer infer, ffzNodeInst inst, OPT(ffzCheckedExpr*) out) {
//	//F_ASSERT(infer.target_type == NULL);
//	CheckInfer peek_infer = infer;
//	peek_infer.target_type = PEEKING_WITHOUT_TARGET_TYPE;
//	//peek_infer.testing_without_target_type = true;
//	TRY(check_expression(c, peek_infer, inst, out));
//	if (!out->type) {
//		TRY(check_expression(c, infer_target_type(infer, ffz_builtin_type(c, ffzKeyword_uint)), inst, out));
//	}
//	return { true };
//}

u32 ffz_get_encoded_constant_size(ffzType* type) {
	return ffz_type_is_integer(type->tag) ? type->size : sizeof(ffzConstant);
}

ffzConstant ffz_constant_fixed_array_get(ffzType* array_type, ffzConstant* array, u32 index) {
	u32 elem_size = ffz_get_encoded_constant_size(array_type->FixedArray.elem_type);
	ffzConstant result = {};
	if (array->fixed_array_elems) memcpy(&result, (u8*)array->fixed_array_elems + index*elem_size, elem_size);
	return result;
}

ffzOk _ffz_add_possible_definition(ffzChecker* c, ffzNode* n) {
	if (n->parent->kind == ffzNodeKind_PolyParamList) {
		TRY(_add_unique_definition(c, n));
	}
	else if (n->kind == ffzNodeKind_Declare) {
		TRY(_add_unique_definition(c, n->Op.left));
	}
	return { true };
}

ffzOk _ffz_add_possible_definitions(ffzChecker* c, OPT(ffzNode*) parent) {
	for FFZ_EACH_CHILD(n, parent) { TRY(_ffz_add_possible_definition(c, n)); }
	return { true };
}

ffzOk ffz_instanceless_check_ex(ffzChecker* c, ffzNode* node, bool recursive, bool new_scope) {
	ffzCheckerScope scope;

	if (new_scope) {
		// when root level, we want the scope node to be NULL, instead of the parser root node!!!
		// This is so that declarations across multiple files/parsers will be placed in equal scope.
		scope.node = node->parent ? node : NULL;
		scope.parent = c->current_scope;
		c->current_scope = &scope;
	}

	if (node->kind == ffzNodeKind_Record) {
		TRY(_ffz_add_possible_definitions(c, node->Record.polymorphic_parameters));
	}
	else if (node->kind == ffzNodeKind_ProcType) {
		TRY(_ffz_add_possible_definitions(c, node->ProcType.polymorphic_parameters));
		if (node->ProcType.out_parameter) TRY(_ffz_add_possible_definition(c, node->ProcType.out_parameter));
	}
	else if (node->kind == ffzNodeKind_PostCurlyBrackets) {
		// If the procedure type is anonymous, add the parameters to this scope. Otherwise, the programmer must use the `in` and `out` keywords to access parameters.
		if (node->Op.left->kind == ffzNodeKind_ProcType) {
			ffz_instanceless_check_ex(c, node->Op.left, recursive, false);
			//TRY(_ffz_add_possible_definitions(c, derived->left));
			//OPT(ffzNode*) out_parameter = AS(derived->left,ProcType)->out_parameter; // :AddOutParamDeclaration
			//if (out_parameter) TRY(_ffz_add_possible_definition(c, out_parameter));
		}
	}
	else if (node->kind == ffzNodeKind_For) {
		if (node->For.header_stmts[0]) { // e.g. `for i: 0, ...`
			TRY(_ffz_add_possible_definition(c, node->For.header_stmts[0]));
		}
	}

	TRY(_ffz_add_possible_definitions(c, node));

	if (recursive) {
		for FFZ_EACH_CHILD(n, node) {
			TRY(ffz_instanceless_check(c, n, recursive));
		}
	}

	if (new_scope) {
		c->current_scope = c->current_scope->parent;
	}
	return { true };
}

ffzOk ffz_instanceless_check(ffzChecker* c, ffzNode* node, bool recursive) { return ffz_instanceless_check_ex(c, node, recursive, true); }


/*
* from https://www.agner.org/optimize/calling_conventions.pdf:
  "Table 3 shows the alignment in bytes of data members of structures and classes. The
  compiler will insert unused bytes, as required, between members to obtain this alignment.
  The compiler will also insert unused bytes at the end of the structure so that the total size of
  the structure is a multiple of the alignment of the element that requires the highest
  alignment"
*/
u32 get_alignment(ffzType* type, u32 pointer_size) {
	switch (type->tag) {
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Pointer: // fallthrough
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Slice: return pointer_size;
	case ffzTypeTag_Record: return 0; // alignment is computed at :ComputeRecordAlignment
	case ffzTypeTag_FixedArray: return get_alignment(type->FixedArray.elem_type, pointer_size);
	}
	return type->size;
}

ffzTypeHash ffz_hash_type(ffzType* type) {
	ffzTypeHash h = f_hash64(type->tag);
	switch (type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Pointer: { f_hash64_push(&h, ffz_hash_type(type->Pointer.pointer_to)); } break;

	case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: { f_hash64_push(&h, ffz_hash_node_inst(type->unique_node)); } break;
	case ffzTypeTag_Enum: { f_hash64_push(&h, ffz_hash_node_inst(type->unique_node)); } break; // :EnumFieldsShouldNotContributeToTypeHash

	case ffzTypeTag_PolyRecord: // fallthrough
	case ffzTypeTag_Record: { f_hash64_push(&h, ffz_hash_node_inst(type->unique_node)); } break;

	case ffzTypeTag_Slice: { f_hash64_push(&h, ffz_hash_type(type->Slice.elem_type)); } break;
	case ffzTypeTag_FixedArray: {
		f_hash64_push(&h, ffz_hash_type(type->FixedArray.elem_type));
		f_hash64_push(&h, type->FixedArray.length);
	} break;

	case ffzTypeTag_Module: // fallthrough
	case ffzTypeTag_Type: // fallthrough
	case ffzTypeTag_String: // fallthrough
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
	default: F_BP;
	}
	return h;
}

ffzType* ffz_make_type(ffzChecker* c, ffzType type_desc) {
	//F_HITS(_c, 35);
	//F_HITS(_c1, 416);
	type_desc.checker_id = c->id;
	type_desc.hash = ffz_hash_type(&type_desc);
	//if (type_desc.hash == 16688289346569842202) F_BP;
	//if (type_desc.hash == 14042532921040479959) F_BP;

	auto entry = f_map64_insert(&c->type_from_hash, type_desc.hash, (ffzType*)0, fMapInsert_DoNotOverride);
	if (entry.added) {
		ffzType* type_ptr = f_mem_clone(type_desc, c->alc);
		type_ptr->align = get_alignment(type_ptr, c->project->pointer_size); // cache the alignment
		*entry._unstable_ptr = type_ptr;
	}
	
	return *entry._unstable_ptr;
}

ffzType* ffz_make_type_ptr(ffzChecker* c, ffzType* pointer_to) {
	ffzType type = { ffzTypeTag_Pointer, c->project->pointer_size };
	type.Pointer.pointer_to = pointer_to;
	return ffz_make_type(c, type);
}

OPT(ffzType*) ffz_builtin_type(ffzChecker* c, ffzKeyword keyword) {
	return c->builtin_types[keyword];
	//if (keyword >= ffzKeyword_FIRST_TYPE && keyword <= ffzKeyword_LAST_TYPE) {
	//}
	//return NULL;
}

ffzType* ffz_make_type_slice(ffzChecker* c, ffzType* elem_type) {
	ffzType type = { ffzTypeTag_Slice, 2 * c->project->pointer_size };
	type.Slice.elem_type = elem_type;
	ffzType* out = ffz_make_type(c, type);

	if (out->record_fields.len == 0) { // this type hasn't been made before
		out->record_fields = f_make_slice_garbage<ffzTypeRecordField>(2, c->alc);
		out->record_fields[0] = { F_LIT("ptr"), ffz_make_type_ptr(c, elem_type), 0, NULL };
		out->record_fields[1] = { F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), c->project->pointer_size, NULL };
		add_fields_to_field_from_name_map(c, out, out, 0);
	}

	return out;
}

ffzType* ffz_make_type_fixed_array(ffzChecker* c, ffzType* elem_type, s32 length) {
	ffzType array_type = { ffzTypeTag_FixedArray };
	if (length >= 0) array_type.size = (u32)length * elem_type->size;

	array_type.FixedArray.elem_type = elem_type;
	array_type.FixedArray.length = length;
	ffzType* out = ffz_make_type(c, array_type);

	if (length > 0 && length <= 4 && out->record_fields.len == 0) { // this type hasn't been made before
		out->record_fields = f_make_slice_garbage<ffzTypeRecordField>(length, c->alc);
		
		const static fString fields[] = { F_LIT("x"), F_LIT("y"), F_LIT("z"), F_LIT("w") };
		for (u32 i = 0; i < (u32)length; i++) {
			out->record_fields[i] = { fields[i], elem_type, elem_type->size * i, NULL };
		}
		add_fields_to_field_from_name_map(c, out, out, 0);
	}
	return out;
}

static ffzNodeOpInst code_stmt_get_parent_proc(ffzProject* p, ffzNodeInst inst, ffzType** out_type) {
	ffzNodeInst parent = inst;
	parent.node = parent.node->parent;
	for (; parent.node; parent.node = parent.node->parent) {
		if (parent.node->kind == ffzNodeKind_PostCurlyBrackets) {
			ffzType* type = ffz_expr_get_type(p, parent);

			// Kind of a hack, but since we can call this function from inside the checker,
			// the parent expression type might not have been cached yet. But procedures are delay-checked so 
			// their types should be available.
			if (type && type->tag == ffzTypeTag_Proc) {
				*out_type = type;
				return parent;
			}
		}
	}
	F_ASSERT(false);
	return {};
}

static bool type_can_be_casted_to(ffzType* from, ffzType* to) {
	if (ffz_type_is_integer_ish(from->tag) && ffz_type_is_integer_ish(to->tag)) return true;
	if (ffz_type_is_slice_ish(from->tag)&& ffz_type_is_slice_ish(to->tag)) return true;
	return false;
}

static ffzOk check_post_round_brackets(ffzChecker* c, ffzNodeInst inst, ffzType* require_type, InferFlags flags, ffzCheckedExpr* result) {
	ffzNodeInst left = CHILD(inst, Op.left);
	bool fall = true;
	if (left.node->kind == ffzNodeKind_Keyword) {
		ffzKeyword keyword = left.node->Keyword.keyword;
		if (ffz_keyword_is_bitwise_op(keyword)) {
			if (ffz_get_child_count(inst.node) != (keyword == ffzKeyword_bit_not ? 1 : 2)) {
				ERR(c, inst.node, "Incorrect number of arguments to a bitwise operation.");
			}
			//F_HITS(_c, 10);
			ffzNodeInst first = ffz_get_child_inst(inst, 0);
			if (keyword == ffzKeyword_bit_not) {
				ffzCheckedExpr chk;
				TRY(check_node(c, first, require_type, flags, &chk));
				result->type = chk.type;
			}
			else {
				ffzNodeInst second = ffz_get_child_inst(inst, 1);
				TRY(check_two_sided(c, first, second, &result->type));
			}

			if (result->type && !is_basic_type_size(result->type->size)) {
				ERR(c, inst.node, "bitwise operations only allow sizes of 1, 2, 4 or 8; Received: %u", result->type->size);
			}

			fall = false;
		}
		else if (keyword == ffzKeyword_size_of || keyword == ffzKeyword_align_of) {
			if (ffz_get_child_count(inst.node) != 1) {
				ERR(c, inst.node, "Incorrect number of arguments to %s.", ffz_keyword_to_cstring(keyword));
			}

			ffzCheckedExpr chk;
			ffzNodeInst first = ffz_get_child_inst(inst, 0);
			TRY(check_node(c, first, NULL, 0, &chk));
			ffzType* type = ffz_ground_type(chk);
			//if (chk.type->tag != ffzTypeTag_Type) {
			//	ERR(c, inst.node, "Expected a type to %s, but got a value.", ffz_keyword_to_cstring(keyword));
			//}

			result->type = ffz_builtin_type(c, ffzKeyword_uint);
			result->const_val = make_constant_int(c, keyword == ffzKeyword_align_of ? type->align : type->size);
			fall = false;
		}
		else if (keyword == ffzKeyword_import) {
			result->type = c->module_type;
			result->const_val = make_constant(c);

			ffzChecker* node_module = ffz_checker_from_inst(c->project, inst);
			result->const_val->module = *f_map64_get(&node_module->imported_modules, inst.node->id.global_id);
			fall = false;
		}
	}
	if (fall) {
		ffzCheckedExpr left_chk;
		TRY(check_node(c, left, NULL, 0, &left_chk));

		if (left_chk.type->tag == ffzTypeTag_Type) {
			// ffzType casting
			result->type = left_chk.const_val->type;
			if (ffz_get_child_count(inst.node) != 1) ERR(c, inst.node, "Incorrect number of arguments in type initializer.");

			ffzNodeInst arg = ffz_get_child_inst(inst, 0);
			ffzCheckedExpr chk;

			// check the expression, but do not enforce the type inference, as the type inference rules are
			// more strict than a manual cast. For example, an integer cannot implicitly cast to a pointer, but when inside a cast it can.
			
			TRY(check_node(c, arg, result->type, InferFlag_NoTypesMatchCheck, &chk));
			F_ASSERT(chk.type); //if (chk.type == NULL) ERR(c, inst.node, "Invalid cast.");

			//ffzTypeTag dst_tag = result->type->tag, src_tag = chk.type->tag;
			if (!ffz_type_is_pointer_ish(result->type->tag) && !ffz_type_is_pointer_ish(chk.type->tag)) {
				// the following shouldn't be allowed:
				// #foo: false
				// #bar: u32(&foo)
				// This is because given a constant integer, we want to be able to trivially ask what its value is.
				result->const_val = chk.const_val;
			}

			if (!type_can_be_casted_to(chk.type, result->type)) {
				TRY(check_types_match(c, inst.node, chk.type, result->type, "The received type cannot be casted to the expected type:"));
			}
		}
		else {
			check_procedure_call(c, inst, require_type, flags, &result->type);
		}
	}
	return FFZ_OK;
}

static ffzOk check_post_curly_brackets(ffzChecker* c, ffzNodeInst inst, OPT(ffzType*) require_type, InferFlags flags, bool* delayed_check_proc, ffzCheckedExpr* result) {
	ffzNodeInst left = CHILD(inst, Op.left);

	ffzCheckedExpr left_chk;
	TRY(check_node(c, left, NULL, 0, &left_chk));
	if (left_chk.type->tag != ffzTypeTag_Type) {
		ERR(c, left.node, "Invalid {} initializer; expected a type on the left side, but got a value.");
	}

	// if the left type is PolyProc type and we're currently instantiating this procedure,
	// we should also instantiate the proc type!
	// i.e.
	// #AdderProc: proc[T](a: T, b: T)
	// #adder: AdderProc { dbgbreak }
	// adder[int](50, 60)
	//
	if (left_chk.const_val->type->tag == ffzTypeTag_PolyProc &&
		(inst.polymorph && inst.polymorph->node.node == inst.node))
	{
		ffzPolymorph poly = {};
		poly.checker = c;
		poly.node = left_chk.const_val->type->unique_node;
		poly.parameters = inst.polymorph->parameters;
		
		// @copypaste
		poly.hash = ffz_hash_poly(poly);
		auto entry = f_map64_insert(&c->poly_from_hash, poly.hash, (ffzPolymorph*)0, fMapInsert_DoNotOverride);
		if (entry.added) {
			*entry._unstable_ptr = f_mem_clone(poly, c->alc);
		}
		ffzPolymorph* poly_dedup = *entry._unstable_ptr;
		
		f_map64_insert(&c->poly_instantiation_sites, ffz_hash_node_inst(inst), poly_dedup);
		TRY(check_node(c, ffzNodeInst{ poly.node.node, poly_dedup }, NULL, 0, &left_chk));
	}

	result->type = ffz_ground_type(left_chk);
	if (result->type->tag == ffzTypeTag_Proc || result->type->tag == ffzTypeTag_PolyProc) {
		result->const_val = make_constant(c);
		result->const_val->proc_node = inst;
		if (result->type->tag != ffzTypeTag_PolyProc) {
			*delayed_check_proc = true;
		}
	}
	else if (result->type->tag == ffzTypeTag_Slice || result->type->tag == ffzTypeTag_FixedArray) {
		// Array initialization
		ffzType* elem_type = result->type->tag == ffzTypeTag_Slice ? result->type->Slice.elem_type : result->type->FixedArray.elem_type;

		fArray(ffzCheckedExpr) elems_chk = f_array_make<ffzCheckedExpr>(f_temp_alc());
		bool all_elems_are_constant = true;

		//CheckInfer elem_infer = infer_target_type(infer, elem_type);
		for FFZ_EACH_CHILD_INST(n, inst) {
			ffzCheckedExpr chk;
			TRY(check_node(c, n, elem_type, 0, &chk));
			f_array_push(&elems_chk, chk);
			all_elems_are_constant = all_elems_are_constant && chk.const_val;
		}

		if (result->type->tag == ffzTypeTag_FixedArray) {
			s32 expected = result->type->FixedArray.length;
			if (expected < 0) { // make a new type if [?]
				result->type = ffz_make_type_fixed_array(c, elem_type, (s32)elems_chk.len);
			}
			else if (elems_chk.len != expected) {
				ERR(c, inst.node, "Incorrect number of array initializer arguments. Expected %d, got %d", expected, elems_chk.len);
			}

			if (all_elems_are_constant) {
				u32 elem_size = ffz_get_encoded_constant_size(elem_type);
				void* ptr = f_mem_alloc(elem_size * elems_chk.len, 8, c->alc);
				for (uint i = 0; i < elems_chk.len; i++) {
					memcpy((u8*)ptr + elem_size * i, elems_chk[i].const_val, elem_size);
				}
				result->const_val = make_constant(c);
				result->const_val->fixed_array_elems = ptr;
			}
		}
	}
	else if (result->type->tag == ffzTypeTag_Record) {
		if (result->type->Record.is_union) ERR(c, inst.node, "Union initialization with {} is not currently supported.");

		if (ffz_get_child_count(inst.node) != result->type->record_fields.len) {
			ERR(c, inst.node, "Incorrect number of struct initializer arguments.");
		}

		bool all_fields_are_constant = true;
		fArray(ffzConstant) field_constants = f_array_make<ffzConstant>(c->alc);

		u32 i = 0;
		for FFZ_EACH_CHILD_INST(arg, inst) {
			ffzType* member_type = result->type->record_fields[i].type;
			ffzCheckedExpr chk;
			TRY(check_node(c, arg, member_type, 0, &chk));

			if (chk.const_val) f_array_push(&field_constants, *chk.const_val);
			else all_fields_are_constant = false;
			i++;
		}

		if (all_fields_are_constant) {
			result->const_val = make_constant(c);
			result->const_val->record_fields = field_constants.slice;
		}
	}
	else {
		ERR(c, inst.node, "{}-initializer is not allowed for `%s`.", ffz_type_to_cstring(c->project, result->type));
	}
	return FFZ_OK;
}

static ffzOk check_post_square_brackets(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzCheckedExpr left_chk;
	TRY(check_node(c, CHILD(inst, Op.left), NULL, 0, &left_chk));

	ffzType* left_type = left_chk.type;
	if (left_type->tag == ffzTypeTag_PolyProc ||
		(left_type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_PolyRecord) ||
		(left_type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_PolyProc))
	{
		ffzType* type = ffz_ground_type(left_chk);

		ffzPolymorph poly = {};
		poly.checker = c;
		poly.node = left_type->tag == ffzTypeTag_Type ?
			type->unique_node :
			left_chk.const_val->proc_node;

		uint poly_params_len = ffz_get_child_count(inst.node);
		//ffz_get_child_count(left_type->tag == ffzTypeTag_PolyProc ?
		//	(ffzNode*)AS(left_type->unique_node.node,ProcType->polymorphic_parameters) :
		//	(ffzNode*)AS(left_type->unique_node.node,Record->polymorphic_parameters));

		// TODO!!!!!!!
		//if ( != poly_params_len) {
		//	ERR(c, node, "Incorrect number of polymorphic arguments.");
		//}

		poly.parameters = f_make_slice_garbage<ffzCheckedExpr>(poly_params_len, c->alc);

		uint i = 0;
		for FFZ_EACH_CHILD_INST(arg, inst) {
			ffzCheckedExpr arg_chk;
			TRY(check_node(c, arg, NULL, 0, &arg_chk));
			if (arg_chk.type->tag != ffzTypeTag_Type) ERR(c, arg.node, "Polymorphic parameter must be a type   ...for now.");
			poly.parameters[i] = arg_chk;
			i++;
		}

		// @copypaste
		poly.hash = ffz_hash_poly(poly);
		auto entry = f_map64_insert(&c->poly_from_hash, poly.hash, (ffzPolymorph*)0, fMapInsert_DoNotOverride);
		if (entry.added) {
			*entry._unstable_ptr = f_mem_clone(poly, c->alc);
		}
		ffzPolymorph* poly_dedup = *entry._unstable_ptr;

		f_map64_insert(&c->poly_instantiation_sites, ffz_hash_node_inst(inst), poly_dedup);

		//inst_infer.instantiating_poly_type = type_node;

		// NOTE: if we have a polymorphic procedure, we don't want to check the procedure type - instead,
		// we want to check the procedure body {}-operator.

		TRY(check_node(c, ffzNodeInst{ (ffzNode*)poly.node.node, poly_dedup }, NULL, 0, result));
	}
	else {
		// Array subscript

		if (!(left_chk.type->tag == ffzTypeTag_Slice || left_chk.type->tag == ffzTypeTag_FixedArray)) {
			ERR(c, inst.node->Op.left,
				"Expected an array, a slice, or a polymorphic type as the target of 'post-square-brackets'.\n    received: %s",
				ffz_type_to_cstring(c->project, left_chk.type));
		}

		ffzType* elem_type = left_chk.type->tag == ffzTypeTag_Slice ? left_chk.type->Slice.elem_type : left_chk.type->FixedArray.elem_type;

		u32 child_count = ffz_get_child_count(inst.node);
		if (child_count == 1) {
			ffzNodeInst index = ffz_get_child_inst(inst, 0);

			ffzCheckedExpr index_chk;
			TRY(check_node(c, index, NULL, 0, &index_chk));

			if (!ffz_type_is_integer(index_chk.type->tag)) {
				ERR(c, index.node, "Incorrect type with a slice index; should be an integer.\n    received: %s",
					ffz_type_to_cstring(c->project, index_chk.type));
			}

			result->type = elem_type;
		}
		else if (child_count == 2) {
			ffzNodeInst lo = ffz_get_child_inst(inst, 0);
			ffzNodeInst hi = ffz_get_child_inst(inst, 1);

			ffzCheckedExpr lo_chk, hi_chk;
			if (lo.node->kind != ffzNodeKind_Blank) {
				TRY(check_node(c, lo, NULL, 0, &lo_chk));
				if (!ffz_type_is_integer(lo_chk.type->tag)) ERR(c, lo.node, "Expected an integer.");
			}
			if (hi.node->kind != ffzNodeKind_Blank) {
				TRY(check_node(c, hi, NULL, 0, &hi_chk));
				if (!ffz_type_is_integer(hi_chk.type->tag)) ERR(c, hi.node, "Expected an integer.");
			}

			result->type = ffz_make_type_slice(c, elem_type);
		}
		else {
			ERR(c, inst.node, "Incorrect number of arguments inside subscript/slice operation.");
		}
	}
	return FFZ_OK;
}

static ffzOk check_member_access(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzNodeInst left = CHILD(inst, Op.left);
	ffzNodeInst right = CHILD(inst, Op.right);
	if (right.node->kind != ffzNodeKind_Identifier) {
		ERR(c, inst.node, "Invalid member access; the right side was not an identifier.");
	}

	// Maybe we shouldn't even have the 'in' keyword?
	// since in  V3{x = 1, y = 2, z = 3}  the fields are added to the namespace, why not in
	// MyAdderProc{ ret a + b }  as well? I guess the main thing is "where does this variable come from?"
	// In struct instance it's obvious (since you can't declare/assign to your own variables!)

	fString member_name = right.node->Identifier.name;
	fString lhs_name = {};
	bool found = false;
	if (left.node->kind == ffzNodeKind_Identifier && left.node->Identifier.name == F_LIT("in")) {
		lhs_name = F_LIT("procedure input parameter list");

		ffzType* proc_type;
		ffzNodeOpInst parent_proc = code_stmt_get_parent_proc(c->project, inst, &proc_type);
		if (parent_proc.node->Op.left->kind == ffzNodeKind_ProcType) {
			ERR(c, left.node, "`in` is not allowed when the procedure parameters are accessible by name.");
		}

		for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
			ffzTypeProcParameter& param = proc_type->Proc.in_params[i];
			if (param.name->Identifier.name == member_name) {
				found = true;
				result->type = param.type;
			}
		}
	}
	else {
		ffzCheckedExpr left_chk;
		TRY(check_node(c, left, NULL, 0, &left_chk));

		if (left_chk.type->tag == ffzTypeTag_Module) {
			ffzChecker* left_module = left_chk.const_val->module;
			lhs_name = left_module->_dbg_module_import_name; // TODO: we should get an actual name for the module

			ffzNodeOpDeclareInst decl;
			if (ffz_find_top_level_declaration(left_module, member_name, &decl)) {
				*result = ffz_decl_get_checked(c->project, decl);
				found = true;
			}
		}
		else if (left_chk.type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_Enum) {
			ffzType* enum_type = left_chk.const_val->type;
			lhs_name = ffz_type_to_string(c->project, enum_type);

			ffzChecker* enum_type_module = ffz_checker_from_inst(c->project, enum_type->unique_node);
			ffzFieldHash member_key = ffz_hash_field(left_chk.const_val->type, member_name);

			if (u64* val = f_map64_get(&enum_type_module->enum_value_from_name, member_key)) {
				result->type = left_chk.const_val->type;
				result->const_val = make_constant_int(c, *val);
				found = true;
			}
		}
		else {
			ffzType* dereferenced_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;
			lhs_name = ffz_type_to_string(c->project, dereferenced_type);

			ffzTypeRecordFieldUse field;
			if (ffz_type_find_record_field_use(c->project, dereferenced_type, member_name, &field)) {
				result->type = field.type;
				found = true;
			}
		}
	}

	if (!found) ERR(c, right.node, "Declaration not found for '%.*s' inside '%.*s'", F_STRF(member_name), F_STRF(lhs_name));

	return FFZ_OK;
}

static bool is_lvalue(ffzChecker* c, ffzNode* node) {
	// TODO
	return true; 
	//switch (node->kind) {
	//case ffzNodeKind_Identifier: {
	//	ffzNodeIdentifier* def = ffz_get_definition(c->project, AS(node,Identifier)).node;
	//	if (def->is_constant) return false;
	//	return true;
	//} break;
	//case ffzNodeKind_Operator: {
	//	ffzNodeOp* op = AS(node,Operator);
	//	if (op->op_kind == ffzNodeKind_MemberAccess) return is_lvalue(c, op->left);
	//	if (op->op_kind == ffzNodeKind_PostSquareBrackets) return is_lvalue(c, op->right);
	//	if (op->op_kind == ffzNodeKind_Dereference) return true;
	//} break;
	//}
	//return false;
}

ffzOk ffz_check_toplevel_statement(ffzChecker* c, ffzNode* node) {
	switch (node->kind) {
	case ffzNodeKind_Declare: {
		ffzNodeIdentifier* name = node->Op.left;
		ffzNodeInst inst = ffz_get_toplevel_inst(c, node);
		
		TRY(check_node(c, inst, NULL, 0, NULL));
		
		// first check the tags...
		bool is_global = ffz_get_tag(c->project, inst, ffzKeyword_global) != NULL;
		if (!name->Identifier.is_constant && !is_global) {
			ERR(c, name, "Top-level declaration must be constant, or @|global, but got a non-constant.");
		}
	} break;
	default: ERR(c, node, "Top-level node must be a declaration; got: %s", ffz_node_kind_to_cstring(node->kind));
	}
	return { true };
}

static ffzOk check_tag(ffzChecker* c, ffzNodeInst tag) {
	ffzCheckedExpr chk;
	TRY(check_node(c, tag, NULL, InferFlag_RequireConstant | InferFlag_TypeMeansDefaultValue, &chk));
	if (chk.type->tag != ffzTypeTag_Record) {
		ERR(c, tag.node, "Tag was not a struct literal.", "");
	}

	if (chk.type == ffz_builtin_type(c, ffzKeyword_extern)) {
		fString library = chk.const_val->record_fields[0].string_zero_terminated;
		f_array_push(&c->extern_libraries, library);
		// hmm... if we have a lot of these calls, that might be a bit slow, since we're calling the OS functions
		//if (!f_files_path_to_canonical(c->directory, library,
	}
	//else if (chk.type == ffz_builtin_type(c, ffzKeyword_extern_sys)) {
	//	fString library = chk.const_val->record_fields[0].string_zero_terminated;
	//	f_array_push(&c->extern_sys_libraries, library);
	//}

	auto tags = f_map64_insert(&c->all_tags_of_type, chk.type->hash, {}, fMapInsert_DoNotOverride);
	if (tags.added) *tags._unstable_ptr = f_array_make<ffzNodeInst>(c->alc);
	f_array_push(tags._unstable_ptr, tag);
	return FFZ_OK;
}

static ffzOk check_tags(ffzChecker* c, ffzNodeInst inst) {
	for (ffzNode* tag_n = inst.node->first_tag; tag_n; tag_n = tag_n->next) {
		ffzNodeInst tag = { tag_n, inst.polymorph };
		TRY(check_tag(c, tag));
	}
	return { true };
}

ffzNodeInst ffz_parent_inst(ffzProject* p, ffzNodeInst inst) {
	ffzNode* parent = inst.node->parent;
	if (inst.polymorph && parent == inst.polymorph->node.node) {
		return inst.polymorph->node; // exit current polymorph
	}
	return { parent, inst.polymorph };
}

//ffzNodeInst ffz_get_instantiated_inst(ffzChecker* c, ffzNodeInst node) {
//	if (node.node->kind == ffzNodeKind_PostSquareBrackets) {
//		if (ffzPolymorph** p_poly = f_map64_get(&c->poly_instantiation_sites, ffz_hash_node_inst(node))) {
//			node = ffzNodeInst{ (*p_poly)->node.node, (*p_poly) };
//		}
//	}
//	return node;
//}

struct ffzRecordBuilder {
	ffzType* record;
	fArray(ffzTypeRecordField) fields;
};

static ffzRecordBuilder ffz_record_builder_init(ffzChecker* c, ffzType* record, uint fields_cap) {
	return { record, f_array_make_cap<ffzTypeRecordField>(fields_cap, c->alc) };
}

static void ffz_record_builder_add_field(ffzChecker* c, ffzRecordBuilder* b, fString name, ffzType* field_type, /*optional*/ ffzNodeOpDeclareInst decl) {
	ffzTypeRecordField field;
	field.name = name;
	field.offset = b->record->Record.is_union ? 0 : F_ALIGN_UP_POW2(b->record->size, field_type->align);
	field.type = field_type;
	field.decl = decl;
	f_array_push(&b->fields, field);
	b->record->align = F_MAX(b->record->align, field_type->align); // the alignment of a record is that of the largest field
	b->record->size = field.offset + field_type->size;
}

static ffzOk ffz_record_builder_finish(ffzChecker* c, ffzRecordBuilder* b) {
	b->record->record_fields = b->fields.slice;
	b->record->size = F_ALIGN_UP_POW2(b->record->size, b->record->align); // Align the size up to the largest member alignment
	TRY(add_fields_to_field_from_name_map(c, b->record, b->record));
	return FFZ_OK;
}

//{
//	uint i = 0;
//	u32 offset = 0;
//	u32 max_align = 0;
//	for FFZ_EACH_CHILD_INST(n, inst) {
//		if (n.node->kind != ffzNodeKind_Declare) ERR(c, n.node, "Expected a declaration.");
//
//		ffzCheckedExpr chk;
//		TRY(check_node(c, n, NULL, InferFlag_RequireConstant, &chk));
//
//		ffzType* member_type = ffz_ground_type(chk); // ffz_decl_get_type(c, decl);
//		F_ASSERT(ffz_type_is_grounded(member_type));
//		max_align = F_MAX(max_align, member_type->align);
//
//		fString name = n.node->Op.left->Identifier.name;
//		record_type->record_fields[i] = ffzTypeRecordField{
//			name,                                                    // `name`
//			member_type,                                             // `type`
//			inst.node->Record.is_union ? 0 : offset,                 // `offset`
//			n,                                                       // `decl`
//		};
//		F_ASSERT(!inst.node->Record.is_union); // uhh the logic for calculating union offsets is not correct
//		offset = F_ALIGN_UP_POW2(offset + member_type->size, member_type->align);
//		i++;
//	}
//
//	record_type->size = F_ALIGN_UP_POW2(offset, max_align); // Align the struct size up to the largest member alignment
//	record_type->align = max_align; // :ComputeRecordAlignment
//	TRY(add_fields_to_field_from_name_map(c, record_type, record_type));
//}

static ffzNodeInst ffz_make_pseudo_node(ffzChecker* c) {
	ffzNode* n = f_mem_clone(ffzNode{}, c->alc);
	n->id.global_id = --c->next_pseudo_node_idx; // this is supposed to underflow and to not collide with real nodes
	return { n, NULL };
}

static ffzType* ffz_make_pseudo_record_type(ffzChecker* c) {
	ffzType t = { ffzTypeTag_Record };
	t.unique_node = ffz_make_pseudo_node(c); // NOTE: ffz_hash_node_inst looks at the id of the unique node for record types
	return ffz_make_type(c, t);
}

ffzChecker* ffz_checker_init(ffzProject* p, fAllocator* allocator) {
	ffzChecker* c = f_mem_clone(ffzChecker{}, allocator);	
	c->project = p;
	c->id = (ffzCheckerID)f_array_push(&p->checkers, c);
	c->alc = allocator;
	c->checked_identifiers = f_map64_make_raw(0, c->alc);
	c->definition_map = f_map64_make<ffzNodeIdentifier*>(c->alc);
	c->cache = f_map64_make<ffzCheckedExpr>(c->alc);
	c->poly_instantiation_sites = f_map64_make<ffzPolymorph*>(c->alc);
	c->field_from_name_map = f_map64_make<ffzTypeRecordFieldUse*>(c->alc);
	c->enum_value_from_name = f_map64_make<u64>(c->alc);
	c->enum_value_is_taken = f_map64_make<ffzNode*>(c->alc);
	c->imported_modules = f_map64_make<ffzChecker*>(c->alc);
	c->type_from_hash = f_map64_make<ffzType*>(c->alc);
	c->all_tags_of_type = f_map64_make<fArray(ffzNodeInst)>(c->alc);
	c->poly_from_hash = f_map64_make<ffzPolymorph*>(c->alc);
	c->extern_libraries = f_array_make<fString>(c->alc);
	//c->extern_sys_libraries = f_array_make<fString>(c->alc);

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

		c->module_type = ffz_make_type(c, { ffzTypeTag_Module });
		c->type_type = ffz_make_type(c, { ffzTypeTag_Type });

		{
			ffzType* string = ffz_make_type(c, { ffzTypeTag_String, p->pointer_size * 2 });
			c->builtin_types[ffzKeyword_string] = string;

			string->record_fields = f_make_slice_garbage<ffzTypeRecordField>(2, c->alc);
			string->record_fields[0] = { F_LIT("ptr"), ffz_make_type_ptr(c, ffz_builtin_type(c, ffzKeyword_u8)), 0, NULL };
			string->record_fields[1] = { F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), p->pointer_size, NULL };
			add_fields_to_field_from_name_map(c, string, string, 0);
		}

		{
			c->builtin_types[ffzKeyword_extern] = ffz_make_pseudo_record_type(c);
			ffzRecordBuilder b = ffz_record_builder_init(c, c->builtin_types[ffzKeyword_extern], 1);
			ffz_record_builder_add_field(c, &b, F_LIT("library"), ffz_builtin_type(c, ffzKeyword_string), {});
			ffz_record_builder_finish(c, &b);
		}

		c->builtin_types[ffzKeyword_using] = ffz_make_pseudo_record_type(c);
		c->builtin_types[ffzKeyword_global] = ffz_make_pseudo_record_type(c);
		c->builtin_types[ffzKeyword_module_defined_entry] = ffz_make_pseudo_record_type(c);
	}

	return c;
}

bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee) {
	// TODO: we need to check for procedure boundaries.
	for (ffzNode* p = dot.node->parent; p; p = p->parent) {
		if (p->kind == ffzNodeKind_Assign) {
			*out_assignee = { p->Op.left, dot.polymorph };
			return true;
		}
	}
	return false;
}

ffzConstant* ffz_get_tag_of_type(ffzProject* p, ffzNodeInst node, ffzType* tag_type) {
	for (ffzNode* tag_n = node.node->first_tag; tag_n; tag_n = tag_n->next) {
		ffzNodeInst tag = { tag_n, node.polymorph };
		
		ffzCheckedExpr checked = ffz_expr_get_checked(p, tag);
		if (type_is_a_bit_by_bit(p, checked.type, tag_type)) {
			return checked.const_val;
		}
	}
	return NULL;
}

static ffzOk check_enum(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzCheckedExpr type_chk;
	TRY(check_node(c, CHILD(inst, Enum.internal_type), NULL, 0, &type_chk));

	if (type_chk.type->tag != ffzTypeTag_Type || !ffz_type_is_integer(type_chk.const_val->type->tag)) {
		ERR(c, inst.node->Enum.internal_type, "Invalid enum type; expected an integer.");
	}

	ffzType enum_type = { ffzTypeTag_Enum };
	enum_type.Enum.internal_type = type_chk.const_val->type;
	enum_type.size = enum_type.Enum.internal_type->size;
	enum_type.unique_node = inst;
	enum_type.Enum.fields = f_make_slice_garbage<ffzTypeEnumField>(ffz_get_child_count(inst.node), c->alc);

	// :EnumFieldsShouldNotContributeToTypeHash
	// Note that we're making the enum type pointer BEFORE populating all of the fields
	ffzType* enum_type_ptr = ffz_make_type(c, enum_type);

	//CheckInfer decl_infer = infer_no_help_constant(infer);
	//decl_infer.infer_decl_type = enum_type.Enum.internal_type;

	uint i = 0;
	for FFZ_EACH_CHILD_INST(n, inst) {
		if (n.node->kind != ffzNodeKind_Declare) ERR(c, n.node, "Expected a declaration; got: [%s]", ffz_node_kind_to_cstring(n.node->kind));

		// NOTE: Infer the declaration from the enum internal type!
		ffzCheckedExpr chk;
		TRY(check_node(c, n, enum_type.Enum.internal_type, 0, &chk));

		u64 val = chk.const_val->u64_;
		ffzFieldHash key = ffz_hash_field(enum_type_ptr, n.node->Op.left->Identifier.name);
		f_map64_insert(&c->enum_value_from_name, key, val);

		enum_type.Enum.fields[i] = ffzTypeEnumField{ n.node->Op.left->Identifier.name, val };

		auto val_taken = f_map64_insert(&c->enum_value_is_taken, ffz_hash_enum_value(enum_type_ptr, val), n.node, fMapInsert_DoNotOverride);
		if (!val_taken.added) {
			fString taken_by = (*val_taken._unstable_ptr)->Op.left->Identifier.name;
			ERR(c, n.node->Op.right, "The enum value `%llu` is already taken by `%.*s`.", val, F_STRF(taken_by));
		}
		i++;
	}
	*result = make_type_constant(c, enum_type_ptr);
	return FFZ_OK;
}

static ffzOk check_proc_type(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzType proc_type = { ffzTypeTag_Proc };
	proc_type.unique_node = inst;
	ffzNodeInst out_param = CHILD(inst,ProcType.out_parameter);
	
	if (ffz_get_child_count(inst.node->ProcType.polymorphic_parameters) > 0 &&
		(!inst.polymorph || inst.polymorph->node.node != inst.node))
	{
		proc_type.tag = ffzTypeTag_PolyProc;
	}
	else {
		proc_type.size = c->project->pointer_size;
	
		ffzNodePolyParamListInst poly_params = CHILD(inst,ProcType.polymorphic_parameters);
		for FFZ_EACH_CHILD_INST(n, poly_params) {
			TRY(check_node(c, n, NULL, 0, NULL));
		}
		
		fArray(ffzTypeProcParameter) in_parameters = f_array_make<ffzTypeProcParameter>(c->alc);
		for FFZ_EACH_CHILD_INST(param, inst) {
			if (param.node->kind != ffzNodeKind_Declare) ERR(c, param.node, "Expected a declaration.");
			ffzCheckedExpr param_chk;
			TRY(check_node(c, param, NULL, 0, &param_chk));
	
			f_array_push(&in_parameters, ffzTypeProcParameter{ param.node->Op.left, param_chk.type });
		}
		proc_type.Proc.in_params = in_parameters.slice;
	
		if (out_param.node) {
			// Procedure return value can be either a declaration or an anonymous type.
			
			proc_type.Proc.out_param = f_mem_clone(ffzTypeProcParameter{}, c->alc);
			if (out_param.node->kind == ffzNodeKind_Declare) {
				ffzNodeOpDeclareInst out_param_decl = out_param;
				ffzCheckedExpr param_chk;
				TRY(check_node(c, out_param_decl, NULL, 0, &param_chk));
	
				proc_type.Proc.out_param->name = out_param_decl.node->Op.left;
				proc_type.Proc.out_param->type = param_chk.type;
			}
			else {
				ffzCheckedExpr chk;
				TRY(check_node(c, out_param, NULL, 0, &chk));
				proc_type.Proc.out_param->type = ffz_ground_type(chk);
			}
		}
	}
	
	ffzNodeInst parent = ffz_parent_inst(c->project, inst);
	if (ffz_get_tag(c->project, parent, ffzKeyword_extern)) {
		if (proc_type.tag == ffzTypeTag_PolyProc) ERR(c, inst.node, "Polymorphic procedures cannot be @extern.");
	
		// if it's an extern proc, then don't turn it into a type type!!
		result->type = ffz_make_type(c, proc_type);
		result->const_val = make_constant(c);
		result->const_val->proc_node = inst;
	}
	else {
		*result = make_type_constant(c, ffz_make_type(c, proc_type));
	}
	return FFZ_OK;
}

static ffzOk check_identifier(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	fString name = inst.node->Identifier.name;

	ffzNodeIdentifierInst def = ffz_get_definition(c->project, inst);
	if (!def.node) {
		ERR(c, inst.node, "Declaration not found for an identifier: \"%s\"", f_str_to_cstr(name, c->alc));
	}

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

	//ffzNodeIdentifierInst def_inst = { def, inst.polymorph };
	if (def.node->parent->kind == ffzNodeKind_PolyParamList) {
		*result = def.polymorph->parameters[ffz_get_child_index(def.node)];
	}
	else {
		ffzNodeInst decl_inst = ffz_parent_inst(c->project, def);
		F_ASSERT(decl_inst.node->kind == ffzNodeKind_Declare);

		fMapInsertResult circle_chk = f_map64_insert_raw(&c->checked_identifiers, ffz_hash_node_inst(inst), NULL, fMapInsert_DoNotOverride);
		if (!circle_chk.added) ERR(c, inst.node, "Circular definition!"); // TODO: elaborate

		// Sometimes we need to access a constant declaration that's ahead of us that we haven't yet checked.
		// In that case we need to completely reset the context back to the declaration's scope, then evaluate the
		// thing we need real quick, and then come back as if nothing had happened.

		TRY(check_node(c, decl_inst, NULL, 0, result));

		if (def.node != inst.node &&
			ffz_decl_is_runtime_variable(decl_inst.node) &&
			decl_inst.node->id.local_id > inst.node->id.local_id)
		{
			ERR(c, inst.node, "Variable is being used before it is declared.");
		}

		//result = ffz_decl_get_checked(c->project, decl_inst);
		if (def.node->Identifier.is_constant) F_ASSERT(result->const_val);
	}
	return FFZ_OK;
}

static ffzOk check_return(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzNodeInst return_val = CHILD(inst, Return.value);
	ffzType* proc_type;
	ffzNodeOpInst proc_node = code_stmt_get_parent_proc(c->project, inst, &proc_type);
	
	ffzTypeProcParameter* out_param = proc_type->Proc.out_param;
	
	// named returns are only supported if the procedure header is declared alongside the procedure
	bool has_named_return = out_param && out_param->name && proc_node.node->Op.left->kind == ffzNodeKind_ProcType;
	if (!return_val.node && out_param && !has_named_return) ERR(c, inst.node, "Expected a return value, but none was given.");
	if (return_val.node && !out_param) ERR(c, return_val.node, "Expected no return value, but one was given.");
	
	if (return_val.node) {
		TRY(check_node(c, return_val, out_param->type, 0, result));
	}
	return FFZ_OK;
}

static ffzOk check_assign(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzNodeInst lhs = CHILD(inst, Op.left);
	ffzNodeInst rhs = CHILD(inst, Op.right);
	ffzCheckedExpr lhs_chk, rhs_chk;
	
	TRY(check_node(c, lhs, NULL, 0, &lhs_chk));
	F_ASSERT(ffz_type_is_grounded(lhs_chk.type));
	
	TRY(check_node(c, rhs, lhs_chk.type, 0, &rhs_chk));
	
	// hmm.. should we allow  `foo= u32`  ?
	//if (!ffz_type_is_grounded(rhs_chk.type)) ERR(c, rhs.node, "Expected a value, but got a type.");
	TRY(check_types_match(c, rhs.node, rhs_chk.type, lhs_chk.type, "Incorrect type with assignment:"));
	
	bool is_code_scope = inst.node->parent->kind == ffzNodeKind_Scope || inst.node->parent->kind == ffzNodeKind_ProcType;
	if (is_code_scope && lhs_chk.type->tag != ffzTypeTag_Raw && !is_lvalue(c, lhs.node)) {
		ERR(c, lhs.node, "Attempted to assign to a non-assignable value.");
	}
	return FFZ_OK;
}

static ffzOk check_pre_square_brackets(ffzChecker* c, ffzNodeInst inst, ffzCheckedExpr* result) {
	ffzCheckedExpr right_chk;
	TRY(check_node(c, CHILD(inst, Op.right), NULL, 0, &right_chk));
	if (right_chk.type->tag != ffzTypeTag_Type) ERR(c, inst.node->Op.right, "Expected a type after [], but got a value.");
	
	if (ffz_get_child_count(inst.node) == 0) {
		*result = make_type_constant(c, ffz_make_type_slice(c, right_chk.const_val->type));
	}
	else if (ffz_get_child_count(inst.node) == 1) {
		ffzNode* child = ffz_get_child(inst.node, 0);
		s32 length = -1;
		if (child->kind == ffzNodeKind_IntLiteral) {
			length = (s32)child->IntLiteral.value;
		}
		else if (child->kind == ffzNodeKind_Keyword && child->Keyword.keyword == ffzKeyword_QuestionMark) {}
		else ERR(c, inst.node, "Unexpected value inside the brackets of an array type; expected an integer literal or `?`");
	
		ffzType* array_type = ffz_make_type_fixed_array(c, right_chk.const_val->type, length);
		*result = make_type_constant(c, array_type);
	}
	else ERR(c, inst.node, "Unexpected value inside the brackets of an array type; expected an integer literal or `_`");
	return FFZ_OK;
}

static bool integer_is_negative(void* bits, u32 size) {
	switch (size) {
	case 1: return *(s8*)bits < 0;
	case 2: return *(s16*)bits < 0;
	case 4: return *(s32*)bits < 0;
	case 8: return *(s64*)bits < 0;
	default: F_BP;
	}
	return false;
}

static ffzOk check_node(ffzChecker* c, ffzNodeInst inst, OPT(ffzType*) require_type, InferFlags flags, OPT(ffzCheckedExpr*) out) {
	ffzNodeInstHash inst_hash = ffz_hash_node_inst(inst);
	//if (inst_hash == 5952824672257) F_BP;
	if (ffzCheckedExpr* existing = f_map64_get(&c->cache, inst_hash)) {
		if (out) *out = *existing;
		return { true };
	}
	
	if (!inst.polymorph) {
		ffz_instanceless_check(c, inst.node, false);
	}
	check_tags(c, inst);

	//F_HITS(_c, 10);

	ffzCheckedExpr result = {};
	
	bool delayed_check_record = false;
	bool delayed_check_proc = false;
	bool delayed_check_decl_lhs = false;

	switch (inst.node->kind) {
	case ffzNodeKind_Declare: {
		ffzNodeIdentifierInst name = CHILD(inst, Op.left);
		ffzNodeInst rhs = CHILD(inst, Op.right);

		InferFlags rhs_flags = 0;
		bool is_runtime_value = ffz_decl_is_runtime_variable(inst.node);
		
		if (is_runtime_value) rhs_flags |= InferFlag_TypeMeansDefaultValue;
		else rhs_flags |= InferFlag_RequireConstant;
		
		ffzCheckedExpr rhs_chk;
		// sometimes we want to pass `require_type` down to the rhs, namely with enum field declarations
		TRY(check_node(c, rhs, require_type, rhs_flags, &rhs_chk));

		result = rhs_chk; // Declarations cache the value of the right-hand-side
		if (is_runtime_value) {
			F_ASSERT(ffz_type_is_grounded(result.type)); // :GroundTypeType
			result.const_val = NULL; // runtime declarations shouldn't store the constant value that the rhs expression might have
		}

		// The lhs identifier will recurse into this same declaration,
		// at which point we should have cached the result for this node to cut the loop.
		delayed_check_decl_lhs = true;
	} break;

	case ffzNodeKind_Assign: { TRY(check_assign(c, inst, &result)); } break;

	case ffzNodeKind_Return: { TRY(check_return(c, inst, &result)); } break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(stmt, inst) {
			TRY(check_node(c, stmt, NULL, InferFlag_TypeIsNotRequired, NULL));
		}
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		TRY(check_post_round_brackets(c, inst, require_type, flags, &result));
		//OPT(ffzType*) return_type = NULL;
		//TRY(check_procedure_call(c, infer, inst, &return_type));
		////if (return_type) ERR(c, inst.node,
		////	"Procedure returns a value, but it is ignored. I you want to ignore it, you must explicitly state it, e.g. `_= foo()`");
		//
		////if (!out_param) CHECKER_ERROR(c, node.node->Return.value, F_LIT("Procedure is declared to return no value, but a return value was received."));
		//return { true };
	} break;

	case ffzNodeKind_If: {
		TRY(check_node(c, CHILD(inst, If.condition), ffz_builtin_type(c, ffzKeyword_bool), 0, NULL));
		TRY(check_node(c, CHILD(inst, If.true_scope), NULL, InferFlag_TypeIsNotRequired, NULL));
		if (inst.node->If.else_scope) {
			TRY(check_node(c, CHILD(inst, If.else_scope), NULL, InferFlag_TypeIsNotRequired, NULL));
		}
	} break;

	case ffzNodeKind_For: {
		for (uint i = 0; i < 3; i++) {
			if (inst.node->For.header_stmts[i]) {
				if (i == 1) {
					TRY(check_node(c, CHILD(inst, For.header_stmts[i]), ffz_builtin_type(c, ffzKeyword_bool), 0, NULL));
				}
				else {
					TRY(check_node(c, CHILD(inst, For.header_stmts[i]), NULL, InferFlag_TypeIsNotRequired, NULL));
				}
			}
		}
		
		TRY(check_node(c, CHILD(inst, For.scope), NULL, InferFlag_TypeIsNotRequired, NULL));
	} break;

	case ffzNodeKind_Keyword: {
		ffzKeyword keyword = inst.node->Keyword.keyword;
		OPT(ffzType*) type_expr = ffz_builtin_type(c, keyword);
		if (type_expr) {
			result = make_type_constant(c, type_expr);
		}
		else {
			switch (keyword) {
			case ffzKeyword_dbgbreak: {} break;
			case ffzKeyword_false: {
				result.type = ffz_builtin_type(c, ffzKeyword_bool);
				const static ffzConstant _false = {0};
				result.const_val = (ffzConstant*)&_false;
			} break;
			case ffzKeyword_true: {
				result.type = ffz_builtin_type(c, ffzKeyword_bool);
				const static ffzConstant _true = {1};
				result.const_val = (ffzConstant*)&_true;
			} break;
			case ffzKeyword_string: { result.type = ffz_builtin_type(c, ffzKeyword_string); } break;

			case ffzKeyword_Underscore: {
				F_BP;// result.expr_type = make_type(c, _type_void);
			} break;
			case ffzKeyword_raw: {
				result = make_type_constant(c, ffz_builtin_type(c, ffzKeyword_raw));
			} break;
			//case ffzKeyword_extern: {
			//	result = make_type_constant(c, ffz_builtin_type(c, ffzKeyword_extern));
			//} break;
			default: F_ASSERT(false);
			}
		}
	} break;

	case ffzNodeKind_ThisValueDot: {
		ffzNodeInst assignee;
		if (!ffz_dot_get_assignee(inst, &assignee)) {
			ERR(c, inst.node, "`.` catcher must be used within an assignment, but no assignment was found.");
		}
		result.type = ffz_expr_get_type(c->project, assignee); // when checking assignments, the assignee/lhs is always checked first, so this should be ok.
	} break;

	case ffzNodeKind_Identifier: { TRY(check_identifier(c, inst, &result)); } break;

	case ffzNodeKind_Record: {
		ffzType struct_type = { ffzTypeTag_Record };
		struct_type.unique_node = inst;

		if (ffz_get_child_count(inst.node->Record.polymorphic_parameters) > 0 &&
			(!inst.polymorph || inst.polymorph->node.node != inst.node))
		{
			struct_type.tag = ffzTypeTag_PolyRecord;
		}
		else {
			delayed_check_record = true;
		}
		result = make_type_constant(c, ffz_make_type(c, struct_type));
	} break;

	
	case ffzNodeKind_FloatLiteral: {
		if (require_type && require_type->tag == ffzTypeTag_Float) {
			result.type = require_type;
			result.const_val = make_constant(c);
			
			f64 val = inst.node->FloatLiteral.value;
			if (require_type->size == 4) result.const_val->f32_ = (f32)val;
			else if (require_type->size == 8) result.const_val->f64_ = val;
			else F_BP;
		}
	} break;

	case ffzNodeKind_IntLiteral: {
		//if (require_type && ffz_type_is_integer(require_type->tag)) {
		//	result.type = require_type;
		//	result.const_val = make_constant_int(c, inst.node->IntLiteral.value);
		//}
		//else if (!(flags & InferFlag_TypeIsNotRequired)) {
		//	// If we're not given anything to work with, let's default to uint
		//	result.type = ffz_builtin_type(c, ffzKeyword_uint);
		//	result.const_val = make_constant_int(c, inst.node->IntLiteral.value);
		//	// TODO: range check
		//}
		if (!(flags & InferFlag_TypeIsNotRequired)) {
			result.type = ffz_builtin_type(c, ffzKeyword_uint);
			result.const_val = make_constant_int(c, inst.node->IntLiteral.value);
		}
	} break;

	case ffzNodeKind_StringLiteral: {
		// pointers aren't guaranteed to be valid / non-null, but optional pointers are expected to be null.
		result.type = ffz_builtin_type(c, ffzKeyword_string);
		result.const_val = make_constant(c);
		result.const_val->string_zero_terminated = inst.node->StringLiteral.zero_terminated_string;
	} break;

	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_UnaryPlus: {
		ffzCheckedExpr right_chk;
		TRY(check_node(c, CHILD(inst, Op.right), require_type, flags, &right_chk));
		
		if (!ffz_type_is_integer(right_chk.type->tag) && !ffz_type_is_float(right_chk.type->tag)) {
			ERR(c, inst.node->Op.right, "Incorrect arithmetic type; should be an integer or a float.\n    received: %s",
				ffz_type_to_cstring(c->project, right_chk.type));
		}
		result.type = right_chk.type;
	} break;

	case ffzNodeKind_PreSquareBrackets: { TRY(check_pre_square_brackets(c, inst, &result)); } break;

	case ffzNodeKind_PointerTo: {
		ffzCheckedExpr right_chk;
		TRY(check_node(c, CHILD(inst, Op.right), NULL, 0, &right_chk));
		
		if (right_chk.type->tag != ffzTypeTag_Type) {
			ERR(c, inst.node->Op.right, "Expected a type after ^, but got a value.");
		}
		result = make_type_constant(c, ffz_make_type_ptr(c, right_chk.const_val->type));
	} break;

	case ffzNodeKind_ProcType: { TRY(check_proc_type(c, inst, &result)); } break;
	
	case ffzNodeKind_Enum: { TRY(check_enum(c, inst, &result)); } break;
	
	case ffzNodeKind_PostCurlyBrackets: {
		TRY(check_post_curly_brackets(c, inst, require_type, flags, &delayed_check_proc, &result));
	} break;
	
	case ffzNodeKind_PostSquareBrackets: { TRY(check_post_square_brackets(c, inst, &result)); } break;
	
	case ffzNodeKind_MemberAccess: { TRY(check_member_access(c, inst, &result)); } break;
	
	case ffzNodeKind_LogicalNOT: {
		result.type = ffz_builtin_type(c, ffzKeyword_bool);
		TRY(check_node(c, CHILD(inst,Op.right), result.type, 0, NULL));
	} break;

	case ffzNodeKind_LogicalAND: // fallthrough
	case ffzNodeKind_LogicalOR: {
		result.type = ffz_builtin_type(c, ffzKeyword_bool);
		TRY(check_node(c, CHILD(inst,Op.left), result.type, 0, NULL));
		TRY(check_node(c, CHILD(inst,Op.right), result.type, 0, NULL));
	} break;

	case ffzNodeKind_AddressOf: {
		ffzCheckedExpr right_chk;
		TRY(check_node(c, CHILD(inst, Op.right), NULL, 0, &right_chk));
		result.type = ffz_make_type_ptr(c, right_chk.type);
	} break;

	case ffzNodeKind_Dereference: {
		ffzCheckedExpr left_chk;
		TRY(check_node(c, CHILD(inst, Op.left), NULL, 0, &left_chk));
		if (left_chk.type->tag != ffzTypeTag_Pointer) ERR(c, inst.node, "Attempted to dereference a non-pointer.");
		result.type = left_chk.type->Pointer.pointer_to;
	} break;

	case ffzNodeKind_Equal: case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
	case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater: case ffzNodeKind_GreaterOrEqual: {
		OPT(ffzType*) type;
		TRY(check_two_sided(c, CHILD(inst,Op.left), CHILD(inst,Op.right), &type));
		
		bool is_equality_check = inst.node->kind == ffzNodeKind_Equal || inst.node->kind == ffzNodeKind_NotEqual;
		if ((is_equality_check && ffz_type_can_be_checked_for_equality(type)) || ffz_type_is_integer_ish(type->tag)) {
			result.type = ffz_builtin_type(c, ffzKeyword_bool);
		}
		else {
			ERR(c, inst.node, "Operator '%s' is not defined for type '%s'",
				ffz_node_kind_to_op_cstring(inst.node->kind), ffz_type_to_cstring(c->project, type));
		}
	} break;

	case ffzNodeKind_Add: case ffzNodeKind_Sub: case ffzNodeKind_Mul:
	case ffzNodeKind_Div: case ffzNodeKind_Modulo: {
		OPT(ffzType*) type;
		TRY(check_two_sided(c, CHILD(inst,Op.left), CHILD(inst,Op.right), &type));
		
		if (type && !ffz_type_is_integer(type->tag)) {
			ERR(c, inst.node, "Incorrect arithmetic type; should be an integer.\n    received: ",
				ffz_type_to_cstring(c->project, type));
		}
		result.type = type;
	} break;

	default: F_BP;
	}

	if ((flags & InferFlag_RequireConstant) && !result.const_val) {
		ERR(c, inst.node, "Expression is not constant, but constant was expected.");
	}

	if (!(flags & InferFlag_TypeIsNotRequired)) { // type is required
		if (!result.type) {
			ERR(c, inst.node, "Expression has no return type, or it cannot be inferred.");
		}
	}

	if (!(flags & InferFlag_NoTypesMatchCheck)) {
		
		// NOTE: we're ignoring the constant type-casts with InferFlag_NoTypesMatchCheck, because explicit type-casts are allowed to overflow
		if (require_type && result.const_val) { // constant downcast
			// TODO: automatic casting for signed integers
			if (ffz_type_is_integer(require_type->tag) && ffz_type_is_integer(result.type->tag)) {
				if (require_type->size <= result.type->size) {
					F_ASSERT(is_basic_type_size(result.type->size));
					F_ASSERT(is_basic_type_size(require_type->size));

					u64 src = ffz_type_is_signed_integer(result.type->tag) ? (u64)-1 : 0;
					u64 masked = src;
					memcpy(&src, &result.const_val->u64_, result.type->size);
					memcpy(&masked, &result.const_val->u64_, require_type->size);
					
					bool src_is_negative = ffz_type_is_signed_integer(result.type->tag) && integer_is_negative(&src, result.type->size);
					bool masked_is_negative = ffz_type_is_signed_integer(require_type->tag) && integer_is_negative(&masked, require_type->size);
					
					bool ok = masked == src && (src_is_negative == masked_is_negative) && (ffz_type_is_signed_integer(require_type->tag) || !src_is_negative);
					if (!ok) {
						if (ffz_type_is_signed_integer(result.type->tag)) {
							ERR(c, inst.node, "Constant type-cast failed; value '%lld' can't be represented in type '%s'.", src, ffz_type_to_cstring(c->project, require_type));
						} else {
							ERR(c, inst.node, "Constant type-cast failed; value '%llu' can't be represented in type '%s'.", src, ffz_type_to_cstring(c->project, require_type));
						}
					}
					// NOTE: we don't need to make a new constant value, as the encoding for it would be exactly the same.
					result.type = require_type;
				}
			}
		}

		// If `require_type` is specified and we found a type for this instance, the type of the expression must match it.
		if (require_type && result.type) {
			TRY(check_types_match(c, inst.node, result.type, require_type, "Unexpected type with an expression:"));
		}
	}

	if (result.type && result.type->tag == ffzTypeTag_Type && (flags & InferFlag_TypeMeansDefaultValue)) {
		result.type = ffz_ground_type(result);
		result.const_val = ffz_get_default_value_for_type(c, result.type);
	}

	// Say you have `#X: struct { a: ^X }`
	// When checking it the first time, when we get to the identifier after the pointer-to-operator,
	// it will recurse back into the declaration node and check it.
	// When we come back to the outer declaration check, it has already been checked and cached for us.
	// Let the children do the work for us!

	bool child_already_fully_checked_us = false;
	if (!(flags & InferFlag_CacheOnlyIfGotType) || result.type) {
		if (!f_map64_insert(&c->cache, inst_hash, result, fMapInsert_DoNotOverride).added) {
			child_already_fully_checked_us = true;
		}
	}

	if (!child_already_fully_checked_us) {
		if (delayed_check_decl_lhs) {
			TRY(check_node(c, CHILD(inst, Op.left), NULL, 0, NULL));
		}
		else if (delayed_check_proc) {
			// only check the procedure body when we have a physical procedure instance (not polymorphic)
			// and after the proc type has been cached.
			for FFZ_EACH_CHILD_INST(n, inst) {
				TRY(check_node(c, n, NULL, InferFlag_TypeIsNotRequired, NULL));
			}
		}
		else if (delayed_check_record) {
			// Add the record fields only after the type has been registered in the cache. This is to avoid
			// infinite loops when checking.

			// IMPORTANT: We're modifying the type AFTER it was created and hash-deduplicated. So, the things we modify must not change the type hash!
			ffzType* record_type = ffz_ground_type(result);
			ffzRecordBuilder b = ffz_record_builder_init(c, record_type, 0);

			for FFZ_EACH_CHILD_INST(n, inst) {
				if (n.node->kind != ffzNodeKind_Declare) ERR(c, n.node, "Expected a declaration.");
				fString name = n.node->Op.left->Identifier.name;
				
				ffzCheckedExpr chk;
				TRY(check_node(c, n, NULL, InferFlag_RequireConstant, &chk));
				
				ffzType* field_type = ffz_ground_type(chk);
				ffz_record_builder_add_field(c, &b, name, field_type, n);
			}
			TRY(ffz_record_builder_finish(c, &b));
			
			//ffz_record_builder_finish
			//record_type->record_fields = f_make_slice_garbage<ffzTypeRecordField>(ffz_get_child_count(inst.node), c->alc);
			//
			//// :InitRecordType
			//uint i = 0;
			//u32 offset = 0;
			//u32 max_align = 0;
			//for FFZ_EACH_CHILD_INST(n, inst) {
			//	if (n.node->kind != ffzNodeKind_Declare) ERR(c, n.node, "Expected a declaration.");
			//
			//	ffzCheckedExpr chk;
			//	TRY(check_node(c, n, NULL, InferFlag_RequireConstant, &chk));
			//
			//	ffzType* member_type = ffz_ground_type(chk); // ffz_decl_get_type(c, decl);
			//	F_ASSERT(ffz_type_is_grounded(member_type));
			//	max_align = F_MAX(max_align, member_type->align);
			//
			//	F_BP; // we're not aligning offset forward, i.e.   { u8 foo; int test; }
			//	fString name = n.node->Op.left->Identifier.name;
			//	record_type->record_fields[i] = ffzTypeRecordField{
			//		name,                                                    // `name`
			//		member_type,                                             // `type`
			//		inst.node->Record.is_union ? 0 : offset,                 // `offset`
			//		n,                                                       // `decl`
			//	};
			//	F_ASSERT(!inst.node->Record.is_union); // uhh the logic for calculating union offsets is not correct
			//	offset = F_ALIGN_UP_POW2(offset + member_type->size, member_type->align);
			//	i++;
			//}
			//
			//record_type->size = F_ALIGN_UP_POW2(offset, max_align); // Align the struct size up to the largest member alignment
			//record_type->align = max_align; // :ComputeRecordAlignment
		}
	}

	if (out) *out = result;
	return { true };
}


void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline = false) {
	f_os_print_color(error_kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
	f_os_print(F_LIT("("));

	f_os_print_color(parser->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);

	fString line_num_str = f_str_from_uint(F_AS_BYTES(loc.start.line_num), f_temp_alc());

	f_os_print(F_LIT(":"));
	f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(":"));
	f_os_print_color(f_str_from_uint(F_AS_BYTES(loc.start.column_num), f_temp_alc()), fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(")\n  "));
	f_os_print(error);
	f_os_print(F_LIT("\n"));
	if (extra_newline) f_os_print(F_LIT("\n"));

	//String src_file = parser->src_file_contents[start.file_index];

	// Scan left until the start of the line
	uint line_start_offset = loc.start.offset;
	for (;;) {
		uint prev = line_start_offset;
		u8 r = (u8)f_str_prev_rune(parser->source_code, &prev);
		if (r == 0 || r == '\n') break;
		line_start_offset = prev;
	}

	u16 code_color = fConsoleAttribute_Green | fConsoleAttribute_Red;

	fString src_line_separator = F_LIT(":    ");
	f_os_print_color(line_num_str, fConsoleAttribute_Intensify);
	f_os_print_color(src_line_separator, fConsoleAttribute_Intensify);
	fString start_str = f_str_replace(f_slice(parser->source_code, line_start_offset, loc.start.offset), F_LIT("\t"), F_LIT("    "), f_temp_alc());
	f_os_print_color(start_str, code_color);

	{
		uint offset = loc.start.offset;
		for (uint i = 0;; i++) {
			rune r = (u8)f_str_next_rune(parser->source_code, &offset);
			if (r == 0 || r == '\n') break;

			u8 r_utf8[4];
			fString r_str = { r_utf8, f_str_encode_rune(r_utf8, r) };
			f_os_print_color(r_str, offset <= loc.end.offset ? (fConsoleAttribute_Red | fConsoleAttribute_Intensify) : code_color);
		}
		f_os_print(F_LIT("\n"));
	}

	{
		// write the ^^^ characters

		//for (i64 i=0; i<
		uint num_spaces = line_num_str.len + src_line_separator.len + f_str_rune_count(start_str);
		for (uint i = 0; i < num_spaces; i++) f_os_print(F_LIT(" "));

		uint offset = loc.start.offset;
		for (uint i = 0; offset < loc.end.offset; i++) {
			rune r = (u8)f_str_next_rune(parser->source_code, &offset);
			if (r == 0 || r == '\n') break;

			f_os_print_color(F_LIT("^"), fConsoleAttribute_Red);
		}
	}
}

static bool _parse_and_check_directory(ffzProject* project, fString _directory, ffzChecker** out_checker, fString _dbg_module_import_name) {
	fString directory;
	if (!f_files_path_to_canonical({}, _directory, f_temp_alc(), &directory)) {
		printf("Invalid directory: \"%.*s\"\n", F_STRF(directory));
		return false;
	}
	
	auto checker_insertion = f_map64_insert(&project->checked_module_from_directory, f_hash64_str_ex(directory, 0),
		(ffzChecker*)0, fMapInsert_DoNotOverride);
	if (!checker_insertion.added) {
		*out_checker = *checker_insertion._unstable_ptr;
		return true;
	}

	ffzChecker* checker = ffz_checker_init(project, f_temp_alc());
	*checker_insertion._unstable_ptr = checker;
	checker->directory = directory;

	checker->report_error = [](ffzChecker* checker, fSlice(ffzNode*) poly_path, ffzNode* at, fString error) {
		ffzParser* parser = checker->project->parsers[at->id.parser_id];

		ffz_log_pretty_error(parser, F_LIT("Semantic error "), at->loc, error, true);
		for (uint i = poly_path.len - 1; i < poly_path.len; i++) {
			ffz_log_pretty_error(parser, F_LIT("\n  ...inside instantiation "), poly_path[i]->loc, F_LIT(""), false);
		}
		F_BP;
	};

	*out_checker = checker;

#ifdef _DEBUG
	checker->_dbg_module_import_name = _dbg_module_import_name;
#endif

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
		printf("Directory `%.*s` does not exist!\n", F_STRF(directory));
		return false;
	}

	checker->parsers = f_make_slice_garbage<ffzParser*>(visit.files.len, checker->alc);
	for (uint i = 0; i < visit.files.len; i++) {
		ffzParser* parser = f_mem_clone(ffzParser{}, f_temp_alc());
		checker->parsers[i] = parser;

		fString file_contents;
		F_ASSERT(f_files_read_whole(visit.files[i], f_temp_alc(), &file_contents));

		parser->project = project;
		parser->alc = f_temp_alc();
		parser->id = (ffzParserID)f_array_push(&project->parsers, parser);
		parser->checker = checker;
		parser->source_code = file_contents;
		parser->source_code_filepath = visit.files[i];
		parser->keyword_from_string = &project->keyword_from_string;
		parser->report_error = [](ffzParser* parser, ffzLocRange at, fString error) {
			ffz_log_pretty_error(parser, F_LIT("Syntax error "), at, error, true);
			F_BP;
		};
			
		parser->module_imports = f_array_make<ffzNodeKeyword*>(parser->alc);
		//parser->tag_decl_lists = f_map64_make<ffzNodeTagDecl*>(parser->alc);

		ffzOk ok = ffz_parse(parser);
		if (!ok.ok) return false;

		if (true) {
			f_os_print(F_LIT("PRINTING AST: ======================================================\n"));
			fArray(u8) builder = f_array_make_cap<u8>(64, f_temp_alc());
			for (ffzNode* n = parser->root->first_child; n; n = n->next) {
				f_str_print_il(&builder, { ffz_print_ast(f_temp_alc(), n), F_LIT("\n") });
			}
			f_os_print(builder.slice);
			f_os_print(F_LIT("====================================================================\n\n"));
			int a = 250;
		}
		
		for (uint i = 0; i < parser->module_imports.len; i++) {
			ffzNodeKeyword* import_keyword = parser->module_imports[i];
				
			ffzNodeOp* import_op = import_keyword->parent;
			F_ASSERT(import_op && import_op->kind == ffzNodeKind_PostRoundBrackets && ffz_get_child_count(import_op) == 1);

			ffzNode* import_name_node = ffz_get_child(import_op, 0);
			F_ASSERT(import_name_node->kind == ffzNodeKind_StringLiteral);
			fString import_path = import_name_node->StringLiteral.zero_terminated_string;
			
			// : means that the path is relative to the modules directory shipped with the compiler
			if (f_str_starts_with(import_path, F_LIT(":"))) {
				import_path = F_STR_T_JOIN(project->compiler_install_dir, F_LIT("/modules/"), f_str_slice_after(import_path, 1));
			}
			else {
				// let's make the import path absolute, relative to the checker's directory
				if (!f_files_path_to_canonical(checker->directory, import_path, f_temp_alc(), &import_path)) {
					F_BP;
				}	
			}

			// Compile the imported module.

			ffzChecker* child_checker = NULL;
			bool ok = _parse_and_check_directory(project, import_path, &child_checker, f_str_path_tail(import_path));
			if (!ok) return false;

			f_map64_insert(&checker->imported_modules, import_op->id.global_id, child_checker);
		}

		// now that imported modules have been checked, we can add our module to the dependency-sorted array
		f_array_push(&project->checkers_dependency_sorted, checker);
	}

	// checker stage
	{
		//ffzCheckerStackFrame root_frame = {};
		//ffzCheckerScope root_scope = {};
		//checker->current_scope = &root_scope;
		//array_push(&checker->stack, &root_frame);

		// We need to first add top-level declarations from all files before proceeding  :EarlyTopLevelDeclarations
		for (uint i = 0; i < checker->parsers.len; i++) {
			ffzParser* parser = checker->parsers[i];
			//root_scope.parser = parser;
			//checker->report_error_userptr = parser;

			//ffzNodeInst root = ffz_get_toplevel_inst(checker, );
			if (!ffz_instanceless_check(checker, parser->root, false).ok) {
				return false;
			}
		}

		for (uint i = 0; i < checker->parsers.len; i++) {
			ffzParser* parser = checker->parsers[i];
			//root_scope.parser = parser;
			//checker->report_error_userptr = parser;

			// Note that the root node of a parser should not introduce a new scope. Instead, the root-scope should be the module scope.
			//for FFZ_EACH_CHILD(n, parser->root) {

			for (ffzNode* n = parser->root->first_child; n; n = n->next) {
				ffzNodeInst inst = ffz_get_toplevel_inst(checker, n);

				// Standalone tags are skipped by FFZ_EACH_CHILD so treat them specially here.
				// This is a bit dumb way to do this, but right now standalone tags are only checked at top-level. We should probably check them
				// recursively in instanceless_check() or something. :StandaloneTagTopLevel
				if (n->flags & ffzNodeFlag_IsStandaloneTag) {
					if (!check_tag(checker, inst).ok) {
						return false;
					}
					continue;
				}
				
				if (!ffz_check_toplevel_statement(checker, n).ok) {
					F_BP;
					return false;
				}
			}
		}

		for (uint i = 0; i < checker->extern_libraries.len; i++) {
			fString input = checker->extern_libraries[i];
			if (input == F_LIT("?")) continue;
			
			if (f_str_cut_start(&input, F_LIT(":"))) {
				// system library
				f_array_push(&project->link_system_libraries, input);
			}
			else {
				F_ASSERT(f_files_path_to_canonical(directory, input, f_temp_alc(), &input));
				f_array_push(&project->link_libraries, input);
			}
		}
	}

	return true;
}

bool ffz_parse_and_check_directory(ffzProject* p, fString directory) {
	ffzChecker* checker;
	return _parse_and_check_directory(p, directory, &checker, {});
}

bool ffz_build_directory(fString directory, fString compiler_install_dir) {
	if (!f_files_path_to_canonical(fString{}, directory, f_temp_alc(), &directory)) {
		F_BP;
		return false;
	}
	if (!f_files_path_to_canonical(fString{}, compiler_install_dir, f_temp_alc(), &compiler_install_dir)) {
		// TODO: have a global error reporting procedure
		F_BP;
		return false;
	}

	// TODO: we really should cleanup the f_temp_alc() calls everywhere

	ffzProject* p = f_mem_clone(ffzProject{}, f_temp_alc());
	p->persistent_allocator = f_temp_alc();
	p->directory = directory;
	p->name = f_str_path_tail(directory);
	p->compiler_install_dir = compiler_install_dir;
	p->checked_module_from_directory = f_map64_make<ffzChecker*>(f_temp_alc());
	p->parsers = f_array_make<ffzParser*>(f_temp_alc());
	p->checkers = f_array_make<ffzChecker*>(f_temp_alc());
	p->checkers_dependency_sorted = f_array_make<ffzChecker*>(f_temp_alc());
	p->link_libraries = f_array_make<fString>(f_temp_alc());
	p->link_system_libraries = f_array_make<fString>(f_temp_alc());
	p->pointer_size = 8;

	{
		// initialize constant lookup tables

		p->keyword_from_string = f_map64_make<ffzKeyword>(p->persistent_allocator);
		for (uint i = 0; i < ffzKeyword_COUNT; i++) {
			f_map64_insert(&p->keyword_from_string,
				f_hash64_str(ffz_keyword_to_string((ffzKeyword)i)), (ffzKeyword)i, fMapInsert_DoNotOverride);
		}
	}

	//os_delete_directory(ffz_build_dir); // deleting a directory causes problems when visual studio is attached to the thing. Even if this is allowed to fail, it will still take a long time.

	if (!ffz_parse_and_check_directory(p, directory)) return false;

	//fString ffz_build_dir = f_files_path_to_absolute(directory, F_LIT(".ffz"), temp);
	//fString exe_filepath = F_STR_T_JOIN(directory, F_LIT("\\build\\"), p->module_name, F_LIT(".exe"));
	
#if defined(FFZ_BUILD_INCLUDE_TB)
	if (!ffz_backend_gen_executable_tb(p)) {
		return 1;
	}
#elif defined(FFZ_BUILD_INCLUDE_GMMC)
	if (!ffz_backend_gen_executable_gmmc(p)) {
		return 1;
	}
#else
	F_BP;
#endif
	
#if 0
	fString objname = F_STR_JOIN(temp, ffz_build_dir, F_LIT("\\"), p->module_name, F_LIT(".obj"));

	WinSDK_Find_Result windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
	fString msvc_directory = f_str_from_utf16(windows_sdk.vs_exe_path, temp); // contains cl.exe, link.exe
	fString windows_sdk_include_base_path = f_str_from_utf16(windows_sdk.windows_sdk_include_base, temp); // contains <string.h>, etc
	fString windows_sdk_um_library_path = f_str_from_utf16(windows_sdk.windows_sdk_um_library_path, temp); // contains kernel32.lib, etc
	fString windows_sdk_ucrt_library_path = f_str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, temp); // contains libucrt.lib, etc
	fString vs_library_path = f_str_from_utf16(windows_sdk.vs_library_path, temp); // contains MSVCRT.lib etc
	fString vs_include_path = f_str_from_utf16(windows_sdk.vs_include_path, temp); // contains vcruntime.h
#endif

#if 0
	{
		Array<String> msvc_args = make_array<String>(temp);
		array_push(&msvc_args, STR_JOIN(temp, msvc_directory, F_LIT("\\cl.exe")));
		array_push(&msvc_args, F_LIT("/Zi"));
		array_push(&msvc_args, F_LIT("/std:c11"));
		array_push(&msvc_args, F_LIT("/Ob1")); // enable inlining
		array_push(&msvc_args, F_LIT("/MDd")); // raylib uses this setting
		array_push(&msvc_args, F_LIT("generated.c"));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\shared")));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\ucrt")));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\um")));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), vs_include_path));

		array_push(&msvc_args, F_LIT("/link"));
		array_push(&msvc_args, F_LIT("/INCREMENTAL:NO"));
		array_push(&msvc_args, F_LIT("/MACHINE:X64"));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/LIBPATH:"), vs_library_path));

		for (uint i = 0; i < project.linker_inputs.len; i++) {
			array_push(&msvc_args, project.linker_inputs[i]);
		}

		printf("Running cl.exe: \n");
		u32 exit_code;
		if (!os_run_command(msvc_args.slice, ffz_build_dir, &exit_code)) return false;
		if (exit_code != 0) return false;
	}
#endif

#if 0
	{
		fArray(fString) linker_args = f_array_make<fString>(temp);
		f_array_push(&linker_args, F_STR_JOIN(temp, msvc_directory, F_LIT("\\link.exe")));

		// Note that we should not put quotation marks around the path. It's because of some weird rules with how command line arguments are combined into one string on windows.
		f_array_push(&linker_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		f_array_push(&linker_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		f_array_push(&linker_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), vs_library_path));
		f_array_push(&linker_args, F_LIT("/INCREMENTAL:NO"));     // incremental linking would break things with the way we're generating OBJ files
		f_array_push(&linker_args, F_LIT("/DEBUG"));

		// f_array_push(&linker_args, F_LIT("/NODEFAULTLIB")); // disable linking to CRT

		bool console_app = true;
		f_array_push(&linker_args, console_app ? F_LIT("/SUBSYSTEM:CONSOLE") : F_LIT("/SUBSYSTEM:WINDOWS"));
		//if (!console_app) f_array_push(&linker_args, F_LIT("/ENTRY:ffz_entry"));

		f_array_push(&linker_args, F_LIT("/OUT:.ffz/.exe"));
		f_array_push(&linker_args, objname);

		for (uint i = 0; i < p->linker_inputs.len; i++) {
			f_array_push(&linker_args, p->linker_inputs[i]);
		}

		printf("Running linker: \n");
		for (uint i = 0; i < linker_args.len; i++) {
			printf("\"%s\" ", f_str_to_cstr(linker_args[i], temp));
		}
		printf("\n\n");

		u32 exit_code;
		if (!f_os_run_command(linker_args.slice, directory, &exit_code)) return false; // @leak: WinSDK_free_resources
		if (exit_code != 0) return false; // @leak: WinSDK_free_resources
	}
#endif

	//WinSDK_free_resources(&windows_sdk);

	// deinit_leak_tracker();
	// GMMC_Deinit(gen.gmmc);

	f_os_print_color(F_LIT("Compile succeeded!\n"), fConsoleAttribute_Green | fConsoleAttribute_Intensify);
	return true;
}