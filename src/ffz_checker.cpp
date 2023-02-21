#include "foundation/foundation.hpp"

#include "ffz_lib.h"
#include "ffz_ast.h"
#include "ffz_checker.h"
#include <string.h> // for memcpy

#define TRY(x) { if ((x).ok == false) return ffzOk{false}; }

#define OPT(ptr) ptr

#define ERR(c, node, fmt, ...) { \
	c->report_error(c, {}, node, f_str_format(c->alc, fmt, __VA_ARGS__)); \
	return ffzOk{false}; \
}

// Helper macros

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

#define IAS(node, kind) FFZ_INST_AS(node, kind)
#define IBASE(node) FFZ_INST_BASE(node) 
#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).poly_idx }

#define VALIDATE(x) F_ASSERT(x)

ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value) {
	return f_hash64_ex((u64)enum_type, value);
}

static bool is_basic_type_size(u32 size) { return size == 1 || size == 2 || size == 4 || size == 8; }

ffzPolymorphHash ffz_hash_poly(ffzPolymorph inst) {
	ffzHash seed = f_hash64(inst.node);
	for (uint i = 0; i < inst.parameters.len; i++) {
		f_hash64_push(&seed, ffz_hash_constant(inst.parameters[i]));
	}
	return seed;
}

ffzMemberHash ffz_hash_member(ffzType* type, fString member_name) {
	return f_hash64_ex((u64)type, f_hash64_str(member_name));
}

ffzNodeInstHash ffz_hash_node_inst(ffzNodeInst inst) {
	return f_hash64_ex((u64)inst.node, f_hash64(inst.poly_idx.idx));
}

ffzTypeHash ffz_hash_type(ffzType* type) {
	ffzTypeHash h = f_hash64(type->tag);
	switch (type->tag) {
	case ffzTypeTag_Raw: break;
	case ffzTypeTag_Pointer: { f_hash64_push(&h, ffz_hash_type(type->Pointer.pointer_to)); } break;
	
	case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: { f_hash64_push(&h, ffz_hash_node_inst(IBASE(type->unique_node))); } break;
	case ffzTypeTag_Enum: { f_hash64_push(&h, ffz_hash_node_inst(IBASE(type->unique_node))); } break; // :EnumFieldsShouldNotContributeToTypeHash

	case ffzTypeTag_PolyRecord: // fallthrough
	case ffzTypeTag_Record: { f_hash64_push(&h, ffz_hash_node_inst(IBASE(type->unique_node))); } break;
	
	case ffzTypeTag_Slice: { f_hash64_push(&h, ffz_hash_type(type->fSlice.elem_type)); } break;
	case ffzTypeTag_FixedArray: {
		f_hash64_push(&h, ffz_hash_type(type->FixedArray.elem_type));
		f_hash64_push(&h, type->FixedArray.length);
	} break;
	
	case ffzTypeTag_Module: // fallthrough
	case ffzTypeTag_Type: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_Float: {
		// Note: we don't want record types to hash in the size of the type, because of :delayed_check_record
		f_hash64_push(&h, type->size);
		break;
	}
	default: F_BP;
	}
	return h;
}

ffzConstantHash ffz_hash_constant(ffzCheckedExpr constant) {
	// TODO: speed this thing up. The type must be hashed into the constant, because otherwise `u64(0)` and `false` would have the same hash!
	ffzTypeHash h = ffz_hash_type(constant.type);
	switch (constant.type->tag) {
	case ffzTypeTag_Pointer: { F_BP; } break;

	case ffzTypeTag_PolyProc: // fallthrough
	case ffzTypeTag_Proc: {
		f_hash64_push(&h, ffz_hash_node_inst(IBASE(constant.const_val->proc_node)));
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

	case ffzTypeTag_Module: { f_hash64_push(&h, constant.const_val->module); } break;
	case ffzTypeTag_Type: { f_hash64_push(&h, ffz_hash_type(constant.const_val->type)); } break;
	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_Raw: // fallthrough
	case ffzTypeTag_Float: {
		f_hash64_push(&h, constant.const_val->u64_); // TODO: what about u128?
	} break;
	default: F_BP;
	}
	return h;
}

ffzChecker* node_get_module(ffzProject* project, ffzNode* node) {
	ffzCheckerIndex idx = project->parsers_dependency_sorted.data[node->parser_idx]->checker_idx;
	return project->checkers.data[idx];
}

u64 ffz_hash_declaration_path(ffzDefinitionPath path) {
	return f_hash64_ex((u64)path.parent_scope, f_hash64_str(path.name));
}

static ffzOk _add_unique_definition(ffzChecker* c, ffzNodeIdentifier* def) {
	fString name = def->name;
	
	for (ffzCheckerScope* scope = c->current_scope; scope; scope = scope->parent) {
		ffzDefinitionPath path = { scope->node, name };
		if (ffzNodeIdentifier** existing = f_map64_get(&c->definition_map, ffz_hash_declaration_path(path))) {
			ERR(c, BASE(def), "`%s` is already declared before (at line: %u)",
				f_str_to_cstr(name, c->alc),
				(*existing)->loc.start.line_num);
		}
	}
	
	//printf("TODO: have a `ffz_get_scope()` function\n");
	ffzDefinitionPath path = { c->current_scope->node, name };
	f_map64_insert(&c->definition_map, ffz_hash_declaration_path(path), def, fMapInsert_DoNotOverride);
	return { true };
}

/*
* from https://www.agner.org/optimize/calling_conventions.pdf:
  "Table 3 shows the alignment in bytes of data members of structures and classes. The
  compiler will insert unused bytes, as required, between members to obtain this alignment.
  The compiler will also insert unused bytes at the end of the structure so that the total size of
  the structure is a multiple of the alignment of the element that requires the highest
  alignment"
*/
u32 get_alignment(ffzChecker* c, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_Pointer: // fallthrough
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Slice: return c->pointer_size;
	case ffzTypeTag_Record: return 0; // alignment is computed at :ComputeRecordAlignment
	case ffzTypeTag_FixedArray: return get_alignment(c, type->FixedArray.elem_type);
	}
	return type->size;
}

ffzType* make_type(ffzChecker* c, ffzType type_desc) {
	F_ASSERT(!ffz_type_is_integer(type_desc.tag));
	ffzTypeHash hash = ffz_hash_type(&type_desc);
	if (ffzType** existing = f_map64_get(&c->type_from_hash, hash)) return *existing;

	ffzType* type_ptr = f_mem_clone(type_desc, c->alc);
	type_ptr->align = get_alignment(c, type_ptr);
	
	//type_ptr->module = c;
	f_map64_insert(&c->type_from_hash, hash, type_ptr);
	return type_ptr;
}

static ffzConstant* make_constant(ffzChecker* c) {
	ffzConstant* constant = f_mem_clone(ffzConstant{}, c->alc);
	return constant;
}

static ffzConstant* make_constant_int(ffzChecker* c, u64 u64_) {
	ffzConstant* constant = make_constant(c);
	constant->u64_ = u64_;
	return constant;
}

ffzType* get_type_type() { const static ffzType type_type = { ffzTypeTag_Type }; return (ffzType*)&type_type; }
ffzType* get_type_module() { const static ffzType type_module = { ffzTypeTag_Module }; return (ffzType*)&type_module; }

ffzCheckedExpr make_type_type(ffzChecker* c, ffzType* type) {
	ffzCheckedExpr out;
	out.type = get_type_type();
	out.const_val = make_constant(c);
	out.const_val->type = type;
	return out;
}
//@cleanup 
ffzCheckedExpr _make_type_type(ffzChecker* c, ffzNodeInst node, ffzType* type) { return make_type_type(c, type);}

OPT(ffzType*) ffz_builtin_type(ffzChecker* c, ffzKeyword keyword) {
	if (keyword >= ffzKeyword_u8 && keyword <= ffzKeyword_string) {
		return (ffzType*)&c->builtin_types[keyword - ffzKeyword_u8];
	}
	return NULL;
}

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
bool ffz_type_is_comparable(ffzType* type) {
	if (ffz_type_is_integer(type->tag)) return true;

	switch (type->tag) {
	case ffzTypeTag_Bool: return true;
	case ffzTypeTag_Pointer: return true;
	case ffzTypeTag_Proc: return true;
	case ffzTypeTag_Enum: return true;
	case ffzTypeTag_Record: {
		if (type->Record.is_union) return false;

		for (uint i = 0; i < type->record_fields.len; i++) {
			if (!ffz_type_is_comparable(type->record_fields[i].type)) return false;
		}
	} return true;
	
	case ffzTypeTag_FixedArray: return ffz_type_is_comparable(type->FixedArray.elem_type);
	}
	return false;
}

void _print_constant(ffzProject* p, fArray(u8)* b, ffzCheckedExpr constant);

void _print_type(ffzProject* p, fArray(u8)* b, ffzType* type) {
	fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop());

	switch (type->tag) {
	case ffzTypeTag_Invalid: { f_str_print(b, F_LIT("[invalid]")); } break;
	case ffzTypeTag_Module: { f_str_print(b, F_LIT("[module]")); } break;
	case ffzTypeTag_PolyProc: { f_str_print(b, F_LIT("[poly-proc]")); } break;
	case ffzTypeTag_PolyRecord: { f_str_print(b, F_LIT("[poly-struct]")); } break;
		//case TypeTag_UninstantiatedPolyStruct: { str_print(builder, F_LIT("[uninstantiated polymorphic struct]")); } break;
	case ffzTypeTag_Type: {
		f_str_print(b, F_LIT("[type]")); // maybe it'd be good to actually store the type type thing in the type
		//_print_type(c, builder, type->type.t);
		//str_print(builder, F_LIT("]"));
	} break;
	case ffzTypeTag_Bool: { f_str_print(b, F_LIT("bool")); } break;
	case ffzTypeTag_Raw: { f_str_print(b, F_LIT("raw")); } break;
	case ffzTypeTag_Pointer: {
		f_str_print(b, F_LIT("^"));
		_print_type(p, b, type->Pointer.pointer_to);
	} break;
	case ffzTypeTag_Int: { f_str_print(b, F_LIT("int")); } break;
	case ffzTypeTag_Uint: { f_str_print(b, F_LIT("uint")); } break;
	case ffzTypeTag_SizedInt: {
		uint num_bits = type->size * 8;
		f_str_print(b, F_LIT("s"));
		f_str_print(b, f_str_from_uint(F_AS_BYTES(num_bits), temp));
	} break;
	case ffzTypeTag_SizedUint: {
		uint num_bits = type->size * 8;
		f_str_print(b, F_LIT("u"));
		f_str_print(b, f_str_from_uint(F_AS_BYTES(num_bits), temp));
	} break;
	case ffzTypeTag_Float: {F_BP; } break;
	case ffzTypeTag_Proc: {
		ffzNodeProcType* s = AS(type->unique_node.node,ProcType);
		fString name = ffz_get_parent_decl_name(BASE(s));
		if (name.len > 0) {
			f_str_print(b, name);
		}
		else {
			f_str_printf(b, "[anonymous proc type defined at line:%u, col:%u]", s->loc.start.line_num, s->loc.start.column_num);
		}

		if (ffz_get_child_count(BASE(s->polymorphic_parameters)) > 0) {
			F_BP;
			//str_print(builder, F_LIT("["));
			//PolyInst* inst = map64_get(&c->poly_instantiations, s.poly_inst);
			//for (uint i = 0; i < inst->parameters.len; i++) {
			//	if (i > 0) str_print(builder, F_LIT(", "));
			//	_print_type(c, builder, inst->parameters[i]);
			//}
			//str_print(builder, F_LIT("]"));
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
		ffzNodeRecordInst n = IAS(type->unique_node,Record);
		fString name = ffz_get_parent_decl_name(BASE(n.node));
		if (name.len > 0) {
			f_str_print(b, name);
		}
		else {
			f_str_printf(b, "[anonymous %s defined at line:%u, col:%u]",
				AS(n.node,Record)->is_union ? "union" : "struct", n.node->loc.start.line_num, n.node->loc.start.column_num);
		}

		if (ffz_get_child_count(BASE(AS(n.node,Record)->polymorphic_parameters)) > 0) {
			f_str_print(b, F_LIT("["));
			ffzPolymorph poly = ffz_poly_from_inst(p, IBASE(n));
			
			for (uint i = 0; i < poly.parameters.len; i++) {
				if (i > 0) f_str_print(b, F_LIT(", "));
				_print_constant(p, b, poly.parameters[i]);
			}
			f_str_print(b, F_LIT("]"));
		}
	} break;
	case ffzTypeTag_Slice: {
		f_str_print(b, F_LIT("[]"));
		_print_type(p, b, type->fSlice.elem_type);
	} break;
	case ffzTypeTag_String: {
		f_str_print(b, F_LIT("string"));
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

bool ffz_get_decl_if_definition(ffzNodeIdentifierInst node, ffzNodeDeclarationInst* out_decl) {
	if (node.node->parent->kind != ffzNodeKind_Declaration) return false;
	
	*out_decl = { AS(node.node->parent,Declaration), node.poly_idx };
	return out_decl->node->name == node.node;
}

//bool ffz_definition_is_constant(ffzNodeIdentifier* definition) { return definition->is_constant || definition->parent->kind == ffzNodeKind_PolyParamList; }

bool ffz_decl_is_runtime_value(ffzNodeDeclaration* decl) {
	if (decl->parent->kind == ffzNodeKind_Record) return false;
	if (decl->parent->kind == ffzNodeKind_Enum) return false;
	if (decl->parent->kind == ffzNodeKind_PolyParamList) return false;
	if (decl->name->is_constant) return false;
	return true;
}

//bool ffz_decl_is_constant(ffzNodeDeclaration* decl) {  }

ffzNodeIdentifier* ffz_get_definition(ffzProject* project, ffzNodeIdentifier* ident) {
	ffzChecker* module = node_get_module(project, BASE(ident));

	for (ffzNode* n = BASE(ident); n; n = n->parent) {
		ffzDefinitionPath decl_path = { n->parent, ident->name };
		if (ffzNodeIdentifier** found = f_map64_get(&module->definition_map, ffz_hash_declaration_path(decl_path))) {
			return *found;
		}
	}
	return NULL;
}

ffzCheckedExpr ffz_expr_get_checked(ffzProject* p, ffzNodeInst node) {
	ffzCheckedExpr* out = f_map64_get(&ffz_checker_from_inst(p, node)->cache, ffz_hash_node_inst(node));
	return out ? *out : ffzCheckedExpr{};
}

ffzConstant* ffz_get_default_value_for_type(ffzChecker* c, ffzType* t) {
	const static ffzConstant empty = {};
	return (ffzConstant*)&empty;
}

ffzCheckedExpr ffz_decl_get_checked(ffzProject* p, ffzNodeDeclarationInst decl) {
	ffzChecker* c = ffz_checker_from_inst(p, IBASE(decl));
	ffzCheckedExpr* out = f_map64_get(&c->cache, ffz_hash_node_inst(IBASE(decl)));
	return out ? *out : ffzCheckedExpr{};
}

ffzPolymorph ffz_poly_from_idx(ffzProject* p, ffzPolymorphIdx idx) {
	ffzChecker* checker = ffz_checker_from_poly_idx(p, idx);
	return *f_map64_get(&checker->poly_from_idx, idx.idx); // hmm... maybe poly_from_idx should be an array in Project instead of a map in each Checker?
}

bool ffz_find_top_level_declaration(ffzChecker* c, fString name, ffzNodeDeclarationInst* out_decl) {
	ffzNodeIdentifier** def = f_map64_get(&c->definition_map, ffz_hash_declaration_path(ffzDefinitionPath{ NULL, name }));
	return def && ffz_get_decl_if_definition(ffzNodeIdentifierInst{ *def, c->toplevel_poly_idx }, out_decl);
}

static ffzType* make_type_fixed_array(ffzChecker* c, ffzType* elem_type, s32 length) {
	ffzType array_type = { ffzTypeTag_FixedArray };
	if (length >= 0) array_type.size = (u32)length * elem_type->size;
	array_type.FixedArray.elem_type = elem_type;
	array_type.FixedArray.length = length;
	return make_type(c, array_type);
}

ffzType* make_type_ptr(ffzChecker* c, ffzType* pointer_to) {
	ffzType type = { ffzTypeTag_Pointer, c->pointer_size };
	type.Pointer.pointer_to = pointer_to;
	return make_type(c, type);
}

static ffzOk add_names_to_record_member_map(ffzChecker* c, ffzType* root_type, ffzType* parent_type, u32 offset_from_root = 0) {
	for (u32 i = 0; i < parent_type->record_fields.len; i++) {
		ffzTypeRecordField* member = &parent_type->record_fields[i];

		ffzTypeRecordFieldUse* field_use = f_mem_clone(ffzTypeRecordFieldUse{ member->type, offset_from_root + member->offset }, c->alc);
		ffzMemberHash key = ffz_hash_member(root_type, member->name);

		auto insertion = f_map64_insert(&c->record_field_from_name, key, field_use, fMapInsert_DoNotOverride);
		if (!insertion.added) {
			ERR(c, BASE(member->decl), "`%s` is already declared before inside (TODO: print struct name) (TODO: print line)",
				f_str_to_cstr(member->name, c->alc)); // (*insertion._unstable_ptr)->name->start_pos.line_number);
		}

		if (member->decl && ffz_node_get_compiler_tag(BASE(member->decl), F_LIT("using"))) {
			//if (member->type->tag != ffzTypeTag_Record) {
			//	ERR(c, BASE(member->decl), "The type of a struct member with @using must be a struct, a slice, or a string, but got ", ffz_type_to_cstring(c, member->type));
			//}
			TRY(add_names_to_record_member_map(c, root_type, member->type));
		}
	}
	return { true };
}

static ffzType* make_type_slice(ffzChecker* c, ffzType* elem_type) {
	ffzType type = { ffzTypeTag_Slice, 2*c->pointer_size };
	type.fSlice.elem_type = elem_type;
	ffzType* out = make_type(c, type);
	
	if (out->record_fields.len == 0) { // this type hasn't been made before
		out->record_fields = f_make_slice_garbage<ffzTypeRecordField>(2, c->alc);
		out->record_fields[0] = { F_LIT("ptr"), make_type_ptr(c, elem_type), 0, NULL };
		out->record_fields[1] = { F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), c->pointer_size, NULL };
		add_names_to_record_member_map(c, out, out, 0);
	}

	return out;
}

/*fSlice(ffzTypeRecordField) ffz_type_get_record_fields(ffzChecker* c, ffzType* type) {
	if (type->tag == ffzTypeTag_String || type->tag == ffzTypeTag_Slice) {
		ffzType* ptr_to = type->tag == ffzTypeTag_Slice ? type->fSlice.elem_type : ffz_builtin_type(c, ffzKeyword_u8);

		ffzTypeRecordField fields[2] = {
			{ F_LIT("ptr"), make_type_ptr(c, ptr_to), 0, NULL },
			{ F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), c->pointer_size, NULL },
		};
		return f_clone_slice<ffzTypeRecordField>(C_ARRAY_SLICE(fields), c->alc);
	}
	if (type->tag == ffzTypeTag_Record) {
		return type->Record.fields;
	}
	return {};
}*/

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out) {
	ffzChecker* checker = ffz_checker_from_type(p, type);
	if (checker) {
		if (ffzTypeRecordFieldUse** result = f_map64_get(&checker->record_field_from_name, ffz_hash_member(type, name))) {
			*out = **result;
			return true;
		}
	}
	return false;
}

struct CheckInfer {
	OPT(ffzType*) target_type;
	bool testing_target_type;
	bool expect_constant;

	OPT(ffzType*) infer_decl_type;
	ffzNode* instantiating_poly_type;
};

static ffzOk check_expression(ffzChecker* c, const CheckInfer& infer, ffzNodeInst node, OPT(ffzCheckedExpr*) out = NULL);
static ffzOk check_code_statement(ffzChecker* c, const CheckInfer& infer, ffzNodeInst node);

static CheckInfer infer_target_type(CheckInfer infer, OPT(ffzType*) target_type) {
	infer.target_type = target_type;
	return infer;
}

inline CheckInfer infer_no_help(const CheckInfer& infer) { return infer_target_type(infer, NULL); }
inline CheckInfer infer_no_help_constant(CheckInfer infer) { infer = infer_target_type(infer, NULL); infer.expect_constant = true; return infer; }
inline CheckInfer infer_no_help_nonconstant(CheckInfer infer) { infer = infer_target_type(infer, NULL); infer.expect_constant = false; return infer; }
inline CheckInfer infer_no_help_pass(CheckInfer infer) { infer = infer_target_type(infer, NULL); infer.expect_constant = true; return infer; }

// if this returns true, its ok to bit-cast between the types
static bool type_is_a(ffzProject* p, ffzType* src, ffzType* target) {
	if (src->tag == ffzTypeTag_Uint && target->tag == ffzTypeTag_Int) return true; // allow implicit cast from uint -> int
	if (target->tag == ffzTypeTag_Raw) return true; // everything can cast to raw
	
	if (src->tag == ffzTypeTag_Pointer && target->tag == ffzTypeTag_Pointer) {
		// i.e. allow casting from ^int to ^raw
		return type_is_a(p, src->Pointer.pointer_to, target->Pointer.pointer_to);
	}

	// hmm... maybe we should just store the ffzChecker* directly in type?
	// or maybe we should just have an atomic map in Project for types so that we could compare pointers easily.
	ffzChecker* src_module = ffz_checker_from_type(p, src);
	if (src_module && src_module == ffz_checker_from_type(p, target)) {
		bool matches = ffz_hash_type(src) == ffz_hash_type(target);
		F_ASSERT((src == target) == matches);
		return src == target;
	}
	else return ffz_hash_type(src) == ffz_hash_type(target); // if the types are from different modules, they are in different hash maps and aren't deduplicated.
}

static ffzOk check_types_match(ffzChecker* c, ffzNode* node, ffzType* received, ffzType* expected, const char* message) {
	if (!type_is_a(c->project, received, expected)) {
		ERR(c, node, "%s\n    received: %s\n    expected: %s",
			message, ffz_type_to_cstring(c->project, received), ffz_type_to_cstring(c->project, expected));
	}
	return { true };
}

static ffzOk error_not_an_expression(ffzChecker* c, ffzNode* node) {
	ERR(c, node, "Expected an expression, but got a statement or a procedure call with no return value.");
}

static ffzOk check_procedure_call(ffzChecker* c, const CheckInfer& infer, ffzNodeOperatorInst inst, OPT(ffzType*)* out_type) {
	ffzNodeInst left = ICHILD(inst, left);
	ffzCheckedExpr left_chk;
	TRY(check_expression(c, infer_no_help(infer), left, &left_chk));

	ffzType* type = left_chk.type;
	if (left_chk.type->tag != ffzTypeTag_Proc) {
		ERR(c, BASE(inst.node), "Attempted to call a non-procedure (%s)", ffz_type_to_cstring(c->project, left_chk.type));
	}

	*out_type = type->Proc.out_param ? type->Proc.out_param->type : NULL;

	if (ffz_get_child_count(BASE(inst.node)) != type->Proc.in_params.len) {
		ERR(c, BASE(inst.node), "Incorrect number of procedure arguments. (expected %u, got %u)",
			type->Proc.in_params.len, ffz_get_child_count(BASE(inst.node)));
	}

	uint i = 0;
	for FFZ_EACH_CHILD_INST(arg, inst) {
		ffzType* param_type = type->Proc.in_params[i].type;
		ffzCheckedExpr arg_chk;
		TRY(check_expression(c, infer_target_type(infer, param_type), arg, &arg_chk));
		TRY(check_types_match(c, arg.node, arg_chk.type, param_type, "Incorrect type with a procedure call argument:"));
		i++;
	}
	return { true };
}

static ffzOk check_two_sided(ffzChecker* c, const CheckInfer& infer, ffzNodeInst left, ffzNodeInst right, OPT(ffzType*)* out_type) {
	ffzCheckedExpr left_chk;
	ffzCheckedExpr right_chk;

	// Infer expressions, such as  `x: u32(1) + 50`  or  x: `2 * u32(552)`
	// first try inferring without the outside context. Then if that doesn't work, try inferring with it.

	CheckInfer input_infer = infer;
	input_infer.target_type = NULL;
	input_infer.testing_target_type = true;
	
	for (int i = 0; i < 2; i++) {
		TRY(check_expression(c, input_infer, left, &left_chk));
		TRY(check_expression(c, input_infer, right, &right_chk));

		if (left_chk.type && right_chk.type) {}
		else if (!left_chk.type && right_chk.type) {
			input_infer.target_type = right_chk.type;
			TRY(check_expression(c, input_infer, left, &left_chk));
		}
		else if (!right_chk.type && left_chk.type) {
			input_infer.target_type = left_chk.type;
			TRY(check_expression(c, input_infer, right, &right_chk));
		}
		else {
			input_infer = infer;
			continue;
		}
		break;
	}

	OPT(ffzType*) result = NULL;
	if (right_chk.type && left_chk.type) {
		if (type_is_a(c->project, left_chk.type, right_chk.type))      result = right_chk.type;
		else if (type_is_a(c->project, right_chk.type, left_chk.type)) result = left_chk.type;
		else {
			ERR(c, left.node->parent, "Types do not match.\n    left:    %s\nright:   %s",
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
static ffzOk check_expression_defaulting_to_uint(ffzChecker* c, CheckInfer infer, ffzNodeInst inst, OPT(ffzCheckedExpr*) out) {
	//F_ASSERT(infer.target_type == NULL);
	CheckInfer peek_infer = infer;
	peek_infer.testing_target_type = true;
	TRY(check_expression(c, peek_infer, inst, out));
	if (!out->type) {
		TRY(check_expression(c, infer_target_type(infer, ffz_builtin_type(c, ffzKeyword_uint)), inst, out));
	}
	return { true };
}

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
		TRY(_add_unique_definition(c, AS(n, Identifier)));
	}
	else if (n->kind == ffzNodeKind_Declaration) {
		TRY(_add_unique_definition(c, AS(AS(n, Declaration)->name, Identifier)));
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
		TRY(_ffz_add_possible_definitions(c, BASE(AS(node, Record)->polymorphic_parameters)));
	}
	else if (node->kind == ffzNodeKind_ProcType) {
		ffzNodeProcType* derived = AS(node, ProcType);

		TRY(_ffz_add_possible_definitions(c, BASE(derived->polymorphic_parameters)));
		if (derived->out_parameter) TRY(_ffz_add_possible_definition(c, derived->out_parameter));
	}
	else if (node->kind == ffzNodeKind_Operator) {
		ffzNodeOperator* derived = AS(node, Operator);

		if (derived->op_kind == ffzOperatorKind_PostCurlyBrackets) {
			// If the procedure type is anonymous, add the parameters to this scope. Otherwise, the programmer must use the `in` and `out` keywords to access parameters.
			if (derived->left->kind == ffzNodeKind_ProcType) {
				ffz_instanceless_check_ex(c, derived->left, recursive, false);
				//TRY(_ffz_add_possible_definitions(c, derived->left));

				//OPT(ffzNode*) out_parameter = AS(derived->left,ProcType)->out_parameter; // :AddOutParamDeclaration
				//if (out_parameter) TRY(_ffz_add_possible_definition(c, out_parameter));
			}
		}
	}
	else if (node->kind == ffzNodeKind_For) {
		ffzNodeFor* derived = AS(node, For);
		if (derived->header_stmts[0]) { // e.g. `for i: 0, ...`
			TRY(_ffz_add_possible_definition(c, derived->header_stmts[0]));
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

static ffzOk _check_operator(ffzChecker* c, ffzNodeOperatorInst inst, CheckInfer infer, ffzCheckedExpr* result, bool* delayed_check_proc) {
	ffzNodeOperator* node = inst.node;
	ffzNodeInst left = ICHILD(inst, left);
	ffzNodeInst right = ICHILD(inst, right);

	switch (node->op_kind) {
	case ffzOperatorKind_PostRoundBrackets: {
		bool fall = true;
		if (left.node->kind == ffzNodeKind_Keyword) {
			ffzKeyword keyword = AS(left.node, Keyword)->keyword;
			if (ffz_keyword_is_bitwise_op(keyword)) {
				if (ffz_get_child_count(BASE(node)) != (keyword == ffzKeyword_bit_not ? 1 : 2)) {
					ERR(c, BASE(node), "Incorrect number of arguments to a bitwise operation.");
				}

				ffzNodeInst first = ffz_get_child_inst(IBASE(inst), 0);
				if (keyword == ffzKeyword_bit_not) {
					ffzCheckedExpr chk;
					TRY(check_expression(c, infer, first, &chk));
					result->type = chk.type;
				}
				else {
					ffzNodeInst second = ffz_get_child_inst(IBASE(inst), 1);
					TRY(check_two_sided(c, infer, first, second, &result->type));
				}
				
				if (!is_basic_type_size(result->type->size)) {
					ERR(c, BASE(node), "bitwise operations only allow sizes of 1, 2, 4 or 8; Received: %u", result->type->size);
				}

				fall = false;
			}
			else if (keyword == ffzKeyword_size_of || keyword == ffzKeyword_align_of) {
				if (ffz_get_child_count(BASE(node)) != 1) {
					ERR(c, BASE(node), "Incorrect number of arguments to %s.", ffz_keyword_to_string[keyword].data);
				}

				ffzCheckedExpr chk;
				ffzNodeInst first = ffz_get_child_inst(IBASE(inst), 0);
				TRY(check_expression(c, infer_no_help(infer), first, &chk));
				if (!chk.type || chk.type->tag != ffzTypeTag_Type) {
					ERR(c, BASE(node), "Expected a type to %s, but got a value.", ffz_keyword_to_string[keyword].data);
				}
				
				result->type = ffz_builtin_type(c, ffzKeyword_uint);
				result->const_val = make_constant_int(c, keyword == ffzKeyword_align_of ? chk.const_val->type->align : chk.const_val->type->size);
				fall = false;
			}
			else if (keyword == ffzKeyword_import) {
				result->type = get_type_module();
				result->const_val = make_constant(c);
				
				ffzChecker* node_module = node_get_module(c->project, BASE(inst.node));
				result->const_val->module = *f_map64_get(&node_module->imported_modules, (u64)inst.node);
				fall = false;
			}
		}
		if (fall) {
			//HITS(___c, 2);
			ffzCheckedExpr left_chk;
			TRY(check_expression(c, infer_no_help(infer), left, &left_chk));

			if (left_chk.type->tag == ffzTypeTag_Type) {
				// ffzType casting
				result->type = left_chk.const_val->type;
				if (ffz_get_child_count(BASE(node)) != 1) ERR(c, BASE(node), "Incorrect number of arguments in type initializer.");

				ffzNodeInst arg = ffz_get_child_inst(IBASE(inst), 0);
				ffzCheckedExpr chk;

				// check the expression, but do not enforce the type inference, as the type inference rules are
				// more strict than a manual cast. For example, an integer cannot implicitly cast to a pointer, but when inside a cast it can.
				TRY(check_expression_defaulting_to_uint(c, infer_target_type(infer, result->type), arg, &chk));
				if (chk.type == NULL) ERR(c, BASE(node), "Invalid cast.");
				
				ffzTypeTag dst_tag = result->type->tag, src_tag = chk.type->tag;

				if (!ffz_type_is_pointer_ish(dst_tag) && !ffz_type_is_pointer_ish(src_tag)) {
					// the following shouldn't be allowed:
					// #foo: false
					// #bar: u32(&foo)
					// This is because given a constant integer, we want to be able to trivially ask what its value is.
					result->const_val = chk.const_val;
				}

				if (ffz_type_is_integer_ish(dst_tag) && ffz_type_is_integer_ish(src_tag)) {} // integer-ish types can be casted between
				else {
					TRY(check_types_match(c, BASE(node), chk.type, result->type, "The received type cannot be casted to the expected type:"));
				}
			}
			else {
				check_procedure_call(c, infer, inst, &result->type);
			}
		}
	} break;

	case ffzOperatorKind_UnaryMinus: // fallthrough
	case ffzOperatorKind_UnaryPlus: {
		ffzCheckedExpr right_chk;
		TRY(check_expression(c, infer, right, &right_chk));

		if (!ffz_type_is_integer(right_chk.type->tag)) {
			ERR(c, right.node, "Incorrect arithmetic type; should be an integer.\n    received: %s",
				ffz_type_to_cstring(c->project, right_chk.type));
		}
		result->type = right_chk.type;
	} break;

	case ffzOperatorKind_PreSquareBrackets: {
		ffzCheckedExpr right_chk;
		TRY(check_expression(c, infer_no_help(infer), right, &right_chk));
		if (right_chk.type->tag != ffzTypeTag_Type) ERR(c, right.node, "Expected a type after [], but got a value.");

		if (ffz_get_child_count(BASE(node)) == 0) {
			*result = _make_type_type(c, IBASE(inst), make_type_slice(c, right_chk.const_val->type));
		}
		else if (ffz_get_child_count(BASE(node)) == 1) {
			ffzNode* child = ffz_get_child(BASE(node), 0);
			s32 length = -1;
			if (child->kind == ffzNodeKind_IntLiteral) {
				length = (s32)AS(child, IntLiteral)->value;
			}
			else if (child->kind == ffzNodeKind_Keyword && AS(child,Keyword)->keyword == ffzKeyword_QuestionMark) {}
			else ERR(c, BASE(node), "Unexpected value inside the brackets of an array type; expected an integer literal or `?`");

			ffzType* array_type = make_type_fixed_array(c, right_chk.const_val->type, length);
			*result = _make_type_type(c, IBASE(inst), array_type);
		}
		else ERR(c, BASE(node), "Unexpected value inside the brackets of an array type; expected an integer literal or `_`");
	} break;

	case ffzOperatorKind_PointerTo: {
		ffzCheckedExpr right_chk;
		TRY(check_expression(c, infer_no_help(infer), right, &right_chk));
		
		if (right_chk.type->tag != ffzTypeTag_Type) {
			ERR(c, right.node, "Expected a type after ^, but got a value.");
		}
		*result = _make_type_type(c, IBASE(inst), make_type_ptr(c, right_chk.const_val->type));
	} break;
		
	case ffzOperatorKind_PostCurlyBrackets: {
		ffzCheckedExpr left_chk;
		TRY(check_expression(c, infer_no_help(infer), left, &left_chk));
		if (left_chk.type->tag != ffzTypeTag_Type) {
			ERR(c, left.node, "Invalid {} initializer; expected a type on the left side, but got a value.");
		}
		
		result->type = ffz_ground_type(left_chk);

		if (result->type->tag == ffzTypeTag_Proc || result->type->tag == ffzTypeTag_PolyProc) {
			result->const_val = make_constant(c);
			result->const_val->proc_node = IBASE(inst);
			if (result->type->tag != ffzTypeTag_PolyProc) {
				*delayed_check_proc = true;
			}
		}
		else if (result->type->tag == ffzTypeTag_Slice || result->type->tag == ffzTypeTag_FixedArray) {
			// Array initialization
			ffzType* elem_type = result->type->tag == ffzTypeTag_Slice ? result->type->fSlice.elem_type : result->type->FixedArray.elem_type;

			fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop());
			fArray(ffzCheckedExpr) elems_chk = f_array_make<ffzCheckedExpr>(temp);
			bool all_elems_are_constant = true;

			CheckInfer elem_infer = infer_target_type(infer, elem_type);
			for FFZ_EACH_CHILD_INST(n, inst) {
				ffzCheckedExpr chk;
				TRY(check_expression(c, elem_infer, n, &chk));
				f_array_push(&elems_chk, chk);
				all_elems_are_constant = all_elems_are_constant && chk.const_val;
			}

			if (result->type->tag == ffzTypeTag_FixedArray) {
				s32 expected = result->type->FixedArray.length;
				if (expected < 0) { // make a new type if [?]
					result->type = make_type_fixed_array(c, elem_type, (s32)elems_chk.len);
				}
				else if (elems_chk.len != expected) {
					ERR(c, BASE(node), "Incorrect number of array initializer arguments. Expected %d, got %d", expected, elems_chk.len);
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
			if (result->type->Record.is_union) ERR(c, BASE(node), "Union initialization with {} is not currently supported.");

			if (ffz_get_child_count(BASE(node)) != result->type->record_fields.len) {
				ERR(c, BASE(node), "Incorrect number of struct initializer arguments.");
			}

			bool all_fields_are_constant = true;
			fArray(ffzConstant) field_constants = f_array_make<ffzConstant>(c->alc);

			for FFZ_EACH_CHILD_INST(arg, inst) {
				ffzType* member_type = result->type->record_fields[field_constants.len].type;
				ffzCheckedExpr chk;
				TRY(check_expression(c, infer_target_type(infer, member_type), arg, &chk));

				if (chk.const_val) f_array_push(&field_constants, *chk.const_val);
				else all_fields_are_constant = false;
			}

			if (all_fields_are_constant) {
				result->const_val = make_constant(c);
				result->const_val->record_fields = field_constants.slice;
			}
		}
		else ERR(c, BASE(node), "{}-initializer is not allowed for `%s`.", ffz_type_to_cstring(c->project, result->type));
	} break;

	case ffzOperatorKind_PostSquareBrackets: {
		ffzCheckedExpr left_chk;
		TRY(check_expression(c, infer_no_help(infer), left, &left_chk));

		ffzType* left_type = left_chk.type;
		if (left_type->tag == ffzTypeTag_PolyProc ||
			(left_type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_PolyRecord))
		{
			left_type = ffz_ground_type(left_chk);
			//if (inst.node->loc.start.line_num == 12) F_BP;

			ffzPolymorph polymorph = {};
			polymorph.node = left_type->tag == ffzTypeTag_PolyProc ? BASE(left_chk.const_val->proc_node.node) : BASE(left_type->unique_node.node);
			ffzNode* type_node = BASE(left_type->unique_node.node);

			uint poly_params_len = ffz_get_child_count(left_type->tag == ffzTypeTag_PolyProc ? 
				BASE(AS(left_type->unique_node.node,ProcType)->polymorphic_parameters) :
				BASE(AS(left_type->unique_node.node,Record)->polymorphic_parameters));
			
			if (ffz_get_child_count(BASE(node)) != poly_params_len) {
				ERR(c, BASE(node), "Incorrect number of polymorphic arguments.");
			}

			polymorph.parameters = f_make_slice_garbage<ffzCheckedExpr>(poly_params_len, c->alc);

			uint i = 0;
			for FFZ_EACH_CHILD_INST(arg, inst) {
				ffzCheckedExpr arg_chk;
				TRY(check_expression(c, infer_no_help_constant(infer), arg, &arg_chk));
				if (arg_chk.type->tag != ffzTypeTag_Type) ERR(c, arg.node, "Polymorphic parameter must be a type   ...for now.");
				polymorph.parameters[i] = arg_chk;
				i++;
			}

			ffzPolymorphHash poly_hash = ffz_hash_poly(polymorph);
			auto poly_idx_entry = f_map64_insert(&c->poly_idx_from_hash, poly_hash, ffzPolymorphIdx{}, fMapInsert_DoNotOverride);
			if (poly_idx_entry.added) {
				// atomic array push, there should be a mutex here
				uint poly_inst_idx = f_array_push(&c->project->checker_from_poly_idx, c);
				*poly_idx_entry._unstable_ptr = ffzPolymorphIdx{ (u32)poly_inst_idx };
			}

			ffzPolymorphIdx poly_idx = *poly_idx_entry._unstable_ptr;
			f_map64_insert(&c->poly_from_idx, (u64)poly_idx.idx, polymorph, fMapInsert_DoNotOverride);
			f_map64_insert(&c->poly_instantiation_sites, ffz_hash_node_inst(IBASE(inst)), poly_idx);

			CheckInfer inst_infer = infer;
			inst_infer.instantiating_poly_type = type_node;
			
			// NOTE: if we have a polymorphic procedure, we don't want to check the procedure type - instead,
			// we want to check the procedure body {}-operator.
			
			TRY(check_expression(c, inst_infer, ffzNodeInst{ BASE(polymorph.node), poly_idx }, result));
		}
		else {
			// Array subscript

			if (!(left_chk.type->tag == ffzTypeTag_Slice || left_chk.type->tag == ffzTypeTag_FixedArray)) {
				ERR(c, left.node,
					"Expected an array, a slice, or a polymorphic type.\n    received: %s",
					ffz_type_to_cstring(c->project, left_chk.type));
			}
			
			ffzType* elem_type = left_chk.type->tag == ffzTypeTag_Slice ? left_chk.type->fSlice.elem_type : left_chk.type->FixedArray.elem_type;

			u32 child_count = ffz_get_child_count(BASE(node));
			if (child_count == 1) {
				ffzNodeInst index = ffz_get_child_inst(IBASE(inst), 0);
				
				ffzCheckedExpr index_chk;
				TRY(check_expression_defaulting_to_uint(c, infer_no_help(infer), index, &index_chk));
				
				if (!ffz_type_is_integer(index_chk.type->tag)) {
					ERR(c, index.node, "Incorrect type with a slice index; should be an integer.\n    received: %s",
						ffz_type_to_cstring(c->project, index_chk.type));
				}

				result->type = elem_type;
			}
			else if (child_count == 2) {
				ffzNodeInst lo = ffz_get_child_inst(IBASE(inst), 0);
				ffzNodeInst hi = ffz_get_child_inst(IBASE(inst), 1);
				
				ffzCheckedExpr lo_chk, hi_chk;
				if (lo.node->kind != ffzNodeKind_Blank) {
					TRY(check_expression_defaulting_to_uint(c, infer_no_help(infer), lo, &lo_chk));
					if (!ffz_type_is_integer(lo_chk.type->tag)) ERR(c, lo.node, "Expected an integer.");
				}
				if (hi.node->kind != ffzNodeKind_Blank) {
					TRY(check_expression_defaulting_to_uint(c, infer_no_help(infer), hi, &hi_chk));
					if (!ffz_type_is_integer(hi_chk.type->tag)) ERR(c, hi.node, "Expected an integer.");
				}

				result->type = make_type_slice(c, elem_type);
			}
			else {
				ERR(c, BASE(node), "Incorrect number of arguments inside subscript/slice operation.");
			}
		}
	} break;

	case ffzOperatorKind_MemberAccess: { // :CheckMemberAccess
		if (right.node->kind != ffzNodeKind_Identifier) {
			ERR(c, BASE(node), "Invalid member access; the right side was not an identifier.");
		}
		
		fString member_name = AS(right.node,Identifier)->name;
		
		bool found = false;
		if (left.node->kind == ffzNodeKind_Identifier && AS(left.node,Identifier)->name == F_LIT("in")) {
			F_BP;//if (AS(c->current_scope->parent_proc.node,Operator)->left->kind == ffzNodeKind_ProcType) {
			//	ERR(c, left.node, "`in` is not allowed when the procedure parameters are accessible by name.");
			//}

			F_BP;//for (uint i = 0; i < c->current_scope->parent_proc_type->Proc.in_params.len; i++) {
			//	ffzTypeProcParameter& param = c->current_scope->parent_proc_type->Proc.in_params[i];
			//	if (param.name->name == member_name) {
			//		found = true;
			//		result->type = param.type;
			//	}
			//}
		}
		else {
			ffzCheckedExpr left_chk;
			TRY(check_expression(c, infer_no_help(infer), left, &left_chk));

			if (left_chk.type->tag == ffzTypeTag_Module) {
				ffzChecker* left_module = left_chk.const_val->module;
				ffzNodeDeclarationInst decl;
				if (ffz_find_top_level_declaration(left_module, member_name, &decl)) {
					*result = ffz_decl_get_checked(c->project, decl);
					found = true;
				}
			}
			else if (left_chk.type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_Enum) {
				ffzType* enum_type = left_chk.const_val->type;
				ffzChecker* enum_type_module = ffz_checker_from_type(c->project, enum_type);
				ffzMemberHash member_key = ffz_hash_member(left_chk.const_val->type, member_name);

				if (u64* val = f_map64_get(&enum_type_module->enum_value_from_name, member_key)) {
					result->type = left_chk.const_val->type;
					result->const_val = make_constant_int(c, *val);
					found = true;
				}
			}
			else {
				ffzType* dereferenced_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;

				ffzTypeRecordFieldUse field;
				if (ffz_type_find_record_field_use(c->project, dereferenced_type, member_name, &field)) {
					result->type = field.type;
					found = true;
				}
			}
		}

		if (!found) ERR(c, BASE(right.node), "Declaration not found for `%s` inside (TODO: print LHS type)", f_str_to_cstr(member_name, c->alc));
	} break;

	case ffzOperatorKind_LogicalNOT: {
		result->type = ffz_builtin_type(c, ffzKeyword_bool);
		TRY(check_expression(c, infer_target_type(infer, result->type), right));
	} break;

	case ffzOperatorKind_LogicalAND: // fallthrough
	case ffzOperatorKind_LogicalOR: {
		result->type = ffz_builtin_type(c, ffzKeyword_bool);
		TRY(check_expression(c, infer_target_type(infer, result->type), left));
		TRY(check_expression(c, infer_target_type(infer, result->type), right));
	} break;

	case ffzOperatorKind_AddressOf: {
		ffzCheckedExpr right_chk;
		TRY(check_expression(c, infer_no_help(infer), right, &right_chk));
		result->type = make_type_ptr(c, right_chk.type);
	} break;

	case ffzOperatorKind_Dereference: {
		ffzCheckedExpr left_chk;
		TRY(check_expression(c, infer_no_help(infer), left, &left_chk));
		if (left_chk.type->tag != ffzTypeTag_Pointer) ERR(c, BASE(node), "Attempted to dereference a non-pointer.");
		result->type = left_chk.type->Pointer.pointer_to;
	} break;
		
	case ffzOperatorKind_Equal: case ffzOperatorKind_NotEqual: case ffzOperatorKind_Less:
	case ffzOperatorKind_LessOrEqual: case ffzOperatorKind_Greater: case ffzOperatorKind_GreaterOrEqual: {
		OPT(ffzType*) type;
		TRY(check_two_sided(c, infer, left, right, &type));
		
		if (!ffz_type_is_comparable(type)) {
			ERR(c, BASE(node), "Types cannot be compared. Received: %s", ffz_type_to_cstring(c->project, type));
		}
		result->type = ffz_builtin_type(c, ffzKeyword_bool);
	} break;

	case ffzOperatorKind_Add: case ffzOperatorKind_Sub: case ffzOperatorKind_Mul:
	case ffzOperatorKind_Div: case ffzOperatorKind_Modulo: {
		OPT(ffzType*) type;
		TRY(check_two_sided(c, infer, left, right, &type));
		
		if (type && !ffz_type_is_integer(type->tag)) {
			ERR(c, BASE(node), "Incorrect arithmetic type; should be an integer.\n    received: ",
				ffz_type_to_cstring(c->project, type));
		}
		result->type = type;
	} break;

		default: F_BP;
	}
	return { true };
}

//bool ffz_definition_is_constant(ffzNode* def) {
//	//ASSERT(node_is_definition(def));
//	return def->kind != ffzNodeKind_Declaration || AS(def,Declaration)->name->is_constant;
//}

static bool is_lvalue(ffzChecker* c, ffzNode* node) {
	switch (node->kind) {
	case ffzNodeKind_Identifier: {
		ffzNodeIdentifier* def = ffz_get_definition(c->project, AS(node,Identifier));
		if (def->is_constant) return false;
		return true;
	} break;
	case ffzNodeKind_Operator: {
		ffzNodeOperator* op = AS(node,Operator);
		if (op->op_kind == ffzOperatorKind_MemberAccess) return is_lvalue(c, op->left);
		if (op->op_kind == ffzOperatorKind_PostSquareBrackets) return is_lvalue(c, op->right);
		if (op->op_kind == ffzOperatorKind_Dereference) return true;
	} break;
	}
	return false;
}

// The type checking stage checks if the program is correct, and in doing so,
// computes and caches information about the program, such as which declarations
// identifiers are pointing to, what types do expressions have, and so on.
// If the c succeeds, the program is valid and should compile with no errors.

static bool checker_already_cached(ffzChecker* c, ffzNodeInst node) {
	return f_map64_get(&c->cache, ffz_hash_node_inst(node));
}

static void checker_cache(ffzChecker* c, ffzNodeInst node, ffzCheckedExpr result) {
	f_map64_insert(&c->cache, ffz_hash_node_inst(node), result, fMapInsert_DoNotOverride);
}


/////// this should return the same CheckedExpr as the left-hand-side expression of the declaration.
static ffzOk check_declaration(ffzChecker* c, const CheckInfer& infer, ffzNodeDeclarationInst inst) {
	if (checker_already_cached(c, IBASE(inst))) return { true };
	F_ASSERT(infer.target_type == NULL);

	ffzNodeIdentifierInst name = ICHILD(inst, name);
	//if(name.node->name == F_LIT("arr")) F_BP;

	ffzNodeInst rhs = ICHILD(inst, rhs);
	
	CheckInfer child_infer = infer;
	if (!ffz_decl_is_runtime_value(inst.node)) child_infer.expect_constant = true;
	
//	F_HITS(_c, 263);
	ffzCheckedExpr lhs_chk, rhs_chk;
	TRY(check_expression_defaulting_to_uint(c, child_infer, rhs, &rhs_chk));
	
	ffzCheckedExpr out = rhs_chk;
	if (ffz_decl_is_runtime_value(inst.node)) {
		F_ASSERT(ffz_type_is_grounded(out.type)); // :GroundTypeType

		F_ASSERT(out.type->size > 0); // todo: get rid of this check

		out.const_val = NULL; // non-constant declarations shouldn't store the constant value that the rhs expression might have
		// hmm... but they should within struct definitions.
	}

	checker_cache(c, IBASE(inst), out); // the lhs check_expression will recurse into this same check_declaration procedure, so this will prevent it.
	TRY(check_expression(c, child_infer, IBASE(name), &lhs_chk));
	return { true };
}

ffzOk ffz_check_toplevel_statement(ffzChecker* c, ffzNode* node) {
	switch (node->kind) {
	case ffzNodeKind_Declaration: {
		ffzNodeIdentifier* name = AS(node,Declaration)->name;
		if (!name->is_constant) ERR(c, BASE(name), "Top-level declaration must be constant, but got a non-constant.");
		
		ffzNodeInst inst = ffz_get_toplevel_inst(c, node);
		TRY(check_declaration(c, CheckInfer{}, IAS(inst,Declaration)));
	} break;
	default: ERR(c, node, "Top-level node must be a declaration; got: %s", ffz_node_kind_to_cstring(node->kind));
	}
	return { true };
}

static ffzNodeOperatorInst code_stmt_get_parent_proc(ffzProject* p, ffzNodeInst inst, ffzType** out_type) {
	ffzNodeInst parent = inst;
	parent.node = parent.node->parent;
	for (; parent.node; parent.node = parent.node->parent) {
		if (parent.node->kind == ffzNodeKind_Operator) {
			ffzType* type = ffz_expr_get_type(p, parent);
			F_ASSERT(type);
			if (type->tag == ffzTypeTag_Proc) {
				*out_type = type;
				return IAS(parent, Operator);
			}
		}
	}
	F_ASSERT(false);
	return {};
}


static ffzOk check_code_statement(ffzChecker* c, const CheckInfer& infer, ffzNodeInst inst) {
	F_ASSERT(infer.target_type == NULL && !infer.expect_constant);
	// TODO: avoid duplicate checking like in check_expression
	//AstNodePolyInstHash node_hash = hash_node_inst(node);
	//auto insertion = map64_insert(&c->cache, node_hash, CheckResult{}, MapInsert_DoNotOverride);
	//if (!insertion.added) return { true };

	if (!infer.instantiating_poly_type) {
		ffz_instanceless_check(c, inst.node, false);
	}

	// infer_decl_type is only currently used with enums, where the enum header defines the type of the expressions
	//HITS(_c, 67);
	switch (inst.node->kind) {
	case ffzNodeKind_Declaration: {
		TRY(check_declaration(c, infer, IAS(inst,Declaration)));
		return { true };
	} break;

	case ffzNodeKind_Assignment: {
		ffzNodeInst lhs = ICHILD(IAS(inst,Assignment), lhs);
		ffzNodeInst rhs = ICHILD(IAS(inst, Assignment), rhs);
		ffzCheckedExpr lhs_chk, rhs_chk;

		//ffzCheckerStackFrame frame;
		//push_scope(c, inst, &frame);
		//frame.parent_targeted = inst;

		TRY(check_expression(c, infer_no_help(infer), lhs, &lhs_chk));
		F_ASSERT(ffz_type_is_grounded(lhs_chk.type));

		TRY(check_expression(c, infer_target_type(infer, lhs_chk.type), rhs, &rhs_chk));
		
		// hmm.. should we allow  `foo= u32`  ?
		//if (!ffz_type_is_grounded(rhs_chk.type)) ERR(c, rhs.node, "Expected a value, but got a type.");
		TRY(check_types_match(c, rhs.node, rhs_chk.type, lhs_chk.type, "Incorrect type with assignment:"));
		
		bool is_code_scope = inst.node->parent->kind == ffzNodeKind_Scope || inst.node->parent->kind == ffzNodeKind_ProcType;
		if (is_code_scope && lhs_chk.type->tag != ffzTypeTag_Raw && !is_lvalue(c, lhs.node)) {
			ERR(c, lhs.node, "Attempted to assign to a non-assignable value.");
		}
		//pop_scope(c);
		return { true };
	} break;

	case ffzNodeKind_Keyword: {
		switch (AS(inst.node,Keyword)->keyword) {
		case ffzKeyword_dbgbreak: return { true };
		}
	} break;

	case ffzNodeKind_Return: {
		ffzNodeInst return_val = ICHILD(IAS(inst,Return), value);
		ffzType* proc_type;
		ffzNodeOperatorInst proc_node = code_stmt_get_parent_proc(c->project, inst, &proc_type);
		
		ffzTypeProcParameter* out_param = proc_type->Proc.out_param;
		
		// named returns are only supported if the procedure header is declared alongside the procedure
		bool has_named_return = out_param && out_param->name && proc_node.node->left->kind == ffzNodeKind_ProcType;
		if (!return_val.node && out_param && !has_named_return) ERR(c, inst.node, "Expected a return value, but none was given.");
		if (return_val.node && !out_param) ERR(c, return_val.node, "Expected no return value, but one was given.");
		
		if (return_val.node) {
			TRY(check_expression(c, infer_target_type(infer, out_param->type), return_val));
		}
		return { true };
	} break;

	case ffzNodeKind_Scope: {
		CheckInfer child_infer = infer_target_type(infer, NULL);
		for FFZ_EACH_CHILD_INST(stmt, inst) {
			TRY(check_code_statement(c, child_infer, stmt));
		}
		return { true };
	} break;

	case ffzNodeKind_Operator: {
		ffzNodeOperatorInst op = IAS(inst,Operator);
		if (op.node->op_kind == ffzOperatorKind_PostRoundBrackets) {
			OPT(ffzType*) return_type = NULL;
			TRY(check_procedure_call(c, infer, op, &return_type));
			//if (return_type) ERR(c, inst.node,
			//	"Procedure returns a value, but it is ignored. I you want to ignore it, you must explicitly state it, e.g. `_= foo()`");
			
			//if (!out_param) CHECKER_ERROR(c, node.node->Return.value, F_LIT("Procedure is declared to return no value, but a return value was received."));
			return { true };
		}
	} break;

	case ffzNodeKind_If: {
		ffzNodeIfInst if_stmt = IAS(inst,If);
		TRY(check_expression(c, infer_target_type(infer, ffz_builtin_type(c, ffzKeyword_bool)), ICHILD(if_stmt,condition)));
		TRY(check_code_statement(c, infer, ICHILD(if_stmt,true_scope)));
		if (if_stmt.node->else_scope) {
			TRY(check_code_statement(c, infer, ICHILD(if_stmt,else_scope)));
		}
		return { true };
	} break;

	case ffzNodeKind_For: {
		ffzNodeForInst for_loop = IAS(inst,For);
		//ffzCheckerScope scope;
		//push_scope(c, inst, &scope); // This scope is for the possible declaration inside the for-loop header.

		for (int i = 0; i < 3; i++) {
			if (for_loop.node->header_stmts[i]) {
				if (i == 1) {
					TRY(check_expression(c, infer_target_type(infer, ffz_builtin_type(c, ffzKeyword_bool)), ICHILD(for_loop,header_stmts[i])));
				}
				else {
					//TRY(ffz_add_possible_definition(c, for_loop.node->header_stmts[i]));
					TRY(check_code_statement(c, infer, ICHILD(for_loop,header_stmts[i])));
				}
			}
		}

		TRY(check_code_statement(c, infer, ICHILD(for_loop,scope)));
		//pop_scope(c);
		return { true };
	} break;
	}

	ERR(c, inst.node, "Invalid statement.");
	return { false };
}

ffzNodeInst ffz_get_instantiated_inst(ffzChecker* c, ffzNodeInst node) {
	if (node.node->kind == ffzNodeKind_Operator && AS(node.node,Operator)->kind == ffzOperatorKind_PostSquareBrackets) {
		ffzPolymorphIdx* poly_idx = f_map64_get(&c->poly_instantiation_sites, ffz_hash_node_inst(node));
		if (poly_idx) {
			node = ffzNodeInst{ f_map64_get(&c->poly_from_idx, poly_idx->idx)->node, *poly_idx };
		}
	}
	return node;
}

ffzChecker* ffz_checker_init(ffzProject* p, fAllocator* allocator) {
	ffzChecker* c = f_mem_clone(ffzChecker{}, allocator);	
	c->project = p;
	c->self_idx = (ffzCheckerIndex)f_array_push(&p->checkers, c);
	c->alc = allocator;
	c->checked_identifiers = f_map64_make_raw(0, c->alc);
	c->definition_map = f_map64_make<ffzNodeIdentifier*>(c->alc);
	c->cache = f_map64_make<ffzCheckedExpr>(c->alc);
	c->type_from_hash = f_map64_make<ffzType*>(c->alc);
	c->poly_from_idx = f_map64_make<ffzPolymorph>(c->alc);
	c->poly_idx_from_hash = f_map64_make<ffzPolymorphIdx>(c->alc);
	c->poly_instantiation_sites = f_map64_make<ffzPolymorphIdx>(c->alc);
	c->record_field_from_name = f_map64_make<ffzTypeRecordFieldUse*>(c->alc);
	c->enum_value_from_name = f_map64_make<u64>(c->alc);
	c->enum_value_is_taken = f_map64_make<ffzNode*>(c->alc);
	c->imported_modules = f_map64_make<ffzChecker*>(c->alc);
	c->pointer_size = 8;

	c->toplevel_poly_idx = ffzPolymorphIdx{ (u32)f_array_push(&p->checker_from_poly_idx, c) };

	{
		u32 a = ffzKeyword_u8;
		c->builtin_types[ffzKeyword_u8 - a] = { ffzTypeTag_SizedUint, 1, 1 };
		c->builtin_types[ffzKeyword_u16 - a] = { ffzTypeTag_SizedUint, 2, 2 };
		c->builtin_types[ffzKeyword_u32 - a] = { ffzTypeTag_SizedUint, 4, 4 };
		c->builtin_types[ffzKeyword_u64 - a] = { ffzTypeTag_SizedUint, 8, 8 };
		c->builtin_types[ffzKeyword_s8 - a] = { ffzTypeTag_SizedInt, 1, 1 };
		c->builtin_types[ffzKeyword_s16 - a] = { ffzTypeTag_SizedInt, 2, 2 };
		c->builtin_types[ffzKeyword_s32 - a] = { ffzTypeTag_SizedInt, 4, 4 };
		c->builtin_types[ffzKeyword_s64 - a] = { ffzTypeTag_SizedInt, 8, 8 };
		c->builtin_types[ffzKeyword_uint - a] = { ffzTypeTag_Uint, c->pointer_size, c->pointer_size };
		c->builtin_types[ffzKeyword_int - a] = { ffzTypeTag_Int, c->pointer_size, c->pointer_size };
		c->builtin_types[ffzKeyword_raw - a] = { ffzTypeTag_Raw };
		c->builtin_types[ffzKeyword_bool - a] = { ffzTypeTag_Bool, 1, 1 };

		{
			ffzType* string = &c->builtin_types[ffzKeyword_string - a];
			*string = { ffzTypeTag_String, c->pointer_size * 2, c->pointer_size };

			string->record_fields = f_make_slice_garbage<ffzTypeRecordField>(2, c->alc);
			string->record_fields[0] = { F_LIT("ptr"), make_type_ptr(c, ffz_builtin_type(c, ffzKeyword_u8)), 0, NULL };
			string->record_fields[1] = { F_LIT("len"), ffz_builtin_type(c, ffzKeyword_uint), c->pointer_size, NULL };
			add_names_to_record_member_map(c, string, string, 0);
		}
	}
	return c;
}

bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee) {
	// TODO: we need to check for procedure boundaries.
	for (ffzNode* p = dot.node->parent; p; p = p->parent) {
		if (p->kind == ffzNodeKind_Assignment) {
			ffzNodeAssignmentInst assignment_inst = { AS(p,Assignment), dot.poly_idx };
			*out_assignee = ICHILD(assignment_inst,lhs);
			return true;
		}
	}
	return false;
}

static ffzOk check_expression(ffzChecker* c, const CheckInfer& infer, ffzNodeInst inst, OPT(ffzCheckedExpr*) out) {
	ffzNodeInstHash inst_hash = ffz_hash_node_inst(inst);
	if (ffzCheckedExpr* existing = f_map64_get(&c->cache, inst_hash)) {
		if (out) *out = *existing;
		return { true };
	}
	//F_HITS(_c, 32);
	
	if (!infer.instantiating_poly_type) {
		ffz_instanceless_check(c, inst.node, false);
	}

	ffzCheckedExpr result = {};
	
	bool delayed_check_record = false;
	bool delayed_check_proc = false;

	switch (inst.node->kind) {
	case ffzNodeKind_Keyword: {
		ffzKeyword keyword = AS(inst.node,Keyword)->keyword;
		OPT(ffzType*) type_expr = ffz_builtin_type(c, keyword);
		if (type_expr) {
			result = _make_type_type(c, inst, type_expr);
		}
		else {
			switch (keyword) {
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
				result = _make_type_type(c, inst, ffz_builtin_type(c, ffzKeyword_raw));
			} break;
			default: F_ASSERT(false);
			}
		}
	} break;

	case ffzNodeKind_Dot: {
		ffzNodeInst assignee;
		if (!ffz_dot_get_assignee(IAS(inst,Dot), &assignee)) {
			ERR(c, inst.node, "`.` catcher must be used within an assignment, but no assignment was found.");
		}
		result.type = ffz_expr_get_type(c->project, assignee); // when checking assignments, the assignee/lhs is always checked first, so this should be ok.
	} break;

	case ffzNodeKind_Identifier: {
		fString name = AS(inst.node, Identifier)->name;
		ffzNodeIdentifier* def = ffz_get_definition(c->project, AS(inst.node, Identifier));
		if (!def) {
			ERR(c, inst.node, "Declaration not found for an identifier: \"%s\"", f_str_to_cstr(name, c->alc));
		}

		/* the poly inst must be taken from the node, not the scope. e.g.
			#AdderType: proc[T](first: T, second: T)
			#adder: AdderType { dbgbreak }
			#demo: proc() { adder[int](5, 6) }
		*/
		
		/*
		#outer: proc[R] {
			#b: proc[T] {
				aaa: R
				aaa= 5
			}
			b[R]()
		}
		#main: proc {
			outer[u32]()
		}
		*/

		ffzNodeIdentifierInst def_inst = { def, inst.poly_idx };
		if (def_inst.node->parent->kind == ffzNodeKind_PolyParamList) {
			ffzPolymorph poly = ffz_poly_from_inst(c->project, inst);
			result = poly.parameters[ffz_get_child_index(BASE(def))];
		}
		else {
			ffzNodeDeclarationInst decl_inst;
			F_ASSERT(ffz_get_decl_if_definition(def_inst, &decl_inst));

			fMapInsertResult circle_chk = f_map64_insert_raw(&c->checked_identifiers, ffz_hash_node_inst(IBASE(inst)), NULL, fMapInsert_DoNotOverride);
			if (!circle_chk.added) ERR(c, BASE(inst.node), "Circular definition!"); // TODO: elaborate

			// Sometimes we need to access a constant declaration that's ahead of us that we haven't yet checked.
			// In that case we need to completely reset the context back to the declaration's scope, then evaluate the
			// thing we need real quick, and then come back as if nothing had happened.
			
			TRY(check_declaration(c, infer_no_help(infer), decl_inst));			

			if (BASE(def) != inst.node && ffz_decl_is_runtime_value(decl_inst.node) && decl_inst.node->parser_local_index > inst.node->parser_local_index) {
				ERR(c, inst.node, "Variable is being used before it is declared.");
			}
			
			result = ffz_decl_get_checked(c->project, decl_inst);
			if (def_inst.node->is_constant) F_ASSERT(result.const_val);
		}

	} break;

	case ffzNodeKind_Operator: {
		TRY(_check_operator(c, IAS(inst,Operator), infer, &result, &delayed_check_proc));
	} break;

	case ffzNodeKind_ProcType: {
		ffzNodeProcTypeInst type_node = IAS(inst,ProcType);
		ffzType proc_type = { ffzTypeTag_Proc };
		proc_type.unique_node = inst;
		ffzNodeInst out_param = ICHILD(type_node, out_parameter);

		if (ffz_get_child_count(BASE(type_node.node->polymorphic_parameters)) > 0 && infer.instantiating_poly_type != inst.node) {
			proc_type.tag = ffzTypeTag_PolyProc;
		}
		else {
			proc_type.size = c->pointer_size;

			ffzNodePolyParamListInst poly_params = ICHILD(type_node, polymorphic_parameters);
			for FFZ_EACH_CHILD_INST(n, poly_params) {
				TRY(check_expression(c, infer_no_help_constant(infer), n));
			}
			
			fArray(ffzTypeProcParameter) in_parameters = f_array_make<ffzTypeProcParameter>(c->alc);
			for FFZ_EACH_CHILD_INST(param, inst) {
				if (param.node->kind != ffzNodeKind_Declaration) ERR(c, param.node, "Expected a declaration.");
				TRY(check_declaration(c, infer_no_help_nonconstant(infer), IAS(param, Declaration)));

				f_array_push(&in_parameters, ffzTypeProcParameter{
					IAS(param,Declaration).node->name,
						ffz_decl_get_type(c->project, IAS(param,Declaration)),
					});
			}
			proc_type.Proc.in_params = in_parameters.slice;

			//type_node.node->out_parameter
			if (out_param.node) {
				// Procedure return value can be either a declaration or an anonymous type.

				proc_type.Proc.out_param = f_mem_clone(ffzTypeProcParameter{}, c->alc);
				if (out_param.node->kind == ffzNodeKind_Declaration) {
					ffzNodeDeclarationInst out_param_decl = IAS(out_param, Declaration);
					TRY(check_declaration(c, infer_no_help(infer), out_param_decl));

					proc_type.Proc.out_param->name = out_param_decl.node->name;
					proc_type.Proc.out_param->type = ffz_decl_get_type(c->project, out_param_decl);
				}
				else {
					ffzCheckedExpr chk;
					TRY(check_expression(c, infer_no_help(infer), out_param, &chk));
					proc_type.Proc.out_param->type = ffz_ground_type(chk);
				}
			}
		}
		
		if (ffz_node_get_compiler_tag(BASE(type_node.node), F_LIT("extern"))) {
			if (proc_type.tag == ffzTypeTag_PolyProc) ERR(c, inst.node, "Polymorphic procedures cannot be @extern.");

			// if it's an extern proc, then don't turn it into a type type!!
			result.type = make_type(c, proc_type);
			result.const_val = make_constant(c);
			result.const_val->proc_node = inst;
		}
		else {
			result = _make_type_type(c, inst, make_type(c, proc_type));
		}
	} break;

	case ffzNodeKind_Record: {
		ffzNodeRecordInst inst_struct = IAS(inst,Record);
		ffzType struct_type = { ffzTypeTag_Record };
		struct_type.unique_node = inst;

		if (ffz_get_child_count(BASE(inst_struct.node->polymorphic_parameters)) > 0 && infer.instantiating_poly_type != inst.node) {
			struct_type.tag = ffzTypeTag_PolyRecord;
		}
		else {
			delayed_check_record = true;
		}
		result = _make_type_type(c, inst, make_type(c, struct_type));
	} break;

	case ffzNodeKind_Enum: {
		ffzCheckedExpr type_chk;
		ffzNodeEnumInst inst_enum = IAS(inst, Enum);
		TRY(check_expression(c, infer_no_help(infer), ICHILD(inst_enum,internal_type), &type_chk));

		if (type_chk.type->tag != ffzTypeTag_Type || !ffz_type_is_integer(type_chk.const_val->type->tag)) {
			ERR(c, inst_enum.node->internal_type, "Invalid enum type; expected an integer.");
		}

		ffzType enum_type = { ffzTypeTag_Enum };
		enum_type.Enum.internal_type = type_chk.const_val->type;
		enum_type.size = enum_type.Enum.internal_type->size;
		enum_type.unique_node = inst;
		enum_type.Enum.fields = f_make_slice_garbage<ffzTypeEnumField>(ffz_get_child_count(inst.node), c->alc);

		// :EnumFieldsShouldNotContributeToTypeHash
		// Note that we're making the enum type pointer BEFORE populating all of the fields
		ffzType* enum_type_ptr = make_type(c, enum_type);

		CheckInfer decl_infer = infer_no_help_constant(infer);
		decl_infer.infer_decl_type = enum_type.Enum.internal_type;

		uint i = 0;
		for FFZ_EACH_CHILD_INST(n, inst_enum) {
			if (n.node->kind != ffzNodeKind_Declaration) ERR(c, BASE(n.node), "Expected a declaration; got: [%s]", ffz_node_kind_to_cstring(n.node->kind));
			
			ffzNodeDeclarationInst decl = IAS(n, Declaration);
			TRY(check_declaration(c, decl_infer, decl));
			ffzCheckedExpr chk = ffz_decl_get_checked(c->project, decl);

			u64 val = chk.const_val->u64_;
			ffzMemberHash key = ffz_hash_member(enum_type_ptr, decl.node->name->name);
			f_map64_insert(&c->enum_value_from_name, key, val);

			enum_type.Enum.fields[i] = ffzTypeEnumField{ decl.node->name->name, val };

			auto val_taken = f_map64_insert(&c->enum_value_is_taken, ffz_hash_enum_value(enum_type_ptr, val), n.node, fMapInsert_DoNotOverride);
			if (!val_taken.added) {
				ERR(c, decl.node->rhs, "The enum value `%llu` is already taken by `%s`.", val,
					f_str_to_cstr(AS(*val_taken._unstable_ptr,Declaration)->name->name, c->alc));
			}
			i++;
		}
		result = _make_type_type(c, inst, enum_type_ptr);
	} break;

	case ffzNodeKind_FloatLiteral: {F_BP; } break;

	case ffzNodeKind_IntLiteral: {
		//if (!required_type) Error(node->pos, F_LIT("Can't infer the type of an integer literal."));
		//if (required_type->tag != TypeTag_SignedInt && required_type->tag != TypeTag_UnsignedInt) Error(node->pos, F_LIT("Invalid value."));

		//if (!required_type) CHECKER_ERROR(c, node, F_LIT("Cannot infer integer literal."));

		if (infer.target_type) {
			if (ffz_type_is_integer(infer.target_type->tag)) {
				result.type = infer.target_type;
				result.const_val = make_constant_int(c, AS(inst.node, IntLiteral)->value);
			}
			else if (!infer.testing_target_type) {
				ERR(c, inst.node, "Unexpected integer literal.");
			}
		}
		//else {
		//	t = &type_uint;
		//	if (node->IntLiteral.value < 0) CHECKER_ERROR(c, node, F_LIT("The default type for an integer literal is `uint`, but a negative number was given. If you want a signed integer, use int(x) instead."));
		//}
		//should_cache_type = false;
	} break;

	case ffzNodeKind_StringLiteral: {
		// pointers aren't guaranteed to be valid / non-null, but optional pointers are expected to be null.
		result.type = ffz_builtin_type(c, ffzKeyword_string);
		result.const_val = make_constant(c);
		result.const_val->string_zero_terminated = AS(inst.node,StringLiteral)->zero_terminated_string;
	} break;

	default: ERR(c, inst.node, "Expected an expression; got [%s]", ffzNodeKind_String[inst.node->kind].data);
	}

	ffzCheckedExpr ungrounded_result = result;
	if (result.type) {
		if (infer.expect_constant && !result.const_val) {
			ERR(c, inst.node, "Expression is not constant, but constant was expected.");
		}
		
		if (result.type->tag == ffzTypeTag_Type &&
			inst.node->parent->kind == ffzNodeKind_Declaration &&
			ffz_decl_is_runtime_value(AS(inst.node->parent, Declaration))) {
			// If you query the type of the declaration's expression without any context,
			// it may have a type type. i.e.
			// ...
			// MyThing: u32 
			// ...
			// calling ffz_expr_get_type() on the right-hand-side will return a type type,
			// but calling ffz_decl_get_type() on the declaration, or ffz_expr_get_type()
			// on the left-hand-side will return the grounded type.
			result.type = ffz_ground_type(result);
			result.const_val = ffz_get_default_value_for_type(c, result.type);
		}

		f_map64_insert(&c->cache, inst_hash, result);
	}

	if (!infer.testing_target_type) {
		if (infer.target_type) {
			// make sure the target type matches
			TRY(check_types_match(c, inst.node, result.type, infer.target_type, "Unexpected type with an expression:"));
		}
		if (!result.type) {
			ERR(c, inst.node, "Expression has no return type, or it cannot be inferred.");
		}
	}

	if (result.type) {
		if (result.type->tag == ffzTypeTag_Type) {
			F_ASSERT(result.const_val);
		}
		
		if (delayed_check_proc) {
			// only check the procedure body when we have a physical procedure instance (not polymorphic)
			// and after the proc type has been cached.
			for FFZ_EACH_CHILD_INST(n, inst) {
				TRY(check_code_statement(c, infer_no_help_nonconstant(infer), n));
			}
		}
		else if (delayed_check_record) {
			// Add the record fields only after the type has been registered in the cache. This is to avoid
			// infinite loops when checking.
			
			// IMPORTANT: We're modifying the type AFTER it was created and hash-deduplicated. So, the things we modify must not change the type hash!
			//HITS(__c, 2);
			ffzNodeRecordInst inst_struct = IAS(inst, Record);
			ffzType* record_type = ffz_ground_type(result);
			record_type->record_fields = f_make_slice_garbage<ffzTypeRecordField>(ffz_get_child_count(inst.node), c->alc);
			
			uint i = 0;
			u32 offset = 0;
			u32 alignment = 0;
			for FFZ_EACH_CHILD_INST(n, inst_struct) {
				if (n.node->kind != ffzNodeKind_Declaration) ERR(c, n.node, "Expected a declaration.");

				ffzNodeDeclarationInst decl = IAS(n, Declaration);
				TRY(check_declaration(c, infer_no_help(infer), decl));

				ffzType* member_type = ffz_ground_type(ffz_decl_get_checked(c->project, decl)); // ffz_decl_get_type(c, decl);
				F_ASSERT(ffz_type_is_grounded(member_type));
				alignment = F_MAX(alignment, member_type->align);

				//if (ffz_node_get_compiler_tag(BASE(decl.node), F_LIT("using"))) F_BP; // TODO: bring back @using

				record_type->record_fields[i] = ffzTypeRecordField{
					decl.node->name->name,                                      // `name`
					member_type,                                                // `type`
					inst_struct.node->is_union ? 0 : offset,                    // `offset`
					decl.node,                                                  // `decl`
				};
				F_ASSERT(!inst_struct.node->is_union); // uhh the logic for calculating union offsets is not correct
				offset = F_ALIGN_UP_POW2(offset + member_type->size, alignment);
				i++;
			}

			record_type->size = F_ALIGN_UP_POW2(offset, alignment); // Align the struct size up to the largest member alignment
			record_type->align = alignment; // :ComputeRecordAlignment
			TRY(add_names_to_record_member_map(c, record_type, record_type));
		}
	}

	if (out) *out = result;
	return { true };
}

