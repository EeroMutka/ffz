#if 0
#include "foundation/foundation.hpp"

//#include "GMMC/gmmc.h"


#include "ffz_ast.h"
#include "ffz_checker.h"
#include "ffz_backend_c0.h"
#include "ffz_lib.h"

#define SHA256_DECL extern "C"
#include "vendor/sha256.h"

// Helper macros

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

#define IAS(node, kind) FFZ_INST_AS(node, kind)
#define IBASE(node) FFZ_INST_BASE(node) 
#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).poly_inst }

static C0Instr* gen_expr(ffzGenC0* g, ffzNodeInst inst, bool address_of = false);
static void gen_statement(ffzGenC0* g, ffzNodeInst inst);
static C0Global* gen_global(ffzGenC0* g, ffzCheckedExpr expr);
static C0Constant gen_constant(ffzGenC0* g, ffzType* type, ffzConstant* const_val);

/*
static C0Proc* test_factorial(C0Gen* g) {
	C0AggType* agg_u32 = c0_agg_type_basic(g, C0Basic_u32);

	C0Array(C0AggType*) sig_types = NULL;
	c0array_push(sig_types, agg_u32);

	C0Array(C0String) sig_names = NULL;
	c0array_push(sig_names, C0STR("n"));

	C0Proc* p = c0_proc_create(g, C0STR("main"), c0_agg_type_proc(g, agg_u32, sig_names, sig_types, 0));

	C0Instr* n = p->parameters[0];

	C0Instr* cond = c0_push_lt(p, n, c0_push_basic_u32(p, 2));
	c0_push_if(p, cond);
	{
		c0_push_return(p, c0_push_basic_u32(p, 1));
	}
	c0_pop_if(p);
	{
		C0Instr* one_below = c0_push_call_proc1(p, p, c0_push_sub(p, n, c0_push_basic_u32(p, 1)));
		C0Instr* res = c0_push_mul(p, n, one_below);
		c0_push_return(p, res);
	}
	
	return c0_proc_finish(p);
}*/

static void print_c0(void* user_data, const char* fmt, va_list args) {
	vfprintf((FILE*)user_data, fmt, args);
	//vprintf(fmt, args);
}

static String fill_empty_name_with_id(ffzGenC0* g, String name) {
	if (name.len == 0) {
		name = str_format(g->alc, "_ffz_%llu", g->dummy_name_counter);
		g->dummy_name_counter++;
	}
	return name;
}

#define TO_C0String(s) C0String{(const char*)(s).data, (isize)(s).len}

static C0String make_anonymous_name(ffzGenC0* g) {
	return TO_C0String(fill_empty_name_with_id(g, {}));
}

static C0String make_name(ffzGenC0* g, ffzNodeInst inst, bool pretty = false) {
	Array<u8> name = make_array<u8>(g->alc);
	str_print(&name, ffz_get_parent_decl_name(inst.node));

	if (inst.poly_inst != 0) {
		if (pretty) {
			str_print(&name, F_LIT("["));

			ffzPolyInst* poly_inst = map64_get(&g->checker->poly_instantiations, inst.poly_inst);
			for (uint i = 0; i < poly_inst->parameters.len; i++) {
				if (i > 0) str_print(&name, F_LIT(", "));

				str_print(&name, ffz_constant_to_string(g->checker, poly_inst->parameters[i]));
			}

			str_print(&name, F_LIT("]"));
		}
		else {
			// we could improve this by having an incremental counter per poly inst, that way we could use
			// 128 bit hashes and still end up with short names
			str_printf(&name, "$%llx", inst.poly_inst);
		}
	}
	if (g->checker->_dbg_module_import_name.len > 0) {
		// We don't want to export symbols from imported modules.
		// Currently, we're giving these symbols unique ids and exporting them anyway, because
		// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!

		name.slice = STR_JOIN(g->alc, g->checker->_dbg_module_import_name, F_LIT("$$"), name.slice);
	}
	return TO_C0String(fill_empty_name_with_id(g, name.slice));
}

inline C0String make_name_pretty(ffzGenC0* g, ffzNodeInst inst) { return make_name(g, inst, true); }

static C0AggType* get_c0_type(ffzGenC0* g, ffzType* type) {
	ASSERT(ffz_type_is_grounded(type));
	//type = ffz_ground_type(type);
	if (C0AggType** existing = map64_get(&g->type_to_c0, (u64)type)) return *existing;

	C0AggType* result = NULL;
	switch (type->tag) {

	case ffzTypeTag_FixedArray: {
		i64 len = type->size / type->FixedArray.elem_type->size;
		result = c0_agg_type_array(g->c0, get_c0_type(g, type->FixedArray.elem_type), len);
	} break;

	case ffzTypeTag_Pointer: { result = c0_agg_type_basic(g->c0, C0Basic_ptr); } break;

	case ffzTypeTag_Proc: {
		C0Array(C0String) param_names = NULL;
		C0Array(C0AggType*) param_types = NULL;

		for (uint i = 0; i < type->Proc.in_params.len; i++) {
			ffzTypeProcParameter& param = type->Proc.in_params[i];

			c0array_push(param_names, TO_C0String(param.name->name));
			c0array_push(param_types, get_c0_type(g, param.type));
		}

		C0AggType* ret_type = type->Proc.out_param ? get_c0_type(g, type->Proc.out_param->type) : c0_agg_type_basic(g->c0, C0Basic_void);
		result = c0_agg_type_proc(g->c0, ret_type, param_names, param_types, 0);
	} break;

	case ffzTypeTag_Enum: case ffzTypeTag_Uint: case ffzTypeTag_SizedUint: {
		if (type->size == 1)      result = c0_agg_type_basic(g->c0, C0Basic_u8);
		else if (type->size == 2) result = c0_agg_type_basic(g->c0, C0Basic_u16);
		else if (type->size == 4) result = c0_agg_type_basic(g->c0, C0Basic_u32);
		else if (type->size == 8) result = c0_agg_type_basic(g->c0, C0Basic_u64);
		else BP;
	} break;

	case ffzTypeTag_Int: case ffzTypeTag_SizedInt: {
		if (type->size == 1)      result = c0_agg_type_basic(g->c0, C0Basic_i8);
		else if (type->size == 2) result = c0_agg_type_basic(g->c0, C0Basic_i16);
		else if (type->size == 4) result = c0_agg_type_basic(g->c0, C0Basic_i32);
		else if (type->size == 8) result = c0_agg_type_basic(g->c0, C0Basic_i64);
		else BP;
	} break;

	case ffzTypeTag_Bool: { result = c0_agg_type_basic(g->c0, C0Basic_u8); } break;

	//{
	//	// TODO: maybe FFZ should give us a type-info-struct for a string so this could use the same logic as user-struct
	//	//ffz_builtin_type_string
	//	//C0Array(C0String) names = NULL; C0Array(i64) aligns = NULL; C0Array(C0AggType*) types = NULL;
	//	//
	//	//c0array_push(names, C0STR("ptr"));
	//	//c0array_push(names, C0STR("len"));
	//	//c0array_push(types, c0_agg_type_basic(g->c0, C0Basic_ptr));
	//	//c0array_push(types, c0_agg_type_basic(g->c0, C0Basic_u64));
	//	//c0array_push(aligns, 8);
	//	//c0array_push(aligns, 8);
	//	//result = c0_agg_type_record(g->c0, 8, 16, C0STR("string"), names, aligns, types);
	//} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Record: {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) BP;

		C0Array(C0String) names = NULL;
		C0Array(i64) aligns = NULL;
		C0Array(C0AggType*) types = NULL;

		Slice<ffzTypeRecordField> fields = ffz_type_get_record_fields(g->checker, type);
		for (uint i = 0; i < fields.len; i++) {
			ffzTypeRecordField& field = fields[i];
			c0array_push(names, TO_C0String(field.name));
			c0array_push(aligns, field.type->alignment);
			c0array_push(types, get_c0_type(g, field.type));
		}

		C0String name = type->tag == ffzTypeTag_String ? C0STR("string") : make_name(g, IBASE(type->Record.node));

		result = c0_agg_type_record(g->c0,
			type->alignment,
			type->size,
			name,
			names, aligns, types);
	} break;

	default: BP;
	}
	ASSERT(result);
		
	map64_insert(&g->type_to_c0, (u64)type, result);
	return result;
}

static C0Proc* gen_procedure(ffzGenC0* g, ffzNodeOpInst inst) {
	C0String export_name = make_name(g, IBASE(inst));

	ffzType* proc_type = ffz_expr_get_type(g->checker, IBASE(inst));
	ASSERT(proc_type->tag == ffzTypeTag_Proc);

	C0Proc* _proc = c0_proc_create(g->c0, export_name, get_c0_type(g, proc_type));
	
	ffzNodeInst left = ICHILD(inst, left);
	if (left.node->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		gen_statement(g, ICHILD(IAS(left, ProcType), out_parameter));
	}

	C0Proc* c0_proc_before = g->c0_proc;
	g->c0_proc = _proc;

	ffzNodeProcTypeInst proc_type_inst = proc_type->Proc.type_node;
	
	{
		uint i = 0;
		for FFZ_EACH_CHILD_INST(n, proc_type_inst) {
			ASSERT(n.node->kind == ffzNodeKind_Declaration);
			ffzNodeIdentifierInst param_definition = ICHILD(IAS(n,Declaration),name);
			ffzNodeInstHash hash = ffz_hash_node_inst(IBASE(param_definition));
			
			map64_insert(&g->c0_instr_from_definition, hash, _proc->parameters[i]);
			i++;
		}
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_statement(g, n);
	}

	//gen_return(g, NULL, inst.node->base.end_pos); // Always return at the end of the procedure

	g->c0_proc = c0_proc_before;
	c0_proc_finish(_proc);

	array_push(&g->c0_procs, _proc);
	return _proc;
}

/*
static C0Constant gen_operator_const(ffzGen* g, ffzType* type, ffzNodeOpInst inst) {
	ffzNodeInst left = ICHILD(inst, left);
	ffzNodeInst right = ICHILD(inst, right);
	C0Constant out = {};

	ffzNodeKind kind = inst.node->kind;
	switch (kind) {

	case ffzNodeKind_PostCurlyBrackets: {
		ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
		ASSERT(left_chk.type->tag == ffzTypeTag_Type);
		ffzType* left_type = left_chk.const_val->type;

		u32 num_arguments = ffz_get_child_count(BASE(inst.node));
		if (left_type->tag == ffzTypeTag_Record) {
			BP;
		}
		else if (left_type->tag == ffzTypeTag_Slice) {
			BP;
		}
		else if (left_type->tag == ffzTypeTag_FixedArray) {
			BP;
		}
		else if (left_type->tag == ffzTypeTag_Proc) {
			out._proc = gen_procedure(g, inst);
		}
		else BP;
	} break;

	case ffzNodeKind_MemberAccess: {
		ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
		ASSERT(left_chk.type->tag == ffzTypeTag_Module);
		
		ffzChecker* checker_before = g->checker;
		g->checker = left_chk.const_val->module;

		String member_name = AS(right.node, Identifier)->name;
		ffzNodeDeclarationInst decl;
		ASSERT(ffz_find_top_level_declaration(g->checker, member_name, &decl));
		out = gen_expr_const(g, ICHILD(decl,rhs));

		g->checker = checker_before;
	} break;

	default: BP;
	}
	return out;
}
*/
/*static C0Constant gen_expr_const(ffzGen* g, ffzNodeInst inst) {
	if (C0Constant* existing = map64_get(&g->c0_constant_from_definition, ffz_hash_node_inst(inst))) {
		return *existing;
	}

	C0Constant out = {};
	inst = ffz_get_instantiated_expression(g->checker, inst);

	ffzCheckedExpr checked = ffz_expr_get_checked(g->checker, inst);
	ffzType* type = ffz_expr_get_type(g->checker, inst);
	if (type->tag == ffzTypeTag_Type) {
		// if this expression is a type, return the default value for this type.
		BP;
	}

	switch (inst.node->kind) {
	case ffzNodeKind_Identifier: {
		ffzNodeDeclarationInst parent_decl;
		if (ffz_get_decl_if_definition(IAS(inst,Identifier), &parent_decl)) {
			// this is the lhs of a declaration
			out = gen_expr_const(g, ICHILD(parent_decl, rhs));
		}
		else {
			BP;//ffzNodeIdentifierInst def = ffz_get_definition(g->checker, IAS(inst, Identifier));
			//out = gen_expr_const(g, IBASE(def));
		}
	} break;

	case ffzNodeKind_Operator: {
		out = gen_operator_const(g, type, IAS(inst, Operator));
		map64_insert(&g->c0_constant_from_definition, ffz_hash_node_inst(inst), out);
	} break;

	case ffzNodeKind_ProcType: {
		// extern proc
		String name = ffz_get_parent_decl_name(inst.node);
		out._proc = c0_extern_proc_create(g->c0, TO_C0String(name), get_c0_type(g, type));
	} break;

	default: BP;
	}

	return out;
}*/

static C0Instr* gen_call(ffzGenC0* g, ffzNodeOpInst inst) {
	ffzNodeInst left = ICHILD(inst,left);
	ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
	ASSERT(left_chk.const_val && left_chk.type->tag == ffzTypeTag_Proc); // TODO: c0 doesn't support dynamic dispatch yet
	
	C0Constant proc_c0 = gen_constant(g, left_chk.type, left_chk.const_val);
	
	C0Array(C0Instr*) args = NULL;
	for FFZ_EACH_CHILD_INST(n, inst) {
		c0array_push(args, gen_expr(g, n));
	}

	return c0_push_call_proc(g->c0_proc, proc_c0.proc, args);
}

static C0Instr* c0_push_if_not(C0Proc* p, C0Instr* cond) {
	C0Instr* not_cond = c0_push_notb(p, cond);
	return c0_push_if(p, not_cond);
}

static C0Instr* push_zero_value(ffzGenC0* g, ffzType* type) {
	switch (type->tag) {

	case ffzTypeTag_Int:
	case ffzTypeTag_SizedInt: {
		if (type->size == 1)      return c0_push_basic_i8(g->c0_proc, 0);
		else if (type->size == 2) return c0_push_basic_i16(g->c0_proc, 0);
		else if (type->size == 4) return c0_push_basic_i32(g->c0_proc, 0);
		else if (type->size == 8) return c0_push_basic_i64(g->c0_proc, 0);
		else BP;
	} break;

	case ffzTypeTag_Uint:
	case ffzTypeTag_SizedUint: {
		if (type->size == 1)      return c0_push_basic_u8(g->c0_proc, 0);
		else if (type->size == 2) return c0_push_basic_u16(g->c0_proc, 0);
		else if (type->size == 4) return c0_push_basic_u32(g->c0_proc, 0);
		else if (type->size == 8) return c0_push_basic_u64(g->c0_proc, 0);
		else BP;
	} break;
	}

	C0AggType* c0_type = get_c0_type(g, type);
	return c0_push_decl_agg(g->c0_proc, c0_type, make_anonymous_name(g));
}

static C0Instr* gen_comparison(ffzGenC0* g, ffzType* comp_type, C0Instr* left, C0Instr* right, bool addr) {
	// I suppose we should just emit memcmp
	C0AggType* comp_type_c0 = get_c0_type(g, comp_type);
	if (comp_type->tag == ffzTypeTag_Record) {
		if (!addr) {
			left = c0_push_addr_of(g->c0_proc, left);
			right = c0_push_addr_of(g->c0_proc, right);
		}
		C0Instr* result = c0_push_basic_u8(g->c0_proc, 1);
		for (u32 i = 0; i < comp_type->Record.fields.len; i++) {
			C0Instr* field_left = c0_push_field_ptr(g->c0_proc, comp_type_c0, left, i);
			C0Instr* field_right = c0_push_field_ptr(g->c0_proc, comp_type_c0, right, i);
			C0Instr* field_equals = gen_comparison(g, comp_type->Record.fields[i].type, field_left, field_right, true);
			
			result = c0_push_and(g->c0_proc, result, field_equals);
		}
		return result;
	}
	else if (comp_type->tag == ffzTypeTag_FixedArray) {
		if (!addr) {
			left = c0_push_addr_of(g->c0_proc, left);
			right = c0_push_addr_of(g->c0_proc, right);
		}
		C0Instr* result = c0_push_basic_u8(g->c0_proc, 1);
		ASSERT(comp_type->FixedArray.length >= 0);
		for (s32 i = 0; i < comp_type->FixedArray.length; i++) {
			C0Instr* idx = c0_push_basic_u32(g->c0_proc, i);
			C0Instr* elem_left = c0_push_index_ptr(g->c0_proc, comp_type_c0, left, idx);
			C0Instr* elem_right = c0_push_index_ptr(g->c0_proc, comp_type_c0, right, idx);
			C0Instr* elem_equals = gen_comparison(g, comp_type->FixedArray.elem_type, elem_left, elem_right, true);
			result = c0_push_and(g->c0_proc, result, elem_equals);
		}
		return result;
	}
	else {
		if (addr) {
			left = c0_push_load(g->c0_proc, comp_type_c0, left);
			right = c0_push_load(g->c0_proc, comp_type_c0, right);
		}
		return c0_push_eq(g->c0_proc, left, right);
	}
}

static C0Instr* gen_operator(ffzGenC0* g, ffzType* type, ffzNodeOpInst inst, bool address_of) {
	//HITS(_c, 4);
	ffzNodeInst left = ICHILD(inst,left);
	ffzNodeInst right = ICHILD(inst,right);
	C0Instr* out = NULL;
	
	ffzNodeKind kind = inst.node->op_kind;
	switch (kind) {

	case ffzNodeKind_MemberAccess: { // :CheckMemberAccess
		// :MemberAccess
		String member_name = AS(right.node, Identifier)->name;

		if (left.node->kind == ffzNodeKind_Identifier && AS(left.node, Identifier)->name == F_LIT("in")) {
			ASSERT(!address_of); // TODO
			BP;//for (u32 i = 0; i < g->curr_proc->proc_type->Proc.in_params.len; i++) {
			//	ffzTypeProcParameter& param = g->curr_proc->proc_type->Proc.in_params[i];
			//	if (param.name->name == member_name) {
			//		result = gmmc_val_param(g->curr_proc->gmmc_proc, param.type->size, i);
			//	}
			//}
		}
		else {
			ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
			
			if (left_chk.type->tag == ffzTypeTag_Module) { BP; } // not allowed
			else if (left_chk.type->tag == ffzTypeTag_Type && left_chk.const_val->type->tag == ffzTypeTag_Enum) {
				ASSERT(!address_of);
				// shouldn't this be part of the checker constant evaluation too?
				BP;//ffzType* enum_type = left_chk.const_val->type;
				//
				//C0AggType* type_c0 = get_c0_type(g, type);
				//ASSERT(type_c0->kind == C0AggType_basic && c0_basic_type_is_integer(type_c0->basic.type));
				//ffzMemberHash member_key = ffz_hash_member(left_chk.const_val->type, member_name);
				//
				//C0Instr* val = c0_instr_create(g->c0_proc, C0Instr_decl);
				//val->basic_type = type_c0->basic.type;
				//val->value_u64 = *map64_get(&left_chk.const_val->type->module->enum_value_from_name, member_key);
				//out = c0_instr_push(g->c0_proc, val);
			}
			else {
				ffzType* struct_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;
				C0AggType* struct_type_c0 = get_c0_type(g, struct_type);

				ffzTypeRecordFieldUse field;
				ASSERT(ffz_type_find_record_field_use(g->checker, struct_type, member_name, &field));
				ASSERT(field.parent == NULL);

				C0Instr* addr_of_struct = gen_expr(g, left, left_chk.type->tag != ffzTypeTag_Pointer);
				out = c0_push_field_ptr(g->c0_proc, struct_type_c0, addr_of_struct, field.local_index);
				if (!address_of) {
					out = c0_push_load(g->c0_proc, get_c0_type(g, field.type), out);
				}
			}
		}
	} break;

	case ffzNodeKind_PostSquareBrackets: { // Array subscript
		ffzType* left_type = ffz_expr_get_type(g->checker, left);
		ASSERT(left_type->tag == ffzTypeTag_FixedArray || left_type->tag == ffzTypeTag_Slice);

		ffzType* elem_type = left_type->tag == ffzTypeTag_Slice ? left_type->Slice.elem_type : left_type->FixedArray.elem_type;
		C0AggType* left_type_c0 = get_c0_type(g, left_type);

		C0Instr* left_value = gen_expr(g, left, true);
		C0Instr* array_data = left_value;
		if (left_type->tag == ffzTypeTag_Slice) {
			array_data = c0_push_load(g->c0_proc, c0_agg_type_basic(g->c0, C0Basic_ptr), array_data);
		}

		if (ffz_get_child_count(BASE(inst.node)) == 2) { // slicing
			ASSERT(!address_of);
			
			C0AggType* type_c0 = get_c0_type(g, type);
			ffzNodeInst lo_inst = ffz_get_child_inst(IBASE(inst), 0);
			ffzNodeInst hi_inst = ffz_get_child_inst(IBASE(inst), 1);
			
			C0Instr* lo = lo_inst.node->kind == ffzNodeKind_Blank ? c0_push_basic_u64(g->c0_proc, 0) : gen_expr(g, lo_inst);
			
			C0Instr* hi;
			if (hi_inst.node->kind == ffzNodeKind_Blank) {
				if (left_type->tag == ffzTypeTag_FixedArray) {
					hi = c0_push_basic_u64(g->c0_proc, left_type->FixedArray.length);
				}
				else {
					C0Instr* len_src = c0_push_field_ptr(g->c0_proc, type_c0, left_value, 1);
					hi = c0_push_load(g->c0_proc, c0_agg_type_basic(g->c0, C0Basic_u64), len_src);
				}
			}
			else {
				hi = gen_expr(g, hi_inst);
			}
			
			out = c0_push_decl_agg(g->c0_proc, type_c0, make_anonymous_name(g));
			C0Instr* addr_of_out = c0_push_addr_of(g->c0_proc, out);

			C0Instr* array_data_as_uint = c0_push_convert(g->c0_proc, C0Basic_u64, array_data);
			C0Instr* lo_as_uint = c0_push_convert(g->c0_proc, C0Basic_u64, lo);
			C0Instr* hi_as_uint = c0_push_convert(g->c0_proc, C0Basic_u64, hi);
			
			C0Instr* lo_offset = c0_push_mul(g->c0_proc, lo_as_uint, c0_push_basic_u64(g->c0_proc, elem_type->size));
			C0Instr* ptr_src = c0_push_add(g->c0_proc, array_data_as_uint, lo_offset);
			C0Instr* len_src = c0_push_sub(g->c0_proc, hi_as_uint, lo_as_uint);
			
			C0Instr* ptr_dst = c0_push_field_ptr(g->c0_proc, type_c0, addr_of_out, 0);
			C0Instr* len_dst = c0_push_field_ptr(g->c0_proc, type_c0, addr_of_out, 1);
			c0_push_store(g->c0_proc, ptr_dst, ptr_src);
			c0_push_store(g->c0_proc, len_dst, len_src);
		}
		else { // taking an index
			ffzNodeInst index_node = ffz_get_child_inst(IBASE(inst), 0);
			C0Instr* index = c0_push_convert(g->c0_proc, C0Basic_u64, gen_expr(g, index_node));

			if (left_type->tag == ffzTypeTag_Slice) {
				// push_index_ptr only works for fixed length arrays...
				C0Instr* array_data_as_uint = c0_push_convert(g->c0_proc, C0Basic_u64, array_data);
				C0Instr* index_offset = c0_push_mul(g->c0_proc, index, c0_push_basic_u64(g->c0_proc, elem_type->size));
				out = c0_push_convert(g->c0_proc, C0Basic_ptr, c0_push_add(g->c0_proc, array_data_as_uint, index_offset));
			}
			else {
				out = c0_push_index_ptr(g->c0_proc, left_type_c0, array_data, index);
			}
			
			if (!address_of) {
				out = c0_push_load(g->c0_proc, get_c0_type(g, type), out);
			}
		}
	} break;

	case ffzNodeKind_Add: case ffzNodeKind_Sub: case ffzNodeKind_Mul:
	case ffzNodeKind_Div: case ffzNodeKind_Modulo:
	case ffzNodeKind_Equal: case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
	case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater: case ffzNodeKind_GreaterOrEqual:
	{
		ASSERT(!address_of);

		C0Instr* left_val = gen_expr(g, left);
		C0Instr* right_val = gen_expr(g, right);
		switch (kind) {
		case ffzNodeKind_Add:            { out = c0_push_add(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_Sub:            { out = c0_push_sub(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_Mul:            { out = c0_push_mul(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_Div:            { out = c0_push_quo(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_Modulo:         { out = c0_push_rem(g->c0_proc, left_val, right_val); } break;
		
		case ffzNodeKind_Equal: {
			ffzType* comp_type = ffz_expr_get_type(g->checker, left);
			out = gen_comparison(g, comp_type, left_val, right_val, false);
		} break;
		case ffzNodeKind_NotEqual: {
			ffzType* comp_type = ffz_expr_get_type(g->checker, left);
			out = gen_comparison(g, comp_type, left_val, right_val, false);
			out = c0_push_notb(g->c0_proc, out);
		} break;
		
		case ffzNodeKind_Less:           { out = c0_push_lt(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_LessOrEqual:    { out = c0_push_lteq(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_Greater:        { out = c0_push_gt(g->c0_proc, left_val, right_val); } break;
		case ffzNodeKind_GreaterOrEqual: { out = c0_push_gteq(g->c0_proc, left_val, right_val); } break;
		}
	} break;

	case ffzNodeKind_LogicalAND: case ffzNodeKind_LogicalOR: {
		ASSERT(!address_of);

		out = c0_push_decl_basic(g->c0_proc, C0Basic_u8, make_anonymous_name(g));
		C0Instr* out_addr = c0_push_addr_of(g->c0_proc, out);
		C0Instr* left_val = gen_expr(g, left);
		
		// We need to implement short circuiting for the logical operations
		if (kind == ffzNodeKind_LogicalAND) {
			out->value_u64 = 0;

			c0_push_if(g->c0_proc, left_val);
			// set the result to the value of right. Otherwise it will be set to 0 automatically
			C0Instr* right_val = gen_expr(g, right);
			c0_push_store(g->c0_proc, out_addr, right_val);
			c0_pop_if(g->c0_proc);
		}
		else {
			out->value_u64 = 1;
			c0_push_if_not(g->c0_proc, left_val);

			// set the result to the value of right. Otherwise it will be set to 1 automatically
			C0Instr* right_val = gen_expr(g, right);
			c0_push_store(g->c0_proc, out_addr, right_val);
			c0_pop_if(g->c0_proc);
		}
	} break;

	case ffzNodeKind_AddressOf: {
		ASSERT(!address_of);
		out = gen_expr(g, right, true);
	} break;

	case ffzNodeKind_UnaryPlus: case ffzNodeKind_UnaryMemberAccess:
	case ffzNodeKind_PointerTo: {	
		BP;
	} break;

	case ffzNodeKind_UnaryMinus: {
		ASSERT(!address_of);
		C0Instr* zero = push_zero_value(g, type);
		out = c0_push_sub(g->c0_proc, zero, gen_expr(g, right));
	} break;

	case ffzNodeKind_LogicalNOT: {
		ASSERT(!address_of);
		out = c0_push_notb(g->c0_proc, gen_expr(g, right));
	} break;

	case ffzNodeKind_Dereference: {
		out = gen_expr(g, left);
		if (!address_of) {
			out = c0_push_load(g->c0_proc, get_c0_type(g, type), out);
		}
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		ASSERT(!address_of);
		if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(AS(left.node,Keyword)->keyword)) {
			ffzKeyword keyword = AS(left.node,Keyword)->keyword;
			
			ffzType* type = ffz_expr_get_type(g->checker, IBASE(inst));
			
			C0Instr* first = gen_expr(g, ffz_get_child_inst(IBASE(inst), 0));
			if (keyword == ffzKeyword_bit_not) {
				out = c0_push_noti(g->c0_proc, first);
			}
			else {
				C0Instr* second = gen_expr(g, ffz_get_child_inst(IBASE(inst), 1));
			
				switch (keyword) {
				case ffzKeyword_bit_and: { out = c0_push_and(g->c0_proc, first, second); } break;
				case ffzKeyword_bit_or: { out = c0_push_or(g->c0_proc, first, second); } break;
				case ffzKeyword_bit_xor: { out = c0_push_xor(g->c0_proc, first, second); } break;
				default: BP;
				}
			}
		}
		else if (left.node->kind == ffzNodeKind_Keyword && AS(left.node, Keyword)->kind == ffzKeyword_size_of) {
			BP; // this should be done in the checker's constant evaluation phase

			//ffzNodeInst arg = ffz_get_child_inst(IBASE(inst), 0);
			//ffzType* arg_type = ffz_expr_get_type(g->checker, arg)->type.t;
			//u64* size = mem_clone(u64(arg_type->size), g->allocator);
			//result = gmmc_val_constant(g->gmmc, 8, size);
		}
		else {
			ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
			if (left_chk.type->tag == ffzTypeTag_Type) {
				// type-cast, e.g. u32(5293900)

				C0AggType* type = get_c0_type(g, left_chk.const_val->type);
				ASSERT(type->kind == C0AggType_basic);

				C0Instr* val = gen_expr(g, ffz_get_child_inst(IBASE(inst), 0));
				out = c0_push_convert(g->c0_proc, type->basic.type, val);
			}
			else {
				out = gen_call(g, inst);
			}
		}
	} break;

	case ffzNodeKind_PostCurlyBrackets: {
		ASSERT(!address_of);

		ffzType* left_type = ffz_expr_get_type(g->checker, left);
		ASSERT(left_type->tag == ffzTypeTag_Type);

		C0AggType* type_c0 = get_c0_type(g, type);

		u32 num_arguments = ffz_get_child_count(BASE(inst.node));
		if (type->tag == ffzTypeTag_Record) {
			out = c0_push_decl_agg(g->c0_proc, type_c0, make_anonymous_name(g));
			C0Instr* addr_of = c0_push_addr_of(g->c0_proc, out);
			
			u32 i = 0;
			for FFZ_EACH_CHILD_INST(n, inst) {
				C0Instr* src = gen_expr(g, n);
				C0Instr* dst = c0_push_field_ptr(g->c0_proc, type_c0, addr_of, i);
				c0_push_store(g->c0_proc, dst, src);
				i++;
			}
		}
		else if (type->tag == ffzTypeTag_Slice) {
			BP;//ASSERT(left_is_a_type->size == 16);
			//// Slice literal
			//
			//Slice<gmmcValue*> elements = make_slice_garbage< gmmcValue*>(num_arguments, g->allocator);
			//uint i = 0;
			//for FFZ_EACH_CHILD_INST(n, inst) {
			//	elements[i] = gen_expression(g, n, GenExprDesc{ false, true });
			//	i++;
			//}
			//
			//gmmcValue* slice_data = gmmc_val_constant_composite(g->gmmc, elements.data, (u32)elements.len);
			//result = gen_constant_slice_literal(g, slice_data, (u32)elements.len);
		}
		else if (type->tag == ffzTypeTag_FixedArray) {
			out = c0_push_decl_agg(g->c0_proc, type_c0, make_anonymous_name(g));
			C0Instr* addr_of = c0_push_addr_of(g->c0_proc, out);
			
			uint i = 0;
			for FFZ_EACH_CHILD_INST(n, inst) {
				C0Instr* src = gen_expr(g, n, false);
				C0Instr* index = c0_push_basic_u64(g->c0_proc, i);
				C0Instr* index_ptr = c0_push_index_ptr(g->c0_proc, type_c0, addr_of, index);
				c0_push_store(g->c0_proc, index_ptr, src);
				i++;
			}
		}
		else if (type->tag == ffzTypeTag_Proc) {
			BP;
			//out = c0_push_addr_of_proc(g->c0)
			//out = gen_procedure(g, inst);
		}
		else BP;
	} break;

	default: BP;
	}
	ASSERT(out);
	return out;
}

static C0Constant gen_constant(ffzGenC0* g, ffzType* type, ffzConstant* const_val) {
	ffzConstantHash hash = ffz_hash_constant({ type, const_val });
	if (C0Constant* existing = map64_get(&g->c0_constant_from_constant, hash)) {
		return *existing;
	}

	C0Constant c = {};
	switch (type->tag) {
	case ffzTypeTag_Pointer: {
		if (const_val->ptr) {
			c.basic_ptr = gen_global(g, ffzCheckedExpr{ type->Pointer.pointer_to, const_val->ptr });
		}
	} break;

	case ffzTypeTag_Uint: case ffzTypeTag_SizedUint:
	case ffzTypeTag_Int: case ffzTypeTag_SizedInt:
	{
		ASSERT(type->size > 0 && type->size <= 8);
		c.basic_u64 = const_val->u64_;
	} break;

	case ffzTypeTag_Slice: {
		C0Constant* fields = (C0Constant*)c0_arena_alloc(&g->c0->arena, sizeof(C0Constant) * 2, ALIGN_OF(C0Constant));
		fields[0].basic_ptr = NULL;
		fields[1].basic_u64 = 0;
		c.record_fields = fields;
	} break;

	case ffzTypeTag_String: {
		String str = const_val->string_zero_terminated;

		C0AggType* array_type = c0_agg_type_array(g->c0, c0_agg_type_basic(g->c0, C0Basic_u8), str.len + 1);

		C0Constant data;
		data.array_elems = str.data;
		C0Global* array_global = c0_global_create_const(g->c0, make_anonymous_name(g), array_type, data);

		C0Constant* fields = (C0Constant*)c0_arena_alloc(&g->c0->arena, sizeof(C0Constant) * 2, ALIGN_OF(C0Constant));
		fields[0].basic_ptr = array_global;
		fields[1].basic_u64 = str.len;
		c.record_fields = fields;
	} break;

	case ffzTypeTag_FixedArray: {
		u32 ffz_elem_size = ffz_get_encoded_constant_size(type->FixedArray.elem_type);
		u32 c0_elem_size = MIN(ffz_elem_size, 8);
		c.array_elems = mem_alloc(type->FixedArray.length * c0_elem_size, 8, g->alc);

		for (uint i = 0; i < type->FixedArray.length; i++) {
			ffzConstant elem_ffz = {};
			memcpy(&elem_ffz, (u8*)const_val->fixed_array_elems + ffz_elem_size * i, ffz_elem_size);

			C0Constant elem_c0 = gen_constant(g, type->FixedArray.elem_type, &elem_ffz);
			memcpy((u8*)c.array_elems + c0_elem_size * i, &elem_c0, c0_elem_size);
		}
	} break;
		//case ffzTypeTag_Float: {} break;
	case ffzTypeTag_Proc: {
		BP;//if (const_val->proc_node.node) { // with extern procs the node is invalid
		//	c.proc = gen_procedure(g, const_val->proc_node);
		//}
	} break;

	case ffzTypeTag_Record: {
		ASSERT(const_val->record_fields.len == 0 || const_val->record_fields.len == type->Record.fields.len);
		ffzConstant empty_constant = {};

		c.record_fields = make_slice<C0Constant>(type->Record.fields.len, C0Constant{}, g->alc).data;
		for (uint i = 0; i < type->Record.fields.len; i++) {
			c.record_fields[i] = gen_constant(g, type->Record.fields[i].type,
				const_val->record_fields.len == 0 ? &empty_constant : &const_val->record_fields[i]);
		}
	} break;
		//case ffzTypeTag_Enum: {} break;

	default: BP;
	}
	map64_insert(&g->c0_constant_from_constant, hash, c);
	return c;
}

static C0Global* gen_global(ffzGenC0* g, ffzCheckedExpr expr) {
	C0AggType* type_c0 = get_c0_type(g, expr.type);
	ffzConstantHash hash = ffz_hash_constant(expr);
	if (C0Global** existing = map64_get(&g->c0_global_from_constant, hash)) {
		return *existing;
	}
	
	C0Constant constant = gen_constant(g, expr.type, expr.const_val);

	C0Global* out = c0_global_create_const(g->c0, make_anonymous_name(g), type_c0, constant);
	map64_insert(&g->c0_global_from_constant, hash, out);
	return out;
}

static C0Instr* gen_expr(ffzGenC0* g, ffzNodeInst inst, bool address_of) {
	C0Instr* out = NULL;
	//inst = ffz_get_instantiated_expression(g->checker, inst);
	
	ffzCheckedExpr checked = ffz_expr_get_checked(g->checker, inst);
	if (checked.const_val) {
		C0Global* global = gen_global(g, checked);
		
		out = c0_push_addr_of_global(g->c0_proc, global);
		if (!address_of) {
			out = c0_push_load(g->c0_proc, get_c0_type(g, checked.type), out);
		}
		return out;
	}
	
	ffzType* type = checked.type;
	ASSERT(ffz_type_is_grounded(type));

	switch (inst.node->kind) {
	case ffzNodeKind_Identifier: {
		// runtime variable and its definition should always have the same poly instance. This won't be true if we add globals though.
		ffzNodeIdentifierInst def = { ffz_get_definition(g->project, AS(inst.node,Identifier)), inst.poly_inst };
		if (ffz_definition_is_constant(def.node)) BP;
		
		C0Instr** instr = map64_get(&g->c0_instr_from_definition, ffz_hash_node_inst(IBASE(def)));
		ASSERT(instr);
		out = address_of ? c0_push_addr_of(g->c0_proc, *instr) : *instr;
	} break;

	case ffzNodeKind_Keyword: {
		// TODO: I think this should also be part of the checker constant evaluation.
		BP;
		//if (AS(inst.node,Keyword)->kind == ffzKeyword_true)  return c0_push_basic_u8(g->c0_proc, 1);
		//if (AS(inst.node,Keyword)->kind == ffzKeyword_false) return c0_push_basic_u8(g->c0_proc, 0);
	} break;

	case ffzNodeKind_Dot: {
		ffzNodeInst assignee;
		ASSERT(ffz_dot_get_assignee(IAS(inst,Dot), &assignee));
		out = gen_expr(g, assignee, false); // expand the dot to the same expression as the assignee
	} break;

	case ffzNodeKind_Operator: {
		out = gen_operator(g, type, IAS(inst,Operator), address_of);
	} break;

	default: BP;
	}
	return out;
}

static void gen_statement(ffzGenC0* g, ffzNodeInst inst) {
	if (g->c0_proc && inst.node->kind != ffzNodeKind_Scope) {
		c0_push_comment(g->c0_proc, C0String{});

		ffzParser* parser = g->project->parsers_dependency_sorted[inst.node->parser_idx];
		u32 start = inst.node->loc.start.offset;
		u32 end = inst.node->loc.end.offset;
		C0String comment = { (const char*)parser->source_code.data + start, end - start };
		c0_push_comment(g->c0_proc, comment);
	}

	switch (inst.node->kind) {

	case ffzNodeKind_Declaration: {
		ffzNodeDeclarationInst decl = IAS(inst, Declaration);
		ffzNodeIdentifierInst definition = ICHILD(decl, name);
		
		ffzType* type = ffz_decl_get_type(g->checker, decl);
		if (ffz_definition_is_constant(definition.node)) {
			// need to generate exported procs
			if (type->tag == ffzTypeTag_Proc) {
				//gen_expr_const(g, );
				gen_global(g, ffz_expr_get_checked(g->checker, ICHILD(decl, rhs)));
			}
		}
		else {
			C0Instr* rhs_value = gen_expr(g, ICHILD(decl,rhs));
			rhs_value->name = TO_C0String(definition.node->name);
			map64_insert(&g->c0_instr_from_definition, ffz_hash_node_inst(IBASE(definition)), rhs_value);
		}
	} break;

	case ffzNodeKind_Assignment: {
		ffzNodeAssignmentInst assign = IAS(inst, Assignment);
		
		// Generate store
		ffzNodeInst lhs = ICHILD(assign,lhs);
		ffzType* type = ffz_expr_get_type(g->checker, ffz_get_instantiated_expression(g->checker, lhs));
		
		C0Instr* rhs_value = gen_expr(g, ICHILD(assign,rhs));
		C0Instr* address_of_lhs = gen_expr(g, lhs, true);
		c0_push_store(g->c0_proc, address_of_lhs, rhs_value);
		int __ = 50;
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		ffzNodeIfInst if_stmt = IAS(inst, If);
		C0Instr* cond = gen_expr(g, ICHILD(if_stmt,condition));
		
		C0Instr* if_block = c0_push_if(g->c0_proc, cond);
		gen_statement(g, ICHILD(if_stmt,true_scope));
		c0_pop_if(g->c0_proc);
		
		if (if_stmt.node->else_scope) {
			c0_block_else_block(g->c0_proc, if_block);
			gen_statement(g, ICHILD(if_stmt,else_scope));
			c0_pop_nested_block(g->c0_proc);
		}
	} break;

	case ffzNodeKind_For: {
		ffzNodeForInst for_loop = IAS(inst,For);

		ffzNodeInst pre = ICHILD(for_loop,header_stmts[0]);
		ffzNodeInst condition = ICHILD(for_loop,header_stmts[1]);
		ffzNodeInst post = ICHILD(for_loop,header_stmts[2]);
		ffzNodeInst body = ICHILD(for_loop,scope);

		ffzType* second_stmt_type = ffz_expr_get_type(g->checker, condition);
		ASSERT(second_stmt_type->tag == ffzTypeTag_Bool);

		// We need a block to get the correct scope for the pre-statement declaration.
		C0Instr* block = c0_instr_create(g->c0_proc, C0Instr_block);
		c0_instr_push(g->c0_proc, block);
		c0_push_nested_block(g->c0_proc, block);
		
		if (pre.node) gen_statement(g, pre);
		
		c0_push_loop(g->c0_proc);
		C0Instr* cond = gen_expr(g, condition);
		{
			c0_push_if_not(g->c0_proc, cond);
			c0_push_break(g->c0_proc);
			c0_pop_if(g->c0_proc);
		}

		gen_statement(g, body);

		if (post.node) gen_statement(g, post);
		c0_pop_loop(g->c0_proc);
		
		c0_pop_nested_block(g->c0_proc);
	} break;

	case ffzNodeKind_Keyword: {
		c0_push_trap(g->c0_proc);
	} break;

	case ffzNodeKind_Return: {
		ffzNodeReturnInst ret = IAS(inst,Return);
		C0Instr* val = NULL;
		if (ret.node->value) {
			val = gen_expr(g, ICHILD(ret,value));
		}
		c0_push_return(g->c0_proc, val);

	} break;

	case ffzNodeKind_Operator: {
		ASSERT(AS(inst.node, Operator)->kind == ffzNodeKind_PostRoundBrackets);
		gen_call(g, IAS(inst,Operator));
		//if (AS(inst.node, Operator)->kind == ffzNodeKind_PostRoundBrackets) {
		//	gen_call(g, IAS(inst, Operator));
		//}
	} break;

	default: BP;
	}
}

void ffz_c0_generate(ffzProject* project, const char* generated_c_file) {
	Allocator* temp = temp_push(); defer(temp_pop());
	c0_platform_virtual_memory_init();
	
	C0Gen c0 = {};
	c0_gen_init(&c0);

	ffzGenC0 g = {};
	g.c0 = &c0;
	g.project = project;
	g.alc = temp;
	g.c0_procs = make_array<C0Proc*>(g.alc);
	g.type_to_c0 = make_map64<C0AggType*>(g.alc);
	g.c0_instr_from_definition = make_map64<C0Instr*>(g.alc);
	g.c0_constant_from_constant = make_map64<C0Constant>(g.alc);
	g.c0_global_from_constant = make_map64<C0Global*>(g.alc);

	FILE* file = fopen(generated_c_file, "wb");
	C0Print print_info = { print_c0, file };

	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		g.checker = project->checkers[parser->checker_idx];


		//ProjectFile pair = project->project_files_dependency_sorted[i];
		//g->curr_parser = project->parsers_dependency_sorted[i];

		//g->source_code_file_index = i;
		for FFZ_EACH_CHILD(n, parser->root) {
			gen_statement(&g, ffzNodeInst{ n, 0 });
		}
	}

	//C0Proc* factorial = test_factorial(&g);
	c0_gen_instructions_print(&c0, &print_info);

	for (uint i = 0; i < g.c0_procs.len; i++) {
		c0_print_proc(&print_info, g.c0_procs[i]);
	}
	
	c0_gen_destroy(&c0);
	fclose(file);
}

#endif