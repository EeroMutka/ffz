#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"
#include "ffz_lib.h"

#include "ffz_backend_tb.h"

#pragma warning(disable:4200)
#include "Cuik/tb/include/tb.h"

// hack, to get TB to compile
extern "C" uint64_t cuik_time_in_nanos(void) { return 0; }
extern "C" void cuikperf_region_start(uint64_t now, const char* fmt, const char* extra) {}
extern "C" void cuikperf_region_end(void) {}

union Constant {
	TB_Symbol* symbol;
};

/*struct Local {
	TB_Reg reg;
	bool is_big_parameter;
};*/

struct Gen {
	ffzProject* project;
	Allocator* alc;
	ffzChecker* checker;

	TB_Module* tb;
	TB_Function* tb_func;
	TB_Reg func_big_return;

	uint dummy_name_counter;
	
	Map64<TB_Function*> func_from_hash;
	Map64<TB_Reg> tb_local_addr_from_definition;
	Array<TB_FileID> tb_file_from_parser_idx;
};

// Helper macros for ffz

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

#define IAS(node, kind) FFZ_INST_AS(node, kind)
#define IBASE(node) FFZ_INST_BASE(node) 
#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).poly_inst }

// holds either a value, or a pointer to the value if the size of the type > 8 bytes
struct SmallOrPtr {
	TB_Reg small;
	TB_Reg ptr; // This is a read-only pointer; the caller must make a local copy of the value if they need it.
};

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc = true);
static SmallOrPtr gen_expr(Gen* g, ffzNodeInst inst, bool address_of = false);

static const char* make_name(Gen* g, ffzNodeInst inst = {}, bool pretty = false) {
	Array<u8> name = make_array<u8>(g->alc);

	if (inst.node) {
		str_print(&name, ffz_get_parent_decl_name(inst.node));
	}

	if (inst.poly_inst != 0) {
		if (pretty) {
			str_print(&name, LIT("["));

			ffzPolyInst* poly_inst = map64_get(&g->checker->poly_instantiations, inst.poly_inst);
			for (uint i = 0; i < poly_inst->parameters.len; i++) {
				if (i > 0) str_print(&name, LIT(", "));

				str_print(&name, ffz_constant_to_string(g->checker, poly_inst->parameters[i]));
			}

			str_print(&name, LIT("]"));
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

		BP;// name.slice = STR_JOIN(g->alc, g->checker->_dbg_module_import_name, LIT("$$"), name.slice);
	}
	
	if (name.len == 0) {
		str_printf(&name, "_ffz_%llu", g->dummy_name_counter);
		g->dummy_name_counter++;
	}

	str_print(&name, LIT("\0"));
	return (const char*)name.data;
}

struct TypeWithDebug {
	TB_DataType dt;
	TB_DebugType* dbg_type;
};


TB_DataType get_tb_basic_type(Gen* g, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Bool: return TB_TYPE_BOOL;
	case ffzTypeTag_Pointer: return TB_TYPE_PTR;

	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: {
		if (type->size == 1) return TB_TYPE_I8;
		else if (type->size == 2) return TB_TYPE_I16;
		else if (type->size == 4) return TB_TYPE_I32;
		else if (type->size == 8) return TB_TYPE_I64;
		else BP;
	} break;

	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: {
		if (type->size == 1) return TB_TYPE_I8;
		else if (type->size == 2) return TB_TYPE_I16;
		else if (type->size == 4) return TB_TYPE_I32;
		else if (type->size == 8) return TB_TYPE_I64;
		else BP;
	} break;

	case ffzTypeTag_Record: {
		ASSERT(type->size <= 8);
		return TB_TYPE_I64; // maybe we should get the smallest type that the struct fits in instead
	} break;
		//case ffzTypeTag_Enum: {} break;
		//case ffzTypeTag_FixedArray: {} break;
	}
	BP;
	return {};
}

//TB_DataType get_tb_basic_type_or_ptr(Gen* g, ffzType* type) {
//	if (type->size > 8) return TB_TYPE_PTR; // return pointer if the size is > 8
//	return get_tb_basic_type(g, type);
//}

TB_DebugType* get_tb_debug_type(Gen* g, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Bool: return tb_debug_get_bool(g->tb);

	case ffzTypeTag_Pointer: return tb_debug_create_ptr(g->tb, get_tb_debug_type(g, type->Pointer.pointer_to));

	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: return tb_debug_get_integer(g->tb, true, type->size * 8);

	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: return tb_debug_get_integer(g->tb, false, type->size * 8);
		//case ffzTypeTag_Float: {} break;
		//case ffzTypeTag_Proc: {} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Record: {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) BP;

		Slice<ffzTypeRecordField> fields = ffz_type_get_record_fields(g->checker, type);
		Array<TB_DebugType*> tb_fields = make_array<TB_DebugType*>(g->alc);

		for (uint i = 0; i < fields.len; i++) {
			ffzTypeRecordField& field = fields[i];
			TB_DebugType* t = tb_debug_create_field(g->tb, get_tb_debug_type(g, field.type), str_to_cstring(field.name, g->alc), field.offset);
			array_push(&tb_fields, t);
		}

		const char* name = type->tag == ffzTypeTag_String ? "string" : make_name(g, IBASE(type->Record.node));
		TB_DebugType* out = tb_debug_create_struct(g->tb, name);
		tb_debug_complete_record(out, tb_fields.data, tb_fields.len, type->size, type->alignment);
		return out;
	} break;

		//case ffzTypeTag_Enum: {} break;
		//case ffzTypeTag_FixedArray: {} break;
	default: BP;
	}
	return NULL;
}

// should we separate this into DebugType and DataType?
//TypeWithDebug type_to_tb(Gen* g, ffzType* type) {
//	TypeWithDebug out = {};
//	
//
//	return out;
//}

//TB_DataType get_proc_return_type(Gen* g, ffzType* proc_type) {
//	return proc_type->Proc.out_param ? get_tb_basic_type(g, proc_type->Proc.out_param->type) : TB_TYPE_VOID;
//}

#define FIX_TB_BIG_RETURN_HACK 1

static TB_Function* gen_procedure(Gen* g, ffzNodeOperatorInst inst) {
	auto insertion = map64_insert(&g->func_from_hash, ffz_hash_node_inst(IBASE(inst)), (TB_Function*)0, MapInsert_DoNotOverride);
	if (!insertion.added) return *insertion._unstable_ptr;

	ffzType* proc_type = ffz_expr_get_type(g->checker, IBASE(inst));
	ASSERT(proc_type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = proc_type->Proc.out_param ? proc_type->Proc.out_param->type : NULL;
	
	bool big_return = ret_type && ret_type->size > 8;
	TB_DataType ret_type_tb = big_return ? TB_TYPE_PTR :
		ret_type ? get_tb_basic_type(g, ret_type) : TB_TYPE_VOID;

	// TODO: deduplicate prototypes?
	TB_FunctionPrototype* proto = tb_prototype_create(g->tb, TB_CDECL, ret_type_tb, NULL, (int)proc_type->Proc.in_params.len + (int)big_return, false); // TODO: debug type?
	
	if (big_return) {
		// if big return, pass the pointer to the return value as the first argument the same way C does. :BigReturn
		tb_prototype_add_param(proto, TB_TYPE_PTR);
	}

	for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];
		
		TB_DebugType* param_debug_type = get_tb_debug_type(g, param->type);
		TB_DataType param_type = param->type->size > 8 ? TB_TYPE_PTR : get_tb_basic_type(g, param->type);
		
		if (param->type->size > 8) {
			param_debug_type = tb_debug_create_ptr(g->tb, param_debug_type); // TB doesn't allow parameters > 8 bytes
		}
		
		tb_prototype_add_param_named(proto, param_type, str_to_cstring(param->name->name, g->alc), param_debug_type);
	}

	const char* name = make_name(g, IBASE(inst));
	TB_Function* func = tb_function_create(g->tb, name, TB_LINKAGE_PUBLIC);
	tb_function_set_prototype(func, proto);
	*insertion._unstable_ptr = func;

	// Set function start location
	tb_inst_loc(func, g->tb_file_from_parser_idx[inst.node->parser_idx], inst.node->loc.start.line_num);
	
	ffzNodeInst left = ICHILD(inst,left);
	if (left.node->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		BP;//gen_statement(g, ICHILD(IAS(left, ProcType), out_parameter));
	}

	TB_Function* func_before = g->tb_func;
	TB_Reg func_big_return_before = g->func_big_return;
	g->tb_func = func;
	
	g->func_big_return = TB_NULL_REG;
	if (big_return) {
#if FIX_TB_BIG_RETURN_HACK
		g->func_big_return = tb_inst_local(func, 8, 8);
		tb_inst_store(func, TB_TYPE_PTR, g->func_big_return, tb_inst_param(func, 0), 8);
#else
		g->func_big_return = tb_inst_param(func, 0);
#endif
	}

	ffzNodeProcTypeInst proc_type_inst = proc_type->Proc.type_node;

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, proc_type_inst) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];

		ASSERT(n.node->kind == ffzNodeKind_Declaration);
		ffzNodeIdentifierInst param_definition = ICHILD(IAS(n, Declaration), name);
		ffzNodeInstHash hash = ffz_hash_node_inst(IBASE(param_definition));
		
		TB_Reg param_addr = tb_inst_param_addr(func, i + (u32)big_return); // TB parameter inspection doesn't work if we never call this

		// if it's a big parameter, then let's dereference the pointer pointer
		if (param->type->size > 8) {
			param_addr = tb_inst_param(func, i + (u32)big_return); // NOTE: this works with the new TB X64 backend, but has a bug with the old backend.
			//param_addr = tb_inst_load(g->tb_func, TB_TYPE_PTR, param_addr, 8); // so let's use this to make sure it works.
		}
		map64_insert(&g->tb_local_addr_from_definition, hash, param_addr);
		i++;
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_statement(g, n);
	}
	
	if (!proc_type->Proc.out_param) { // automatically generate a return statement if the proc doesn't return a value
		tb_inst_loc(func, g->tb_file_from_parser_idx[inst.node->parser_idx], inst.node->loc.end.line_num);
		tb_inst_ret(func, TB_NULL_REG);
	}

	g->tb_func = func_before;
	g->func_big_return = func_big_return_before;

	printf("\n");
	tb_function_print(func, tb_default_print_callback, stdout, false);
	printf("\n");

	bool ok = tb_module_compile_function(g->tb, func, TB_ISEL_FAST);
	ASSERT(ok);

	return func;
}
/*
static Constant gen_constant(Gen* g, ffzCheckedExpr constant) {
	ffzConstantHash hash = ffz_hash_constant(constant);
	if (Constant* existing = map64_get(&g->constant_from_hash, hash)) {
		return *existing;
	}
}*/


static SmallOrPtr gen_call(Gen* g, ffzNodeOperatorInst inst) {
	ffzNodeInst left = ICHILD(inst, left);
	ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
	ASSERT(left_chk.type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = left_chk.type->Proc.out_param ? left_chk.type->Proc.out_param->type : NULL;
	bool big_return = ret_type && ret_type->size > 8; // :BigReturn
	
	TB_DataType ret_type_tb = big_return ? TB_TYPE_PTR :
		ret_type ? get_tb_basic_type(g, ret_type) : TB_TYPE_VOID;

	Array<TB_Reg> args = make_array<TB_Reg>(g->alc);

	if (big_return) {
		// allocate a local for the return value. TODO: right now this local kind of goes to waste!
		TB_Reg return_val_addr = tb_inst_local(g->tb_func, ret_type->size, ret_type->alignment);
		array_push(&args, return_val_addr);
	}

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, inst) {
		ffzType* param_type = left_chk.type->Proc.in_params[i].type;
		SmallOrPtr arg = gen_expr(g, n);
		
		if (param_type->size > 8) {
			// make a copy on the stack for the parameter
			TB_Reg local_copy_addr = tb_inst_local(g->tb_func, param_type->size, param_type->alignment);
			tb_inst_memcpy(g->tb_func, local_copy_addr, arg.ptr, tb_inst_uint(g->tb_func, TB_TYPE_I32, param_type->size), param_type->alignment);
			array_push(&args, local_copy_addr);
		}
		else {
			ASSERT(arg.small != TB_NULL_REG);
			array_push(&args, arg.small);
		}
		i++;
	}

	// TODO: non-vcall for constant procedures

	TB_Reg target = gen_expr(g, left, false).small;
	ASSERT(target != TB_NULL_REG);

	TB_Reg return_val = tb_inst_vcall(g->tb_func, ret_type_tb, target, args.len, args.data);
	
	SmallOrPtr out = {};
	if (big_return) out.ptr = return_val; else out.small = return_val;
	return out;
}


static void gen_initializer_constant(Gen* g, void* dst, ffzType* type, ffzConstant* constant) {
	switch (type->tag) {
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: {
		memcpy(dst, constant, type->size);
	} break;
	case ffzTypeTag_Record: {
		memset(dst, 0, type->size);
		for (uint i = 0; i < type->Record.fields.len; i++) {
			ffzTypeRecordField* field = &type->Record.fields[i];
			gen_initializer_constant(g, (u8*)dst + field->offset, field->type, &constant->record_fields[i]);
		}
	} break;
	default: BP;
	}
}

static SmallOrPtr gen_expr(Gen* g, ffzNodeInst inst, bool address_of) {
	SmallOrPtr out = {};

	ffzCheckedExpr checked = ffz_expr_get_checked(g->checker, inst);
	if (checked.const_val) {
		switch (checked.type->tag) {
		case ffzTypeTag_Bool: {
			out.small = tb_inst_bool(g->tb_func, checked.const_val->bool_);
		} break;
		case ffzTypeTag_SizedInt: // fallthrough
		case ffzTypeTag_Int: {
			if (checked.type->size == 1)      out.small = tb_inst_sint(g->tb_func, TB_TYPE_I8,  checked.const_val->u8_);
			else if (checked.type->size == 2) out.small = tb_inst_sint(g->tb_func, TB_TYPE_I16, checked.const_val->u16_);
			else if (checked.type->size == 4) out.small = tb_inst_sint(g->tb_func, TB_TYPE_I32, checked.const_val->u32_);
			else if (checked.type->size == 8) out.small = tb_inst_sint(g->tb_func, TB_TYPE_I64, checked.const_val->u64_);
			else BP;
		} break;

		case ffzTypeTag_SizedUint: // fallthrough
		case ffzTypeTag_Uint: {
			if (checked.type->size == 1)      out.small = tb_inst_uint(g->tb_func, TB_TYPE_I8,  checked.const_val->u8_);
			else if (checked.type->size == 2) out.small = tb_inst_uint(g->tb_func, TB_TYPE_I16, checked.const_val->u16_);
			else if (checked.type->size == 4) out.small = tb_inst_uint(g->tb_func, TB_TYPE_I32, checked.const_val->u32_);
			else if (checked.type->size == 8) out.small = tb_inst_uint(g->tb_func, TB_TYPE_I64, checked.const_val->u64_);
			else BP;
		} break;
		//case ffzTypeTag_Int: { BP; } break;
		case ffzTypeTag_Proc: {
			if (checked.const_val->proc_node.node->kind == ffzNodeKind_ProcType) { // @extern proc
				const char* name = make_name(g, checked.const_val->proc_node);
				TB_External* external = tb_extern_create(g->tb, name, TB_EXTERNAL_SO_EXPORT);
				out.small = tb_inst_get_symbol_address(g->tb_func, (TB_Symbol*)external);
			}
			else {
				TB_Function* func = gen_procedure(g, IAS(checked.const_val->proc_node,Operator));
				out.small = tb_inst_get_symbol_address(g->tb_func, (TB_Symbol*)func);
			}
		} break;

		case ffzTypeTag_Record: {
			TB_Initializer* init = tb_initializer_create(g->tb, checked.type->size, checked.type->alignment, 1);
			
			void* mem = tb_initializer_add_region(g->tb, init, 0, checked.type->size);
			gen_initializer_constant(g, mem, checked.type, checked.const_val);
			
			TB_Global* global = tb_global_create(g->tb, make_name(g), TB_STORAGE_DATA, NULL, TB_LINKAGE_PRIVATE);
			tb_global_set_initializer(g->tb, global, init);
			
			TB_Reg global_addr = tb_inst_get_symbol_address(g->tb_func, (TB_Symbol*)global);
			if (checked.type->size > 8) {
				out.ptr = global_addr;
			}
			else BP;

		} break;

		default: BP;
		}

		return out;
	}

	bool should_dereference = false;

	switch (inst.node->kind) {
	case ffzNodeKind_Identifier: {
		// runtime variable and its definition should always have the same poly instance. This won't be true if we add globals though.
		ffzNodeIdentifierInst def = { ffz_get_definition(g->project, AS(inst.node,Identifier)), inst.poly_inst };
		if (ffz_definition_is_constant(def.node)) BP;

		ffzNodeInstHash hash = ffz_hash_node_inst(IBASE(def));
		out.small = *map64_get(&g->tb_local_addr_from_definition, hash);

		//TypeWithDebug type_tb = type_to_tb(g, checked.type);
		should_dereference = !address_of;
		//checked.type
	} break;
	case ffzNodeKind_Operator: {
		ffzNodeOperatorInst derived = IAS(inst,Operator);
		ffzNodeInst left = ICHILD(derived,left);
		ffzNodeInst right = ICHILD(derived,right);

		switch (derived.node->op_kind) {

		case ffzOperatorKind_Add: case ffzOperatorKind_Sub:
		case ffzOperatorKind_Mul: case ffzOperatorKind_Div:
		case ffzOperatorKind_Modulo: case ffzOperatorKind_Equal:
		case ffzOperatorKind_NotEqual: case ffzOperatorKind_Less:
		case ffzOperatorKind_LessOrEqual: case ffzOperatorKind_Greater:
		case ffzOperatorKind_GreaterOrEqual:
		{
			ASSERT(!address_of);
			TB_Reg a = gen_expr(g, left).small;
			TB_Reg b = gen_expr(g, right).small;
			
			bool is_signed = ffz_type_is_signed_integer(checked.type->tag);

			switch (derived.node->op_kind) {
			case ffzOperatorKind_Add: { out.small = tb_inst_add(g->tb_func, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzOperatorKind_Sub: { out.small = tb_inst_sub(g->tb_func, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzOperatorKind_Mul: { out.small = tb_inst_mul(g->tb_func, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzOperatorKind_Div: { out.small = tb_inst_div(g->tb_func, a, b, is_signed); } break;
			case ffzOperatorKind_Modulo: { out.small = tb_inst_mod(g->tb_func, a, b, is_signed); } break;

			case ffzOperatorKind_Equal: { out.small = tb_inst_cmp_eq(g->tb_func, a, b); } break;
			case ffzOperatorKind_NotEqual: { out.small = tb_inst_cmp_ne(g->tb_func, a, b); } break;
			case ffzOperatorKind_Less: { out.small = tb_inst_cmp_ilt(g->tb_func, a, b, is_signed); } break;
			case ffzOperatorKind_LessOrEqual: { out.small = tb_inst_cmp_ile(g->tb_func, a, b, is_signed); } break;
			case ffzOperatorKind_Greater: { out.small = tb_inst_cmp_igt(g->tb_func, a, b, is_signed); } break;
			case ffzOperatorKind_GreaterOrEqual: { out.small = tb_inst_cmp_ige(g->tb_func, a, b, is_signed); } break;

			default: BP;
			}
		} break;
		case ffzOperatorKind_PostRoundBrackets: {
			ASSERT(!address_of);

			if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(AS(left.node, Keyword)->keyword)) { BP; }
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->checker, left);
				if (left_chk.type->tag == ffzTypeTag_Type) {
					// type-cast, e.g. u32(5293900)
					BP;
					//C0AggType* type = get_c0_type(g, left_chk.const_val->type);
					//ASSERT(type->kind == C0AggType_basic);
					//
					//C0Instr* val = gen_expr(g, ffz_get_child_inst(IBASE(inst), 0));
					//out = c0_push_convert(g->c0_proc, type->basic.type, val);
				}
				else {
					out = gen_call(g, derived);
				}
			}
		} break;
		
		case ffzOperatorKind_AddressOf: {
			ASSERT(!address_of);
			out = gen_expr(g, right, true);
		} break;

		case ffzOperatorKind_Dereference: {
			if (address_of) {
				out = gen_expr(g, left);
			}
			else {
				out = gen_expr(g, left, true);
				should_dereference = true;
			}
		} break;

		case ffzOperatorKind_MemberAccess: {
			String member_name = AS(right.node, Identifier)->name;

			if (left.node->kind == ffzNodeKind_Identifier && AS(left.node, Identifier)->name == LIT("in")) {
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
				
				ffzType* struct_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;
				//C0AggType* struct_type_c0 = get_c0_type(g, struct_type);

				ffzTypeRecordFieldUse field;
				ASSERT(ffz_type_find_record_field_use(g->checker, struct_type, member_name, &field));
				ASSERT(field.parent == NULL);

				TB_Reg addr_of_struct = gen_expr(g, left, left_chk.type->tag != ffzTypeTag_Pointer).small;
				ASSERT(addr_of_struct != TB_NULL_REG);
				
				out.small = tb_inst_member_access(g->tb_func, addr_of_struct, field.offset_from_root);
				should_dereference = !address_of;
			}
		} break;

			default: BP;
		}

	} break;

	case ffzNodeKind_Dot: {
		ffzNodeInst assignee;
		ASSERT(ffz_dot_get_assignee(IAS(inst, Dot), &assignee));
		out = gen_expr(g, assignee, address_of); 
	} break;

	default: BP;
	}
	
	if (should_dereference) {
		if (checked.type->size > 8) {
			// We're not making a local copy here
			out.ptr = out.small;
			out.small = {};
		}
		else {
			out.small = tb_inst_load(g->tb_func, get_tb_basic_type(g, checked.type), out.small, checked.type->alignment);
		}
	}
	
	ASSERT(out.small || out.ptr);
	return out;
}

static void inst_loc(Gen* g, ffzNode* node, u32 line_num) {
	tb_inst_loc(g->tb_func, g->tb_file_from_parser_idx[node->parser_idx], line_num);
}

static void gen_store(Gen* g, TB_Reg lhs_address, ffzNodeInst rhs) {
	SmallOrPtr rhs_value = gen_expr(g, rhs);
	ffzType* type = ffz_expr_get_type(g->checker, rhs);

	if (type->size > 8) {
		tb_inst_memcpy(g->tb_func, lhs_address, rhs_value.ptr, tb_inst_uint(g->tb_func, TB_TYPE_I64, type->size), type->alignment);
	}
	else {
		tb_inst_store(g->tb_func, get_tb_basic_type(g, type), lhs_address, rhs_value.small, type->alignment);
	}
}

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc) {
	if (set_loc) {
		if (inst.node->kind == ffzNodeKind_Declaration && ffz_decl_is_constant(AS(inst.node, Declaration))) {}
		else {
			inst_loc(g, inst.node, inst.node->loc.start.line_num);
		}
	}

	switch (inst.node->kind) {
		
	case ffzNodeKind_Declaration: {
		ffzNodeDeclarationInst decl = IAS(inst, Declaration);
		ffzNodeIdentifierInst definition = ICHILD(decl, name);
		
		ffzType* type = ffz_decl_get_type(g->checker, decl);
		if (ffz_definition_is_constant(definition.node)) {
			// need to generate exported procs
			if (type->tag == ffzTypeTag_Proc) {
				ffzNodeInst rhs = ICHILD(decl,rhs);
				if (rhs.node->kind == ffzNodeKind_Operator) { // @extern procs also have the type ffzTypeTag_Proc
					gen_procedure(g, IAS(rhs, Operator));
				}
			}
		}
		else {
			TB_Reg local_addr = tb_inst_local(g->tb_func, type->size, type->alignment);
			map64_insert(&g->tb_local_addr_from_definition, ffz_hash_node_inst(IBASE(definition)), local_addr);
			
			tb_function_attrib_variable(g->tb_func, local_addr, str_to_cstring(definition.node->name, g->alc), get_tb_debug_type(g, type));

			gen_store(g, local_addr, ICHILD(decl, rhs));
		}
	} break;

	case ffzNodeKind_Assignment: {
		ffzNodeAssignmentInst assign = IAS(inst, Assignment);
		ffzNodeInst lhs = ICHILD(assign, lhs);
		TB_Reg addr_of_lhs = gen_expr(g, lhs, true).small;
		gen_store(g, addr_of_lhs, ICHILD(assign, rhs));
		
		//ffzType* type = ffz_decl_get_type(g->checker, decl);
		
		//ffzType* type = ffz_expr_get_type(g->checker, lhs);
		//tb_inst_store(g->tb_func, get_tb_basic_type(g, type), addr_of_lhs, rhs_value, type->alignment);
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		ffzNodeIfInst if_stmt = IAS(inst, If);
		TB_Reg cond = gen_expr(g, ICHILD(if_stmt, condition)).small;
		
		TB_Label true_bb = tb_basic_block_create(g->tb_func);
		TB_Label else_bb;
		if (if_stmt.node->else_scope) {
			else_bb = tb_basic_block_create(g->tb_func);
		}

		TB_Label after_bb = tb_basic_block_create(g->tb_func);
		tb_inst_if(g->tb_func, cond, true_bb, if_stmt.node->else_scope ? else_bb : after_bb);
		
		tb_inst_set_label(g->tb_func, true_bb);
		gen_statement(g, ICHILD(if_stmt,true_scope));
		
		inst_loc(g, inst.node, if_stmt.node->true_scope->loc.end.line_num);
		tb_inst_goto(g->tb_func, after_bb);

		if (if_stmt.node->else_scope) {
			tb_inst_set_label(g->tb_func, else_bb);
			gen_statement(g, ICHILD(if_stmt,else_scope));
			
			inst_loc(g, inst.node, if_stmt.node->else_scope->loc.end.line_num);
			tb_inst_goto(g->tb_func, after_bb);
		}

		tb_inst_set_label(g->tb_func, after_bb);
	} break;

	case ffzNodeKind_For: {
		ffzNodeForInst for_loop = IAS(inst,For);
		ffzNodeInst pre = ICHILD(for_loop, header_stmts[0]);
		ffzNodeInst condition = ICHILD(for_loop, header_stmts[1]);
		ffzNodeInst post = ICHILD(for_loop, header_stmts[2]);
		ffzNodeInst body = ICHILD(for_loop, scope);
		
		if (pre.node) gen_statement(g, pre);
		
		TB_Label cond_bb = tb_basic_block_create(g->tb_func);
		TB_Label body_bb = tb_basic_block_create(g->tb_func);
		TB_Label after_bb = tb_basic_block_create(g->tb_func);
		tb_inst_goto(g->tb_func, cond_bb);

		if (!condition.node) BP; // TODO
		
		{
			tb_inst_set_label(g->tb_func, cond_bb);
			TB_Reg cond = gen_expr(g, condition).small;
			tb_inst_if(g->tb_func, cond, body_bb, after_bb);
		}

		{
			tb_inst_set_label(g->tb_func, body_bb);
			gen_statement(g, body);
			
			inst_loc(g, inst.node, body.node->loc.end.line_num);
			if (post.node) gen_statement(g, post, false); // don't set loc, let's override the loc to be at the end of the body scope

			tb_inst_goto(g->tb_func, cond_bb);
		}

		tb_inst_set_label(g->tb_func, after_bb);
	} break;

	case ffzNodeKind_Keyword: {
		tb_inst_debugbreak(g->tb_func);
	} break;

	case ffzNodeKind_Return: {
		ffzNodeReturnInst ret = IAS(inst, Return);
		TB_Reg val = TB_NULL_REG;
		
		if (ret.node->value) {
			SmallOrPtr return_value = gen_expr(g, ICHILD(ret, value));
			if (return_value.ptr) {
				ffzType* ret_type = ffz_expr_get_type(g->checker, ICHILD(ret, value));

#if FIX_TB_BIG_RETURN_HACK
				val = tb_inst_load(g->tb_func, TB_TYPE_PTR, g->func_big_return, 8);
#else
				val = g->func_big_return;
#endif
				//tb_inst_param(g->tb_func, 0); // :BigReturn
				tb_inst_memcpy(g->tb_func, val, return_value.ptr, tb_inst_uint(g->tb_func, TB_TYPE_I64, ret_type->size), ret_type->alignment);
			}
			else {
				val = return_value.small;
			}
		}

		tb_inst_ret(g->tb_func, val);
	} break;

	case ffzNodeKind_Operator: {
		ASSERT(AS(inst.node, Operator)->op_kind == ffzOperatorKind_PostRoundBrackets);
		gen_call(g, IAS(inst, Operator));
	} break;

	default: BP;
	}
}

void ffz_tb_generate(ffzProject* project, String objname) {
	Allocator* temp = temp_push(); defer(temp_pop());
	
	TB_FeatureSet features = { 0 };
	TB_Module* tb_module = tb_module_create_for_host(&features, true);

	Gen g = {};
	g.tb = tb_module;
	g.alc = temp;
	g.project = project;
	g.tb_file_from_parser_idx = make_array<TB_FileID>(g.alc);
	g.tb_local_addr_from_definition = make_map64<TB_Reg>(g.alc);
	g.func_from_hash = make_map64<TB_Function*>(g.alc);

	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		
		TB_FileID file = tb_file_create(tb_module, str_to_cstring(parser->source_code_filepath, temp));
		array_push(&g.tb_file_from_parser_idx, file);
	}

	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		g.checker = project->checkers[parser->checker_idx];

		for FFZ_EACH_CHILD(n, parser->root) {
			gen_statement(&g, ffzNodeInst{ n, 0 });
		}
	}

	TB_Exports exports = tb_exporter_write_output(tb_module, TB_FLAVOR_OBJECT, TB_DEBUGFMT_CODEVIEW);
	os_file_write_whole(objname, String{ exports.files[0].data, exports.files[0].length });
	tb_exporter_free(exports);
	
	tb_module_destroy(tb_module);
}

#if 0
static void tb_test() {
	TB_FeatureSet features = { 0 };
	TB_Module* m = tb_module_create_for_host(&features, true);
	
	TB_FunctionPrototype* proto = tb_prototype_create(m, TB_CDECL, TB_TYPE_I32, NULL, 1, false);
	tb_prototype_add_param(proto, TB_TYPE_PTR);
	
	TB_Function* func = tb_function_create(m, "entry", TB_LINKAGE_PUBLIC);
	tb_function_set_prototype(func, proto);

	TB_FileID my_file = tb_file_create(m, "test.txt");
	tb_inst_loc(func, my_file, 2);
	
	TB_Reg result = tb_inst_sint(func, TB_TYPE_I32, 999);
	tb_function_attrib_variable(func, result, "RESULT", tb_debug_get_integer(m, true, 32));
	tb_inst_ret(func, result);

	tb_function_print(func, tb_default_print_callback, stdout, false);

	bool ok = tb_module_compile_function(m, func, TB_ISEL_FAST);

	TB_Exports exports = tb_exporter_write_output(m, TB_FLAVOR_OBJECT, TB_DEBUGFMT_CODEVIEW);
	os_file_write_whole(LIT("DUMMY.obj"), String{ exports.files[0].data, exports.files[0].length });
	tb_exporter_free(exports);

	tb_module_destroy(m);
}
#endif