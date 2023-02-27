#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include "ffz_backend_tb.h"

#define gmmcString fString
#include "gmmc/gmmc.h"

#include "microsoft_craziness.h"
#undef small // window include header, wtf?

#define todo F_BP

// holds either a value, or a pointer to the value if the size of the type > 8 bytes
//struct SmallOrPtr {
//	gmmcReg small;
//	gmmcReg ptr;
//	bool ptr_can_be_stolen; // if false, the caller must make a local copy of the value if they need it. Otherwise, they can just take it and pretend its their own copy.
//};

struct Gen {
	ffzProject* project;
	fAllocator* alc;
	ffzChecker* checker;

	gmmcModule* gmmc;
	gmmcProc* proc;
	gmmcBasicBlock* bb;
	
	ffzType* proc_type;
	//gmmcReg func_big_return;
	
	uint dummy_name_counter;
	
	fMap64(gmmcProc*) proc_from_hash;
	fMap64(gmmcReg) gmmc_local_addr_from_definition;
};

// Helper macros for ffz

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

#define IAS(node, kind) FFZ_INST_AS(node, kind)
#define IBASE(node) FFZ_INST_BASE(node) 
#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).polymorph }

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc = true);
static gmmcReg gen_expr(Gen* g, ffzNodeInst inst, bool address_of = false);


static fString make_name(Gen* g, ffzNodeInst inst = {}, bool pretty = true) {
	fArray(u8) name = f_array_make<u8>(g->alc);

	if (inst.node) {
		f_str_print(&name, ffz_get_parent_decl_name(inst.node));
		
		if (inst.polymorph) {
			if (pretty) {
				f_str_print(&name, F_LIT("["));

				for (uint i = 0; i < inst.polymorph->parameters.len; i++) {
					if (i > 0) f_str_print(&name, F_LIT(", "));

					f_str_print(&name, ffz_constant_to_string(g->project, inst.polymorph->parameters[i]));
				}

				f_str_print(&name, F_LIT("]"));
			}
			//else {
			//	// hmm.. deterministic index for polymorph, how?
			//	//F_BP; // f_str_printf(&name, "$%u", inst.poly_idx.idx);
			//}
			//f_str_printf(&name, "$%xll", inst.polymorph->hash);
		}
		
		if (g->checker->_dbg_module_import_name.len > 0) {
			// We don't want to export symbols from imported modules.
			// Currently, we're giving these symbols unique ids and exporting them anyway, because
			// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!

			if (!ffz_node_get_compiler_tag(inst.node, F_LIT("extern"))) {
				f_str_print(&name, F_LIT("$$"));
				f_str_print(&name, g->checker->_dbg_module_import_name);
			}
		}
	}
	else {
		f_str_printf(&name, "_ffz_%llu", g->dummy_name_counter);
		g->dummy_name_counter++;
	}

	return name.slice;
}

//struct TypeWithDebug {
//	gmmcType dt;
//	TB_DebugType* dbg_type;
//};

gmmcType get_gmmc_type(Gen* g, ffzType* type) {
	F_ASSERT(type->size <= 8);
	switch (type->tag) {
	case ffzTypeTag_Bool: return gmmcType_bool;
	
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_Pointer: return gmmcType_ptr;

	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: {
		if (type->size == 1) return gmmcType_i8;
		else if (type->size == 2) return gmmcType_i16;
		else if (type->size == 4) return gmmcType_i32;
		else if (type->size == 8) return gmmcType_i64;
		else F_BP;
	} break;

	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: {
		if (type->size == 1) return gmmcType_i8;
		else if (type->size == 2) return gmmcType_i16;
		else if (type->size == 4) return gmmcType_i32;
		else if (type->size == 8) return gmmcType_i64;
		else F_BP;
	} break;

	case ffzTypeTag_Record: {
		return gmmcType_i64; // maybe we should get the smallest type that the struct fits in instead
	} break;
		//case ffzTypeTag_Enum: {} break;
		//case ffzTypeTag_FixedArray: {} break;
	}
	F_BP;
	return {};
}

gmmcType get_gmmc_type_or_ptr(Gen* g, ffzType* type) {
	if (type->size > 8) return gmmcType_ptr;
	return get_gmmc_type(g, type);
}


static gmmcProc* gen_procedure(Gen* g, ffzNodeOperatorInst inst) {
	auto insertion = f_map64_insert(&g->proc_from_hash, ffz_hash_node_inst(IBASE(inst)), (gmmcProc*)0, fMapInsert_DoNotOverride);
	if (!insertion.added) return *insertion._unstable_ptr;

	ffzType* proc_type = ffz_expr_get_type(g->project, IBASE(inst));
	F_ASSERT(proc_type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = proc_type->Proc.out_param ? proc_type->Proc.out_param->type : NULL;
	
	bool big_return = ret_type && ret_type->size > 8;
	gmmcType ret_type_gmmc = big_return ? gmmcType_ptr :
		ret_type ? get_gmmc_type(g, ret_type) : gmmcType_None;

	// TODO: deduplicate prototypes?
	fArray(gmmcType) param_types = f_array_make<gmmcType>(g->alc);
	
	if (big_return) {
		// if big return, pass the pointer to the return value as the first argument the same way C does. :BigReturn
		f_array_push(&param_types, gmmcType_ptr);
	}

	for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];
		
		gmmcType param_type = param->type->size > 8 ? gmmcType_ptr : get_gmmc_type(g, param->type);
		f_array_push(&param_types, param_type);
	}

	gmmcProcSignature* sig = gmmc_make_proc_signature(g->gmmc, ret_type_gmmc, param_types.data, (u32)param_types.len);

	fString name = make_name(g, IBASE(inst));
	gmmcBasicBlock* entry_bb;
	gmmcProc* proc = gmmc_make_proc(g->gmmc, sig, name, &entry_bb);
	*insertion._unstable_ptr = proc;

	ffzNodeInst left = ICHILD(inst,left);
	if (left.node->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		F_BP;//gen_statement(g, ICHILD(IAS(left, ProcType), out_parameter));
	}

	gmmcProc* proc_before = g->proc;
	gmmcBasicBlock* bb_before = g->bb;
	ffzType* proc_type_before = g->proc_type;
	g->proc = proc;
	g->proc_type = proc_type;
	g->bb = entry_bb;

	//g->func_big_return = TB_NULL_REG;
	/*if (big_return) {
		// There's some weird things going on in TB debug info if we don't call tb_inst_param_addr on every parameter. So let's just call it.
		gmmcReg _param_addr = tb_inst_param_addr(func, 0);

#if FIX_TB_BIG_RETURN_HACK
		g->func_big_return = tb_inst_local(func, 8, 8);
		tb_inst_store(func, gmmcType_ptr, g->func_big_return, tb_inst_param(func, 0), 8);
#else
#endif
		g->func_big_return = tb_inst_param(func, 0);
	}*/

	///if (inst.node->loc.start.line_num == 176) F_BP;

	ffzNodeProcTypeInst proc_type_inst = IAS(proc_type->unique_node,ProcType);
	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, proc_type_inst) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];

		F_ASSERT(n.node->kind == ffzNodeKind_Declaration);
		ffzNodeIdentifierInst param_definition = ICHILD(IAS(n, Declaration), name);
		param_definition.polymorph = inst.polymorph; // hmmm...
		ffzNodeInstHash hash = ffz_hash_node_inst(IBASE(param_definition));

		if (param->type->size > 8) {
			F_BP;
		}
		
		// from language perspective, it'd be the nicest to be able to get the address of a reg,
		// and to be able to assign to a reg. But that's a bit weird for the backend. Let's just make a local every time for now.
		gmmcReg param_local = gmmc_op_local(g->proc, param->type->size, param->type->align);
		gmmc_op_store(g->bb, param_local, gmmc_op_param(proc, i));
		f_map64_insert(&g->gmmc_local_addr_from_definition, hash, param_local);
		i++;
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_statement(g, n);
	}
	
	if (!proc_type->Proc.out_param) { // automatically generate a return statement if the proc doesn't return a value
		gmmc_op_return(g->bb, GMMC_REG_NONE);
	}

	g->proc_type = proc_type_before;
	g->proc = proc_before;
	g->bb = bb_before;
	
	//gmmc_proc_print(
	//printf("\n");
	//tb_function_print(func, tb_default_print_callback, stdout, false);
	//printf("\n");

	//bool ok = tb_module_compile_function(g->gmmc, func, TB_ISEL_FAST);
	//F_ASSERT(ok);

	return proc;
}

static gmmcReg gen_call(Gen* g, ffzNodeOperatorInst inst) {
	ffzNodeInst left = ICHILD(inst,left);
	ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
	F_ASSERT(left_chk.type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = left_chk.type->Proc.out_param ? left_chk.type->Proc.out_param->type : NULL;
	bool big_return = ret_type && ret_type->size > 8; // :BigReturn
	
	gmmcType ret_type_gmmc = big_return ? gmmcType_ptr :
		ret_type ? get_gmmc_type(g, ret_type) : gmmcType_None;

	fArray(gmmcReg) args = f_array_make<gmmcReg>(g->alc);

	gmmcReg out = {};
	if (big_return) {
		out = gmmc_op_local(g->proc, ret_type->size, ret_type->align);
		//out.ptr_can_be_stolen = true;
		f_array_push(&args, out);
	}

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, inst) {
		ffzType* param_type = left_chk.type->Proc.in_params[i].type;
		gmmcReg arg = gen_expr(g, n);
		
		if (param_type->size > 8) {
			// make a copy on the stack for the parameter
			// TODO: use the `ptr_can_be_stolen` here!
			gmmcReg local_copy_addr = gmmc_op_local(g->proc, param_type->size, param_type->align);
			gmmc_op_memmove(g->bb, local_copy_addr, arg, gmmc_op_i32(g->bb, param_type->size));
			f_array_push(&args, local_copy_addr);
		}
		else {
			f_array_push(&args, arg);
		}
		i++;
	}

	// TODO: non-vcall for constant procedures

	gmmcReg target = gen_expr(g, left, false);
	F_ASSERT(target);

	gmmcReg return_val = gmmc_op_vcall(g->bb, ret_type_gmmc, target, args.data, (u32)args.len);
	if (!big_return) out = return_val;

	return out;
}

static gmmcReg load_small(Gen* g, gmmcReg ptr, uint size) {
	if (size == 1) return gmmc_op_load(g->bb, gmmcType_i8, ptr);
	else if (size == 2) return gmmc_op_load(g->bb, gmmcType_i16, ptr);
	else if (size == 4) return gmmc_op_load(g->bb, gmmcType_i32, ptr);
	else if (size == 8) return gmmc_op_load(g->bb, gmmcType_i64, ptr);
	else F_BP; // TODO!! i.e. a type could be of size 3, when [3]u8
	return 0;
}

static gmmcSymbol* get_proc_symbol(Gen* g, ffzNodeInst proc_node) {
	if (proc_node.node->kind == ffzNodeKind_ProcType) { // @extern proc
		fString name = make_name(g, proc_node);
		return gmmc_make_external_symbol(g->gmmc, name);
	}
	else {
		return gmmc_proc_as_symbol(gen_procedure(g, IAS(proc_node, Operator)));
	}
}

static void gen_global_constant(Gen* g, gmmcGlobal* global, u8* base, u32 offset, ffzType* type, ffzConstant* constant) {
	switch (type->tag) {
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: {
		memcpy(base + offset, constant, type->size);
	} break;

	case ffzTypeTag_Proc: {
		memset(base + offset, 0, 8);
		if (constant->proc_node.node) {
			gmmcSymbol* proc_sym = get_proc_symbol(g, constant->proc_node);
			gmmc_global_add_relocation(global, offset, proc_sym);
		}
	} break;

	case ffzTypeTag_Pointer: {
		if (constant->ptr) todo;
		memset(base + offset, 0, 8);
	} break;

	case ffzTypeTag_String: {
		fString s = constant->string_zero_terminated;
		
		void* str_data;
		gmmcGlobal* str_data_global = gmmc_make_global(g->gmmc, (u32)s.len, 1, true, &str_data);
		memcpy(str_data, s.data, s.len);

		memset(base + offset, 0, 8);
		gmmc_global_add_relocation(global, offset, gmmc_global_as_symbol(str_data_global));

		u64 len = s.len;
		memcpy(base + offset + 8, &len, 8);
	} break;

	case ffzTypeTag_Slice: {
		memset(base + offset, 0, 16);
	} break;

	case ffzTypeTag_Record: {
		memset(base + offset, 0, type->size);
		ffzConstant empty_constant = {};
		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzTypeRecordField* field = &type->record_fields[i];

			gen_global_constant(g, global, base, offset + field->offset, field->type,
				constant->record_fields.len == 0 ? &empty_constant : &constant->record_fields[i]);
		}
	} break;
	case ffzTypeTag_FixedArray: {
		u32 elem_size = type->FixedArray.elem_type->size;
		for (u32 i = 0; i < (u32)type->FixedArray.length; i++) {
			ffzConstant c = ffz_constant_fixed_array_get(type, constant, i);
			gen_global_constant(g, global, base, offset + i * elem_size, type->FixedArray.elem_type, &c);
		}
	} break;
	default: F_BP;
	}
}

static gmmcReg gen_expr(Gen* g, ffzNodeInst inst, bool address_of) {
	gmmcReg out = {};

	ffzCheckedExpr checked = ffz_expr_get_checked(g->project, inst);
	F_ASSERT(ffz_type_is_grounded(checked.type));

	if (checked.const_val) {
		switch (checked.type->tag) {
		case ffzTypeTag_Bool: {
			F_ASSERT(!address_of);
			out = gmmc_op_bool(g->bb, checked.const_val->bool_);
		} break;
		case ffzTypeTag_SizedInt: // fallthrough
		case ffzTypeTag_Int: {
			F_ASSERT(!address_of);
			if (checked.type->size == 1)      out = gmmc_op_i8(g->bb, checked.const_val->u8_);
			else if (checked.type->size == 2) out = gmmc_op_i16(g->bb, checked.const_val->u16_);
			else if (checked.type->size == 4) out = gmmc_op_i32(g->bb, checked.const_val->u32_);
			else if (checked.type->size == 8) out = gmmc_op_i64(g->bb, checked.const_val->u64_);
			else F_BP;
		} break;

		case ffzTypeTag_SizedUint: // fallthrough
		case ffzTypeTag_Uint: {
			F_ASSERT(!address_of);
			if (checked.type->size == 1)      out = gmmc_op_i8(g->bb, checked.const_val->u8_);
			else if (checked.type->size == 2) out = gmmc_op_i16(g->bb, checked.const_val->u16_);
			else if (checked.type->size == 4) out = gmmc_op_i32(g->bb, checked.const_val->u32_);
			else if (checked.type->size == 8) out = gmmc_op_i64(g->bb, checked.const_val->u64_);
			else F_BP;
		} break;

		case ffzTypeTag_Proc: {
			F_ASSERT(!address_of);
			out = gmmc_op_addr_of_symbol(g->bb, get_proc_symbol(g, checked.const_val->proc_node));
		} break;

		case ffzTypeTag_Slice: // fallthrough
		case ffzTypeTag_String: // fallthrough
		case ffzTypeTag_FixedArray: // fallthrough
		case ffzTypeTag_Record: {
			void* global_data;
			gmmcGlobal* global = gmmc_make_global(g->gmmc, checked.type->size, checked.type->align, true, &global_data);
			
			gen_global_constant(g, global, (u8*)global_data, 0, checked.type, checked.const_val);

			gmmcReg global_addr = gmmc_op_addr_of_symbol(g->bb, gmmc_global_as_symbol(global));
			if (address_of) out = global_addr;
			else {
				if (checked.type->size > 8) out = global_addr;
				else out = load_small(g, global_addr, checked.type->size);
			}
		} break;

		default: F_BP;
		}

		return out;
	}

	bool should_dereference = false;
	bool should_take_address = false;

	switch (inst.node->kind) {
	case ffzNodeKind_Identifier: {
		ffzNodeIdentifierInst def = ffz_get_definition(g->project, IAS(inst,Identifier));
		if (def.node->is_constant) F_BP;
		
		out = *f_map64_get(&g->gmmc_local_addr_from_definition, ffz_hash_node_inst(IBASE(def)));
		should_dereference = !address_of;
	} break;
	case ffzNodeKind_Operator: {
//		F_HITS(__c, 12);
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
			F_ASSERT(!address_of);
			//F_HITS(___c, 6);
			gmmcReg a = gen_expr(g, left);
			gmmcReg b = gen_expr(g, right);
			
			bool is_signed = ffz_type_is_signed_integer(checked.type->tag);

			switch (derived.node->op_kind) {
			case ffzOperatorKind_Add: { out = gmmc_op_add(g->bb, a, b); } break;
			case ffzOperatorKind_Sub: { out = gmmc_op_sub(g->bb, a, b); } break;
			case ffzOperatorKind_Mul: { out = gmmc_op_mul(g->bb, a, b, is_signed); } break;
			case ffzOperatorKind_Div: { out = gmmc_op_div(g->bb, a, b, is_signed); } break;
			case ffzOperatorKind_Modulo: { out = gmmc_op_mod(g->bb, a, b, is_signed); } break;

			case ffzOperatorKind_Equal: { out = gmmc_op_eq(g->bb, a, b); } break;
			case ffzOperatorKind_NotEqual: { out = gmmc_op_ne(g->bb, a, b); } break;
			case ffzOperatorKind_Less: { out = gmmc_op_lt(g->bb, a, b, is_signed); } break;
			case ffzOperatorKind_LessOrEqual: { out = gmmc_op_le(g->bb, a, b, is_signed); } break;
			case ffzOperatorKind_Greater: { out = gmmc_op_gt(g->bb, a, b, is_signed); } break;
			case ffzOperatorKind_GreaterOrEqual: { out = gmmc_op_ge(g->bb, a, b, is_signed); } break;

			default: F_BP;
			}
		} break;

		case ffzOperatorKind_UnaryMinus: {
			F_ASSERT(!address_of);
			F_BP; //out = tb_inst_neg(g->fn, gen_expr(g, right).small);
		} break;

		case ffzOperatorKind_LogicalNOT: {
			F_ASSERT(!address_of);
			// (!x) is equivalent to (x == false)
			F_BP; //out = tb_inst_cmp_eq(g->fn, gen_expr(g, right).small, tb_inst_bool(g->fn, false));
		} break;

		case ffzOperatorKind_PostRoundBrackets: {
			// sometimes we need to take the address of a temporary.
			// e.g.  copy_string("hello").ptr
			F_ASSERT(!address_of); // TODO
			/*should_take_address = address_of;*/

			if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(AS(left.node, Keyword)->keyword)) {
				ffzKeyword keyword = AS(left.node,Keyword)->keyword;
				
				gmmcReg first = gen_expr(g, ffz_get_child_inst(IBASE(inst), 0));
				if (keyword == ffzKeyword_bit_not) {
					out = gmmc_op_not(g->bb, first);
				}
				else {
					gmmcReg second = gen_expr(g, ffz_get_child_inst(IBASE(inst), 1));
					switch (keyword) {		
					case ffzKeyword_bit_and: { out = gmmc_op_and(g->bb, first, second); } break;
					case ffzKeyword_bit_or:  { out = gmmc_op_or(g->bb, first, second); } break;
					case ffzKeyword_bit_xor: { out = gmmc_op_xor(g->bb, first, second); } break;
					case ffzKeyword_bit_shl: { out = gmmc_op_shl(g->bb, first, second); } break;
					case ffzKeyword_bit_shr: { out = gmmc_op_shr(g->bb, first, second); } break;
					default: F_BP;
					}
				}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				if (left_chk.type->tag == ffzTypeTag_Type) {
					ffzType* dst_type = left_chk.const_val->type;
					// type cast, e.g. u32(5293900)

					ffzNodeInst arg = ffz_get_child_inst(IBASE(inst), 0);
					ffzType* arg_type = ffz_expr_get_type(g->project, arg);

					out = gen_expr(g, arg);
					if (ffz_type_is_pointer_ish(dst_type->tag)) { // cast to pointer
						if (arg_type->tag == ffzTypeTag_Pointer) {}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							out = gmmc_op_int2ptr(g->bb, out);
						}
					}
					else if (ffz_type_is_integer_ish(dst_type->tag)) { // cast to integer
						gmmcType dt = get_gmmc_type(g, dst_type);
						if (arg_type->tag == ffzTypeTag_Pointer) {
							out = gmmc_op_ptr2int(g->bb, out, dt);
						}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							// integer -> integer cast

							if (dst_type->size > arg_type->size) {
								if (ffz_type_is_signed_integer(dst_type->tag)) {
									out = gmmc_op_sxt(g->bb, out, dt);  // sign extend
								}
								else {
									out = gmmc_op_zxt(g->bb, out, dt);  // zero extend
								}
							}
							else if (dst_type->size < arg_type->size) {
								out = gmmc_op_trunc(g->bb, out, dt);
							}
						}
						else { todo; }
					}
					else todo;
				}
				else {
					out = gen_call(g, derived);
				}
			}
		} break;
		
		case ffzOperatorKind_AddressOf: {
			F_ASSERT(!address_of);
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
			fString member_name = AS(right.node, Identifier)->name;

			if (left.node->kind == ffzNodeKind_Identifier && AS(left.node, Identifier)->name == F_LIT("in")) {
				F_ASSERT(!address_of); // TODO
				for (int i = 0; i < g->proc_type->Proc.in_params.len; i++) {
					ffzTypeProcParameter& param = g->proc_type->Proc.in_params[i];
					if (param.name->name == member_name) {
						out = gmmc_op_param(g->proc, i);
						F_ASSERT(param.type->size <= 8);
					}
				}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				ffzType* struct_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;

				ffzTypeRecordFieldUse field;
				F_ASSERT(ffz_type_find_record_field_use(g->project, struct_type, member_name, &field));

				gmmcReg addr_of_struct = gen_expr(g, left, left_chk.type->tag != ffzTypeTag_Pointer);
				F_ASSERT(addr_of_struct);
				
				out = gmmc_op_member_access(g->bb, addr_of_struct, field.offset);
				should_dereference = !address_of;
			}
		} break;

		case ffzOperatorKind_PostCurlyBrackets: {
			// dynamic initializer
			F_BP;
			/*out.ptr = tb_inst_local(g->fn, checked.type->size, checked.type->align);
			out.ptr_can_be_stolen = true;
			F_ASSERT(checked.type->size > 8);

			if (checked.type->tag == ffzTypeTag_Record) {
				u32 i = 0;
				for FFZ_EACH_CHILD_INST(n, inst) {
					ffzTypeRecordField& field = checked.type->record_fields[i];
					
					SmallOrPtr src = gen_expr(g, n);
					gmmcReg dst_ptr = tb_inst_member_access(g->fn, out.ptr, field.offset);
					_gen_store(g, dst_ptr, src, field.type);
					i++;
				}
			}
			else if (checked.type->tag == ffzTypeTag_FixedArray) {
				u32 i = 0;
				ffzType* elem_type = checked.type->FixedArray.elem_type;
				for FFZ_EACH_CHILD_INST(n, inst) {
					SmallOrPtr src = gen_expr(g, n, false);
					gmmcReg dst_ptr = tb_inst_member_access(g->fn, out.ptr, i * elem_type->size);
					_gen_store(g, dst_ptr, src, elem_type);
					i++;
				}
			}
			else F_BP;*/
		} break;

		case ffzOperatorKind_PostSquareBrackets: {
			F_BP;
			/*
			ffzType* left_type = ffz_expr_get_type(g->project, left);
			F_ASSERT(left_type->tag == ffzTypeTag_FixedArray || left_type->tag == ffzTypeTag_Slice);

			ffzType* elem_type = left_type->tag == ffzTypeTag_Slice ? left_type->fSlice.elem_type : left_type->FixedArray.elem_type;
			
			gmmcReg left_value = gen_expr(g, left, true).small;
			gmmcReg array_data = left_value;

			if (left_type->tag == ffzTypeTag_Slice) {
				F_BP;// array_data = c0_push_load(g->c0_proc, c0_agg_type_basic(g->c0, C0Basic_ptr), array_data);
			}

			if (ffz_get_child_count(BASE(inst.node)) == 2) { // slicing
				ffzNodeInst lo_inst = ffz_get_child_inst(IBASE(inst), 0);
				ffzNodeInst hi_inst = ffz_get_child_inst(IBASE(inst), 1);

				gmmcReg lo = lo_inst.node->kind == ffzNodeKind_Blank ?
					tb_inst_uint(g->fn, TB_TYPE_I64, 0) : gen_expr(g, lo_inst).small;
				gmmcReg hi;
				if (hi_inst.node->kind == ffzNodeKind_Blank) {
					if (left_type->tag == ffzTypeTag_FixedArray) {
						hi = tb_inst_uint(g->fn, TB_TYPE_I64, left_type->FixedArray.length);
					} else {
						// load the 'len' field of a slice
						hi = tb_inst_load(g->fn, TB_TYPE_I64, tb_inst_member_access(g->fn, left_value, 8), 8);
					}
				} else {
					hi = gen_expr(g, hi_inst).small;
				}

				out.ptr = tb_inst_local(g->fn, 16, 8);
				lo = tb_inst_zxt(g->fn, lo, TB_TYPE_I64);
				hi = tb_inst_zxt(g->fn, hi, TB_TYPE_I64);
				gmmcReg lo_offset = tb_inst_mul(g->fn, lo, tb_inst_uint(g->fn, TB_TYPE_I64, elem_type->size), (TB_ArithmaticBehavior)0);
				gmmcReg ptr = tb_inst_add(g->fn, tb_inst_ptr2int(g->fn, array_data, TB_TYPE_I64), lo_offset, (TB_ArithmaticBehavior)0);
				gmmcReg len = tb_inst_sub(g->fn, hi, lo, (TB_ArithmaticBehavior)0);

				tb_inst_store(g->fn, TB_TYPE_I64, out.ptr, ptr, 8);
				tb_inst_store(g->fn, TB_TYPE_I64, tb_inst_member_access(g->fn, out.ptr, 8), len, 8);
			}
			else { // taking an index
				ffzNodeInst index_node = ffz_get_child_inst(IBASE(inst), 0);
				gmmcReg index = tb_inst_zxt(g->fn, gen_expr(g, index_node).small, TB_TYPE_I64);
				
				gmmcReg index_offset = tb_inst_mul(g->fn, index,
					tb_inst_uint(g->fn, TB_TYPE_I64, elem_type->size), (TB_ArithmaticBehavior)0);
				
				out = tb_inst_add(g->fn, tb_inst_ptr2int(g->fn, array_data, TB_TYPE_I64),
					index_offset, (TB_ArithmaticBehavior)0);

				should_dereference = !address_of;
			}*/
		} break;

		case ffzOperatorKind_LogicalOR: // fallthrough
		case ffzOperatorKind_LogicalAND: {
			bool AND = derived.node->op_kind == ffzOperatorKind_LogicalAND;
			gmmcReg left_val = gen_expr(g, left);
			
			// implement short-circuiting

			gmmcBasicBlock* test_right_bb = gmmc_make_basic_block(g->proc);
			gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);

			gmmcReg result = gmmc_op_local(g->proc, 1, 1);
			if (AND) {
				gmmc_op_store(g->bb, result, gmmc_op_bool(g->bb, false));
				gmmc_op_if(g->bb, left_val, test_right_bb, after_bb);
			}
			else {
				gmmc_op_store(g->bb, result, gmmc_op_bool(g->bb, true));
				gmmc_op_if(g->bb, left_val, after_bb, test_right_bb);
			}

			g->bb = test_right_bb;
			gmmc_op_store(g->bb, result, gen_expr(g, right));
			gmmc_op_goto(g->bb, after_bb);
			
			g->bb = after_bb;
			out = gmmc_op_load(g->bb, gmmcType_bool, result);
		} break;

		default: F_BP;
		}

	} break;

	case ffzNodeKind_Dot: {
		ffzNodeInst assignee;
		F_ASSERT(ffz_dot_get_assignee(IAS(inst, Dot), &assignee));
		out = gen_expr(g, assignee, address_of); 
	} break;

	default: F_BP;
	}
	
	if (should_dereference) {
		F_ASSERT(!should_take_address);
		if (checked.type->size <= 8) {
			out = gmmc_op_load(g->bb, get_gmmc_type(g, checked.type), out);
		}
	}

	return out;
}

static void gen_store(Gen* g, gmmcReg addr, gmmcReg value, ffzType* type) {
	if (type->size > 8) {
		gmmc_op_memmove(g->bb, addr, value, gmmc_op_i32(g->bb, type->size));
	} else {
		gmmc_op_store(g->bb, addr, value);
	}
}

static bool node_is_keyword(ffzNode* node, ffzKeyword keyword) { return node->kind == ffzNodeKind_Keyword && node->Keyword.keyword == keyword; }

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc) {
	
	if (g->proc) {
		//gmmc_op_comment(g->bb, fString{}); // empty line
		if (inst.node->kind != ffzNodeKind_Scope && !node_is_keyword(inst.node, ffzKeyword_dbgbreak)) {
			ffzParser* parser = g->project->parsers_dependency_sorted[inst.node->id.parser_id];
			u32 start = inst.node->loc.start.offset;
			u32 end = inst.node->loc.end.offset;
			gmmc_op_comment(g->bb, fString{ parser->source_code.data + start, end - start });
		}
	}
	
	switch (inst.node->kind) {
		
	case ffzNodeKind_Declaration: {
		ffzNodeDeclarationInst decl = IAS(inst, Declaration);
		ffzNodeIdentifierInst definition = ICHILD(decl, name);
		ffzType* type = ffz_decl_get_type(g->project, decl);

		if (ffz_decl_is_runtime_value(decl.node)) {
			gmmcReg local = gmmc_op_local(g->proc, type->size, type->align);
			gmmcReg rhs_value = gen_expr(g, ICHILD(decl, rhs));
			local = gmmc_op_local(g->proc, type->size, type->align);
			gen_store(g, local, rhs_value, type);

			f_map64_insert(&g->gmmc_local_addr_from_definition, ffz_hash_node_inst(IBASE(definition)), local);
		}
		else {
			// need to still generate exported procs
			if (type->tag == ffzTypeTag_Proc) {
				ffzNodeInst rhs = ICHILD(decl,rhs);
				if (rhs.node->kind == ffzNodeKind_Operator) { // @extern procs also have the type ffzTypeTag_Proc
					gen_procedure(g, IAS(rhs, Operator));
				}
			}
		}
	} break;

	case ffzNodeKind_Assignment: {
		ffzNodeAssignmentInst assign = IAS(inst, Assignment);
		ffzNodeInst lhs = ICHILD(assign,lhs);
		ffzNodeInst rhs = ICHILD(assign,rhs);
		gmmcReg lhs_addr = gen_expr(g, lhs, true);
		
		gmmcReg rhs_value = gen_expr(g, rhs);
		gen_store(g, lhs_addr, rhs_value, ffz_expr_get_type(g->project, rhs));
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		ffzNodeIfInst if_stmt = IAS(inst, If);
		gmmcReg cond = gen_expr(g, ICHILD(if_stmt, condition));
		
		gmmcBasicBlock* true_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* false_bb;
		if (if_stmt.node->else_scope) {
			false_bb = gmmc_make_basic_block(g->proc);
		}

		gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);
		gmmc_op_if(g->bb, cond, true_bb, if_stmt.node->else_scope ? false_bb : after_bb);

		g->bb = true_bb;
		gen_statement(g, ICHILD(if_stmt,true_scope));
		gmmc_op_goto(g->bb, after_bb);

		if (if_stmt.node->else_scope) {
			g->bb = false_bb;
			gen_statement(g, ICHILD(if_stmt,else_scope));
			gmmc_op_goto(g->bb, after_bb);
		}

		g->bb = after_bb;
	} break;

	case ffzNodeKind_For: {
		ffzNodeForInst for_loop = IAS(inst,For);
		ffzNodeInst pre = ICHILD(for_loop, header_stmts[0]);
		ffzNodeInst condition = ICHILD(for_loop, header_stmts[1]);
		ffzNodeInst post = ICHILD(for_loop, header_stmts[2]);
		ffzNodeInst body = ICHILD(for_loop, scope);
		
		if (pre.node) gen_statement(g, pre);
		
		gmmcBasicBlock* cond_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* body_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);
		gmmc_op_goto(g->bb, cond_bb);

		if (!condition.node) F_BP; // TODO
		
		g->bb = cond_bb;
		gmmcReg cond = gen_expr(g, condition);
		gmmc_op_if(g->bb, cond, body_bb, after_bb);

		g->bb = body_bb;
		gen_statement(g, body);
			
		if (post.node) gen_statement(g, post, false);

		gmmc_op_goto(g->bb, cond_bb);

		g->bb = after_bb;
	} break;

	case ffzNodeKind_Keyword: {
		gmmc_op_debugbreak(g->bb);
	} break;

	case ffzNodeKind_Return: {
		ffzNodeReturnInst ret = IAS(inst, Return);
		gmmcReg val = 0;

		if (ret.node->value) {
			ffzType* ret_type = ffz_expr_get_type(g->project, ICHILD(ret, value));
			gmmcReg return_value = gen_expr(g, ICHILD(ret, value));
			if (ret_type->size > 8) {
				val = gmmc_op_param(g->proc, 0); // :BigReturn
				gmmc_op_memmove(g->bb, val, return_value, gmmc_op_i32(g->bb, ret_type->size));
			}
			else {
				val = return_value;
			}
		}

		gmmc_op_return(g->bb, val);
	} break;

	case ffzNodeKind_Operator: {
		F_ASSERT(AS(inst.node, Operator)->op_kind == ffzOperatorKind_PostRoundBrackets);
		gen_call(g, IAS(inst, Operator));
	} break;

	default: F_BP;
	}
}

bool ffz_backend_gen_executable(ffzProject* project, fString exe_filepath) {
	F_ASSERT(f_files_path_is_absolute(exe_filepath));

	fString build_dir = f_str_path_dir(exe_filepath);
	F_ASSERT(f_files_make_directory(build_dir));

	fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop()); // temp_push_volatile?
	
	gmmcModule* gmmc = gmmc_init(temp);

	Gen g = {};
	g.gmmc = gmmc;
	g.alc = temp;
	g.project = project;
	//g.tb_file_from_parser_idx = f_array_make<TB_FileID>(g.alc);
	g.gmmc_local_addr_from_definition = f_map64_make<gmmcReg>(g.alc);
	g.proc_from_hash = f_map64_make<gmmcProc*>(g.alc);

	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		g.checker = parser->checker;

		for FFZ_EACH_CHILD(n, parser->root) {
			gen_statement(&g, ffz_get_toplevel_inst(g.checker, n));
		}
	}

	// Compile with MSVC

	fArray(u8) buf = f_array_make<u8>(temp);
	gmmc_module_print(&buf, gmmc);
	f_os_print(buf.slice);

	if (!f_files_write_whole(F_STR_JOIN(temp, build_dir, F_LIT("/gen.c")), buf.slice)) {
		printf("Failed writing temporary C file to disk!\n");
		return false;
	}

	WinSDK_Find_Result windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
	fString msvc_directory = f_str_from_utf16(windows_sdk.vs_exe_path, temp); // contains cl.exe, link.exe
	fString windows_sdk_include_base_path = f_str_from_utf16(windows_sdk.windows_sdk_include_base, temp); // contains <string.h>, etc
	fString windows_sdk_um_library_path = f_str_from_utf16(windows_sdk.windows_sdk_um_library_path, temp); // contains kernel32.lib, etc
	fString windows_sdk_ucrt_library_path = f_str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, temp); // contains libucrt.lib, etc
	fString vs_library_path = f_str_from_utf16(windows_sdk.vs_library_path, temp); // contains MSVCRT.lib etc
	fString vs_include_path = f_str_from_utf16(windows_sdk.vs_include_path, temp); // contains vcruntime.h

	{
		fArray(fString) msvc_args = f_array_make<fString>(temp);
		f_array_push(&msvc_args, F_STR_JOIN(temp, msvc_directory, F_LIT("\\cl.exe")));
		f_array_push(&msvc_args, F_LIT("/Zi"));
		f_array_push(&msvc_args, F_LIT("/std:c11"));
		f_array_push(&msvc_args, F_LIT("/Ob1")); // enable inlining
		f_array_push(&msvc_args, F_LIT("/MDd")); // raylib uses this setting
		f_array_push(&msvc_args, F_LIT("gen.c"));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\shared")));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\ucrt")));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\um")));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/I"), vs_include_path));

		f_array_push(&msvc_args, F_LIT("/link"));
		f_array_push(&msvc_args, F_LIT("/INCREMENTAL:NO"));
		f_array_push(&msvc_args, F_LIT("/MACHINE:X64"));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		f_array_push(&msvc_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), vs_library_path));

		for (uint i = 0; i < project->linker_inputs.len; i++) {
			f_array_push(&msvc_args, project->linker_inputs[i]);
		}

		printf("Running cl.exe: \n");
		u32 exit_code;
		if (!f_os_run_command(msvc_args.slice, build_dir, &exit_code)) return false;
		if (exit_code != 0) return false;
	}

	WinSDK_free_resources(&windows_sdk);
	return true;
}