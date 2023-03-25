#ifdef FFZ_BUILD_INCLUDE_GMMC

#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#define gmmcString fString
#include "gmmc/gmmc.h"

#define coffString fString
#include "gmmc/coff.h"
#include "gmmc/codeview.h"

#define SHA256_DECL extern "C"
#include "sha256.h"

#include "microsoft_craziness.h"
#undef small // window include header, wtf?

#include <stdlib.h> // for qsort

#define todo F_BP

#define CHILD(parent, child_access) ffzNodeInst{ (parent).node->child_access, (parent).polymorph }

struct Value {
	gmmcSymbol* symbol;
	gmmcOpIdx local_addr; // local_addr is used if symbol is NULL
	bool local_addr_is_indirect;
};

struct DebugInfoLine {
	gmmcOpIdx op;
	u32 line_number;
};

struct DebugInfoLocal {
	coffString name;
	gmmcOpIdx local_or_param;
	u32 type_idx;
};

struct ProcInfo {
	gmmcProc* gmmc_proc;
	ffzType* type;
	ffzNode* node;
	gmmcOpIdx addr_of_big_return;
	
	fArray(DebugInfoLine) dbginfo_lines; // we wouldn't need this if we could compile one procedure at a time with gmmc_asm_x64
	fArray(DebugInfoLocal) dbginfo_locals; // we wouldn't need this if we could compile one procedure at a time with gmmc_asm_x64
};

struct Gen {
	ffzProject* project;
	fAllocator* alc;
	ffzChecker* checker;

	gmmcModule* gmmc;

	struct {
		ProcInfo* proc_info;
		gmmcProc* proc;

		gmmcBasicBlock* bb;
	};

	uint dummy_name_counter;
	
	fMap64(ProcInfo*) proc_from_hash;
	fArray(ProcInfo*) procs_sorted;
	fMap64(Value) value_from_definition;
	
	// debug info
	fArray(cviewType) cv_types;
	fArray(cviewSourceFile) cv_file_from_parser_idx;
};

static void gen_statement(Gen* g, ffzNodeInst inst, u32 overwrite_line_num = 0);
static gmmcOpIdx gen_expr(Gen* g, ffzNodeInst inst, bool address_of = false);

static fString make_name(Gen* g, ffzNodeInst inst = {}, bool pretty = true) {
	fStringBuilder name;
	f_init_string_builder(&name, f_temp_alc());

	if (inst.node) {
		ffzNodeInst parent = ffz_parent_inst(g->project, inst);
		f_prints(name.w, ffz_get_parent_decl_name(inst.node));
		
		if (inst.polymorph) {
			//if (pretty) {
			//	f_str_print(&name, F_LIT("["));
			//
			//	for (uint i = 0; i < inst.polymorph->parameters.len; i++) {
			//		if (i > 0) f_str_print(&name, F_LIT(", "));
			//
			//		f_str_print(&name, ffz_constant_to_string(g->project, inst.polymorph->parameters[i]));
			//	}
			//
			//	f_str_print(&name, F_LIT("]"));
			//}
			//else {
			//	// hmm.. deterministic index for polymorph, how?
			
			f_print(name.w, "$~x64", inst.polymorph->hash);

			//}
			//f_str_printf(&name, "$%xll", inst.polymorph->hash);
		}
		
		if (g->checker->_dbg_module_import_name.len > 0) {
			// We don't want to export symbols from imported modules.
			// Currently, we're giving these symbols unique ids and exporting them anyway, because
			// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!
			
			bool is_extern = ffz_get_tag(g->project, parent, ffzKeyword_extern);
			bool is_module_defined_entry = ffz_get_tag(g->project, parent, ffzKeyword_module_defined_entry);
			if (!is_extern && !is_module_defined_entry)
			{
				f_prints(name.w, F_LIT("$$"));
				f_prints(name.w, g->checker->_dbg_module_import_name);
			}
		}
	}
	else {
		f_print(name.w, "_ffz_`u64", g->dummy_name_counter);
		g->dummy_name_counter++;
	}

	return name.buffer.slice;
}

// if you have e.g.  [3]u32,  then it can't be trivially stored/loaded and we pass around its address instead
static bool value_is_direct(ffzType* type) {
	if (type->size > 8) return false;
	const static bool table[] = { 0, 1, 1, 0, 1, 0, 0, 0, 1 };
	return table[type->size];
}

gmmcType get_gmmc_type(Gen* g, ffzType* type) {
	F_ASSERT(value_is_direct(type));
	switch (type->tag) {
	case ffzTypeTag_Bool: return gmmcType_bool;
	
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_Pointer: return gmmcType_ptr;

	case ffzTypeTag_Float: {
		if (type->size == 4) return gmmcType_f32;
		else if (type->size == 8) return gmmcType_f64;
		else F_BP;
	} break;

	case ffzTypeTag_FixedArray: // fallthrough
	case ffzTypeTag_Record: // fallthrough
	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultUint: {
		if (type->size == 1) return gmmcType_i8;
		else if (type->size == 2) return gmmcType_i16;
		else if (type->size == 4) return gmmcType_i32;
		else if (type->size == 8) return gmmcType_i64;
		else F_BP;
	} break;
		//case ffzTypeTag_Enum: {} break;
	}
	F_BP;
	return {};
}

//gmmcType get_gmmc_type_or_ptr(Gen* g, ffzType* type) {
//	if (value_is_indirect(type)) return gmmcType_ptr;
//	return get_gmmc_type(g, type);
//}

static bool has_big_return(ffzType* proc_type) {
	return proc_type->Proc.out_param && proc_type->Proc.out_param->type->size > 8; // :BigReturn
}

static void set_dbginfo_loc(Gen* g, gmmcOpIdx op, u32 line_num) {
	if (!gmmc_is_op_instant(g->proc, op)) {
		f_array_push(&g->proc_info->dbginfo_lines, DebugInfoLine{ op, line_num });
	}
}

static cviewTypeIdx get_debuginfo_type(Gen* g, ffzType* type) {
	cviewType cv_type = {};
	cv_type.size = type->size;

	switch (type->tag) {
	case ffzTypeTag_Bool: {
		cv_type.tag = cviewTypeTag_UnsignedInt; // TODO
		cv_type.size = 1;
	} break;

	case ffzTypeTag_Proc: {
		cv_type.tag = cviewTypeTag_UnsignedInt; // TODO
		cv_type.size = 8;
	} break;
	case ffzTypeTag_Pointer: {
		if (type->Pointer.pointer_to->tag == ffzTypeTag_Raw) {
			cv_type.tag = cviewTypeTag_VoidPointer;
		} else {
			cv_type.tag = cviewTypeTag_Pointer;
			cv_type.Pointer.type_idx = get_debuginfo_type(g, type->Pointer.pointer_to);
		}
	} break;

	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Sint: {
		cv_type.tag = cviewTypeTag_Int;
	} break;

	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Uint: {
		cv_type.tag = cviewTypeTag_UnsignedInt;
	} break;
		//case ffzTypeTag_Float: {} break;
		//case ffzTypeTag_Proc: {} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Record: {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) F_BP;

		fSlice(cviewStructMember) cv_fields = f_make_slice_garbage<cviewStructMember>(type->record_fields.len, g->alc);
		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzTypeRecordField& field = type->record_fields[i];
			cviewStructMember& cv_field = cv_fields[i];

			cv_field.name = field.name;
			cv_field.offset_of_member = field.offset;
			cv_field.type_idx = get_debuginfo_type(g, field.type);
		}

		cv_type.tag = cviewTypeTag_Record;
		cv_type.Record.fields = cv_fields.data;
		cv_type.Record.fields_count = (u32)cv_fields.len;
		
		cv_type.Record.name = type->tag == ffzTypeTag_String ? F_LIT("string") :
			type->tag == ffzTypeTag_Slice ? make_name(g) : // TODO
			make_name(g, type->unique_node);
	} break;

	//case ffzTypeTag_Enum: {} break;
	case ffzTypeTag_FixedArray: {
		cv_type.tag = cviewTypeTag_Array;
		cv_type.Array.elem_type_idx = get_debuginfo_type(g, type->FixedArray.elem_type);
	} break;

	default: F_BP;
	}

	F_ASSERT(cv_type.tag);
	// TODO: deduplicate types?
	return (u32)f_array_push(&g->cv_types, cv_type);
}


static void add_dbginfo_local(Gen* g, fString name, gmmcOpIdx addr, ffzType* type, bool ref = false) {
	DebugInfoLocal dbginfo_local;
	dbginfo_local.local_or_param = addr;
	dbginfo_local.name = name;
	dbginfo_local.type_idx = get_debuginfo_type(g, type);
	
	if (ref) {
		cviewType cv_type = {};
		cv_type.size = type->size;
		cv_type.tag = cviewTypeTag_Pointer;
		cv_type.Pointer.cpp_style_reference = true;
		cv_type.Pointer.type_idx = dbginfo_local.type_idx;
		dbginfo_local.type_idx = (u32)f_array_push(&g->cv_types, cv_type);
	}

	f_array_push(&g->proc_info->dbginfo_locals, dbginfo_local);
}

static gmmcProc* gen_procedure(Gen* g, ffzNodeOpInst inst) {
	auto insertion = f_map64_insert(&g->proc_from_hash, ffz_hash_node_inst(inst), (ProcInfo*)0, fMapInsert_DoNotOverride);
	if (!insertion.added) return (*insertion._unstable_ptr)->gmmc_proc;

	ffzType* proc_type = ffz_expr_get_type(g->project, inst);
	F_ASSERT(proc_type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = proc_type->Proc.out_param ? proc_type->Proc.out_param->type : NULL;
	bool big_return = has_big_return(proc_type);
	
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
		
		// NOTE: [3]u8 is not direct, and it does indeed get the type 'ptr', but since it's small, its stored directly
		// in the parameter (as per X64 calling convention)
		gmmcType param_type = value_is_direct(param->type) ? get_gmmc_type(g, param->type) : gmmcType_ptr;
		f_array_push(&param_types, param_type);
	}

	fString name = make_name(g, inst);
	//if (name == F_LIT("arena_push")) F_BP;
	gmmcProcSignature* sig = gmmc_make_proc_signature(g->gmmc, ret_type_gmmc, param_types.data, (u32)param_types.len);

	gmmcBasicBlock* entry_bb;
	
	gmmcProc* proc = gmmc_make_proc(g->gmmc, sig, name, &entry_bb);
	
	ProcInfo* proc_info = f_mem_clone(ProcInfo{}, g->alc);
	proc_info->gmmc_proc = proc;
	proc_info->node = inst.node;
	proc_info->type = proc_type;
	proc_info->dbginfo_locals = f_array_make<DebugInfoLocal>(g->alc);
	proc_info->dbginfo_lines = f_array_make<DebugInfoLine>(g->alc);

	f_array_push(&g->procs_sorted, proc_info);
	*insertion._unstable_ptr = proc_info;

	if (inst.node->Op.left->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		F_BP;//gen_statement(g, ICHILD(left, out_parameter));
	}

	gmmcProc* proc_before = g->proc;
	gmmcBasicBlock* bb_before = g->bb;
	ProcInfo* proc_info_before = g->proc_info;
	g->proc_info = proc_info;
	g->proc = proc;
	g->bb = entry_bb;

	ffzNodeProcTypeInst proc_type_inst = proc_type->unique_node;
	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, proc_type_inst) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];
		
		F_ASSERT(n.node->kind == ffzNodeKind_Declare);
		ffzNodeIdentifierInst param_definition = CHILD(n, Op.left);
		param_definition.polymorph = inst.polymorph; // hmmm...
		ffzNodeInstHash hash = ffz_hash_node_inst(param_definition);

		gmmcOpIdx param_addr = gmmc_op_addr_of_param(proc, i + (u32)big_return);
		
		Value val = {};
		val.local_addr = param_addr;
		add_dbginfo_local(g, param->name->Identifier.name, val.local_addr, param->type, param->type->size > 8);
		
		if (param->type->size > 8) {
			// This is Microsoft-X64 calling convention specific!
			// NOTE: we can't do gmmc_op_load here, because we can't access a values from other BBs.
			val.local_addr_is_indirect = true;
			//val.local_addr = gmmc_op_load(entry_bb, gmmcType_ptr, val.local_addr);
		}

		f_map64_insert(&g->value_from_definition, hash, val);
		i++;
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_statement(g, n);
	}
	
	if (!proc_type->Proc.out_param) { // automatically generate a return statement if the proc doesn't return a value
		gmmcOpIdx op = gmmc_op_return(g->bb, GMMC_OP_IDX_INVALID);
		set_dbginfo_loc(g, op, inst.node->loc.end.line_num);
	}

	g->proc_info = proc_info_before;
	g->proc = proc_before;
	g->bb = bb_before;
	
	//gmmc_proc_print(
	//f_cprint("\n");
	//tb_function_print(func, tb_default_print_callback, stdout, false);
	//f_cprint("\n");

	//bool ok = tb_module_compile_function(g->gmmc, func, TB_ISEL_FAST);
	//F_ASSERT(ok);

	return proc;
}


static gmmcOpIdx gen_call(Gen* g, ffzNodeOpInst inst) {
	ffzNodeInst left = CHILD(inst,Op.left);
	ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
	F_ASSERT(left_chk.type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = left_chk.type->Proc.out_param ? left_chk.type->Proc.out_param->type : NULL;
	bool big_return = has_big_return(left_chk.type); // :BigReturn
	
	gmmcType ret_type_gmmc = big_return ? gmmcType_ptr :
		ret_type ? get_gmmc_type(g, ret_type) : gmmcType_None;

	fArray(gmmcOpIdx) args = f_array_make<gmmcOpIdx>(g->alc);

	gmmcOpIdx out = {};
	if (big_return) {
		out = gmmc_op_local(g->proc, ret_type->size, ret_type->align);
		f_array_push(&args, out);
	}

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, inst) {
		ffzType* param_type = left_chk.type->Proc.in_params[i].type;
		gmmcOpIdx arg = gen_expr(g, n);
		

		if (param_type->size > 8) {
			// make a copy on the stack for the parameter
			gmmcOpIdx local_copy_addr = gmmc_op_local(g->proc, param_type->size, param_type->align);
			gmmc_op_memcpy(g->bb, local_copy_addr, arg, gmmc_op_i32(g->proc, param_type->size));
			f_array_push(&args, local_copy_addr);
		}
		else {
			if (!value_is_direct(param_type)) {
				// we need to do this to make sure we aren't reading out of bounds memory
				gmmcOpIdx local_copy_addr = gmmc_op_local(g->proc, 8, 8);
				gmmc_op_memcpy(g->bb, local_copy_addr, arg, gmmc_op_i32(g->proc, param_type->size));
				f_array_push(&args, gmmc_op_load(g->bb, gmmcType_i64, local_copy_addr));
			}
			else {
				f_array_push(&args, arg);
			}
		}
		i++;
	}

	// TODO: non-vcall for constant procedures

	gmmcOpIdx target = gen_expr(g, left, false);
	F_ASSERT(target);

	gmmcOpIdx return_val = gmmc_op_vcall(g->bb, ret_type_gmmc, target, args.data, (u32)args.len);
	if (!big_return) out = return_val;

	return out;
}

//static gmmcOpIdx load_small(Gen* g, gmmcOpIdx ptr, ffzType* type) {
//	if (type->size == 1 || type->size == 2 || type->size == 4 || type->size == 8) {
//		return gmmc_op_load(g->bb, get_gmmc_type(g, type), ptr);
//	}
//	else F_BP; // TODO!! i.e. a type could be of size 3, when [3]u8
//	return 0;
//}

static gmmcSymbol* get_proc_symbol(Gen* g, ffzNodeInst proc_node) {
	if (proc_node.node->kind == ffzNodeKind_ProcType) { // @extern proc
		fString name = make_name(g, proc_node);
		return gmmc_extern_as_symbol(gmmc_make_extern(g->gmmc, name));
	}
	else {
		return gmmc_proc_as_symbol(gen_procedure(g, proc_node));
	}
}

static void gen_global_constant(Gen* g, gmmcGlobal* global, u8* base, u32 offset, ffzType* type, ffzConstant* constant) {
	switch (type->tag) {
	case ffzTypeTag_Float: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultUint: {
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
		gmmcGlobal* str_data_global = gmmc_make_global(g->gmmc, (u32)s.len + 1, 1, gmmcSection_RData, &str_data);
		memcpy(str_data, s.data, s.len);
		((u8*)str_data)[s.len] = 0; // zero-termination

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

static gmmcOpIdx gen_store(Gen* g, gmmcOpIdx addr, gmmcOpIdx value, ffzType* type) {
	if (value_is_direct(type)) {
		return gmmc_op_store(g->bb, addr, value);
	}
	else {
		return gmmc_op_memcpy(g->bb, addr, value, gmmc_op_i32(g->proc, type->size));
	}
}

static gmmcOpIdx gen_expr(Gen* g, ffzNodeInst inst, bool address_of) {
	gmmcOpIdx out = {};

	ffzCheckedExpr checked = ffz_expr_get_checked(g->project, inst);
	F_ASSERT(ffz_type_is_grounded(checked.type));

	F_ASSERT(inst.node->kind != ffzNodeKind_Declare);
	if (checked.const_val) {
		switch (checked.type->tag) {
		case ffzTypeTag_Bool: {
			F_ASSERT(!address_of);
			out = gmmc_op_bool(g->proc, checked.const_val->bool_);
		} break;

		case ffzTypeTag_Float: {
			if (checked.type->size == 4)      out = gmmc_op_f32(g->proc, checked.const_val->f32_);
			else if (checked.type->size == 8) out = gmmc_op_f64(g->proc, checked.const_val->f64_);
			else F_BP;
		} break;

		case ffzTypeTag_Enum: // fallthrough
		case ffzTypeTag_Sint: // fallthrough
		case ffzTypeTag_DefaultSint: // fallthrough
		case ffzTypeTag_Uint: // fallthrough
		case ffzTypeTag_DefaultUint: {
			F_ASSERT(!address_of);
			if (checked.type->size == 1)      out = gmmc_op_i8(g->proc, checked.const_val->u8_);
			else if (checked.type->size == 2) out = gmmc_op_i16(g->proc, checked.const_val->u16_);
			else if (checked.type->size == 4) out = gmmc_op_i32(g->proc, checked.const_val->u32_);
			else if (checked.type->size == 8) out = gmmc_op_i64(g->proc, checked.const_val->u64_);
			else F_BP;
		} break;

		case ffzTypeTag_Proc: {
			F_ASSERT(!address_of);
			out = gmmc_op_addr_of_symbol(g->proc, get_proc_symbol(g, checked.const_val->proc_node));
		} break;

		case ffzTypeTag_Slice: // fallthrough
		case ffzTypeTag_String: // fallthrough
		case ffzTypeTag_FixedArray: // fallthrough
		case ffzTypeTag_Record: {
			void* global_data;
			gmmcGlobal* global = gmmc_make_global(g->gmmc, checked.type->size, checked.type->align, gmmcSection_RData, &global_data);
			
			gen_global_constant(g, global, (u8*)global_data, 0, checked.type, checked.const_val);

			out = gmmc_op_addr_of_symbol(g->proc, gmmc_global_as_symbol(global));
			
			if (!address_of && value_is_direct(checked.type)) {
				out = gmmc_op_load(g->bb, get_gmmc_type(g, checked.type), out);
			}
		} break;

		default: F_BP;
		}

		return out;
	}

	bool should_dereference = false;
	bool should_take_address = false;

	if (ffz_node_is_operator(inst.node->kind)) {
		ffzNodeInst left = CHILD(inst, Op.left);
		ffzNodeInst right = CHILD(inst, Op.right);

		switch (inst.node->kind) {

		case ffzNodeKind_Add: case ffzNodeKind_Sub:
		case ffzNodeKind_Mul: case ffzNodeKind_Div:
		case ffzNodeKind_Modulo: case ffzNodeKind_Equal:
		case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
		case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater:
		case ffzNodeKind_GreaterOrEqual:
		{
			F_ASSERT(!address_of);
			ffzType* input_type = ffz_expr_get_type(g->project, left);
			bool is_signed = ffz_type_is_signed_integer(input_type->tag);
			
			// TODO: more operator defines. I guess we should do this together with the fix for vector math
			F_ASSERT(value_is_direct(input_type));
			
			gmmcOpIdx a = gen_expr(g, left);
			gmmcOpIdx b = gen_expr(g, right);

			switch (inst.node->kind) {
			case ffzNodeKind_Add: { out = gmmc_op_add(g->bb, a, b); } break;
			case ffzNodeKind_Sub: { out = gmmc_op_sub(g->bb, a, b); } break;
			case ffzNodeKind_Mul: { out = gmmc_op_mul(g->bb, a, b, is_signed); } break;
			case ffzNodeKind_Div: { out = gmmc_op_div(g->bb, a, b, is_signed); } break;
			case ffzNodeKind_Modulo: { out = gmmc_op_mod(g->bb, a, b, is_signed); } break;

			case ffzNodeKind_Equal: { out = gmmc_op_eq(g->bb, a, b); } break;
			case ffzNodeKind_NotEqual: { out = gmmc_op_ne(g->bb, a, b); } break;
			case ffzNodeKind_Less: { out = gmmc_op_lt(g->bb, a, b, is_signed); } break;
			case ffzNodeKind_LessOrEqual: { out = gmmc_op_le(g->bb, a, b, is_signed); } break;
			case ffzNodeKind_Greater: { out = gmmc_op_gt(g->bb, a, b, is_signed); } break;
			case ffzNodeKind_GreaterOrEqual: { out = gmmc_op_ge(g->bb, a, b, is_signed); } break;

			default: F_BP;
			}
		} break;

		case ffzNodeKind_UnaryMinus: {
			F_ASSERT(!address_of);
			u64 zero = 0;
			out = gen_expr(g, right);
			out = gmmc_op_sub(g->bb, gmmc_op_immediate(g->proc, get_gmmc_type(g, checked.type), &zero), out);  // -x = 0 - x
		} break;

		case ffzNodeKind_LogicalNOT: {
			F_ASSERT(!address_of);
			// (!x) is equivalent to (x == false)
			out = gmmc_op_eq(g->bb, gen_expr(g, right), gmmc_op_bool(g->proc, false));
		} break;

		case ffzNodeKind_PostRoundBrackets: {
			// sometimes we need to take the address of a temporary.
			// e.g.  copy_string("hello").ptr
			should_take_address = address_of;

			if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(left.node->Keyword.keyword)) {
				ffzKeyword keyword = left.node->Keyword.keyword;

				gmmcOpIdx first = gen_expr(g, ffz_get_child_inst(inst, 0));
				if (keyword == ffzKeyword_bit_not) {
					out = gmmc_op_not(g->bb, first);
				}
				else {
					gmmcOpIdx second = gen_expr(g, ffz_get_child_inst(inst, 1));
					switch (keyword) {
					case ffzKeyword_bit_and: { out = gmmc_op_and(g->bb, first, second); } break;
					case ffzKeyword_bit_or: { out = gmmc_op_or(g->bb, first, second); } break;
					case ffzKeyword_bit_xor: { out = gmmc_op_xor(g->bb, first, second); } break;
					case ffzKeyword_bit_shl: { out = gmmc_op_shl(g->bb, first, gmmc_op_int2int(g->bb, second, gmmcType_i8, false)); } break;
					case ffzKeyword_bit_shr: { out = gmmc_op_shr(g->bb, first, gmmc_op_int2int(g->bb, second, gmmcType_i8, false)); } break;
					default: F_BP;
					}
				}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				if (left_chk.type->tag == ffzTypeTag_Type) {
					ffzType* dst_type = left_chk.const_val->type;
					// type cast, e.g. u32(5293900)

					ffzNodeInst arg = ffz_get_child_inst(inst, 0);
					ffzType* arg_type = ffz_expr_get_type(g->project, arg);

					out = gen_expr(g, arg);
					if (ffz_type_is_pointer_ish(dst_type->tag)) { // cast to pointer
						if (ffz_type_is_pointer_ish(arg_type->tag)) {}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							out = gmmc_op_int2ptr(g->bb, out);
						}
					}
					else if (ffz_type_is_integer_ish(dst_type->tag)) { // cast to integer
						gmmcType dt = get_gmmc_type(g, dst_type);
						if (ffz_type_is_pointer_ish(arg_type->tag)) {
							out = gmmc_op_ptr2int(g->bb, out);
						}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							// integer -> integer cast
							out = gmmc_op_int2int(g->bb, out, dt, ffz_type_is_signed_integer(dst_type->tag));
							//if (dst_type->size > arg_type->size) {
							//	
							//	if (ffz_type_is_signed_integer(dst_type->tag)) {
							//		out = gmmc_op_sxt(g->bb, out, dt);  // sign extend
							//	}
							//	else {
							//		out = gmmc_op_zxt(g->bb, out, dt);  // zero extend
							//	}
							//}
							//else if (dst_type->size < arg_type->size) {
							//	out = gmmc_op_trunc(g->bb, out, dt);
							//}
						}
						else { todo; }
					}
					else if (ffz_type_is_slice_ish(dst_type->tag) && ffz_type_is_slice_ish(arg_type->tag)) {} // only a semantic cast
					else todo;
				}
				else {
					out = gen_call(g, inst);
				}
			}
		} break;

		case ffzNodeKind_AddressOf: {
			F_ASSERT(!address_of);
			out = gen_expr(g, right, true);
		} break;

		case ffzNodeKind_Dereference: {
			out = gen_expr(g, left);
			should_dereference = !address_of;
		} break;

		case ffzNodeKind_MemberAccess: {
			fString member_name = right.node->Identifier.name;

			if (left.node->kind == ffzNodeKind_Identifier && left.node->Identifier.name == F_LIT("in")) {
				//F_ASSERT(!address_of); // TODO
				
				bool found = false;
				for (u32 i = 0; i < g->proc_info->type->Proc.in_params.len; i++) {
					ffzTypeProcParameter& param = g->proc_info->type->Proc.in_params[i];
					if (param.name->Identifier.name == member_name) {
						out = gmmc_op_addr_of_param(g->proc, i + (u32)has_big_return(g->proc_info->type));
						F_ASSERT(value_is_direct(param.type));
						found = true;
						//out = gmmc_op_load(g->bb, param.type
						//F_BP;//out = gmmc_op_param(g->proc, ));
					}
				}
				F_ASSERT(found);
			}
			else {
				//F_HITS(____c, 61);
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				ffzType* struct_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;

				ffzTypeRecordFieldUse field;
				F_ASSERT(ffz_type_find_record_field_use(g->project, struct_type, member_name, &field));

				gmmcOpIdx addr_of_struct = gen_expr(g, left, left_chk.type->tag != ffzTypeTag_Pointer);
				F_ASSERT(addr_of_struct);

				out = field.offset ? gmmc_op_member_access(g->bb, addr_of_struct, field.offset) : addr_of_struct;
			}
			should_dereference = !address_of;
		} break;

		case ffzNodeKind_PostCurlyBrackets: {
			// dynamic initializer
			out = gmmc_op_local(g->proc, checked.type->size, checked.type->align);
			//out.ptr_can_be_stolen = true;
			//F_ASSERT(checked.type->size > 8);

			if (checked.type->tag == ffzTypeTag_Record) {
				u32 i = 0;
				for FFZ_EACH_CHILD_INST(n, inst) {
					ffzTypeRecordField& field = checked.type->record_fields[i];

					gmmcOpIdx src = gen_expr(g, n);
					gmmcOpIdx dst_ptr = gmmc_op_member_access(g->bb, out, field.offset);
					gen_store(g, dst_ptr, src, field.type);
					i++;
				}
			}
			else if (checked.type->tag == ffzTypeTag_FixedArray) {
				u32 i = 0;
				ffzType* elem_type = checked.type->FixedArray.elem_type;
				for FFZ_EACH_CHILD_INST(n, inst) {
					gmmcOpIdx src = gen_expr(g, n, false);
					gmmcOpIdx dst_ptr = gmmc_op_member_access(g->bb, out, i * elem_type->size);
					gen_store(g, dst_ptr, src, elem_type);
					i++;
				}
			}
			else F_BP;

			should_dereference = !address_of;
			//if (!address_of && checked.type->size <= 8) {
			//	out = load_small(g, out, checked.type->size);
			//}
		} break;

		case ffzNodeKind_PostSquareBrackets: {
			ffzType* left_type = ffz_expr_get_type(g->project, left);
			F_ASSERT(left_type->tag == ffzTypeTag_FixedArray || left_type->tag == ffzTypeTag_Slice);

			ffzType* elem_type = left_type->tag == ffzTypeTag_Slice ? left_type->Slice.elem_type : left_type->FixedArray.elem_type;

			gmmcOpIdx left_value = gen_expr(g, left, true);
			gmmcOpIdx array_data = left_value;

			if (left_type->tag == ffzTypeTag_Slice) {
				array_data = gmmc_op_load(g->bb, gmmcType_ptr, array_data);
			}

			if (ffz_get_child_count(inst.node) == 2) { // slicing
				ffzNodeInst lo_inst = ffz_get_child_inst(inst, 0);
				ffzNodeInst hi_inst = ffz_get_child_inst(inst, 1);

				gmmcOpIdx lo = lo_inst.node->kind == ffzNodeKind_Blank ? gmmc_op_i64(g->proc, 0) : gen_expr(g, lo_inst);
				gmmcOpIdx hi;
				if (hi_inst.node->kind == ffzNodeKind_Blank) {
					if (left_type->tag == ffzTypeTag_FixedArray) {
						hi = gmmc_op_i64(g->proc, left_type->FixedArray.length);
					}
					else {
						// load the 'len' field of a slice
						hi = gmmc_op_load(g->bb, gmmcType_i64, gmmc_op_member_access(g->bb, left_value, 8));
					}
				}
				else {
					hi = gen_expr(g, hi_inst);
				}

				out = gmmc_op_local(g->proc, 16, 8);
				lo = gmmc_op_int2int(g->bb, lo, gmmcType_i32, false);
				hi = gmmc_op_int2int(g->bb, hi, gmmcType_i32, false);
				gmmcOpIdx ptr = gmmc_op_array_access(g->bb, array_data, lo, elem_type->size);
				gmmcOpIdx len = gmmc_op_sub(g->bb, hi, lo);

				gmmc_op_store(g->bb, out, ptr);
				gmmc_op_store(g->bb, gmmc_op_member_access(g->bb, out, 8), len);
			}
			else { // taking an index
				ffzNodeInst index_node = ffz_get_child_inst(inst, 0);
				
				gmmcOpIdx index = gen_expr(g, index_node);
				index = gmmc_op_int2int(g->bb, index, gmmcType_i64, false);
				out = gmmc_op_array_access(g->bb, array_data, index, elem_type->size);

				should_dereference = !address_of;
			}
		} break;

		case ffzNodeKind_LogicalOR: // fallthrough
		case ffzNodeKind_LogicalAND: {
			gmmcOpIdx left_val = gen_expr(g, left);

			// implement short-circuiting

			gmmcBasicBlock* test_right_bb = gmmc_make_basic_block(g->proc);
			gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);

			gmmcOpIdx result = gmmc_op_local(g->proc, 1, 1);
			if (inst.node->kind == ffzNodeKind_LogicalAND) {
				gmmc_op_store(g->bb, result, gmmc_op_bool(g->proc, false));
				gmmc_op_if(g->bb, left_val, test_right_bb, after_bb);
			}
			else {
				gmmc_op_store(g->bb, result, gmmc_op_bool(g->proc, true));
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
	}
	else {
		switch (inst.node->kind) {
		case ffzNodeKind_Identifier: {
			ffzNodeIdentifierInst def = ffz_get_definition(g->project, inst);
			if (def.node->Identifier.is_constant) F_BP;

			Value* val = f_map64_get(&g->value_from_definition, ffz_hash_node_inst(def));
			F_ASSERT(val);

			out = val->symbol ? gmmc_op_addr_of_symbol(g->proc, val->symbol) : val->local_addr;
			if (val->local_addr_is_indirect) {
				out = gmmc_op_load(g->bb, gmmcType_ptr, out);
			}

			should_dereference = !address_of;
		} break;

		case ffzNodeKind_ThisValueDot: {
			ffzNodeInst assignee;
			F_ASSERT(ffz_dot_get_assignee(inst, &assignee));
			out = gen_expr(g, assignee, address_of);
		} break;
		}
	}

	F_ASSERT(out);
	
	if (should_dereference) {
		F_ASSERT(!should_take_address);
		if (value_is_direct(checked.type)) {
			//out = load_small(g, out, checked.type);
			out = gmmc_op_load(g->bb, get_gmmc_type(g, checked.type), out);
		}
	}
	if (should_take_address) {
		F_ASSERT(!should_dereference);
		if (value_is_direct(checked.type)) {
			gmmcOpIdx tmp = gmmc_op_local(g->proc, checked.type->size, checked.type->align);
			gmmc_op_store(g->bb, tmp, out);
			out = tmp;
		}
	}

	return out;
}

static bool node_is_keyword(ffzNode* node, ffzKeyword keyword) { return node->kind == ffzNodeKind_Keyword && node->Keyword.keyword == keyword; }

static void gen_statement(Gen* g, ffzNodeInst inst, u32 overwrite_line_num) {
	if (g->proc) {
		//gmmc_op_comment(g->bb, fString{}); // empty line
		if (inst.node->kind == ffzNodeKind_Scope) {}
		else if (inst.node->kind == ffzNodeKind_If) {}
		else if (inst.node->kind == ffzNodeKind_For) {}
		else if (node_is_keyword(inst.node, ffzKeyword_dbgbreak)) {}
		else {
			ffzParser* parser = g->project->parsers[inst.node->id.parser_id];
			u32 start = inst.node->loc.start.offset;
			u32 end = inst.node->loc.end.offset;
			gmmc_op_comment(g->bb, fString{ parser->source_code.data + start, end - start });
		}
	}
	
	u32 line_num = overwrite_line_num ? overwrite_line_num : inst.node->loc.start.line_num;

	switch (inst.node->kind) {
		
	case ffzNodeKind_Declare: {
		ffzNodeIdentifierInst definition = CHILD(inst,Op.left);
		ffzCheckedExpr checked = ffz_decl_get_checked(g->project, inst);

		if (ffz_decl_is_runtime_variable(inst.node)) {
			ffzNodeInst rhs = CHILD(inst, Op.right);
			Value val = {};
			if (ffz_get_tag(g->project, inst, ffzKeyword_global)) {
				ffzCheckedExpr rhs_checked = ffz_decl_get_checked(g->project, rhs); // get the initial value
				
				void* global_data;
				gmmcGlobal* global = gmmc_make_global(g->gmmc, rhs_checked.type->size, rhs_checked.type->align, gmmcSection_Data, &global_data);

				gen_global_constant(g, global, (u8*)global_data, 0, rhs_checked.type, rhs_checked.const_val);
				val.symbol = gmmc_global_as_symbol(global);
			}
			else {
				gmmcOpIdx rhs_value = gen_expr(g, rhs);
				set_dbginfo_loc(g, rhs_value, line_num);
				val.local_addr = gmmc_op_local(g->proc, checked.type->size, checked.type->align);

				add_dbginfo_local(g, definition.node->Identifier.name, val.local_addr, checked.type);

				set_dbginfo_loc(g, gen_store(g, val.local_addr, rhs_value, checked.type), line_num);
			}
			f_map64_insert(&g->value_from_definition, ffz_hash_node_inst(definition), val);
		}
		else {
			// need to still generate exported procs
			if (checked.type->tag == ffzTypeTag_Proc) {
				ffzNodeInst rhs = CHILD(inst,Op.right);
				if (rhs.node->kind == ffzNodeKind_PostCurlyBrackets) { // @extern procs also have the type ffzTypeTag_Proc so we need to ignore those
					gen_procedure(g, rhs);
				}
			}
		}
	} break;

	case ffzNodeKind_Assign: {
		ffzNodeInst lhs = CHILD(inst,Op.left);
		ffzNodeInst rhs = CHILD(inst,Op.right);
		gmmcOpIdx lhs_addr = gen_expr(g, lhs, true);
		
		gmmcOpIdx rhs_value = gen_expr(g, rhs);
		set_dbginfo_loc(g, gen_store(g, lhs_addr, rhs_value, ffz_expr_get_type(g->project, rhs)), line_num);
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		gmmcOpIdx cond = gen_expr(g, CHILD(inst, If.condition));
		set_dbginfo_loc(g, cond, line_num);

		gmmcBasicBlock* true_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* false_bb;
		if (inst.node->If.else_scope) {
			false_bb = gmmc_make_basic_block(g->proc);
		}

		gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);
		set_dbginfo_loc(g, gmmc_op_if(g->bb, cond, true_bb, inst.node->If.else_scope ? false_bb : after_bb), line_num);
		g->bb = true_bb;
		gen_statement(g, CHILD(inst,If.true_scope));
		gmmc_op_goto(g->bb, after_bb);

		if (inst.node->If.else_scope) {
			g->bb = false_bb;
			gen_statement(g, CHILD(inst,If.else_scope));
			gmmc_op_goto(g->bb, after_bb);
		}

		g->bb = after_bb;
	} break;

	case ffzNodeKind_For: {
		ffzNodeInst pre = CHILD(inst,For.header_stmts[0]);
		ffzNodeInst condition = CHILD(inst,For.header_stmts[1]);
		ffzNodeInst post = CHILD(inst,For.header_stmts[2]);
		ffzNodeInst body = CHILD(inst,For.scope);
		
		if (pre.node) gen_statement(g, pre);
		
		gmmcBasicBlock* cond_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* body_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);
		gmmc_op_goto(g->bb, cond_bb);

		if (!condition.node) F_BP; // TODO
		
		g->bb = cond_bb;
		gmmcOpIdx cond = gen_expr(g, condition);
		gmmc_op_if(g->bb, cond, body_bb, after_bb);

		g->bb = body_bb;
		gen_statement(g, body);
			
		if (post.node) {
			gen_statement(g, post, body.node->loc.end.line_num); // let's override the loc to be at the end of the body scope
			//set_dbginfo_loc(g, 
		}
		//inst_loc(g, inst.node, );
		//if (post.node) gen_statement(g, post, false); 

		gmmc_op_goto(g->bb, cond_bb);

		g->bb = after_bb;
	} break;

	case ffzNodeKind_Keyword: {
		//if (inst.node->kind == ffzNodeKind_Keyword) { // debugbreak()
		//}

		set_dbginfo_loc(g, gmmc_op_debugbreak(g->bb), line_num);
	} break;

	case ffzNodeKind_Return: {
		ffzNodeReturnInst ret = inst;
		gmmcOpIdx val = 0;

		if (ret.node->Return.value) {
			ffzType* ret_type = ffz_expr_get_type(g->project, CHILD(ret,Return.value));
			gmmcOpIdx return_value = gen_expr(g, CHILD(ret,Return.value));
			if (ret_type->size > 8) {
				val = gmmc_op_load(g->bb, gmmcType_ptr, gmmc_op_addr_of_param(g->proc, 0)); // :BigReturn
				gmmc_op_memcpy(g->bb, val, return_value, gmmc_op_i32(g->proc, ret_type->size));
			}
			else {
				val = return_value;
			}
		}

		set_dbginfo_loc(g, gmmc_op_return(g->bb, val), line_num);
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		set_dbginfo_loc(g, gen_call(g, inst), line_num);
	} break;

	default: F_BP;
	}

}

// TODO: command-line option for console/no console
const bool BUILD_WITH_CONSOLE = true;

enum SectionNum {
	SectionNum_Code = 1,
	SectionNum_Data,
	SectionNum_RData,
	
	// Optional, required for debug info
	SectionNum_xdata,
	SectionNum_pdata,
	SectionNum_debugS,
	SectionNum_debugT,
	//SectionNum_Data = 2,
	//SectionNum_RData = 3,
	//SectionNum_BSS = 4,
};

static u32 build_x64_section_get_sym_idx(SectionNum section) {
	return (u32)section - 1; // sections come first in the symbol table
}

static SectionNum build_x64_section_num_from_gmmc_section(gmmcSection section) {
	switch (section) {
	case gmmcSection_Code: return SectionNum_Code;
	case gmmcSection_Data: return SectionNum_Data;
	case gmmcSection_RData: return SectionNum_RData;
	}
	F_BP; return {};
}

static void build_x64_add_section_relocs(Gen* g, gmmcAsmModule* asm_mod, gmmcSection gmmc_section,
	coffSection* sect, u32 first_external_symbol_index)
{
	fSlice(gmmcRelocation) relocs;
	gmmc_asm_get_section_relocations(asm_mod, gmmc_section, &relocs);

	fSlice(coffRelocation) coff_relocs = f_make_slice_garbage<coffRelocation>(relocs.len, g->alc);

	for (uint i = 0; i < relocs.len; i++) {
		gmmcRelocation reloc = relocs[i];
		coffRelocation* coff_reloc = &coff_relocs[i];

		if (reloc.target->kind == gmmcSymbolKind_Global) {
			gmmcGlobal* target = (gmmcGlobal*)reloc.target;

			u32 target_offset = gmmc_asm_global_get_offset(asm_mod, target);
			SectionNum target_section_num = build_x64_section_num_from_gmmc_section(target->section);

			// We need to add the offset of the target into the relocation value
			u64* reloc_value = (u64*)(sect->data.data + reloc.offset);
			*reloc_value += target_offset;

			// So the runtime address of the sym_idx (the section of the target global) will be
			// added to the relocation value, which is the offset of the target global within its section +
			// the value that was there before
			coff_reloc->sym_idx = build_x64_section_get_sym_idx(target_section_num);
		}
		else if (reloc.target->kind == gmmcSymbolKind_Proc) {
			gmmcProc* target = (gmmcProc*)reloc.target;

			u32 target_offset = gmmc_asm_proc_get_start_offset(asm_mod, target);
			u64* reloc_value = (u64*)(sect->data.data + reloc.offset);
			*reloc_value += target_offset;

			coff_reloc->sym_idx = build_x64_section_get_sym_idx(SectionNum_Code);
		}
		else {
			gmmcExtern* target = (gmmcExtern*)reloc.target;
			coff_reloc->sym_idx = first_external_symbol_index + target->self_idx;
		}

		coff_reloc->offset = reloc.offset;
		coff_reloc->type = IMAGE_REL_AMD64_ADDR64;
	}

	sect->relocations = coff_relocs.data;
	sect->relocations_count = (u32)coff_relocs.len;
}

static void build_x64_add_section(Gen* g, gmmcAsmModule* asm_module, fArray(coffSection)* sections,
	gmmcSection gmmc_section, fString name, coffSectionCharacteristics flags)
{
	coffSection sect = {};
	sect.name = name;
	sect.Characteristics = flags | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_READ;
	sect.data = gmmc_asm_get_section_data(asm_module, gmmc_section);
	f_array_push(sections, sect);
}

static int cviewLine_compare_fn(const void* a, const void* b) {
	return ((cviewLine*)a)->offset - ((cviewLine*)b)->offset;
}

static bool build_x64(Gen* g, fString build_dir) {
	gmmcAsmModule* asm_module = gmmc_asm_build_x64(g->gmmc);

	const bool INCLUDE_DEBUG_INFO = true;

	// TODO: have a strict temp scope here
	
	// Add codeview debug info to the object file

	fArray(coffSection) sections = f_array_make<coffSection>(g->alc);
	fArray(coffSymbol) symbols = f_array_make<coffSymbol>(g->alc);
	
	build_x64_add_section(g, asm_module, &sections, gmmcSection_Code, F_LIT(".code"), IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
	build_x64_add_section(g, asm_module, &sections, gmmcSection_Data, F_LIT(".data"), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_WRITE);
	build_x64_add_section(g, asm_module, &sections, gmmcSection_RData, F_LIT(".rdata"), IMAGE_SCN_CNT_INITIALIZED_DATA);

	if (INCLUDE_DEBUG_INFO) {
		{
			coffSection sect = {};
			sect.name = F_LIT(".xdata");
			sect.Characteristics = 0x40300040;
			f_array_push(&sections, sect);
		}

		{
			coffSection sect = {};
			sect.name = F_LIT(".pdata");
			sect.Characteristics = 0x40300040;
			f_array_push(&sections, sect);
		}

		{
			coffSection sect = {};
			sect.name = F_LIT(".debug$S");
			sect.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_READ;
			f_array_push(&sections, sect);
		}

		{
			coffSection sect = {};
			sect.name = F_LIT(".debug$T");
			sect.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_READ;
			f_array_push(&sections, sect);
		}
	}

	for (u16 i = 0; i < sections.len; i++) { // add sections as symbols
		coffSymbol sym = {};
		sym.name = sections[i].name;
		sym.is_section = true;
		sym.section_number = i + 1;
		f_array_push(&symbols, sym);
	}
	
	u32 first_external_symbol_index = (u32)symbols.len;

	// then external symbols
	for (uint i = 0; i < g->gmmc->external_symbols.len; i++) {
		gmmcExtern* extern_sym = g->gmmc->external_symbols[i];
		coffSymbol sym = {};
		sym.section_number = IMAGE_SYM_UNDEFINED;
		sym.is_external = true;
		sym.type = 0x20;
		sym.name = extern_sym->sym.name;
		f_array_push(&symbols, sym);
	}

	// When we add the relocations, we need to know the symbol index of the first external symbol
	build_x64_add_section_relocs(g, asm_module, gmmcSection_Code, &sections[0], first_external_symbol_index);
	build_x64_add_section_relocs(g, asm_module, gmmcSection_Data, &sections[1], first_external_symbol_index);
	build_x64_add_section_relocs(g, asm_module, gmmcSection_RData, &sections[2], first_external_symbol_index);

	fArray(cviewFunction) cv_functions = f_array_make_cap<cviewFunction>(g->proc_from_hash.alive_count, g->alc);

	// the procs need to be sorted for debug info
	for (uint i = 0; i < g->procs_sorted.len; i++) {
		ProcInfo* proc_info = g->procs_sorted[i];
		gmmcProc* proc = proc_info->gmmc_proc;

		u32 start_offset = gmmc_asm_proc_get_start_offset(asm_module, proc);

		coffSymbol sym = {};
		sym.name = proc->sym.name;
		sym.type = 0x20;
		sym.section_number = SectionNum_Code;
		sym.value = start_offset;
		sym.is_external = true;
		u32 sym_idx = (u32)f_array_push(&symbols, sym);

		if (INCLUDE_DEBUG_INFO) {
			cviewFunction cv_func = {};
			cv_func.name = proc->sym.name;
			cv_func.sym_index = sym_idx;
			cv_func.section_sym_index = build_x64_section_get_sym_idx(SectionNum_Code);
			cv_func.size_of_initial_sub_rsp_instruction = gmmc_asm_proc_get_prolog_size(asm_module, proc);
			cv_func.stack_frame_size = gmmc_asm_proc_get_stack_frame_size(asm_module, proc);
			cv_func.file_idx = proc_info->node->id.parser_id;

			fArray(cviewLocal) locals = f_array_make_cap<cviewLocal>(proc_info->dbginfo_locals.len, g->alc);
			for (uint i = 0; i < proc_info->dbginfo_locals.len; i++) {
				DebugInfoLocal it = proc_info->dbginfo_locals[i];
				cviewLocal local;
				local.name = it.name;
				local.rsp_rel_offset = gmmc_asm_get_frame_rel_offset(asm_module, proc, it.local_or_param) + cv_func.stack_frame_size;
				local.type_idx = it.type_idx;
				f_array_push(&locals, local);
			}

			cv_func.block.locals = locals.data;
			cv_func.block.locals_count = (u32)locals.len;

			fArray(cviewLine) lines = f_array_make_cap<cviewLine>(proc_info->dbginfo_lines.len + 1, g->alc);
			f_array_push(&lines, cviewLine{ proc_info->node->loc.start.line_num, start_offset });

			for (uint i = 0; i < proc_info->dbginfo_lines.len; i++) {
				//if (i == 6) F_BP;
				DebugInfoLine it = proc_info->dbginfo_lines[i];
				cviewLine line;
				line.line_num = it.line_number;
				line.offset = gmmc_asm_instruction_get_offset(asm_module, proc, it.op);
				f_array_push(&lines, line);
			}
			
			// we must sort the lines by offset for codeview!!
			qsort(lines.data, lines.len, sizeof(cviewLine), cviewLine_compare_fn);

			cv_func.lines = lines.data;
			cv_func.lines_count = (u32)lines.len;
			cv_func.block.start_offset = start_offset;
			cv_func.block.end_offset = gmmc_asm_proc_get_end_offset(asm_module, proc);
			f_array_push(&cv_functions, cv_func);
		}
	}

	fString obj_file_path = F_STR_T_JOIN(build_dir, F_LIT("\\a.obj"));

	if (INCLUDE_DEBUG_INFO) {
		cviewGenerateDebugInfoDesc cv_desc = {};
		cv_desc.obj_name = obj_file_path;
		cv_desc.files = g->cv_file_from_parser_idx.data;
		cv_desc.files_count = (u32)g->cv_file_from_parser_idx.len;
		cv_desc.functions = cv_functions.data;
		cv_desc.functions_count = (u32)cv_functions.len;
		cv_desc.xdata_section_sym_index = build_x64_section_get_sym_idx(SectionNum_xdata);
		cv_desc.types = g->cv_types.data;
		cv_desc.types_count = (u32)g->cv_types.len;
		codeview_generate_debug_info(&cv_desc, g->alc);

		sections[SectionNum_xdata - 1].data = cv_desc.result.xdata;

		sections[SectionNum_pdata - 1].data = cv_desc.result.pdata;
		sections[SectionNum_pdata - 1].relocations = cv_desc.result.pdata_relocs.data;
		sections[SectionNum_pdata - 1].relocations_count = (u32)cv_desc.result.pdata_relocs.len;

		sections[SectionNum_debugS - 1].data = cv_desc.result.debugS;
		sections[SectionNum_debugS - 1].relocations = cv_desc.result.debugS_relocs.data;
		sections[SectionNum_debugS - 1].relocations_count = (int)cv_desc.result.debugS_relocs.len;

		sections[SectionNum_debugT - 1].data = cv_desc.result.debugT;
	}

	coffDesc coff_desc = {};
	coff_desc.sections = sections.data;
	coff_desc.sections_count = (u32)sections.len;
	coff_desc.symbols = symbols.data;
	coff_desc.symbols_count = (u32)symbols.len;
	
	coff_create([](fString result, void* userptr) {
		fString obj_file_path = *(fString*)userptr;
		
		bool ok = f_files_write_whole(obj_file_path, result);
		F_ASSERT(ok);

		}, & obj_file_path, &coff_desc);


	WinSDK_Find_Result windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
	fString msvc_directory = f_str_from_utf16(windows_sdk.vs_exe_path, g->alc); // contains cl.exe, link.exe
	fString windows_sdk_include_base_path = f_str_from_utf16(windows_sdk.windows_sdk_include_base, g->alc); // contains <string.h>, etc
	fString windows_sdk_um_library_path = f_str_from_utf16(windows_sdk.windows_sdk_um_library_path, g->alc); // contains kernel32.lib, etc
	fString windows_sdk_ucrt_library_path = f_str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, g->alc); // contains libucrt.lib, etc
	fString vs_library_path = f_str_from_utf16(windows_sdk.vs_library_path, g->alc); // contains MSVCRT.lib etc
	fString vs_include_path = f_str_from_utf16(windows_sdk.vs_include_path, g->alc); // contains vcruntime.h

	fArray(fString) ms_linker_args = f_array_make<fString>(g->alc);
	f_array_push(&ms_linker_args, F_STR_T_JOIN(msvc_directory, F_LIT("\\link.exe")));
	f_array_push(&ms_linker_args, obj_file_path);

	f_array_push(&ms_linker_args, F_STR_T_JOIN(F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
	f_array_push(&ms_linker_args, F_STR_T_JOIN(F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
	f_array_push(&ms_linker_args, F_STR_T_JOIN(F_LIT("/LIBPATH:"), vs_library_path));

	f_array_push(&ms_linker_args, F_STR_T_JOIN(F_LIT("/SUBSYSTEM:"), BUILD_WITH_CONSOLE ? F_LIT("CONSOLE") : F_LIT("WINDOWS")));
	f_array_push(&ms_linker_args, F_LIT("/ENTRY:ffz_entry"));
	f_array_push(&ms_linker_args, F_LIT("/INCREMENTAL:NO"));
	f_array_push(&ms_linker_args, F_LIT("/NODEFAULTLIB")); // disable CRT
	f_array_push(&ms_linker_args, F_LIT("/DEBUG"));

	for (uint i = 0; i < g->project->link_libraries.len; i++) {
		f_array_push(&ms_linker_args, g->project->link_libraries[i]);
	}
	for (uint i = 0; i < g->project->link_system_libraries.len; i++) {
		f_array_push(&ms_linker_args, g->project->link_system_libraries[i]);
	}

	// specify reserve and commit for the stack.
	f_array_push(&ms_linker_args, F_LIT("/STACK:0x200000,200000"));

	f_cprint("Running link.exe: ");
	for (uint i = 0; i < ms_linker_args.len; i++) {
		f_cprint("\"~s\" ", ms_linker_args[i]);
	}
	f_cprint("\n");

	u32 exit_code;
	if (!f_os_run_command(ms_linker_args.slice, build_dir, &exit_code)) {
		f_cprint("link.exe couldn't be found! Have you installed visual studio?\n");
		return false;
	}
	return exit_code == 0;
}

static bool build_c(Gen* g, fString build_dir) {
	fString c_file_path = F_STR_T_JOIN(build_dir, F_LIT("/a.c"));
	
	fFile c_file;
	if (!f_files_open(c_file_path, fFileOpenMode_Write, &c_file)) {
		f_cprint("Failed writing temporary C file to disk!\n");
		return false;
	}

	fWriter* c_file_writer = f_files_get_writer(&c_file);
	gmmc_module_print_c(c_file_writer, g->gmmc);

	f_files_close(&c_file);

	fArray(fString) clang_args = f_array_make<fString>(f_temp_alc());

	f_array_push(&clang_args, F_LIT("clang"));

	if (false) { // with debug info?
		f_array_push(&clang_args, F_LIT("-gcodeview"));
		f_array_push(&clang_args, F_LIT("--debug"));
	}
	else {
		f_array_push(&clang_args, F_LIT("-O1"));
		//f_array_push(&clang_args, F_LIT("-gcodeview"));
		//f_array_push(&clang_args, F_LIT("--debug"));
	}

	// Use the LLD linker
	//f_array_push(&clang_args, F_LIT("-fuse-ld=lld"));

	f_array_push(&clang_args, F_LIT("-I../include"));
	f_array_push(&clang_args, F_LIT("-Wno-main-return-type"));
	f_array_push(&clang_args, c_file_path);

	fStringBuilder clang_linker_args;
	f_init_string_builder(&clang_linker_args, f_temp_alc());

	f_print(clang_linker_args.w, "-Wl"); // pass comma-separated argument list to the linker
	f_print(clang_linker_args.w, ",/SUBSYSTEM:~c", BUILD_WITH_CONSOLE ? "CONSOLE" : "WINDOWS");
	f_print(clang_linker_args.w, ",/ENTRY:ffz_entry,");
	f_print(clang_linker_args.w, ",/INCREMENTAL:NO");
	f_print(clang_linker_args.w, ",/NODEFAULTLIB"); // disable CRT

	for (uint i = 0; i < g->project->link_libraries.len; i++) {
		f_print(clang_linker_args.w, ",~s", g->project->link_libraries[i]);
	}
	for (uint i = 0; i < g->project->link_system_libraries.len; i++) {
		f_print(clang_linker_args.w, ",~s", g->project->link_system_libraries[i]);
	}

	// https://metricpanda.com/rival-fortress-update-45-dealing-with-__chkstk-__chkstk_ms-when-cross-compiling-for-windows/

	// specify reserve and commit for the stack. We have to use -Xlinker for this, because of the comma ambiguity...
	f_array_push(&clang_args, F_LIT("-Xlinker"));
	f_array_push(&clang_args, F_LIT("/STACK:0x200000,200000"));

	f_array_push(&clang_args, clang_linker_args.buffer.slice);

	f_cprint("Running clang: ");
	for (uint i = 0; i < clang_args.len; i++) {
		f_cprint("\"~s\" ", clang_args[i]);
	}
	f_cprint("\n");

	u32 exit_code;
	if (!f_os_run_command(clang_args.slice, build_dir, &exit_code)) {
		f_cprint("clang couldn't be found! Have you added clang.exe to your PATH?\n");
		return false;
	}
	return exit_code == 0;
}

bool ffz_backend_gen_executable_gmmc(ffzProject* project) {
	fString build_dir = F_STR_T_JOIN(project->directory, F_LIT("\\.build"));
	F_ASSERT(f_files_make_directory(build_dir));

	fString exe_path = F_STR_T_JOIN(build_dir, F_LIT("\\"), project->name, F_LIT(".exe"));

	fArenaMark temp_base = f_temp_get_mark();
	gmmcModule* gmmc = gmmc_init(f_temp_alc());

	Gen g = {};
	g.gmmc = gmmc;
	g.alc = f_temp_alc();
	g.project = project;
	//g.tb_file_from_parser_idx = f_array_make<TB_FileID>(g.alc);
	g.value_from_definition = f_map64_make<Value>(g.alc);
	g.proc_from_hash = f_map64_make<ProcInfo*>(g.alc);
	g.procs_sorted = f_array_make<ProcInfo*>(g.alc);
	g.cv_file_from_parser_idx = f_array_make<cviewSourceFile>(g.alc);
	g.cv_types = f_array_make<cviewType>(g.alc);

	for (u32 i = 0; i < project->parsers.len; i++) {
		ffzParser* parser = project->parsers[i];

		cviewSourceFile file = {};
		file.filepath = parser->source_code_filepath;
		
		SHA256_CTX sha256;
		sha256_init(&sha256);
		sha256_update(&sha256, parser->source_code.data, parser->source_code.len);
		sha256_final(&sha256, &file.hash.bytes[0]);
		
		f_array_push(&g.cv_file_from_parser_idx, file);
	}

	for (uint i = 0; i < project->checkers_dependency_sorted.len; i++) {
		ffzChecker* checker = project->checkers_dependency_sorted[i];
		g.checker = checker;
		
		for (uint j = 0; j < checker->parsers.len; j++) {
			ffzParser* parser = checker->parsers[j];
			for FFZ_EACH_CHILD(n, parser->root) {
				gen_statement(&g, ffz_get_toplevel_inst(g.checker, n));
			}
		}
	}

	bool x64 = true;
	if (x64) {
		return build_x64(&g, build_dir);
	}
	else {
		return build_c(&g, build_dir);
	}

	return true;
}

#endif // FFZ_BUILD_INCLUDE_GMMC