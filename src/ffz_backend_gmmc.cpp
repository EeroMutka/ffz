#ifdef FFZ_BUILD_INCLUDE_GMMC

#include "tracy/tracy/Tracy.hpp"

#define F_DEF_INCLUDE_OS
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


#define todo f_trap()

#define CHILD(parent, child_access) ffzNode*{ (parent).node->child_access, (parent).polymorph }

struct Variable {
	gmmcSymbol* symbol;
	gmmcOpIdx local_addr; // local_addr is used if symbol is NULL
	bool local_addr_is_indirect;
};

#define UNDEFINED_VALUE GMMC_OP_IDX_INVALID

struct Value {
	// NOTE: this may be UNDEFINED_VALUE.
	// In FFZ, undefined values are only allowed in variable declarations.
	//  i.e. `foo: int(~~)`
	gmmcOpIdx op;
	
	bool indirect_is_temporary_copy; // e.g. with `foo: MyStruct{1, 2, 3}`, the right side would be a temporary copy.
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
	
	fSlice(gmmcOpIdx) dbginfo_line_ops; // index 0 is the procedure's starting line. A value of GMMC_OP_IDX_INVALID means that the line doesn't have an op.
	fArray(DebugInfoLocal) dbginfo_locals;
};

struct GlobalInfo {
	ffzNode* node;
	gmmcGlobal* gmmc_global;
};

struct Gen {
	ffzProject* project;
	ffzModule* root_module;

	fAllocator* alc;
	//ffzModule* checker;
	ffzCheckerContext* checker_ctx;

	gmmcModule* gmmc;

	struct {
		ProcInfo* proc_info;
		gmmcProc* proc;

		gmmcBasicBlock* bb;
		fOpt(u32*) override_line_num;
	};

	bool link_against_libc;
	u32 pointer_size;

	uint dummy_name_counter;
	
	fMap64(u32) file_id_from_source; // key: ffzSource*
	fMap64(ProcInfo*) proc_from_hash;
	fArray(ProcInfo*) procs_sorted;
	fMap64(Variable) variable_from_definition; // key: ffzNode*
	
	fArray(GlobalInfo) globals;

	// debug info
	fArray(cviewType) cv_types;
	fArray(cviewSourceFile) cv_file_from_parser_idx;
};

static void gen_statement(Gen* g, ffzNode* node);
static Value gen_expr(Gen* g, ffzNode* node, bool address_of);

static fString make_name(Gen* g, ffzNode* node = NULL, bool pretty = true) {
	// @memory; we could reuse the names
	fStringBuilder name;
	f_init_string_builder(&name, f_temp_alc());

	if (node) {
		fOpt(ffzConstantData*) extern_tag = ffz_checked_get_tag(node->parent, ffzKeyword_extern);
		if (extern_tag) {
			f_prints(name.w, extern_tag->record_fields[1].string_zero_terminated); // name_prefix
		}

		f_prints(name.w, ffz_get_parent_decl_name(node));
		
		if (node->_module != g->root_module) {
			// We don't want to export symbols from imported modules.
			// Currently, we're giving these symbols unique ids and exporting them anyway, because
			// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!
			
			bool is_module_defined_entry = ffz_checked_get_tag(node->parent, ffzKeyword_module_defined_entry);
			if (extern_tag == NULL && !is_module_defined_entry) {
				f_print(name.w, "$$~u32", node->_module->self_id);
				//f_prints(name.w, g->checker->_dbg_module_import_name);
			}
		}
	}
	
	if (name.str.len == 0) {
		f_print(name.w, "_ffz_~x64", g->dummy_name_counter);
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

gmmcType get_gmmc_trivial_type(Gen* g, ffzType* type) {
	f_assert(value_is_direct(type));
	switch (type->tag) {
	case ffzTypeTag_Bool: return gmmcType_bool;
	
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_Pointer: return gmmcType_ptr;

	case ffzTypeTag_Float: {
		if (type->size == 4) return gmmcType_f32;
		else if (type->size == 8) return gmmcType_f64;
		else f_trap();
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
		else f_trap();
	} break;
		//case ffzTypeTag_Enum: {} break;
	default: f_trap();
	}
	return {};
}

static bool has_big_return(ffzType* proc_type) {
	return proc_type->Proc.return_type && proc_type->Proc.return_type->size > 8; // :BigReturn
}

// optionally set debug-info location
static void set_loc(Gen* g, gmmcOpIdx op, ffzLocRange loc) {
	if (!gmmc_is_op_direct(g->proc, op)) {
		u32 line_num = g->override_line_num ? *g->override_line_num : loc.start.line_num;
		line_num -= g->proc_info->node->loc.start.line_num;
		
		gmmcOpIdx* line_op = &g->proc_info->dbginfo_line_ops[line_num];
		if ((*line_op) == GMMC_OP_IDX_INVALID) {
			*line_op = op;
		}
	}
}

static cviewTypeIdx get_debuginfo_type(Gen* g, ffzType* type) {
	cviewType cv_type = {};
	cv_type.size = type->size;

	switch (type->tag) {
	case ffzTypeTag_Bool: {
		cv_type.tag = cviewTypeTag_Bool;
		cv_type.size = 1;
	} break;

	case ffzTypeTag_Proc: {
		cv_type.tag = cviewTypeTag_VoidPointer;
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

	case ffzTypeTag_Float: {
		cv_type.tag = cviewTypeTag_Float;
	} break;

	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Sint: {
		cv_type.tag = cviewTypeTag_Int;
	} break;

	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Uint: {
		cv_type.tag = cviewTypeTag_UnsignedInt;
	} break;
		//case ffzTypeTag_Float: {} break;
		//case ffzTypeTag_Proc: {} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Record: {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) f_trap();

		fSlice(cviewStructMember) cv_fields = f_make_slice_undef<cviewStructMember>(type->record_fields.len, g->alc);
		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzField& field = type->record_fields[i];
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
			make_name(g/*, type->unique_node*/);
	} break;

	//case ffzTypeTag_Enum: {} break;
	case ffzTypeTag_FixedArray: {
		cv_type.tag = cviewTypeTag_Array;
		cv_type.Array.elem_type_idx = get_debuginfo_type(g, type->FixedArray.elem_type);
	} break;

	default: f_trap();
	}

	f_assert(cv_type.tag);
	// TODO: deduplicate types?
	return (u32)f_array_push(&g->cv_types, cv_type);
}


static void add_dbginfo_local(Gen* g, fString name, gmmcOpIdx addr, ffzType* type, bool ref = false) {
	DebugInfoLocal dbginfo_local;
	dbginfo_local.local_or_param = addr;
	dbginfo_local.name = name;
	dbginfo_local.type_idx = get_debuginfo_type(g, type);
	
	if (ref) {
		// hmm... we're not deduplicating these types
		cviewType cv_type = {};
		cv_type.size = type->size;
		cv_type.tag = cviewTypeTag_Pointer;
		cv_type.Pointer.cpp_style_reference = true;
		cv_type.Pointer.type_idx = dbginfo_local.type_idx;
		dbginfo_local.type_idx = (u32)f_array_push(&g->cv_types, cv_type);
	}

	f_array_push(&g->proc_info->dbginfo_locals, dbginfo_local);
}

static gmmcProc* gen_procedure(Gen* g, ffzNode* node) {
	auto insertion = f_map64_insert(&g->proc_from_hash, (u64)node, (ProcInfo*)0, fMapInsert_DoNotOverride);
	if (!insertion.added) return (*insertion._unstable_ptr)->gmmc_proc;

	ffzType* proc_type = ffz_checked_get_info(g->checker_ctx, node).type;
	f_assert(proc_type->tag == ffzTypeTag_Proc);

	fOpt(ffzType*) ret_type = proc_type->Proc.return_type;
	bool big_return = has_big_return(proc_type);
	
	gmmcType ret_type_gmmc = big_return ? gmmcType_ptr :
		ret_type ? get_gmmc_trivial_type(g, ret_type) : gmmcType_None;

	// TODO: deduplicate prototypes?
	fArray(gmmcType) param_types = f_array_make<gmmcType>(g->alc);
	
	if (big_return) {
		// if big return, pass the pointer to the return value as the first argument the same way C does. :BigReturn
		f_array_push(&param_types, gmmcType_ptr);
	}

	for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
		ffzField* param = &proc_type->Proc.in_params[i];
		
		// NOTE: [3]u8 is not trivial, and it does indeed get the type 'ptr', but since it's small, its stored directly
		// in the parameter (as per X64 calling convention)
		gmmcType param_type = value_is_direct(param->type) ? get_gmmc_trivial_type(g, param->type) : gmmcType_ptr;
		f_array_push(&param_types, param_type);
	}
	//F_HITS(_c, 4);
	fString name = make_name(g, node);
	//if (name == F_LIT("arena_push")) f_trap();
	gmmcProcSignature* sig = gmmc_make_proc_signature(g->gmmc, ret_type_gmmc, param_types.data, (u32)param_types.len);

	gmmcBasicBlock* entry_bb;
	
	gmmcProc* proc = gmmc_make_proc(g->gmmc, sig, name, &entry_bb);
	
	ProcInfo* proc_info = f_mem_clone(ProcInfo{}, g->alc);
	proc_info->gmmc_proc = proc;
	proc_info->node = node;
	proc_info->type = proc_type;
	proc_info->dbginfo_locals = f_array_make<DebugInfoLocal>(g->alc);
	proc_info->dbginfo_line_ops = f_make_slice<gmmcOpIdx>(node->loc.end.line_num - node->loc.start.line_num + 1, gmmcOpIdx{GMMC_OP_IDX_INVALID}, g->alc);

	f_array_push(&g->procs_sorted, proc_info);
	*insertion._unstable_ptr = proc_info;

	gmmcProc* proc_before = g->proc;
	gmmcBasicBlock* bb_before = g->bb;
	ProcInfo* proc_info_before = g->proc_info;
	g->proc_info = proc_info;
	g->proc = proc;
	g->bb = entry_bb;

	if (node->kind == ffzNodeKind_PostCurlyBrackets && node->Op.left->kind == ffzNodeKind_ProcType) {
		// Expose the parameters to the body.
		// NOTE: we must loop through the parameter nodes like this instead of looking at the parameters using the type info,
		// because procedure types are structurally typed, and the decl given by the field info might not be the one declared by this procedure.
		u32 i = 0;
		for FFZ_EACH_CHILD(param_decl, node->Op.left) {
			f_assert(param_decl->kind == ffzNodeKind_Declare);
			gmmcOpIdx param_addr = gmmc_op_addr_of_param(proc, i + (u32)big_return);
			ffzType* param_type = ffz_checked_get_info(g->checker_ctx, param_decl).type;

			Variable val = {};
			val.local_addr = param_addr;
			add_dbginfo_local(g, ffz_decl_get_name(param_decl), val.local_addr, param_type, param_type->size > 8);

			if (param_type->size > 8) {
				// This is Microsoft-X64 calling convention specific!
				// NOTE: we can't do gmmc_op_load here, because we can't access a values from other BBs.
				val.local_addr_is_indirect = true;
				//val.local_addr = gmmc_op_load(entry_bb, gmmcType_ptr, val.local_addr);
			}

			f_map64_insert(&g->variable_from_definition, (u64)param_decl->Op.left, val);
			i++;
		}
	}

	for FFZ_EACH_CHILD(n, node) {
		gen_statement(g, n);
	}
	
	if (!proc_type->Proc.return_type) { // automatically generate a return statement if the proc doesn't return a value
		g->override_line_num = &node->loc.end.line_num;
		gmmcOpIdx op = gmmc_op_return(g->bb, gmmcOpIdx{GMMC_OP_IDX_INVALID});
		set_loc(g, op, node->loc);
		g->override_line_num = NULL;
	}

	g->proc_info = proc_info_before;
	g->proc = proc_before;
	g->bb = bb_before;
	
	//gmmc_proc_print(
	//f_cprint("\n");
	//tb_function_print(func, tb_default_print_callback, stdout, false);
	//f_cprint("\n");

	//bool ok = tb_module_compile_function(g->gmmc, func, TB_ISEL_FAST);
	//f_assert(ok);

	return proc;
}

static gmmcSymbol* get_proc_symbol(Gen* g, ffzNode* proc_node) {
	if (proc_node->kind == ffzNodeKind_ProcType) { // @extern proc
		fString name = make_name(g, proc_node);
		return gmmc_extern_as_symbol(gmmc_make_extern(g->gmmc, name));
	}
	else {
		return gmmc_proc_as_symbol(gen_procedure(g, proc_node));
	}
}

static void fill_global_constant_data(Gen* g, gmmcGlobal* global, u8* base, u32 offset, ffzType* type, ffzConstantData* data) {
	switch (type->tag) {
	case ffzTypeTag_Float: // fallthrough
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultUint: {
		memcpy(base + offset, data, type->size);
	} break;

	case ffzTypeTag_Proc: {
		memset(base + offset, 0, 8);
		if (data->node) {
			gmmcSymbol* proc_sym = get_proc_symbol(g, data->node);
			gmmc_global_add_relocation(global, offset, proc_sym);
		}
	} break;

	case ffzTypeTag_Pointer: {
		if (data->ptr.as_ptr_to_constant) todo;
		memcpy(base + offset, &data->ptr.as_integer, 8);
	} break;

	case ffzTypeTag_FixedArray: {
		ffzType* elem_type = type->FixedArray.elem_type;
		f_assert(ffz_type_is_integer(type->FixedArray.length.type->tag));
		
		for (u32 i = 0; i < (u32)type->FixedArray.length.value->_uint; i++) {
			ffzConstantData elem_constant_data = ffz_constant_array_get_elem(ffzConstant{ type, data }, i);
			fill_global_constant_data(g, global, base, offset + i*elem_type->size, elem_type, &elem_constant_data);
		}
	} break;

	case ffzTypeTag_Slice: {
		ffzType* elem_type = type->Slice.elem_type;

		void* slice_data;
		gmmcGlobal* slice_data_global = gmmc_make_global(g->gmmc, elem_type->size * data->array_elems.len,
			elem_type->align, gmmcSection_RData, &slice_data);

		for (u32 i = 0; i < data->array_elems.len; i++) {
			ffzConstantData elem_constant_data = ffz_constant_array_get_elem({ type, data }, i);
			fill_global_constant_data(g, slice_data_global, (u8*)slice_data, i*elem_type->size, elem_type, &elem_constant_data);
		}
		
		gmmc_global_add_relocation(global, offset, gmmc_global_as_symbol(slice_data_global));

		u64 len = data->array_elems.len;
		memcpy(base + offset + 8, &len, 8);
	} break;

	case ffzTypeTag_String: {
		fString s = data->string_zero_terminated;

		void* str_data;
		gmmcGlobal* str_data_global = gmmc_make_global(g->gmmc, (u32)s.len + 1, 1, gmmcSection_RData, &str_data);
		memcpy(str_data, s.data, s.len);
		((u8*)str_data)[s.len] = 0; // zero-termination

		gmmc_global_add_relocation(global, offset, gmmc_global_as_symbol(str_data_global));

		u64 len = s.len;
		memcpy(base + offset + 8, &len, 8);
	} break;

	case ffzTypeTag_Record: {
		memset(base + offset, 0, type->size);
		for (u32 i = 0; i < type->record_fields.len; i++) {
			ffzField* field = &type->record_fields[i];
			
			ffzConstantData* field_data = data->record_fields.len == 0 ? ffz_zero_value_constant() : &data->record_fields[i];
			fill_global_constant_data(g, global, base, offset + field->offset, field->type, field_data);
		}
	} break;

	default: f_trap();
	}
}

// If non-trivial type, the returned op-value will point to a stack copy.
static Value gen_constant(Gen* g, ffzType* type, ffzConstantData* data, ffzLocRange loc) {
	Value out = {};

	switch (type->tag) {
	case ffzTypeTag_Bool: {
		out.op = gmmc_op_bool(g->proc, data->_bool);
	} break;

	case ffzTypeTag_Float: {
		if (type->size == 4)      out.op = gmmc_op_f32(g->proc, data->_f32);
		else if (type->size == 8) out.op = gmmc_op_f64(g->proc, data->_f64);
		else f_trap();
	} break;

	case ffzTypeTag_Enum: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultUint: {
		if (type->size == 1)      out.op = gmmc_op_i8(g->proc,   (u8)data->_uint);
		else if (type->size == 2) out.op = gmmc_op_i16(g->proc, (u16)data->_uint);
		else if (type->size == 4) out.op = gmmc_op_i32(g->proc, (u32)data->_uint);
		else if (type->size == 8) out.op = gmmc_op_i64(g->proc, (u64)data->_uint);
		else f_trap();
	} break;

	case ffzTypeTag_Proc: {
		out.op = gmmc_op_addr_of_symbol(g->proc, get_proc_symbol(g, data->node));
	} break;

	case ffzTypeTag_Pointer: // fallthrough
	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_FixedArray: // fallthrough
	case ffzTypeTag_Record: {
		void* global_data;
		gmmcGlobal* global = gmmc_make_global(g->gmmc, type->size, type->align, gmmcSection_RData, &global_data);

		fill_global_constant_data(g, global, (u8*)global_data, 0, type, data);

		out.op = gmmc_op_addr_of_symbol(g->proc, gmmc_global_as_symbol(global));

		if (value_is_direct(type)) {
			out.op = gmmc_op_load(g->bb, get_gmmc_trivial_type(g, type), out.op);
		}
		else {
			// Create a stack copy
			gmmcOpIdx local_copy_addr = gmmc_op_local(g->proc, type->size, type->align);
			gmmcOpIdx copy_op = gmmc_op_memcpy(g->bb, local_copy_addr, out.op, gmmc_op_i32(g->proc, type->size));
			set_loc(g, copy_op, loc);
			out.op = local_copy_addr;
			out.indirect_is_temporary_copy = true;
		}
	} break;

	default: f_trap();
	}
	
	return out;
}

static Value gen_call(Gen* g, ffzNodeOp* node) {
	ffzNode* proc_node = ffz_call_get_target_procedure(g->checker_ctx, node);
	//ffzNode* left = node->Op.left;
	
	ffzType* proc_type = ffz_checked_get_info(g->checker_ctx, proc_node).type;
	f_assert(proc_type->tag == ffzTypeTag_Proc);

	fOpt(ffzType*) ret_type = proc_type->Proc.return_type;
	bool big_return = has_big_return(proc_type); // :BigReturn
	
	gmmcType ret_type_gmmc = big_return ? gmmcType_ptr :
		ret_type ? get_gmmc_trivial_type(g, ret_type) : gmmcType_None;

	fArray(gmmcOpIdx) args = f_array_make<gmmcOpIdx>(g->alc);

	Value out = {};
	if (big_return) {
		out.op = gmmc_op_local(g->proc, ret_type->size, ret_type->align);
		out.indirect_is_temporary_copy = true;
		f_array_push(&args, out.op);
	}

	fSlice(ffzNode*) arg_nodes;
	ffz_get_arguments_flat(node, proc_type->Proc.in_params, &arg_nodes, f_temp_alc());

	for (u32 i = 0; i< arg_nodes.len; i++) {
		ffzField* field = &proc_type->Proc.in_params[i];
		ffzNode* arg_node = arg_nodes[i];
		ffzType* param_type = field->type;

		Value arg_value;
		if (arg_node == NULL) {
			// use the default value
			arg_value = gen_constant(g, param_type, &field->default_value, node->loc);
		} else {
			arg_value = gen_expr(g, arg_node, false);
		}


		// The GMMC values returned by gen_expr, et al, are either direct (trivial) or indirect, meaning a pointer
		// is stored to the value instead. When you do `foo: Vector2{1, 2}, bar(foo)`, then the indirect value
		// holds the address of the local, and thus a copy must be made on the stack for the callee procedure.
		// But when you do `bar(Vector2{1, 2})`, the indirect value already holds a pointer to a temporary stack value
		// that will not be modified in any way, so we don't need to copy the value in that case.

		if (!value_is_direct(param_type)) {
			if (arg_value.indirect_is_temporary_copy) {
			}
			else {
				// We need to copy the value for the callee.
				gmmcOpIdx local_copy_addr = gmmc_op_local(g->proc, param_type->size, param_type->align);
				gmmcOpIdx copy = gmmc_op_memcpy(g->bb, local_copy_addr, arg_value.op, gmmc_op_i32(g->proc, param_type->size));
				set_loc(g, copy, arg_node->loc);
				arg_value.op = local_copy_addr;
			}
		}

		// NOTE: the way we pass around op-values matches the parameter passing calling convention nicely:
		// "Structs and unions of size 8, 16, 32, or 64 bits, and __m64 types, are
		//  passed as if they were integers of the same size"
		//  https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170

		f_array_push(&args, arg_value.op);
	}

	Value target = gen_expr(g, proc_node, false);
	f_assert(target.op != UNDEFINED_VALUE);

	gmmcOpIdx call = gmmc_op_call(g->bb, ret_type_gmmc, target.op, args.data, (u32)args.len);
	set_loc(g, call, node->loc);
	if (!big_return) out.op = call;

	return out;
}


static gmmcOpIdx gen_store(Gen* g, gmmcOpIdx addr, gmmcOpIdx value, ffzType* type, ffzNode* node) {
	gmmcOpIdx result;
	if (value_is_direct(type)) {
		result = gmmc_op_store(g->bb, addr, value);
	} else {
		result = gmmc_op_memcpy(g->bb, addr, value, gmmc_op_i32(g->proc, type->size));
	}
	set_loc(g, result, node->loc);
	return result;
}

// return a pointer to the value
static gmmcOpIdx gen_curly_initializer(Gen* g, ffzType* type, ffzNode* node) {
	gmmcOpIdx out = gmmc_op_local(g->proc, type->size, type->align);

	if (type->tag == ffzTypeTag_FixedArray) {
		u32 i = 0;
		ffzType* elem_type = type->FixedArray.elem_type;
		for FFZ_EACH_CHILD(n, node) {
			Value src = gen_expr(g, n, false);
			gmmcOpIdx dst_ptr = gmmc_op_member_access(g->bb, out, i * elem_type->size);
			gen_store(g, dst_ptr, src.op, elem_type, n);
			i++;
		}
	}
	else if (type->tag == ffzTypeTag_Slice) {
		ffzType* elem_type = type->Slice.elem_type;
		u32 child_count = ffz_get_child_count(node);
		
		gmmcOpIdx array_data = child_count > 0 ? gmmc_op_local(g->proc, child_count * elem_type->size, elem_type->align) :
			gmmc_op_int2ptr(g->bb, gmmc_op_i64(g->proc, 0));

		gmmc_op_store(g->bb, out, array_data); // set pointer
		gmmc_op_store(g->bb, gmmc_op_member_access(g->bb, out, g->pointer_size), gmmc_op_i64(g->proc, child_count)); // set len
		
		u32 i = 0;
		for FFZ_EACH_CHILD(n, node) {
			Value src = gen_expr(g, n, false);
			gmmcOpIdx dst_ptr = gmmc_op_member_access(g->bb, array_data, i * elem_type->size);
			gen_store(g, dst_ptr, src.op, elem_type, n);
			i++;
		}
	}
	else {
		fSlice(ffzField) fields = type->record_fields;

		fSlice(fOpt(ffzNode*)) arguments;
		ffz_get_arguments_flat(node, fields, &arguments, f_temp_alc());

		// First memset to zero, then fill out the fields that are non-zero
		// TODO: only do this memset if there's any padding!
		gmmc_op_memset(g->bb, out, gmmc_op_i8(g->proc, 0), gmmc_op_i32(g->proc, type->size));

		for (uint i = 0; i < fields.len; i++) {
			ffzField& field = fields[i];
			fOpt(ffzNode*) arg = arguments[i];

			Value src;
			if (arg == NULL) { // use default value
				if (ffz_constant_is_zero(field.default_value)) continue;
				src = gen_constant(g, field.type, &field.default_value, node->loc);
			}
			else {
				fOpt(ffzConstantData*) arg_constant = ffz_checked_get_info(g->checker_ctx, arg).const_val;
				if (arg_constant) {
					if (ffz_constant_is_zero(*arg_constant)) continue;
					src = gen_constant(g, field.type, arg_constant, arg->loc);
				}
				else {
					src = gen_expr(g, arg, false);
				}
			}

			gmmcOpIdx field_addr = gmmc_op_member_access(g->bb, out, field.offset);
			gen_store(g, field_addr, src.op, field.type, node);
		}
	}
	return out;
}


static Value gen_expr(Gen* g, ffzNode* node, bool address_of) {
	ZoneScoped;
	Value out = {};

	//if (node->loc.start.line_num == 13) f_trap();
	ffzCheckInfo checked = ffz_checked_get_info(g->checker_ctx, node);
	f_assert(ffz_type_is_concrete(checked.type));
	f_assert(node->kind != ffzNodeKind_Declare);

	bool needs_dereference = false;

	if (checked.const_val) {
		// if you take an address of constant, it should make a copy.
		out = gen_constant(g, checked.type, checked.const_val, node->loc);
	}
	else if (ffz_node_is_operator(node->kind)) {
		fOpt(ffzNode*) left = node->Op.left;
		ffzNode* right = node->Op.right;
		ffzCheckInfo left_checked;
		if (left) left_checked = ffz_checked_get_info(g->checker_ctx, left);

		switch (node->kind) {

		case ffzNodeKind_Add: case ffzNodeKind_Sub:
		case ffzNodeKind_Mul: case ffzNodeKind_Div:
		case ffzNodeKind_Modulo: case ffzNodeKind_Equal:
		case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
		case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater:
		case ffzNodeKind_GreaterOrEqual:
		{
			ffzType* input_type = left_checked.type;
			bool is_signed = ffz_type_is_signed_integer(input_type->tag);
			
			// TODO: more operator defines. I guess we should do this together with the fix for vector math
			f_assert(value_is_direct(input_type));
			
			gmmcOpIdx a = gen_expr(g, left, false).op;
			gmmcOpIdx b = gen_expr(g, right, false).op;

			if (ffz_type_is_float(input_type->tag)) {
				switch (node->kind) {
				case ffzNodeKind_Add: { out.op = gmmc_op_fadd(g->bb, a, b); } break;
				case ffzNodeKind_Sub: { out.op = gmmc_op_fsub(g->bb, a, b); } break;
				case ffzNodeKind_Mul: { out.op = gmmc_op_fmul(g->bb, a, b); } break;
				case ffzNodeKind_Div: { out.op = gmmc_op_fdiv(g->bb, a, b); } break;
				case ffzNodeKind_Equal: { out.op = gmmc_op_eq(g->bb, a, b); } break;
				case ffzNodeKind_NotEqual: { out.op = gmmc_op_ne(g->bb, a, b); } break;
				case ffzNodeKind_Less: { out.op = gmmc_op_lt(g->bb, a, b, false); } break;
				case ffzNodeKind_LessOrEqual: { out.op = gmmc_op_le(g->bb, a, b, false); } break;
				case ffzNodeKind_Greater: { out.op = gmmc_op_gt(g->bb, a, b, false); } break;
				case ffzNodeKind_GreaterOrEqual: { out.op = gmmc_op_ge(g->bb, a, b, false); } break;
				default: f_trap();
				}
			} else {
				switch (node->kind) {
				case ffzNodeKind_Add: { out.op = gmmc_op_add(g->bb, a, b); } break;
				case ffzNodeKind_Sub: { out.op = gmmc_op_sub(g->bb, a, b); } break;
				case ffzNodeKind_Mul: { out.op = gmmc_op_mul(g->bb, a, b, is_signed); } break;
				case ffzNodeKind_Div: { out.op = gmmc_op_div(g->bb, a, b, is_signed); } break;
				case ffzNodeKind_Modulo: { out.op = gmmc_op_mod(g->bb, a, b, is_signed); } break;
				case ffzNodeKind_Equal: { out.op = gmmc_op_eq(g->bb, a, b); } break;
				case ffzNodeKind_NotEqual: { out.op = gmmc_op_ne(g->bb, a, b); } break;
				case ffzNodeKind_Less: { out.op = gmmc_op_lt(g->bb, a, b, is_signed); } break;
				case ffzNodeKind_LessOrEqual: { out.op = gmmc_op_le(g->bb, a, b, is_signed); } break;
				case ffzNodeKind_Greater: { out.op = gmmc_op_gt(g->bb, a, b, is_signed); } break;
				case ffzNodeKind_GreaterOrEqual: { out.op = gmmc_op_ge(g->bb, a, b, is_signed); } break;
				default: f_trap();
				}
			}
		} break;

		case ffzNodeKind_UnaryMinus: {
			gmmcType type = get_gmmc_trivial_type(g, checked.type);

			u64 zero = 0;
			out.op = gen_expr(g, right, false).op;
			if (gmmc_type_is_float(type)) {
				out.op = gmmc_op_fsub(g->bb, gmmc_op_immediate(g->proc, type, &zero), out.op);
			} else {
				out.op = gmmc_op_sub(g->bb, gmmc_op_immediate(g->proc, type, &zero), out.op);
			}
		} break;

		case ffzNodeKind_LogicalNOT: {
			// (!x) is equivalent to (x == false)
			out.op = gmmc_op_eq(g->bb, gen_expr(g, right, false).op, gmmc_op_bool(g->proc, false));
		} break;

		case ffzNodeKind_PostRoundBrackets: {
			if (left->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(left->Keyword.keyword)) {
				ffzKeyword keyword = left->Keyword.keyword;

				gmmcOpIdx first = gen_expr(g, ffz_get_child(node, 0), false).op;
				if (keyword == ffzKeyword_bit_not) {
					out.op = gmmc_op_not(g->bb, first);
				}
				else {
					gmmcOpIdx second = gen_expr(g, ffz_get_child(node, 1), false).op;
					switch (keyword) {
					case ffzKeyword_bit_and: { out.op = gmmc_op_and(g->bb, first, second); } break;
					case ffzKeyword_bit_or: { out.op = gmmc_op_or(g->bb, first, second); } break;
					case ffzKeyword_bit_xor: { out.op = gmmc_op_xor(g->bb, first, second); } break;
					case ffzKeyword_bit_shl: { out.op = gmmc_op_shl(g->bb, first, gmmc_op_int2int(g->bb, second, gmmcType_i8, false)); } break;
					case ffzKeyword_bit_shr: { out.op = gmmc_op_shr(g->bb, first, gmmc_op_int2int(g->bb, second, gmmcType_i8, false)); } break;
					default: f_trap();
					}
				}
			}
			else {
				//ffzCheckedInst left_chk = ffz_get_checked(g->project, left);
				if (left_checked.type->tag == ffzTypeTag_Type) {
					// type cast, e.g. u32(520.32)

					ffzType* dst_type = ffz_as_type(left_checked.const_val);

					ffzNode* arg = ffz_get_child(node, 0);
					ffzCheckInfo arg_checked = ffz_checked_get_info(g->checker_ctx, arg);
					
					if (arg_checked.type->tag == ffzTypeTag_Type && ffz_as_type(arg_checked.const_val)->tag == ffzTypeTag_Undefined) {
						out.op = UNDEFINED_VALUE;
						return out;
					}

					out = gen_expr(g, arg, false);
					
					if (ffz_type_is_slice_ish(dst_type->tag) && ffz_type_is_slice_ish(arg_checked.type->tag)) {} // no-op
					else if (ffz_type_is_pointer_ish(dst_type->tag)) { // cast to pointer
						if (ffz_type_is_pointer_ish(arg_checked.type->tag)) {} // no-op
						else if (ffz_type_is_integer_ish(arg_checked.type->tag)) {
							out.op = gmmc_op_int2ptr(g->bb, out.op);
						}
					}
					else if (ffz_type_is_integer_ish(dst_type->tag)) { // cast to integer
						gmmcType dt = get_gmmc_trivial_type(g, dst_type);
						if (ffz_type_is_pointer_ish(arg_checked.type->tag)) {
							out.op = gmmc_op_ptr2int(g->bb, out.op);
						}
						else if (ffz_type_is_integer_ish(arg_checked.type->tag)) {
							out.op = gmmc_op_int2int(g->bb, out.op, dt, ffz_type_is_signed_integer(dst_type->tag));
						}
						else if (ffz_type_is_float(arg_checked.type->tag)) {
							out.op = gmmc_op_float2int(g->bb, out.op, dt/*, ffz_type_is_signed_integer(dst_type->tag)*/);
						}
					}
					else if (ffz_type_is_float(dst_type->tag)) {
						gmmcType dt = get_gmmc_trivial_type(g, dst_type);
						if (ffz_type_is_float(arg_checked.type->tag)) {
							if (arg_checked.type->size != dst_type->size) {
								out.op = gmmc_op_float2float(g->bb, out.op, dt);
							}
						}
						else if (ffz_type_is_integer_ish(arg_checked.type->tag)) {
							out.op = gmmc_op_int2float(g->bb, out.op, dt, ffz_type_is_signed_integer(arg_checked.type->tag));
						}
					}
					else todo;
				}
				else {
					out = gen_call(g, node);
				}
			}
		} break;

		case ffzNodeKind_AddressOf: {
			out = gen_expr(g, right, true);
		} break;

		case ffzNodeKind_Dereference: {
			out = gen_expr(g, left, false);
			needs_dereference = true; //should_dereference = !address_of;
		} break;

		case ffzNodeKind_MemberAccess: {
			fString member_name = right->Identifier.name;

			if (left->kind == ffzNodeKind_Identifier && left->Identifier.name == F_LIT("in")) {
				
				bool found = false;
				for (u32 i = 0; i < g->proc_info->type->Proc.in_params.len; i++) {
					ffzField* param = &g->proc_info->type->Proc.in_params[i];
					if (param->name == member_name) {
						out.op = gmmc_op_addr_of_param(g->proc, i + (u32)has_big_return(g->proc_info->type));
						f_assert(value_is_direct(param->type));
						found = true;
					}
				}
				f_assert(found);
			}
			else {
				ffzType* left_type = left_checked.type;
				ffzType* struct_type = left_type->tag == ffzTypeTag_Pointer ? left_type->Pointer.pointer_to : left_type; // NOTE: implicit dereference

				ffzTypeRecordFieldUse field;
				f_assert(ffz_type_find_record_field_use(g->project, struct_type, member_name, &field));

				gmmcOpIdx addr_of_struct = gen_expr(g, left, left_type->tag != ffzTypeTag_Pointer).op;
				f_assert(addr_of_struct != UNDEFINED_VALUE);

				out.op = field.offset ? gmmc_op_member_access(g->bb, addr_of_struct, field.offset) : addr_of_struct;
			}
			needs_dereference = true; //should_dereference = !address_of;
		} break;

		case ffzNodeKind_PostCurlyBrackets: {
			out.op = gen_curly_initializer(g, checked.type, node);
			needs_dereference = true;// should_dereference = !address_of;
		} break;

		case ffzNodeKind_PostSquareBrackets: {
			bool implicit_dereference = left_checked.type->tag == ffzTypeTag_Pointer;
			ffzType* subscriptable_type = implicit_dereference ? left_checked.type->Pointer.pointer_to : left_checked.type;

			u32 offset = 0;
			if (subscriptable_type->tag == ffzTypeTag_FixedArray || subscriptable_type->tag == ffzTypeTag_Slice) {}
			else {
				ffzTypeRecordFieldUse subscriptable_field;
				f_assert(ffz_find_subscriptable_base_type(subscriptable_type, &subscriptable_field));
				subscriptable_type = subscriptable_field.src_field->type;
				offset = subscriptable_field.offset;
			}

			ffzType* elem_type = subscriptable_type->tag == ffzTypeTag_Slice ? subscriptable_type->Slice.elem_type : subscriptable_type->FixedArray.elem_type;

			gmmcOpIdx left_value = gen_expr(g, left, !implicit_dereference).op;
			if (offset != 0) {
				left_value = gmmc_op_member_access(g->bb, left_value, offset);
			}

			gmmcOpIdx array_data_ptr = left_value;
			if (subscriptable_type->tag == ffzTypeTag_Slice) {
				array_data_ptr = gmmc_op_load(g->bb, gmmcType_ptr, array_data_ptr);
			}

			if (ffz_get_child_count(node) == 2) { // slicing
				ffzNode* lo_node = ffz_get_child(node, 0);
				ffzNode* hi_node = ffz_get_child(node, 1);

				gmmcOpIdx lo = lo_node->kind == ffzNodeKind_Blank ? gmmc_op_i64(g->proc, 0) : gen_expr(g, lo_node, false).op;
				gmmcOpIdx hi;
				if (hi_node->kind == ffzNodeKind_Blank) {
					if (subscriptable_type->tag == ffzTypeTag_FixedArray) {
						f_trap(); //hi = gmmc_op_i64(g->proc, subscriptable_type->FixedArray.length);
					}
					else {
						// load the 'len' field of a slice
						hi = gmmc_op_load(g->bb, gmmcType_i64, gmmc_op_member_access(g->bb, left_value, g->pointer_size));
					}
				}
				else {
					hi = gen_expr(g, hi_node, false).op;
				}

				out.op = gmmc_op_local(g->proc, g->pointer_size*2, g->pointer_size);
				out.indirect_is_temporary_copy = true;

				lo = gmmc_op_int2int(g->bb, lo, gmmcType_i32, false); // ??? why and how are we converting to 32-bit integers?
				hi = gmmc_op_int2int(g->bb, hi, gmmcType_i32, false);
				gmmcOpIdx ptr = gmmc_op_array_access(g->bb, array_data_ptr, lo, elem_type->size);
				gmmcOpIdx len = gmmc_op_sub(g->bb, hi, lo);

				gmmc_op_store(g->bb, out.op, ptr);
				gmmc_op_store(g->bb, gmmc_op_member_access(g->bb, out.op, g->pointer_size), len);
			}
			else { // taking an index
				ffzNode* index_node = ffz_get_child(node, 0);
				
				gmmcOpIdx index = gen_expr(g, index_node, false).op;
				index = gmmc_op_int2int(g->bb, index, gmmcType_i64, false);
				out.op = gmmc_op_array_access(g->bb, array_data_ptr, index, elem_type->size);

				needs_dereference = true; //should_dereference = !address_of;
			}
		} break;

		case ffzNodeKind_LogicalOR: // fallthrough
		case ffzNodeKind_LogicalAND: {
			gmmcOpIdx left_val = gen_expr(g, left, false).op;

			// implement short-circuiting

			gmmcBasicBlock* test_right_bb = gmmc_make_basic_block(g->proc);
			gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);

			gmmcOpIdx result = gmmc_op_local(g->proc, 1, 1);
			if (node->kind == ffzNodeKind_LogicalAND) {
				gmmc_op_store(g->bb, result, gmmc_op_bool(g->proc, false));
				gmmc_op_if(g->bb, left_val, test_right_bb, after_bb);
			}
			else {
				gmmc_op_store(g->bb, result, gmmc_op_bool(g->proc, true));
				gmmc_op_if(g->bb, left_val, after_bb, test_right_bb);
			}

			g->bb = test_right_bb;
			gmmc_op_store(g->bb, result, gen_expr(g, right, false).op);
			gmmc_op_goto(g->bb, after_bb);

			g->bb = after_bb;
			out.op = gmmc_op_load(g->bb, gmmcType_bool, result);
		} break;

		default: f_trap();
		}
	}
	else {
		switch (node->kind) {
		case ffzNodeKind_Scope: {
			// type-inferred initializer
			out.op = gen_curly_initializer(g, checked.type, node);
			needs_dereference = true; //should_dereference = !address_of;
		} break;
		case ffzNodeKind_Identifier: {
			ffzNodeIdentifier* def = ffz_find_definition(g->checker_ctx, node);
			if (def->Identifier.is_constant) f_trap();

			Variable* var = f_map64_get(&g->variable_from_definition, (u64)def);
			f_assert(var);

			out.op = var->symbol ? gmmc_op_addr_of_symbol(g->proc, var->symbol) : var->local_addr;
			if (var->local_addr_is_indirect) {
				out.op = gmmc_op_load(g->bb, gmmcType_ptr, out.op);
			}

			needs_dereference = true; //should_dereference = !address_of;
		} break;

		case ffzNodeKind_ThisDot: {
			ffzNode* assignee = ffz_checked_this_dot_get_assignee(node);
			out = gen_expr(g, assignee, address_of);
		} break;

		default: break;
		}
	}

	f_assert(out.op != UNDEFINED_VALUE);
	set_loc(g, out.op, node->loc);
	
	if (needs_dereference) {
		if (address_of) {}
		else {
			// Dereference the indirect value
			if (value_is_direct(checked.type)) {
				out.op = gmmc_op_load(g->bb, get_gmmc_trivial_type(g, checked.type), out.op);
				set_loc(g, out.op, node->loc);
			}
		}
	}
	else if (address_of) {
		// Take address to copy
		if (value_is_direct(checked.type)) {
			gmmcOpIdx tmp = gmmc_op_local(g->proc, checked.type->size, checked.type->align);
			gmmc_op_store(g->bb, tmp, out.op);
			set_loc(g, tmp, node->loc);
			out.op = tmp;
			out.indirect_is_temporary_copy = true;
		}
	}
	
	return out;
}

static void gen_statement(Gen* g, ffzNode* node) {
	ZoneScoped;
	if (g->proc) {
		//gmmc_op_comment(g->bb, fString{}); // empty line
		if (node->kind == ffzNodeKind_Scope) {}
		else if (node->kind == ffzNodeKind_If) {}
		else if (node->kind == ffzNodeKind_For) {}
		else if (ffz_node_is_keyword(node, ffzKeyword_dbgbreak)) {}
		else {
			//ffzParser* parser = g->project->parsers[node->source_id];
			u32 start = node->loc.start.offset;
			u32 end = node->loc.end.offset;
			
			gmmc_op_comment(g->bb, f_tprint("line ~u32:   ~s", node->loc.start.line_num,
				fString{ node->loc_source->source_code.data + start, end - start }));
		}
	}
	
	ffzCheckInfo checked = ffz_checked_get_info(g->checker_ctx, node);

	switch (node->kind) {
		
	case ffzNodeKind_Declare: {
		ffzNodeIdentifier* definition = node->Op.left;
		//F_HITS(__c, 2);
		if (ffz_checked_decl_is_variable(g->checker_ctx, node)) {
			ffzNode* rhs = node->Op.right;
			ffzCheckInfo rhs_checked = ffz_checked_get_info(g->checker_ctx, rhs);
			
			Variable var = {};
			if (ffz_checked_get_tag(node, ffzKeyword_global)) {
				//f_assert(rhs_checked.type == checked.type);

				void* global_data;
				gmmcGlobal* global = gmmc_make_global(g->gmmc, rhs_checked.type->size, rhs_checked.type->align, gmmcSection_Data, &global_data);

				f_array_push(&g->globals, { node, global });
				
				if (rhs_checked.const_val != NULL) { // Could be an undefined (~~) global
					fill_global_constant_data(g, global, (u8*)global_data, 0, rhs_checked.type, rhs_checked.const_val);
				}
		
				var.symbol = gmmc_global_as_symbol(global);
			}
			else {
				Value rhs_value = gen_expr(g, rhs, false);
				var.local_addr = gmmc_op_local(g->proc, checked.type->size, checked.type->align);
				add_dbginfo_local(g, definition->Identifier.name, var.local_addr, checked.type);
		
				if (rhs_value.op != UNDEFINED_VALUE) {
					gen_store(g, var.local_addr, rhs_value.op, checked.type, node);
				}
			}
			f_map64_insert(&g->variable_from_definition, (u64)definition, var);
		}
		else {
			// need to still generate exported procs
			if (checked.type->tag == ffzTypeTag_Proc) {
				ffzNode* rhs = node->Op.right;
				if (rhs->kind == ffzNodeKind_PostCurlyBrackets) { // @extern procs also have the type ffzTypeTag_Proc so we need to ignore those
					gen_procedure(g, rhs);
				}
			}
		}
	} break;

	case ffzNodeKind_Assign: {
		ffzNode* lhs = node->Op.left;
		ffzNode* rhs = node->Op.right;

		gmmcOpIdx rhs_value = gen_expr(g, rhs, false).op;

		if (!ffz_node_is_keyword(lhs, ffzKeyword_Eater)) {
			gmmcOpIdx lhs_addr = gen_expr(g, lhs, true).op;
			gen_store(g, lhs_addr, rhs_value, ffz_checked_get_info(g->checker_ctx, rhs).type, node);
		}
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD(n, node) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		gmmcOpIdx cond = gen_expr(g, node->If.condition, false).op;

		gmmcBasicBlock* true_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* false_bb;
		if (node->If.false_scope) {
			false_bb = gmmc_make_basic_block(g->proc);
		}

		gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);
		set_loc(g, gmmc_op_if(g->bb, cond, true_bb, node->If.false_scope ? false_bb : after_bb), node->loc);

		g->bb = true_bb;
		gen_statement(g, node->If.true_scope);
		gmmc_op_goto(g->bb, after_bb);

		if (node->If.false_scope) {
			g->bb = false_bb;
			gen_statement(g, node->If.false_scope);
			gmmc_op_goto(g->bb, after_bb);
		}

		g->bb = after_bb;
	} break;

	case ffzNodeKind_For: {
		fOpt(ffzNode*) pre = node->For.header_stmts[0];
		fOpt(ffzNode*) condition = node->For.header_stmts[1];
		fOpt(ffzNode*) post = node->For.header_stmts[2];
		ffzNode* body = node->For.scope;
		
		if (pre) gen_statement(g, pre);
		
		gmmcBasicBlock* cond_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* body_bb = gmmc_make_basic_block(g->proc);
		gmmcBasicBlock* after_bb = gmmc_make_basic_block(g->proc);
		gmmc_op_goto(g->bb, cond_bb);

		if (!condition) f_trap(); // TODO
		
		g->bb = cond_bb;
		gmmcOpIdx cond = gen_expr(g, condition, false).op;
		gmmc_op_if(g->bb, cond, body_bb, after_bb);

		g->bb = body_bb;
		gen_statement(g, body);
			
		if (post) {
			g->override_line_num = &body->loc.end.line_num;
			gen_statement(g, post); // let's override the loc to be at the end of the body scope
			g->override_line_num = NULL;
			//set_dbginfo_loc(g, 
		}
		//inst_loc(g, node, );
		//if (post.node) gen_statement(g, post, false); 

		gmmc_op_goto(g->bb, cond_bb);

		g->bb = after_bb;
	} break;

	case ffzNodeKind_Keyword: {
		f_assert(node->Keyword.keyword == ffzKeyword_dbgbreak);
		set_loc(g, gmmc_op_debugbreak(g->bb), node->loc);
	} break;

	case ffzNodeKind_Return: {
		gmmcOpIdx val = GMMC_OP_IDX_INVALID;

		if (node->Return.value) {
			ffzType* ret_type = ffz_checked_get_info(g->checker_ctx, node->Return.value).type;
			Value return_value = gen_expr(g, node->Return.value, false);
			if (ret_type->size > 8) {
				val = gmmc_op_load(g->bb, gmmcType_ptr, gmmc_op_addr_of_param(g->proc, 0)); // :BigReturn
				gmmc_op_memcpy(g->bb, val, return_value.op, gmmc_op_i32(g->proc, ret_type->size));
			}
			else {
				val = return_value.op;
			}
		}

		set_loc(g, gmmc_op_return(g->bb, val), node->loc);
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		gen_call(g, node);
	} break;

	default: f_trap();
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
	default: f_trap();
	}
	return {};
}

static void build_x64_add_section_relocs(Gen* g, gmmcAsmModule* asm_mod, gmmcSection gmmc_section,
	coffSection* sect, u32 first_external_symbol_index)
{
	fSlice(gmmcRelocation) relocs;
	gmmc_asm_get_section_relocations(asm_mod, gmmc_section, &relocs);

	fSlice(coffRelocation) coff_relocs = f_make_slice_undef<coffRelocation>(relocs.len, g->alc);

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
	ZoneScoped;
	fString obj_filename = F_LIT("a.obj");
	fString obj_file_path = f_str_join_tmp(build_dir, F_LIT("/"), obj_filename);

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
	fArray(cviewGlobal) cv_globals = f_array_make_cap<cviewGlobal>(g->globals.len, g->alc);

	// the procs need to be sorted for debug info
	for (uint i = 0; i < g->procs_sorted.len; i++) {
		ZoneScopedN("add procedure symbol");
		ProcInfo* proc_info = g->procs_sorted[i];
		gmmcProc* proc = proc_info->gmmc_proc;

		//gmmc_asm_global_get_offset(asm_module, 

		u32 start_offset = gmmc_asm_proc_get_start_offset(asm_module, proc);

		coffSymbol sym = {};
		sym.name = proc->sym.name;
		sym.type = 0x20;
		sym.section_number = SectionNum_Code;
		sym.value = start_offset;
		sym.is_external = true;
		u32 sym_idx = (u32)f_array_push(&symbols, sym);

		if (INCLUDE_DEBUG_INFO) {
			ZoneScopedN("add procedure debug info");
			cviewFunction cv_func = {};
			cv_func.name = proc->sym.name;
			cv_func.sym_index = sym_idx;
			cv_func.section_sym_index = build_x64_section_get_sym_idx(SectionNum_Code);
			cv_func.size_of_initial_sub_rsp_instruction = gmmc_asm_proc_get_prolog_size(asm_module, proc);
			cv_func.stack_frame_size = gmmc_asm_proc_get_stack_frame_size(asm_module, proc);
			cv_func.file_idx = *f_map64_get(&g->file_id_from_source, (u64)proc_info->node->loc_source);

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

			fArray(cviewLine) lines = f_array_make<cviewLine>(g->alc);
			u32 start_line_num = proc_info->node->loc.start.line_num;
			f_array_push(&lines, cviewLine{ start_line_num , start_offset });

			for (u32 i = 0; i < proc_info->dbginfo_line_ops.len; i++) {
				gmmcOpIdx line_op = proc_info->dbginfo_line_ops[i];
				if (line_op != GMMC_OP_IDX_INVALID) {
					cviewLine line;
					line.line_num = start_line_num + i;
					line.offset = gmmc_asm_instruction_get_offset(asm_module, proc, line_op);
					f_array_push(&lines, line);
				}
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


	if (INCLUDE_DEBUG_INFO) {
		
		// add globals as symbols
		for (uint i = 0; i < g->globals.len; i++) {
			GlobalInfo global_info = g->globals[i];
			fString name = ffz_decl_get_name(global_info.node);

			coffSymbol sym = {};
			sym.name = name;
			sym.section_number = SectionNum_Data;
			sym.value = gmmc_asm_global_get_offset(asm_module, global_info.gmmc_global);
			u32 sym_idx = (u32)f_array_push(&symbols, sym);
			
			cviewGlobal cv_global;
			cv_global.name = name;
			cv_global.type_idx = get_debuginfo_type(g, ffz_checked_get_info(g->checker_ctx, global_info.node).type);
			cv_global.sym_index = sym_idx;
			f_array_push(&cv_globals, cv_global);
		}

		cviewGenerateDebugInfoDesc cv_desc = {};
		cv_desc.obj_name = obj_filename;
		cv_desc.files = g->cv_file_from_parser_idx.data;
		cv_desc.files_count = (u32)g->cv_file_from_parser_idx.len;
		cv_desc.functions = cv_functions.data;
		cv_desc.functions_count = (u32)cv_functions.len;
		cv_desc.xdata_section_sym_index = build_x64_section_get_sym_idx(SectionNum_xdata);
		cv_desc.globals = cv_globals.data;
		cv_desc.globals_count = (u32)cv_globals.len;
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
	
	{
		ZoneScopedN("coff_create");
		coff_create([](fString result, void* userptr) {
			fString obj_file_path = *(fString*)userptr;
		
			bool ok = f_files_write_whole(obj_file_path, result);
			f_assert(ok);

			}, &obj_file_path, &coff_desc);
	}

	WinSDK_Find_Result windows_sdk;
	{
		ZoneScopedN("WinSDK_find_visual_studio_and_windows_sdk");
		windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
	}
	fString msvc_directory = f_str_from_utf16(windows_sdk.vs_exe_path, g->alc); // contains cl.exe, link.exe
	//fString windows_sdk_include_base_path = f_str_from_utf16(windows_sdk.windows_sdk_include_base, g->alc); // contains <string.h>, etc
	fString windows_sdk_um_library_path = f_str_from_utf16(windows_sdk.windows_sdk_um_library_path, g->alc); // contains kernel32.lib, etc
	fString windows_sdk_ucrt_library_path = f_str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, g->alc); // contains libucrt.lib, etc
	fString vs_library_path = f_str_from_utf16(windows_sdk.vs_library_path, g->alc); // contains MSVCRT.lib etc
	//fString vs_include_path = f_str_from_utf16(windows_sdk.vs_include_path, g->alc); // contains vcruntime.h

	fArray(fString) ms_linker_args = f_array_make<fString>(g->alc);
	{
		ZoneScopedN("build ms_linker_args");

		f_array_push(&ms_linker_args, f_str_join_tmp(msvc_directory, F_LIT("\\link.exe")));
		f_array_push(&ms_linker_args, obj_filename);

		f_array_push(&ms_linker_args, f_str_join_tmp(F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		f_array_push(&ms_linker_args, f_str_join_tmp(F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		f_array_push(&ms_linker_args, f_str_join_tmp(F_LIT("/LIBPATH:"), vs_library_path));

		f_array_push(&ms_linker_args, f_str_join_tmp(F_LIT("/SUBSYSTEM:"), BUILD_WITH_CONSOLE ? F_LIT("CONSOLE") : F_LIT("WINDOWS")));
		f_array_push(&ms_linker_args, F_LIT("/INCREMENTAL:NO"));

		if (!g->link_against_libc) {
			f_array_push(&ms_linker_args, F_LIT("/ENTRY:main"));
			f_array_push(&ms_linker_args, F_LIT("/NODEFAULTLIB"));
		}

		f_array_push(&ms_linker_args, F_LIT("/DEBUG"));
		f_array_push(&ms_linker_args, F_LIT("/DYNAMICBASE:NO")); // to get deterministic pointers

		//for (uint i = 0; i < g->project->link_libraries.len; i++) {
		//	f_array_push(&ms_linker_args, g->project->link_libraries[i]);
		//}
		//for (uint i = 0; i < g->project->link_system_libraries.len; i++) {
		//	f_array_push(&ms_linker_args, g->project->link_system_libraries[i]);
		//}

		// specify reserve and commit for the stack.
		f_array_push(&ms_linker_args, F_LIT("/STACK:0x200000,200000"));

		if (true) {
			f_cprint("Running link.exe: ");
			for (uint i = 0; i < ms_linker_args.len; i++) {
				f_cprint("\"~s\" ", ms_linker_args[i]);
			}
			f_cprint("\n");
		}
	}


	u32 exit_code;
	{
		ZoneScopedN("run linker");
		if (!f_os_run_command(ms_linker_args.slice, build_dir, &exit_code)) {
			f_cprint("link.exe couldn't be found! Have you installed visual studio?\n");
			return false;
		}
	}
	return exit_code == 0;
}

static bool build_c(Gen* g, fString build_dir) {
	fString c_filename = F_LIT("a.c");
	fString c_filepath = f_str_join_tmp(build_dir, F_LIT("/"), c_filename);
	
	bool write = true;
	if (write) {
		fFile c_file;
		if (!f_files_open(c_filepath, fFileOpenMode_Write, &c_file)) {
			f_cprint("Failed writing temporary C file to disk!\n");
			return false;
		}

		fWriter* c_file_writer = f_files_get_writer(&c_file);
		gmmc_module_print_c(c_file_writer, g->gmmc);

		f_files_close(&c_file);
	}

	fArray(fString) clang_args = f_array_make<fString>(f_temp_alc());

	f_array_push(&clang_args, F_LIT("clang"));

	if (true) { // with debug info?
		f_array_push(&clang_args, F_LIT("-gcodeview"));
		f_array_push(&clang_args, F_LIT("--debug"));
	}
	else {
		f_array_push(&clang_args, F_LIT("-gcodeview"));
		f_array_push(&clang_args, F_LIT("--debug"));
		f_array_push(&clang_args, F_LIT("-O1"));
	}
	
	// hmm... it seems like we need to use 'main' if we want to use UBSAN
	//f_array_push(&clang_args, F_LIT("-fsanitize=undefined"));

	// Use the LLD linker
	//f_array_push(&clang_args, F_LIT("-fuse-ld=lld"));

	f_array_push(&clang_args, F_LIT("-I../include"));
	f_array_push(&clang_args, F_LIT("-Wno-main-return-type"));
	f_array_push(&clang_args, c_filename);

	fStringBuilder clang_linker_args;
	f_init_string_builder(&clang_linker_args, f_temp_alc());

	f_print(clang_linker_args.w, "-Wl"); // pass comma-separated argument list to the linker
	//f_print(clang_linker_args.w, ",/SUBSYSTEM:~c", BUILD_WITH_CONSOLE ? "CONSOLE" : "WINDOWS");
	//f_print(clang_linker_args.w, ",/ENTRY:ffz_entry,");

	f_print(clang_linker_args.w, ",/INCREMENTAL:NO");
	//f_print(clang_linker_args.w, ",/NODEFAULTLIB"); // disable CRT
	f_print(clang_linker_args.w, ",/DYNAMICBASE:NO"); // to get deterministic pointers

	//for (uint i = 0; i < g->project->link_libraries.len; i++) {
	//	f_print(clang_linker_args.w, ",~s", g->project->link_libraries[i]);
	//}
	//for (uint i = 0; i < g->project->link_system_libraries.len; i++) {
	//	f_print(clang_linker_args.w, ",~s", g->project->link_system_libraries[i]);
	//}

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

extern "C" bool ffz_backend_gen_executable_gmmc(ffzCheckerContext root_module_checker, fSlice(ffzSource*) sources, fString build_dir, fString name) {
	ZoneScoped;
	ffzProject* project = root_module_checker.project;

	//fArenaMark temp_base = f_temp_get_mark();
	gmmcModule* gmmc = gmmc_init(f_temp_alc());

	Gen g = {};
	g.project = project;
	g.pointer_size = project->pointer_size;
	g.root_module = root_module_checker.mod;
	g.gmmc = gmmc;
	g.alc = f_temp_alc();
	g.variable_from_definition = f_map64_make<Variable>(g.alc);
	g.file_id_from_source = f_map64_make<u32>(g.alc);
	g.proc_from_hash = f_map64_make<ProcInfo*>(g.alc);
	g.procs_sorted = f_array_make<ProcInfo*>(g.alc);
	g.globals = f_array_make<GlobalInfo>(g.alc);
	g.cv_file_from_parser_idx = f_array_make<cviewSourceFile>(g.alc);
	g.cv_types = f_array_make<cviewType>(g.alc);

	for (u32 i = 0; i < sources.len; i++) {
		ffzSource* source = sources[i];
		f_map64_insert(&g.file_id_from_source, (u64)source, i);

		cviewSourceFile file = {};
		file.filepath = source->source_code_filepath;
		
		SHA256_CTX sha256;
		sha256_init(&sha256);
		sha256_update(&sha256, source->source_code.data, source->source_code.len);
		sha256_final(&sha256, &file.hash.bytes[0]);
		
		f_array_push(&g.cv_file_from_parser_idx, file);
	}

	//for (uint i = 0; i < project->checkers_dependency_sorted.len; i++) {
	//	ffzModule* mod = project->checkers_dependency_sorted[i];
	{
		g.checker_ctx = &root_module_checker;
		ffzModule* mod = root_module_checker.mod;
		
		// hmm........ so should a ffzProject be responsible for holding analysis about the program?
		// or should it just be responsible for holding the program itself?
		// I think it makes sense to separate the analysis. That way you could make an arena for analysis/checking, modify the program, clear the arena, etc.
		// Separating dependencies is good I think.

		//g.checker = checker;

		// check for the "link_against_libc" build option
		//ffzType* build_option_type = ffz_builtin_type(mod, ffzKeyword_build_option);
		//fArray(ffzNode*)* build_opts = f_map64_get(&mod->all_tags_of_type, build_option_type->hash);
		//if (build_opts) {
		//	for (uint i = 0; i < build_opts->len; i++) {
		//		ffzNode* decl = (*build_opts)[i]->parent;
		//		
		//		// TODO: error reporting. The question is, is this a valid FFZ program if this fails? If it's a valid FFZ program,
		//		// then it should be catched in the checker phase. But should we allow passing isolated flags to the backend?
		//		f_assert(decl->kind == ffzNodeKind_Declare);
		//		
		//		if (ffz_decl_get_name(decl) == F_LIT("link_against_libc")) {
		//			g.link_against_libc = true;
		//			break;
		//		}
		//	}
		//}
		
		for FFZ_EACH_CHILD(n, mod->root) {
			gen_statement(&g, n);
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