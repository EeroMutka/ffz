#include "src/foundation/foundation.h"

#define gmmcString fString
#include "gmmc.h"

#define VALIDATE(x) f_assert(x)

GMMC_API gmmcProcSignature* gmmc_make_proc_signature(gmmcModule* m, gmmcType return_type,
	gmmcType* params, uint32_t params_count)
{
	gmmcProcSignature* s = f_mem_clone((gmmcProcSignature){0}, m->arena);
	s->return_type = return_type;
	s->params = (fSliceRaw){params, params_count};
	f_array_push(&m->proc_signatures, s);
	return s;
}

GMMC_API void gmmc_global_add_relocation(gmmcGlobal* global, uint32_t offset, gmmcSymbol* target) {
	gmmcRelocation reloc = { offset, target };
	f_array_push(&global->relocations, reloc);
}

static gmmcOpIdx gmmc_push_op(gmmcBasicBlock* bb, gmmcOpData* op) {
	op->bb_idx = bb->self_idx;

	gmmcOpIdx idx = (gmmcOpIdx)f_array_push(&bb->proc->ops, *op);
	f_array_push(&bb->ops, idx);
	return idx;
}

static void validate_operand(gmmcBasicBlock* bb, gmmcOpIdx operand, gmmcType required_type/* = gmmcType_None*/) {
#ifdef _DEBUG
	// ops can use operands only from the same basic block, or from GMMC_BB_INDEX_NONE
	gmmcOpData* op = f_array_get_ptr(gmmcOpData, bb->proc->ops, operand);
	gmmcBasicBlockIdx operand_bb_idx = op->bb_idx;
	VALIDATE(operand_bb_idx == bb->self_idx || operand_bb_idx == GMMC_BB_INDEX_NONE);

	if (required_type) VALIDATE(op->type == required_type);
#endif
}

GMMC_API gmmcOpIdx gmmc_op_return(gmmcBasicBlock* bb, gmmcOpIdx value) {
	//if (bb->proc == (void*)0x00000200001811c0 && bb->proc->ops.len == 7) f_trap();
	if (bb->proc->signature->return_type) {
		validate_operand(bb, value, bb->proc->signature->return_type);
	} else {
		VALIDATE(value == GMMC_OP_IDX_INVALID);
	}

	gmmcOpData op = { gmmcOpKind_return };
	op.operands[0] = value;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_debugbreak(gmmcBasicBlock* bb) {
	gmmcOpData op = { gmmcOpKind_debugbreak };
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_comment(gmmcBasicBlock* bb, fString text) {
	gmmcOpData op = { gmmcOpKind_comment };
	op.comment = text;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_load(gmmcBasicBlock* bb, gmmcType type, gmmcOpIdx ptr) {
	validate_operand(bb, ptr, gmmcType_ptr);

	gmmcOpData op = { gmmcOpKind_load };
	op.operands[0] = ptr;
	op.type = type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_store(gmmcBasicBlock* bb, gmmcOpIdx ptr, gmmcOpIdx value) {
	validate_operand(bb, ptr, gmmcType_ptr);
	validate_operand(bb, value, gmmcType_None);
	
	gmmcOpData op = { gmmcOpKind_store };
	op.operands[0] = ptr;
	op.operands[1] = value;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_member_access(gmmcBasicBlock* bb, gmmcOpIdx base, uint32_t offset) {
	validate_operand(bb, base, gmmcType_ptr);

	gmmcOpData op = { gmmcOpKind_member_access };
	op.operands[0] = base;
	op.imm_bits = offset;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_array_access(gmmcBasicBlock* bb, gmmcOpIdx base, gmmcOpIdx index_i64, uint32_t stride) {
	validate_operand(bb, base, gmmcType_ptr);
	validate_operand(bb, index_i64, gmmcType_i64);
	
	gmmcOpData op = { gmmcOpKind_array_access };
	op.operands[0] = base;
	op.operands[1] = index_i64;
	op.imm_bits = stride;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_memcpy(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx src_ptr, gmmcOpIdx size_i32) {
	validate_operand(bb, dst_ptr, gmmcType_ptr);
	validate_operand(bb, src_ptr, gmmcType_ptr);
	validate_operand(bb, size_i32, gmmcType_i32);
	
	gmmcOpData op = { gmmcOpKind_memcpy };
	op.operands[0] = dst_ptr;
	op.operands[1] = src_ptr;
	op.operands[2] = size_i32;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_memset(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx value_i8, gmmcOpIdx size) {
	validate_operand(bb, dst_ptr, gmmcType_ptr);
	validate_operand(bb, value_i8, gmmcType_i8);
	validate_operand(bb, size, gmmcType_i32);

	gmmcOpData op = { gmmcOpKind_memset };
	op.operands[0] = dst_ptr;
	op.operands[1] = value_i8;
	op.operands[2] = size;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_addr_of_symbol(gmmcProc* proc, gmmcSymbol* symbol) {
	gmmcOpData op = { gmmcOpKind_addr_of_symbol };
	op.bb_idx = GMMC_BB_INDEX_NONE;
	op.symbol = symbol;
	op.type = gmmcType_ptr;
	return (gmmcOpIdx)f_array_push(&proc->ops, op);
}

GMMC_API gmmcOpIdx gmmc_op_local(gmmcProc* proc, uint32_t size, uint32_t align) {
	VALIDATE(size > 0);
	gmmcLocal local = { size, align };

	gmmcOpData op = { gmmcOpKind_local };
	op.bb_idx = GMMC_BB_INDEX_NONE;
	op.local_idx = (u32)f_array_push(&proc->locals, local);
	op.type = gmmcType_ptr;
	return (gmmcOpIdx)f_array_push(&proc->ops, op);
}

gmmcOpIdx gmmc_op_immediate(gmmcProc* proc, gmmcType type, void* data) {
	gmmcOpData op = {0};
	op.kind = (gmmcOpKind)(gmmcOpKind_bool + (type - gmmcType_bool));
	op.bb_idx = GMMC_BB_INDEX_NONE;
	memcpy(&op.imm_bits, data, gmmc_type_size(type));
	op.type = type;
	return (gmmcOpIdx)f_array_push(&proc->ops, op);
}

GMMC_API gmmcOpIdx gmmc_op_bool(gmmcProc* proc, bool value) { return gmmc_op_immediate(proc, gmmcType_bool, &value); }
GMMC_API gmmcOpIdx gmmc_op_i8(gmmcProc* proc, uint8_t value) { return gmmc_op_immediate(proc, gmmcType_i8, &value); }
GMMC_API gmmcOpIdx gmmc_op_i16(gmmcProc* proc, uint16_t value) { return gmmc_op_immediate(proc, gmmcType_i16, &value); }
GMMC_API gmmcOpIdx gmmc_op_i32(gmmcProc* proc, uint32_t value) { return gmmc_op_immediate(proc, gmmcType_i32, &value); }
GMMC_API gmmcOpIdx gmmc_op_i64(gmmcProc* proc, uint64_t value) { return gmmc_op_immediate(proc, gmmcType_i64, &value); }
GMMC_API gmmcOpIdx gmmc_op_f32(gmmcProc* proc, float value) { return gmmc_op_immediate(proc, gmmcType_f32, &value); }
GMMC_API gmmcOpIdx gmmc_op_f64(gmmcProc* proc, double value) { return gmmc_op_immediate(proc, gmmcType_f64, &value); }

static gmmcOpIdx op_comparison(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) {
	gmmcType type = gmmc_get_op_type(bb->proc, a);
	validate_operand(bb, a, gmmcType_None);
	validate_operand(bb, b, type);
	
	if (kind == gmmcOpKind_eq || kind == gmmcOpKind_ne) {}
	else {
		VALIDATE(gmmc_type_is_integer(type) || gmmc_type_is_float(type));
	}
	
	gmmcOpData op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.type = gmmcType_bool;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_eq(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_comparison(bb, gmmcOpKind_eq, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_ne(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_comparison(bb, gmmcOpKind_ne, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_lt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_lt, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_le(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_le, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_gt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_gt, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_ge(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_ge, a, b, is_signed); }

GMMC_API gmmcOpIdx gmmc_op_if(gmmcBasicBlock* bb, gmmcOpIdx cond_bool, gmmcBasicBlock* true_bb, gmmcBasicBlock* false_bb) {
	validate_operand(bb, cond_bool, gmmcType_bool);

	gmmcOpData op = { gmmcOpKind_if };
	op.if_.condition = cond_bool;
	op.if_.true_bb = true_bb->self_idx;
	op.if_.false_bb = false_bb->self_idx;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_addr_of_param(gmmcProc* proc, uint32_t index) {
	return f_array_get(gmmcOpIdx, proc->addr_of_params, index);
}

GMMC_API u32 gmmc_type_size(gmmcType type) {
	switch (type) {
	case gmmcType_None: return 0;
	case gmmcType_bool: return 1;
	case gmmcType_ptr: return 8;
	case gmmcType_i8: return 1;
	case gmmcType_i16: return 2;
	case gmmcType_i32: return 4;
	case gmmcType_i64: return 8;
	case gmmcType_i128: return 16;
	case gmmcType_f32: return 4;
	case gmmcType_f64: return 8;
	default: f_trap();
	}
	return 0;
}

static gmmcOpIdx op_int_arithmetic(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) {
	gmmcType type = gmmc_get_op_type(bb->proc, a);
	VALIDATE(gmmc_type_is_integer(type));
	validate_operand(bb, a, gmmcType_None);

	if (kind == gmmcOpKind_not) {}
	else if (kind == gmmcOpKind_shl || kind == gmmcOpKind_shr) {
		validate_operand(bb, b, gmmcType_i8);
	} else {
		validate_operand(bb, b, type);
	}

	gmmcOpData op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.type = type;
	return gmmc_push_op(bb, &op);
}

static gmmcOpIdx op_float_arithmetic(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx a, gmmcOpIdx b) {
	gmmcType type = gmmc_get_op_type(bb->proc, a);
	VALIDATE(gmmc_type_is_float(type));
	validate_operand(bb, a, gmmcType_None);
	validate_operand(bb, b, type);
	
	gmmcOpData op = { kind };
	op.operands[0] = a;
	op.operands[1] = b;
	op.type = type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_fadd(gmmcBasicBlock * bb, gmmcOpIdx a, gmmcOpIdx b) { return op_float_arithmetic(bb, gmmcOpKind_fadd, a, b); }
GMMC_API gmmcOpIdx gmmc_op_fsub(gmmcBasicBlock * bb, gmmcOpIdx a, gmmcOpIdx b) { return op_float_arithmetic(bb, gmmcOpKind_fsub, a, b); }
GMMC_API gmmcOpIdx gmmc_op_fmul(gmmcBasicBlock * bb, gmmcOpIdx a, gmmcOpIdx b) { return op_float_arithmetic(bb, gmmcOpKind_fmul, a, b); }
GMMC_API gmmcOpIdx gmmc_op_fdiv(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_float_arithmetic(bb, gmmcOpKind_fdiv, a, b); }

GMMC_API gmmcOpIdx gmmc_op_add(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_int_arithmetic(bb, gmmcOpKind_add, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_sub(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_int_arithmetic(bb, gmmcOpKind_sub, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_mul(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_int_arithmetic(bb, gmmcOpKind_mul, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_div(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_int_arithmetic(bb, gmmcOpKind_div, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_mod(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_int_arithmetic(bb, gmmcOpKind_mod, a, b, is_signed); }

GMMC_API gmmcOpIdx gmmc_op_int2ptr(gmmcBasicBlock* bb, gmmcOpIdx value) {
	// TODO: specify pointer size on module init
	validate_operand(bb, value, gmmcType_i64);

	gmmcOpData op = { gmmcOpKind_int2ptr };
	op.operands[0] = value;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, &op);
}

static gmmcOpIdx op_simple_convert(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx value, gmmcType type) {
	validate_operand(bb, value, gmmcType_None);
	gmmcOpData op = { kind };
	op.operands[0] = value;
	op.type = type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_ptr2int(gmmcBasicBlock* bb, gmmcOpIdx value) {
	// TODO: specify pointer size on module init
	return op_simple_convert(bb, gmmcOpKind_ptr2int, value, gmmcType_i64);
}

GMMC_API gmmcOpIdx gmmc_op_int2int(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type, bool to_signed) {
	gmmcType src_type = gmmc_get_op_type(bb->proc, value);
	VALIDATE(gmmc_type_is_integer(target_type) && gmmc_type_is_integer(src_type));

	if (gmmc_type_size(target_type) < gmmc_type_size(src_type)) {
		return op_simple_convert(bb, gmmcOpKind_trunc, value, target_type);
	}
	else {
		return to_signed ? op_simple_convert(bb, gmmcOpKind_sxt, value, target_type) :
			op_simple_convert(bb, gmmcOpKind_zxt, value, target_type);
	}
}

GMMC_API gmmcOpIdx gmmc_op_int2float(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type, bool from_signed) {
	gmmcType src_type = gmmc_get_op_type(bb->proc, value);
	validate_operand(bb, value, gmmcType_None);
	VALIDATE(gmmc_type_is_integer(src_type));
	VALIDATE(gmmc_type_is_float(target_type));

	gmmcOpData op = { gmmcOpKind_int2float };
	op.is_signed = from_signed;
	op.operands[0] = value;
	op.type = target_type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_float2int(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type/*, bool to_signed*/) {
	gmmcType src_type = gmmc_get_op_type(bb->proc, value);
	validate_operand(bb, value, gmmcType_None);
	VALIDATE(gmmc_type_is_float(src_type));
	VALIDATE(gmmc_type_is_integer(target_type));

	gmmcOpData op = { gmmcOpKind_float2int };
	//op.is_signed = to_signed;
	op.operands[0] = value;
	op.type = target_type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_float2float(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type) {
	gmmcType src_type = gmmc_get_op_type(bb->proc, value);
	validate_operand(bb, value, gmmcType_None);
	VALIDATE(target_type != src_type);
	VALIDATE(gmmc_type_is_float(src_type));
	VALIDATE(gmmc_type_is_float(target_type));

	gmmcOpData op = { gmmcOpKind_float2float };
	op.operands[0] = value;
	op.type = target_type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcOpIdx gmmc_op_and(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_int_arithmetic(bb, gmmcOpKind_and, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_or(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_int_arithmetic(bb, gmmcOpKind_or, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_xor(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_int_arithmetic(bb, gmmcOpKind_xor, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_not(gmmcBasicBlock* bb, gmmcOpIdx a) { return op_int_arithmetic(bb, gmmcOpKind_not, a, GMMC_OP_IDX_INVALID, false); }
GMMC_API gmmcOpIdx gmmc_op_shl(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx shift) { return op_int_arithmetic(bb, gmmcOpKind_shl, a, shift, false); }
GMMC_API gmmcOpIdx gmmc_op_shr(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx shift) { return op_int_arithmetic(bb, gmmcOpKind_shr, a, shift, false); }

GMMC_API gmmcOpIdx gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to) {
	gmmcOpData op = { gmmcOpKind_goto };
	op.goto_.dst_bb = to->self_idx;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcBasicBlock* gmmc_make_basic_block(gmmcProc* proc) {
	gmmcBasicBlock* b = f_mem_clone((gmmcBasicBlock){0}, proc->sym.module->arena);
	b->mod = proc->sym.module;
	b->proc = proc;
	b->ops = f_array_make(proc->sym.module->arena);
	b->self_idx = (gmmcBasicBlockIdx)f_array_push(&proc->basic_blocks, b);
	return b;
}

GMMC_API gmmcExtern* gmmc_make_extern(gmmcModule* m, gmmcString name) {
	gmmcExtern* sym = f_mem_clone((gmmcExtern){{gmmcSymbolKind_Extern}}, m->arena);
	sym->self_idx = (gmmcExternIdx)f_array_push(&m->external_symbols, sym);
	sym->sym.module = m;
	sym->sym.name = name;
	return sym;
}

GMMC_API gmmcProc* gmmc_make_proc(gmmcModule* m,
	gmmcProcSignature* signature,
	gmmcString name, gmmcBasicBlock** out_entry_bb)
{
	VALIDATE(name.len > 0);

	gmmcProc* proc = f_mem_clone((gmmcProc){0}, m->arena);
	proc->sym.kind = gmmcSymbolKind_Proc;
	proc->sym.module = m;
	proc->sym.name = name;
	proc->self_idx = (gmmcProcIdx)f_array_push(&m->procs, proc);
	proc->signature = signature;
	
	proc->locals = f_array_make(m->arena);
	proc->ops = f_array_make(m->arena);
	f_array_push(&proc->locals, (gmmcLocal){0});      // local 0 is invalid

	proc->basic_blocks = f_array_make(m->arena);
	proc->entry_bb = gmmc_make_basic_block(proc);

	proc->addr_of_params = f_make_slice_undef(gmmcOpIdx, signature->params.len, m->arena);

	for (uint i = 0; i < signature->params.len; i++) {
		gmmcOpData op = { gmmcOpKind_addr_of_param };
		op.bb_idx = GMMC_BB_INDEX_NONE;
		op.type = gmmcType_ptr;
		op.imm_bits = i;
		f_array_set(gmmcOpIdx, proc->addr_of_params, i, (gmmcOpIdx)f_array_push(&proc->ops, op));
	}
	
	*out_entry_bb = proc->entry_bb;
	return proc;
}

GMMC_API gmmcOpIdx gmmc_op_call(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcOpIdx proc_address,
	gmmcOpIdx* in_arguments, uint32_t in_arguments_count)
{
	validate_operand(bb, proc_address, gmmcType_ptr);
	for (u32 i = 0; i < in_arguments_count; i++) {
		validate_operand(bb, in_arguments[i], gmmcType_None);
	}
	
	gmmcOpData op = { gmmcOpKind_vcall };
	op.call.target = proc_address;
	op.call.arguments = f_clone_to_slice(in_arguments, in_arguments_count, bb->mod->arena);
	op.type = return_type;
	return gmmc_push_op(bb, &op);
}

GMMC_API gmmcModule* gmmc_init(fArena* arena) {
	gmmcModule* m = f_mem_clone((gmmcModule){0}, arena);
	m->arena = arena;
	m->proc_signatures = f_array_make(m->arena);
	m->globals = f_array_make(m->arena);
	
	gmmcGlobal* null_global = NULL;
	f_array_push(&m->globals, null_global);
	
	m->procs = f_array_make(m->arena);
	m->external_symbols = f_array_make(m->arena);
	return m;
}

GMMC_API gmmcGlobal* gmmc_make_global(gmmcModule* m, uint32_t size, uint32_t align, gmmcSection section, void** out_data) {
	void* data = f_mem_alloc(size, m->arena);
	memset(data, 0, size);
	f_assert(section != gmmcSection_Code); // hmm... todo? this should be fine on the assembly target, but what about C?

	gmmcGlobal* global = f_mem_clone((gmmcGlobal){0}, m->arena);
	global->self_idx = (gmmcGlobalIdx)f_array_push(&m->globals, global);
	global->sym.kind = gmmcSymbolKind_Global;
	global->sym.module = m;
	global->sym.name = f_aprint(m->arena, "g$~u32", global->self_idx);
	global->size = size;
	global->align = align;
	global->section = section;
	global->data = data;
	global->relocations = f_array_make(m->arena);

	*out_data = data;
	return global;
}


/*
int factorial(int n) {
	if (n <= 1) return 1;
	return n * factorial(n - 1);
}
*/


#if 0
GMMC_API void gmmc_test() {
	fArena* temp = f_temp_alc();
	f_os_set_working_dir(F_LIT("C:\\dev\\ffz\\gmmc\\test"));

	//int x = factorial(10);
	
	// need to specify zero padding!
	//alignas()
	const u8 my_data[] = {125,05,021,0,0,0,0,0,0,0,0,120,152,125,125,0x10,0,0,0,0,0,0,0,250,0125,0,152,125};
	//int x = sizeof(foo);
	//int y = sizeof(my_data);
	
	gmmcModule* m = gmmc_init(temp);

	gmmcType params[] = {gmmcType_i32};
	gmmcProcSignature* sig = gmmc_make_proc_signature(m, gmmcType_i32, params, F_LEN(params));
	
	gmmcBasicBlock* bb;
	gmmcProc* test_proc = gmmc_make_proc(m, sig, F_LIT("factorial"), &bb);
	
	void* global_a_data;
	gmmcGlobal* global_a = gmmc_make_global(m, F_LEN(my_data), 8, gmmcSection_RData, &global_a_data);
	memcpy(global_a_data, my_data, F_LEN(my_data));
	gmmc_global_add_relocation(global_a, 3, gmmc_proc_as_symbol(test_proc));
	gmmc_global_add_relocation(global_a, 15, gmmc_proc_as_symbol(test_proc));

	gmmcBasicBlock* true_bb = gmmc_make_basic_block(test_proc);
	gmmcBasicBlock* false_bb = gmmc_make_basic_block(test_proc);
	gmmc_op_if(bb, gmmc_op_le(bb, gmmc_op_param(test_proc, 0), gmmc_op_i32(bb, 1), false), true_bb, false_bb);
	
	gmmc_op_debugbreak(true_bb);
	gmmc_op_return(true_bb, gmmc_op_i32(true_bb, 1));
	
	gmmc_op_debugbreak(false_bb);
	gmmc_op_debugbreak(false_bb);
	
	gmmcOpIdx param_n = gmmc_op_param(test_proc, 0);
	gmmcOpIdx n_minus_1 = gmmc_op_sub(false_bb, param_n, gmmc_op_i32(false_bb, 1));
	gmmcOpIdx return_val = gmmc_op_mul(false_bb, param_n,
		gmmc_op_call(false_bb, gmmcType_i32, gmmc_proc_as_symbol(test_proc), &n_minus_1, 1), false);

	gmmc_op_return(false_bb, return_val);

	gmmc_module_print(stdout, m);

	//gmmc_proc_compile(test_proc);
	
	//gmmc_create_coff(m, F_LIT("test.obj"));
	f_trap();
}
#endif
