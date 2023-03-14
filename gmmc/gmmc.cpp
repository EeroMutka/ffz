#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"

//#include <Zydis/Zydis.h>

#define VALIDATE(x) F_ASSERT(x)

GMMC_API gmmcProcSignature* gmmc_make_proc_signature(gmmcModule* m, gmmcType return_type,
	gmmcType* params, uint32_t params_count)
{
	gmmcProcSignature* s = f_mem_clone(gmmcProcSignature{}, m->allocator);
	s->return_type = return_type;
	s->params = {params, params_count};
	f_array_push(&m->proc_signatures, s);
	return s;
}

//const fString gmmcOpKind_to_string[] = {
//	F_LIT_COMP("Invalid"),
//	F_LIT_COMP("debugbreak"),
//	F_LIT_COMP("ret"),
//	F_LIT_COMP("if"),
//};
//
//F_STATIC_ASSERT(gmmcOpKind_COUNT == F_LEN(gmmcOpKind_to_string));

GMMC_API void gmmc_global_add_relocation(gmmcGlobal* global, uint32_t offset, gmmcSymbol* target) {
	f_array_push(&global->relocations, gmmcRelocation{offset, target});
}

//static gmmcOpIdx make_reg(gmmcProc* proc, gmmcType type, u32 local_idx = 0);

static gmmcOpIdx gmmc_push_op(gmmcBasicBlock* bb, const gmmcOpData& op) {
	gmmcOpIdx idx = (gmmcOpIdx)f_array_push(&bb->proc->ops, op);
	f_array_push(&bb->ops, idx);
	return idx;
}

GMMC_API gmmcOpIdx gmmc_op_return(gmmcBasicBlock* bb, gmmcOpIdx value) {
	VALIDATE(gmmc_op_get_type(bb->proc, value) == bb->proc->signature->return_type);

	gmmcOpData op = { gmmcOpKind_return };
	op.operands[0] = value;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_debugbreak(gmmcBasicBlock* bb) {
	gmmcOpData op = { gmmcOpKind_debugbreak };
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_comment(gmmcBasicBlock* bb, fString text) {
	gmmcOpData op = { gmmcOpKind_comment };
	op.comment = text;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_load(gmmcBasicBlock* bb, gmmcType type, gmmcOpIdx ptr) {
	VALIDATE(gmmc_op_get_type(bb->proc, ptr) == gmmcType_ptr);

	gmmcOpData op = { gmmcOpKind_load };
	op.operands[0] = ptr;
	op.type = type;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_store(gmmcBasicBlock* bb, gmmcOpIdx ptr, gmmcOpIdx value) {
	VALIDATE(gmmc_op_get_type(bb->proc, ptr) == gmmcType_ptr);
	
	gmmcOpData op = { gmmcOpKind_store };
	op.operands[0] = ptr;
	op.operands[1] = value;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_member_access(gmmcBasicBlock* bb, gmmcOpIdx base, uint32_t offset) {
	F_ASSERT(gmmc_op_get_type(bb->proc, base) == gmmcType_ptr);

	gmmcOpData op = { gmmcOpKind_member_access };
	op.operands[0] = base;
	op.imm_raw = offset;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_array_access(gmmcBasicBlock* bb, gmmcOpIdx base, gmmcOpIdx index, uint32_t stride) {
	F_ASSERT(gmmc_op_get_type(bb->proc, base) == gmmcType_ptr);
	F_ASSERT(gmmc_type_is_integer(gmmc_op_get_type(bb->proc, index)));
	
	gmmcOpData op = { gmmcOpKind_array_access };
	op.operands[0] = base;
	op.operands[1] = index;
	op.imm_raw = stride;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_memmove(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx src_ptr, gmmcOpIdx size) {
	VALIDATE(gmmc_op_get_type(bb->proc, dst_ptr) == gmmcType_ptr);
	VALIDATE(gmmc_op_get_type(bb->proc, src_ptr) == gmmcType_ptr);
	VALIDATE(gmmc_type_is_integer(gmmc_op_get_type(bb->proc, size)));
	
	gmmcOpData op = { gmmcOpKind_memmove };
	op.operands[0] = dst_ptr;
	op.operands[1] = src_ptr;
	op.operands[2] = size;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_memset(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx value_i8, gmmcOpIdx size) {
	VALIDATE(gmmc_op_get_type(bb->proc, dst_ptr) == gmmcType_ptr);
	VALIDATE(gmmc_op_get_type(bb->proc, value_i8) == gmmcType_i8);
	VALIDATE(gmmc_type_is_integer(gmmc_op_get_type(bb->proc, size)));

	gmmcOpData op = { gmmcOpKind_memset };
	op.operands[0] = dst_ptr;
	op.operands[1] = value_i8;
	op.operands[2] = size;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_local(gmmcProc* proc, uint32_t size, uint32_t align) {
	VALIDATE(size > 0);

	gmmcOpData op = { gmmcOpKind_local };
	op.local_idx = (u32)f_array_push(&proc->locals, gmmcLocal{ size, align });
	op.type = gmmcType_ptr;
	return (gmmcOpIdx)f_array_push(&proc->ops, op); // NOTE: we're not adding the local to any BB
}

static gmmcOpIdx op_comparison(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) {
	gmmcType type = gmmc_op_get_type(bb->proc, a);
	F_ASSERT(gmmc_op_get_type(bb->proc, b) == type);
	
	if (kind == gmmcOpKind_eq || kind == gmmcOpKind_ne) {}
	else F_ASSERT(gmmc_type_is_integer(type));
	
	gmmcOpData op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.type = gmmcType_bool;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_eq(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_comparison(bb, gmmcOpKind_eq, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_ne(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_comparison(bb, gmmcOpKind_ne, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_lt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_lt, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_le(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_le, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_gt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_gt, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_ge(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_comparison(bb, gmmcOpKind_ge, a, b, is_signed); }

GMMC_API gmmcOpIdx gmmc_op_if(gmmcBasicBlock* bb, gmmcOpIdx cond_bool, gmmcBasicBlock* true_bb, gmmcBasicBlock* false_bb) {
	F_ASSERT(gmmc_op_get_type(bb->proc, cond_bool) == gmmcType_bool);

	gmmcOpData op = { gmmcOpKind_if };
	op.if_.condition = cond_bool;
	op.if_.dst_bb[0] = true_bb;
	op.if_.dst_bb[1] = false_bb;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_addr_of_param(gmmcProc* proc, uint32_t index) {
	return proc->params[index];
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
	default: F_BP;
	}
	return 0;
}

gmmcOpIdx gmmc_op_immediate(gmmcBasicBlock* bb, gmmcType type, void* data) {
	gmmcOpKind op_kind = (gmmcOpKind)(gmmcOpKind_bool + (type - gmmcType_bool));
	gmmcOpData op = { op_kind };
	memcpy(&op.imm_raw, data, gmmc_type_size(type));
	op.type = type;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_bool(gmmcBasicBlock* bb, bool value) { return gmmc_op_immediate(bb, gmmcType_bool, &value); }
GMMC_API gmmcOpIdx gmmc_op_i8(gmmcBasicBlock* bb, uint8_t value) { return gmmc_op_immediate(bb, gmmcType_i8, &value); }
GMMC_API gmmcOpIdx gmmc_op_i16(gmmcBasicBlock* bb, uint16_t value) { return gmmc_op_immediate(bb, gmmcType_i16, &value); }
GMMC_API gmmcOpIdx gmmc_op_i32(gmmcBasicBlock* bb, uint32_t value) { return gmmc_op_immediate(bb, gmmcType_i32, &value); }
GMMC_API gmmcOpIdx gmmc_op_i64(gmmcBasicBlock* bb, uint64_t value) { return gmmc_op_immediate(bb, gmmcType_i64, &value); }
GMMC_API gmmcOpIdx gmmc_op_f32(gmmcBasicBlock* bb, float value) { return gmmc_op_immediate(bb, gmmcType_f32, &value); }
GMMC_API gmmcOpIdx gmmc_op_f64(gmmcBasicBlock* bb, double value) { return gmmc_op_immediate(bb, gmmcType_f64, &value); }

static gmmcOpIdx op_basic_2(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) {
	gmmcType type = gmmc_op_get_type(bb->proc, a);
	VALIDATE(type == gmmc_op_get_type(bb->proc, b));
	//VALIDATE(gmmc_type_is_integer(type));

	gmmcOpData op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.type = type;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_add(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_basic_2(bb, gmmcOpKind_add, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_sub(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_basic_2(bb, gmmcOpKind_sub, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_mul(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_basic_2(bb, gmmcOpKind_mul, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_div(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_basic_2(bb, gmmcOpKind_div, a, b, is_signed); }
GMMC_API gmmcOpIdx gmmc_op_mod(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed) { return op_basic_2(bb, gmmcOpKind_mod, a, b, is_signed); }


GMMC_API gmmcOpIdx gmmc_op_int2ptr(gmmcBasicBlock* bb, gmmcOpIdx value) {
	VALIDATE(gmmc_type_is_integer(gmmc_op_get_type(bb->proc, value)));

	gmmcOpData op = { gmmcOpKind_int2ptr };
	op.operands[0] = value;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, op);
}

static gmmcOpIdx op_simple_convert(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcOpIdx value, gmmcType type) {
	gmmcOpData op = { kind };
	op.operands[0] = value;
	op.type = type;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_ptr2int(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_ptr2int, value, type); }
GMMC_API gmmcOpIdx gmmc_op_zxt(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_zxt, value, type); }
GMMC_API gmmcOpIdx gmmc_op_sxt(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_sxt, value, type); }
GMMC_API gmmcOpIdx gmmc_op_trunc(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_trunc, value, type); }

GMMC_API gmmcOpIdx gmmc_op_and(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_basic_2(bb, gmmcOpKind_and, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_or(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_basic_2(bb, gmmcOpKind_or, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_xor(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b) { return op_basic_2(bb, gmmcOpKind_xor, a, b, false); }
GMMC_API gmmcOpIdx gmmc_op_not(gmmcBasicBlock* bb, gmmcOpIdx value) { return op_basic_2(bb, gmmcOpKind_not, value, GMMC_OP_IDX_INVALID, false); }
GMMC_API gmmcOpIdx gmmc_op_shl(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcOpIdx shift) { return op_basic_2(bb, gmmcOpKind_shl, value, shift, false); }
GMMC_API gmmcOpIdx gmmc_op_shr(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcOpIdx shift) { return op_basic_2(bb, gmmcOpKind_shr, value, shift, false); }

GMMC_API gmmcOpIdx gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to) {
	gmmcOpData op = { gmmcOpKind_goto };
	op.goto_.dst_bb = to;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_addr_of_symbol(gmmcBasicBlock* bb, gmmcSymbol* symbol) {
	gmmcOpData op = { gmmcOpKind_addr_of_symbol };
	op.symbol = symbol;
	op.type = gmmcType_ptr;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcBasicBlock* gmmc_make_basic_block(gmmcProc* proc) {
	gmmcBasicBlock* b = f_mem_clone(gmmcBasicBlock{}, proc->sym.module->allocator);
	b->mod = proc->sym.module;
	b->proc = proc;
	b->ops = f_array_make<gmmcOpIdx>(proc->sym.module->allocator);
	b->bb_index = (u32)f_array_push(&proc->basic_blocks, b);
	return b;
}

GMMC_API gmmcSymbol* gmmc_make_external_symbol(gmmcModule* m, gmmcString name) {
	gmmcSymbol* sym = f_mem_clone(gmmcSymbol{gmmcSymbolKind_Extern}, m->allocator);
	f_array_push(&m->external_symbols, sym);
	sym->module = m;
	sym->name = name;
	return sym;
}

GMMC_API gmmcProc* gmmc_make_proc(gmmcModule* m,
	gmmcProcSignature* signature,
	gmmcString name, gmmcBasicBlock** out_entry_bb)
{
	gmmcProc* proc = f_mem_clone(gmmcProc{}, m->allocator);
	proc->sym.kind = gmmcSymbolKind_Proc;
	proc->sym.module = m;
	proc->sym.name = name;
	proc->self_idx = (gmmcProcIdx)f_array_push(&m->procs, proc);
	proc->signature = signature;
	
	proc->locals = f_array_make<gmmcLocal>(m->allocator);
	proc->ops = f_array_make<gmmcOpData>(m->allocator);
	f_array_push(&proc->ops, {});        // op 0 is invalid
	f_array_push(&proc->locals, {});     // local 0 is invalid

	proc->basic_blocks = f_array_make<gmmcBasicBlock*>(m->allocator);
	proc->entry_bb = gmmc_make_basic_block(proc);

	proc->params = f_make_slice_garbage<gmmcOpIdx>(signature->params.len, m->allocator);
	for (uint i = 0; i < signature->params.len; i++) {
		gmmcOpData op = { gmmcOpKind_addr_of_param };
		op.type = gmmcType_ptr; //signature->params[i];
		op.imm_raw = i;
		proc->params[i] = (gmmcOpIdx)f_array_push(&proc->ops, op);
	}
	
	*out_entry_bb = proc->entry_bb;
	return proc;
}

GMMC_API gmmcOpIdx gmmc_op_call(gmmcBasicBlock* bb, gmmcType return_type, gmmcSymbol* procedure,
	gmmcOpIdx* in_arguments, uint32_t in_arguments_count)
{
	gmmcOpData op = { gmmcOpKind_call };
	op.call.target_sym = procedure;
	op.call.arguments = f_clone_slice<gmmcOpIdx>({ in_arguments, in_arguments_count }, bb->mod->allocator);
	op.type = return_type;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcOpIdx gmmc_op_vcall(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcOpIdx proc_address,
	gmmcOpIdx* in_arguments, uint32_t in_arguments_count)
{
	gmmcOpData op = { gmmcOpKind_vcall };
	op.call.target = proc_address;
	op.call.arguments = f_clone_slice<gmmcOpIdx>({ in_arguments, in_arguments_count }, bb->mod->allocator);
	op.type = return_type;
	return gmmc_push_op(bb, op);
}

GMMC_API gmmcModule* gmmc_init(fAllocator* allocator) {
	gmmcModule* m = f_mem_clone(gmmcModule{}, allocator);
	m->allocator = allocator;
	m->proc_signatures = f_array_make<gmmcProcSignature*>(m->allocator);
	m->globals = f_array_make<gmmcGlobal*>(m->allocator);
	f_array_push(&m->globals, (gmmcGlobal*)0);
	m->procs = f_array_make<gmmcProc*>(m->allocator);
	m->external_symbols = f_array_make<gmmcSymbol*>(m->allocator);
	return m;
}

GMMC_API gmmcGlobal* gmmc_make_global(gmmcModule* m, uint32_t size, uint32_t align, gmmcSection section, void** out_data) {
	void* data = f_mem_alloc(size, align, m->allocator);
	memset(data, 0, size);
	F_ASSERT(section != gmmcSection_Code); // hmm... todo? this should be fine on the assembly target, but what about C?

	gmmcGlobal* global = f_mem_clone(gmmcGlobal{}, m->allocator);
	global->self_idx = (gmmcGlobalIdx)f_array_push(&m->globals, global);
	global->sym.kind = gmmcSymbolKind_Global;
	global->sym.module = m;
	global->sym.name = f_str_format(m->allocator, "g$%u", global->self_idx);
	global->size = size;
	global->align = align;
	global->section = section;
	global->data = data;
	global->relocations = f_array_make<gmmcRelocation>(m->allocator);

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
	fAllocator* temp = f_temp_alc();
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
	F_BP;
}
#endif
