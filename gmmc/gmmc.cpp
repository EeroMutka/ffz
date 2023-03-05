#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"
#include "gmmc_coff.h"

#include <Zydis/Zydis.h>

#include <stdio.h>
#include <stdlib.h> // for qsort

#define VALIDATE(x) F_ASSERT(x)

typedef struct gmmcModule {
	fAllocator* allocator;
	
	fArray(gmmcProcSignature*) proc_signatures;
	fArray(gmmcGlobal*) globals;
	fArray(gmmcProc*) procs;
	fArray(gmmcSymbol*) external_symbols;

	fArray(u8) code_section;
	//fArray(gmmcType) type_from_reg;

} gmmcModule;

typedef struct gmmcProcSignature {
	//u32 index;
	gmmcType return_type;
	fSlice(gmmcType) params;
} gmmcProcSignature;

GMMC_API gmmcProcSignature* gmmc_make_proc_signature(gmmcModule* m, gmmcType return_type,
	gmmcType* params, uint32_t params_count)
{
	gmmcProcSignature* s = f_mem_clone(gmmcProcSignature{}, m->allocator);
	s->return_type = return_type;
	s->params = {params, params_count};
	f_array_push(&m->proc_signatures, s);
	return s;
}

typedef enum gmmcSymbolKind {
	gmmcSymbolKind_Global,
	gmmcSymbolKind_Proc,
	gmmcSymbolKind_Extern,
} gmmcSymbolKind;

typedef struct gmmcSymbol {
	gmmcSymbolKind kind;
	gmmcModule* mod;
	gmmcString name;
} gmmcSymbol;
typedef struct gmmcLocal {
	u32 size;
	u32 align;
} gmmcLocal;

typedef struct gmmcProc {
	gmmcSymbol sym; // NOTE: must be the first member!

	gmmcProcSignature* signature;
	gmmcBasicBlock* entry_bb;
	
	fArray(gmmcBasicBlock*) basic_blocks;
	
	fSlice(gmmcReg) params;

	//fArray(gmmcLocal) locals;
	
	fArray(gmmcType) type_from_reg;
	fArray(gmmcLocal*) local_from_reg;


	//fSlice(u8) built_x64_instructions;
} gmmcProc;


typedef struct gmmcReloc {
	uint32_t offset;
	gmmcSymbol* target;
} gmmcReloc;

typedef struct gmmcGlobal {
	gmmcSymbol sym; // NOTE: must be the first member!

	u32 size;
	u32 align;
	bool readonly;
	void* data;

	fArray(gmmcReloc) relocations;
} gmmcGlobal;
//const fString gmmcOpKind_to_string[] = {
//	F_LIT_COMP("Invalid"),
//	F_LIT_COMP("debugbreak"),
//	F_LIT_COMP("ret"),
//	F_LIT_COMP("if"),
//};
//
//F_STATIC_ASSERT(gmmcOpKind_COUNT == F_LEN(gmmcOpKind_to_string));

GMMC_API void gmmc_global_add_relocation(gmmcGlobal* global, uint32_t offset, gmmcSymbol* target) {
	f_array_push(&global->relocations, gmmcReloc{offset, target});
}

inline bool gmmc_op_is_terminating(gmmcOpKind op) { return op >= gmmcOpKind_return && op <= gmmcOpKind_if; }

static gmmcReg make_reg(gmmcProc* proc, gmmcType type);

typedef struct gmmcBasicBlock {
	gmmcModule* mod;
	gmmcProc* proc;
	u32 bb_index;

	fArray(gmmcOp) ops;

	struct {
		u32 code_section_offset = F_U32_MAX; // F_U32_MAX if not been built yet
	} gen;
} gmmcBasicBlock;


gmmcType reg_get_type(gmmcProc* proc, gmmcReg reg) {
	return proc->type_from_reg[reg];
}

GMMC_API void gmmc_op_return(gmmcBasicBlock* bb, gmmcReg value) {
	VALIDATE(reg_get_type(bb->proc, value) == bb->proc->signature->return_type);

	gmmcOp op = { gmmcOpKind_return };
	op.operands[0] = value;
	f_array_push(&bb->ops, op);
}

GMMC_API void gmmc_op_debugbreak(gmmcBasicBlock* bb) {
	gmmcOp op = { gmmcOpKind_debugbreak };
	f_array_push(&bb->ops, op);
}

GMMC_API void gmmc_op_comment(gmmcBasicBlock* bb, fString text) {
	gmmcOp op = { gmmcOpKind_comment };
	op.comment = text;
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcReg gmmc_op_load(gmmcBasicBlock* bb, gmmcType type, gmmcReg ptr) {
	VALIDATE(reg_get_type(bb->proc, ptr) == gmmcType_ptr);

	gmmcOp op = { gmmcOpKind_load };
	op.operands[0] = ptr;
	op.result = make_reg(bb->proc, type);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API void gmmc_op_store(gmmcBasicBlock* bb, gmmcReg ptr, gmmcReg value) {
	VALIDATE(reg_get_type(bb->proc, ptr) == gmmcType_ptr);
	
	gmmcOp op = { gmmcOpKind_store };
	op.operands[0] = ptr;
	op.operands[1] = value;
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcReg gmmc_op_member_access(gmmcBasicBlock* bb, gmmcReg base, uint32_t offset) {
	F_ASSERT(reg_get_type(bb->proc, base) == gmmcType_ptr);

	gmmcOp op = { gmmcOpKind_member_access };
	op.operands[0] = base;
	op.imm = offset;
	op.result = make_reg(bb->proc, gmmcType_ptr);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_array_access(gmmcBasicBlock* bb, gmmcReg base, gmmcReg index, uint32_t stride) {
	F_ASSERT(reg_get_type(bb->proc, base) == gmmcType_ptr);
	F_ASSERT(gmmc_type_is_integer(reg_get_type(bb->proc, index)));
	
	gmmcOp op = { gmmcOpKind_array_access };
	op.operands[0] = base;
	op.operands[1] = index;
	op.imm = stride;
	op.result = make_reg(bb->proc, gmmcType_ptr);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API void gmmc_op_memmove(gmmcBasicBlock* bb, gmmcReg dst_ptr, gmmcReg src_ptr, gmmcReg size) {
	VALIDATE(reg_get_type(bb->proc, dst_ptr) == gmmcType_ptr);
	VALIDATE(reg_get_type(bb->proc, src_ptr) == gmmcType_ptr);
	VALIDATE(gmmc_type_is_integer(reg_get_type(bb->proc, size)));
	
	gmmcOp op = { gmmcOpKind_memmove };
	op.operands[0] = dst_ptr;
	op.operands[1] = src_ptr;
	op.operands[2] = size;
	f_array_push(&bb->ops, op);
}

GMMC_API void gmmc_op_memset(gmmcBasicBlock* bb, gmmcReg dst_ptr, gmmcReg value_i8, gmmcReg size) {
	VALIDATE(reg_get_type(bb->proc, dst_ptr) == gmmcType_ptr);
	VALIDATE(reg_get_type(bb->proc, value_i8) == gmmcType_i8);
	VALIDATE(gmmc_type_is_integer(reg_get_type(bb->proc, size)));

	gmmcOp op = { gmmcOpKind_memset };
	op.operands[0] = dst_ptr;
	op.operands[1] = value_i8;
	op.operands[2] = size;
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcReg gmmc_op_local(gmmcProc* proc, uint32_t size, uint32_t align) {
	gmmcLocal* local = f_mem_clone(gmmcLocal{ size, align }, proc->sym.mod->allocator);
	gmmcReg reg = (gmmcReg)f_array_push(&proc->type_from_reg, gmmcType_ptr);
	f_array_push(&proc->local_from_reg, local);
	return reg;
}

static gmmcReg op_comparison(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcReg a, gmmcReg b, bool is_signed) {
	gmmcType type = reg_get_type(bb->proc, a);
	F_ASSERT(reg_get_type(bb->proc, b) == type);
	
	if (kind == gmmcOpKind_eq || kind == gmmcOpKind_ne) {}
	else F_ASSERT(gmmc_type_is_integer(type));
	
	gmmcOp op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.result = make_reg(bb->proc, gmmcType_bool);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_eq(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_comparison(bb, gmmcOpKind_eq, a, b, false); }
GMMC_API gmmcReg gmmc_op_ne(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_comparison(bb, gmmcOpKind_ne, a, b, false); }
GMMC_API gmmcReg gmmc_op_lt(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_comparison(bb, gmmcOpKind_lt, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_le(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_comparison(bb, gmmcOpKind_le, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_gt(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_comparison(bb, gmmcOpKind_gt, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_ge(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_comparison(bb, gmmcOpKind_ge, a, b, is_signed); }

GMMC_API void gmmc_op_if(gmmcBasicBlock* bb, gmmcReg cond_bool, gmmcBasicBlock* true_bb, gmmcBasicBlock* false_bb) {
	F_ASSERT(reg_get_type(bb->proc, cond_bool) == gmmcType_bool);

	gmmcOp op = { gmmcOpKind_if };
	op.if_.condition = cond_bool;
	op.if_.dst_bb[0] = true_bb;
	op.if_.dst_bb[1] = false_bb;
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcReg gmmc_op_param(gmmcProc* proc, uint32_t index) {
	return proc->params[index];
}

gmmcReg gmmc_op_immediate(gmmcBasicBlock* bb, gmmcType type, u64 value) {
	gmmcOpKind op_kind = (gmmcOpKind)(gmmcOpKind_bool + (type - gmmcType_bool));
	gmmcOp op = { op_kind };
	op.imm = value;
	op.result = make_reg(bb->proc, type);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_bool(gmmcBasicBlock* bb, bool value) { return gmmc_op_immediate(bb, gmmcType_bool, (u64)value); }
GMMC_API gmmcReg gmmc_op_i8(gmmcBasicBlock* bb, uint8_t value) { return gmmc_op_immediate(bb, gmmcType_i8, (u64)value); }
GMMC_API gmmcReg gmmc_op_i16(gmmcBasicBlock* bb, uint16_t value) { return gmmc_op_immediate(bb, gmmcType_i16, (u64)value); }
GMMC_API gmmcReg gmmc_op_i32(gmmcBasicBlock* bb, uint32_t value) { return gmmc_op_immediate(bb, gmmcType_i32, (u64)value); }
GMMC_API gmmcReg gmmc_op_i64(gmmcBasicBlock* bb, uint64_t value) { return gmmc_op_immediate(bb, gmmcType_i64, (u64)value); }


static gmmcReg op_basic_2(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcReg a, gmmcReg b, bool is_signed) {
	gmmcType type = reg_get_type(bb->proc, a);
	VALIDATE(type == reg_get_type(bb->proc, b));
	//VALIDATE(gmmc_type_is_integer(type));

	gmmcOp op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.result = make_reg(bb->proc, type);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_add(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_basic_2(bb, gmmcOpKind_add, a, b, false); }
GMMC_API gmmcReg gmmc_op_sub(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_basic_2(bb, gmmcOpKind_sub, a, b, false); }
GMMC_API gmmcReg gmmc_op_mul(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_basic_2(bb, gmmcOpKind_mul, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_div(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_basic_2(bb, gmmcOpKind_div, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_mod(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_basic_2(bb, gmmcOpKind_mod, a, b, is_signed); }


GMMC_API gmmcReg gmmc_op_int2ptr(gmmcBasicBlock* bb, gmmcReg value) {
	VALIDATE(gmmc_type_is_integer(reg_get_type(bb->proc, value)));

	gmmcOp op = { gmmcOpKind_int2ptr };
	op.operands[0] = value;
	op.result = make_reg(bb->proc, gmmcType_ptr);
	f_array_push(&bb->ops, op);
	return op.result;
}

static gmmcReg op_simple_convert(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcReg value, gmmcType type) {
	gmmcOp op = { kind };
	op.operands[0] = value;
	op.result = make_reg(bb->proc, type);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_ptr2int(gmmcBasicBlock* bb, gmmcReg value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_ptr2int, value, type); }
GMMC_API gmmcReg gmmc_op_zxt(gmmcBasicBlock* bb, gmmcReg value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_zxt, value, type); }
GMMC_API gmmcReg gmmc_op_sxt(gmmcBasicBlock* bb, gmmcReg value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_sxt, value, type); }
GMMC_API gmmcReg gmmc_op_trunc(gmmcBasicBlock* bb, gmmcReg value, gmmcType type) { return op_simple_convert(bb, gmmcOpKind_trunc, value, type); }

GMMC_API gmmcReg gmmc_op_and(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_basic_2(bb, gmmcOpKind_and, a, b, false); }
GMMC_API gmmcReg gmmc_op_or(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_basic_2(bb, gmmcOpKind_or, a, b, false); }
GMMC_API gmmcReg gmmc_op_xor(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_basic_2(bb, gmmcOpKind_xor, a, b, false); }
GMMC_API gmmcReg gmmc_op_not(gmmcBasicBlock* bb, gmmcReg value) { return op_basic_2(bb, gmmcOpKind_not, value, GMMC_REG_NONE, false); }
GMMC_API gmmcReg gmmc_op_shl(gmmcBasicBlock* bb, gmmcReg value, gmmcReg shift) { return op_basic_2(bb, gmmcOpKind_shl, value, shift, false); }
GMMC_API gmmcReg gmmc_op_shr(gmmcBasicBlock* bb, gmmcReg value, gmmcReg shift) { return op_basic_2(bb, gmmcOpKind_shr, value, shift, false); }

GMMC_API void gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to) {
	gmmcOp op = { gmmcOpKind_goto };
	op.goto_.dst_bb = to;
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcReg gmmc_op_addr_of_symbol(gmmcBasicBlock* bb, gmmcSymbol* symbol) {
	gmmcOp op = { gmmcOpKind_addr_of_symbol };
	op.symbol = symbol;
	op.result = make_reg(bb->proc, gmmcType_ptr);
	f_array_push(&bb->ops, op);
	return op.result;
}

static gmmcReg make_reg(gmmcProc* proc, gmmcType type) {
	gmmcReg reg = (gmmcReg)f_array_push(&proc->type_from_reg, type);
	f_array_push(&proc->local_from_reg, (gmmcLocal*)0);
	return reg;
}

GMMC_API gmmcBasicBlock* gmmc_make_basic_block(gmmcProc* proc) {
	gmmcBasicBlock* b = f_mem_clone(gmmcBasicBlock{}, proc->sym.mod->allocator);
	b->mod = proc->sym.mod;
	b->proc = proc;
	b->ops = f_array_make<gmmcOp>(proc->sym.mod->allocator);
	b->bb_index = (u32)f_array_push(&proc->basic_blocks, b);
	return b;
}

GMMC_API gmmcSymbol* gmmc_make_external_symbol(gmmcModule* m, gmmcString name) {
	gmmcSymbol* sym = f_mem_clone(gmmcSymbol{gmmcSymbolKind_Extern}, m->allocator);
	f_array_push(&m->external_symbols, sym);
	sym->mod = m;
	sym->name = name;
	return sym;
}

GMMC_API gmmcProc* gmmc_make_proc(gmmcModule* m,
	gmmcProcSignature* signature,
	gmmcString name, gmmcBasicBlock** out_entry_bb)
{
	gmmcProc* proc = f_mem_clone(gmmcProc{}, m->allocator);
	f_array_push(&m->procs, proc);
	proc->sym.kind = gmmcSymbolKind_Proc;
	proc->sym.mod = m;
	proc->sym.name = name;
	proc->signature = signature;
	
	proc->type_from_reg = f_array_make<gmmcType>(m->allocator);
	proc->local_from_reg = f_array_make<gmmcLocal*>(m->allocator);
	f_array_push(&proc->type_from_reg, gmmcType_None);  // reg 0 is always invalid
	f_array_push(&proc->local_from_reg, (gmmcLocal*)0);  // reg 0 is always invalid

	proc->basic_blocks = f_array_make<gmmcBasicBlock*>(m->allocator);
	proc->entry_bb = gmmc_make_basic_block(proc);

	proc->params = f_make_slice_garbage<gmmcReg>(signature->params.len, m->allocator);
	for (uint i = 0; i < signature->params.len; i++) {
		proc->params[i] = make_reg(proc, signature->params[i]);
	}
	
	*out_entry_bb = proc->entry_bb;
	return proc;
}

GMMC_API gmmcReg gmmc_op_call(gmmcBasicBlock* bb, gmmcType return_type, gmmcSymbol* procedure,
	gmmcReg* in_arguments, uint32_t in_arguments_count)
{
	gmmcOp op = { gmmcOpKind_call };
	op.call.target_sym = procedure;
	op.call.arguments = f_clone_slice<gmmcReg>({ in_arguments, in_arguments_count }, bb->mod->allocator);
	if (return_type) {
		op.result = make_reg(bb->proc, return_type);
	}
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_vcall(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcReg proc_address,
	gmmcReg* in_arguments, uint32_t in_arguments_count)
{
	gmmcOp op = { gmmcOpKind_vcall };
	op.call.target_reg = proc_address;
	op.call.arguments = f_clone_slice<gmmcReg>({ in_arguments, in_arguments_count }, bb->mod->allocator);
	if (return_type) {
		op.result = make_reg(bb->proc, return_type);
	}
	f_array_push(&bb->ops, op);
	return op.result;
}

static fString gmmc_type_get_string(gmmcType type) {
	switch (type) {
	case gmmcType_None: return F_LIT("void");
	case gmmcType_bool: return F_LIT("bool");
	case gmmcType_ptr: return F_LIT("void*");
	case gmmcType_i8: return F_LIT("i8");
	case gmmcType_i16: return F_LIT("i16");
	case gmmcType_i32: return F_LIT("i32");
	case gmmcType_i64: return F_LIT("i64");
	case gmmcType_i128: return F_LIT("i128");
	default: F_BP;
	}
	return {};
}

static char* gmmc_type_get_cstr(gmmcType type) { return (char*)gmmc_type_get_string(type).data; }

static u32 gmmc_type_get_size(gmmcType type) {
	switch (type) {
	case gmmcType_None: return 0;
	case gmmcType_bool: return 1;
	case gmmcType_ptr: return 8;
	case gmmcType_i8: return 1;
	case gmmcType_i16: return 2;
	case gmmcType_i32: return 4;
	case gmmcType_i64: return 8;
	case gmmcType_i128: return 16;
	default: F_BP;
	}
	return 0;
}

GMMC_API gmmcModule* gmmc_init(fAllocator* allocator) {
	gmmcModule* m = f_mem_clone(gmmcModule{}, allocator);
	m->allocator = allocator;
	m->code_section = f_array_make<u8>(m->allocator);
	m->proc_signatures = f_array_make<gmmcProcSignature*>(m->allocator);
	m->globals = f_array_make<gmmcGlobal*>(m->allocator);
	f_array_push(&m->globals, (gmmcGlobal*)0); // just to make 0 index invalid
	m->procs = f_array_make<gmmcProc*>(m->allocator);
	m->external_symbols = f_array_make<gmmcSymbol*>(m->allocator);
	return m;
}

static u32 operand_bits(gmmcBasicBlock* bb, gmmcOp* op) {
	return 8 * gmmc_type_get_size(reg_get_type(bb->proc, op->operands[0]));
}

void print_bb(fArray(u8)* b, gmmcBasicBlock* bb, fAllocator* alc) {
	f_str_printf(b, "b$%u:\n", bb->bb_index);

	for (uint i = 0; i < bb->ops.len; i++) {
		gmmcOp* op = &bb->ops[i];
		if (op->kind != gmmcOpKind_comment) {
			f_str_printf(b, "    ");
		}
		
		//f_str_printf(pr, "
		//gmmcOpKind_to_string[op->kind].data
		u32 result_bits = 8 * gmmc_type_get_size(reg_get_type(bb->proc, op->result));
		const char* sign_postfix = op->is_signed ? "signed" : "unsigned";

		switch (op->kind) {
		case gmmcOpKind_bool: { f_str_printf(b, "_$%u = %s;\n", op->result, op->imm ? "1" : "0"); } break;
		case gmmcOpKind_i8: { f_str_printf(b, "_$%u = %hhu;\n", op->result, (u8)op->imm); } break;
		case gmmcOpKind_i16: { f_str_printf(b, "_$%u = %hu;\n", op->result, (u16)op->imm); } break;
		case gmmcOpKind_i32: { f_str_printf(b, "_$%u = %u;\n", op->result, (u32)op->imm); } break;
		case gmmcOpKind_i64: { f_str_printf(b, "_$%u = %llu;\n", op->result, (u64)op->imm); } break;
		
		case gmmcOpKind_int2ptr: { f_str_printf(b, "_$%u = (void*)_$%u;\n", op->result, op->operands[0]); } break;
		case gmmcOpKind_ptr2int: {
			gmmcType value_type = reg_get_type(bb->proc, op->result);
			f_str_printf(b, "_$%u = (%s)_$%u;\n", op->result, gmmc_type_get_cstr(value_type), op->operands[0]);
		} break;

		case gmmcOpKind_trunc: {
			f_str_printf(b, "_$%u = (i%u)_$%u;\n", op->result, result_bits, op->operands[0]);
		} break;

		case gmmcOpKind_and: { f_str_printf(b, "_$%u = _$%u & _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_or: { f_str_printf(b, "_$%u = _$%u | _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_xor: { f_str_printf(b, "_$%u = _$%u ^ _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_not: { f_str_printf(b, "_$%u = ~_$%u;\n", op->result, op->operands[0]); } break;
		case gmmcOpKind_shl: { f_str_printf(b, "_$%u = _$%u << _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_shr: { f_str_printf(b, "_$%u = _$%u >> _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;

		// I guess the nice thing about having explicit $le()  would be
		// that we could show the type and if it's signed at the callsite. e.g.   $le_s32()
		// the signedness thing is a bit weird. Maybe we should have the instructions more like in X64 with above/greater terms.
		// Or name it  $le_s32() / $le_u32()
		// $mul_s32 / $mul_u32
		case gmmcOpKind_eq: { f_str_printf(b, "_$%u = _$%u == _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_ne: { f_str_printf(b, "_$%u = _$%u != _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		
		case gmmcOpKind_lt: {
			f_str_printf(b, "_$%u = $op_%s(%u, <, _$%u, _$%u);\n", op->result, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_le: {
			f_str_printf(b, "_$%u = $op_%s(%u, <=, _$%u, _$%u);\n", op->result, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_gt: {
			f_str_printf(b, "_$%u = $op_%s(%u, >, _$%u, _$%u);\n", op->result, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_ge: {
			f_str_printf(b, "_$%u = $op_%s(%u, >=, _$%u, _$%u);\n", op->result, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_zxt: {
			f_str_printf(b, "_$%u = $zxt(%u, %u, _$%u);\n", op->result,
				operand_bits(bb, op), result_bits, op->operands[0]);
		} break;
		case gmmcOpKind_sxt: {
			f_str_printf(b, "_$%u = $sxt(%u, %u, _$%u);\n", op->result,
				operand_bits(bb, op), result_bits, op->operands[0]);
		} break;


		// TODO: make signed overflow not UB
		case gmmcOpKind_add: { f_str_printf(b, "_$%u = _$%u + _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_sub: { f_str_printf(b, "_$%u = _$%u - _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_mul: {
			f_str_printf(b, "_$%u = $op_%s(%u, *, _$%u, _$%u);\n", op->result, sign_postfix, result_bits, op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_div: {
			f_str_printf(b, "_$%u = $op_%s(%u, /, _$%u, _$%u);\n", op->result, sign_postfix, result_bits, op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_mod: {
			f_str_printf(b, "_$%u = $op_%s(%u, %, _$%u, _$%u);\n", op->result, sign_postfix, result_bits, op->operands[0], op->operands[1]);
		} break;
		
		case gmmcOpKind_addr_of_symbol: {
			if (op->symbol->kind == gmmcSymbolKind_Global) {
				f_str_printf(b, "_$%u = (void*)&%s;\n", op->result, f_str_to_cstr(op->symbol->name, alc));
			}
			else {
				f_str_printf(b, "_$%u = %s;\n", op->result, f_str_to_cstr(op->symbol->name, alc));
			}
		} break;

		case gmmcOpKind_store: {
			gmmcType value_type = reg_get_type(bb->proc, op->operands[1]);
			f_str_printf(b, "$store(%s, _$%u, _$%u);\n", gmmc_type_get_cstr(value_type), op->operands[0], op->operands[1]);
		} break;

		case gmmcOpKind_load: {
			gmmcType value_type = reg_get_type(bb->proc, op->result);
			f_str_printf(b, "_$%u = $load(%s, _$%u);\n", op->result, gmmc_type_get_cstr(value_type), op->operands[0]);
		} break;

		case gmmcOpKind_member_access: {
			f_str_printf(b, "_$%u = $member_access(_$%u, %u);\n", op->result, op->operands[0], (u32)op->imm);
		} break;

		case gmmcOpKind_array_access: {
			f_str_printf(b, "_$%u = $array_access(_$%u, _$%u, %u);\n", op->result, op->operands[0], op->operands[1], (u32)op->imm);
		} break;

		case gmmcOpKind_memmove: {
			f_str_printf(b, "memmove(_$%u, _$%u, _$%u);\n", op->operands[0], op->operands[1], op->operands[2]);
		} break;

		case gmmcOpKind_memset: {
			f_str_printf(b, "memset(_$%u, _$%u, _$%u);\n", op->operands[0], op->operands[1], op->operands[2]);
		} break;

		case gmmcOpKind_goto: {
			f_str_printf(b, "goto b$%u;\n", op->goto_.dst_bb->bb_index);
		} break;

		case gmmcOpKind_if: {
			f_str_printf(b, "if (_$%u) goto b$%u; else goto b$%u;\n", op->if_.condition, op->if_.dst_bb[0]->bb_index, op->if_.dst_bb[1]->bb_index);
		} break;

		case gmmcOpKind_debugbreak: {
			f_str_printf(b, "$debugbreak();\n");
		} break;

		case gmmcOpKind_call: // fallthrough
		case gmmcOpKind_vcall: {
			gmmcType ret_type = reg_get_type(bb->proc, op->result);
			if (ret_type != gmmcType_None) {
				f_str_printf(b, "_$%u = ", op->result);
			}
			
			if (op->kind == gmmcOpKind_call) {
				f_str_printf(b, "%s(", f_str_to_cstr(op->call.target_sym->name, alc));
			}
			else {
				// function pointer cast
				f_str_printf(b, "( (%s(*)(", gmmc_type_get_cstr(ret_type));
				for (uint i = 0; i < op->call.arguments.len; i++) {
					if (i > 0) f_str_printf(b, ", ");

					gmmcType arg_type = reg_get_type(bb->proc, op->call.arguments[i]);
					f_str_printf(b, "%s", gmmc_type_get_cstr(arg_type));
				}
				f_str_printf(b, ")) _$%u ) (", op->call.target_reg);
			}
			
			// args
			for (uint i = 0; i < op->call.arguments.len; i++) {
				if (i > 0) f_str_printf(b, ", ");
				f_str_printf(b, "_$%u", op->call.arguments[i]);
			}
			f_str_printf(b, ");\n");
		} break;

		case gmmcOpKind_comment: {
			if (op->comment.len > 0) {
				fSlice(fRangeUint) lines;
				f_str_split_i(op->comment, '\n', alc, &lines);
				for (uint i = 0; i < lines.len; i++) {
					fString line = f_str_slice(op->comment, lines[i].lo, lines[i].hi);
					f_str_printf(b, "    // %.*s\n", line.len, line.data);
				}
			} else {
				f_str_printf(b, "\n");
			}
		} break;

		case gmmcOpKind_return: {
			if (op->operands[0] != GMMC_REG_NONE) f_str_printf(b, "return _$%u;\n", op->operands[0]);
			else f_str_printf(b, "return;\n");
		} break;

		default: F_BP;
		}

	}
}

GMMC_API void gmmc_proc_print(fArray(u8)* b, gmmcProc* proc) {
	fAllocator* alc = f_temp_push();
	fString name = proc->sym.name;
	
	f_str_printf(b, "%s %.*s(", (proc->signature->return_type ?
		gmmc_type_get_cstr(proc->signature->return_type): "void"), F_STRF(name));

	for (uint i = 0; i < proc->signature->params.len; i++) {
		if (i > 0) f_str_printf(b, ", ");
		gmmcType type = proc->signature->params[i];
		f_str_printf(b, "%s _$%u", gmmc_type_get_cstr(type), proc->params[i]);
	}
	f_str_printf(b, ") {\n");

	f_str_printf(b, "    ");
	
	// locals / regs!
	u32 first_nonparam_reg = 1 + (u32)proc->signature->params.len;
	for (u32 i = first_nonparam_reg; i < proc->type_from_reg.len; i++) {
		gmmcLocal* local = proc->local_from_reg[i];
		if (local) {
			//if (local->align != local->size) f_str_printf(b,
			f_str_printf(b, "_Alignas(%u) i8 _$%u[%u]; ", local->align, i, local->size);
		}
		else {
			f_str_printf(b, "%s _$%u; ", gmmc_type_get_cstr(proc->type_from_reg[i]), i);
		}
		if (i % 8 == 0) f_str_printf(b, "\n    ");
	}
	f_str_printf(b, "\n");

	for (uint i = 0; i < proc->basic_blocks.len; i++) {
		print_bb(b, proc->basic_blocks[i], alc);
	}
	f_str_printf(b, "char _;\n"); // goto: at the end with nothing after it is illegal, this is just a dumb fix for it
	f_str_printf(b, "}\n");
}

GMMC_API gmmcGlobal* gmmc_make_global(gmmcModule* m, uint32_t size, uint32_t align, bool readonly, void** out_data) {
	void* data = f_mem_alloc(size, align, m->allocator);
	memset(data, 0, size);

	gmmcGlobal* global = f_mem_clone(gmmcGlobal{}, m->allocator);
	u32 idx = (u32)f_array_push(&m->globals, global);
	global->sym.kind = gmmcSymbolKind_Global;
	global->sym.mod = m;
	global->sym.name = f_str_format(m->allocator, "g$%u", idx);
	global->size = size;
	global->align = align;
	global->readonly = readonly;
	global->data = data;
	global->relocations = f_array_make<gmmcReloc>(m->allocator);

	*out_data = data;
	return global;
}

void gmmc_create_coff(gmmcModule* m, fString output_file) {
	coffDesc coff_desc = {};
	
	fArray(coffSection) sections = f_array_make<coffSection>(m->allocator);
	fArray(coffSymbol) symbols = f_array_make<coffSymbol>(m->allocator);
	
	{
		coffSection sect = {};
		sect.name = F_LIT(".text");
		sect.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		sect.data = m->code_section.slice;
		//sect.relocations = text_relocs.data;
		//sect.relocations_count = (int)text_relocs.len;
		f_array_push(&sections, sect);
	}

	coff_desc.sections = sections.data;
	coff_desc.sections_count = (u32)sections.len;
	coff_desc.symbols = symbols.data;
	coff_desc.symbols_count = (u32)symbols.len;

	coff_create([](fString result, void* userptr) {
		fString out_file = *(fString*)userptr;
		
		bool ok = f_files_write_whole(out_file, result);
		F_BP;
		
		}, &output_file, &coff_desc);
}

/*
int factorial(int n) {
	if (n <= 1) return 1;
	return n * factorial(n - 1);
}
*/

static int reloc_compare_fn(const void* a, const void* b) {
	return ((gmmcReloc*)a)->offset - ((gmmcReloc*)b)->offset;
}

GMMC_API void gmmc_module_print(fArray(u8)* b, gmmcModule* m) {
	f_str_printf(b, "%s", R"(
// ------------------ GMMC prelude for C11 ----------------------------------

typedef _Bool             bool;
typedef void*              ptr;
typedef unsigned char       i8;
typedef unsigned short     i16;
typedef unsigned int       i32;
typedef unsigned long long i64;
typedef char                $s8;
typedef short              $s16;
typedef int                $s32;
typedef long long          $s64;

#define $debugbreak() do {__debugbreak();} while(0)
#define $store(T, ptr, value) *(T*)ptr = value
#define $load(T, ptr) *(T*)ptr
#define $array_access(base, index, stride) (i8*)base + index * stride
#define $member_access(base, offset) (i8*)base + offset

#define $op_unsigned(bits, op, a, b) a op b
#define $op_signed(bits, op, a, b) (i##bits) (($s##bits)a op ($s##bits)b)

#define $sxt(from, to, value) (i##to)(($s##to)(($s##from)value))
#define $zxt(from, to, value) (i##to)value

// TODO: have a free-standing implementation of these so you could avoid linking to CRT if you wanted to?
void *memmove(void *s1, const void *s2, size_t n);
void *memset(void *s, int c, size_t n);

// --------------------------------------------------------------------------
)");

	//f_str_printf(b, "// -- globals -------------\n\n");
	f_str_printf(b, "#pragma pack(push, 1)\n"); // TODO: use alignas instead! for relocations

	fAllocator* alc = m->allocator;

	// forward declare symbols

	f_str_printf(b, "\n");
	for (uint i = 0; i < m->procs.len; i++) {
		// hmm... do we need to declare procs with the right type?
		gmmcProc* proc = m->procs[i];
		fString name = m->procs[i]->sym.name;

		gmmcType ret_type = proc->signature->return_type;
		f_str_printf(b, "%s %.*s(", ret_type ? gmmc_type_get_cstr(ret_type) : "void", F_STRF(name));
		
		for (uint i = 0; i < proc->signature->params.len; i++) {
			if (i > 0) f_str_printf(b, ", ");
			f_str_printf(b, "%s", gmmc_type_get_cstr(proc->signature->params[i]));
		}
		f_str_printf(b, ");\n");
	}

	for (uint i = 0; i < m->external_symbols.len; i++) {
		fString name = m->external_symbols[i]->name;
		if (name == F_LIT("memset")) continue; // already defined in the prelude
		if (name == F_LIT("memmove")) continue; // already defined in the prelude

		// pretend all external symbols are functions - I'm not sure if this works on non-functions. TODO!
		f_str_printf(b, "void %.*s();\n", F_STRF(name));
	}
	f_str_printf(b, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		const char* name = f_str_to_cstr(global->sym.name, alc);

		// sort the relocations
		qsort(global->relocations.data, global->relocations.len, sizeof(gmmcReloc), reloc_compare_fn);

		//f_str_printf(b, "_Alignas(%u) ", global->align);
		f_str_printf(b, "struct %s_T {", name);

		{
			u32 member_i = 1;
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					global->relocations[next_reloc_idx].offset :
					global->size;

				if (bytes_end > offset) {
					f_str_printf(b, "i8 _%u[%u]; ", member_i++, bytes_end - offset);
					offset = bytes_end;
				}

				if (next_reloc_idx >= global->relocations.len) break;

				f_str_printf(b, "i64 _%u; ", member_i++);
				offset += 8;
				next_reloc_idx++;
			}
		}
		f_str_printf(b, "};\n");
		if (global->readonly) f_str_printf(b, "const ");
		f_str_printf(b, "static struct %s_T %s;\n", name, name);
	}
	
	f_str_printf(b, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		const char* name = f_str_to_cstr(global->sym.name, alc);

		if (global->readonly) f_str_printf(b, "const ");
		f_str_printf(b, "static struct %s_T %s = {", name, name);
		//f_str_printf(b, "\n%s_data = {", name);

		{
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					global->relocations[next_reloc_idx].offset :
					global->size;

				if (bytes_end > offset) {
					f_str_printf(b, "{");
					for (; offset < bytes_end;) {
						f_str_printf(b, "%hhu,", ((u8*)global->data)[offset]);
						offset++;
					}
					f_str_printf(b, "}, ");
				}
				
				if (next_reloc_idx >= global->relocations.len) break;

				gmmcReloc reloc = global->relocations[next_reloc_idx];
				u64 reloc_offset = *(u64*)((u8*)global->data + offset);

				f_str_printf(b, "(i64)(");
				if (reloc_offset != 0) f_str_printf(b, "(i8*)");
				f_str_printf(b, "&%s", f_str_to_cstr(reloc.target->name, alc));
				if (reloc_offset != 0) f_str_printf(b, " + 0x%llx", reloc_offset);
				f_str_printf(b, "), ");
				
				offset += 8;
				next_reloc_idx++;
			}
		}
		f_str_printf(b, "};\n");
	}

	f_str_printf(b, "\n");
	f_str_printf(b, "#pragma pack(pop)\n"); // TODO: use alignas instead! for relocations
	f_str_printf(b, "\n// ------------------------\n\n");

	for (uint i = 0; i < m->procs.len; i++) {
		gmmc_proc_print(b, m->procs[i]);
		f_str_printf(b, "\n");
	}
}

GMMC_API void gmmc_test() {
#if 0
	fAllocator* temp = f_temp_push();
	f_os_set_working_dir(F_LIT("C:\\dev\\ffz\\gmmc\\test"));

	//int x = factorial(10);
	
	// need to specify zero padding!
//#pragma pack(push, 1)
//	const static struct { u8 _1[3]; u64 _2; u8 _3[4]; u64 _4; u8 _5[5]; } foo = {};
//#pragma pack(pop)

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
	gmmcGlobal* global_a = gmmc_make_global(m, F_LEN(my_data), 8, true, &global_a_data);
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
	
	gmmcReg param_n = gmmc_op_param(test_proc, 0);
	gmmcReg n_minus_1 = gmmc_op_sub(false_bb, param_n, gmmc_op_i32(false_bb, 1));
	gmmcReg return_val = gmmc_op_mul(false_bb, param_n, gmmc_op_call(false_bb, test_proc, &n_minus_1, 1), false);
	gmmc_op_return(false_bb, return_val);

	fArray(u8) buf = f_array_make<u8>(temp);
	gmmc_module_print(&buf, m);
	f_os_print(buf.slice);

	//gmmc_proc_print(test_proc);

	//gmmc_proc_compile(test_proc);
	
	//gmmc_create_coff(m, F_LIT("test.obj"));
	F_BP;
#endif
}
