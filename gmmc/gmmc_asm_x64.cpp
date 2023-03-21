#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"

#include "Zydis/Zydis.h"

#include <stdio.h> // for fopen

#define VALIDATE(x) F_ASSERT(x)

typedef u16 RegSize;

struct gmmcAsmProc;

struct gmmcAsmGlobal {
	gmmcGlobal* global; // hmm... why do we store this? its accessible by the index
	u32 offset;
};

struct Section {
	fArray(u8) data;
	fArray(gmmcRelocation) relocs;
};

struct gmmcAsmModule {
	Section sections[gmmcSection_COUNT];
	fSlice(gmmcAsmProc) procs;
	fSlice(gmmcAsmGlobal) globals;
};

GMMC_API gmmcString gmmc_asm_get_section_data(gmmcAsmModule* m, gmmcSection section) {
	return { m->sections[section].data.data, m->sections[section].data.len };
}

GMMC_API void gmmc_asm_get_section_relocations(gmmcAsmModule* m, gmmcSection section, fSlice(gmmcRelocation)* out_relocs) {
	*out_relocs = m->sections[section].relocs.slice;
}

enum GPR {
	GPR_INVALID,
	GPR_AX,
	GPR_CX,
	GPR_DX,
	GPR_BX,
	GPR_SP,
	GPR_BP,
	GPR_SI,
	GPR_DI,
	GPR_8,
	GPR_9,
	GPR_10,
	GPR_11,
	GPR_12,
	GPR_13,
	GPR_14,
	GPR_15,
	GPR_COUNT,
};

typedef struct gmmcAsmBB {
	// U32_MAX means 'unvisited'.
	// In the first pass, its set to 0 when visited.
	// During the second pass, its set to the offset in the code section when visited.
	u32 offset;
} gmmcAsmBB;

struct gmmcAsmOp {
	gmmcOpIdx last_use_time;

	// --- second pass ---
	s32 spill_offset_frame_rel;
	GPR currently_in_register; // GPR_INVALID means it's on the stack / not inside a register
	u32 instruction_offset;
};

struct gmmcAsmProc {
	gmmcAsmModule* module;

	gmmcProc* proc;
	fSlice(s32) local_frame_rel_offset; // per-local

	fSlice(gmmcAsmOp) ops;

	//gmmcBasicBlockIdx current_bb;
	gmmcOpIdx current_op;

	// We do 2 passes. In the first pass, we
	//   - fill up the `last_use_time`s
	//   - calculate the maximum stack space needed for any procedure call (largest_call_shadow_space)
	// In the second pass, we figure out which registers to allocate on the fly and emit the instructions.
	bool emitting;

	fSlice(gmmcAsmBB) blocks;

	// --- second pass ---

	u32 largest_call_shadow_space_size;
	
	u32 code_section_offset;
	u32 code_section_end_offset;

	u32 stack_frame_size;
	u8 prolog_size;

	u32 work_registers_used_count;

	gmmcOpIdx work_reg_taken_by_op[GPR_COUNT]; // per-BB
	
	// When taking a non-volatile register as a work register, we must insert code to store the content of that register onto the stack, and
	// at the end of the procedure, restore the register's state.
	// NOTE: when we begin emitting, we don't know yet how many non-volatile work registers we're going to use.
	// So for now, we just reserve stack space for each possible work register. This could be solved if we introduced a third pass for the emitting, or if we emitted in a separate buffer and appended it at the end.
	s32 work_reg_restore_frame_rel_offset[GPR_COUNT];
};

//s32 frame_rel_to_rsp_rel_offset(ProcGen* gen, s32 offset) { return gen->stack_frame_size + offset; }


// https://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend
// NOTE: high bits of 'x' must be set to 0
static u64 sign_extend(u64 x, u32 num_bits) {
	u64 m = 1llu << (num_bits - 1);
	return (x ^ m) - m;
}

static void emit(gmmcAsmProc* p, const ZydisEncoderRequest& req, const char* comment = "") {
	u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
	uint instr_len = sizeof(instr);
	bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, instr, &instr_len));
	VALIDATE(ok);
	
	Section* code_section = &p->module->sections[gmmcSection_Code];
	f_array_push_n(&code_section->data, { instr, instr_len });

	// print disassembly
	if (false) {
		uint sect_rel_offset = code_section->data.len - instr_len;
		uint proc_rel_offset = sect_rel_offset - p->code_section_offset;

		u8* data = code_section->data.data + proc_rel_offset;
	//	if (proc_rel_offset == 0x3c) F_BP;

		ZydisDisassembledInstruction instruction;
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, proc_rel_offset, instr, instr_len, &instruction))) {
			printf("(%u)  0x%llx:   %s%s\n", p->current_op, proc_rel_offset, instruction.text, comment);
		}
	}
}

// General-purpose registers. Prefer non-volatile registers for now
// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170
const static GPR work_registers[] = {
	GPR_12,
	GPR_13,
	GPR_14,
	GPR_15,
	//GPR_DI,
	//GPR_SI,
	//GPR_BX,
	//GPR_BP,
};


ZydisRegister zydis_reg_table[] = {
	ZYDIS_REGISTER_AL, ZYDIS_REGISTER_CL, ZYDIS_REGISTER_DL, ZYDIS_REGISTER_BL,
	ZYDIS_REGISTER_SPL, ZYDIS_REGISTER_BPL, ZYDIS_REGISTER_SIL, ZYDIS_REGISTER_DIL,
	ZYDIS_REGISTER_R8B, ZYDIS_REGISTER_R9B, ZYDIS_REGISTER_R10B, ZYDIS_REGISTER_R11B,
	ZYDIS_REGISTER_R12B, ZYDIS_REGISTER_R13B, ZYDIS_REGISTER_R14B, ZYDIS_REGISTER_R15B,

	ZYDIS_REGISTER_AX, ZYDIS_REGISTER_CX, ZYDIS_REGISTER_DX, ZYDIS_REGISTER_BX,
	ZYDIS_REGISTER_SP, ZYDIS_REGISTER_BP, ZYDIS_REGISTER_SI, ZYDIS_REGISTER_DI,
	ZYDIS_REGISTER_R8W, ZYDIS_REGISTER_R9W, ZYDIS_REGISTER_R10W, ZYDIS_REGISTER_R11W,
	ZYDIS_REGISTER_R12W, ZYDIS_REGISTER_R13W, ZYDIS_REGISTER_R14W, ZYDIS_REGISTER_R15W,

	ZYDIS_REGISTER_EAX, ZYDIS_REGISTER_ECX, ZYDIS_REGISTER_EDX, ZYDIS_REGISTER_EBX,
	ZYDIS_REGISTER_ESP, ZYDIS_REGISTER_EBP, ZYDIS_REGISTER_ESI, ZYDIS_REGISTER_EDI,
	ZYDIS_REGISTER_R8D, ZYDIS_REGISTER_R9D, ZYDIS_REGISTER_R10D, ZYDIS_REGISTER_R11D,
	ZYDIS_REGISTER_R12D, ZYDIS_REGISTER_R13D, ZYDIS_REGISTER_R14D, ZYDIS_REGISTER_R15D,

	ZYDIS_REGISTER_RAX, ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX, ZYDIS_REGISTER_RBX,
	ZYDIS_REGISTER_RSP, ZYDIS_REGISTER_RBP, ZYDIS_REGISTER_RSI, ZYDIS_REGISTER_RDI,
	ZYDIS_REGISTER_R8, ZYDIS_REGISTER_R9, ZYDIS_REGISTER_R10, ZYDIS_REGISTER_R11,
	ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13, ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
};


ZydisRegister get_x64_reg(GPR reg, RegSize size) {
	u32 size_class_from_size[] = { 0, 1, 2, 0, 3, 0, 0, 0, 4 };
	u32 size_class = size_class_from_size[size];
	F_ASSERT(size_class != 0);
	
	u32 reg_index = (u32)(reg - GPR_AX);
	return zydis_reg_table[reg_index + 16 * (size_class - 1)];
}

ZydisEncoderOperand make_reg_operand(GPR gpr, RegSize size) {
	ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_REGISTER };
	operand.reg.value = get_x64_reg(gpr, size);
	return operand;
}

// Loose register - stored either in a register or on the stack
struct LooseReg { gmmcOpIdx source_op; };

//static bool op_is_to_be_spilled(gmmcOpKind op_kind) {
//	if (gmmc_is_op_immediate(op_kind)) return false;
//	if (op_kind == gmmcOpKind_local) return false;
//	if (op_kind == gmmcOpKind_addr_of_symbol) return false;
//	if (op_kind == gmmcOpKind_addr_of_param) return false;
//	return true;
//}

static void spill(gmmcAsmProc* p, gmmcOpIdx op_idx) {
	// hmm... are you allowed to use an op value from another basic block?
	// We could just disallow it and say "use a local!".
	// That would also make the use of undefined values impossible.
	// it would also make the C printing a bit nicer.
	// we also wouldn't need to worry about spilling when branching!

	GPR reg = p->ops[op_idx].currently_in_register;
	F_ASSERT(p->work_reg_taken_by_op[reg] == op_idx);

	gmmcOpData* op = &p->proc->ops[op_idx];
	
	if (!gmmc_is_op_instant(p->proc, op_idx)) {
		// if computation is required to find out the value of the op, store it on the stack.
		// locals, immediates and addr_of_symbol don't need to be stored on the stack.

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_MOV;
		req.operand_count = 2;
		req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
		req.operands[0].mem.displacement = p->ops[op_idx].spill_offset_frame_rel + p->stack_frame_size;
		req.operands[0].mem.size = gmmc_type_size(op->type);
		req.operands[1] = make_reg_operand(reg, 8);
		emit(p, req, " ; spill the op value");
	}
}

static GPR allocate_gpr(gmmcAsmProc* p, gmmcOpIdx for_op) {
	GPR gpr = GPR_INVALID;
	F_ASSERT(p->emitting);

	F_HITS(_c, 0);

	for (u32 i = 0; i < p->work_registers_used_count; i++) {
		GPR work_reg = work_registers[i];
		gmmcOpIdx taken_by_op = p->work_reg_taken_by_op[work_reg];
		if (p->current_op > p->ops[taken_by_op].last_use_time) { // this op value will never be used later
			gpr = work_reg;
			break;
		}
	}
		
	// Take a new register. If the registers are all in use, then loop through them and steal the one
	// used by the OP with the greatest `last_use_time`
	if (!gpr) {
		if (p->work_registers_used_count < F_LEN(work_registers)) {
			gpr = work_registers[p->work_registers_used_count++];

			// Store the original value of the non-volatile work register, to be restored on return
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[0].mem.displacement = p->work_reg_restore_frame_rel_offset[gpr] + p->stack_frame_size;
			req.operands[0].mem.size = 8;
			req.operands[1] = make_reg_operand(gpr, 8);
			emit(p, req, " ; take a new register, save its foreign value");
		}
		else {
			gmmcOpIdx greatest_last_use_time = 0;
			gmmcOpIdx victim = 0;
			
			for (uint i = 0; i < F_LEN(work_registers); i++) {
				GPR work_reg = work_registers[i];
				gmmcOpIdx potential_victim = p->work_reg_taken_by_op[work_reg];
				F_ASSERT(p->ops[potential_victim].currently_in_register == work_reg);

				gmmcOpIdx last_use_time = p->ops[potential_victim].last_use_time;
				if (last_use_time > greatest_last_use_time) {
					greatest_last_use_time = last_use_time;
					
					victim = potential_victim;
					gpr = work_reg;
				}
			}
			
			spill(p, victim); // steal a register, spill the op value
			p->ops[victim].currently_in_register = GPR_INVALID;
		}
	}

	p->work_reg_taken_by_op[gpr] = for_op;
	p->ops[for_op].currently_in_register = gpr;
	
	return gpr;
}

static void update_last_use_time(gmmcAsmProc* p, gmmcOpIdx op_idx) {
	if (!p->emitting) {
		gmmcAsmOp* op = &p->ops[op_idx];
		op->last_use_time = F_MAX(op->last_use_time, p->current_op);
	}
}

static GPR allocate_op_result(gmmcAsmProc* p) {
	update_last_use_time(p, p->current_op);
	if (p->emitting) {
		return allocate_gpr(p, p->current_op);
	}
	return GPR_INVALID;
}

enum ExtendBits {
	ExtendBits_None,
	ExtendBits_Zero,
	ExtendBits_Sign,
};

static void emit_mov_reg_to_reg(gmmcAsmProc* p, GPR to, GPR from, RegSize size, ExtendBits extend = ExtendBits_None) {
	if (extend == ExtendBits_Zero && size <= 2) {
		// From section 2.3, AMD64 Architecture Programmer's Manual, Volume 3:
		// "The high 32 bits of doubleword operands are zero-extended to 64 bits, but the high
		// bits of word and byte operands are not modified by operations in 64-bit mode".
		// So if the size is 4, then the MOV will be sign-extended automatically.

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_MOVZX;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(to, 8);
		req.operands[1] = make_reg_operand(from, size);
		emit(p, req);
	}
	else if (extend == ExtendBits_Sign && size <= 4) {
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = size == 4 ? ZYDIS_MNEMONIC_MOVSXD : ZYDIS_MNEMONIC_MOVSX;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(to, 8);
		req.operands[1] = make_reg_operand(from, size);
		emit(p, req);
	}
	else {
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_MOV;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(to, size);
		req.operands[1] = make_reg_operand(from, size);
		emit(p, req);
	}
}

static GPR op_value_to_reg(gmmcAsmProc* p, gmmcOpIdx op_idx, GPR specify_reg = GPR_INVALID) {
	GPR result = p->ops[op_idx].currently_in_register;
	if (result) {
		if (specify_reg) {
			emit_mov_reg_to_reg(p, specify_reg, result, 8);
			return specify_reg;
		}

		return result;
	}

	// NOTE: when `specify_reg` is set, we don't want to update the `currently_in_register` state,
	// because we're probably wanting to put the value into a volatile register that is going to go
	// out of date soon, i.e. RAX

	result = specify_reg;
	if (!specify_reg) {
		result = allocate_gpr(p, op_idx);
	}

	// if the op is a `local`, then its value (address) isn't ever stored on the stack.
	gmmcOpData* op = &p->proc->ops[op_idx];

	if (op->kind == gmmcOpKind_local) {
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_LEA;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result, 8);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
		req.operands[1].mem.displacement = p->local_frame_rel_offset[op->local_idx] + p->stack_frame_size;
		req.operands[1].mem.size = 8;
		emit(p, req, " ; address of local");
		int a = 50;
	}
	else if (op->kind == gmmcOpKind_addr_of_param) {
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_LEA;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result, 8);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
		req.operands[1].mem.displacement = p->stack_frame_size + 8 + 8 * (u32)op->imm_raw; // + 8 for return address :AddressOfParam
		req.operands[1].mem.size = 8;
		emit(p, req, " ; address of param");
	}
	else if (op->kind == gmmcOpKind_addr_of_symbol) {
		// we need relocations!!
		gmmcSymbol* sym = p->proc->ops[op_idx].symbol;

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_MOV;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result, 8);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
		req.operands[1].imm.u = 0xfefefefefefefefe; // trick zydis to emit the full 64 bits for the immediate
		emit(p, req, " ; address of symbol (relocation will be applied to imm)");
		//if (sym->name == F_LIT("TiB$$Basic")) F_BP;

		Section* code_section = &p->module->sections[gmmcSection_Code];

		// The relocation will be applied to the encoded immediate operand
		u32 reloc_offset = (u32)code_section->data.len - 8;
		*(u64*)(code_section->data.data + reloc_offset) = 0; // get rid of the fefefefe

		gmmcRelocation reloc = {};
		reloc.offset = reloc_offset;
		reloc.target = sym;
		f_array_push(&code_section->relocs, reloc);
	}
	else if (gmmc_is_op_instant(p->proc, op_idx)) {
		static int __c = 0;
		__c++;

		u32 size = gmmc_type_size(op->type);
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_MOV;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result, size);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
		req.operands[1].imm.u = sign_extend(op->imm_raw, size*8); // zydis requires sign-extended immediates
		emit(p, req, " ; immediate to reg");
		int aa = 5;
	}
	else {
		//F_ASSERT(p->ops[op_idx].currently_in_register == GPR_INVALID);

		RegSize size = gmmc_type_size(p->proc->ops[op_idx].type);

		// load the spilled op value from stack
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_MOV;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result, size);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
		req.operands[1].mem.displacement = p->ops[op_idx].spill_offset_frame_rel + p->stack_frame_size;
		req.operands[1].mem.size = size;
		emit(p, req, " ; load spilled value");
	}
	return result;
}

static GPR use_op_value(gmmcAsmProc* p, gmmcOpIdx op_idx, GPR specify_reg = GPR_INVALID) {
	GPR result = GPR_INVALID;
	update_last_use_time(p, op_idx);

	if (p->emitting) {
		result = op_value_to_reg(p, op_idx, specify_reg);
	}
	return result;
}

static LooseReg use_op_value_loose(gmmcAsmProc* p, gmmcOpIdx op_idx) {
	LooseReg result = {};
	update_last_use_time(p, op_idx);

	if (p->emitting) {
		result.source_op = op_idx;
	}
	return result;
}

GMMC_API u32 gmmc_asm_instruction_get_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx op) {
	VALIDATE(proc->ops[op].bb_idx != GMMC_BB_INDEX_NONE); // immediates do not get assigned an offset
	return m->procs[proc->self_idx].ops[op].instruction_offset;
}

GMMC_API u32 gmmc_asm_proc_get_start_offset(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].code_section_offset; }
GMMC_API u32 gmmc_asm_proc_get_end_offset(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].code_section_end_offset; }
GMMC_API u32 gmmc_asm_proc_get_stack_frame_size(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].stack_frame_size; }
GMMC_API u32 gmmc_asm_proc_get_prolog_size(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].prolog_size; }
GMMC_API u32 gmmc_asm_global_get_offset(gmmcAsmModule* m, gmmcGlobal* global) { return m->globals[global->self_idx].offset; }

GMMC_API s32 gmmc_asm_get_frame_rel_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx local_or_param) {
	gmmcOpData* op = &proc->ops[local_or_param];
	gmmcAsmProc* asm_proc = &m->procs[proc->self_idx];

	if (op->kind == gmmcOpKind_local) {
		u32 local_idx = op->local_idx;
		return asm_proc->local_frame_rel_offset[local_idx];
	}
	else if (op->kind == gmmcOpKind_addr_of_param) {
		return 8 + 8*(u32)op->imm_raw; // :AddressOfParam
	}
	VALIDATE(false); return 0;
}

const static GPR ms_x64_param_regs[4] = { GPR_CX, GPR_DX, GPR_8, GPR_9 };

static void gen_array_access(gmmcAsmProc* p, gmmcOpData* op) {
	GPR result_reg = allocate_op_result(p);
	GPR base_reg = use_op_value(p, op->operands[0]);
	GPR index_reg = use_op_value(p, op->operands[1]);

	if (p->emitting) {
		// memory-based operand `scale` can only encode 1, 2, 4 or 8 in x64.
		bool can_encode_scale_directly = op->imm_raw == 1 || op->imm_raw == 2 || op->imm_raw == 4 || op->imm_raw == 8;
		
		if (!can_encode_scale_directly) {
			// wait... this isn't legal!!! we can't just overwrite the data in the register, hmm...
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_IMUL;
			req.operand_count = 3;
			req.operands[0] = make_reg_operand(GPR_AX, 8);
			req.operands[1] = make_reg_operand(index_reg, 8);
			req.operands[2].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[2].imm.u = (u32)op->imm_raw;
			emit(p, req);

			// NOTE: we `use_op_value` returns a read-only handle to a work register, so use RAX as a temporary
			index_reg = GPR_AX;
		}
		
		// When using the memory-operand 'index' field, we must to use the full 64 bits of it (x64 encoding forces it)

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_LEA;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result_reg, 8);
		req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		req.operands[1].mem.base = get_x64_reg(base_reg, 8);
		req.operands[1].mem.index = get_x64_reg(index_reg, 8);
		req.operands[1].mem.scale = can_encode_scale_directly ? (u8)op->imm_raw : 1;
		req.operands[1].mem.size = 8;
		emit(p, req, " ; array access");
	}
}

static void gen_comparison(gmmcAsmProc* p, gmmcOpData* op) {
	GPR result_value = allocate_op_result(p);
	GPR a = use_op_value(p, op->operands[0]);
	GPR b = use_op_value(p, op->operands[1]);
	
	if (p->emitting) {
		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_CMP;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(a, 1);
			req.operands[1] = make_reg_operand(b, 1);
			emit(p, req);
		}

		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			switch (op->kind) {
			case gmmcOpKind_eq: { req.mnemonic = ZYDIS_MNEMONIC_SETZ; } break; 
			case gmmcOpKind_ne: { req.mnemonic = ZYDIS_MNEMONIC_SETNZ; } break;
			case gmmcOpKind_lt: { req.mnemonic = op->is_signed ? ZYDIS_MNEMONIC_SETL : ZYDIS_MNEMONIC_SETB; } break;
			case gmmcOpKind_le: { req.mnemonic = op->is_signed ? ZYDIS_MNEMONIC_SETLE : ZYDIS_MNEMONIC_SETBE; } break;
			case gmmcOpKind_gt: { req.mnemonic = op->is_signed ? ZYDIS_MNEMONIC_SETNLE : ZYDIS_MNEMONIC_SETNBE; } break;
			case gmmcOpKind_ge: { req.mnemonic = op->is_signed ? ZYDIS_MNEMONIC_SETNL : ZYDIS_MNEMONIC_SETNB; } break;
			}
			req.operand_count = 1;
			req.operands[0] = make_reg_operand(result_value, 1);
			emit(p, req);
		}
	}
}

static void gen_op_basic_2(gmmcAsmProc* p, gmmcOpData* op, ZydisMnemonic mnemonic) {
	GPR result_value = allocate_op_result(p);
	LooseReg a = use_op_value_loose(p, op->operands[0]);
	GPR b = use_op_value(p, op->operands[1]);

	if (p->emitting) {
		op_value_to_reg(p, a.source_op, result_value); // ADD instruction overwrites the first operand with the result

		RegSize size = gmmc_type_size(op->type);
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = mnemonic;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result_value, size);
		req.operands[1] = make_reg_operand(b, size);
		emit(p, req);
	}
}

static void emit_mov_imm_to_reg(gmmcAsmProc* p, GPR reg, u64 imm) {
	ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
	req.mnemonic = ZYDIS_MNEMONIC_MOV;
	req.operand_count = 2;
	req.operands[0] = make_reg_operand(reg, 8);
	req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	req.operands[1].imm.u = imm;
	emit(p, req);
}

static void gen_div_or_mod(gmmcAsmProc* p, gmmcOpData* op, GPR take_result_from) {
	GPR result_value = allocate_op_result(p);

	use_op_value(p, op->operands[0], GPR_AX); // dividend
	GPR divisor = use_op_value(p, op->operands[1]);

	if (p->emitting) {
		//op->is_signed
		RegSize size = gmmc_type_size(op->type);
		
		// if the size is 1 or 2, sign/zero extend the dividend and divisor into 64 bits
		if (size <= 2) {
			emit_mov_reg_to_reg(p, GPR_AX, GPR_AX, size, op->is_signed ? ExtendBits_Sign : ExtendBits_Zero);
			emit_mov_reg_to_reg(p, divisor, divisor, size, op->is_signed ? ExtendBits_Sign : ExtendBits_Zero);
		}

		if (op->is_signed) {
			// sign-extend the dividend in RAX into RDX
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_CQO;
			emit(p, req);
		}
		else {
			emit_mov_imm_to_reg(p, GPR_DX, 0);
		}

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = op->is_signed ? ZYDIS_MNEMONIC_IDIV : ZYDIS_MNEMONIC_DIV;
		req.operand_count = 1;
		req.operands[0] = make_reg_operand(divisor, size);
		emit(p, req);

		emit_mov_reg_to_reg(p, result_value, take_result_from, 8);
	}
}

static void gen_return(gmmcAsmProc* p, gmmcOpData* op) {
	LooseReg value_reg = {};
	if (op->operands[0] != GMMC_OP_IDX_INVALID) value_reg = use_op_value_loose(p, op->operands[0]);

	if (p->emitting) {

		if (op->operands[0] != GMMC_OP_IDX_INVALID) {
			op_value_to_reg(p, value_reg.source_op, GPR_AX); // move the return value to RAX
		}

		for (uint i = 0; i < p->work_registers_used_count; i++) { // restore the state of the non-volatile registers that we used as work registers
			GPR reg = work_registers[i];
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(reg, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement = p->work_reg_restore_frame_rel_offset[reg] + p->stack_frame_size;
			req.operands[1].mem.size = 8;
			emit(p, req, " ; restore foreign value of a register");
		}

		// restore stack-frame
		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_ADD;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(GPR_SP, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.s = p->stack_frame_size;
			emit(p, req);
		}
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_RET;
		emit(p, req);
	}
}

static void gen_vcall(gmmcAsmProc* p, gmmcOpData* op) {
	GPR proc_addr_reg = use_op_value(p, op->call.target);

	// https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170
	//u32 shadow_space_base = p->stack_frame_size + 8; // 

	for (u32 i = (u32)op->call.arguments.len - 1; i < op->call.arguments.len; i--) {
		LooseReg arg = use_op_value_loose(p, op->call.arguments[i]);

		if (p->emitting) {
			if (i < 4) {
				op_value_to_reg(p, arg.source_op, ms_x64_param_regs[i]);
			}
			else {
				GPR arg_reg = op_value_to_reg(p, arg.source_op);

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
				req.operands[0].mem.displacement = i * 8;
				req.operands[0].mem.size = 8;
				req.operands[1] = make_reg_operand(arg_reg, 8);
				emit(p, req);
			}
		}
	}

	if (!p->emitting) {
		// https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170

		// TODO: float arguments
		u32 shadow_space_size = F_MAX((u32)op->call.arguments.len, 4) * 8;
		p->largest_call_shadow_space_size = F_MAX(p->largest_call_shadow_space_size, shadow_space_size);
	}

	GPR result_reg = GPR_INVALID;
	if (op->type) {
		// Procedure returns a value!
		result_reg = allocate_op_result(p);
	}

	if (p->emitting) {
		// move arguments to the stack

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_CALL;
		req.operand_count = 1;
		req.operands[0] = make_reg_operand(proc_addr_reg, 8);
		emit(p, req);

		if (op->type) {
			emit_mov_reg_to_reg(p, result_reg, GPR_AX, 8);
			emit(p, req, " ; save return value");
		}
	}
}

static u32 gen_bb(gmmcAsmProc* p, gmmcBasicBlockIdx bb_idx) {
	gmmcBasicBlock* bb = p->proc->basic_blocks[bb_idx];

	u32 existing_offset = p->blocks[bb_idx].offset;
	if (existing_offset != F_U32_MAX) return existing_offset; // already visited

	if (p->emitting) {
		// Clear out the state of work-registers, as this is a fresh basic block
		for (uint i = 0; i < GPR_COUNT; i++) {
			gmmcOpIdx taken_by_op = p->work_reg_taken_by_op[i];
			if (taken_by_op != GMMC_OP_IDX_INVALID) {
				p->ops[taken_by_op].currently_in_register = GPR_INVALID;
				p->work_reg_taken_by_op[i] = GMMC_OP_IDX_INVALID;
			}
		}
	}

	u32 bb_offset = p->emitting ? (u32)p->module->sections[gmmcSection_Code].data.len : 0;
	p->blocks[bb_idx].offset = bb_offset;

	Section* code_section = &p->module->sections[gmmcSection_Code];

	for (uint i = 0; i < bb->ops.len; i++) {
		p->current_op = bb->ops[i];

		gmmcOpData* op = &p->proc->ops[p->current_op];

		if (p->emitting) {
			p->ops[p->current_op].instruction_offset = (u32)p->module->sections[gmmcSection_Code].data.len;
		}

		switch (op->kind) {
		
		case gmmcOpKind_comment: {
			if (op->comment.len > 0) {
				fSlice(fRangeUint) lines;
				f_str_split_i(op->comment, '\n', f_temp_alc(), &lines);
				for (uint i = 0; i < lines.len; i++) {
					fString line = f_str_slice(op->comment, lines[i].lo, lines[i].hi);
					printf("; %.*s\n", F_STRF(line));
				}
			}
			else {
				printf("\n");
			}
		} break;

		case gmmcOpKind_vcall: { gen_vcall(p, op); } break;
		//case gmmcOpKind_call: { F_BP; } break;
		case gmmcOpKind_return: { gen_return(p, op); } break;

		case gmmcOpKind_goto: {
			F_ASSERT(i == bb->ops.len - 1); // must be the last op

			// if the destination block hasn't been generated yet, we can generate it directly after this op
			// and we don't even need a jump instruction.
			bool dst_block_has_been_generated;
			s32 offset_after_jmp;

			if (p->emitting) {
				dst_block_has_been_generated = p->blocks[op->goto_.dst_bb].offset != F_U32_MAX;
				if (dst_block_has_been_generated) {
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_JMP;
					req.operand_count = 1;
					req.branch_width = ZYDIS_BRANCH_WIDTH_32;
					req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					req.operands[0].imm.u = 0;
					emit(p, req, " ; goto (target address is to be patched)");
					offset_after_jmp = (s32)code_section->data.len;
				}
			}

			u32 dst_bb_offset = gen_bb(p, op->goto_.dst_bb);

			if (p->emitting) {
				if (dst_block_has_been_generated) {
					*(s32*)(code_section->data.data + offset_after_jmp - 4) = (s32)dst_bb_offset - (s32)offset_after_jmp;
				}
			}
		} break;

		case gmmcOpKind_if: {
			F_ASSERT(i == bb->ops.len - 1); // must be the last op
			GPR condition_reg = use_op_value(p, op->if_.condition);
			
			// branches are expected to be 'false'

			if (p->emitting) {
				// ...we're doing a bunch of unnecessary CMPs
				{
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_CMP;
					req.operand_count = 2;
					req.operands[0] = make_reg_operand(condition_reg, 1);
					req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					emit(p, req);
				}
				
				// jump to the 'true' block if the condition is true, otherwise continue execution with hopefully no jump

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_JNZ;
				req.operand_count = 1;
				req.branch_width = ZYDIS_BRANCH_WIDTH_32;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
				req.operands[0].imm.u = 0;
				emit(p, req, " ; if true (target address is to be patched)");
			}

			u32 offset_after_cond_jmp = (u32)code_section->data.len;

			u32 false_bb_offset = gen_bb(p, op->if_.false_bb);
			
			if (p->emitting) {
				if (offset_after_cond_jmp != false_bb_offset) {
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_JMP;
					req.operand_count = 1;
					req.branch_width = ZYDIS_BRANCH_WIDTH_32;
					req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					req.operands[0].imm.u = 0;
					emit(p, req, " ; jump to false block (target address is to be patched)");

					s32 offset_after_jmp = (s32)code_section->data.len;
					*(s32*)(code_section->data.data + offset_after_jmp - 4) = (s32)false_bb_offset - (s32)offset_after_jmp;
				}
			}

			u32 true_bb_offset = gen_bb(p, op->if_.true_bb);
			
			if (p->emitting) {
				*(s32*)(code_section->data.data + offset_after_cond_jmp - 4) = (s32)true_bb_offset - (s32)offset_after_cond_jmp;
			}
		} break;

		case gmmcOpKind_store: {
			GPR dst_reg = use_op_value(p, op->operands[0]);
			GPR value_reg = use_op_value(p, op->operands[1]);
			// hmm... what about immediates?
				
			if (p->emitting) {
				RegSize size = gmmc_type_size(gmmc_get_op_type(p->proc, op->operands[1]));

				// TODO: 64-bit immediate -> memory isn't possible with one instruction
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = get_x64_reg(dst_reg, 8);
				req.operands[0].mem.size = size;
				req.operands[1] = make_reg_operand(value_reg, size);
				emit(p, req, " ; store");
				int a = 50;
			}
		} break;

		case gmmcOpKind_load: {
			GPR result_reg = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0]);

			if (p->emitting) {
				RegSize size = gmmc_type_size(op->type);
				
				// mem -> reg
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, size);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = get_x64_reg(src_reg, 8);
				req.operands[1].mem.size = size;
				emit(p, req, " ; load");
			}
		} break;

		case gmmcOpKind_int2ptr: // fallthrough
		case gmmcOpKind_ptr2int: // fallthrough
		case gmmcOpKind_trunc:{
			// do nothing, just pass the value through
			GPR result_value = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			if (p->emitting) {
				op_value_to_reg(p, a.source_op, result_value);
			}
		} break;

		case gmmcOpKind_sxt: // fallthrough
		case gmmcOpKind_zxt: {
			// our general purpose registers may contain garbage. i.e. when you do an 8-bit load / mov, it won't do
			// anything to the high bits.

			GPR result_value = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0]);
			if (p->emitting) {
				RegSize src_size = gmmc_type_size(gmmc_get_op_type(p->proc, op->operands[0]));
				emit_mov_reg_to_reg(p, result_value, src_reg, src_size, gmmcOpKind_sxt ? ExtendBits_Sign : ExtendBits_Zero);
			}
		} break;

		case gmmcOpKind_memcpy: {
			// NOTE: the direction flag should be always cleared to 0, as specified in the calling convention:
			// "On function exit and on function entry to C Runtime Library calls and Windows system calls,
			// the direction flag in the CPU flags register is expected to be cleared."
			// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170

			GPR src_reg = use_op_value(p, op->operands[0], GPR_DI);
			GPR dst_reg = use_op_value(p, op->operands[1], GPR_SI);
			GPR size_reg = use_op_value(p, op->operands[2], GPR_CX);
			
			if (p->emitting) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOVSB;
				req.prefixes = ZYDIS_ATTRIB_HAS_REP;
				emit(p, req, " ; memcpy");
			}
		} break;

		case gmmcOpKind_member_access: {
			GPR result_reg = allocate_op_result(p);
			GPR base_reg = use_op_value(p, op->operands[0]);
			
			if (p->emitting) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_LEA;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, 8);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = get_x64_reg(base_reg, 8);
				req.operands[1].mem.displacement = op->imm_raw;
				req.operands[1].mem.size = 8;
				emit(p, req, " ; member access");
			}
		} break;

		case gmmcOpKind_array_access: { gen_array_access(p, op); } break;

		// TODO: make these ops not part of a basic block
		case gmmcOpKind_addr_of_symbol: break;
		case gmmcOpKind_bool: break;
		case gmmcOpKind_i8: break;
		case gmmcOpKind_i16: break;
		case gmmcOpKind_i32: break;
		case gmmcOpKind_i64: break;
		case gmmcOpKind_i128: break;
		case gmmcOpKind_f32: break;
		case gmmcOpKind_f64: break;

		case gmmcOpKind_eq: { gen_comparison(p, op); } break;
		case gmmcOpKind_ne: { gen_comparison(p, op); } break;
		case gmmcOpKind_lt: { gen_comparison(p, op); } break;
		case gmmcOpKind_le: { gen_comparison(p, op); } break;
		case gmmcOpKind_gt: { gen_comparison(p, op); } break;
		case gmmcOpKind_ge: { gen_comparison(p, op); } break;

		case gmmcOpKind_add: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_ADD); } break;
		case gmmcOpKind_sub: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_SUB); } break;
		case gmmcOpKind_mul: {
			// https://gpfault.net/posts/asm-tut-3.txt.html
			// NOTE: we can use IMUL always which is a bit more convenient than MUL, because
			// we're discarding the upper half of the result, and the lower half is identical to what you'd get from MUL.
			// This is a little bit magical to me.

			GPR result_value = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			GPR b = use_op_value(p, op->operands[1]);

			if (p->emitting) {
				op_value_to_reg(p, a.source_op, result_value); // The instruction overwrites the first operand with the result.

				RegSize size = gmmc_type_size(op->type);
				if (size < 4) size = 4; // Only ever do 32-bit or 64-bit multiplication.
				
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_IMUL;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_value, size);
				req.operands[1] = make_reg_operand(b, size);
				emit(p, req);
			}
		} break;
		case gmmcOpKind_div: { gen_div_or_mod(p, op, GPR_AX); } break;
		case gmmcOpKind_mod: { gen_div_or_mod(p, op, GPR_DX); } break;

		case gmmcOpKind_and: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_AND); } break;
		case gmmcOpKind_or: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_OR); } break;
		case gmmcOpKind_xor: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_XOR); } break;
		case gmmcOpKind_not: {
			GPR result_value = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			if (p->emitting) {
				op_value_to_reg(p, a.source_op, result_value);

				RegSize size = gmmc_type_size(op->type);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_NOT;
				req.operand_count = 1;
				req.operands[0] = make_reg_operand(result_value, size);
				emit(p, req);
			}
		} break;
		
		case gmmcOpKind_shr: // fallthrough
		case gmmcOpKind_shl: {
			GPR result_value = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			use_op_value(p, op->operands[1], GPR_CX);

			if (p->emitting) {
				op_value_to_reg(p, a.source_op, result_value); // the first operand is overwritten with the result

				RegSize size = gmmc_type_size(op->type);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = op->kind == gmmcOpKind_shr ? ZYDIS_MNEMONIC_SHR : ZYDIS_MNEMONIC_SHL;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_value, size);
				req.operands[1] = make_reg_operand(GPR_CX, 1);
				emit(p, req);
			}
		} break;

		case gmmcOpKind_debugbreak: {
			if (p->emitting) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_INT3;
				emit(p, req);
			}
		} break;

		default: F_BP;
		}
	}

	VALIDATE(bb->ops.len > 0);
	gmmcOpKind last_op_kind = gmmc_get_op_kind(p->proc, bb->ops[bb->ops.len - 1]);
	VALIDATE(gmmc_is_op_terminating(last_op_kind));
	return bb_offset;
}

GMMC_API void gmmc_gen_proc(gmmcAsmModule* module_gen, gmmcAsmProc* p, gmmcProc* proc) {
	printf("---- generating proc: '%.*s' ----\n", F_STRF(proc->sym.name));
	
	//gmmc_proc_print_c(stdout, proc);
	printf("---\n");
	
	p->module = module_gen;
	p->proc = proc;
	
	p->local_frame_rel_offset = f_make_slice_garbage<s32>(proc->locals.len, f_temp_alc());
	
	p->ops = f_make_slice<gmmcAsmOp>(proc->ops.len, {}, f_temp_alc());
	p->blocks = f_make_slice_garbage<gmmcAsmBB>(proc->basic_blocks.len, f_temp_alc());
	
	// When entering a procedure, the stack is always aligned to (16+8) bytes, because
	// before the CALL instruction it must be aligned to 16 bytes.

	s32 offset = 0;
	for (uint i = 1; i < proc->locals.len; i++) {
		gmmcLocal local = proc->locals[i];
		F_ASSERT(local.align <= 16); // 16 bytes is the maximum valid alignment!
		F_ASSERT(local.size > 0);
		
		offset -= local.size; // NOTE: the stack grows downwards!
		
		//F_ASSERT(local.align <= 8); // TODO: fix alignment for 16-byte aligned things
		offset = F_ALIGN_DOWN_POW2(offset, local.align);

		p->local_frame_rel_offset[i] = offset;
	}

	// reserve spill-space for all the ops

	for (gmmcOpIdx i = 0; i < proc->ops.len; i++) {
		// TODO: for `op_param`, we should put the spill rsp rel offset to the shadow-space of the parameter.
		gmmcOpData* op = &proc->ops[i];
		u32 size = gmmc_type_size(op->type);
		if (size == 0) continue;
		
		if (gmmc_is_op_instant(proc, i)) continue; // immediates can't get spilled
		
		offset -= size;

		F_ASSERT(size <= 8);
		offset = F_ALIGN_DOWN_POW2(offset, size);

		p->ops[i].spill_offset_frame_rel = offset;
	}
	
	// Reserve the worst-case space for register spilling (128 bytes)
	for (uint i = GPR_AX; i < GPR_COUNT; i++) {
		offset = F_ALIGN_DOWN_POW2(offset - 8, 8);
		p->work_reg_restore_frame_rel_offset[i] = offset;
	}
	
	// 1st pass
	{
		memset(p->blocks.data, 0xff, p->blocks.len * sizeof(gmmcAsmBB));
		p->emitting = false;
		gen_bb(p, 0);
	}
	
	// reserve shadow space for calls and align the stack to 16 bytes
	offset -= p->largest_call_shadow_space_size;
	offset = F_ALIGN_DOWN_POW2(offset + 8, 16) - 8; // NOTE: 8 byte misaligned stack
	
	// emit
	{
		Section* code_section = &p->module->sections[gmmcSection_Code];
		
		memset(p->blocks.data, 0xff, p->blocks.len * sizeof(gmmcAsmBB));
		p->emitting = true;
		//p->current_op = 0;

		p->code_section_offset = (u32)code_section->data.len;

		// reserve stack-frame
		p->stack_frame_size = -offset;
		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_SUB;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(GPR_SP, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.s = p->stack_frame_size;
			emit(p, req);
		}
		p->prolog_size = (u32)code_section->data.len - p->code_section_offset; // size of the initial sub RSP instruction

		// push the register-parameters onto the stack, so that addr_of_param will work on them

		uint register_params_n = F_MIN(4, p->proc->params.len);
		for (uint i = 0; i < register_params_n; i++) {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[0].mem.displacement = p->stack_frame_size + 8 + 8 * i; // :AddressOfParam
			req.operands[0].mem.size = 8;
			req.operands[1] = make_reg_operand(ms_x64_param_regs[i], 8);
			emit(p, req);
		}

		gen_bb(p, 0);

		p->code_section_end_offset = (u32)code_section->data.len;
	}
	
	printf("---------------------------------\n");
}

GMMC_API gmmcAsmModule* gmmc_asm_build_x64(gmmcModule* m) {
	gmmcAsmModule* gen = f_mem_clone(gmmcAsmModule{}, m->allocator);

	for (uint i = 0; i < gmmcSection_COUNT; i++) {
		gen->sections[i].data = f_array_make<u8>(m->allocator);
		gen->sections[i].relocs = f_array_make<gmmcRelocation>(m->allocator);
	}

	gen->procs = f_make_slice<gmmcAsmProc>(m->procs.len, {}, m->allocator);
	
	// add globals
	gen->globals = f_make_slice_garbage<gmmcAsmGlobal>(m->globals.len, m->allocator);
	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];

		Section* section = &gen->sections[global->section];
		f_array_resize(&section->data, F_ALIGN_UP_POW2((u32)section->data.len, global->align), (u8)0);
		
		gmmcAsmGlobal* asm_global = &gen->globals[i];
		asm_global->global = global;
		asm_global->offset = (u32)section->data.len;
		f_array_push_n(&section->data, fSlice(u8){(u8*)global->data, global->size});
	}

	// compile procedures
	for (uint i = 0; i < m->procs.len; i++) {
		gmmcProc* proc = m->procs[i];
		gmmc_gen_proc(gen, &gen->procs[i], proc);
	}
	
	// add relocations now that all globals and procedures have an offset assigned to them

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		Section* section = &gen->sections[global->section];

		for (uint j = 0; j < global->relocations.len; j++) {
			gmmcRelocation global_reloc = global->relocations[j];

			gmmcRelocation reloc = global_reloc;
			reloc.offset += gen->globals[i].offset;
			f_array_push(&section->relocs, reloc);
		}
	}

	return gen;
}
