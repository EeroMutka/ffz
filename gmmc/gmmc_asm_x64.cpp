#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"

//#define coffString fString
//#include "coff.h"

#include "Zydis/Zydis.h"

#include <stdio.h> // for fopen

#define VALIDATE(x) F_ASSERT(x)

//enum SectionNum {
//	SectionNum_Code = 1,
//	SectionNum_Data = 2,
//	SectionNum_RData = 3,
//};


typedef u16 RegSize;

struct gmmcAsmProc;

struct gmmcAsmModule {
	//gmmcModule* module;
	fArray(u8) code_section;
	fSlice(gmmcAsmProc) procs;
};

GMMC_API gmmcString gmmc_asm_get_code_section(gmmcAsmModule* m) { return { m->code_section.data, m->code_section.len }; }

//GMMC_API gmmcAsmSectionNum gmmc_asm_add_section(gmmcAsmModule* m, fString name) {
//	coffSection section = {};
//	section.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_4BYTES | IMAGE_SCN_MEM_READ;
//	section.name = name;
//	return (gmmcAsmSectionNum)f_array_push(&m->sections, section) + 1; // section numbers start from 1
//}
//
//GMMC_API void gmmc_asm_section_set_data(gmmcAsmModule* m, gmmcAsmSectionNum section, fString data) {
//	m->sections[section-1].data = data;
//}
//
//GMMC_API void gmmc_asm_section_set_relocations(gmmcAsmModule* m, gmmcAsmSectionNum section, gmmcAsmRelocation* relocations, u32 count) {
//	// NOTE: gmmcAsmRelocation is binarily compatible with coffRelocation, so we can just reinterpret the bytes
//	m->sections[section-1].relocations = (coffRelocation*)relocations;
//	m->sections[section-1].relocations_count = count;
//}
//
//GMMC_API u32 gmmc_asm_section_get_sym_index(gmmcAsmModule* m, gmmcAsmSectionNum section) {
//	F_BP;
//	return 0;
//}

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

//typedef struct gmmcAsmBB {
//	int x;
//} gmmcAsmBB;

struct gmmcAsmOp {
	gmmcOpIdx last_use_time;
	s32 spill_offset_frame_rel;

	GPR currently_in_register; // GPR_INVALID means it's on the stack / not inside a register

	u32 instruction_offset;
};

struct gmmcAsmProc {
	gmmcAsmModule* module;

	gmmcProc* proc;
	fSlice(s32) local_frame_rel_offset; // per-local

	fSlice(gmmcAsmOp) ops;
	//fSlice(s32) ops_spill_offset_frame_rel;
	//fSlice(GPR) ops_currently_in_register; // 
	//fSlice(gmmcOpIdx) ops_last_use_time; // 0 if never used
	//fSlice(gmmcOpIdx) ops_instruction_offset;

	//fSlice(gmmcAsmBB) basic_blocks;

	//gmmcBasicBlockIdx current_bb;
	gmmcOpIdx current_op;

	// We do 2 passes. In the first pass, we just fill up the `ops_last_use_time`s.
	// In the second pass, we figure out which registers to allocate on the fly and emit the instructions.
	bool emitting;
	
	u32 code_section_offset;
	u32 code_section_end_offset;

	u32 stack_frame_size;
	u8 prologue_size;

	u32 temp_registers_used_count;

	gmmcOpIdx temp_reg_taken_by_op[GPR_COUNT];

	// When taking a non-volatile register as a temp register, we must insert code to store the content of that register onto the stack, and
	// at the end of the procedure, restore the register's state.
	// NOTE: when we begin emitting, we don't know yet how many non-volatile temp registers we're going to use.
	// So for now, we just reserve stack space for each possible temp register. This could be solved if we introduced a third pass for the emitting, or if we emitted in a separate buffer and appended it at the end.
	s32 temp_reg_restore_frame_rel_offset[GPR_COUNT];
};

//s32 frame_rel_to_rsp_rel_offset(ProcGen* gen, s32 offset) { return gen->stack_frame_size + offset; }

static void emit(gmmcAsmProc* p, const ZydisEncoderRequest& req, const char* comment = "") {
	u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
	uint instr_len = sizeof(instr);
	bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, instr, &instr_len));
	VALIDATE(ok);

	f_array_push_n(&p->module->code_section, { instr, instr_len });

	// print disassembly
	{
		uint sect_rel_offset = p->module->code_section.len - instr_len;
		uint proc_rel_offset = sect_rel_offset - p->code_section_offset;

		u8* data = p->module->code_section.data + proc_rel_offset;
		
		ZydisDisassembledInstruction instruction;
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, proc_rel_offset, instr, instr_len, &instruction))) {
			printf("0x%llx:   %s%s\n", proc_rel_offset, instruction.text, comment);
		}
	}
}

// General-purpose registers. Prefer non-volatile registers for now
// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170
const static GPR temp_registers[] = {
	GPR_12,
	GPR_13,
	GPR_14,
	GPR_15,
	GPR_DI,
	GPR_SI,
	GPR_BX,
	GPR_BP,
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

ZydisEncoderOperand make_x64_reg_operand(GPR gpr, RegSize size) {
	ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_REGISTER };
	operand.reg.value = get_x64_reg(gpr, size);
	return operand;
}

// Loose register - stored either in a register or on the stack
struct LooseReg { gmmcOpIdx source_op; };


ZydisEncoderOperand make_x64_operand(gmmcAsmProc* p, LooseReg loose_reg, RegSize size) {
	GPR reg = p->ops[loose_reg.source_op].currently_in_register;
	
	if (reg) {
		ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_REGISTER };
		operand.reg.value = get_x64_reg(reg, size);
		return operand;
	}
	else {
		ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_MEMORY };
		operand.mem.base = ZYDIS_REGISTER_RSP;
		operand.mem.displacement = p->ops[loose_reg.source_op].spill_offset_frame_rel + p->stack_frame_size;
		operand.mem.size = size;
		return operand;
	}
}

static GPR allocate_gpr(gmmcAsmProc* p) {
	GPR gpr = GPR_INVALID;
	if (p->emitting) {

		for (u32 i = 0; i < p->temp_registers_used_count; i++) {
			gmmcOpIdx taken_by_op = p->temp_reg_taken_by_op[i];
			if (p->current_op > p->ops[taken_by_op].last_use_time) { // this op value will never be accessed later
				gpr = (GPR)i;
				break;
			}
		}
		
		// Take a new register. If the registers are all in use, then loop through them and steal the one used by the OP with the greatest `last_use_time`
		if (!gpr) {
			if (p->temp_registers_used_count < F_LEN(temp_registers)) {
				gpr = temp_registers[p->temp_registers_used_count++];

				// Store the original value of the non-volatile temp register, to be restored on return
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
				req.operands[0].mem.displacement = p->temp_reg_restore_frame_rel_offset[gpr] + p->stack_frame_size;
				req.operands[0].mem.size = 8;
				req.operands[1] = make_x64_reg_operand(gpr, 8);
				emit(p, req, " ; take a new register, save its foreign value");
			}
			else {
				F_BP;
			}
		}
	}
	return gpr;
}

static GPR allocate_op_result(gmmcAsmProc* p, gmmcOpIdx op_idx) {
	GPR reg = allocate_gpr(p);
	if (p->emitting) {
		p->temp_reg_taken_by_op[reg] = op_idx;
		p->ops[op_idx].currently_in_register = reg;
	}
	return reg;
}

static GPR use_op_value_strict(gmmcAsmProc* p, gmmcOpIdx op_idx) {
	GPR result = GPR_INVALID;
	p->ops[op_idx].last_use_time = p->current_op;

	if (p->emitting) {
		result = p->ops[op_idx].currently_in_register;
		if (result) return result;

		result = allocate_gpr(p);
		p->ops[op_idx].currently_in_register = result;

		
		// if the op is a `local`, then its value (address) isn't ever stored on the stack.
		gmmcOpData* op = &p->proc->ops[op_idx];
		if (op->kind == gmmcOpKind_local) {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_LEA;
			req.operand_count = 2;
			req.operands[0] = make_x64_reg_operand(result, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement = p->local_frame_rel_offset[op->local_idx] + p->stack_frame_size;
			req.operands[1].mem.size = 8; // hmm?
			emit(p, req, " ; address of local");
			int a = 50;
		}
		else if (gmmc_op_is_immediate(op->kind)) { // immediates aren't stored on the stack either.
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_x64_reg_operand(result, gmmc_type_size(op->type));
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.u = op->imm_raw;
			emit(p, req, " ; immediate to reg");
		}
		else {
			RegSize size = gmmc_type_size(p->proc->ops[op_idx].type);

			// load the spilled op value from stack
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_x64_reg_operand(result, size);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement = p->ops[op_idx].spill_offset_frame_rel + p->stack_frame_size;
			req.operands[1].mem.size = size;
			emit(p, req, " ; load spilled value");
		}

	}
	return result;
}

static LooseReg use_op_value(gmmcAsmProc* p, gmmcOpIdx op_idx) {
	LooseReg result = {};
	p->ops[op_idx].last_use_time = p->current_op;

	if (p->emitting) {
		result.source_op = op_idx;
		//result.reg = p->ops_currently_in_register[op_idx];
		//if (!result.reg) {
		//	result.rsp_rel_offset = p->ops_spill_offset_frame_rel[op_idx] + p->stack_frame_size;
		//}
	}
	return result;
}

/*ZydisEncoderOperand op_to_x64_operand(ProcGen* p, gmmcOpIdx op_idx, RegSize operand_size) {
	gmmcOpData op = p->proc->ops[op_idx];
	switch (op.kind) {
	case gmmcOpKind_local: {
		ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_MEMORY };
		operand.mem.base = ZYDIS_REGISTER_RSP;
		operand.mem.displacement = p->local_rsp_rel_offset[op.local_idx];
		operand.mem.size = operand_size;
		F_ASSERT(operand_size > 0);
		//u32 local_idx = ->proc->ops[op.operands[0]].
		//
		//operand.mem.size = gmmc_type_size(p.type);
		return operand;
	}

	case gmmcOpKind_bool: // fallthrough
	case gmmcOpKind_i8: // fallthrough
	case gmmcOpKind_i16: // fallthrough
	case gmmcOpKind_i32: // fallthrough
	case gmmcOpKind_i64: {
		ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_IMMEDIATE };
		operand.imm.u = op.imm_raw;
		return operand;
	}
	}

	GPR op_in_register = p->ops_current_register[op_idx];
	if (op_in_register) {
		ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_REGISTER };
		operand.reg.value = get_x64_register(op_in_register, operand_size);
		return operand;
	}
	else {
		s32 offset = p->ops_spill_rsp_rel_offset[op_idx];

		// let's load the op into a register
		GPR reg = take_gpr(p);

		ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_REGISTER };
		operand.reg.value = get_x64_register(reg, operand_size);
		return operand;

		// hmm. I guess sometimes we have to load the value into a register, but if we don't have to, let's use a memory-based operand
		//ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_MEMORY };
		//operand.mem.base = ZYDIS_REGISTER_RSP;
		//operand.mem.displacement = offset;
		//operand.mem.size = operand_size;
		//return operand;
	}
}*/

static void emit_mov_to_r(gmmcAsmProc* p, GPR dst, LooseReg src) {
	ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
	req.mnemonic = ZYDIS_MNEMONIC_MOV;
	req.operand_count = 2;
	req.operands[0] = make_x64_reg_operand(dst, 8);
	req.operands[1] = make_x64_operand(p, src, 8);
	emit(p, req);
}

static void emit_mov(gmmcAsmProc* p, LooseReg dst, LooseReg src) {
	ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
	req.mnemonic = ZYDIS_MNEMONIC_MOV;
	req.operand_count = 2;
	req.operands[0] = make_x64_operand(p, dst, 8);
	req.operands[1] = make_x64_operand(p, src, 8);
	emit(p, req);
}

//static void emit_mov_reg_to_reg(ProcGen* p, GPR dst, GPR src) {
//	ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
//	req.mnemonic = ZYDIS_MNEMONIC_MOV;
//	req.operand_count = 2;
//	req.operands[0] = make_x64_reg_operand(dst, 8);
//	req.operands[1] = make_x64_reg_operand(src, 8);
//	emit(p, req);
//}

GMMC_API u32 gmmc_asm_instruction_get_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx op) { return m->procs[proc->self_idx].ops[op].instruction_offset; }
GMMC_API u32 gmmc_asm_proc_get_start_offset(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].code_section_offset; }
GMMC_API u32 gmmc_asm_proc_get_end_offset(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].code_section_end_offset; }
GMMC_API u32 gmmc_asm_proc_get_stack_frame_size(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].stack_frame_size; }
GMMC_API u32 gmmc_asm_proc_get_prologue_size(gmmcAsmModule* m, gmmcProc* proc) { return m->procs[proc->self_idx].prologue_size; }

GMMC_API s32 gmmc_asm_local_get_frame_rel_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx local) {
	F_ASSERT(proc->ops[local].kind == gmmcOpKind_local);
	u32 local_idx = proc->ops[local].local_idx;
	return m->procs[proc->self_idx].local_frame_rel_offset[local_idx];
}

static void gen_bb(gmmcAsmProc* p, gmmcBasicBlockIdx bb_idx) {
	gmmcBasicBlock* bb = p->proc->basic_blocks[bb_idx];
	
	//if (p->emitting) {
	//	p->basic_blocks[bb_idx].code_section_offset = (u32)p->module_gen->code_section.len;
	//}

	for (uint i = 0; i < bb->ops.len; i++) {
		p->current_op = bb->ops[i];
		gmmcOpData* op = &p->proc->ops[p->current_op];
		
		if (p->emitting) {
			p->ops[p->current_op].instruction_offset = (u32)p->module->code_section.len;
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

		case gmmcOpKind_store: {
			GPR dst_reg = use_op_value_strict(p, op->operands[0]);
			GPR value_reg = use_op_value_strict(p, op->operands[1]);
			// hmm... what about immediates?
				
			if (p->emitting) {
				RegSize size = gmmc_type_size(gmmc_op_get_type(p->proc, op->operands[1]));

				// TODO: 64-bit immediate -> memory isn't possible with one instruction
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = get_x64_reg(dst_reg, 8);
				req.operands[0].mem.size = size;
				req.operands[1] = make_x64_reg_operand(value_reg, size);
				emit(p, req, " ; store");
				int a = 50;
			}
		} break;

		//case gmmcOpKind_local: {
		//	GPR result_reg = allocate_op_result(p, p->current_op);
		//	
		//	if (p->emitting) {
		//		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		//		req.mnemonic = ZYDIS_MNEMONIC_LEA;
		//		req.operand_count = 2;
		//		req.operands[0] = make_x64_reg_operand(result_reg, 8);
		//		req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
		//		req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
		//		req.operands[1].mem.displacement = p->local_frame_rel_offset[op->local_idx] + p->stack_frame_size;
		//		emit(p, req);
		//	}
		//} break;

		case gmmcOpKind_load: {
			GPR result_reg = allocate_op_result(p, p->current_op);
			GPR src_reg = use_op_value_strict(p, op->operands[0]);

			if (p->emitting) {
				RegSize size = gmmc_type_size(op->type);
				
				// mem -> reg
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0] = make_x64_reg_operand(result_reg, size);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = get_x64_reg(src_reg, 8);
				req.operands[1].mem.size = size;
				emit(p, req, " ; load");
			}
		} break;

		case gmmcOpKind_bool: break;
		case gmmcOpKind_i8: break;
		case gmmcOpKind_i16: break;
		case gmmcOpKind_i32: break;
		case gmmcOpKind_i64: break;
		case gmmcOpKind_i128: break;
		case gmmcOpKind_f32: break;
		case gmmcOpKind_f64: break;

		case gmmcOpKind_add: {
			GPR result_value = allocate_op_result(p, p->current_op);
			LooseReg a = use_op_value(p, op->operands[0]);
			LooseReg b = use_op_value(p, op->operands[1]);

			if (p->emitting) {
				emit_mov_to_r(p, result_value, a); // ADD instruction overwrites the first operand with the result

				RegSize size = gmmc_type_size(op->type);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_ADD;
				req.operand_count = 2;
				req.operands[0] = make_x64_reg_operand(result_value, size);
				req.operands[1] = make_x64_operand(p, b, size);
				emit(p, req);
			}
			F_BP;
		} break;

		case gmmcOpKind_debugbreak: {
			if (p->emitting) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_INT3;
				emit(p, req);
			}
		} break;

		case gmmcOpKind_return: {
			LooseReg value_reg = {};
			if (op->type) value_reg = use_op_value(p, op->operands[0]);

			if (p->emitting) {
				if (op->operands[0] != GMMC_REG_NONE) {
					F_BP;
				}

				for (uint i = 0; i < p->temp_registers_used_count; i++) { // restore the state of the non-volatile registers that we used as temporary registers
					GPR reg = temp_registers[i];
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_MOV;
					req.operand_count = 2;
					req.operands[0] = make_x64_reg_operand(reg, 8);
					req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
					req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
					req.operands[1].mem.displacement = p->temp_reg_restore_frame_rel_offset[reg] + p->stack_frame_size;
					req.operands[1].mem.size = 8;
					emit(p, req, " ; restore foreign value of a register");
				}

				// restore stack-frame
				{
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_ADD;
					req.operand_count = 2;
					req.operands[0] = make_x64_reg_operand(GPR_SP, 8);
					req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					req.operands[1].imm.s = p->stack_frame_size;
					emit(p, req);
				}
				
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_RET;
				emit(p, req);
			}
		} break;

		default: F_BP;
		}
	}

	VALIDATE(bb->ops.len > 0);
	gmmcOpKind last_op_kind = gmmc_op_get_kind(p->proc, bb->ops[bb->ops.len - 1]);
	VALIDATE(gmmc_op_is_terminating(last_op_kind));
}


GMMC_API void gmmc_gen_proc(gmmcAsmModule* module_gen, gmmcAsmProc* p, gmmcProc* proc) {
	printf("---- generating proc: '%.*s' ----\n", F_STRF(proc->sym.name));
	
	gmmc_proc_print(stdout, proc);
	printf("---\n");
	
	p->module = module_gen;
	p->proc = proc;
	
	p->local_frame_rel_offset = f_make_slice_garbage<s32>(proc->locals.len, f_temp_alc());
	
	p->ops = f_make_slice<gmmcAsmOp>(proc->ops.len, {}, f_temp_alc());
	
	//p->basic_blocks = f_make_slice<gmmcAsmBB>(proc->basic_blocks.len, {}, f_temp_alc());

	// When entering a procedure, the stack is always aligned to (16+8) bytes, because
	// before the CALL instruction it must be aligned to 16 bytes.

	s32 offset = 0;
	for (uint i = 1; i < proc->locals.len; i++) {
		gmmcLocal local = proc->locals[i];
		F_ASSERT(local.align <= 16); // 16 bytes is the maximum valid alignment!
		F_ASSERT(local.size > 0);
		
		offset -= local.size; // NOTE: the stack grows downwards!
		
		F_ASSERT(local.align <= 8); // TODO: fix alignment for 16-byte aligned things
		offset = F_ALIGN_DOWN_POW2(offset, local.align); // NOTE: 8 byte misaligned stack

		p->local_frame_rel_offset[i] = offset;
	}


	// reserve spill-space for all the ops

	for (uint i = 0; i < proc->ops.len; i++) {
		// TODO: for `op_param`, we should put the spill rsp rel offset to the home-space of the parameter.
		gmmcOpData* op = &proc->ops[i];
		u32 size = gmmc_type_size(op->type);
		if (size == 0) continue;

		// immediates and locals don't require spill space
		//if (gmmc_op_is_immediate(op->kind)) continue;
		if (op->kind == gmmcOpKind_local) continue;
		
		offset -= size;

		F_ASSERT(size <= 8);
		offset = F_ALIGN_DOWN_POW2(offset, size);

		p->ops[i].spill_offset_frame_rel = offset;
	}
	
	// Reserve the worst-case space for register spilling (128 bytes)
	for (uint i = GPR_AX; i < GPR_COUNT; i++) {
		offset = F_ALIGN_DOWN_POW2(offset - 8, 8);
		p->temp_reg_restore_frame_rel_offset[i] = offset;
	}

	// find the live ranges
	{
		p->emitting = false;
		gen_bb(p, 0);
	}
	
	// emit
	{
		p->emitting = true;
		p->code_section_offset = (u32)p->module->code_section.len;

		// reserve stack-frame
		p->stack_frame_size = -offset;
		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_SUB;
			req.operand_count = 2;
			req.operands[0] = make_x64_reg_operand(GPR_SP, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.s = p->stack_frame_size;
			emit(p, req);
		}
		p->prologue_size = (u32)p->module->code_section.len - p->code_section_offset; // size of the initial sub RSP instruction

		gen_bb(p, 0);
		p->code_section_end_offset = (u32)p->module->code_section.len;
	}
	

	printf("---------------------------------\n");
}

GMMC_API gmmcAsmModule* gmmc_asm_build_x64(gmmcModule* m) {
	gmmcAsmModule* gen = f_mem_clone(gmmcAsmModule{}, m->allocator);

	//gen->sections = f_array_make<coffSection>(m->allocator);
	//gen->symbols = f_array_make<coffSymbol>(m->allocator);

	gen->code_section = f_array_make<u8>(m->allocator);
	gen->procs = f_make_slice<gmmcAsmProc>(m->procs.len, {}, m->allocator);

	// compile procedures
	for (uint i = 0; i < m->procs.len; i++) {
		gmmcProc* proc = m->procs[i];
		gmmc_gen_proc(gen, &gen->procs[i], proc);
	}

	/*
	
	{
		coffSection sect = {};
		sect.name = F_LIT(".code");
		sect.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		sect.data = gen->code_section.slice;
		//sect.relocations = text_relocs.data;
		//sect.relocations_count = (int)text_relocs.len;
		f_array_push(&gen->sections, sect);
	}*/

	return gen;
}

//GMMC_API void gmmc_asm_export_x64(fString obj_filepath, gmmcAsmModule* m) {
//	FILE* obj_file = fopen(f_str_t_to_cstr(obj_filepath), "wb");
//	
//	coffDesc coff_desc = {};
//	coff_desc.sections = m->sections.data;
//	coff_desc.sections_count = (u32)m->sections.len;
//	coff_desc.symbols = m->symbols.data;
//	coff_desc.symbols_count = (u32)m->symbols.len;
//
//	coff_create([](fString result, void* userptr) {
//		fwrite(result.data, result.len, 1, (FILE*)userptr);
//		}, obj_file, &coff_desc);
//	
//	fclose(obj_file);
//}


/*

GMMC_API void gmmc_test() {
	fAllocator* temp = f_temp_alc();
	f_os_set_working_dir(F_LIT("C:\\dev\\ffz\\gmmc\\test"));

	gmmcModule* m = gmmc_init(temp);

	gmmcProcSignature* sig = gmmc_make_proc_signature(m, gmmcType_None, NULL, 0);

	gmmcBasicBlock* bb;
	gmmcProc* test_proc = gmmc_make_proc(m, sig, F_LIT("bot"), &bb);

	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);

	gmmc_op_return(bb, GMMC_REG_NONE);

	gmmc_proc_compile(test_proc);

	gmmc_create_coff(m, F_LIT("test.obj"));
	printf("Done!\n");

}*/

