#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"
#include "gmmc_coff.h"

#include "Zydis/Zydis.h"

#define VALIDATE(x) F_ASSERT(x)

enum SectionNum {
	SectionNum_Code = 1,
	SectionNum_Data = 2,
	SectionNum_RData = 3,
};

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

typedef u16 RegSize;

struct ProcGen;

struct ModuleGen {
	//gmmcModule* module;
	fArray(u8) code_section;
	fSlice(ProcGen) procs;
};

typedef struct BasicBlockGen {
	int x;
} BasicBlockGen;

struct ProcGen {
	ModuleGen* module_gen;

	gmmcProc* proc;
	fSlice(s32) local_frame_rel_offset; // per-local

	fSlice(s32) ops_spill_frame_rel_offset;
	fSlice(GPR) ops_currently_in_register; // GPR_INVALID means it's on the stack / not inside a register

	fSlice(gmmcOpIdx) ops_last_use_time; // 0 if never used

	fSlice(BasicBlockGen) basic_blocks;

	//gmmcBasicBlockIdx current_bb;
	gmmcOpIdx current_op;

	// We do 2 passes. In the first pass, we just fill up the `ops_last_use_time`s.
	// In the second pass, we figure out which registers to allocate on the fly and emit the instructions.
	bool emitting;
	
	u32 code_section_offset;
	u32 code_section_end_offset;

	u32 stack_frame_size;

	u32 temp_registers_used_count;

	gmmcOpIdx temp_reg_taken_by_op[GPR_COUNT];

	// When taking a non-volatile register as a temp register, we must insert code to store the content of that register onto the stack, and
	// at the end of the procedure, restore the register's state.
	// NOTE: when we begin emitting, we don't know yet how many non-volatile temp registers we're going to use.
	// So for now, we just reserve stack space for each possible temp register. This could be solved if we introduced a third pass for the emitting, or if we emitted in a separate buffer and appended it at the end.
	s32 temp_reg_restore_frame_rel_offset[GPR_COUNT];
};

//s32 frame_rel_to_rsp_rel_offset(ProcGen* gen, s32 offset) { return gen->stack_frame_size + offset; }

static void emit(ProcGen* p, const ZydisEncoderRequest& req) {
	u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
	uint instr_len = sizeof(instr);
	bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, instr, &instr_len));
	VALIDATE(ok);

	f_array_push_n(&p->module_gen->code_section, { instr, instr_len });


	// print disassembly
	{
		uint sect_rel_offset = p->module_gen->code_section.len - instr_len;
		uint proc_rel_offset = sect_rel_offset - p->code_section_offset;

		u8* data = p->module_gen->code_section.data + proc_rel_offset;
		
		ZydisDisassembledInstruction instruction;
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, proc_rel_offset, instr, instr_len, &instruction))) {
			printf("0x%llx:   %s\n", proc_rel_offset, instruction.text);
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

// stored either in a register or on the stack
struct Value {
	GPR reg;
	s32 rsp_rel_offset; // if reg is GPR_INVALID, this is used
};

static GPR allocate_gpr(ProcGen* p) {
	GPR gpr = GPR_INVALID;
	if (p->emitting) {

		for (u32 i = 0; i < p->temp_registers_used_count; i++) {
			gmmcOpIdx taken_by_op = p->temp_reg_taken_by_op[i];
			if (p->current_op > p->ops_last_use_time[taken_by_op]) { // this op value will never be accessed later
				gpr = (GPR)i;
				break;
			}
		}
		
		// Take a new register. If the registers are all in use, then loop through them and steal the one used by the OP with the greatest `last_use_time`
		if (!gpr) {
			if (p->temp_registers_used_count < F_LEN(temp_registers)) {
				gpr = temp_registers[p->temp_registers_used_count++];

				// Store the original value of the non-volatile temp register, to be restored at return
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
				req.operands[0].mem.displacement = p->temp_reg_restore_frame_rel_offset[gpr] + p->stack_frame_size;
				req.operands[0].mem.size = 8;
				req.operands[1] = make_x64_reg_operand(gpr, 8);
				emit(p, req);
			}
			else {
				F_BP;
			}
		}
	}
	return gpr;
}

static GPR allocate_op_result(ProcGen* p, gmmcOpIdx op_idx) {
	GPR reg = allocate_gpr(p);
	if (p->emitting) {
		p->temp_reg_taken_by_op[reg] = op_idx;
		p->ops_currently_in_register[op_idx] = reg;
	}
	return reg;
}

static GPR use_op_value(ProcGen* p, gmmcOpIdx op_idx) {
	p->ops_last_use_time[op_idx] = p->current_op;

	if (p->emitting) {
		GPR reg = p->ops_currently_in_register[op_idx];
		
		if (!reg) {
			reg = allocate_gpr(p);
			p->ops_currently_in_register[op_idx] = reg;
			
			RegSize size = gmmc_type_size(p->proc->ops[op_idx].type);
			
			// load the spilled op value from stack
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_x64_reg_operand(reg, size);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement = p->ops_spill_frame_rel_offset[op_idx] + p->stack_frame_size;
			req.operands[1].mem.size = size;
			emit(p, req);
		}
		
		return reg;
	}
	return GPR_INVALID;
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

static void emit_mov_reg_to_reg(ProcGen* p, GPR dst, GPR src) {
	ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
	req.mnemonic = ZYDIS_MNEMONIC_MOV;
	req.operand_count = 2;
	req.operands[0] = make_x64_reg_operand(dst, 8);
	req.operands[1] = make_x64_reg_operand(src, 8);
	emit(p, req);
}

static void gen_bb(ProcGen* p, gmmcBasicBlockIdx bb_idx) {
	gmmcBasicBlock* bb = p->proc->basic_blocks[bb_idx];
	
	//if (p->emitting) {
	//	p->basic_blocks[bb_idx].code_section_offset = (u32)p->module_gen->code_section.len;
	//}

	for (uint i = 0; i < bb->ops.len; i++) {
		p->current_op = bb->ops[i];
		gmmcOpData* op = &p->proc->ops[p->current_op];

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
			GPR dst_reg = use_op_value(p, op->operands[0]);
			GPR value_reg = use_op_value(p, op->operands[1]);
				
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
				emit(p, req);
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
			GPR src_reg = use_op_value(p, op->operands[0]);

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
				emit(p, req);
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
			GPR result_reg = allocate_op_result(p, p->current_op);
			GPR a_reg = use_op_value(p, op->operands[0]);
			GPR b_reg = use_op_value(p, op->operands[1]);

			if (p->emitting) {
				emit_mov_reg_to_reg(p, result_reg, a_reg); // ADD instruction overwrites the first operand with the result

				RegSize size = gmmc_type_size(op->type);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_ADD;
				req.operand_count = 2;
				req.operands[0] = make_x64_reg_operand(result_reg, size);
				req.operands[1] = make_x64_reg_operand(b_reg, size);
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
			GPR value_reg = GPR_INVALID;
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
					emit(p, req);
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

GMMC_API void gmmc_gen_proc(ModuleGen* module_gen, ProcGen* p, gmmcProc* proc) {
	printf("---- generating proc: '%.*s' ----\n", F_STRF(proc->sym.name));
	
	gmmc_proc_print(stdout, proc);
	printf("---\n");
	
	p->module_gen = module_gen;
	p->proc = proc;
	
	p->local_frame_rel_offset = f_make_slice_garbage<s32>(proc->locals.len, f_temp_alc());
	p->ops_last_use_time = f_make_slice<gmmcOpIdx>(proc->ops.len, {}, f_temp_alc());
	
	p->basic_blocks = f_make_slice<BasicBlockGen>(proc->basic_blocks.len, {}, f_temp_alc());

	// When entering a procedure, the stack is always aligned to (16+8) bytes, because
	// before the CALL instruction it must be aligned to 16 bytes.

	s32 offset = 0;
	for (uint i = 0; i < proc->locals.len; i++) {
		gmmcLocal local = proc->locals[i];
		F_ASSERT(local.align <= 16); // 16 bytes is the maximum valid alignment!

		offset -= local.size; // NOTE: the stack grows downwards!
		offset = F_ALIGN_DOWN_POW2(offset - 8, local.align) + 8; // NOTE: 8 byte misaligned stack

		p->local_frame_rel_offset[i] = offset;
	}

	p->ops_currently_in_register = f_make_slice<GPR>(proc->ops.len, GPR_INVALID, f_temp_alc());

	// reserve spill-space for all the ops

	p->ops_spill_frame_rel_offset = f_make_slice_garbage<s32>(proc->ops.len, f_temp_alc());
	for (uint i = 0; i < proc->ops.len; i++) {
		// TODO: for `op_param`, we should put the spill rsp rel offset to the home-space of the parameter.
		u32 size = gmmc_type_size(proc->ops[i].type);
		if (size != 0) {
			offset -= size;

			F_ASSERT(size <= 8);
			offset = F_ALIGN_DOWN_POW2(offset, size);

			p->ops_spill_frame_rel_offset[i] = offset;
		}
	}
	
	// Reserve the worst-case space for register spilling (128 bytes)
	for (uint i = GPR_AX; i < GPR_COUNT; i++) {
		offset = F_ALIGN_DOWN_POW2(offset - 8, 8);
		p->temp_reg_restore_frame_rel_offset[i] = offset;
	}
	//p->temp_reg_restore_rsp_rel_offset = f_make_slice_garbage<s32>(proc->ops.len, f_temp_alc());

	// find the live ranges
	{
		p->emitting = false;
		gen_bb(p, 0);
	}
	
	// emit
	{
		p->emitting = true;
		p->code_section_offset = (u32)p->module_gen->code_section.len;

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

		gen_bb(p, 0);
		p->code_section_end_offset = (u32)p->module_gen->code_section.len;
	}
	

	printf("---------------------------------\n");
}

void gmmc_x64_export_module(FILE* output_file, gmmcModule* m) {
	coffDesc coff_desc = {};

	fArray(coffSection) sections = f_array_make<coffSection>(m->allocator);
	fArray(coffSymbol) symbols = f_array_make<coffSymbol>(m->allocator);

	ModuleGen gen = {};
	gen.code_section = f_array_make<u8>(m->allocator);
	gen.procs = f_make_slice<ProcGen>(m->procs.len, {}, m->allocator);

	// compile procedures
	for (uint i = 0; i < m->procs.len; i++) {
		gmmcProc* proc = m->procs[i];
		gmmc_gen_proc(&gen, &gen.procs[i], proc);
	}

	for (uint i = 0; i < m->procs.len; i++) {
		gmmcProc* proc = m->procs[i];
		
		coffSymbol sym = {};
		sym.name = proc->sym.name;
		sym.type = 0x20;
		sym.section_number = SectionNum_Code;
		
		sym.value = gen.procs[i].code_section_offset; // offset into the section
		sym.external = true;
		f_array_push(&symbols, sym);
	}
	
	{
		coffSection sect = {};
		sect.name = F_LIT(".code");
		sect.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		sect.data = gen.code_section.slice;
		//sect.relocations = text_relocs.data;
		//sect.relocations_count = (int)text_relocs.len;
		f_array_push(&sections, sect);
	}

	coff_desc.sections = sections.data;
	coff_desc.sections_count = (u32)sections.len;
	coff_desc.symbols = symbols.data;
	coff_desc.symbols_count = (u32)symbols.len;

	coff_create([](fString result, void* userptr) {
		fwrite(result.data, result.len, 1, (FILE*)userptr);
		}, output_file, &coff_desc);
}


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

