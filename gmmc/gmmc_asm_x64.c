#include "src/foundation/foundation.h"

#define gmmcString fString
#include "gmmc.h"

#include "Zydis/Zydis.h"

//#include <stdio.h> // for fopen

#define VALIDATE(x) f_assert(x)

typedef u16 RegSize;
typedef struct gmmcAsmProc gmmcAsmProc;

typedef struct gmmcAsmGlobal {
	gmmcGlobal* global; // hmm... why do we store this? its accessible by the index
	u32 offset;
} gmmcAsmGlobal;

typedef struct Section {
	fArray(u8) data;
	fArray(gmmcRelocation) relocs;
} Section;

typedef struct gmmcAsmModule {
	Section sections[gmmcSection_COUNT];
	fSlice(gmmcAsmProc) procs;
	fSlice(gmmcAsmGlobal) globals;
} gmmcAsmModule;

typedef enum RegisterSet {
	RegisterSet_Normal,
	RegisterSet_XMM,
	RegisterSet_COUNT,
} RegisterSet;

typedef enum GPR {
	GPR_NONE,
	
	// RegisterSet = 0
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

	// floating point registers
	// RegisterSet = 1
	GPR_XMM0,
	GPR_XMM1,
	GPR_XMM2,
	GPR_XMM3,
	GPR_XMM4,
	GPR_XMM5,
	GPR_XMM6,
	GPR_XMM7,
	GPR_XMM8,
	GPR_XMM9,
	GPR_XMM10,
	GPR_XMM11,
	GPR_XMM12,
	GPR_XMM13,
	GPR_XMM14,
	GPR_XMM15,

	GPR_COUNT,
} GPR;

typedef enum Stage {
	// The idea is to do generation in 3 stages:
	
	// 1st stage:
	// Compute `last_use_time`s and `largest_call_shadow_space_size`
	// The reason we need this stage is because in order to be able to select registers, we need to know when each registers livespan ends.
	Stage_Initial,
	
	// 2nd stage:
	// Figure out which registers to allocate for each op.
	// The reason we need this stage is because when emitting the procedure entry/exit points, we need to know
	// which callee-saved work registers are used throughout the procedure so that we can preserve them for the caller with push/pop.
	Stage_SelectRegs,
	
	// 3rd stage:
	// Emit the actual instructions.
	Stage_Emit,
} Stage;

typedef struct ProcGenSelectRegs {
	u32 work_registers_used_count[RegisterSet_COUNT];
	
	// this is cleared to GMMC_OP_IDX_INVALID when beginning to generate a new basic block
	gmmcOpIdx work_reg_taken_by_op[GPR_COUNT];
	
	fSlice(GPR) ops_currently_in_register; // GPR_NONE means it's on the stack / not inside a register
	
	fArray(GPR) debug_allocate_gpr_order;
} ProcGenSelectRegs;

typedef struct ProcGen {
	gmmcAsmModule* module;
	fOpt(fWriter*) console;
	gmmcProc* proc;
	gmmcAsmProc* result;

	// -- stages -------------

	Stage stage;
	gmmcOpIdx current_op;

	// U32_MAX means 'unvisited'.
	// During the first and the second stage, the BB offset is set to 0 when visited.
	// During the _Emit stage, the BB offset is set to the offset in the code section when visited.
	fSlice(u32) bbs_offset;

	// These are generated only in the _Initial stage
	fSlice(gmmcOpIdx) ops_last_use_time;
	u32 largest_call_shadow_space_size;

	// These are generated only in the _SelectRegs stage
	fSlice(u32) ops_spill_offset_frame_rel; // value of '0' means "op is never spilled"

	// Register selection is reset and re-simulated for both _SelectRegs and _Emit stages
	ProcGenSelectRegs rsel;

	// available in the _Emit stage
	fSlice(u32) ops_float_imm_section_rel_offset;
	u32 callee_saved_reg_offset_frame_rel[GPR_COUNT]; // value of '0' means "work register is not used"

	// available in the _Emit stage
	ProcGenSelectRegs cached_rsel;
} ProcGen;

typedef struct gmmcAsmProc {
	fSlice(s32) local_frame_rel_offset; // [gmmcLocalIdx]

	// offset that is added to RSP when entering the procedure;
	// always negative as the stack grows downwards
	s32 rsp_offset;

	// Filled in the _Emit stage
	fSlice(u32) ops_instruction_offset; // [gmmcOpIdx]

	//u32 stack_frame_size;
	u32 code_section_start_offset;
	u32 code_section_end_offset;
	u32 prolog_size;
} gmmcAsmProc;



// General-purpose registers. Prefer non-volatile registers for now
// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170
const static GPR int_work_registers[] = {
	GPR_12,
	GPR_13,
	GPR_14,
	GPR_15,
	//GPR_DI,
	//GPR_SI,
	//GPR_BX,
	//GPR_BP,
};

// These are also non-volatile registers
const static GPR float_work_registers[] = {
	GPR_XMM6,
	GPR_XMM7,
	GPR_XMM8,
	GPR_XMM9,
	//GPR_XMM10,
	//GPR_XMM11,
	//GPR_XMM12,
	//GPR_XMM13,
	//GPR_XMM14,
	//GPR_XMM15,
};

typedef enum ExtendBits {
	ExtendBits_None,
	ExtendBits_Zero,
	ExtendBits_Sign,
} ExtendBits;

GMMC_API gmmcString gmmc_asm_get_section_data(gmmcAsmModule* m, gmmcSection section) {
	return (gmmcString) { m->sections[section].data.data, m->sections[section].data.len };
}

GMMC_API void gmmc_asm_get_section_relocations(gmmcAsmModule* m, gmmcSection section, fSlice(gmmcRelocation)* out_relocs) {
	*out_relocs = m->sections[section].relocs.slice;
}


// https://graphics.stanford.edu/~seander/bithacks.html#VariableSignExtend
// NOTE: high bits of 'x' must be set to 0
static u64 sign_extend(u64 x, u32 num_bits) {
	u64 m = 1llu << (num_bits - 1);
	return (x ^ m) - m;
}

static uint get_zydis_instruction_len(const ZydisEncoderRequest* req) {
	u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
	uint instr_len = sizeof(instr);
	bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(req, instr, &instr_len));
	VALIDATE(ok);
	return instr_len;
}

static void emit(ProcGen* p, const ZydisEncoderRequest* req, const char* comment) {
	f_assert(p->stage == Stage_Emit);
	
	u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
	uint instr_len = sizeof(instr);
	bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(req, instr, &instr_len));
	VALIDATE(ok);
	
	Section* code_section = &p->module->sections[gmmcSection_Code];
	f_array_push_n_raw(&code_section->data, instr, instr_len, 1);

	// print disassembly
	if (p->console) {
		uint sect_rel_offset = code_section->data.len - instr_len;
		uint proc_rel_offset = sect_rel_offset - p->result->code_section_start_offset;

		ZydisDisassembledInstruction instruction;
		if (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, proc_rel_offset, instr, instr_len, &instruction))) {
			f_print(p->console, "(~u32)  0x~x32:   ~c~c\n", p->current_op, proc_rel_offset, instruction.text, comment);
		}
	}
}


static void reserve_stack_space(s32* rsp_offset, u32 amount, u32 align) {
	// NOTE: the stack is misaligned by 8 bytes when entering a procedure.
	// That's why we need to do the + 8 - 8 shuffle
	*rsp_offset = F_ALIGN_DOWN_POW2(*rsp_offset - (s32)amount + 8, (s32)align) - 8;
}

static RegisterSet get_register_set_from_type(gmmcType type) {
	return gmmc_type_is_float(type) ? RegisterSet_XMM : RegisterSet_Normal;
}

static RegisterSet get_register_set(GPR reg) {
	return reg >= GPR_XMM0 && reg <= GPR_XMM15 ? RegisterSet_XMM : RegisterSet_Normal;
}

static fSlice(GPR) get_work_registers(RegisterSet reg_set) {
	switch (reg_set) {
	case RegisterSet_Normal: return (fSliceRaw){(void*)&int_work_registers, F_LEN(int_work_registers)};
	case RegisterSet_XMM: return (fSliceRaw){(void*)&float_work_registers, F_LEN(float_work_registers)};
	}
	f_trap(); return (fSliceRaw){0};
}

// `size` is ignored for XMM registers
static ZydisRegister get_x64_reg(GPR reg, RegSize size) {
	if (get_register_set(reg) == RegisterSet_XMM) {
		return (ZydisRegister)(ZYDIS_REGISTER_XMM0 + (reg - GPR_XMM0));
	}
	else {
		const static ZydisRegister table[] = {
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

		u32 size_class_from_size[] = { 0, 1, 2, 0, 3, 0, 0, 0, 4 };
		u32 size_class = size_class_from_size[size];
		f_assert(size_class != 0);

		u32 reg_index = (u32)(reg - GPR_AX);
		return table[reg_index + 16 * (size_class - 1)];
	}
}

// `size` is ignored for XMM registers
static ZydisEncoderOperand make_reg_operand(GPR gpr, RegSize size) {
	ZydisEncoderOperand operand = { ZYDIS_OPERAND_TYPE_REGISTER };
	operand.reg.value = get_x64_reg(gpr, size);
	return operand;
}

// TODO: get rid of this garbage
typedef struct LooseReg { gmmcOpIdx source_op; } LooseReg;

static void spill(ProcGen* p, gmmcOpIdx op_idx) {
	GPR reg = f_array_get(GPR, p->rsel.ops_currently_in_register, op_idx);
	f_assert(p->rsel.work_reg_taken_by_op[reg] == op_idx);

	gmmcOpData* op = f_array_get_ptr(gmmcOpData, p->proc->ops, op_idx);
	u32 size = gmmc_type_size(op->type);
	
	//if (op_idx == 22) f_trap();
	if (!gmmc_is_op_direct(p->proc, op_idx)) {
		// if computation is required to find out the value of the op, store it on the stack.
		// locals, immediates and addr_of_symbol don't need to be stored on the stack.

		if (p->stage == Stage_SelectRegs && f_array_get(u32, p->ops_spill_offset_frame_rel, op_idx) == 0) {
			reserve_stack_space(&p->result->rsp_offset, size, size);
			f_array_set(u32, p->ops_spill_offset_frame_rel, op_idx, p->result->rsp_offset);
		}

		if (p->stage == Stage_Emit) {
			f_assert(f_array_get(u32, p->ops_spill_offset_frame_rel, op_idx) != 0);

			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic =	op->type == gmmcType_f64 ? ZYDIS_MNEMONIC_MOVSD :
							op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_MOVSS :
								ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[0].mem.displacement = f_array_get(u32, p->ops_spill_offset_frame_rel, op_idx) - p->result->rsp_offset;
			req.operands[0].mem.size = size;
			req.operands[1] = make_reg_operand(reg, size);
			emit(p, &req, " ; spill the op value");
			int a = 50;
		}
	}
	f_array_set(GPR, p->rsel.ops_currently_in_register, op_idx, GPR_NONE);
	p->rsel.work_reg_taken_by_op[reg] = (gmmcOpIdx){ GMMC_OP_IDX_INVALID };
}

static GPR allocate_gpr(ProcGen* p, gmmcOpIdx for_op) {
	//if (for_op == 26) f_trap();
	//if (p->rsel.debug_allocate_gpr_order.len == 4) f_trap();
	
	GPR gpr = GPR_NONE;
	f_assert(p->stage > Stage_Initial);

	//F_HITS(_c, 51);

	gmmcType type = f_array_get(gmmcOpData, p->proc->ops, for_op).type;
	RegisterSet rset = get_register_set_from_type(type);
	fSlice(GPR) work_regs = get_work_registers(rset);

	for (u32 i = 0; i < p->rsel.work_registers_used_count[rset]; i++) {
		GPR work_reg = f_array_get(GPR, work_regs, i);
		gmmcOpIdx work_reg_owner = p->rsel.work_reg_taken_by_op[work_reg];
		
		if (work_reg_owner == GMMC_OP_IDX_INVALID) {
			// Register is in the open market
			gpr = work_reg;
			break;
		}
		
		if (p->current_op > f_array_get(gmmcOpIdx, p->ops_last_use_time, work_reg_owner)) {
			// `work_reg_owner` will never be used later
			f_array_set(GPR, p->rsel.ops_currently_in_register, work_reg_owner, GPR_NONE);
			gpr = work_reg;
			break;
		}
	}
		
	// Take a new register. If the registers are all in use, then loop through them and steal the one
	// used by the OP with the greatest `last_use_time`
	if (!gpr) {
		if (p->rsel.work_registers_used_count[rset] < work_regs.len) {
			u32 work_reg_idx = p->rsel.work_registers_used_count[rset]++;
			gpr = f_array_get(GPR, work_regs, work_reg_idx);
		}
		else {
			gmmcOpIdx greatest_last_use_time = GMMC_OP_IDX_INVALID;
			gmmcOpIdx victim = GMMC_OP_IDX_INVALID;
			
			for (uint i = 0; i < work_regs.len; i++) {
				GPR work_reg = f_array_get(GPR, work_regs, i);
				gmmcOpIdx potential_victim = p->rsel.work_reg_taken_by_op[work_reg];
				f_assert(f_array_get(GPR, p->rsel.ops_currently_in_register, potential_victim) == work_reg);
				
				if (potential_victim == p->current_op) {
					// The current op has this register locked as its result register, so let's not steal it
					continue;
				}

				gmmcOpIdx last_use_time = f_array_get(gmmcOpIdx, p->ops_last_use_time, potential_victim);
				if (greatest_last_use_time == GMMC_OP_IDX_INVALID || last_use_time > greatest_last_use_time) {
					greatest_last_use_time = last_use_time;
					
					victim = potential_victim;
					gpr = work_reg;
				}
			}
			
			spill(p, victim); // steal a register, spill the op value
		}
	}

	p->rsel.work_reg_taken_by_op[gpr] = for_op;
	f_array_set(GPR, p->rsel.ops_currently_in_register, for_op, gpr);

	{
		// Verify that the register allocation is deterministic across Stage_SelectRegs and Stage_Emit.
		// TODO: just use this array as a lookup directly to avoid having to do the same computation in the _Emit stage!!
		uint i = f_array_push(&p->rsel.debug_allocate_gpr_order, gpr);
		if (p->stage == Stage_Emit) {
			f_assert(f_array_get(GPR, p->cached_rsel.debug_allocate_gpr_order, i) == gpr);
		}
	}

	return gpr;
}

static void update_last_use_time(ProcGen* p, gmmcOpIdx op_idx) {
	if (p->stage == Stage_Initial) {
		gmmcOpIdx existing = f_array_get(gmmcOpIdx, p->ops_last_use_time, op_idx);
		
		gmmcOpIdx last_use_time = existing == GMMC_OP_IDX_INVALID || p->current_op > existing ? p->current_op : existing;
		f_array_set(gmmcOpIdx, p->ops_last_use_time, op_idx, last_use_time);
	}
}

static GPR allocate_op_result(ProcGen* p) {
	update_last_use_time(p, p->current_op);
	if (p->stage > Stage_Initial) {
		return allocate_gpr(p, p->current_op);
	}
	return GPR_NONE;
}

static void emit_mov_reg_to_reg(ProcGen* p, GPR to, GPR from, gmmcType type, ExtendBits extend/* = ExtendBits_None*/) {
	f_assert(p->stage == Stage_Emit);
	RegSize size = gmmc_type_size(type);
	
	if (gmmc_type_is_float(type)) {
		f_assert(extend == ExtendBits_None);

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = type == gmmcType_f64 ? ZYDIS_MNEMONIC_MOVSD : ZYDIS_MNEMONIC_MOVSS;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(to, size);
		req.operands[1] = make_reg_operand(from, size);
		emit(p, &req, "");
	}
	else {
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
			emit(p, &req, "");
		}
		else if (extend == ExtendBits_Sign && size <= 4) {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = size == 4 ? ZYDIS_MNEMONIC_MOVSXD : ZYDIS_MNEMONIC_MOVSX;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(to, 8);
			req.operands[1] = make_reg_operand(from, size);
			emit(p, &req, "");
		}
		else {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(to, size);
			req.operands[1] = make_reg_operand(from, size);
			emit(p, &req, "");
		}
	}
}

static u32 section_push_data(Section* section, void* data, uint size, uint align) {
	f_array_resize_raw(&section->data, F_ALIGN_UP_POW2(section->data.len, align), &(u8){0}, 1);
	u32 offset = (u32)section->data.len;
	f_array_push_n_raw(&section->data, data, size, 1);
	return offset;
}

static GPR op_value_to_reg(ProcGen* p, gmmcOpIdx op_idx, GPR specify_reg/* = GPR_INVALID*/) {
	if (p->stage == Stage_Initial) return GPR_NONE;

	GPR result = f_array_get(GPR, p->rsel.ops_currently_in_register, op_idx);
	if (result) {
		if (specify_reg) {
			if (p->stage == Stage_Emit) {
				emit_mov_reg_to_reg(p, specify_reg, result, f_array_get(gmmcOpData, p->proc->ops, op_idx).type, ExtendBits_None);
			}
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

	if (p->stage == Stage_Emit) {
		gmmcOpData* op = f_array_get_ptr(gmmcOpData, p->proc->ops, op_idx);
		if (op->kind == gmmcOpKind_local) {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_LEA;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(result, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement =
				f_array_get(s32, p->result->local_frame_rel_offset, op->local_idx) - p->result->rsp_offset;
			req.operands[1].mem.size = 8;
			emit(p, &req, " ; address of local");
			int a = 50;
		}
		else if (op->kind == gmmcOpKind_addr_of_param) {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_LEA;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(result, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement = 8 + 8 * (u32)op->imm_bits - p->result->rsp_offset; // + 8 for return address :AddressOfParam
			req.operands[1].mem.size = 8;
			emit(p, &req, " ; address of param");
		}
		else if (op->kind == gmmcOpKind_addr_of_symbol) {
			
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(result, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.u = 0xfefefefefefefefe; // trick zydis to emit the full 64 bits for the immediate
			emit(p, &req, " ; address of symbol (relocation will be applied to imm)");

			Section* code_section = &p->module->sections[gmmcSection_Code];

			// The relocation will be applied to the encoded immediate operand
			u32 reloc_offset = (u32)code_section->data.len - 8;
			*(u64*)((u8*)code_section->data.data + reloc_offset) = 0; // get rid of the fefefefe

			gmmcRelocation reloc = {reloc_offset, op->symbol};
			f_array_push(&code_section->relocs, reloc);
		}
		else if (gmmc_is_op_direct(p->proc, op_idx)) {

			u32 size = gmmc_type_size(op->type);
			if (gmmc_type_is_float(op->type)) {
				// If this is a floating point immediate, we need to load it from memory, because
				// there are no floating point immediates in X64. Before emitting, we allocated
				// all float immediates into the code section and that way we can access them relative to RIP.
				
				s64 float_offset = (s64)f_array_get(u32, p->ops_float_imm_section_rel_offset, op_idx);

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = op->type == gmmcType_f64 ? ZYDIS_MNEMONIC_MOVSD : ZYDIS_MNEMONIC_MOVSS;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result, size);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = ZYDIS_REGISTER_RIP;
				req.operands[1].mem.size = size;
				
				// NOTE: when using RIP-relative memory operand, RIP refers to the beginning of the next instruction.
				// http://www.codegurus.be/Programming/riprelativeaddressing_en.htm

				s64 next_instruction_offset = (s64)p->module->sections[gmmcSection_Code].data.len + (s64)get_zydis_instruction_len(&req);
				req.operands[1].mem.displacement = float_offset - next_instruction_offset;
				
				emit(p, &req, " ; immediate float to reg");
			}
			else {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result, size);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
				req.operands[1].imm.u = sign_extend(op->imm_bits, size * 8); // zydis requires sign-extended immediates
				emit(p, &req, " ; immediate to reg");
			}
		}
		else {
			gmmcType type = op->type;
			RegSize size = gmmc_type_size(type);

			// load the spilled op value from stack
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic =	type == gmmcType_f64 ? ZYDIS_MNEMONIC_MOVSD :
							type == gmmcType_f32 ? ZYDIS_MNEMONIC_MOVSS :
								ZYDIS_MNEMONIC_MOV;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(result, size);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[1].mem.displacement = f_array_get(u32, p->ops_spill_offset_frame_rel, op_idx) - p->result->rsp_offset;
			req.operands[1].mem.size = size;
			emit(p, &req, " ; load spilled value");
		}
	}
	return result;
}

static GPR use_op_value(ProcGen* p, gmmcOpIdx op_idx, GPR specify_reg/* = GPR_INVALID*/) {
	update_last_use_time(p, op_idx);

	GPR result = op_value_to_reg(p, op_idx, specify_reg);
	return result;
}

static LooseReg use_op_value_loose(ProcGen* p, gmmcOpIdx op_idx) {
	LooseReg result = {0};
	update_last_use_time(p, op_idx);

	if (p->stage > Stage_Initial) {
		result.source_op = op_idx;
	}
	return result;
}


// retrieving computed data
GMMC_API u32 gmmc_asm_instruction_get_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx op) {
	VALIDATE(f_array_get(gmmcOpData, proc->ops, op).bb_idx != GMMC_BB_INDEX_NONE); // immediates do not get assigned an offset
	
	gmmcAsmProc* asm_proc = f_array_get_ptr(gmmcAsmProc, m->procs, proc->self_idx);
	return f_array_get(u32, asm_proc->ops_instruction_offset, op);
}

GMMC_API u32 gmmc_asm_proc_get_start_offset(gmmcAsmModule* m, gmmcProc* proc) {
	return f_array_get(gmmcAsmProc, m->procs, proc->self_idx).code_section_start_offset; }

GMMC_API u32 gmmc_asm_proc_get_end_offset(gmmcAsmModule* m, gmmcProc* proc) {
	return f_array_get(gmmcAsmProc, m->procs, proc->self_idx).code_section_end_offset; }

GMMC_API u32 gmmc_asm_proc_get_stack_frame_size(gmmcAsmModule* m, gmmcProc* proc) {
	return 0 - f_array_get(gmmcAsmProc, m->procs, proc->self_idx).rsp_offset; }

GMMC_API u32 gmmc_asm_proc_get_prolog_size(gmmcAsmModule* m, gmmcProc* proc) {
	return f_array_get(gmmcAsmProc, m->procs, proc->self_idx).prolog_size; }

GMMC_API u32 gmmc_asm_global_get_offset(gmmcAsmModule* m, gmmcGlobal* global) {
	return f_array_get(gmmcAsmGlobal, m->globals, global->self_idx).offset; }

GMMC_API s32 gmmc_asm_get_frame_rel_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx local_or_param) {
	gmmcOpData* op = f_array_get_ptr(gmmcOpData, proc->ops, local_or_param);
	gmmcAsmProc* asm_proc = f_array_get_ptr(gmmcAsmProc, m->procs, proc->self_idx);

	if (op->kind == gmmcOpKind_local) {
		u32 local_idx = op->local_idx;
		return f_array_get(u32, asm_proc->local_frame_rel_offset, local_idx);
	}
	else if (op->kind == gmmcOpKind_addr_of_param) {
		return 8 + 8*(u32)op->imm_bits; // :AddressOfParam
	}
	VALIDATE(false); return 0;
}

const static GPR ms_x64_param_normal_regs[4] = { GPR_CX, GPR_DX, GPR_8, GPR_9 };
const static GPR ms_x64_param_float_regs[4] = { GPR_XMM0, GPR_XMM1, GPR_XMM2, GPR_XMM3 };

static void gen_array_access(ProcGen* p, gmmcOpData* op) {
	GPR result_reg = allocate_op_result(p);
	GPR base_reg = use_op_value(p, op->operands[0], GPR_NONE);
	GPR index_reg = use_op_value(p, op->operands[1], GPR_NONE);

	if (p->stage == Stage_Emit) {
		// memory-based operand `scale` can only encode 1, 2, 4 or 8 in x64.
		bool can_encode_scale_directly = op->imm_bits == 1 || op->imm_bits == 2 || op->imm_bits == 4 || op->imm_bits == 8;
		
		if (!can_encode_scale_directly) {
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_IMUL;
			req.operand_count = 3;
			req.operands[0] = make_reg_operand(GPR_AX, 8);
			req.operands[1] = make_reg_operand(index_reg, 8);
			req.operands[2].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[2].imm.u = (u32)op->imm_bits;
			emit(p, &req, "");

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
		req.operands[1].mem.scale = can_encode_scale_directly ? (u8)op->imm_bits : 1;
		req.operands[1].mem.size = 8;
		emit(p, &req, " ; array access");
	}
}

static void gen_comparison(ProcGen* p, gmmcOpData* op) {
	GPR result_value = allocate_op_result(p);
	GPR a = use_op_value(p, op->operands[0], GPR_NONE);
	GPR b = use_op_value(p, op->operands[1], GPR_NONE);
	
	if (p->stage == Stage_Emit) {
		{
			RegSize size = gmmc_type_size(gmmc_get_op_type(p->proc, op->operands[0]));
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_CMP;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(a, size);
			req.operands[1] = make_reg_operand(b, size);
			emit(p, &req, "");
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
			emit(p, &req, "");
		}
	}
}

static void gen_op_basic_2(ProcGen* p, gmmcOpData* op, ZydisMnemonic mnemonic) {
	GPR result_value = allocate_op_result(p);
	LooseReg a = use_op_value_loose(p, op->operands[0]);
	GPR b = use_op_value(p, op->operands[1], GPR_NONE);

	if (p->stage == Stage_Emit) {
		op_value_to_reg(p, a.source_op, result_value); // ADD instruction overwrites the first operand with the result

		RegSize size = gmmc_type_size(op->type);
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = mnemonic;
		req.operand_count = 2;
		req.operands[0] = make_reg_operand(result_value, size);
		req.operands[1] = make_reg_operand(b, size);
		emit(p, &req, "");
	}
}

static void emit_mov_imm_to_reg(ProcGen* p, GPR reg, u64 imm) {
	ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
	req.mnemonic = ZYDIS_MNEMONIC_MOV;
	req.operand_count = 2;
	req.operands[0] = make_reg_operand(reg, 8);
	req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
	req.operands[1].imm.u = imm;
	emit(p, &req, "");
}

static void gen_div_or_mod(ProcGen* p, gmmcOpData* op, GPR take_result_from) {
	GPR result_value = allocate_op_result(p);

	use_op_value(p, op->operands[0], GPR_AX); // dividend
	GPR divisor = use_op_value(p, op->operands[1], GPR_NONE);

	if (p->stage == Stage_Emit) {
		//op->is_signed
		RegSize size = gmmc_type_size(op->type);
		
		// if the size is 1 or 2, sign/zero extend the dividend and divisor into 64 bits
		if (size <= 2) {
			emit_mov_reg_to_reg(p, GPR_AX, GPR_AX, op->type, op->is_signed ? ExtendBits_Sign : ExtendBits_Zero);
			emit_mov_reg_to_reg(p, divisor, divisor, op->type, op->is_signed ? ExtendBits_Sign : ExtendBits_Zero);
		}

		if (op->is_signed) {
			// sign-extend the dividend in RAX into RDX
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_CQO;
			emit(p, &req, "");
		}
		else {
			emit_mov_imm_to_reg(p, GPR_DX, 0);
		}

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = op->is_signed ? ZYDIS_MNEMONIC_IDIV : ZYDIS_MNEMONIC_DIV;
		req.operand_count = 1;
		req.operands[0] = make_reg_operand(divisor, size);
		emit(p, &req, "");

		emit_mov_reg_to_reg(p, result_value, take_result_from, op->type, ExtendBits_None);
	}
}

static void gen_return(ProcGen* p, gmmcOpData* op) {
	LooseReg value_reg = {0};
	if (op->operands[0] != GMMC_OP_IDX_INVALID) value_reg = use_op_value_loose(p, op->operands[0]);

	if (p->stage == Stage_Emit) {

		if (op->operands[0] != GMMC_OP_IDX_INVALID) {
			// move the return value to RAX (or XMM0 if float)
			gmmcType type = gmmc_get_op_type(p->proc, value_reg.source_op);
			op_value_to_reg(p, value_reg.source_op, gmmc_type_is_float(type) ? GPR_XMM0 : GPR_AX);
		}

		for (uint rset = 0; rset < RegisterSet_COUNT; rset++) {
			fSlice(GPR) work_regs = get_work_registers((RegisterSet)rset);

			for (u32 i = 0; i < p->cached_rsel.work_registers_used_count[rset]; i++) {
				GPR reg = f_array_get(GPR, work_regs, i);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = rset == RegisterSet_XMM ? ZYDIS_MNEMONIC_MOVAPS : ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(reg, 8);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = ZYDIS_REGISTER_RSP;
				req.operands[1].mem.displacement = p->callee_saved_reg_offset_frame_rel[reg] - p->result->rsp_offset;
				req.operands[1].mem.size = rset == RegisterSet_XMM ? 16 : 8;
				emit(p, &req, " ; restore callee-saved register");
			}
		}

		// restore stack-frame
		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_ADD;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(GPR_SP, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.s = 0 - p->result->rsp_offset;
			emit(p, &req, " ; pop stack frame");
		}
		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_RET;
		emit(p, &req, "");
	}
}


static void gen_call(ProcGen* p, gmmcOpData* op) {

	for (u32 i = (u32)op->call.arguments.len - 1; i < op->call.arguments.len; i--) {
		gmmcOpIdx arg_op_idx = f_array_get(gmmcOpIdx, op->call.arguments, i);
		LooseReg arg = use_op_value_loose(p, arg_op_idx);
		bool is_float = gmmc_type_is_float(gmmc_get_op_type(p->proc, arg_op_idx));

		if (i < 4) {
			op_value_to_reg(p, arg.source_op, is_float ? ms_x64_param_float_regs[i] : ms_x64_param_normal_regs[i]);
		}
		else {
			GPR arg_reg = op_value_to_reg(p, arg.source_op, GPR_NONE);
			
			// the stack arguments are always 64 bits, this applies to floats/doubles too.

			if (p->stage == Stage_Emit) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = is_float ? ZYDIS_MNEMONIC_MOVSD : ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY; 
				req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
				req.operands[0].mem.displacement = i * 8;
				req.operands[0].mem.size = 8;
				req.operands[1] = make_reg_operand(arg_reg, 8);
				emit(p, &req, "");
			}
		}
	}

	if (p->stage == Stage_Initial) {
		// https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170

		u32 shadow_space_size = F_MAX((u32)op->call.arguments.len, 4) * 8;
		p->largest_call_shadow_space_size = F_MAX(p->largest_call_shadow_space_size, shadow_space_size);
	}

	GPR result_reg = GPR_NONE;
	if (op->type) {
		// Procedure returns a value!
		result_reg = allocate_op_result(p);
	}

	// NOTE: we must do `use_op_value` on the call target AFTER we've pushed the parameters on the stack,
	// because pushing the parameters might require the use of work registers that could invalidate this
	GPR proc_addr_reg = use_op_value(p, op->call.target, GPR_NONE);

	if (p->stage == Stage_Emit) {
		// hmm... the call target will not be in a register anymore
		f_assert(f_array_get(GPR, p->rsel.ops_currently_in_register, op->call.target) == proc_addr_reg);

		ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
		req.mnemonic = ZYDIS_MNEMONIC_CALL;
		req.operand_count = 1;
		req.operands[0] = make_reg_operand(proc_addr_reg, 8);
		emit(p, &req, "");

		if (op->type) {
			// save the return value
			emit_mov_reg_to_reg(p, result_reg, gmmc_type_is_float(op->type) ? GPR_XMM0 : GPR_AX, op->type, ExtendBits_None);
		}
	}
}

static u32 gen_bb(ProcGen* p, gmmcBasicBlockIdx bb_idx) {
	gmmcBasicBlock* bb = f_array_get(gmmcBasicBlock*, p->proc->basic_blocks, bb_idx);

	u32 existing_offset = f_array_get(u32, p->bbs_offset, bb_idx);
	if (existing_offset != F_U32_MAX) return existing_offset; // already visited

	if (p->stage > Stage_Initial) {
		//F_HITS(__c, 2);
		//F_HITS(__c2, 11);
		// Clear out the state of work-registers, as this is a fresh basic block
		for (uint i = 0; i < GPR_COUNT; i++) {
			gmmcOpIdx taken_by_op = p->rsel.work_reg_taken_by_op[i];
			if (taken_by_op != GMMC_OP_IDX_INVALID) {
				p->rsel.work_reg_taken_by_op[i] = GMMC_OP_IDX_INVALID;
				f_array_set(GPR, p->rsel.ops_currently_in_register, taken_by_op, GPR_NONE);
			}
		}

#ifdef _DEBUG
		for (uint i = 0; i < p->rsel.ops_currently_in_register.len; i++) {
			f_assert(f_array_get(GPR, p->rsel.ops_currently_in_register, i) == GPR_NONE);
		}
#endif
	}

	u32 bb_offset = p->stage == Stage_Emit ? (u32)p->module->sections[gmmcSection_Code].data.len : 0;
	f_array_set(u32, p->bbs_offset, bb_idx, bb_offset);

	Section* code_section = &p->module->sections[gmmcSection_Code];

	for (uint i = 0; i < bb->ops.len; i++) {
		p->current_op = f_array_get(gmmcOpIdx, bb->ops, i);

		gmmcOpData* op = f_array_get_ptr(gmmcOpData, p->proc->ops, p->current_op);

		if (p->stage == Stage_Emit) {
			f_array_set(u32, p->result->ops_instruction_offset, p->current_op, (u32)p->module->sections[gmmcSection_Code].data.len);
		}

		switch (op->kind) {
		
		case gmmcOpKind_comment: {
			if (p->console && p->stage == Stage_Emit) {
				if (op->comment.len > 0) {
					fSlice(fRangeUint) lines;
					f_str_split_i(op->comment, '\n', f_temp_alc(), &lines);
					
					for (uint i = 0; i < lines.len; i++) {
						fRangeUint line_range = f_array_get(fRangeUint, lines, i);
						fString line = f_str_slice(op->comment, line_range.lo, line_range.hi);
						f_print(p->console, "; ~s\n", line);
					}
				}
				else {
					f_print(p->console, "\n");
				}
			}
		} break;

		case gmmcOpKind_vcall: { gen_call(p, op); } break;
		case gmmcOpKind_return: { gen_return(p, op); } break;

		case gmmcOpKind_goto: {
			f_assert(i == bb->ops.len - 1); // must be the last op

			// if the destination block hasn't been generated yet, we can generate it directly after this op
			// and we don't even need a jump instruction.
			bool dst_block_has_been_generated;
			s32 offset_after_jmp;

			if (p->stage == Stage_Emit) {
				dst_block_has_been_generated = f_array_get(u32, p->bbs_offset, op->goto_.dst_bb) != F_U32_MAX;
				if (dst_block_has_been_generated) {
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_JMP;
					req.operand_count = 1;
					req.branch_width = ZYDIS_BRANCH_WIDTH_32;
					req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					req.operands[0].imm.u = 0;
					emit(p, &req, " ; goto (target address is to be patched)");
					offset_after_jmp = (s32)code_section->data.len;
				}
			}

			u32 dst_bb_offset = gen_bb(p, op->goto_.dst_bb);

			if (p->stage == Stage_Emit) {
				if (dst_block_has_been_generated) {
					*(s32*)((u8*)code_section->data.data + offset_after_jmp - 4) = (s32)dst_bb_offset - (s32)offset_after_jmp;
				}
			}
		} break;

		case gmmcOpKind_if: {
			f_assert(i == bb->ops.len - 1); // must be the last op
			GPR condition_reg = use_op_value(p, op->if_.condition, GPR_NONE);
			
			// branches are expected to be 'false'

			if (p->stage == Stage_Emit) {
				// ...we're doing a bunch of unnecessary CMPs
				{
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_CMP;
					req.operand_count = 2;
					req.operands[0] = make_reg_operand(condition_reg, 1);
					req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					emit(p, &req, "");
				}
				
				// jump to the 'true' block if the condition is true, otherwise continue execution with hopefully no jump

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_JNZ;
				req.operand_count = 1;
				req.branch_width = ZYDIS_BRANCH_WIDTH_32;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
				req.operands[0].imm.u = 0;
				emit(p, &req, " ; if true (target address is to be patched)");
			}

			u32 offset_after_cond_jmp = (u32)code_section->data.len;

			u32 false_bb_offset = gen_bb(p, op->if_.false_bb);
			
			if (p->stage == Stage_Emit) {
				if (offset_after_cond_jmp != false_bb_offset) {
					ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
					req.mnemonic = ZYDIS_MNEMONIC_JMP;
					req.operand_count = 1;
					req.branch_width = ZYDIS_BRANCH_WIDTH_32;
					req.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
					req.operands[0].imm.u = 0;
					emit(p, &req, " ; jump to false block (target address is to be patched)");

					s32 offset_after_jmp = (s32)code_section->data.len;
					*(s32*)((u8*)code_section->data.data + offset_after_jmp - 4) = (s32)false_bb_offset - (s32)offset_after_jmp;
				}
			}

			u32 true_bb_offset = gen_bb(p, op->if_.true_bb);
			
			if (p->stage == Stage_Emit) {
				*(s32*)((u8*)code_section->data.data + offset_after_cond_jmp - 4) = (s32)true_bb_offset - (s32)offset_after_cond_jmp;
			}
		} break;

		case gmmcOpKind_float2float: {
			GPR result_reg = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0], GPR_NONE);

			if (p->stage == Stage_Emit) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_CVTSD2SS : ZYDIS_MNEMONIC_CVTSS2SD;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, 0);
				req.operands[1] = make_reg_operand(src_reg, 0);
				emit(p, &req, "");
			}
		} break;

		case gmmcOpKind_int2float: {
			GPR result_reg = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0], GPR_NONE);

			if (p->stage == Stage_Emit) {
				gmmcType src_type = gmmc_get_op_type(p->proc, op->operands[0]);

				// if the size is 1 or 2, sign/zero extend the input into 64 bits
				if (gmmc_type_size(src_type) <= 2) {
					emit_mov_reg_to_reg(p, src_reg, src_reg, src_type, op->is_signed ? ExtendBits_Sign : ExtendBits_Zero);
				}

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_CVTSI2SS : ZYDIS_MNEMONIC_CVTSI2SD;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, 0);
				req.operands[1] = make_reg_operand(src_reg, src_type == gmmcType_i64 ? 8 : 4);
				emit(p, &req, "");
			}
		} break;

		case gmmcOpKind_float2int: {
			GPR result_reg = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0], GPR_NONE);

			if (p->stage == Stage_Emit) {
				gmmcType src_type = gmmc_get_op_type(p->proc, op->operands[0]);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = src_type == gmmcType_f32 ? ZYDIS_MNEMONIC_CVTTSS2SI : ZYDIS_MNEMONIC_CVTTSD2SI; // !!! NOTE !!! it is CVTTS*2SI, not CVTS*2SI
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, op->type == gmmcType_i64 ? 8 : 4);
				req.operands[1] = make_reg_operand(src_reg, 4);
				emit(p, &req, "");
			}
		} break;

		case gmmcOpKind_store: {
			GPR dst_reg = use_op_value(p, op->operands[0], GPR_NONE);
			GPR value_reg = use_op_value(p, op->operands[1], GPR_NONE);
				
			if (p->stage == Stage_Emit) {
				gmmcType type = gmmc_get_op_type(p->proc, op->operands[1]);
				//if (type == gmmcType_f32) {
				//}
				RegSize size = gmmc_type_size(type);

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic =	type == gmmcType_f64 ? ZYDIS_MNEMONIC_MOVSD :
								type == gmmcType_f32 ? ZYDIS_MNEMONIC_MOVSS :
									ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = get_x64_reg(dst_reg, 8);
				req.operands[0].mem.size = size;
				req.operands[1] = make_reg_operand(value_reg, size);
				emit(p, &req, " ; store");
				int a = 50;
			}
		} break;

		case gmmcOpKind_load: {
			GPR result_reg = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0], GPR_NONE);

			if (p->stage == Stage_Emit) {
				RegSize size = gmmc_type_size(op->type);
				
				// mem -> reg
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic =	op->type == gmmcType_f64 ? ZYDIS_MNEMONIC_MOVSD :
								op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_MOVSS :
									ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, size);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = get_x64_reg(src_reg, 8);
				req.operands[1].mem.size = size;
				emit(p, &req, " ; load");
			}
		} break;

		case gmmcOpKind_int2ptr: // fallthrough
		case gmmcOpKind_ptr2int: // fallthrough
		case gmmcOpKind_trunc:{
			// do nothing, just pass the value through
			GPR result_value = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			op_value_to_reg(p, a.source_op, result_value);
		} break;

		case gmmcOpKind_sxt: // fallthrough
		case gmmcOpKind_zxt: {
			// our general purpose registers may contain garbage. i.e. when you do an 8-bit load / mov, it won't do
			// anything to the high bits.

			GPR result_value = allocate_op_result(p);
			GPR src_reg = use_op_value(p, op->operands[0], GPR_NONE);
			if (p->stage == Stage_Emit) {
				gmmcType src_type = gmmc_get_op_type(p->proc, op->operands[0]);
				emit_mov_reg_to_reg(p, result_value, src_reg, src_type, gmmcOpKind_sxt ? ExtendBits_Sign : ExtendBits_Zero);
			}
		} break;

		case gmmcOpKind_memset: {
			use_op_value(p, op->operands[0], GPR_DI);
			use_op_value(p, op->operands[1], GPR_AX);
			use_op_value(p, op->operands[2], GPR_CX);

			if (p->stage == Stage_Emit) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_STOSB;
				req.prefixes = ZYDIS_ATTRIB_HAS_REP;
				emit(p, &req, " ; memset");
			}
		} break;

		case gmmcOpKind_memcpy: {
			// NOTE: the direction flag is always cleared to 0, as specified in the calling convention:
			// "On function exit and on function entry to C Runtime Library calls and Windows system calls,
			// the direction flag in the CPU flags register is expected to be cleared."
			// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170

			use_op_value(p, op->operands[0], GPR_DI);
			use_op_value(p, op->operands[1], GPR_SI);
			use_op_value(p, op->operands[2], GPR_CX);
			
			if (p->stage == Stage_Emit) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOVSB;
				req.prefixes = ZYDIS_ATTRIB_HAS_REP;
				emit(p, &req, " ; memcpy");
			}
		} break;

		case gmmcOpKind_member_access: {
			GPR result_reg = allocate_op_result(p);
			GPR base_reg = use_op_value(p, op->operands[0], GPR_NONE);
			
			if (p->stage == Stage_Emit) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_LEA;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, 8);
				req.operands[1].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[1].mem.base = get_x64_reg(base_reg, 8);
				req.operands[1].mem.displacement = op->imm_bits;
				req.operands[1].mem.size = 8;
				emit(p, &req, " ; member access");
			}
		} break;

		case gmmcOpKind_array_access: { gen_array_access(p, op); } break;

		case gmmcOpKind_eq: { gen_comparison(p, op); } break;
		case gmmcOpKind_ne: { gen_comparison(p, op); } break;
		case gmmcOpKind_lt: { gen_comparison(p, op); } break;
		case gmmcOpKind_le: { gen_comparison(p, op); } break;
		case gmmcOpKind_gt: { gen_comparison(p, op); } break;
		case gmmcOpKind_ge: { gen_comparison(p, op); } break;

		case gmmcOpKind_fadd: { gen_op_basic_2(p, op, op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_ADDSS : ZYDIS_MNEMONIC_ADDSD); } break;
		case gmmcOpKind_fsub: { gen_op_basic_2(p, op, op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_SUBSS : ZYDIS_MNEMONIC_SUBSD); } break;
		case gmmcOpKind_fmul: { gen_op_basic_2(p, op, op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_MULSS : ZYDIS_MNEMONIC_MULSD); } break;
		case gmmcOpKind_fdiv: { gen_op_basic_2(p, op, op->type == gmmcType_f32 ? ZYDIS_MNEMONIC_DIVSS : ZYDIS_MNEMONIC_DIVSD); } break;

		case gmmcOpKind_add: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_ADD); } break;
		case gmmcOpKind_sub: { gen_op_basic_2(p, op, ZYDIS_MNEMONIC_SUB); } break;
		case gmmcOpKind_mul: {
			// https://gpfault.net/posts/asm-tut-3.txt.html
			// NOTE: we can use IMUL always which is a bit more convenient than MUL, because
			// we're discarding the upper half of the result, and the lower half is identical to what you'd get from MUL.
			// This is a little bit magical to me.
			GPR result_reg = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			GPR b = use_op_value(p, op->operands[1], GPR_NONE);

			op_value_to_reg(p, a.source_op, result_reg);
			if (result_reg == GPR_12 && b == GPR_12) f_trap();

			if (p->stage == Stage_Emit) {
				RegSize size = gmmc_type_size(op->type);
				if (size < 4) size = 4; // Only ever do 32-bit or 64-bit multiplication.
				
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_IMUL;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_reg, size);
				req.operands[1] = make_reg_operand(b, size);
				emit(p, &req, "");
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
			
			op_value_to_reg(p, a.source_op, result_value);

			if (p->stage == Stage_Emit) {
				RegSize size = gmmc_type_size(op->type);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_NOT;
				req.operand_count = 1;
				req.operands[0] = make_reg_operand(result_value, size);
				emit(p, &req, "");
			}
		} break;
		
		case gmmcOpKind_shr: // fallthrough
		case gmmcOpKind_shl: {
			GPR result_value = allocate_op_result(p);
			LooseReg a = use_op_value_loose(p, op->operands[0]);
			use_op_value(p, op->operands[1], GPR_CX);
			
			op_value_to_reg(p, a.source_op, result_value); // the first operand is overwritten with the result

			if (p->stage == Stage_Emit) {
				RegSize size = gmmc_type_size(op->type);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = op->kind == gmmcOpKind_shr ? ZYDIS_MNEMONIC_SHR : ZYDIS_MNEMONIC_SHL;
				req.operand_count = 2;
				req.operands[0] = make_reg_operand(result_value, size);
				req.operands[1] = make_reg_operand(GPR_CX, 1);
				emit(p, &req, "");
			}
		} break;

		case gmmcOpKind_debugbreak: {
			if (p->stage == Stage_Emit) {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_INT3;
				emit(p, &req, "");
			}
		} break;

		default: f_trap();
		}
	}

	VALIDATE(bb->ops.len > 0);
	gmmcOpIdx last_op_idx = f_array_get(gmmcOpIdx, bb->ops, bb->ops.len - 1);
	VALIDATE(gmmc_is_op_terminating(gmmc_get_op_kind(p->proc, last_op_idx)));
	return bb_offset;
}

static void default_rsel(ProcGenSelectRegs* rsel, gmmcProc* proc) {
	*rsel = (ProcGenSelectRegs){0};
	rsel->debug_allocate_gpr_order = f_array_make(f_temp_alc());
	rsel->ops_currently_in_register = f_make_slice(GPR, proc->ops.len, (GPR){GPR_NONE}, f_temp_alc()); // @memory: we don't need to reallocate this slice on the second round of default_rsel()
	
	for (uint i = 0; i < F_LEN(rsel->work_reg_taken_by_op); i++) {
		rsel->work_reg_taken_by_op[i] = GMMC_OP_IDX_INVALID;
	}
}

GMMC_API void gmmc_gen_proc(gmmcAsmModule* module_gen, gmmcAsmProc* result, gmmcProc* proc) {
	fWriter* w = f_get_stdout();
	bool buffered = true;

	u8 console_buf[4096];
	fBufferedWriter console_writer;
	if (buffered) w = f_open_buffered_writer(w, console_buf, F_LEN(console_buf), &console_writer);
	
	f_print(w, "---- generating proc: '~s' ----\n", proc->sym.name);
	//gmmc_proc_print_c(stdout, proc);
	f_print(w, "---\n");
	
	ProcGen _p = {0}; ProcGen* p = &_p;
	//p->console = w;
	p->module = module_gen;
	p->proc = proc;
	p->result = result;

	result->local_frame_rel_offset = f_make_slice_undef(s32, proc->locals.len, f_temp_alc());
	result->ops_instruction_offset = f_make_slice(u32, proc->ops.len, (u32){F_U32_MAX}, f_temp_alc());

	p->ops_last_use_time = f_make_slice(gmmcOpIdx, proc->ops.len, (gmmcOpIdx){GMMC_OP_IDX_INVALID}, f_temp_alc());

	p->ops_float_imm_section_rel_offset = f_make_slice(u32, proc->ops.len, (u32){F_U32_MAX}, f_temp_alc());
	p->ops_spill_offset_frame_rel = f_make_slice(u32, proc->ops.len, (u32){0}, f_temp_alc());
	p->bbs_offset = f_make_slice_undef(u32, proc->basic_blocks.len, f_temp_alc());
	
	// When entering a procedure, the stack is always aligned to (16+8) bytes, because
	// before the CALL instruction it must be aligned to 16 bytes.

	result->rsp_offset = 0;
	for (uint i = 1; i < proc->locals.len; i++) {
		gmmcLocal local = f_array_get(gmmcLocal, proc->locals, i);
		f_assert(local.size > 0);

		reserve_stack_space(&result->rsp_offset, local.size, local.align);
		f_array_set(s32, result->local_frame_rel_offset, i, result->rsp_offset);
	}

	{
		p->stage = Stage_Initial;
		memset(p->bbs_offset.data, 0xff, p->bbs_offset.len * sizeof(u32));
		gen_bb(p, 0);
	}
	
	{
		p->stage = Stage_SelectRegs;
		default_rsel(&p->rsel, proc);
		memset(p->bbs_offset.data, 0xff, p->bbs_offset.len * sizeof(u32));
		gen_bb(p, 0);
	}
	
	// Now that we know which callee-saved work registers were used, let's reserve stack space so that we can save them

	for (uint rset = 0; rset < RegisterSet_COUNT; rset++) {
		fSlice(GPR) work_regs = get_work_registers((RegisterSet)rset);

		for (u32 i = 0; i < p->rsel.work_registers_used_count[rset]; i++) {
			GPR reg = f_array_get(GPR, work_regs, i);
			RegisterSet rset = get_register_set(reg);

			if (rset == RegisterSet_XMM) {
				reserve_stack_space(&result->rsp_offset, 16, 16);
			} else {
				reserve_stack_space(&result->rsp_offset, 8, 8);
			}
			p->callee_saved_reg_offset_frame_rel[reg] = result->rsp_offset;
		}
	}

	// Reserve shadow space for calls and align it to 16 bytes, as we're now done with the stack frame
	// and that is the required alignment for the stack pointer when calling any procedure.
	reserve_stack_space(&result->rsp_offset, p->largest_call_shadow_space_size, 16);

	{
		Section* code_section = &p->module->sections[gmmcSection_Code];
		
		p->stage = Stage_Emit;
		p->cached_rsel = p->rsel;
		default_rsel(&p->rsel, proc);
		memset(p->bbs_offset.data, 0xff, p->bbs_offset.len * sizeof(u32));
		
		for (uint i = 0; i < proc->ops.len; i++) {
			gmmcOpData* op = f_array_get_ptr(gmmcOpData, proc->ops, i);
			if (op->kind == gmmcOpKind_f64 || op->kind == gmmcOpKind_f32) {
				// We need to push float immediates into the code section and save their offsets.
				u32 size = gmmc_type_size(op->type);
				u32 offset = section_push_data(&p->module->sections[gmmcSection_Code], &op->imm_bits, size, size);
				f_array_set(u32, p->ops_float_imm_section_rel_offset, i, offset);
			}
		
		}
		result->code_section_start_offset = (u32)code_section->data.len;

		{
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = ZYDIS_MNEMONIC_SUB;
			req.operand_count = 2;
			req.operands[0] = make_reg_operand(GPR_SP, 8);
			req.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			req.operands[1].imm.s = 0 - result->rsp_offset;
			emit(p, &req, " ; push stack frame");
		}

		// Store the size of the initial sub RSP instruction.
		// Note that we're using MOVs to push/pop the callee-saved registers instead of the PUSH/POP instructions.
		// There's no real benefit to using either one, but if we did use PUSH/POP, we'd have to FIRST do the push/pops and THEN do the sub RSP for the
		// remaining stack frame, because we want to have free space at the end of the stack frame for subsequent calls / shadow space.
		// This would mean that `prolog_size` would have to include the push/pops as well, and I believe it'd complicate the unwind info
		// code on windows, where its required in order to get proper callstacks to show in the debugger. So the obvious choice is to just use MOV.
		result->prolog_size = (u32)code_section->data.len - result->code_section_start_offset;

		for (uint rset = 0; rset < RegisterSet_COUNT; rset++) {
			fSlice(GPR) work_regs = get_work_registers((RegisterSet)rset);

			for (u32 i = 0; i < p->cached_rsel.work_registers_used_count[rset]; i++) {
				GPR reg = f_array_get(GPR, work_regs, i);
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = rset == RegisterSet_XMM ? ZYDIS_MNEMONIC_MOVAPS : ZYDIS_MNEMONIC_MOV;
				req.operand_count = 2;
				req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
				req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
				req.operands[0].mem.displacement = p->callee_saved_reg_offset_frame_rel[reg] - p->result->rsp_offset;
				req.operands[0].mem.size = rset == RegisterSet_XMM ? 16 : 8;
				req.operands[1] = make_reg_operand(reg, 8);
				emit(p, &req, " ; store callee-saved register");
				int _ = 50;
			}
		}
		
		// immediately spill the register-parameters onto the stack, so that addr_of_param will work on them (and inspecting
		// their values in the debugger)

		uint register_params_n = F_MIN(4, p->proc->signature->params.len);
		for (uint i = 0; i < register_params_n; i++) {
			gmmcType type = f_array_get(gmmcType, p->proc->signature->params, i);
			bool is_float = gmmc_type_is_float(type);
			
			ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
			req.mnemonic = is_float ? ZYDIS_MNEMONIC_MOVSD : ZYDIS_MNEMONIC_MOV; // In the case of floating point registers, always push it as a double
			req.operand_count = 2;
			req.operands[0].type = ZYDIS_OPERAND_TYPE_MEMORY;
			req.operands[0].mem.base = ZYDIS_REGISTER_RSP;
			req.operands[0].mem.displacement = 8 + 8 * i - result->rsp_offset; // :AddressOfParam
			req.operands[0].mem.size = 8;
			req.operands[1] = make_reg_operand(is_float ? ms_x64_param_float_regs[i] : ms_x64_param_normal_regs[i], 8);
			emit(p, &req, "");
		}

		gen_bb(p, 0);

		result->code_section_end_offset = (u32)code_section->data.len;
	}
	
	f_print(w, "---------------------------------\n");
	if (buffered) f_flush_buffered_writer(&console_writer);
}

GMMC_API gmmcAsmModule* gmmc_asm_build_x64(gmmcModule* m) {
	gmmcAsmModule* gen = f_mem_clone((gmmcAsmModule){0}, m->allocator);

	for (uint i = 0; i < gmmcSection_COUNT; i++) {
		gen->sections[i].data = f_array_make(m->allocator);
		gen->sections[i].relocs = f_array_make(m->allocator);
	}

	gen->procs = f_make_slice(gmmcAsmProc, m->procs.len, (gmmcAsmProc){0}, m->allocator);
	
	// add globals
	gen->globals = f_make_slice_undef(gmmcAsmGlobal, m->globals.len, m->allocator);
	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = f_array_get(gmmcGlobal*, m->globals, i);

		Section* section = &gen->sections[global->section];
		gmmcAsmGlobal* asm_global = f_array_get_ptr(gmmcAsmGlobal, gen->globals, i);
		asm_global->global = global;
		asm_global->offset = section_push_data(section, global->data, global->size, global->align);
	}

	// compile procedures
	for (uint i = 0; i < m->procs.len; i++) {
		gmmc_gen_proc(gen, f_array_get_ptr(gmmcAsmProc, gen->procs, i), f_array_get(gmmcProc*, m->procs, i));
	}
	
	// add relocations now that all globals and procedures have an offset assigned to them

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = f_array_get(gmmcGlobal*, m->globals, i);
		Section* section = &gen->sections[global->section];

		for (uint j = 0; j < global->relocations.len; j++) {
			gmmcRelocation global_reloc = f_array_get(gmmcRelocation, global->relocations, j);

			gmmcRelocation reloc = global_reloc;
			reloc.offset += f_array_get(gmmcAsmGlobal, gen->globals, i).offset;
			f_array_push(&section->relocs, reloc);
		}
	}

	return gen;
}
