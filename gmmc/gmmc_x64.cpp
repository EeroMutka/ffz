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

//static void gen_immediate(gmmcBasicBlock* bb, gmmcOp* op) {
//	// so how will this all work?
//}

static void push_instruction(gmmcModule* mod, const ZydisEncoderRequest& req) {
	u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
	uint instr_len = sizeof(instr);
	bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, instr, &instr_len));
	VALIDATE(ok);

	f_array_push_n(&mod->code_section, { instr, instr_len });
}

struct ProcGen {
	gmmcProc* proc;
	fArray(s32) local_rsp_rel_offset;
};

ZydisEncoderOperand reg_to_x64_operand(ProcGen* p, gmmcOpIdx op_idx) {
	gmmcOpData op = p->proc->ops[op_idx];
	if (op.kind == gmmcOpKind_local) {
		ZydisEncoderOperand operand = {};
		operand.type = ZYDIS_OPERAND_TYPE_MEMORY;
		operand.mem.base = ZYDIS_REGISTER_RSP;
		operand.mem.displacement = p->local_rsp_rel_offset[op.local_idx];
		return operand;
	}
	else {
		// if it's an immediate... hmm.
		// yeah we need a mapping form reg -> Op
		F_BP;
	}
	return {};
	//gmmcLocal* local = p->local_from_reg[reg];
	//if (gmmc_reg_get_type
}

static void gen_bb(ProcGen* p, gmmcBasicBlock* bb) {
	if (bb->gen.code_section_offset == F_U32_MAX) { // not been built yet?
		bb->gen.code_section_offset = (u32)bb->mod->code_section.len;

		for (uint i = 0; i < bb->ops.len; i++) {
			gmmcOpData* op = &p->proc->ops[bb->ops[i]];

			switch (op->kind) {
			case gmmcOpKind_comment: break; // it'd be nice to include the comments in the printing

			case gmmcOpKind_store: {
				//ZydisRegister dst = reg_to_gpr(p, op->operands[0]);
				// op kind
				
				// need to get the first operand into a register
				//op->operands[0]
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_MOV;
				req.operands[0] = reg_to_x64_operand(p, op->operands[0]);
				req.operands[1] = reg_to_x64_operand(p, op->operands[1]);
				//push_instruction(bb->mod, req);
				F_BP;
			} break;

			// Immediates don't map to any actual instructions
			case gmmcOpKind_bool: break;
			case gmmcOpKind_i8: break;
			case gmmcOpKind_i16: break;
			case gmmcOpKind_i32: break;
			case gmmcOpKind_i64: break;
			case gmmcOpKind_i128: break;
			case gmmcOpKind_f32: break;
			case gmmcOpKind_f64: break;

			case gmmcOpKind_debugbreak: {
				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_INT3;
				push_instruction(bb->mod, req);
			} break;

			case gmmcOpKind_return: {
				if (op->operands[0] != GMMC_REG_NONE) {
					F_BP;
				}

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_RET;
				push_instruction(bb->mod, req);
			} break;

			default: F_BP;
			}
		}

		bb->gen.code_section_end_offset = (u32)bb->mod->code_section.len;

		// print disassembly
		{
			ZyanU64 runtime_address = 0;

			ZyanUSize offset = bb->gen.code_section_offset;
			ZydisDisassembledInstruction instruction;
			while (ZYAN_SUCCESS(ZydisDisassembleIntel(
				/* machine_mode:    */ ZYDIS_MACHINE_MODE_LONG_64,
				/* runtime_address: */ runtime_address,
				/* buffer:          */ bb->mod->code_section.data + offset,
				/* length:          */ bb->gen.code_section_end_offset - offset,
				/* instruction:     */ &instruction
			))) {
				printf("0x%llx:   %s\n", runtime_address, instruction.text);
				offset += instruction.info.length;
				runtime_address += instruction.info.length;
			}
		}
	}

	VALIDATE(bb->ops.len > 0);
	gmmcOpKind last_op_kind = gmmc_op_get_kind(p->proc, bb->ops[bb->ops.len - 1]);
	VALIDATE(gmmc_op_is_terminating(last_op_kind));
}


GMMC_API void gmmc_proc_compile(gmmcProc* proc) {
	printf("---- generating proc: '%.*s' ----\n", F_STRF(proc->sym.name));
	
	gmmc_proc_print(stdout, proc);
	printf("---\n");
	
	ProcGen proc_gen = {};
	proc_gen.proc = proc;
	gen_bb(&proc_gen, proc->entry_bb);
	printf("---------------------------------\n");
}

void gmmc_x64_export_module(FILE* output_file, gmmcModule* m) {
	coffDesc coff_desc = {};

	fArray(coffSection) sections = f_array_make<coffSection>(m->allocator);
	fArray(coffSymbol) symbols = f_array_make<coffSymbol>(m->allocator);

	// compile procedures
	for (uint i = 0; i < m->procs.len; i++) {
		gmmcProc* proc = m->procs[i];
		gmmc_proc_compile(proc);
	}


	for (uint i = 0; i < m->procs.len; i++) {
		gmmcProc* proc = m->procs[i];
		
		coffSymbol sym = {};
		sym.name = proc->sym.name;
		sym.type = 0x20;
		sym.section_number = SectionNum_Code;
		F_ASSERT(proc->entry_bb->gen.code_section_offset != F_U32_MAX);
		sym.value = proc->entry_bb->gen.code_section_offset; // offset into the section
		sym.external = true;
		f_array_push(&symbols, sym);
	}
	
	{
		coffSection sect = {};
		sect.name = F_LIT(".code");
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

