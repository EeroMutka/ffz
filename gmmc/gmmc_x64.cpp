#if 0
static void gen_bb(gmmcBasicBlock* bb) {
	if (bb->gen.code_section_offset == F_U32_MAX) { // not been built yet?
		bb->gen.code_section_offset = (u32)bb->mod->code_section.len;

		for (uint i = 0; i < bb->ops.len; i++) {
			gmmcOp* op = &bb->ops[i];

			switch (op->kind) {

			case gmmcOpKind_debugbreak: {
				f_array_push(&bb->mod->code_section, (u8)0xCC); // int3
			} break;

			case gmmcOpKind_ret: {
				if (op->operands[0] != GMMC_REG_NONE) {
					F_BP;
				}

				ZydisEncoderRequest req = { ZYDIS_MACHINE_MODE_LONG_64 };
				req.mnemonic = ZYDIS_MNEMONIC_RET;

				u8 instr[ZYDIS_MAX_INSTRUCTION_LENGTH];
				uint instr_len = sizeof(instr);
				bool ok = ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, instr, &instr_len));
				VALIDATE(ok);

				f_array_push_slice(&bb->mod->code_section, { instr, instr_len });
			} break;

			default: F_BP;
			}

		}
	}

	VALIDATE(bb->ops.len > 0 && gmmc_op_is_terminating(bb->ops[bb->ops.len - 1].kind));
}

GMMC_API void gmmc_proc_compile(gmmcProc* proc) {
	gen_bb(proc->entry_bb);
}
#endif