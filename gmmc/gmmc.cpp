#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"
#include "gmmc_coff.h"

#include <Zydis/Zydis.h>

#include <stdio.h>

#define VALIDATE(x) F_ASSERT(x)

typedef struct gmmcModule {
	fAllocator* allocator;
	
	fArray(u8) code_section;
	fArray(gmmcType) type_from_reg;

} gmmcModule;

typedef struct gmmcProcSignature {
	gmmcType return_type;
	fSlice(gmmcType) params;
} gmmcProcSignature;

GMMC_API gmmcProcSignature* gmmc_make_proc_signature(gmmcModule* m, gmmcType return_type,
	gmmcType* params, uint32_t params_count)
{
	gmmcProcSignature* s = f_mem_clone(gmmcProcSignature{}, m->allocator);
	s->return_type = return_type;
	s->params = {params, params_count};
	return s;
}

typedef struct gmmcProc {
	gmmcModule* mod;
	gmmcProcSignature* signature;
	gmmcString name;
	gmmcBasicBlock* entry_bb;
	
	u32 next_bb_index;

	//fSlice(u8) built_x64_instructions;
} gmmcProc;

const fString gmmcOpKind_to_string[] = {
	F_LIT_COMP("Invalid"),
	F_LIT_COMP("debugbreak"),
	F_LIT_COMP("ret"),
	F_LIT_COMP("if"),
};

typedef enum gmmcOpKind {
	gmmcOpKind_Invalid = 0,
	gmmcOpKind_debugbreak,

	// :gmmc_op_is_terminating
	gmmcOpKind_ret,
	gmmcOpKind_if,

	gmmcOpKind_COUNT,
} gmmcOpKind;

F_STATIC_ASSERT(gmmcOpKind_COUNT == F_LEN(gmmcOpKind_to_string));

inline bool gmmc_op_is_terminating(gmmcOpKind op) { return op >= gmmcOpKind_ret && op <= gmmcOpKind_if; }

typedef struct gmmcOp {
	gmmcOpKind kind;
	gmmcReg result;

	gmmcReg operands[2];
} gmmcOp;

typedef struct gmmcBasicBlock {
	gmmcModule* mod;
	gmmcProc* proc;
	u32 bb_index;

	fArray(gmmcOp) ops;

	struct {
		u32 code_section_offset = F_U32_MAX; // F_U32_MAX if not been built yet
	} gen;
} gmmcBasicBlock;


gmmcType reg_get_type(gmmcModule* m, gmmcReg reg) {
	return m->type_from_reg[reg];
}

GMMC_API void gmmc_op_return(gmmcBasicBlock* bb, gmmcReg value) {
	VALIDATE(reg_get_type(bb->mod, value) == bb->proc->signature->return_type);

	gmmcOp op = { gmmcOpKind_ret };
	op.operands[0] = value;
	f_array_push(&bb->ops, op);
}

GMMC_API void gmmc_op_debugbreak(gmmcBasicBlock* bb) {
	gmmcOp op = { gmmcOpKind_debugbreak };
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcBasicBlock* gmmc_make_basic_block(gmmcProc* proc) {
	gmmcBasicBlock* b = f_mem_clone(gmmcBasicBlock{}, proc->mod->allocator);
	b->mod = proc->mod;
	b->proc = proc;
	b->bb_index = proc->next_bb_index++;
	b->ops = f_array_make<gmmcOp>(proc->mod->allocator);
	return b;
}

GMMC_API gmmcProc* gmmc_make_proc(gmmcModule* m,
	gmmcProcSignature* signature,
	gmmcString name, gmmcBasicBlock** out_entry_bb)
{
	gmmcProc* proc = f_mem_clone(gmmcProc{}, m->allocator);
	proc->mod = m;
	proc->signature = signature;
	proc->name = name;
	proc->entry_bb = gmmc_make_basic_block(proc);
	*out_entry_bb = proc->entry_bb;
	return proc;
}

const fString gmmcType_to_string[] = {
	F_LIT("(none)"),
	F_LIT("bool"),
	F_LIT("ptr"),
	F_LIT("i8"),
	F_LIT("i16"),
	F_LIT("i32"),
	F_LIT("i64"),
	F_LIT("i128"),
};

GMMC_API gmmcModule* gmmc_init(fAllocator* allocator) {
	gmmcModule* m = f_mem_clone(gmmcModule{}, allocator);
	m->allocator = allocator;
	m->code_section = f_array_make<u8>(m->allocator);
	m->type_from_reg = f_array_make<gmmcType>(m->allocator);
	
	f_array_push(&m->type_from_reg, gmmcType_None); // for GMMG_REG_NONE
	return m;
}

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
				
				f_array_push_slice(&bb->mod->code_section, { instr, instr_len} );
			} break;

			default: F_BP;
			}

		}
	}
	
	VALIDATE(bb->ops.len > 0 && gmmc_op_is_terminating(bb->ops[bb->ops.len-1].kind));
}

GMMC_API void gmmc_proc_compile(gmmcProc* proc) {
	gen_bb(proc->entry_bb);
}

void print_bb(gmmcBasicBlock* bb) {
	printf("$b%u:\n", bb->bb_index);

	for (uint i = 0; i < bb->ops.len; i++) {
		gmmcOp* op = &bb->ops[i];
		printf("    ");
		
		//printf("
		//gmmcOpKind_to_string[op->kind].data
		
		switch (op->kind) {
		case gmmcOpKind_debugbreak: {
			printf("$debugbreak();\n");
		} break;

		case gmmcOpKind_ret: {
			if (op->operands[0] != GMMC_REG_NONE) {
				F_BP;
			}
			else printf("return;\n");
		} break;

		default: F_BP;
		}

	}
}

GMMC_API void gmmc_proc_print(gmmcProc* proc) {
	fAllocator* a = f_temp_push();
	
	printf("%s %s(", (proc->signature->return_type ?
		(const char*)gmmcType_to_string[proc->signature->return_type].data : "void"),
		f_str_to_cstr(proc->name, a));

	for (uint i = 0; i < proc->signature->params.len; i++) {
		if (i > 0) printf(", ");
		printf("%s", gmmcType_to_string[proc->signature->return_type].data);
	}
	printf(") {\n");
	print_bb(proc->entry_bb);
	printf("}\n");
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

GMMC_API void gmmc_test() {
	fAllocator* temp = f_temp_push();
	f_os_set_working_dir(F_LIT("C:\\dev\\ffz\\gmmc\\test"));

	//int x = factorial(10);

	gmmcModule* m = gmmc_init(temp);

	gmmcType params[] = {gmmcType_i32};
	gmmcProcSignature* sig = gmmc_make_proc_signature(m, gmmcType_i32, params, F_LEN(params));
	
	gmmcBasicBlock* bb;
	gmmcProc* test_proc = gmmc_make_proc(m, sig, F_LIT("factorial"), &bb);

	gmmcBasicBlock* true_bb = gmmc_make_basic_block(test_proc);
	gmmcBasicBlock* false_bb = gmmc_make_basic_block(test_proc);
	gmmc_op_if(bb, gmmc_op_le(bb, gmmc_op_param(bb, 0), gmmc_op_i32(bb, 1), false), true_bb, false_bb);

	gmmc_op_return(true_bb, GMMC_REG_NONE);
	
	// hmm... should the parameters be accessible in any BB?

	gmmcReg param_n = gmmc_op_param(false_bb, 0);
	gmmc_op_return(false_bb, gmmc_op_mul(false_bb, , ));


	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);
	gmmc_op_debugbreak(bb);
	gmmc_op_return(bb, GMMC_REG_NONE);

	gmmc_proc_compile(test_proc);
	gmmc_proc_print(test_proc);
	
	gmmc_create_coff(m, F_LIT("test.obj"));
	F_BP;
}
