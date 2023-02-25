#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"
#include "gmmc_coff.h"

#include <Zydis/Zydis.h>

#include <stdio.h>

#define VALIDATE(x) F_ASSERT(x)

typedef struct gmmcModule {
	fAllocator* allocator;
	
	fArray(gmmcProcSignature*) proc_signatures;

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

typedef struct gmmcSymbol {
	gmmcModule* mod;
	gmmcString name;
} gmmcSymbol;

typedef struct gmmcProc {
	gmmcSymbol sym; // NOTE: must be the first member!

	gmmcProcSignature* signature;
	gmmcBasicBlock* entry_bb;
	
	fArray(gmmcBasicBlock*) basic_blocks;
	
	fSlice(gmmcReg) params;

	fArray(gmmcType) type_from_reg;
	

	//fSlice(u8) built_x64_instructions;
} gmmcProc;

//const fString gmmcOpKind_to_string[] = {
//	F_LIT_COMP("Invalid"),
//	F_LIT_COMP("debugbreak"),
//	F_LIT_COMP("ret"),
//	F_LIT_COMP("if"),
//};
//
//F_STATIC_ASSERT(gmmcOpKind_COUNT == F_LEN(gmmcOpKind_to_string));


inline bool gmmc_op_is_terminating(gmmcOpKind op) { return op >= gmmcOpKind_ret && op <= gmmcOpKind_if; }

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

	gmmcOp op = { gmmcOpKind_ret };
	op.operands[0] = value;
	f_array_push(&bb->ops, op);
}

GMMC_API void gmmc_op_debugbreak(gmmcBasicBlock* bb) {
	gmmcOp op = { gmmcOpKind_debugbreak };
	f_array_push(&bb->ops, op);
}

static gmmcReg op_comparison(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcReg a, gmmcReg b, bool is_signed) {
	gmmcOp op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.result = gmmc_op_reg(bb->proc, gmmcType_bool);
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
	gmmcOp op = { gmmcOpKind_if };
	op.operands[0] = cond_bool;
	op.dst_bb[0] = true_bb;
	op.dst_bb[1] = false_bb;
	f_array_push(&bb->ops, op);
}

GMMC_API gmmcReg gmmc_op_param(gmmcProc* proc, uint32_t index) {
	return proc->params[index];
}

static gmmcReg op_immediate(gmmcBasicBlock* bb, gmmcOpKind op_kind, gmmcType type, u64 value) {
	gmmcOp op = { op_kind };
	op.imm = value;
	op.result = gmmc_op_reg(bb->proc, type);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_bool(gmmcBasicBlock* bb, bool value) { return op_immediate(bb, gmmcOpKind_bool, gmmcType_bool, (u64)value); }
GMMC_API gmmcReg gmmc_op_i8(gmmcBasicBlock* bb, uint8_t value) { return op_immediate(bb, gmmcOpKind_i8, gmmcType_i8, (u64)value); }
GMMC_API gmmcReg gmmc_op_i16(gmmcBasicBlock* bb, uint16_t value) { return op_immediate(bb, gmmcOpKind_i16, gmmcType_i16, (u64)value); }
GMMC_API gmmcReg gmmc_op_i32(gmmcBasicBlock* bb, uint32_t value) { return op_immediate(bb, gmmcOpKind_i32, gmmcType_i32, (u64)value); }
GMMC_API gmmcReg gmmc_op_i64(gmmcBasicBlock* bb, uint64_t value) { return op_immediate(bb, gmmcOpKind_i64, gmmcType_i64, (u64)value); }

static gmmcReg op_arithmetic(gmmcBasicBlock* bb, gmmcOpKind kind, gmmcReg a, gmmcReg b, bool is_signed) {
	gmmcType type = reg_get_type(bb->proc, a);

	VALIDATE(type == reg_get_type(bb->proc, b));
	VALIDATE(gmmc_type_is_integer(type));

	gmmcOp op = { kind };
	op.is_signed = is_signed;
	op.operands[0] = a;
	op.operands[1] = b;
	op.result = gmmc_op_reg(bb->proc, type);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_add(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_arithmetic(bb, gmmcOpKind_add, a, b, false); }
GMMC_API gmmcReg gmmc_op_sub(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b) { return op_arithmetic(bb, gmmcOpKind_sub, a, b, false); }
GMMC_API gmmcReg gmmc_op_mul(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_arithmetic(bb, gmmcOpKind_mul, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_div(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_arithmetic(bb, gmmcOpKind_div, a, b, is_signed); }
GMMC_API gmmcReg gmmc_op_mod(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed) { return op_arithmetic(bb, gmmcOpKind_mod, a, b, is_signed); }

GMMC_API void gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to) {
	F_BP;
}

GMMC_API gmmcReg gmmc_op_addr_of_symbol(gmmcBasicBlock* bb, gmmcSymbol* symbol) {
	gmmcOp op = { gmmcOpKind_addr_of_symbol };
	op.symbol = symbol;
	op.result = gmmc_op_reg(bb->proc, gmmcType_ptr);
	f_array_push(&bb->ops, op);
	return op.result;
}

GMMC_API gmmcReg gmmc_op_reg(gmmcProc* proc, gmmcType type) {
	gmmcReg reg = (gmmcReg)f_array_push(&proc->type_from_reg, type);
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

GMMC_API gmmcProc* gmmc_make_proc(gmmcModule* m,
	gmmcProcSignature* signature,
	gmmcString name, gmmcBasicBlock** out_entry_bb)
{
	gmmcProc* proc = f_mem_clone(gmmcProc{}, m->allocator);
	proc->sym.mod = m;
	proc->sym.name = name;
	proc->signature = signature;
	
	proc->type_from_reg = f_array_make<gmmcType>(m->allocator);
	f_array_push(&proc->type_from_reg, gmmcType_None);  // reg 0 is always invalid

	proc->basic_blocks = f_array_make<gmmcBasicBlock*>(m->allocator);
	proc->entry_bb = gmmc_make_basic_block(proc);

	proc->params = f_make_slice_garbage<gmmcReg>(signature->params.len, m->allocator);
	for (uint i = 0; i < signature->params.len; i++) {
		proc->params[i] = gmmc_op_reg(proc, signature->params[i]);
	}
	
	*out_entry_bb = proc->entry_bb;
	return proc;
}

GMMC_API gmmcReg gmmc_op_call(gmmcBasicBlock* bb, gmmcProc* procedure,
	gmmcReg* in_arguments, uint32_t in_arguments_count)
{
	gmmcReg addr = gmmc_op_addr_of_symbol(bb, gmmc_proc_as_symbol(procedure));
	return gmmc_op_vcall(bb, procedure->signature->return_type, addr, in_arguments, in_arguments_count);
}

GMMC_API gmmcReg gmmc_op_vcall(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcReg proc_address,
	gmmcReg* in_arguments, uint32_t in_arguments_count)
{
	gmmcOp op = { gmmcOpKind_vcall };
	op.operands[0] = proc_address;
	op.call_arguments = f_clone_slice<gmmcReg>({ in_arguments, in_arguments_count }, bb->mod->allocator);

	if (return_type) {
		op.result = gmmc_op_reg(bb->proc, return_type);
	}
	f_array_push(&bb->ops, op);
	return op.result;
}

const fString gmmcType_to_string[] = {
	F_LIT("(none)"),
	F_LIT("bool"),
	F_LIT("void*"),
	F_LIT("i8"),
	F_LIT("i16"),
	F_LIT("i32"),
	F_LIT("i64"),
	F_LIT("i128"),
};
const char* type_to_cstr(gmmcType type) { return (const char*)gmmcType_to_string[type].data; }

GMMC_API gmmcModule* gmmc_init(fAllocator* allocator) {
	gmmcModule* m = f_mem_clone(gmmcModule{}, allocator);
	m->allocator = allocator;
	m->code_section = f_array_make<u8>(m->allocator);
	m->proc_signatures = f_array_make<gmmcProcSignature*>(m->allocator);
	//m->type_from_reg = f_array_make<gmmcType>(m->allocator);
	//f_array_push(&m->type_from_reg, gmmcType_None); // for GMMG_REG_NONE
	
	return m;
}


void print_bb(gmmcBasicBlock* bb, fAllocator* alc) {
	printf("$B%u:\n", bb->bb_index);

	for (uint i = 0; i < bb->ops.len; i++) {
		gmmcOp* op = &bb->ops[i];
		printf("    ");
		
		//printf("
		//gmmcOpKind_to_string[op->kind].data
		
		switch (op->kind) {
		case gmmcOpKind_bool: { printf("_$%u = %s;\n", op->result, op->imm ? "true" : "false"); } break;
		case gmmcOpKind_i8: { printf("_$%u = %hhu;\n", op->result, (u8)op->imm); } break;
		case gmmcOpKind_i16: { printf("_$%u = %hu;\n", op->result, (u16)op->imm); } break;
		case gmmcOpKind_i32: { printf("_$%u = %u;\n", op->result, (u32)op->imm); } break;
		case gmmcOpKind_i64: { printf("_$%u = %llu;\n", op->result, (u64)op->imm); } break;

		// I guess the nice thing about having explicit $le()  would be
		// that we could show the type and if it's signed at the callsite. e.g.   $le_s32()
		// the signedness thing is a bit weird. Maybe we should have the instructions more like in X64 with above/greater terms.
		// Or name it  $le_s32() / $le_u32()
		// $mul_s32 / $mul_u32
		case gmmcOpKind_eq: { printf("_$%u = _$%u == _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_ne: { printf("_$%u = _$%u != _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_lt: { printf("_$%u = _$%u < _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_le: { printf("_$%u = _$%u <= _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_gt: { printf("_$%u = _$%u > _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_ge: { printf("_$%u = _$%u >= _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;

		case gmmcOpKind_add: { printf("_$%u = _$%u + _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_sub: { printf("_$%u = _$%u - _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_mul: { printf("_$%u = _$%u * _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_div: { printf("_$%u = _$%u / _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_mod: { printf("_$%u = _$%u %% _$%u;\n", op->result, op->operands[0], op->operands[1]); } break;
		
		case gmmcOpKind_addr_of_symbol: {
			printf("_$%u = (void*)%s;\n", op->result, f_str_to_cstr(op->symbol->name, alc));
		} break;

		case gmmcOpKind_if: {
			printf("if (_$%u) goto $B%u; else goto $B%u;\n", op->operands[0], op->dst_bb[0]->bb_index, op->dst_bb[1]->bb_index);
		} break;

		case gmmcOpKind_debugbreak: {
			printf("$debugbreak();\n");
		} break;

		case gmmcOpKind_vcall: {
			gmmcType ret_type = reg_get_type(bb->proc, op->result);
			if (ret_type != gmmcType_None) {
				printf("_$%u = ", op->result);
			}
			printf("( (%s(*)(", type_to_cstr(ret_type));
			
			// function pointer cast
			for (uint i = 0; i < op->call_arguments.len; i++) {
				if (i > 0) printf(", ");
				
				gmmcType arg_type = reg_get_type(bb->proc, op->call_arguments[i]);
				printf("%s", type_to_cstr(arg_type));
			}
			printf(")) _$%u ) (", op->operands[0]);
			
			// args
			for (uint i = 0; i < op->call_arguments.len; i++) {
				if (i > 0) printf(", ");
				printf("_$%u", op->call_arguments[i]);
			}
			printf(");\n");
		} break;

		case gmmcOpKind_ret: {
			if (op->operands[0] != GMMC_REG_NONE) printf("return _$%u;\n", op->operands[0]);
			else printf("return;\n");
		} break;

		default: F_BP;
		}

	}
}

GMMC_API void gmmc_proc_print(gmmcProc* proc) {
	fAllocator* alc = f_temp_push();
	
	printf("%s %s(", (proc->signature->return_type ?
		type_to_cstr(proc->signature->return_type): "void"),
		f_str_to_cstr(proc->sym.name, alc));

	for (uint i = 0; i < proc->signature->params.len; i++) {
		if (i > 0) printf(", ");
		printf("%s _$%u", type_to_cstr(proc->signature->return_type),
			proc->params[i]);
	}
	printf(") {\n");

	printf("    ");
	u32 first_nonparam_reg = 1 + (u32)proc->signature->params.len;
	for (u32 i = first_nonparam_reg; i < proc->type_from_reg.len; i++) {
		printf("%s _$%u; ", type_to_cstr(proc->type_from_reg[i]), i);
		if (i % 8 == 0) printf("\n    ");
	}
	printf("\n");

	for (uint i = 0; i < proc->basic_blocks.len; i++) {
		print_bb(proc->basic_blocks[i], alc);
	}
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
	gmmc_op_if(bb, gmmc_op_le(bb, gmmc_op_param(test_proc, 0), gmmc_op_i32(bb, 1), false), true_bb, false_bb);
	
	gmmc_op_debugbreak(true_bb);
	gmmc_op_return(true_bb, gmmc_op_i32(true_bb, 1));
	
	gmmc_op_debugbreak(false_bb);
	gmmc_op_debugbreak(false_bb);
	
	gmmcReg param_n = gmmc_op_param(test_proc, 0);
	gmmcReg n_minus_1 = gmmc_op_sub(false_bb, param_n, gmmc_op_i32(false_bb, 1));
	gmmcReg return_val = gmmc_op_mul(false_bb, param_n, gmmc_op_call(false_bb, test_proc, &n_minus_1, 1), false);
	gmmc_op_return(false_bb, return_val);

	//gmmc_proc_compile(test_proc);
	gmmc_proc_print(test_proc);
	
	//gmmc_create_coff(m, F_LIT("test.obj"));
	F_BP;
}
