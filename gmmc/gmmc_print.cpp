#include "src/foundation/foundation.hpp"

#define gmmcString fString
#include "gmmc.h"

#include <stdlib.h> // for qsort

static int reloc_compare_fn(const void* a, const void* b) {
	return ((gmmcRelocation*)a)->offset - ((gmmcRelocation*)b)->offset;
}

static u32 operand_bits(gmmcBasicBlock* bb, gmmcOpData* op) {
	return 8 * gmmc_type_size(gmmc_get_op_type(bb->proc, op->operands[0]));
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
	case gmmcType_f32: return F_LIT("f32");
	case gmmcType_f64: return F_LIT("f64");
	default: F_BP;
	}
	return {};
}

static char* gmmc_type_get_cstr(gmmcType type) { return (char*)gmmc_type_get_string(type).data; }

void print_bb(FILE* f, gmmcBasicBlock* bb) {
	fprintf(f, "b$%u:\n", bb->bb_index);

	for (uint i = 0; i < bb->ops.len; i++) {
		gmmcOpIdx op_idx = bb->ops[i];
		gmmcOpData* op = &bb->proc->ops[op_idx];

		if (op->kind != gmmcOpKind_comment) {
			fprintf(f, "    ");
		}
		
		u32 result_bits = 8 * gmmc_type_size(gmmc_get_op_type(bb->proc, op_idx));
		const char* sign_postfix = op->is_signed ? "signed" : "unsigned";

		switch (op->kind) {
		case gmmcOpKind_bool: { fprintf(f, "_$%u = %s;\n", op_idx, op->imm_raw ? "1" : "0"); } break;
		case gmmcOpKind_i8: { fprintf(f, "_$%u = %hhu;\n", op_idx, (u8)op->imm_raw); } break;
		case gmmcOpKind_i16: { fprintf(f, "_$%u = %hu;\n", op_idx, (u16)op->imm_raw); } break;
		case gmmcOpKind_i32: { fprintf(f, "_$%u = %u;\n", op_idx, (u32)op->imm_raw); } break;
		case gmmcOpKind_i64: { fprintf(f, "_$%u = %llu;\n", op_idx, (u64)op->imm_raw); } break;
		
		case gmmcOpKind_f32: {
			f32 value;
			memcpy(&value, &op->imm_raw, 4);
			fprintf(f, "_$%u = %ff;\n", op_idx, (f64)value);
		} break;

		case gmmcOpKind_f64: {
			f64 value;
			memcpy(&value, &op->imm_raw, 8);
			fprintf(f, "_$%u = %f;\n", op_idx, value);
		} break;
		
		case gmmcOpKind_int2ptr: { fprintf(f, "_$%u = (void*)_$%u;\n", op_idx, op->operands[0]); } break;
		case gmmcOpKind_ptr2int: {
			gmmcType value_type = gmmc_get_op_type(bb->proc, op_idx);
			fprintf(f, "_$%u = (%s)_$%u;\n", op_idx, gmmc_type_get_cstr(value_type), op->operands[0]);
		} break;

		case gmmcOpKind_trunc: {
			fprintf(f, "_$%u = (i%u)_$%u;\n", op_idx, result_bits, op->operands[0]);
		} break;

		case gmmcOpKind_and: { fprintf(f, "_$%u = _$%u & _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_or: { fprintf(f, "_$%u = _$%u | _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_xor: { fprintf(f, "_$%u = _$%u ^ _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_not: { fprintf(f, "_$%u = ~_$%u;\n", op_idx, op->operands[0]); } break;
		case gmmcOpKind_shl: { fprintf(f, "_$%u = _$%u << _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_shr: { fprintf(f, "_$%u = _$%u >> _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;

		// I guess the nice thing about having explicit $le()  would be
		// that we could show the type and if it's signed at the callsite. e.g.   $le_s32()
		// the signedness thing is a bit weird. Maybe we should have the instructions more like in X64 with above/greater terms.
		// Or name it  $le_s32() / $le_u32()
		// $mul_s32 / $mul_u32
		case gmmcOpKind_eq: { fprintf(f, "_$%u = _$%u == _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_ne: { fprintf(f, "_$%u = _$%u != _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		
		case gmmcOpKind_lt: {
			fprintf(f, "_$%u = $op_%s(%u, <, _$%u, _$%u);\n", op_idx, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_le: {
			fprintf(f, "_$%u = $op_%s(%u, <=, _$%u, _$%u);\n", op_idx, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_gt: {
			fprintf(f, "_$%u = $op_%s(%u, >, _$%u, _$%u);\n", op_idx, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_ge: {
			fprintf(f, "_$%u = $op_%s(%u, >=, _$%u, _$%u);\n", op_idx, sign_postfix,
				operand_bits(bb, op), op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_zxt: {
			fprintf(f, "_$%u = $zxt(%u, %u, _$%u);\n", op_idx,
				operand_bits(bb, op), result_bits, op->operands[0]);
		} break;
		case gmmcOpKind_sxt: {
			fprintf(f, "_$%u = $sxt(%u, %u, _$%u);\n", op_idx,
				operand_bits(bb, op), result_bits, op->operands[0]);
		} break;


		// TODO: make signed overflow not UB
		case gmmcOpKind_add: { fprintf(f, "_$%u = _$%u + _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_sub: { fprintf(f, "_$%u = _$%u - _$%u;\n", op_idx, op->operands[0], op->operands[1]); } break;
		case gmmcOpKind_mul: {
			fprintf(f, "_$%u = $op_%s(%u, *, _$%u, _$%u);\n", op_idx, sign_postfix, result_bits, op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_div: {
			fprintf(f, "_$%u = $op_%s(%u, /, _$%u, _$%u);\n", op_idx, sign_postfix, result_bits, op->operands[0], op->operands[1]);
		} break;
		case gmmcOpKind_mod: {
			fprintf(f, "_$%u = $op_%s(%u, %%, _$%u, _$%u);\n", op_idx, sign_postfix, result_bits, op->operands[0], op->operands[1]);
		} break;
		
		case gmmcOpKind_addr_of_symbol: {
			if (op->symbol->kind == gmmcSymbolKind_Global) {
				fprintf(f, "_$%u = (void*)&%s;\n", op_idx, f_str_t_to_cstr(op->symbol->name));
			}
			else {
				fprintf(f, "_$%u = %s;\n", op_idx, f_str_t_to_cstr(op->symbol->name));
			}
		} break;

		case gmmcOpKind_store: {
			gmmcType value_type = gmmc_get_op_type(bb->proc, op->operands[1]);
			fprintf(f, "$store(%s, _$%u, _$%u);\n", gmmc_type_get_cstr(value_type), op->operands[0], op->operands[1]);
		} break;

		case gmmcOpKind_load: {
			gmmcType value_type = gmmc_get_op_type(bb->proc, op_idx);
			fprintf(f, "_$%u = $load(%s, _$%u);\n", op_idx, gmmc_type_get_cstr(value_type), op->operands[0]);
		} break;

		case gmmcOpKind_member_access: {
			fprintf(f, "_$%u = $member_access(_$%u, %u);\n", op_idx, op->operands[0], (u32)op->imm_raw);
		} break;

		case gmmcOpKind_array_access: {
			fprintf(f, "_$%u = $array_access(_$%u, _$%u, %u);\n", op_idx, op->operands[0], op->operands[1], (u32)op->imm_raw);
		} break;

		case gmmcOpKind_memcpy: {
			fprintf(f, "mem_move(_$%u, _$%u, _$%u);\n", op->operands[0], op->operands[1], op->operands[2]);
		} break;

		case gmmcOpKind_memset: {
			fprintf(f, "mem_set(_$%u, _$%u, _$%u);\n", op->operands[0], op->operands[1], op->operands[2]);
		} break;

		case gmmcOpKind_goto: {
			fprintf(f, "goto b$%u;\n", op->goto_.dst_bb->bb_index);
		} break;

		case gmmcOpKind_if: {
			fprintf(f, "if (_$%u) goto b$%u; else goto b$%u;\n", op->if_.condition, op->if_.dst_bb[0]->bb_index, op->if_.dst_bb[1]->bb_index);
		} break;

		case gmmcOpKind_debugbreak: {
			fprintf(f, "$debugbreak();\n");
		} break;

		case gmmcOpKind_call: // fallthrough
		case gmmcOpKind_vcall: {
			gmmcType ret_type = gmmc_get_op_type(bb->proc, op_idx);
			if (ret_type != gmmcType_None) {
				fprintf(f, "_$%u = ", op_idx);
			}
			
			if (op->kind == gmmcOpKind_call) {
				fprintf(f, "%s(", f_str_t_to_cstr(op->call.target_sym->name));
			}
			else {
				// function pointer cast
				fprintf(f, "( (%s(*)(", gmmc_type_get_cstr(ret_type));
				for (uint i = 0; i < op->call.arguments.len; i++) {
					if (i > 0) fprintf(f, ", ");

					gmmcType arg_type = gmmc_get_op_type(bb->proc, op->call.arguments[i]);
					fprintf(f, "%s", gmmc_type_get_cstr(arg_type));
				}
				fprintf(f, ")) _$%u ) (", op->call.target);
			}
			
			// args
			for (uint i = 0; i < op->call.arguments.len; i++) {
				if (i > 0) fprintf(f, ", ");
				fprintf(f, "_$%u", op->call.arguments[i]);
			}
			fprintf(f, ");\n");
		} break;

		case gmmcOpKind_comment: {
			if (op->comment.len > 0) {
				fSlice(fRangeUint) lines;
				f_str_split_i(op->comment, '\n', f_temp_alc(), &lines);
				for (uint i = 0; i < lines.len; i++) {
					fString line = f_str_slice(op->comment, lines[i].lo, lines[i].hi);
					fprintf(f, "    // %.*s\n", F_STRF(line));
				}
			} else {
				fprintf(f, "\n");
			}
		} break;

		case gmmcOpKind_return: {
			if (op->operands[0] != GMMC_OP_IDX_INVALID) fprintf(f, "return _$%u;\n", op->operands[0]);
			else fprintf(f, "return;\n");
		} break;

		default: F_BP;
		}

	}
}

GMMC_API void gmmc_proc_print_c(FILE* f, gmmcProc* proc) {
	fString name = proc->sym.name;
	
	fprintf(f, "%s %.*s(", (proc->signature->return_type ?
		gmmc_type_get_cstr(proc->signature->return_type): "void"), F_STRF(name));

	for (uint i = 0; i < proc->signature->params.len; i++) {
		if (i > 0) fprintf(f, ", ");
		gmmcType type = proc->signature->params[i];
		fprintf(f, "%s _$%u", gmmc_type_get_cstr(type), proc->params[i]);
	}
	fprintf(f, ") {\n");

	fprintf(f, "    ");
	
	// locals / regs!
	u32 first_nonparam_reg = 1 + (u32)proc->signature->params.len;
	for (u32 i = first_nonparam_reg; i < proc->ops.len; i++) {
		gmmcOpData* op = &proc->ops[i];
		//gmmcRegInfo info = proc->reg_infos[i];
		if (op->kind == gmmcOpKind_local) {
			gmmcLocal local = proc->locals[op->local_idx];
			fprintf(f, "_Alignas(%u) i8 _$%u[%u]; ", local.align, i, local.size);
		}
		else if (op->type != gmmcType_None) {
			fprintf(f, "%s _$%u; ", gmmc_type_get_cstr(op->type), i);
		}
		if (i % 8 == 0) fprintf(f, "\n    ");
	}
	fprintf(f, "\n");

	for (uint i = 0; i < proc->basic_blocks.len; i++) {
		print_bb(f, proc->basic_blocks[i]);
	}
	fprintf(f, "char _;\n"); // goto: at the end with nothing after it is illegal, this is just a dumb fix for it
	fprintf(f, "}\n");
}

GMMC_API void gmmc_module_print_c(FILE* f, gmmcModule* m) {
	fprintf(f, "%s", R"(
// ------------------ GMMC prelude for C11 ----------------------------------

typedef _Bool             bool;
typedef void*              ptr;
typedef unsigned char       i8;
typedef unsigned short     i16;
typedef unsigned int       i32;
typedef unsigned long long i64;
typedef float              f32;
typedef double             f64;
typedef char               $s8;
typedef short             $s16;
typedef int               $s32;
typedef long long         $s64;

// Required CRT magic definitions
void __chkstk() {}
int _fltused = 0x9875;

#define $debugbreak() do {__debugbreak();} while(0)
#define $store(T, ptr, value) *(T*)ptr = value
#define $load(T, ptr) *(T*)ptr
#define $array_access(base, index, stride) (i8*)base + index * stride
#define $member_access(base, offset) (i8*)base + offset

#define $op_unsigned(bits, op, a, b) a op b
#define $op_signed(bits, op, a, b) (i##bits) (($s##bits)a op ($s##bits)b)

#define $sxt(from, to, value) (i##to)(($s##to)(($s##from)value))
#define $zxt(from, to, value) (i##to)value

// TODO: better implementation!!!
static void mem_move(void *dest, const void *src, size_t len) {
	// https://github.com/malxau/minicrt/blob/master/crt/mem.c
	size_t i;
    char* char_src = (char *)src;
    char* char_dest = (char *)dest;
    if (char_dest > char_src) {
        if (len == 0) {
            return; //return dest;
        }
        for (i = len - 1; ; i--) {
            char_dest[i] = char_src[i];
            if (i==0) break;
        }
    } else {
        for (i = 0; i < len; i++) {
            char_dest[i] = char_src[i];
        }
    }
    //return dest;
}

// TODO: better implementation!!!
static void mem_set(void *dest, int c, size_t len) {
	// https://github.com/malxau/minicrt/blob/master/crt/mem.c
	size_t i;
    unsigned int fill;
    size_t chunks = len / sizeof(fill);
    char * char_dest = (char *)dest;
    unsigned int * uint_dest = (unsigned int *)dest;

    //
    //  Note we go from the back to the front.  This is to 
    //  prevent newer compilers from noticing what we're doing
    //  and trying to invoke the built-in memset instead of us.
    //

    fill = (c<<24) + (c<<16) + (c<<8) + c;

    for (i = len; i > chunks * sizeof(fill); i--) {
        char_dest[i - 1] = c;
    }

    for (i = chunks; i > 0; i--) {
        uint_dest[i - 1] = fill;
    }
}

// --------------------------------------------------------------------------
)");

	//fprintf(f, "// -- globals -------------\n\n");
	fprintf(f, "#pragma pack(push, 1)\n"); // TODO: use alignas instead! for relocations

	fAllocator* alc = m->allocator;

	// forward declare symbols

	fprintf(f, "\n");
	for (uint i = 0; i < m->procs.len; i++) {
		// hmm... do we need to declare procs with the right type?
		gmmcProc* proc = m->procs[i];
		fString name = m->procs[i]->sym.name;

		gmmcType ret_type = proc->signature->return_type;
		fprintf(f, "%s %.*s(", ret_type ? gmmc_type_get_cstr(ret_type) : "void", F_STRF(name));

		for (uint i = 0; i < proc->signature->params.len; i++) {
			if (i > 0) fprintf(f, ", ");
			fprintf(f, "%s", gmmc_type_get_cstr(proc->signature->params[i]));
		}
		fprintf(f, ");\n");
	}

	for (uint i = 0; i < m->external_symbols.len; i++) {
		fString name = m->external_symbols[i]->sym.name;
		if (name == F_LIT("mem_set")) continue; // already defined in the prelude
		if (name == F_LIT("mem_move")) continue; // already defined in the prelude

		// pretend all external symbols are functions - I'm not sure if this works on non-functions. TODO!
		fprintf(f, "void %.*s();\n", F_STRF(name));
	}
	fprintf(f, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		const char* name = f_str_to_cstr(global->sym.name, alc);

		// sort the relocations
		qsort(global->relocations.data, global->relocations.len, sizeof(gmmcRelocation), reloc_compare_fn);

		//fprintf(f, "_Alignas(%u) ", global->align);
		fprintf(f, "struct %s_T {", name);

		{
			u32 member_i = 1;
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					global->relocations[next_reloc_idx].offset :
					global->size;

				if (bytes_end > offset) {
					fprintf(f, "i8 _%u[%u]; ", member_i++, bytes_end - offset);
					offset = bytes_end;
				}

				if (next_reloc_idx >= global->relocations.len) break;

				fprintf(f, "i64 _%u; ", member_i++);
				offset += 8;
				next_reloc_idx++;
			}
		}
		fprintf(f, "};\n");
		// forward declare
		//if (global->section == gmmcSection_Threadlocal) fprintf(f, "_Thread_local ");
		if (global->section == gmmcSection_RData) fprintf(f, "const ");
		fprintf(f, "static struct %s_T %s;\n", name, name);
	}

	fprintf(f, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		const char* name = f_str_to_cstr(global->sym.name, alc);

		//if (global->section == gmmcSection_Threadlocal) fprintf(f, "_Thread_local ");
		if (global->section == gmmcSection_RData) fprintf(f, "const ");
		fprintf(f, "static struct %s_T %s = {", name, name);
		//fprintf(f, "\n%s_data = {", name);

		{
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					global->relocations[next_reloc_idx].offset :
					global->size;

				if (bytes_end > offset) {
					fprintf(f, "{");
					for (; offset < bytes_end;) {
						fprintf(f, "%hhu,", ((u8*)global->data)[offset]);
						offset++;
					}
					fprintf(f, "}, ");
				}

				if (next_reloc_idx >= global->relocations.len) break;

				gmmcRelocation reloc = global->relocations[next_reloc_idx];
				u64 reloc_offset = *(u64*)((u8*)global->data + offset);

				fprintf(f, "(i64)(");
				if (reloc_offset != 0) fprintf(f, "(i8*)");
				fprintf(f, "&%s", f_str_to_cstr(reloc.target->name, alc));
				if (reloc_offset != 0) fprintf(f, " + 0x%llx", reloc_offset);
				fprintf(f, "), ");

				offset += 8;
				next_reloc_idx++;
			}
		}
		fprintf(f, "};\n");
	}

	fprintf(f, "\n");
	fprintf(f, "#pragma pack(pop)\n"); // TODO: use alignas instead! for relocations
	fprintf(f, "\n// ------------------------\n\n");

	for (uint i = 0; i < m->procs.len; i++) {
		gmmc_proc_print_c(f, m->procs[i]);
		fprintf(f, "\n");
	}
}