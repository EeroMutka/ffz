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

static fString operand_to_str(fWriter* f, gmmcBasicBlock* bb, gmmcOpIdx op_idx) {
	gmmcOpData* op = &bb->proc->ops[op_idx];
	switch (op->kind) {
		case gmmcOpKind_bool: return f_tprint(op->imm_raw ? "1" : "0");
		case gmmcOpKind_i8: return f_tprint("%hhu", (u8)op->imm_raw);
		case gmmcOpKind_i16: return f_tprint("%hu", (u16)op->imm_raw);
		case gmmcOpKind_i32: return f_tprint("%u", (u32)op->imm_raw);
		case gmmcOpKind_i64: return f_tprint("%llu", (u64)op->imm_raw);
		case gmmcOpKind_f32: {
			F_BP;//f32 value;
			//memcpy(&value, &op->imm_raw, 4);
			//f_writef(f, "%ff;\n", (f64)value);
		} break;

		case gmmcOpKind_f64: {
			F_BP;//f64 value;
			//memcpy(&value, &op->imm_raw, 8);
			//f_writef(f, "%f;\n", value);
		} break;

		case gmmcOpKind_addr_of_param: {
			return f_tprint("(void*)&_$%u", op_idx);
		} break;

		case gmmcOpKind_addr_of_symbol: {
			if (op->symbol->kind == gmmcSymbolKind_Global) {
				return f_tprint("(void*)&%.*s", F_STRF(op->symbol->name));
			} else {
				return op->symbol->name;
			}
		} break;

		default: {
			return f_tprint("_$%u", op_idx);
		}
	}
	return {};
}

void print_bb(fWriter* f, gmmcBasicBlock* bb) {
	f_writef(f, "b$%u:\n", bb->self_idx);
	
	fArenaMark mark = f_temp_get_mark();

	for (uint i = 0; i < bb->ops.len; i++) {
		gmmcOpIdx op_idx = bb->ops[i];
		gmmcOpData* op = &bb->proc->ops[op_idx];

		if (op->kind != gmmcOpKind_comment) {
			f_writef(f, "    ");
		}
		
		gmmcType type = gmmc_get_op_type(bb->proc, op_idx);
		u32 result_bits = 8 * gmmc_type_size(type);
		const char* sign_postfix = op->is_signed ? "signed" : "unsigned";

		// operand count
		//operand_to_str(bb, op->operands[0])

		if (gmmc_is_op_instant(bb->proc, op_idx)) continue;

		if (type != gmmcType_None) {
			f_writef(f, "%s _$%u = ", gmmc_type_get_cstr(type), op_idx);
		}

#define OTOS(i) F_STRF(operand_to_str(f, bb, op->operands[i]))
#define OTOS_(operand) F_STRF(operand_to_str(f, bb, operand))

		switch (op->kind) {
		
		case gmmcOpKind_int2ptr: { f_writef(f, "(void*)%.*s", OTOS(0)); } break;
		case gmmcOpKind_ptr2int: {
			gmmcType value_type = gmmc_get_op_type(bb->proc, op_idx);
			f_writef(f, "(%s)%.*s", gmmc_type_get_cstr(value_type), OTOS(0));
		} break;

		case gmmcOpKind_trunc: {
			f_writef(f, "(i%u)%.*s", result_bits, OTOS(0));
		} break;

		case gmmcOpKind_and: { f_writef(f, "%.*s & %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_or: { f_writef(f, "%.*s | %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_xor: { f_writef(f, "%.*s ^ %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_not: { f_writef(f, "~%.*s", OTOS(0)); } break;
		case gmmcOpKind_shl: { f_writef(f, "%.*s << %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_shr: { f_writef(f, "%.*s >> %.*s", OTOS(0), OTOS(1)); } break;

		// I guess the nice thing about having explicit $le()  would be
		// that we could show the type and if it's signed at the callsite. e.g.   $le_s32()
		// the signedness thing is a bit weird. Maybe we should have the instructions more like in X64 with above/greater terms.
		// Or name it  $le_s32() / $le_u32()
		// $mul_s32 / $mul_u32
		case gmmcOpKind_eq: { f_writef(f, "%.*s == %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_ne: { f_writef(f, "%.*s != %.*s", OTOS(0), OTOS(1)); } break;
		
		case gmmcOpKind_lt: {
			f_writef(f, "$op_%s(%u, <, %.*s, %.*s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_le: {
			f_writef(f, "$op_%s(%u, <=, %.*s, %.*s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_gt: {
			f_writef(f, "$op_%s(%u, >, %.*s, %.*s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_ge: {
			f_writef(f, "$op_%s(%u, >=, %.*s, %.*s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_zxt: {
			f_writef(f, "$zxt(%u, %u, %.*s)", operand_bits(bb, op), result_bits, OTOS(0));
		} break;
		case gmmcOpKind_sxt: {
			f_writef(f, "$sxt(%u, %u, %.*s)", operand_bits(bb, op), result_bits, OTOS(0));
		} break;

		// TODO: make signed overflow not UB
		case gmmcOpKind_add: { f_writef(f, "%.*s + %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_sub: { f_writef(f, "%.*s - %.*s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_mul: {
			f_writef(f, "$op_%s(%u, *, %.*s, %.*s)", sign_postfix, result_bits, OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_div: {
			f_writef(f, "$op_%s(%u, /, %.*s, %.*s)", sign_postfix, result_bits, OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_mod: {
			f_writef(f, "$op_%s(%u, %%, %.*s, %.*s)", sign_postfix, result_bits, OTOS(0), OTOS(1));
		} break;

		case gmmcOpKind_store: {
			gmmcType value_type = gmmc_get_op_type(bb->proc, op->operands[1]);
			f_writef(f, "$store(%s, %.*s, %.*s)", gmmc_type_get_cstr(value_type), OTOS(0), OTOS(1));
		} break;

		case gmmcOpKind_load: {
			gmmcType value_type = gmmc_get_op_type(bb->proc, op_idx);
			f_writef(f, "$load(%s, %.*s)", gmmc_type_get_cstr(value_type), OTOS(0));
		} break;

		case gmmcOpKind_member_access: {
			f_writef(f, "$member_access(%.*s, %u)", OTOS(0), (u32)op->imm_raw);
		} break;

		case gmmcOpKind_array_access: {
			f_writef(f, "$array_access(%.*s, %.*s, %u)", OTOS(0), OTOS(1), (u32)op->imm_raw);
		} break;

		case gmmcOpKind_memcpy: {
			f_writef(f, "memcpy(%.*s, %.*s, %.*s)", OTOS(0), OTOS(1), OTOS(2));
		} break;

		case gmmcOpKind_memset: {
			f_writef(f, "memset(%.*s, %.*s, %.*s)", OTOS(0), OTOS(1), OTOS(2));
		} break;

		case gmmcOpKind_goto: {
			f_writef(f, "goto b$%u", op->goto_.dst_bb);
		} break;

		case gmmcOpKind_if: {
			//operand_to_cstr(bb, op->if_.condition)
			f_writef(f, "if (%.*s) goto b$%u; else goto b$%u", OTOS_(op->if_.condition), op->if_.true_bb, op->if_.false_bb);
		} break;

		case gmmcOpKind_debugbreak: {
			f_writef(f, "$debugbreak()");
		} break;

		case gmmcOpKind_vcall: {
			//gmmcType ret_type = gmmc_get_op_type(bb->proc, op_idx);
			
			gmmcOpData* call_target = &bb->proc->ops[op->call.target];
			if (call_target->kind == gmmcOpKind_addr_of_symbol && call_target->symbol->kind == gmmcSymbolKind_Proc) {
				f_writef(f, "%s(", f_str_t_to_cstr(call_target->symbol->name));
			}
			else {
				// function pointer cast
				f_writef(f, "( (%s(*)(", gmmc_type_get_cstr(type));
				for (uint i = 0; i < op->call.arguments.len; i++) {
					if (i > 0) f_writef(f, ", ");

					gmmcType arg_type = gmmc_get_op_type(bb->proc, op->call.arguments[i]);
					f_writef(f, "%s", gmmc_type_get_cstr(arg_type));
				}
				f_writef(f, ")) %.*s ) (", OTOS_(op->call.target));
			}
			
			// args
			for (uint i = 0; i < op->call.arguments.len; i++) {
				if (i > 0) f_writef(f, ", ");
				f_writef(f, "%.*s", OTOS_(op->call.arguments[i]));
			}
			f_writef(f, ")");
		} break;

		case gmmcOpKind_comment: {
			if (op->comment.len > 0) {
				fSlice(fRangeUint) lines;
				f_str_split_i(op->comment, '\n', f_temp_alc(), &lines);
				for (uint i = 0; i < lines.len; i++) {
					fString line = f_str_slice(op->comment, lines[i].lo, lines[i].hi);
					f_writef(f, "    // %.*s\n", F_STRF(line));
				}
			} else {
				f_writef(f, "\n");
			}
		} break;

		case gmmcOpKind_return: {
			if (op->operands[0] != GMMC_OP_IDX_INVALID) f_writef(f, "return %.*s", OTOS(0));
			else f_writef(f, "return");
		} break;

		default: F_BP;
		}

		if (op->kind == gmmcOpKind_comment) {}
		else {
			if (type == gmmcType_None) f_writef(f, "; // _$%u\n", op_idx);
			else f_writef(f, ";\n");
		}
	}
	f_temp_set_mark(mark);
}

GMMC_API void gmmc_proc_print_c(fWriter* f, gmmcProc* proc) {
	fString name = proc->sym.name;
	
	f_writef(f, "%s %.*s(", (proc->signature->return_type ?
		gmmc_type_get_cstr(proc->signature->return_type): "void"), F_STRF(name));

	for (uint i = 0; i < proc->signature->params.len; i++) {
		if (i > 0) f_writef(f, ", ");
		gmmcType type = proc->signature->params[i];
		f_writef(f, "%s _$%u", gmmc_type_get_cstr(type), proc->params[i]);
	}
	f_writef(f, ") {\n");

	
	// locals / regs!
	u32 first_nonparam_reg = 1 + (u32)proc->signature->params.len;
	//u32 counter = 1;
	for (u32 i = first_nonparam_reg; i < proc->ops.len; i++) {
		gmmcOpData* op = &proc->ops[i];
		
		if (op->kind == gmmcOpKind_local) {
			gmmcLocal local = proc->locals[op->local_idx];
			f_writef(f, "_Alignas(%u) i8 _$%u[%u]; ", local.align, i, local.size);
			
			//if (counter % 8 == 0) f_writef(f, "\n    ");
			//counter++;
		}
		//else if (op->type != gmmcType_None) {
		//	f_writef(f, "%s _$%u; ", gmmc_type_get_cstr(op->type), i);
		//}
	}
	//f_writef(f, "    ");
	if (proc->locals.len > 0) f_writef(f, "\n");

	for (uint i = 0; i < proc->basic_blocks.len; i++) {
		print_bb(f, proc->basic_blocks[i]);
	}
	//f_writef(f, "char _;\n"); // goto: at the end with nothing after it is illegal, this is just a dumb fix for it
	f_writef(f, "}\n");
}

GMMC_API void gmmc_module_print_c(fWriter* f, gmmcModule* m) {
	f_writef(f, "%s", R"(
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

void* memcpy(void* dst, const void* src, size_t n);
void* memset(void* str, int c, size_t n);

// --------------------------------------------------------------------------
)");

	//f_writef(f, "// -- globals -------------\n\n");
	f_writef(f, "#pragma pack(push, 1)\n"); // TODO: use alignas instead! for relocations

	fAllocator* alc = m->allocator;

	// forward declare symbols

	f_writef(f, "\n");
	for (uint i = 0; i < m->procs.len; i++) {
		// hmm... do we need to declare procs with the right type?
		gmmcProc* proc = m->procs[i];
		fString name = m->procs[i]->sym.name;

		gmmcType ret_type = proc->signature->return_type;
		f_writef(f, "%s %.*s(", ret_type ? gmmc_type_get_cstr(ret_type) : "void", F_STRF(name));

		for (uint i = 0; i < proc->signature->params.len; i++) {
			if (i > 0) f_writef(f, ", ");
			f_writef(f, "%s", gmmc_type_get_cstr(proc->signature->params[i]));
		}
		f_writef(f, ");\n");
	}

	for (uint i = 0; i < m->external_symbols.len; i++) {
		fString name = m->external_symbols[i]->sym.name;
		if (name == F_LIT("memset")) continue; // already defined in the prelude
		if (name == F_LIT("memcpy")) continue; // already defined in the prelude

		// pretend all external symbols are functions - I'm not sure if this works on non-functions. TODO!
		f_writef(f, "void %.*s();\n", F_STRF(name));
	}
	f_writef(f, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		const char* name = f_str_to_cstr(global->sym.name, alc);

		// sort the relocations
		qsort(global->relocations.data, global->relocations.len, sizeof(gmmcRelocation), reloc_compare_fn);

		//f_writef(f, "_Alignas(%u) ", global->align);
		f_writef(f, "struct %s_T {", name);

		{
			u32 member_i = 1;
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					global->relocations[next_reloc_idx].offset :
					global->size;

				if (bytes_end > offset) {
					f_writef(f, "i8 _%u[%u]; ", member_i++, bytes_end - offset);
					offset = bytes_end;
				}

				if (next_reloc_idx >= global->relocations.len) break;

				f_writef(f, "i64 _%u; ", member_i++);
				offset += 8;
				next_reloc_idx++;
			}
		}
		f_writef(f, "};\n");
		// forward declare
		//if (global->section == gmmcSection_Threadlocal) f_writef(f, "_Thread_local ");
		if (global->section == gmmcSection_RData) f_writef(f, "const ");
		f_writef(f, "static struct %s_T %s;\n", name, name);
	}

	f_writef(f, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = m->globals[i];
		const char* name = f_str_to_cstr(global->sym.name, alc);

		//if (global->section == gmmcSection_Threadlocal) f_writef(f, "_Thread_local ");
		if (global->section == gmmcSection_RData) f_writef(f, "const ");
		f_writef(f, "static struct %s_T %s", name, name);
		//f_writef(f, "\n%s_data = {", name);

		bool is_all_zeroes = true;
		for (uint j = 0; j < global->size; j++) {
			if (((u8*)global->data)[j] != 0) {
				is_all_zeroes = false;
				break;
			}
		}

		if (is_all_zeroes) {
			f_writef(f, "; // zeroed out\n");
		}
		else {
			f_writef(f, " = {");
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					global->relocations[next_reloc_idx].offset :
					global->size;

				if (bytes_end > offset) {
					f_writef(f, "{");
					for (; offset < bytes_end;) {
						f_writef(f, "%hhu,", ((u8*)global->data)[offset]);
						offset++;
					}
					f_writef(f, "}, ");
				}

				if (next_reloc_idx >= global->relocations.len) break;

				gmmcRelocation reloc = global->relocations[next_reloc_idx];
				u64 reloc_offset = *(u64*)((u8*)global->data + offset);

				f_writef(f, "(i64)(");
				if (reloc_offset != 0) f_writef(f, "(i8*)");
				f_writef(f, "&%s", f_str_to_cstr(reloc.target->name, alc));
				if (reloc_offset != 0) f_writef(f, " + 0x%llx", reloc_offset);
				f_writef(f, "), ");

				offset += 8;
				next_reloc_idx++;
			}
			f_writef(f, "};\n");
		}
	}

	f_writef(f, "\n");
	f_writef(f, "#pragma pack(pop)\n"); // TODO: use alignas instead! for relocations
	f_writef(f, "\n// ------------------------\n\n");

	for (uint i = 0; i < m->procs.len; i++) {
		gmmc_proc_print_c(f, m->procs[i]);
		f_writef(f, "\n");
	}
}