#include "src/foundation/foundation.h"

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
	case gmmcType_bool: return F_LIT("$bool");
	case gmmcType_ptr: return F_LIT("$ptr");
	case gmmcType_i8: return F_LIT("$i8");
	case gmmcType_i16: return F_LIT("$i16");
	case gmmcType_i32: return F_LIT("$i32");
	case gmmcType_i64: return F_LIT("$i64");
	case gmmcType_i128: return F_LIT("$i128");
	case gmmcType_f32: return F_LIT("$f32");
	case gmmcType_f64: return F_LIT("$f64");
	default: f_trap();
	}
	return (fString){0};
}

//static char* gmmc_type_get_cstr(gmmcType type) { return (char*)gmmc_type_get_string(type).data; }

static fString operand_to_str(gmmcBasicBlock* bb, gmmcOpIdx op_idx, fArena* arena) {
	gmmcOpData* op = f_array_get_ptr(gmmcOpData, bb->proc->ops, op_idx);
	switch (op->kind) {
		case gmmcOpKind_bool: return f_aprint(arena, op->imm_bits ? "1" : "0");
		case gmmcOpKind_i8: return f_aprint(arena, "~u8", (u8)op->imm_bits);
		case gmmcOpKind_i16: return f_aprint(arena, "~u16", (u16)op->imm_bits);
		case gmmcOpKind_i32: return f_aprint(arena, "~u32", (u32)op->imm_bits);
		case gmmcOpKind_i64: return f_aprint(arena, "~u64", (u64)op->imm_bits);
		
		case gmmcOpKind_f32: {
			f32 value;
			memcpy(&value, &op->imm_bits, 4);
			return f_aprint(arena, "~f", (f64)value);
		} break;

		case gmmcOpKind_f64: {
			f64 value;
			memcpy(&value, &op->imm_bits, 8);
			return f_aprint(arena, "~f", value);
		} break;

		case gmmcOpKind_addr_of_param: {
			return f_aprint(arena, "(void*)&_$~u32", op_idx);
		} break;

		case gmmcOpKind_addr_of_symbol: {
			if (op->symbol->kind == gmmcSymbolKind_Global) {
				return f_aprint(arena, "(void*)&~s", op->symbol->name);
			} else {
				return op->symbol->name;
			}
		} break;
		
		default: break;
	}
	return f_aprint(arena, "_$~u32", op_idx);
}

void print_bb(fWriter* f, gmmcBasicBlock* bb) {
	fTempScope temp = f_temp_push();
	f_print(f, "b$~u32:\n", bb->self_idx);
	
	for (uint i = 0; i < bb->ops.len; i++) {
		gmmcOpIdx op_idx = f_array_get(gmmcOpIdx, bb->ops, i);
		gmmcOpData* op = f_array_get_ptr(gmmcOpData, bb->proc->ops, op_idx);

		if (op->kind != gmmcOpKind_comment) {
			f_print(f, "    ");
		}
		
		gmmcType type = gmmc_get_op_type(bb->proc, op_idx);
		u32 result_bits = 8 * gmmc_type_size(type);
		const char* sign_postfix = op->is_signed ? "signed" : "unsigned";

		// operand count
		//operand_to_str(bb, op->operands[0])

		if (gmmc_is_op_direct(bb->proc, op_idx)) continue;

		if (type != gmmcType_None) {
			f_print(f, "~s _$~u32 = ", gmmc_type_get_string(type), op_idx);
		}


#define OTOS(i) operand_to_str(bb, op->operands[i], temp.arena)
#define OTOS_(operand) operand_to_str(bb, operand, temp.arena)

		gmmcType result_type = op->type;
		switch (op->kind) {
		
		case gmmcOpKind_int2float: {
			if (op->is_signed) {
				f_print(f, "(~s)($s~u32)~s", gmmc_type_get_string(result_type), operand_bits(bb, op), OTOS(0));
			} else {
				f_print(f, "(~s)~s", gmmc_type_get_string(result_type), OTOS(0));
			}
		} break;

		case gmmcOpKind_float2int: {
			f_print(f, "$f2~c~u32(~s)", "s", result_bits, OTOS(0));
			//f_print(f, "$f2~c~u32(~s)", op->is_signed ? "s" : "u", result_bits, OTOS(0));
		} break;

		case gmmcOpKind_int2ptr: // fallthrough
		case gmmcOpKind_ptr2int: {
			f_print(f, "(~s)~s", gmmc_type_get_string(result_type), OTOS(0));
		} break;

		case gmmcOpKind_trunc: {
			f_print(f, "(~s)~s", gmmc_type_get_string(type), OTOS(0));
		} break;

		case gmmcOpKind_and: { f_print(f, "~s & ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_or: { f_print(f, "~s | ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_xor: { f_print(f, "~s ^ ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_not: { f_print(f, "~~ ~s", OTOS(0)); } break;
		case gmmcOpKind_shl: { f_print(f, "~s << ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_shr: { f_print(f, "~s >> ~s", OTOS(0), OTOS(1)); } break;

		// I guess the nice thing about having explicit $le()  would be
		// that we could show the type and if it's signed at the callsite. e.g.   $le_s32()
		// the signedness thing is a bit weird. Maybe we should have the instructions more like in X64 with above/greater terms.
		// Or name it  $le_s32() / $le_u32()
		// $mul_s32 / $mul_u32
		case gmmcOpKind_eq: { f_print(f, "~s == ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_ne: { f_print(f, "~s != ~s", OTOS(0), OTOS(1)); } break;
		
		case gmmcOpKind_lt: {
			f_print(f, "$op_~c(~u32, <, ~s, ~s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_le: {
			f_print(f, "$op_~c(~u32, <=, ~s, ~s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_gt: {
			f_print(f, "$op_~c(~u32, >, ~s, ~s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_ge: {
			f_print(f, "$op_~c(~u32, >=, ~s, ~s)", sign_postfix, operand_bits(bb, op), OTOS(0), OTOS(1));
		} break;
		case gmmcOpKind_zxt: {
			f_print(f, "$zxt(~u32, ~u32, ~s)", operand_bits(bb, op), result_bits, OTOS(0));
		} break;
		case gmmcOpKind_sxt: {
			f_print(f, "$sxt(~u32, ~u32, ~s)", operand_bits(bb, op), result_bits, OTOS(0));
		} break;

		case gmmcOpKind_fadd: // fallthrough
		case gmmcOpKind_add: { f_print(f, "~s + ~s", OTOS(0), OTOS(1)); } break;

		case gmmcOpKind_fsub: // fallthrough
		case gmmcOpKind_sub: { f_print(f, "~s - ~s", OTOS(0), OTOS(1)); } break;

		case gmmcOpKind_fmul: { f_print(f, "~s * ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_mul: {
			f_print(f, "$op_~c(~u32, *, ~s, ~s)", sign_postfix, result_bits, OTOS(0), OTOS(1));
		} break;
		
		case gmmcOpKind_fdiv: { f_print(f, "~s / ~s", OTOS(0), OTOS(1)); } break;
		case gmmcOpKind_div: {
			f_print(f, "$div_~c~u32(~s, ~s)", op->is_signed ? "s" : "u", result_bits, OTOS(0), OTOS(1));
		} break;
		
		case gmmcOpKind_mod: {
			f_print(f, "$mod_~c~u32(~s, ~s)", op->is_signed ? "s" : "u", result_bits, OTOS(0), OTOS(1));
		} break;

		case gmmcOpKind_store: {
			gmmcType operand_type = gmmc_get_op_type(bb->proc, op->operands[1]);
			f_print(f, "$store(~sua, ~s, ~s)", gmmc_type_get_string(operand_type), OTOS(0), OTOS(1));
		} break;

		case gmmcOpKind_load: {
			f_print(f, "$load(~sua, ~s)", gmmc_type_get_string(result_type), OTOS(0));
		} break;

		case gmmcOpKind_member_access: {
			f_print(f, "$member_access(~s, ~u32)", OTOS(0), (u32)op->imm_bits);
		} break;

		case gmmcOpKind_array_access: {
			f_print(f, "$array_access(~s, ~s, ~u32)", OTOS(0), OTOS(1), (u32)op->imm_bits);
		} break;

		case gmmcOpKind_memcpy: {
			f_print(f, "memcpy(~s, ~s, ~s)", OTOS(0), OTOS(1), OTOS(2));
		} break;

		case gmmcOpKind_memset: {
			f_print(f, "memset(~s, ~s, ~s)", OTOS(0), OTOS(1), OTOS(2));
		} break;

		case gmmcOpKind_goto: {
			f_print(f, "goto b$~u32", op->goto_.dst_bb);
		} break;

		case gmmcOpKind_if: {
			//operand_to_cstr(bb, op->if_.condition)
			f_print(f, "if (~s) goto b$~u32; else goto b$~u32", OTOS_(op->if_.condition), op->if_.true_bb, op->if_.false_bb);
		} break;

		case gmmcOpKind_debugbreak: {
			f_print(f, "$debugbreak()");
		} break;

		case gmmcOpKind_vcall: {
			//gmmcType ret_type = gmmc_get_op_type(bb->proc, op_idx);
			
			gmmcOpData* call_target = f_array_get_ptr(gmmcOpData, bb->proc->ops, op->call.target);
			if (call_target->kind == gmmcOpKind_addr_of_symbol && call_target->symbol->kind == gmmcSymbolKind_Proc) {
				f_print(f, "~s(", call_target->symbol->name);
			}
			else {
				// function pointer cast
				f_print(f, "( (~s(*)(", gmmc_type_get_string(type));
				for (uint i = 0; i < op->call.arguments.len; i++) {
					if (i > 0) f_print(f, ", ");

					gmmcType arg_type = gmmc_get_op_type(bb->proc, f_array_get(gmmcOpIdx, op->call.arguments, i));
					f_prints(f, gmmc_type_get_string(arg_type));
				}
				f_print(f, ")) ~s ) (", OTOS_(op->call.target));
			}

			// args
			f_for_array(gmmcOpIdx, op->call.arguments, arg) {
				if (arg.i > 0) f_print(f, ", ");
				f_prints(f, OTOS_(arg.elem));
			}
			f_print(f, ")");
		} break;

		case gmmcOpKind_comment: {
			if (op->comment.len > 0) {
				fTempScope temp = f_temp_push();
				fSlice(fRangeUint) lines;
				f_str_split_i(op->comment, '\n', temp.arena, &lines);

				f_for_array(fRangeUint, lines, line) {
					fString line_str = f_str_slice(op->comment, line.elem.lo, line.elem.hi);
					f_print(f, "    // ~s\n", line_str);
				}

				f_temp_pop(temp);
			} else {
				f_print(f, "\n");
			}
		} break;

		case gmmcOpKind_return: {
			if (op->operands[0] != GMMC_OP_IDX_INVALID) f_print(f, "return ~s", OTOS(0));
			else if (f_str_equals(bb->proc->sym.name, F_LIT("main"))) {
				// if "main" and no return parameter, return 0 instead. :MainSpecialHandling
				f_print(f, "return 0");
			}
			else f_print(f, "return");
		} break;

		default: f_trap();
		}

		if (op->kind == gmmcOpKind_comment) {}
		else {
			if (type == gmmcType_None) f_print(f, "; // _$~u32\n", op_idx);
			else f_print(f, ";\n");
		}
	}
	f_temp_pop(temp);
}

GMMC_API void gmmc_proc_print_c(fWriter* f, gmmcProc* proc) {
	fString name = proc->sym.name;
	
	// :MainSpecialHandling
	// clang is very strict about the definition of main, it will give errors if it's not exact.
	bool is_main = f_str_equals(name, F_LIT("main"));
	if (is_main) {
		uint param_count = proc->signature->params.len;
		f_print(f, "int main(int _$~u32, char** _$~u32) {\n",
			param_count > 0 ? f_array_get(gmmcOpIdx, proc->addr_of_params, 0) : 0xFFFFFFFF-1,
			param_count > 1 ? f_array_get(gmmcOpIdx, proc->addr_of_params, 1) : 0xFFFFFFFF);
	}
	else {
		f_print(f, "~s ~s(", (proc->signature->return_type ?
			gmmc_type_get_string(proc->signature->return_type) : F_LIT("void")), name);

		f_for_array(gmmcType, proc->signature->params, it) {
			if (it.i > 0) f_print(f, ", ");
			f_print(f, "~s _$~u32", gmmc_type_get_string(it.elem), f_array_get(gmmcOpIdx, proc->addr_of_params, it.i));
		}
		f_print(f, ") {\n");
	}
	
	// locals / regs!
	u32 first_nonparam_reg = (u32)proc->signature->params.len;
	for (u32 i = first_nonparam_reg; i < proc->ops.len; i++) {
		gmmcOpData* op = f_array_get_ptr(gmmcOpData, proc->ops, i);
		
		if (op->kind == gmmcOpKind_local) {
			gmmcLocal local = f_array_get(gmmcLocal, proc->locals, op->local_idx);
			f_print(f, "_Alignas(~u32) $i8 _$~u32[~u32]; ", local.align, i, local.size);
			
			//if (counter % 8 == 0) f_writef(f, "\n    ");
			//counter++;
		}
		//else if (op->type != gmmcType_None) {
		//	f_writef(f, "%s _$~u32; ", gmmc_type_get_cstr(op->type), i);
		//}
	}
	//f_writef(f, "    ");
	if (proc->locals.len > 0) f_print(f, "\n");

	f_for_array(gmmcBasicBlock*, proc->basic_blocks, it) {
		print_bb(f, it.elem);
	}
	//f_writef(f, "char _;\n"); // goto: at the end with nothing after it is illegal, this is just a dumb fix for it

	f_print(f, "}\n");
}

GMMC_API void gmmc_module_print_c(fWriter* f, gmmcModule* m) {
	f_printc(f, "\n"
"// ------------------ GMMC prelude for C11 ----------------------------------\n"
"\n"
"typedef _Bool             $bool;\n"
"typedef void*              $ptr;\n"
"typedef unsigned char       $i8;\n"
"typedef unsigned short     $i16;\n"
"typedef unsigned int       $i32;\n"
"typedef unsigned long long $i64;\n"
"typedef float              $f32;\n"
"typedef double             $f64;\n"
"\n"
"#include <stdint.h> // for uintptr_t and INT*_MAX, INT*_MIN\n"
"\n"
"// Unaligned primitive types.\n"
"// This is required to get rid of the UB around unaligned accesses in C.\n"
"#pragma pack(push, 1)\n"
"typedef struct { $bool _value; } $boolua;\n"
"typedef struct { $ptr  _value; }  $ptrua;\n"
"typedef struct { $i8   _value; }   $i8ua;\n"
"typedef struct { $i16  _value; }  $i16ua;\n"
"typedef struct { $i32  _value; }  $i32ua;\n"
"typedef struct { $i64  _value; }  $i64ua;\n"
"typedef struct { $f32  _value; }  $f32ua;\n"
"typedef struct { $f64  _value; }  $f64ua;\n"
"#pragma pack(pop)\n"
"\n"
"// Required CRT magic definitions\n"
"void __chkstk() {}\n"
"int _fltused = 0x9875;\n"
"\n"
"#define $INLINE __forceinline\n"
"\n"
"$INLINE void $debugbreak() {\n"
"	// https://github.com/scottt/debugbreak/\n"
"	__asm__ volatile(\"int $0x03\");\n"
"}\n"
"\n"
"#define $store(T, ptr, value)  ((T*)ptr)->_value = value\n"
"#define $load(T, ptr)          ((T*)ptr)->_value\n"
"\n"
"//#define $array_access(base, index, stride) ($i8*)base + index * stride\n"
"//#define $member_access(base, offset) ($i8*)base + offset\n"
"#define $array_access(base, index, stride) ($ptr)((uintptr_t)base + (uintptr_t)(index * stride))\n"
"#define $member_access(base, offset) ($ptr)((uintptr_t)base + (uintptr_t)offset)\n"
"\n"
"// signed types\n"
"typedef char               $s8;\n"
"typedef short             $s16;\n"
"typedef int               $s32;\n"
"typedef long long         $s64;\n"
"\n"
"#define $op_unsigned(bits, op, a, b) a op b\n"
"#define $op_signed(bits, op, a, b) ($i##bits) (($s##bits)a op ($s##bits)b)\n"
"\n"
"// We define division and modulo by zero to trap.\n"
"\n"
"$INLINE  $i8 $div_u8($i8 a, $i8 b)    { if (b == 0) { $debugbreak(); return 0; } return a / b; }\n"
"$INLINE  $i8 $div_s8($i8 a, $i8 b)    { if (b == 0) { $debugbreak(); return 0; } return ($i8)(($s8)a / ($s8)b); }\n"
"$INLINE $i16 $div_u16($i16 a, $i16 b) { if (b == 0) { $debugbreak(); return 0; } return a / b; }\n"
"$INLINE $i16 $div_s16($i16 a, $i16 b) { if (b == 0) { $debugbreak(); return 0; } return ($i16)(($s16)a / ($s16)b); }\n"
"$INLINE $i32 $div_u32($i32 a, $i32 b) { if (b == 0) { $debugbreak(); return 0; } return a / b; }\n"
"$INLINE $i32 $div_s32($i32 a, $i32 b) { if (b == 0) { $debugbreak(); return 0; } return ($i32)(($s32)a / ($s32)b); }\n"
"$INLINE $i64 $div_u64($i64 a, $i64 b) { if (b == 0) { $debugbreak(); return 0; } return a / b; }\n"
"$INLINE $i64 $div_s64($i64 a, $i64 b) { if (b == 0) { $debugbreak(); return 0; } return ($i64)(($s64)a / ($s64)b); }\n"
"\n"
"$INLINE  $i8 $mod_u8($i8 a, $i8 b)    { if (b == 0) { $debugbreak(); return 0; } return a % b; }\n"
"$INLINE  $i8 $mod_s8($i8 a, $i8 b)    { if (b == 0) { $debugbreak(); return 0; } return ($i8)(($s8)a % ($s8)b); }\n"
"$INLINE $i16 $mod_u16($i16 a, $i16 b) { if (b == 0) { $debugbreak(); return 0; } return a % b; }\n"
"$INLINE $i16 $mod_s16($i16 a, $i16 b) { if (b == 0) { $debugbreak(); return 0; } return ($i16)(($s16)a % ($s16)b); }\n"
"$INLINE $i32 $mod_u32($i32 a, $i32 b) { if (b == 0) { $debugbreak(); return 0; } return a % b; }\n"
"$INLINE $i32 $mod_s32($i32 a, $i32 b) { if (b == 0) { $debugbreak(); return 0; } return ($i32)(($s32)a % ($s32)b); }\n"
"$INLINE $i64 $mod_u64($i64 a, $i64 b) { if (b == 0) { $debugbreak(); return 0; } return a % b; }\n"
"$INLINE $i64 $mod_s64($i64 a, $i64 b) { if (b == 0) { $debugbreak(); return 0; } return ($i64)(($s64)a % ($s64)b); }\n"
"\n"
"#define $sxt(from, to, value) ($i##to)(($s##to)(($s##from)value))\n"
"#define $zxt(from, to, value) ($i##to)value\n"
"\n"
"//\n"
"// float -> integer overflow is undefined in C, but we define it to clamp.\n"
"// https://stackoverflow.com/questions/526070/handling-overflow-when-casting-doubles-to-integers-in-c\n"
"//\n"
"#define $f2s8(value) ($i8)($s8)value\n"
"#define $f2s16(value) ($i16)($s16)value\n"
"#define $f2s32(value) ($i32)($s32)value\n"
"#define $f2s64(value) ($i64)($s64)value\n"
"\n"
"//#define $f2s8(value) ($i8)(value > INT8_MIN ? (value < INT8_MAX ? ($s8)value : INT8_MAX) : INT8_MIN)\n"
"//#define $f2s16(value) ($i16)(value > INT16_MIN ? (value < INT16_MAX ? ($s16)value : INT16_MAX) : INT16_MIN)\n"
"//#define $f2s32(value) ($i32)(value > INT32_MIN ? (value < INT32_MAX ? ($s32)value : INT32_MAX) : INT32_MIN)\n"
"//#define $f2s64(value) ($i64)(value > INT64_MIN ? (value < INT64_MAX ? ($s64)value : INT64_MAX) : INT64_MIN)\n"
"//#define $f2u8(value) (value > 0 ? (value < UINT8_MAX ? ($i8)value : UINT8_MAX) : 0)\n"
"//#define $f2u16(value) (value > 0 ? (value < UINT16_MAX ? ($i16)value : UINT16_MAX) : 0)\n"
"//#define $f2u32(value) (value > 0 ? (value < UINT32_MAX ? ($i32)value : UINT32_MAX) : 0)\n"
"//#define $f2u64(value) (value > 0 ? (value < UINT64_MAX ? ($i64)value : UINT64_MAX) : 0)\n"
"\n"
"\n"
"void* memcpy(void* dst, const void* src, size_t n);\n"
"void* memset(void* str, int c, size_t n);\n"
"\n"
"// --------------------------------------------------------------------------\n");

	//f_writef(f, "// -- globals -------------\n\n");
	
	f_print(f, "#pragma pack(push, 1)\n"); // TODO: use alignas instead! for relocations

	// forward declare symbols

	f_print(f, "\n");
	f_for_array(gmmcProc*, m->procs, it) {
		// hmm... do we need to declare procs with the right type?
		fString name = it.elem->sym.name;
		if (f_str_equals(name, F_LIT("main"))) continue; // :MainSpecialHandling

		gmmcType ret_type = it.elem->signature->return_type;
		f_print(f, "~s ~s(", ret_type ? gmmc_type_get_string(ret_type) : F_LIT("void"), name);

		f_for_array(gmmcType, it.elem->signature->params, param) {
			if (param.i > 0) f_print(f, ", ");
			f_prints(f, gmmc_type_get_string(param.elem));
		}
		f_print(f, ");\n");
	}

	f_for_array(gmmcExtern*, m->external_symbols, it) {
		fString name = it.elem->sym.name;
		if (f_str_equals(name, F_LIT("memset"))) continue; // already defined in the prelude
		if (f_str_equals(name, F_LIT("memcpy"))) continue; // already defined in the prelude

		// pretend all external symbols are functions - I'm not sure if this works on non-functions. TODO!
		f_print(f, "void ~s();\n", name);
	}
	f_print(f, "\n");

	for (uint i = 1; i < m->globals.len; i++) { // TODO: 0-based
		gmmcGlobal* global = f_array_get(gmmcGlobal*, m->globals, i);
		fString name = global->sym.name;

		// sort the relocations
		qsort(global->relocations.data, global->relocations.len, sizeof(gmmcRelocation), reloc_compare_fn);

		f_print(f, "struct ~s_T {", name);

		{
			u32 member_i = 1;
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					f_array_get(gmmcRelocation, global->relocations, next_reloc_idx).offset :
					global->size;

				if (bytes_end > offset) {
					f_print(f, "$i8 _~u32[~u32]; ", member_i++, bytes_end - offset);
					offset = bytes_end;
				}

				if (next_reloc_idx >= global->relocations.len) break;

				f_print(f, "$i64 _~u32; ", member_i++);
				offset += 8;
				next_reloc_idx++;
			}
		}
		f_print(f, "};\n");
		// forward declare
		//if (global->section == gmmcSection_Threadlocal) f_writef(f, "_Thread_local ");
		if (global->section == gmmcSection_RData) f_print(f, "const ");
		f_print(f, "_Alignas(~u32) static struct ~s_T ~s;\n", global->align, name, name);
	}

	f_print(f, "\n");

	for (uint i = 1; i < m->globals.len; i++) {
		gmmcGlobal* global = f_array_get(gmmcGlobal*, m->globals, i);
		fString name = global->sym.name;

		//if (global->section == gmmcSection_Threadlocal) f_writef(f, "_Thread_local ");
		if (global->section == gmmcSection_RData) f_print(f, "const ");
		f_print(f, "_Alignas(~u32) static struct ~s_T ~s", global->align, name, name);
		//f_writef(f, "\n%s_data = {", name);

		bool is_all_zeroes = true;
		for (uint j = 0; j < global->size; j++) {
			if (((u8*)global->data)[j] != 0) {
				is_all_zeroes = false;
				break;
			}
		}

		if (is_all_zeroes && global->relocations.len == 0) {
			f_print(f, "; // zeroed out\n");
		}
		else {
			f_print(f, " = {");
			u32 next_reloc_idx = 0;
			u32 offset = 0;
			for (;;) {
				u32 bytes_end = next_reloc_idx < global->relocations.len ?
					f_array_get(gmmcRelocation, global->relocations, next_reloc_idx).offset :
					global->size;

				if (bytes_end > offset) {
					f_print(f, "{");
					for (; offset < bytes_end;) {
						f_print(f, "~u8,", ((u8*)global->data)[offset]);
						offset++;
					}
					f_print(f, "}, ");
				}

				if (next_reloc_idx >= global->relocations.len) break;

				gmmcRelocation reloc = f_array_get(gmmcRelocation, global->relocations, next_reloc_idx);
				u64 reloc_offset = *(u64*)((u8*)global->data + offset);

				f_print(f, "($i64)(");
				if (reloc_offset != 0) f_print(f, "($i8*)");
				f_print(f, "&~s", reloc.target->name);
				if (reloc_offset != 0) f_print(f, " + 0x~x64", reloc_offset);
				f_print(f, "), ");

				offset += 8;
				next_reloc_idx++;
			}
			f_print(f, "};\n");
		}
	}

	f_print(f, "\n");
	f_print(f, "#pragma pack(pop)\n"); // TODO: use alignas instead! for relocations
	f_print(f, "\n// ------------------------\n\n");

	f_for_array(gmmcProc*, m->procs, it) {
		gmmc_proc_print_c(f, it.elem);
		f_print(f, "\n");
	}
}