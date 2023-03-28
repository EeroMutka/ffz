// Give-Me-Machine-Code
// 
// You're on your way to making your dream programming language. Excitedly, you start parsing in
// source code files, then building some structure out of them, then, ... uhh... how do you get
// to an executable?
// 
// You could compile to an existing language, and use their compiler for the task. But that begs
// the question - how does *that* language do it?
// 
// In short, you generate a blob of machine code instructions for your target machine (i.e. X64, ARM, WASM)
// and another blob of data containing your global variables, and put them inside an executable file
// for your target OS (i.e. PE, ELF, MACH-O). In practice, it's simpler to generate an
// intermediate object file instead of an executable directly, and run a linker on it. This way you
// can also easily link to static libraries created in other programming languages. But the
// principle is the same - object files, static and dynamic libraries, and executables are all
// very similar.
// 
// No step along the way in particular complicated, but it still a lot of steps.
// The goal of Give-Me-Machine-Code is to be an easy to use library to generate machine code
// for you
// 
// I saw room for an easy-to-use library to do this task, so I decided to make it.
// 
// 
// There are many layers of software between you writing code, and the code
// being ran by your computer. This process of compiling code can seem like a mysterious
// black box, where don't really know what happens between pressing compile and getting
// and executable. And why would you even care? After all, the smart people already
// figured it all for you!
// 
// Well, sort of. Modern optimizing compilers are quite amazing; it is for sure a
// difficult task to do well. On the flipside, they tend to be huge, complicated
// codebases that are difficult to understand, extend and contribute to. And if you
// decide to rely on one, your project will be standing on the shoulder of giants.
// Maybe that's fine! But the giant might also just hickup some day, and then you'll fly right off.
// 
// The goal of GMMC is to be easy-to-use, fast and simple library intended
// for those who want to make programming languages/tools/whatever that needs to generate executable code.
// This header file exposes an API for building an intermediate representation of code that can be
// printed as straight C code or compiled into X64 machine code. The printed C code is a very direct
// translation of the API calls, making it easy to debug and understand, i.e. 
// 
//     result = gmmc_op_add(block, gmmc_op_i32(proc, 5201), gmmc_op_i32(proc, 9920));
// 
// will print out as:
// 
//     _$1 = $add_i32(5201, 9920);
// 
// You can even step through it in a debugger!
// 
// The ability to print to C also means you can still use existing compilers with
// heavy optimizations enabled to get the best performance of your code. It also means
// that you can easily target any architecture and platform that has a C compiler
// made for it (which is quite the list!).
// 
// The X64 backend is meant to be the fast path, with instant compile times and
// the ability to plug in your own debug-information to. It can also act as a learning
// resource and as an example for how to generate machine code directly without the compiler-middleman.
// Though debug performance matters, the main goal isn't to generate optimal code, but
// rather to be simple to understand with little code. The hope is to be descriptive enough with
// good names and comments to get rid of the mystery surrounding compilers and code-generation.
// 
// I hope you'll find this library useful and good luck with whatever you're making :-)
// 

#include <stdint.h>
#include <stdbool.h>

#ifndef GMMC_API
#ifdef __cplusplus
#define GMMC_API extern "C"
#else
#define GMMC_API
#endif
#endif

#ifndef gmmcString
typedef struct { uint8_t* ptr; uint64_t len; } gmmcString;
#define gmmcString gmmcString
#endif

typedef uint32_t gmmcOpIdx; // Each procedure has its own array of ops, where 1 is the first valid index.
typedef uint32_t gmmcProcIdx;
typedef uint32_t gmmcGlobalIdx; // starts from 1
typedef uint32_t gmmcExternIdx;
typedef uint32_t gmmcLocalIdx; // starts from 1
typedef u32 gmmcBasicBlockIdx;
typedef struct gmmcModule gmmcModule;
typedef struct gmmcProc gmmcProc;
typedef struct gmmcGlobal gmmcGlobal;
typedef struct gmmcProcSignature gmmcProcSignature;
typedef struct gmmcBasicBlock gmmcBasicBlock;
typedef struct gmmcSymbol gmmcSymbol;

enum { GMMC_OP_IDX_INVALID = 0 };

typedef enum gmmcOpKind {
	gmmcOpKind_Invalid = 0,
	gmmcOpKind_debugbreak,
	gmmcOpKind_comment,

	// comparisons
	gmmcOpKind_eq,
	gmmcOpKind_ne,
	gmmcOpKind_lt,
	gmmcOpKind_le,
	gmmcOpKind_gt,
	gmmcOpKind_ge,

	gmmcOpKind_load,
	gmmcOpKind_store,
	
	gmmcOpKind_local,
	
	gmmcOpKind_member_access,
	gmmcOpKind_array_access,

	// :gmmc_is_op_terminating
	gmmcOpKind_return,
	gmmcOpKind_goto,
	gmmcOpKind_if,
	
	// immediates. NOTE: the order must match the order in gmmcType!!! see :gmmc_op_immediate
	// :gmmc_is_op_immediate
	gmmcOpKind_bool,
	gmmcOpKind_i8,
	gmmcOpKind_i16,
	gmmcOpKind_i32,
	gmmcOpKind_i64,
	gmmcOpKind_i128,
	gmmcOpKind_f32,
	gmmcOpKind_f64,
	
	gmmcOpKind_add,
	gmmcOpKind_sub,
	gmmcOpKind_mul,
	gmmcOpKind_div,
	gmmcOpKind_mod,

	gmmcOpKind_fadd,
	gmmcOpKind_fsub,
	gmmcOpKind_fmul,
	gmmcOpKind_fdiv,
	
	gmmcOpKind_and,
	gmmcOpKind_or,
	gmmcOpKind_xor,
	gmmcOpKind_not,
	gmmcOpKind_shl,
	gmmcOpKind_shr,

	gmmcOpKind_int2ptr,
	gmmcOpKind_ptr2int,
	gmmcOpKind_zxt,
	gmmcOpKind_sxt,
	gmmcOpKind_trunc,

	gmmcOpKind_int2float,
	gmmcOpKind_float2int,
	gmmcOpKind_float2float,

	gmmcOpKind_addr_of_param,
	
	gmmcOpKind_call,
	gmmcOpKind_vcall,
	
	gmmcOpKind_memcpy,
	gmmcOpKind_memset,

	gmmcOpKind_addr_of_symbol,

	gmmcOpKind_COUNT,
} gmmcOpKind;

typedef enum gmmcType {
	gmmcType_None = 0,
	gmmcType_ptr = 1,
	gmmcType_bool = 2,

	// integer types
	gmmcType_i8 = 3,
	gmmcType_i16 = 4,
	gmmcType_i32 = 5,
	gmmcType_i64 = 6,
	gmmcType_i128 = 7,

	// float types
	gmmcType_f32 = 8,
	gmmcType_f64 = 9,
} gmmcType;

typedef struct gmmcOpData {
	gmmcOpKind kind;
	gmmcBasicBlockIdx bb_idx;
	gmmcType type;

	union {
		u32 local_idx; // 0 means "not a local"

		struct {
			gmmcOpIdx operands[3];
			bool is_signed;
		};
		
		struct {
			gmmcOpIdx condition;
			gmmcBasicBlockIdx true_bb;
			gmmcBasicBlockIdx false_bb;
		} if_;

		struct {
			gmmcBasicBlockIdx dst_bb;
		} goto_;

		struct {
			union { gmmcSymbol* target_sym; gmmcOpIdx target; };
			fSlice(gmmcOpIdx) arguments;
		} call;
		
		fString comment;
		gmmcSymbol* symbol;
	};
	u64 imm_bits;
} gmmcOpData;

typedef struct gmmcBasicBlock {
	gmmcModule* mod;
	gmmcProc* proc;
	gmmcBasicBlockIdx self_idx;

	fArray(gmmcOpIdx) ops;
} gmmcBasicBlock;

typedef enum gmmcSymbolKind {
	gmmcSymbolKind_Global,
	gmmcSymbolKind_Proc,
	gmmcSymbolKind_Extern,
} gmmcSymbolKind;

typedef struct gmmcProcSignature {
	gmmcType return_type;
	fSlice(gmmcType) params;
} gmmcProcSignature;

typedef struct gmmcSymbol {
	gmmcSymbolKind kind;
	gmmcModule* module;
	gmmcString name;
} gmmcSymbol;

typedef struct gmmcExtern {
	gmmcSymbol sym;
	gmmcExternIdx self_idx;
} gmmcExtern;

typedef struct gmmcLocal {
	u32 size;
	u32 align;
} gmmcLocal;

typedef struct gmmcProc {
	gmmcSymbol sym; // NOTE: must be the first member!
	gmmcProcIdx self_idx;

	gmmcProcSignature* signature;
	gmmcBasicBlock* entry_bb;

	fArray(gmmcBasicBlock*) basic_blocks;
	fArray(gmmcOpData) ops; // 0 is invalid!

	fSlice(gmmcOpIdx) params;
	fArray(gmmcLocal) locals; // gmmcLocalIdx, 0 is invalid!
} gmmcProc;

typedef struct gmmcRelocation {
	uint32_t offset;
	gmmcSymbol* target;
} gmmcRelocation;

typedef enum gmmcSection {
	gmmcSection_Code,
	gmmcSection_RData,
	gmmcSection_Data,
	//gmmcSection_Threadlocal
	// TODO: BSS section?
	gmmcSection_COUNT,
} gmmcSection;

typedef struct gmmcGlobal {
	gmmcSymbol sym; // NOTE: must be the first member!
	gmmcGlobalIdx self_idx;

	u32 size;
	u32 align;
	gmmcSection section;
	void* data;
	
	fArray(gmmcRelocation) relocations;
} gmmcGlobal;

typedef struct gmmcModule {
	fAllocator* allocator;

	fArray(gmmcProcSignature*) proc_signatures;
	fArray(gmmcGlobal*) globals; // starts from index 1, can be indexed with gmmcGlobalIdx
	fArray(gmmcProc*) procs; // can be indexed with gmmcProcIdx
	fArray(gmmcExtern*) external_symbols; // can be indexed with gmmcExternIdx

	// should we hold like an "extra sections"
	//fArray(u8) code_section;
} gmmcModule;

GMMC_API gmmcModule* gmmc_init(fAllocator* allocator);

GMMC_API void gmmc_test(); // @cleanup

//GMMC_API void gmmc_build(gmmcModule* m);

//void gmmc_deinit(gmmcModule* m);

// `parameter_sizes` will be copied internally.
// `return_type` should be `gmmcType_None` if it doesn't return a value.
GMMC_API gmmcProcSignature* gmmc_make_proc_signature(gmmcModule* m, gmmcType return_type,
	gmmcType* params, uint32_t params_count);

GMMC_API gmmcProc* gmmc_make_proc(gmmcModule* m,
	gmmcProcSignature* signature,
	gmmcString name, gmmcBasicBlock** out_entry_bb);


// need some way of mapping back from instruction offset -> op,
// I guess we could cache the offset per-op, and let the user inspect that.
// But only for ASM targets.

//GMMC_API void gmmc_proc_compile(gmmcProc* proc);
//GMMC_API void gmmc_x64_export_module(FILE* output_obj_file, gmmcModule* m);

GMMC_API void gmmc_module_print_c(fWriter* w, gmmcModule* m);
GMMC_API void gmmc_proc_print_c(fWriter* w, gmmcProc* proc);

inline gmmcSymbol* gmmc_proc_as_symbol(gmmcProc* proc) { return (gmmcSymbol*)proc; }
inline gmmcSymbol* gmmc_global_as_symbol(gmmcGlobal* global) { return (gmmcSymbol*)global; }
inline gmmcSymbol* gmmc_extern_as_symbol(gmmcExtern* extern_sym) { return (gmmcSymbol*)extern_sym; }

GMMC_API gmmcExtern* gmmc_make_extern(gmmcModule* m, gmmcString name);

// TODO: is there a way to mark the memory as executable?
GMMC_API gmmcGlobal* gmmc_make_global(gmmcModule* m, uint32_t size, uint32_t align, gmmcSection section, void** out_data);

GMMC_API gmmcBasicBlock* gmmc_make_basic_block(gmmcProc* proc);

// This will place a 64-bit relocation at the specified offset.
// The 64-bit integer that lies at `offset` will be replaced
// by the sum of itself and the runtime address of `target`.
GMMC_API void gmmc_global_add_relocation(gmmcGlobal* global, uint32_t offset, gmmcSymbol* target);

//
// -- Operations --------------------------------------------------------------
//

GMMC_API gmmcOpIdx gmmc_op_debugbreak(gmmcBasicBlock* bb);

// empty string will insert a newline
GMMC_API gmmcOpIdx gmmc_op_comment(gmmcBasicBlock* bb, fString text);

// Comparisons always return a boolean

// ==, !=
// Defined for all types
GMMC_API gmmcOpIdx gmmc_op_eq(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_ne(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);

// <, <=, >, >=
// Defined for integer and float types. `is_signed` is ignored when using floats.
GMMC_API gmmcOpIdx gmmc_op_lt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_le(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_gt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_ge(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);

// There is no alignment requirement for load / store.
// C backend note:
//     If you try to load (dereference) an invalid pointer, that is undefined behaviour in C.
//     If the C compiler can statically determine that your code dereferences e.g. a NULL pointer,
//     then it can remove the code or do whatever it wants.
//     I think our best bet is to enable -fno-delete-null-pointer-checks with clang.
GMMC_API gmmcOpIdx gmmc_op_load(gmmcBasicBlock* bb, gmmcType type, gmmcOpIdx ptr);
GMMC_API gmmcOpIdx gmmc_op_store(gmmcBasicBlock* bb, gmmcOpIdx ptr, gmmcOpIdx value);

// result = base + offset
GMMC_API gmmcOpIdx gmmc_op_member_access(gmmcBasicBlock* bb, gmmcOpIdx base, uint32_t offset);

// result = base + (index * stride)
GMMC_API gmmcOpIdx gmmc_op_array_access(gmmcBasicBlock* bb, gmmcOpIdx base_ptr, gmmcOpIdx index_i64, uint32_t stride);

GMMC_API gmmcOpIdx gmmc_op_memcpy(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx src_ptr, gmmcOpIdx size_i32);
// hmm... should we have a memmove instruction or not? On x64, it makes sense to implement memmove on user-level so idk.
GMMC_API gmmcOpIdx gmmc_op_memset(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx value_i8, gmmcOpIdx size_i32);

GMMC_API gmmcOpIdx gmmc_op_if(gmmcBasicBlock* bb, gmmcOpIdx cond_bool, gmmcBasicBlock* true_bb, gmmcBasicBlock* false_bb);
GMMC_API gmmcOpIdx gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to);

// value should be GMMC_REG_NONE if the procedure returns no value
GMMC_API gmmcOpIdx gmmc_op_return(gmmcBasicBlock* bb, gmmcOpIdx value);

// -- Convertions ---------------------------------------

// `value` must be a pointer-sized integer.
GMMC_API gmmcOpIdx gmmc_op_int2ptr(gmmcBasicBlock* bb, gmmcOpIdx value);

// the result will be a pointer-sized integer
GMMC_API gmmcOpIdx gmmc_op_ptr2int(gmmcBasicBlock* bb, gmmcOpIdx value);

GMMC_API gmmcOpIdx gmmc_op_int2int(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type, bool to_signed);

GMMC_API gmmcOpIdx gmmc_op_float2float(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type);

// * TODO: document the behaviour of how large unsigned 32-bit and 64-bit are handled.
//         There's a discrepency between the C and the X64 backend currently.
GMMC_API gmmcOpIdx gmmc_op_int2float(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type, bool from_signed);

// * TODO: document the behaviour of overflow.
// * The value will be rounded towards zero.
// * Converting from float to an unsigned 64-bit integer is a non-trivial task in X64, so at least for now
//   we only support converting floats into signed integers. Maybe we should leave it like that.
GMMC_API gmmcOpIdx gmmc_op_float2int(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType target_type/*, bool to_signed*/);

// -- Integer operations --------------------------------
// These work on any integer type, where `a` and `b` must have the same type.

// +, -, *, /, %
GMMC_API gmmcOpIdx gmmc_op_add(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_sub(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_mul(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);

// Division or modulo zero will always trap, even when using the C backend with an optimizing compiler.
GMMC_API gmmcOpIdx gmmc_op_div(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_mod(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);

// &, |, ^, ~
GMMC_API gmmcOpIdx gmmc_op_and(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_or(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_xor(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_not(gmmcBasicBlock* bb, gmmcOpIdx a);

// <<, >>
// TODO: currently it's UB to overflow, fix this!
GMMC_API gmmcOpIdx gmmc_op_shl(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx shift_u8);
GMMC_API gmmcOpIdx gmmc_op_shr(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx shift_u8);

// -- Floating point operations -------------------------
// These work on any float type, where `a` and `b` must have the same type.

GMMC_API gmmcOpIdx gmmc_op_fadd(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_fsub(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_fmul(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_fdiv(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);

// ----------------------------------------------

GMMC_API gmmcOpIdx gmmc_op_vcall(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcOpIdx proc_address,
	gmmcOpIdx* in_arguments, uint32_t in_arguments_count);

// -- Direct values ----------------------------
//
// Direct values are values that don't require any computation and such aren't tied to any specific basic block.
//
#define GMMC_BB_INDEX_NONE 0xFFFFFFFF
inline bool gmmc_is_op_direct(gmmcProc* proc, gmmcOpIdx op) { return proc->ops[op].bb_idx == GMMC_BB_INDEX_NONE; }

GMMC_API gmmcOpIdx gmmc_op_addr_of_param(gmmcProc* proc, uint32_t index);

// returns a pointer to the local
GMMC_API gmmcOpIdx gmmc_op_local(gmmcProc* proc, uint32_t size, uint32_t align);

GMMC_API gmmcOpIdx gmmc_op_addr_of_symbol(gmmcProc* proc, gmmcSymbol* symbol); // maybe we should ask for a u32 offset since we get that for free with relocations?

GMMC_API gmmcOpIdx gmmc_op_bool(gmmcProc* proc, bool value);
GMMC_API gmmcOpIdx gmmc_op_i8(gmmcProc* proc, uint8_t value);
GMMC_API gmmcOpIdx gmmc_op_i16(gmmcProc* proc, uint16_t value);
GMMC_API gmmcOpIdx gmmc_op_i32(gmmcProc* proc, uint32_t value);
GMMC_API gmmcOpIdx gmmc_op_i64(gmmcProc* proc, uint64_t value);
GMMC_API gmmcOpIdx gmmc_op_f32(gmmcProc* proc, float value);
GMMC_API gmmcOpIdx gmmc_op_f64(gmmcProc* proc, double value);
GMMC_API gmmcOpIdx gmmc_op_immediate(gmmcProc* proc, gmmcType type, void* data);


// -- Machine code target ----------------------

// IMPORTANT!!!!!!
// All GMMC sections must be 16-byte aligned. This is because globals are aligned to a certain value,
// and that alignment will be used when adding the global's data into its section.
// And so, if the section is not aligned to the largest possible alignment (16),
// the global might not get aligned correctly.

typedef struct gmmcAsmModule gmmcAsmModule;
typedef u32 gmmcAsmSectionNum;

// 'build' and 'export' are separated here to give you a chance to inspect the assembly output before exporting an object file.
// This can be useful for embedding debug information into the module; i.e. Microsoft's CodeView debug information is stored
// in a few different sections (.debug$S, .debug$T, .pdata, .xdata) in a COFF object file.

// hmm... I wonder if we should even include the COFF module with GMMC. Maybe we should just give you the generated assembly blobs

GMMC_API gmmcAsmModule* gmmc_asm_build_x64(gmmcModule* m); // TODO: pass a separate allocator

//GMMC_API void gmmc_asm_export_x64(fString obj_filepath, gmmcAsmModule* m);

// returns the offset relative to the beginning of the code-section.
GMMC_API u32 gmmc_asm_instruction_get_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx op);
GMMC_API u32 gmmc_asm_proc_get_start_offset(gmmcAsmModule* m, gmmcProc* proc);
GMMC_API u32 gmmc_asm_proc_get_end_offset(gmmcAsmModule* m, gmmcProc* proc);

// This works for both `op_local`, as well as for `op_addr_of_param`.
// For locals, this will always return a negative value, as the local
// is inside our stack frame, stack growing downwards.
// For params, this will be a positive value, as it will be in the shadow space,
// outside of our stack frame.
GMMC_API s32 gmmc_asm_get_frame_rel_offset(gmmcAsmModule* m, gmmcProc* proc, gmmcOpIdx local_or_param);

// Returns the size of the initial SUB RSP instruction.
GMMC_API u32 gmmc_asm_proc_get_prolog_size(gmmcAsmModule* m, gmmcProc* proc);

// returns the amount that is subtracted from RSP at the start of the procedure.
GMMC_API u32 gmmc_asm_proc_get_stack_frame_size(gmmcAsmModule* m, gmmcProc* proc);

// returns the offset relative to the beginning of the section this global is part of.
GMMC_API u32 gmmc_asm_global_get_offset(gmmcAsmModule* m, gmmcGlobal* global);

// NOTE: Returns a slice to the bytes of a built section. You are allowed to modify this data (i.e. for relocations).
GMMC_API gmmcString gmmc_asm_get_section_data(gmmcAsmModule* m, gmmcSection section);

GMMC_API void gmmc_asm_get_section_relocations(gmmcAsmModule* m, gmmcSection section, fSlice(gmmcRelocation)* out_relocs);

// -- Common utilities -------------------------

inline gmmcOpKind gmmc_get_op_kind(gmmcProc* proc, gmmcOpIdx op) { return proc->ops[op].kind; }
inline gmmcType gmmc_get_op_type(gmmcProc* proc, gmmcOpIdx op) { return proc->ops[op].type; }
GMMC_API u32 gmmc_type_size(gmmcType type);

inline bool gmmc_type_is_integer(gmmcType t) { return t >= gmmcType_i8 && t <= gmmcType_i128; }
inline bool gmmc_type_is_float(gmmcType t) { return t >= gmmcType_f32 && t <= gmmcType_f64; }
inline bool gmmc_is_op_terminating(gmmcOpKind op) { return op >= gmmcOpKind_return && op <= gmmcOpKind_if; }
//inline bool gmmc_is_op_immediate(gmmcOpKind op) { return op >= gmmcOpKind_bool && op <= gmmcOpKind_f64; }
