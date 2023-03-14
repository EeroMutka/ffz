// Give Me Machine Code
// 
// Compilers and code generators can seem like a dark art.
// In reality, it's just kind of a chore that not so many people, apart from the LLVM team,
// have taken upon themselves. The main difficulty is that a lot of these things
// aren't documented very well (I'm looking at you, microsoft's debug-info format!),
// and that the existing code bases are difficult and complicated, and there is just a lack of
// capable tools and documentation in this area.
// 
// Goal:
// The goal of GMMC is to both act both as a learning resource
// for someone who wants to know how their source code translates
// into X64 instructions and executables files, as well as an easy-to-use
// library to generate machine code that runs directly on your CPU.
// This is also much of an area of research for me. Coming into this, I didn't really
// know that much about compilers or code generation, so please forgive and let me know
// if you think I'm doing something really stupid. I will try to leave a
// lot of informational comments, as well as use a programming style that is easy
// to follow (link to orthodox C++). I hope you'll find this useful :-)
// 

// Random resources:
// Fast register allocation: https://www.mattkeeter.com/blog/2022-10-04-ssra/

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h> // for FILE*

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

	// :gmmc_op_is_terminating
	gmmcOpKind_return,
	gmmcOpKind_goto,
	gmmcOpKind_if,
	
	// immediates. NOTE: the order must match the order in gmmcType!!! see :gmmc_op_immediate
	// :gmmc_op_is_immediate
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

	gmmcOpKind_addr_of_param,
	
	gmmcOpKind_call,
	gmmcOpKind_vcall,
	
	gmmcOpKind_memmove,
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
	
	gmmcType type;

	union {
		u32 local_idx; // 0 means "not a local"

		struct {
			gmmcOpIdx operands[3];
			bool is_signed;
		};
		
		struct {
			gmmcOpIdx condition;
			gmmcBasicBlock* dst_bb[2];
		} if_;

		struct {
			gmmcBasicBlock* dst_bb;
		} goto_;

		struct {
			union { gmmcSymbol* target_sym; gmmcOpIdx target; };
			fSlice(gmmcOpIdx) arguments;
		} call;
		
		fString comment;
		gmmcSymbol* symbol;
	};
	u64 imm_raw;
} gmmcOpData;

typedef struct gmmcBasicBlock {
	gmmcModule* mod;
	gmmcProc* proc;
	u32 bb_index;

	fArray(gmmcOpIdx) ops;

	//struct {
	//	u32 code_section_offset; // U32_MAX if not been built yet
	//	u32 code_section_end_offset;
	//} gen;
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
	fArray(gmmcLocal) locals; // 0 is invalid!
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
	gmmcGlobalIdx self_idx; // TODO: get rid of this / use gmmcGlobalIdx instead everywhere?

	u32 size;
	u32 align;
	gmmcSection section;
	void* data;

	fArray(gmmcRelocation) relocations;
} gmmcGlobal;

typedef struct gmmcModule {
	fAllocator* allocator;

	fArray(gmmcProcSignature*) proc_signatures;
	fArray(gmmcGlobal*) globals; // starts from index 1
	fArray(gmmcProc*) procs;
	fArray(gmmcSymbol*) external_symbols;

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

GMMC_API void gmmc_module_print_c(FILE* b, gmmcModule* m);
GMMC_API void gmmc_proc_print_c(FILE* b, gmmcProc* proc);

inline gmmcSymbol* gmmc_proc_as_symbol(gmmcProc* proc) { return (gmmcSymbol*)proc; }
inline gmmcSymbol* gmmc_global_as_symbol(gmmcGlobal* global) { return (gmmcSymbol*)global; }

GMMC_API gmmcSymbol* gmmc_make_external_symbol(gmmcModule* m, gmmcString name);

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
GMMC_API gmmcOpIdx gmmc_op_eq(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_ne(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);

// <, <=, >, >=
GMMC_API gmmcOpIdx gmmc_op_lt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_le(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_gt(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_ge(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);

// TODO: add align? for SIMD types?
GMMC_API gmmcOpIdx gmmc_op_load(gmmcBasicBlock* bb, gmmcType type, gmmcOpIdx ptr);
GMMC_API gmmcOpIdx gmmc_op_store(gmmcBasicBlock* bb, gmmcOpIdx ptr, gmmcOpIdx value);

// result = base + offset
GMMC_API gmmcOpIdx gmmc_op_member_access(gmmcBasicBlock* bb, gmmcOpIdx base, uint32_t offset);

// result = base + (index * stride)
GMMC_API gmmcOpIdx gmmc_op_array_access(gmmcBasicBlock* bb, gmmcOpIdx base, gmmcOpIdx index, uint32_t stride);

// `size` can be any integer type
GMMC_API gmmcOpIdx gmmc_op_memmove(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx src_ptr, gmmcOpIdx size);
GMMC_API gmmcOpIdx gmmc_op_memset(gmmcBasicBlock* bb, gmmcOpIdx dst_ptr, gmmcOpIdx value_i8, gmmcOpIdx size);

GMMC_API gmmcOpIdx gmmc_op_if(gmmcBasicBlock* bb, gmmcOpIdx cond_bool, gmmcBasicBlock* true_bb, gmmcBasicBlock* false_bb);
GMMC_API gmmcOpIdx gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to);

// value should be GMMC_REG_NONE if the procedure returns no value
GMMC_API gmmcOpIdx gmmc_op_return(gmmcBasicBlock* bb, gmmcOpIdx value);

GMMC_API gmmcOpIdx gmmc_op_int2ptr(gmmcBasicBlock* bb, gmmcOpIdx value);
GMMC_API gmmcOpIdx gmmc_op_ptr2int(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type);
GMMC_API gmmcOpIdx gmmc_op_zxt(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type);
GMMC_API gmmcOpIdx gmmc_op_sxt(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type);
GMMC_API gmmcOpIdx gmmc_op_trunc(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcType type);

// -- Immediates --------------------------------

// TODO: make immediates not part of a basic block, like with locals/addr_of_symbol
GMMC_API gmmcOpIdx gmmc_op_bool(gmmcBasicBlock* bb, bool value);
GMMC_API gmmcOpIdx gmmc_op_i8(gmmcBasicBlock* bb, uint8_t value);
GMMC_API gmmcOpIdx gmmc_op_i16(gmmcBasicBlock* bb, uint16_t value);
GMMC_API gmmcOpIdx gmmc_op_i32(gmmcBasicBlock* bb, uint32_t value);
GMMC_API gmmcOpIdx gmmc_op_i64(gmmcBasicBlock* bb, uint64_t value);
GMMC_API gmmcOpIdx gmmc_op_f32(gmmcBasicBlock* bb, float value);
GMMC_API gmmcOpIdx gmmc_op_f64(gmmcBasicBlock* bb, double value);
GMMC_API gmmcOpIdx gmmc_op_immediate(gmmcBasicBlock* bb, gmmcType type, void* data);

// -- Arithmetic --------------------------------
// Arithmetic ops work on any integer and float type, where both inputs must have the same type.

GMMC_API gmmcOpIdx gmmc_op_add(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_sub(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_mul(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);
GMMC_API gmmcOpIdx gmmc_op_div(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);

// `mod` doesn't work with float types
GMMC_API gmmcOpIdx gmmc_op_mod(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b, bool is_signed);

// ----------------------------------------------

GMMC_API gmmcOpIdx gmmc_op_and(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_or(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_xor(gmmcBasicBlock* bb, gmmcOpIdx a, gmmcOpIdx b);
GMMC_API gmmcOpIdx gmmc_op_not(gmmcBasicBlock* bb, gmmcOpIdx value);
GMMC_API gmmcOpIdx gmmc_op_shl(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcOpIdx shift);
GMMC_API gmmcOpIdx gmmc_op_shr(gmmcBasicBlock* bb, gmmcOpIdx value, gmmcOpIdx shift);



GMMC_API gmmcOpIdx gmmc_op_call(gmmcBasicBlock* bb, gmmcType return_type, gmmcSymbol* procedure,
	gmmcOpIdx* in_arguments, uint32_t in_arguments_count);

GMMC_API gmmcOpIdx gmmc_op_vcall(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcOpIdx proc_address,
	gmmcOpIdx* in_arguments, uint32_t in_arguments_count);

//GMMC_API gmmcOpIdx gmmc_op_param(gmmcProc* proc, uint32_t index);
GMMC_API gmmcOpIdx gmmc_op_addr_of_param(gmmcProc* proc, uint32_t index);

// returns a pointer to the local
GMMC_API gmmcOpIdx gmmc_op_local(gmmcProc* proc, uint32_t size, uint32_t align);

// TODO: make this not part of a basic block
GMMC_API gmmcOpIdx gmmc_op_addr_of_symbol(gmmcBasicBlock* bb, gmmcSymbol* symbol); // maybe we should ask for a u32 offset since we get that for free with relocations?


// -- Machine code target ----------------------

// IMPORTANT!!!!!!
// All GMMC sections must be 16-byte aligned. This is because globals are aligned to a certain value,
// and that alignment will be used when adding the global's data into its section.
// And so, if the section is not aligned to the largest possible alignment (16),
// the global might not get aligned correctly.

typedef struct gmmcAsmModule gmmcAsmModule;
typedef u32 gmmcAsmSectionNum;

// The runtime address of `target_section` will be added to the
// 64-bit integer value that lies at `offset`.
typedef struct gmmcAsmRelocation {
	u32 offset;
	gmmcSection target_section;
} gmmcAsmRelocation;

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

// returns the size of the initial SUB RSP instruction
GMMC_API u32 gmmc_asm_proc_get_prolog_size(gmmcAsmModule* m, gmmcProc* proc);

// returns the amount that is subtracted from RSP at the start of the procedure.
GMMC_API u32 gmmc_asm_proc_get_stack_frame_size(gmmcAsmModule* m, gmmcProc* proc);

GMMC_API gmmcString gmmc_asm_get_section_data(gmmcAsmModule* m, gmmcSection section);
GMMC_API void gmmc_asm_get_section_relocations(gmmcAsmModule* m, gmmcSection section, fSlice(gmmcAsmRelocation)* out_relocs);

// -- Common utilities -------------------------

inline gmmcOpKind gmmc_op_get_kind(gmmcProc* proc, gmmcOpIdx op) { return proc->ops[op].kind; }
inline gmmcType gmmc_op_get_type(gmmcProc* proc, gmmcOpIdx op) { return proc->ops[op].type; }
GMMC_API u32 gmmc_type_size(gmmcType type);

inline bool gmmc_type_is_integer(gmmcType t) { return t >= gmmcType_i8 && t <= gmmcType_i128; }
inline bool gmmc_type_is_float(gmmcType t) { return t >= gmmcType_f32 && t <= gmmcType_f64; }
inline bool gmmc_op_is_terminating(gmmcOpKind op) { return op >= gmmcOpKind_return && op <= gmmcOpKind_if; }
inline bool gmmc_op_is_immediate(gmmcOpKind op) { return op >= gmmcOpKind_bool && op <= gmmcOpKind_f64; }
