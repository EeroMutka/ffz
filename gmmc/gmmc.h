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

typedef uint32_t gmmcReg;
typedef struct gmmcModule gmmcModule;
typedef struct gmmcProc gmmcProc;
typedef struct gmmcGlobal gmmcGlobal;
typedef struct gmmcProcSignature gmmcProcSignature;
typedef struct gmmcBasicBlock gmmcBasicBlock;
typedef struct gmmcSymbol gmmcSymbol;

enum { GMMC_REG_NONE = 0 };

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

	// :gmmc_op_is_terminating
	gmmcOpKind_ret,
	gmmcOpKind_goto,
	gmmcOpKind_if,
	
	// immediates
	gmmcOpKind_bool,
	gmmcOpKind_i8,
	gmmcOpKind_i16,
	gmmcOpKind_i32,
	gmmcOpKind_i64,
	
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

	gmmcOpKind_call,
	gmmcOpKind_vcall,
	
	gmmcOpKind_memmove,
	gmmcOpKind_memset,

	gmmcOpKind_addr_of_symbol,

	gmmcOpKind_COUNT,
} gmmcOpKind;

typedef struct gmmcOp {
	gmmcOpKind kind;
	gmmcReg result;

	union {
		struct {
			gmmcReg operands[3];
			bool is_signed;
		};

		struct {
			gmmcReg condition;
			gmmcBasicBlock* dst_bb[2];
		} if_;

		struct {
			gmmcBasicBlock* dst_bb;
		} goto_;

		struct {
			union { gmmcSymbol* target_sym; gmmcReg target_reg; };
			fSlice(gmmcReg) arguments;
		} call;
		
		fString comment;
		gmmcSymbol* symbol;
		u64 imm;
	};
} gmmcOp;

typedef enum {
	gmmcType_None = 0,
	gmmcType_bool = 1,
	gmmcType_ptr = 2,
	
	// integer types
	gmmcType_i8 = 3,
	gmmcType_i16 = 4,
	gmmcType_i32 = 5,
	gmmcType_i64 = 6,
	gmmcType_i128 = 7,
} gmmcType;

inline bool gmmc_type_is_integer(gmmcType t) { return t >= gmmcType_i8 && t <= gmmcType_i128; }

typedef enum {
	gmmcSection_Invalid = 0,
	gmmcSection_RData = 1,
	gmmcSection_RWData = 2,
	gmmcSection_Code = 3,
} gmmcSection;

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

GMMC_API void gmmc_proc_compile(gmmcProc* proc);

GMMC_API void gmmc_module_print(fArray(u8)* b, gmmcModule* m);
GMMC_API void gmmc_proc_print(fArray(u8)* b, gmmcProc* proc);

inline gmmcSymbol* gmmc_proc_as_symbol(gmmcProc* proc) { return (gmmcSymbol*)proc; }
inline gmmcSymbol* gmmc_global_as_symbol(gmmcGlobal* global) { return (gmmcSymbol*)global; }

GMMC_API gmmcSymbol* gmmc_make_external_symbol(gmmcModule* m, gmmcString name);

// TODO: is there a way to mark the memory as executable?
GMMC_API gmmcGlobal* gmmc_make_global(gmmcModule* m, uint32_t size, uint32_t align, bool readonly, void** out_data);

GMMC_API gmmcBasicBlock* gmmc_make_basic_block(gmmcProc* proc);

// This will place a 64-bit relocation at the specified offset.
// The 64-bit integer that lies at `offset` will be replaced
// by the sum of itself and the runtime address of `target`.
GMMC_API void gmmc_global_add_relocation(gmmcGlobal* global, uint32_t offset, gmmcSymbol* target);

//
// -- Operations --------------------------------------------------------------
//

GMMC_API void gmmc_op_debugbreak(gmmcBasicBlock* bb);

// empty string will insert a newline
GMMC_API void gmmc_op_comment(gmmcBasicBlock* bb, fString text);

// Comparisons always return a boolean

// ==, !=
GMMC_API gmmcReg gmmc_op_eq(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);
GMMC_API gmmcReg gmmc_op_ne(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);

// <, <=, >, >=
GMMC_API gmmcReg gmmc_op_lt(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);
GMMC_API gmmcReg gmmc_op_le(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);
GMMC_API gmmcReg gmmc_op_gt(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);
GMMC_API gmmcReg gmmc_op_ge(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);

// TODO: add align? for SIMD types?
GMMC_API gmmcReg gmmc_op_load(gmmcBasicBlock* bb, gmmcType type, gmmcReg ptr);
GMMC_API void gmmc_op_store(gmmcBasicBlock* bb, gmmcReg ptr, gmmcReg value);

// result = base + offset
GMMC_API gmmcReg gmmc_op_member_access(gmmcBasicBlock* bb, gmmcReg base, uint32_t offset);

// result = base + (index * stride)
GMMC_API gmmcReg gmmc_op_array_access(gmmcBasicBlock* bb, gmmcReg base, gmmcReg index, uint32_t stride);

// `size` can be any integer type
GMMC_API void gmmc_op_memmove(gmmcBasicBlock* bb, gmmcReg dst_ptr, gmmcReg src_ptr, gmmcReg size);
GMMC_API void gmmc_op_memset(gmmcBasicBlock* bb, gmmcReg dst_ptr, gmmcReg value_i8, gmmcReg size);

GMMC_API void gmmc_op_if(gmmcBasicBlock* bb, gmmcReg cond_bool, gmmcBasicBlock* true_bb, gmmcBasicBlock* false_bb);
GMMC_API void gmmc_op_goto(gmmcBasicBlock* bb, gmmcBasicBlock* to);

// value should be GMMC_REG_NONE if the procedure returns no value
GMMC_API void gmmc_op_return(gmmcBasicBlock* bb, gmmcReg value);

GMMC_API gmmcReg gmmc_op_int2ptr(gmmcBasicBlock* bb, gmmcReg value);
GMMC_API gmmcReg gmmc_op_ptr2int(gmmcBasicBlock* bb, gmmcReg value, gmmcType type);
GMMC_API gmmcReg gmmc_op_zxt(gmmcBasicBlock* bb, gmmcReg value, gmmcType type);
GMMC_API gmmcReg gmmc_op_sxt(gmmcBasicBlock* bb, gmmcReg value, gmmcType type);
GMMC_API gmmcReg gmmc_op_trunc(gmmcBasicBlock* bb, gmmcReg value, gmmcType type);

// -- Immediates --------------------------------

GMMC_API gmmcReg gmmc_op_bool(gmmcBasicBlock* bb, bool value);
GMMC_API gmmcReg gmmc_op_i8(gmmcBasicBlock* bb, uint8_t value);
GMMC_API gmmcReg gmmc_op_i16(gmmcBasicBlock* bb, uint16_t value);
GMMC_API gmmcReg gmmc_op_i32(gmmcBasicBlock* bb, uint32_t value);
GMMC_API gmmcReg gmmc_op_i64(gmmcBasicBlock* bb, uint64_t value);

// -- Arithmetic --------------------------------
// Arithmetic ops work on any integer and float type, where both inputs must have the same type.

GMMC_API gmmcReg gmmc_op_add(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);
GMMC_API gmmcReg gmmc_op_sub(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);
GMMC_API gmmcReg gmmc_op_mul(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);
GMMC_API gmmcReg gmmc_op_div(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);

// `mod` doesn't work with float types
GMMC_API gmmcReg gmmc_op_mod(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b, bool is_signed);

// ----------------------------------------------

GMMC_API gmmcReg gmmc_op_and(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);
GMMC_API gmmcReg gmmc_op_or(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);
GMMC_API gmmcReg gmmc_op_xor(gmmcBasicBlock* bb, gmmcReg a, gmmcReg b);
GMMC_API gmmcReg gmmc_op_not(gmmcBasicBlock* bb, gmmcReg value);
GMMC_API gmmcReg gmmc_op_shl(gmmcBasicBlock* bb, gmmcReg value, gmmcReg shift);
GMMC_API gmmcReg gmmc_op_shr(gmmcBasicBlock* bb, gmmcReg value, gmmcReg shift);



GMMC_API gmmcReg gmmc_op_call(gmmcBasicBlock* bb, gmmcType return_type, gmmcSymbol* procedure,
	gmmcReg* in_arguments, uint32_t in_arguments_count);

GMMC_API gmmcReg gmmc_op_vcall(gmmcBasicBlock* bb,
	gmmcType return_type, gmmcReg proc_address,
	gmmcReg* in_arguments, uint32_t in_arguments_count);

GMMC_API gmmcReg gmmc_op_param(gmmcProc* proc, uint32_t index);

// returns a pointer to the local
GMMC_API gmmcReg gmmc_op_local(gmmcProc* proc, uint32_t size, uint32_t align);

GMMC_API gmmcReg gmmc_op_addr_of_symbol(gmmcBasicBlock* bb, gmmcSymbol* symbol);
