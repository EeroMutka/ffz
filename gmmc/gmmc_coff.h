// An incomplete, but hopefully useful library for generating COFF files with support for CodeView debug information.

typedef uint16_t coffRelocationType;
enum {
	IMAGE_REL_AMD64_ABSOLUTE = 0x0000,
	IMAGE_REL_AMD64_ADDR64 = 0x0001,
	IMAGE_REL_AMD64_ADDR32 = 0x0002,
	IMAGE_REL_AMD64_ADDR32NB = 0x0003,
	IMAGE_REL_AMD64_REL32 = 0x0004,
	IMAGE_REL_AMD64_REL32_1 = 0x0005,
	IMAGE_REL_AMD64_REL32_2 = 0x0006,
	IMAGE_REL_AMD64_REL32_3 = 0x0007,
	IMAGE_REL_AMD64_REL32_4 = 0x0008,
	IMAGE_REL_AMD64_REL32_5 = 0x0009,
	IMAGE_REL_AMD64_SECTION = 0x000A,
	IMAGE_REL_AMD64_SECREL = 0x000B,
	IMAGE_REL_AMD64_SECREL7 = 0x000C,
	IMAGE_REL_AMD64_TOKEN = 0x000D,
	IMAGE_REL_AMD64_SREL32 = 0x000E,
	IMAGE_REL_AMD64_PAIR = 0x000F,
	IMAGE_REL_AMD64_SSPAN32 = 0x0010,
	IMAGE_REL_AMD64_EHANDLER = 0x0011,
	IMAGE_REL_AMD64_IMPORT_BR = 0x0012,
	IMAGE_REL_AMD64_IMPORT_CALL = 0x0013,
	IMAGE_REL_AMD64_CFG_BR = 0x0014,
	IMAGE_REL_AMD64_CFG_BR_REX = 0x0015,
	IMAGE_REL_AMD64_CFG_CALL = 0x0016,
	IMAGE_REL_AMD64_INDIR_BR = 0x0017,
	IMAGE_REL_AMD64_INDIR_BR_REX = 0x0018,
	IMAGE_REL_AMD64_INDIR_CALL = 0x0019,
	IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_FIRST = 0x0020,
	IMAGE_REL_AMD64_INDIR_BR_SWITCHTABLE_LAST = 0x002F,
};

typedef uint32_t coffSectionCharacteristics;
enum {
	IMAGE_SCN_CNT_CODE = 0x00000020,
	IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
	IMAGE_SCN_LNK_INFO = 0x00000200,
	IMAGE_SCN_LNK_REMOVE = 0x00000800,
	IMAGE_SCN_LNK_COMDAT = 0x00001000,
	IMAGE_SCN_NO_DEFER_SPEC_EXC = 0x00004000,
	IMAGE_SCN_GPREL = 0x00008000,
	IMAGE_SCN_MEM_FARDATA = 0x00008000,
	IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
	IMAGE_SCN_MEM_16BIT = 0x00020000,
	IMAGE_SCN_MEM_LOCKED = 0x00040000,
	IMAGE_SCN_MEM_PRELOAD = 0x00080000,
	IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
	IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
	IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
	IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
	IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
	IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
	IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
	IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
	IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
	IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
	IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
	IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
	IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
	IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
	IMAGE_SCN_ALIGN_MASK = 0x00F00000,
	IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
	IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
	IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
	IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
	IMAGE_SCN_MEM_SHARED = 0x10000000,
	IMAGE_SCN_MEM_EXECUTE = 0x20000000,
	IMAGE_SCN_MEM_READ = 0x40000000,
	IMAGE_SCN_MEM_WRITE = 0x80000000,
};

typedef struct {
	uint32_t offset;
	uint32_t sym_idx;
	coffRelocationType type;
} coffRelocation;

typedef struct {
	gmmcString name;
	gmmcString data; // the pointer field must be set to NULL when IMAGE_SCN_CNT_UNINITIALIZED_DATA is set in Characteristics

	coffSectionCharacteristics Characteristics;

	coffRelocation* relocations;
	u32 relocations_count;
} coffSection;

typedef struct {
	gmmcString name;
	uint16_t section_number; // starts from 1. Special values: IMAGE_SYM_UNDEFINED (0), IMAGE_SYM_ABSOLUTE (-1), IMAGE_SYM_DEBUG (-2)
	uint16_t type; // 0x20 means 'function', 0 means 'not a function'. I don't think this matters more than that, if at all
	uint32_t value;

	bool external; // external/static
	bool is_section;

	u32 _checksum; // This field doesn't seem to matter at all, but it's still encoded in here
} coffSymbol;

typedef struct {
	coffSection* sections;
	u32 sections_count;
	
	coffSymbol* symbols;
	u32 symbols_count;
} coffDesc;

// creates an .obj file
GMMC_API void coff_create(void(*store_result)(gmmcString, void*), void* store_result_userptr, coffDesc* desc);


#ifdef GMMC_CODEVIEW

struct coffCVLine {
	uint32_t line_num;
	uint32_t offset; // offset into the .text section
};

typedef uint32_t coffCVTypeIdx;

typedef struct {
	gmmcString name;
	coffCVTypeIdx type_idx;
	uint32_t offset_of_member;
} coffCVStructMember;

typedef enum coffCVTypeTag {
	coffCVTypeTag_Invalid,
	coffCVTypeTag_Int,
	coffCVTypeTag_UnsignedInt,
	coffCVTypeTag_Struct,
	coffCVTypeTag_Pointer,
	coffCVTypeTag_Enum,
	// TODO: fixed length arrays
} coffCVTypeTag;

typedef struct {
	gmmcString name;
	uint32_t value; // values > 2^32 are not supported by Codeview
} coffCVEnumField;

typedef struct coffCVType {
	coffCVTypeTag tag;
	uint32_t size;

	union {
		struct {
			gmmcString name;
			coffCVStructMember* fields;
			uint32_t fields_count;
		} Struct;

		struct {
			coffCVTypeIdx type_idx;
			bool cpp_style_reference;
		} Pointer;

		struct {
			gmmcString name;

			coffCVEnumField* fields;
			uint32_t fields_count;
		} Enum;
	};
} coffCVType;

struct coffCVLocal {
	gmmcString name;
	u32 rsp_rel_offset;
	coffCVTypeIdx type_idx; // index into the `types` array
};

struct coffCVBlock {
	u32 start_offset; // block start offset into the .text section
	u32 end_offset; // block end offset into the .text section

	coffCVBlock* child_blocks;
	u32 child_blocks_count;

	coffCVLocal* locals;
	u32 locals_count;
};

struct coffCVFunction {
	gmmcString name;
	uint32_t sym_index;
	uint32_t code_section_sym_index;

	u8 size_of_initial_sub_rsp_instruction;

	u32 file_idx; // index into the `files` array in CodeView_GenerateDebugInfo_Desc
	coffCVLine* lines;
	u32 lines_count;

	coffCVBlock block;

	uint32_t stack_frame_size; // describes how much is subtracted from RSP at the start of the procedure
};

typedef struct { uint8_t bytes[32]; } coffHashSHA256;
typedef struct {
	gmmcString filepath;

	// You can find an implementation of the SHA256 hashing algorithm for example in
	// https://github.com/B-Con/crypto-algorithms
	coffHashSHA256 hash;
} coffCVSourceFile;

struct coffCVGenerateDebugInfoDesc {
	gmmcString obj_name; // path to the obj file. NOTE: path separators must be backslashes!!

	coffCVSourceFile* files;
	u32 files_count;

	coffCVFunction* functions;
	u32 functions_count;

	coffCVType* types;
	u32 types_count;

	uint32_t xdata_section_sym_index;
};

// The pdata and xdata sections in a COFF file describe how to deal with runtime exceptions, but
// they are also required to make walking the callstack possible (StackWalk64). Without them,
// the debugger can't read the callstack.

// NOTE: pdata and xdata sections are generated with the assumption that the first instruction of any procedure is to
// subtract the stack frame size from RSP, adding to add it back when returning.
// That should be the only way you're manipulating the stack. If you want to use alloca, sorry!

struct coffCVGenerateDebugInfoResult {
	fSlice(u8) debugS;
	fSlice(coffRelocation) debugS_relocs;

	fSlice(u8) pdata;
	fSlice(coffRelocation) pdata_relocs;
	
	fSlice(u8) xdata;
	
	fSlice(u8) debugT;
};

GMMC_API coffCVGenerateDebugInfoResult coff_generate_debug_info(coffCVGenerateDebugInfoDesc* desc, fAllocator* allocator);

#endif