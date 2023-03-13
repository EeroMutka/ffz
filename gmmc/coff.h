// An incomplete, but hopefully useful library for generating COFF files with support for CodeView debug information.

#ifndef coffString
typedef struct { uint8_t* ptr; uint64_t len; } coffString;
#define coffString coffString
#endif

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
	coffString name;
	coffString data; // the pointer field must be set to NULL when IMAGE_SCN_CNT_UNINITIALIZED_DATA is set in Characteristics

	coffSectionCharacteristics Characteristics;

	coffRelocation* relocations;
	u32 relocations_count;
} coffSection;

typedef struct {
	coffString name;
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

#ifndef COFF_API
#ifdef __cplusplus
#define COFF_API extern "C"
#else
#define COFF_API
#endif
#endif

// creates an .obj file
COFF_API void coff_create(void(*store_result)(coffString, void*), void* store_result_userptr, coffDesc* desc);

