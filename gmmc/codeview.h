// microsoft codeview debug information

struct msCVLine {
	uint32_t line_num;
	uint32_t offset; // offset into the .text section
};

typedef uint32_t msCVTypeIdx;

typedef struct {
	coffString name;
	msCVTypeIdx type_idx;
	uint32_t offset_of_member;
} msCVStructMember;

typedef enum msCVTypeTag {
	msCVTypeTag_Invalid,
	msCVTypeTag_Int,
	msCVTypeTag_UnsignedInt,
	msCVTypeTag_Struct,
	msCVTypeTag_Pointer,
	msCVTypeTag_Enum,
	// TODO: fixed length arrays
} msCVTypeTag;

typedef struct {
	coffString name;
	uint32_t value; // values > 2^32 are not supported by Codeview
} msCVEnumField;

typedef struct msCVType {
	msCVTypeTag tag;
	uint32_t size;

	union {
		struct {
			coffString name;
			msCVStructMember* fields;
			uint32_t fields_count;
		} Struct;

		struct {
			msCVTypeIdx type_idx;
			bool cpp_style_reference;
		} Pointer;

		struct {
			coffString name;

			msCVEnumField* fields;
			uint32_t fields_count;
		} Enum;
	};
} msCVType;

struct msCVLocal {
	coffString name;
	u32 rsp_rel_offset;
	msCVTypeIdx type_idx; // index into the `types` array
};

struct msCVBlock {
	u32 start_offset; // block start offset into the code section
	u32 end_offset; // block end offset into the code section

	msCVBlock* child_blocks;
	u32 child_blocks_count;

	msCVLocal* locals;
	u32 locals_count;
};

struct msCVFunction {
	coffString name;
	uint32_t sym_index;
	uint32_t section_sym_index; // symbol index of the code section this function belongs to

	u8 size_of_initial_sub_rsp_instruction;
	uint32_t stack_frame_size; // describes how much is subtracted from RSP at the start of the procedure

	u32 file_idx;
	msCVLine* lines;
	u32 lines_count;

	msCVBlock block;
};

typedef struct { uint8_t bytes[32]; } coffHashSHA256;
typedef struct {
	coffString filepath;

	// You can find an implementation of the SHA256 hashing algorithm for example in
	// https://github.com/B-Con/crypto-algorithms
	coffHashSHA256 hash;
} msCVSourceFile;

struct msCVGenerateDebugInfoDesc {
	coffString obj_name; // path to the obj file. NOTE: path separators must be backslashes!!

	msCVSourceFile* files;
	u32 files_count;

	msCVFunction* functions;
	u32 functions_count;

	msCVType* types;
	u32 types_count;

	// the pdata section will have relocations that reference the xdata section,
	// so we need to know the symbol index it of it
	uint32_t xdata_section_sym_index;

	// these will be filled by coff_generate_debug_info
	struct {
		fSlice(u8) debugS;
		fSlice(coffRelocation) debugS_relocs;

		fSlice(u8) pdata;
		fSlice(coffRelocation) pdata_relocs;

		fSlice(u8) xdata;

		fSlice(u8) debugT;
	} result;
};

// The pdata and xdata sections in a COFF file describe how to deal with runtime exceptions, but
// they are also required to make walking the callstack possible (StackWalk64). Without them,
// the debugger can't read the callstack.

// NOTE: pdata and xdata sections are generated with the assumption that the first instruction of any procedure is to
// subtract the stack frame size from RSP, adding to add it back when returning.
// That should be the only way you're manipulating the stack. If you want to use alloca, sorry!

#ifdef __cplusplus
extern "C" {
#endif

void mscv_generate_debug_info(msCVGenerateDebugInfoDesc* desc, fAllocator* alc);

#ifdef __cplusplus
}
#endif