// microsoft codeview debug information

struct cviewLine {
	uint32_t line_num;
	uint32_t offset; // offset into the .text section
};

typedef uint32_t cviewTypeIdx;

typedef struct {
	coffString name;
	cviewTypeIdx type_idx;
	uint32_t offset_of_member;
} cviewStructMember;

typedef enum cviewTypeTag {
	cviewTypeTag_Invalid,
	cviewTypeTag_Int,
	cviewTypeTag_UnsignedInt,
	cviewTypeTag_Record,
	cviewTypeTag_Pointer,
	cviewTypeTag_VoidPointer,
	cviewTypeTag_Enum,
	cviewTypeTag_Array,
} cviewTypeTag;

typedef struct {
	coffString name;
	uint32_t value; // values > 2^32 are not supported by Codeview
} cviewEnumField;

typedef struct cviewType {
	cviewTypeTag tag;
	uint32_t size;

	union {
		struct {
			coffString name;
			cviewStructMember* fields;
			uint32_t fields_count;
		} Record;

		struct {
			cviewTypeIdx type_idx;
			bool cpp_style_reference;
		} Pointer;

		struct {
			coffString name;

			cviewEnumField* fields;
			uint32_t fields_count;
		} Enum;

		struct {
			cviewTypeIdx elem_type_idx;
		} Array;
	};
} cviewType;

struct cviewLocal {
	coffString name;
	u32 rsp_rel_offset;
	cviewTypeIdx type_idx; // index into the `types` array
};

struct cviewBlock {
	u32 start_offset; // block start offset into the code section. QUESTION: should this include the prologue?
	u32 end_offset; // block end offset into the code section

	cviewBlock* child_blocks;
	u32 child_blocks_count;

	cviewLocal* locals;
	u32 locals_count;
};

struct cviewFunction {
	coffString name;
	uint32_t sym_index;
	uint32_t section_sym_index; // symbol index of the code section this function belongs to

	u8 size_of_initial_sub_rsp_instruction;
	uint32_t stack_frame_size; // describes how much is subtracted from RSP at the start of the procedure

	u32 file_idx;
	cviewLine* lines;
	u32 lines_count;

	cviewBlock block;
};

typedef struct { uint8_t bytes[32]; } coffHashSHA256;
typedef struct {
	coffString filepath;

	// You can find an implementation of the SHA256 hashing algorithm for example in
	// https://github.com/B-Con/crypto-algorithms
	coffHashSHA256 hash;
} cviewSourceFile;

struct cviewGenerateDebugInfoDesc {
	coffString obj_name; // path to the obj file. NOTE: path separators must be backslashes!!

	cviewSourceFile* files;
	u32 files_count;

	cviewFunction* functions;
	u32 functions_count;

	cviewType* types;
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

void codeview_generate_debug_info(cviewGenerateDebugInfoDesc* desc, fAllocator* alc);

#ifdef __cplusplus
}
#endif