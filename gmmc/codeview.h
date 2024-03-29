// microsoft codeview debug information
// I think if I ever get to doing drawf debug info, I should make a shared API to this for it

// About generics/templates:
// if you want natvis support for templated types, i.e. visualize an array / map, and you
// look at the way C++ debug info for templates is generated - there is no such thing! The template
// instantiated structs will just be named with the `<` and `>` brackets, i.e. "Vector<int>". Visual studio
// parses the name to extract the template arguments. Very convenient for us!

typedef struct cviewLine {
	uint32_t line_num;
	uint32_t offset; // offset into the .text section
} cviewLine;

typedef uint32_t cviewTypeIdx; // index into the `types` array

typedef struct cviewStructMember {
	coffString name;
	cviewTypeIdx type_idx;
	uint32_t offset_of_member;
} cviewStructMember;

typedef enum cviewTypeTag {
	cviewTypeTag_Invalid,
	cviewTypeTag_Int,
	cviewTypeTag_Float,
	cviewTypeTag_Bool,
	cviewTypeTag_UnsignedInt,
	cviewTypeTag_Record,
	cviewTypeTag_Pointer,
	cviewTypeTag_VoidPointer,
	cviewTypeTag_Enum,
	cviewTypeTag_Array,
} cviewTypeTag;

typedef struct cviewEnumField {
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

typedef struct cviewLocal {
	coffString name;
	u32 rsp_rel_offset;
	cviewTypeIdx type_idx;
} cviewLocal;

typedef struct cviewBlock {
	u32 start_offset; // block start offset into the code section. QUESTION: should this include the prologue?
	u32 end_offset; // block end offset into the code section

	struct cviewBlock* child_blocks;
	u32 child_blocks_count;

	cviewLocal* locals;
	u32 locals_count;
} cviewBlock;

typedef struct cviewGlobal {
	coffString name;
	uint32_t sym_index;
	cviewTypeIdx type_idx;
} cviewGlobal;

typedef struct cviewFunction {
	coffString name;
	uint32_t sym_index;
	uint32_t section_sym_index; // symbol index of the code section this function belongs to

	u8 size_of_initial_sub_rsp_instruction;
	uint32_t stack_frame_size; // describes how much is subtracted from RSP at the start of the procedure

	u32 file_idx;
	
	// The lines must be sorted by 'offset', in growing order
	cviewLine* lines;
	u32 lines_count;

	cviewBlock block;
} cviewFunction;

typedef struct coffHashSHA256 {
	uint8_t bytes[32];
} coffHashSHA256;

typedef struct cviewSourceFile {
	coffString filepath;

	// You can find an implementation of the SHA256 hashing algorithm for example in
	// https://github.com/B-Con/crypto-algorithms
	coffHashSHA256 hash;
} cviewSourceFile;

typedef struct cviewGenerateDebugInfoDesc {
	coffString obj_name; // path to the obj file. NOTE: path separators must be backslashes!!

	cviewSourceFile* files;
	u32 files_count;

	cviewFunction* functions;
	u32 functions_count;

	// NOTE: globals are untested
	cviewGlobal* globals;
	u32 globals_count;

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
} cviewGenerateDebugInfoDesc;

// The pdata and xdata sections in a COFF file describe how to deal with runtime exceptions, but
// they are also required to make walking the callstack possible (StackWalk64). Without them,
// the debugger can't read the callstack.

// NOTE: pdata and xdata sections are generated with the assumption that the first instruction of any procedure is to
// subtract the stack frame size from RSP, adding to add it back when returning.
// That should be the only way you're manipulating the stack. If you want to use alloca, sorry!

#ifdef __cplusplus
extern "C" {
#endif

void codeview_generate_debug_info(cviewGenerateDebugInfoDesc* desc, fArena* arena);

#ifdef __cplusplus
}
#endif