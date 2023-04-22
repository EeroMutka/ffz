#include "src/foundation/foundation.h"

#define coffString fString
#include "coff.h"
#include "codeview.h"

#define VALIDATE(x) f_assert(x)

#define _VC_VER_INC
#include "cvinfo.h"

typedef struct xdata_UnwindCode {
	u8 CodeOffset;
	u8 UnwindOp : 4;
	u8 OpInfo : 4;
} xdata_UnwindCode;

// @portability
#pragma pack(push, 1)

typedef struct _TYPTYPE {
	unsigned short len;
	unsigned short leaf;
} _TYPTYPE;

// NOTE: 1-byte alignment
typedef struct _lfEnumerate {
	unsigned short  leaf;       // LF_ENUMERATE
	CV_fldattr_t    attr;       // u16, access
	// variable length value field followed by length-prefixed name
} _lfEnumerate;

// NOTE: 1-byte alignment
typedef struct _lfArray {
	u16 len;
	unsigned short  leaf;           // LF_ARRAY
	CV_typ_t        elemtype;       // type index of element type
	CV_typ_t        idxtype;        // type index of indexing type
	// followed by variable length data specifying the size in bytes and name
} _lfArray;

// NOTE: 1-byte alignment
typedef struct _lfEnum {
	u16  len;
	unsigned short  leaf;           // LF_ENUM
	unsigned short  count;          // count of number of elements in class
	CV_prop_t       property;       // property attribute field
	CV_typ_t        utype;          // underlying type of the enum
	CV_typ_t        field;          // type index of LF_FIELD descriptor list
	// followed by a length prefixed name of the enum
} _lfEnum;

// NOTE: 1-byte alignment
typedef struct _lfMember {
	unsigned short  leaf;           // LF_MEMBER
	CV_fldattr_t    attr;           // u16, attribute mask
	unsigned long   index;          // index of type record for field
	// variable length offset of field followed by length prefixed name of field
} _lfMember;

// NOTE: 1-byte alignment
typedef struct _lfStructure {
	u16 len;
	unsigned short  leaf;           // LF_CLASS, LF_STRUCT, LF_INTERFACE
	unsigned short  count;          // count of number of elements in class
	CV_prop_t       property;       // property attribute field (prop_t)
	CV_typ_t        field;          // type index of LF_FIELD descriptor list
	CV_typ_t        derived;        // type index of derived from list if not zero
	CV_typ_t        vshape;         // type index of vshape table for this class
	// followed by data describing length of structure in bytes and name
} _lfStructure;

// NOTE: 1-byte alignment
typedef struct CV_Filedata {
	u32 offstFileName;
	u8  cbChecksum;
	u8  ChecksumType;
} CV_Filedata;

// NOTE: 1-byte alignment
typedef struct xdata_UnwindInfoHeader {
	u8 Version : 3;
	u8 Flags : 5;
	u8 SizeOfProlog;
	u8 CountOfCodes;
	u8 FrameRegister : 4;
	u8 FrameOffset : 4;
} xdata_UnwindInfoHeader;

// NOTE: 1-byte alignment
typedef struct _lfPointer { // lfPointer
	u16 reclen;
	struct {
		unsigned short      leaf;           // LF_POINTER
		CV_typ_t            utype;          // type index of the underlying type
		struct {
			unsigned long   ptrtype : 5; // ordinal specifying pointer type (CV_ptrtype_e)
			unsigned long   ptrmode : 3; // ordinal specifying pointer mode (CV_ptrmode_e)
			unsigned long   isflat32 : 1; // true if 0:32 pointer
			unsigned long   isvolatile : 1; // TRUE if volatile pointer
			unsigned long   isconst : 1; // TRUE if const pointer
			unsigned long   isunaligned : 1; // TRUE if unaligned pointer
			unsigned long   isrestrict : 1; // TRUE if restricted pointer (allow agressive opts)
			unsigned long   size : 6; // size of pointer (in bytes)
			unsigned long   ismocom : 1; // TRUE if it is a MoCOM pointer (^ or %)
			unsigned long   islref : 1; // TRUE if it is this pointer of member function with & ref-qualifier
			unsigned long   isrref : 1; // TRUE if it is this pointer of member function with && ref-qualifier
			unsigned long   unused : 10;// pad out to 32-bits for following cv_typ_t's
		} attr;
	} u;
} _lfPointer;

#pragma pack(pop)

static void pad_to_4_bytes_zero(fStringBuilder* buf) {
	f_array_resize_raw(&buf->buffer, F_ALIGN_UP_POW2(buf->buffer.len, 4), NULL, 1);
};

static void pad_to_4_bytes_LF_pad(fStringBuilder* buf) {
	uint pad = F_ALIGN_UP_POW2(buf->buffer.len, 4) - buf->buffer.len;
	if (pad >= 3) f_printb(buf->w, (u8)LF_PAD3);
	if (pad >= 2) f_printb(buf->w, (u8)LF_PAD2);
	if (pad >= 1) f_printb(buf->w, (u8)LF_PAD1);
	f_assert(F_HAS_ALIGNMENT_POW2(buf->buffer.len, 4));
};

static void append_so_called_length_prefixed_name(fStringBuilder* buf, coffString name) {
	// ...it's actually not length-prefixed. The comments just say that, because it was like that in old codeview versions.

	f_prints(buf->w, name);
	f_prints(buf->w, F_LIT("\0"));
	pad_to_4_bytes_LF_pad(buf);
}

// cbLen is the size of the subsection in bytes, not including the header itself and not including
// the padding bytes after the subsection.
static void patch_cbLen(fStringBuilder* debugS_buf, u32 subsection_base) {
	u32 cbLen = (u32)debugS_buf->buffer.len - subsection_base;
	*(u32*)((u8*)debugS_buf->buffer.data + subsection_base - 4) = cbLen;
}

static void patch_reclen(fStringBuilder* buf, u32 reclen_offset) {
	u16 len = (u16)(buf->buffer.len - (reclen_offset + 2));
	*(u16*)((u8*)buf->buffer.data + reclen_offset) = len;
}

#define byte_array_push_as_bytes(array, value) f_array_push_n_raw(array, &value, sizeof(value), 1)

static void generate_xdata_and_pdata(fArray(u8)* pdata_builder, fArray(coffRelocation)* pdata_relocs, fArray(u8)* xdata_builder, cviewGenerateDebugInfoDesc* desc) {
	f_assert(xdata_builder->len == 0);
	f_assert(pdata_builder->len == 0);
	f_assert(pdata_relocs->len == 0);

	s32 prev_sym_index = -1;
	s32 prev_fn_offset = -1;
	for (u32 i = 0; i < desc->functions_count; i++) {
		cviewFunction* fn = &desc->functions[i];
		
		// The functions must be sorted! Otherwise the linker will complain.
		VALIDATE((s32)fn->sym_index > prev_sym_index);
		VALIDATE((s32)fn->block.start_offset > prev_fn_offset);
		prev_sym_index = (s32)fn->sym_index;
		prev_fn_offset = (s32)fn->block.start_offset;

		u32 unwind_info_address = (u32)xdata_builder->len;

		// pdata
		{
			// Do we need IMAGE_REL_AMD64_ADDR32NB???
			// "In an object file, an RVA is less meaningful because
			// "memory locations are not assigned.In this case, an RVA would be an address within a section"
			// hmm.. and could we get rid of `section_sym_index` and use IMAGE_REL_AMD64_SECTION?

			{
				coffRelocation reloc = {0};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = fn->section_sym_index;
				f_array_push(pdata_relocs, reloc);

				byte_array_push_as_bytes(pdata_builder, fn->block.start_offset); // Function start address
			}
			{
				coffRelocation reloc = {0};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = fn->section_sym_index;
				f_array_push(pdata_relocs, reloc);

				byte_array_push_as_bytes(pdata_builder, fn->block.end_offset); // Function end address
			}
			{
				f_assert(desc->xdata_section_sym_index != 0);
				coffRelocation reloc = {0};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = desc->xdata_section_sym_index;
				f_array_push(pdata_relocs, reloc);

				byte_array_push_as_bytes(pdata_builder, unwind_info_address);
			}
		}

		// xdata
		{
			f_assert(fn->size_of_initial_sub_rsp_instruction > 0);

			bool is_large = fn->stack_frame_size >= 128;
			xdata_UnwindInfoHeader header = {0};
			header.Version = 1;
			header.SizeOfProlog = fn->size_of_initial_sub_rsp_instruction; // the SUB RSP, (*) instruction including the immediate takes 4 bytes
			header.CountOfCodes = is_large ? 2 : 1;
			//header.FrameRegister = 0; // use RSP as the stack base pointer
			byte_array_push_as_bytes(xdata_builder, header);

#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2

			if (is_large) {
				VALIDATE(fn->stack_frame_size < F_KIB(512));

				xdata_UnwindCode unwind_code = {0}; // "Save a nonvolatile integer register on the stack using a MOV instead of a PUSH"
				unwind_code.CodeOffset = fn->size_of_initial_sub_rsp_instruction; // offset of the end of the instruction
				unwind_code.UnwindOp = UWOP_ALLOC_LARGE;
				unwind_code.OpInfo = 0;
				byte_array_push_as_bytes(xdata_builder, unwind_code);

				// "If the operation info equals 0, then the size of the allocation divided by 8 is recorded in the next slot, allowing an allocation up to 512K - 8"
				u16 size = fn->stack_frame_size >> 3;
				f_assert(size * 8 == fn->stack_frame_size);
				byte_array_push_as_bytes(xdata_builder, size);
			}
			else {
				// op_info * 8 + 8 == fn.stack_frame_size
				u8 op_info = (fn->stack_frame_size - 8) >> 3;
				f_assert(op_info * 8 + 8 == fn->stack_frame_size);

				xdata_UnwindCode unwind_code = {0}; // "Save a nonvolatile integer register on the stack using a MOV instead of a PUSH"
				unwind_code.CodeOffset = fn->size_of_initial_sub_rsp_instruction; // offset of the end of the instruction
				unwind_code.UnwindOp = UWOP_ALLOC_SMALL;
				unwind_code.OpInfo = op_info;
				byte_array_push_as_bytes(xdata_builder, unwind_code);

				u16 padding = 0;
				byte_array_push_as_bytes(xdata_builder, padding); // NOTE: unwind code count must be a multiple of two
			}

		}
	}
}

typedef struct DebugSectionGen {
	fStringBuilder debugS;
	fArray(coffRelocation) debugS_relocs;
	fStringBuilder debugT;
	
	cviewGenerateDebugInfoDesc* desc;
} DebugSectionGen;

typedef struct TypeGen {
	CV_typ_t* struct_forward_ref_idx;
	CV_typ_t* to_codeview_type_idx;
	CV_typ_t next_cv_type_idx;
} TypeGen;

static void add_locals(DebugSectionGen* ctx, TypeGen* types, cviewFunction* fn, cviewBlock* parent) {
	for (u32 i = 0; i < parent->locals_count; i++) {
		cviewLocal local = parent->locals[i];
		VALIDATE(local.name.len < F_U16_MAX);

		REGREL32 sym = {0};
		sym.reclen = F_OFFSET_OF(REGREL32, name) - 2 + ((u16)local.name.len + 1);
		sym.rectyp = S_REGREL32;
		sym.off = local.rsp_rel_offset;
		sym.reg = CV_AMD64_RSP;

		// Our API type index to codeview type index

		sym.typind = types->to_codeview_type_idx[local.type_idx];

		f_prints(ctx->debugS.w, (fString){ (u8*)&sym, F_OFFSET_OF(REGREL32, name) });

		f_prints(ctx->debugS.w, local.name);
		f_printb(ctx->debugS.w, '\0');
	}

	for (u32 i = 0; i < parent->child_blocks_count; i++) {
		cviewBlock* block = &parent->child_blocks[i];
		{
			BLOCKSYM32 sym = {0};
			sym.reclen = sizeof(BLOCKSYM32) - 2;
			sym.rectyp = S_BLOCK32;
			sym.len = block->end_offset - block->start_offset; // block length

			sym.seg = 0; // Section number of the block. To be relocated
			{
				coffRelocation seg_reloc = {0};
				seg_reloc.offset = (u32)ctx->debugS.buffer.len + F_OFFSET_OF(BLOCKSYM32, seg);
				seg_reloc.sym_idx = fn->sym_index;
				if (seg_reloc.sym_idx == 9) f_trap();
				seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
				f_array_push(&ctx->debugS_relocs, seg_reloc);
			}

			sym.off = block->start_offset; // Start offset of the block within the section. To be relocated
			{
				coffRelocation off_reloc = {0};
				off_reloc.offset = (u32)ctx->debugS.buffer.len + F_OFFSET_OF(BLOCKSYM32, off);
				off_reloc.sym_idx = fn->sym_index;
				if (off_reloc.sym_idx == 9) f_trap();
				off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
				f_array_push(&ctx->debugS_relocs, off_reloc);
			}

			f_prints(ctx->debugS.w, F_AS_BYTES(sym));
		}

		add_locals(ctx, types, fn, block);

		{
			u16 reclen = 2;
			u16 rectyp = S_END;
			f_prints(ctx->debugS.w, F_AS_BYTES(reclen));
			f_prints(ctx->debugS.w, F_AS_BYTES(rectyp));
		}
	}
};

static void write_variable_length_number(fStringBuilder* buf, u32 number) {
	// see `PrintNumeric` in microsoft pdb dump.
	// values >= 2^32 are not supported by codeview.
	if (number < 0x8000) {
		f_prints(buf->w, (fString){(u8*)&number, 2});
	}
	else if (number < F_U16_MAX) {
		u16 prefix = LF_USHORT;
		f_prints(buf->w, F_AS_BYTES(prefix));
		f_prints(buf->w, (fString){(u8*)&number, 2});
	}
	else {
		u16 prefix = LF_ULONG;
		f_prints(buf->w, F_AS_BYTES(prefix));
		f_prints(buf->w, (fString){(u8*)&number, 4});
	}
}

static u32 generate_cv_type(DebugSectionGen* ctx, TypeGen* types, u32 index, bool root/* = false*/) {
	CV_typ_t existing = types->to_codeview_type_idx[index];
	if (existing) return existing;

	cviewType type = ctx->desc->types[index];

	CV_typ_t t = 0;
	
	switch (type.tag) {
	case cviewTypeTag_Pointer: {
		CV_typ_t pointer_to = generate_cv_type(ctx, types, type.Pointer.type_idx, false);

		_lfPointer cv_pointer = {0};
		u32 reclen_offset = (u32)ctx->debugT.buffer.len;
		cv_pointer.u.leaf = LF_POINTER;
		cv_pointer.u.utype = pointer_to;
		cv_pointer.u.attr.ptrtype = CV_PTR_64;
		cv_pointer.u.attr.ptrmode = type.Pointer.cpp_style_reference ? CV_PTR_MODE_REF : CV_PTR_MODE_PTR;
		cv_pointer.u.attr.size = 8;
		f_prints(ctx->debugT.w, F_AS_BYTES(cv_pointer));
		patch_reclen(&ctx->debugT, reclen_offset);

		t = types->next_cv_type_idx++;
	} break;
	
	case cviewTypeTag_VoidPointer: { t = T_64PVOID; } break;

	case cviewTypeTag_Bool: {
		if (type.size == 1) t = T_BOOL08;
		else if (type.size == 2) t = T_BOOL16;
		else if (type.size == 4) t = T_BOOL32;
		else if (type.size == 8) t = T_BOOL64;
		else VALIDATE(false);
	} break;

	case cviewTypeTag_Float: {
		if (type.size == 2) t = T_REAL16;
		else if (type.size == 4) t = T_REAL32;
		else if (type.size == 8) t = T_REAL64;
		else VALIDATE(false);
	} break;

	case cviewTypeTag_Int: {
		if (type.size == 1) t = T_INT1;
		else if (type.size == 2) t = T_INT2;
		else if (type.size == 4) t = T_INT4;
		else if (type.size == 8) t = T_INT8;
		else VALIDATE(false);
	} break;

	case cviewTypeTag_UnsignedInt: {
		if (type.size == 1) t = T_UINT1;
		else if (type.size == 2) t = T_UINT2;
		else if (type.size == 4) t = T_UINT4;
		else if (type.size == 8) t = T_UINT8;
		else VALIDATE(false);
	} break;
	
	case cviewTypeTag_Enum: {
		// LF_FIELDLIST
		CV_typ_t fieldlist_type_idx = 0;
		{
			_TYPTYPE cv_fieldlist = {0};
			u32 reclen_offset = (u32)ctx->debugT.buffer.len;
			cv_fieldlist.leaf = LF_FIELDLIST;
			f_prints(ctx->debugT.w, F_AS_BYTES(cv_fieldlist));

			for (uint field_i = 0; field_i < type.Enum.fields_count; field_i++) {
				f_assert(F_HAS_ALIGNMENT_POW2(ctx->debugT.buffer.len, 4));
				cviewEnumField field = type.Enum.fields[field_i];

				_lfEnumerate cv_field = {0};
				cv_field.leaf = LF_ENUMERATE;
				cv_field.attr.access = CV_public;
				f_prints(ctx->debugT.w, F_AS_BYTES(cv_field));

				write_variable_length_number(&ctx->debugT, field.value);
				append_so_called_length_prefixed_name(&ctx->debugT, field.name);
			}

			patch_reclen(&ctx->debugT, reclen_offset);

			fieldlist_type_idx = types->next_cv_type_idx++;
		}

		// LF_ENUM
		{
			_lfEnum cv_enum = {0};
			u32 reclen_offset = (u32)ctx->debugT.buffer.len;
			cv_enum.leaf = LF_ENUM;
			cv_enum.count = type.Enum.fields_count;

			VALIDATE(type.size == 1 || type.size == 2 || type.size == 4 || type.size == 8);
			cv_enum.utype = type.size == 1 ? T_UINT1 :
				type.size == 2 ? T_UINT2 :
				type.size == 4 ? T_UINT4 : T_UINT8;
			cv_enum.field = fieldlist_type_idx;
			f_prints(ctx->debugT.w, F_AS_BYTES(cv_enum));
			
			append_so_called_length_prefixed_name(&ctx->debugT, type.Enum.name);
			
			patch_reclen(&ctx->debugT, reclen_offset);
		}
		
		t = types->next_cv_type_idx++;
	} break;

	case cviewTypeTag_Array: {
		// LF_ARRAY

		CV_typ_t elem_type = generate_cv_type(ctx, types, type.Array.elem_type_idx, false);
		
		_lfArray cv_array = {0};
		u32 reclen_offset = (u32)ctx->debugT.buffer.len;
		cv_array.leaf = LF_ARRAY;
		cv_array.elemtype = elem_type;
		cv_array.idxtype = T_UQUAD; // 64-bit unsigned
		f_prints(ctx->debugT.w, F_AS_BYTES(cv_array));
		
		write_variable_length_number(&ctx->debugT, type.size);
		append_so_called_length_prefixed_name(&ctx->debugT, (fString){0});

		patch_reclen(&ctx->debugT, reclen_offset);
		
		t = types->next_cv_type_idx++;
	} break;
	
	case cviewTypeTag_Record: {
		
		// When recursing, stop the recursion by using the forward reference
		if (!root) {
			return types->struct_forward_ref_idx[index];
		}
		
		// see `strForFieldList` in the microsoft pdb dump

		// first generate the member types
		for (u32 member_i = 0; member_i < type.Record.fields_count; member_i++) {
			cviewStructMember* member = &type.Record.fields[member_i];
			generate_cv_type(ctx, types, member->type_idx, false);
		}

		// LF_FIELDLIST
		u32 fieldlist_type_idx = 0;
		{
			_TYPTYPE cv_fieldlist = {0};
			u32 reclen_offset = (u32)ctx->debugT.buffer.len;
			cv_fieldlist.leaf = LF_FIELDLIST;
			f_prints(ctx->debugT.w, F_AS_BYTES(cv_fieldlist));

			for (u32 member_i = 0; member_i < type.Record.fields_count; member_i++) {
				cviewStructMember member = type.Record.fields[member_i];

				_lfMember cv_member = {0};
				cv_member.leaf = LF_MEMBER;
				cv_member.attr.access = CV_public;

				cv_member.index = types->to_codeview_type_idx[member.type_idx]; // codeview type index
				f_assert(cv_member.index != 0);
				f_prints(ctx->debugT.w, F_AS_BYTES(cv_member));

				write_variable_length_number(&ctx->debugT, member.offset_of_member);
				append_so_called_length_prefixed_name(&ctx->debugT, member.name);
			}

			patch_reclen(&ctx->debugT, reclen_offset);

			fieldlist_type_idx = types->next_cv_type_idx++;
		}

		// LF_STRUCTURE
		{
			_lfStructure cv_structure = {0};
			u32 reclen_offset = (u32)ctx->debugT.buffer.len;

			VALIDATE(type.Record.fields_count < F_U16_MAX);
			VALIDATE(type.size < F_U16_MAX);

			cv_structure.leaf = LF_STRUCTURE;
			cv_structure.count = (u16)type.Record.fields_count;
			//cv_structure.property
			cv_structure.field = fieldlist_type_idx;
			//cv_structure.derived
			//cv_structure.vshape
			f_prints(ctx->debugT.w, F_AS_BYTES(cv_structure));

			write_variable_length_number(&ctx->debugT, type.size);
			append_so_called_length_prefixed_name(&ctx->debugT, type.Record.name);

			patch_reclen(&ctx->debugT, reclen_offset);
		}

		t = types->next_cv_type_idx++;
	} break;

	default: f_trap();
	}

	f_assert(t != 0);
	types->to_codeview_type_idx[index] = t;
	return t;
}

static u32 begin_subsection(DebugSectionGen* gen, enum DEBUG_S_SUBSECTION_TYPE type) {
	struct CV_DebugSSubsectionHeader_t subsection_header;
	subsection_header.type = type;
	f_prints(gen->debugS.w, F_AS_BYTES(subsection_header));
	
	u32 subsection_base = (u32)gen->debugS.buffer.len;
	return subsection_base;
}

static void end_subsection(DebugSectionGen* gen, u32 subsection_base) {
	patch_cbLen(&gen->debugS, subsection_base);
	pad_to_4_bytes_zero(&gen->debugS); // Subsections must be aligned to 4 byte boundaries
}

static void generate_debug_sections(DebugSectionGen* gen) {
	fAllocator* temp = f_temp_alc();

	u32 signature = CV_SIGNATURE_C13;

	// -- Types section -------------------------------------------------------

	//fString test_debugT = os_file_read_whole(F_LIT("C:\\dev\\slump\\GMMC\\minimal\\lettuce_debugT.hex"), gen->desc->allocator);
	//f_array_push_n(&gen->debugT, test_debugT);

	f_prints(gen->debugT.w, F_AS_BYTES(signature));

	TypeGen types = {0};
	// We have two different concepts of a type index. The first is the type index provided by the user of the API, pointing
	// to an element in the `CodeView_GenerateDebugInfo_Desc.types` array.
	// The second is the type index that's used in the actual compiled binary. We'll refer to the latter as "codeview type index"
	types.to_codeview_type_idx = f_mem_alloc_n(CV_typ_t, gen->desc->types_count, temp);
	memset(types.to_codeview_type_idx, 0, gen->desc->types_count * sizeof(CV_typ_t));
	
	types.struct_forward_ref_idx = f_mem_alloc_n(CV_typ_t, gen->desc->types_count, temp);
	types.next_cv_type_idx = 0x1000;

	// First create forward references for all the record types

	for (u32 i = 0; i < gen->desc->types_count; i++) {
		cviewType* type = &gen->desc->types[i];
		if (type->tag == cviewTypeTag_Record) {
			_lfStructure cv_structure = {0};
			u32 reclen_offset = (u32)gen->debugT.buffer.len;
			cv_structure.leaf = LF_STRUCTURE;
			cv_structure.property.fwdref = true;
			f_prints(gen->debugT.w, F_AS_BYTES(cv_structure));

			u16 struct_size = 0;
			f_prints(gen->debugT.w, F_AS_BYTES(struct_size));
			append_so_called_length_prefixed_name(&gen->debugT, type->Record.name);

			patch_reclen(&gen->debugT, reclen_offset);

			types.struct_forward_ref_idx[i] = types.next_cv_type_idx++;
		}
	}

	// DumpModTypC7 implementation is missing from the microsoft's PDB dump.

	for (u32 i = 0; i < gen->desc->types_count; i++) {
		generate_cv_type(gen, &types, i, true);
	}

	// -- Symbols section --------------------------------------------------------

	f_prints(gen->debugS.w, F_AS_BYTES(signature));

	// *** SYMBOLS

	{
		u32 subsection_base = begin_subsection(gen, DEBUG_S_SYMBOLS);
		
		{
			//fString name = F_LIT("C:\\dev\\slump\\GMMC\\minimal\\lettuce.obj");
			VALIDATE(!f_str_contains(gen->desc->obj_name, F_LIT("/"))); // Only backslashes are allowed!

			OBJNAMESYM objname = {0};
			u32 reclen_offset = (u32)gen->debugS.buffer.len;
			objname.rectyp = S_OBJNAME;

			f_prints(gen->debugS.w, (fString){(u8*)&objname, sizeof(OBJNAMESYM) - 1});
			f_prints(gen->debugS.w, gen->desc->obj_name);
			f_printb(gen->debugS.w, '\0');

			patch_reclen(&gen->debugS, reclen_offset);
		}
		{
			fString name = F_LIT("Microsoft (R) Optimizing Compiler"); // TODO

			u32 reclen_offset = (u32)gen->debugS.buffer.len;
			COMPILESYM3 compile3 = {0};
			compile3.rectyp = S_COMPILE3;
			compile3.machine = CV_CFL_X64;

			f_prints(gen->debugS.w, (fString){(u8*)&compile3, sizeof(compile3) - 1});
			f_prints(gen->debugS.w, name);
			f_printb(gen->debugS.w, '\0');

			patch_reclen(&gen->debugS, reclen_offset);
		}

		end_subsection(gen, subsection_base);
	}

	const u32 size_of_file_checksum_entry = 40;

	for (u32 i = 0; i < gen->desc->functions_count; i++) {
		cviewFunction* fn = &gen->desc->functions[i];

		// *** SYMBOLS
		{
			u32 subsection_base = begin_subsection(gen, DEBUG_S_SYMBOLS);

			// S_GPROC32_ID
			{
				//fString name = transmute(fString)fn->fn->dbginfo_name;
				//CodeView_Function& fn = gen->desc->functions[0];
				f_assert(fn->name.len > 0);

				PROCSYM32 proc_sym = {0};
				u32 reclen_offset = (u32)gen->debugS.buffer.len;
				proc_sym.rectyp = S_GPROC32_ID;

				proc_sym.seg = 0; // Section number of the procedure. To be relocated
				{
					coffRelocation seg_reloc = {0};
					seg_reloc.offset = reclen_offset + F_OFFSET_OF(PROCSYM32, seg);
					seg_reloc.sym_idx = fn->sym_index;
					seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
					f_array_push(&gen->debugS_relocs, seg_reloc);
				}

				proc_sym.off = 0; // Start offset of the function within the section. To be relocated
				{
					coffRelocation off_reloc = {0};
					off_reloc.offset = reclen_offset + F_OFFSET_OF(PROCSYM32, off);
					off_reloc.sym_idx = fn->sym_index;
					off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
					f_array_push(&gen->debugS_relocs, off_reloc);
				}

				// in cvdump, this is the "Cb" field. This marks the size of the function in the .text section, in bytes.
				proc_sym.len = fn->block.end_offset - fn->block.start_offset;

				proc_sym.typind = 0; // this is an index of the symbol's type
				proc_sym.DbgStart = 0; // this seems to always be zero
				proc_sym.DbgEnd = proc_sym.len - 1; // this seems to usually (not always) be PROCSYM32.len - 1. Not sure what this means.

				f_prints(gen->debugS.w, (fString){(u8*)&proc_sym, sizeof(proc_sym) - 1});
				f_prints(gen->debugS.w, fn->name);
				f_printb(gen->debugS.w, '\0');

				patch_reclen(&gen->debugS, reclen_offset);
			}

			// S_FRAMEPROC

			{
				// see C7FrameProc (microsoft's pdb source code dump)
				FRAMEPROCSYM frameproc = {0};
				frameproc.rectyp = S_FRAMEPROC;
				frameproc.reclen = sizeof(FRAMEPROCSYM) - 2;
				frameproc.cbFrame = fn->stack_frame_size; // size of the stack frame
				frameproc.cbPad = 0;
				frameproc.offPad = 0;
				frameproc.cbSaveRegs = 0;
				frameproc.sectExHdlr = 0;
				frameproc.offExHdlr = 0;
				frameproc.flags.fAsyncEH = 1;
				frameproc.flags.fOptSpeed = 1;
				frameproc.flags.encodedLocalBasePointer = 1; // 0=none, 1=RSP, 2=RBP, 3=R13  (rgszRegAMD64[rgFramePointerRegX64[encodedLocalBasePointer]])
				frameproc.flags.encodedParamBasePointer = 1; // same encoding as above
				f_prints(gen->debugS.w, F_AS_BYTES(frameproc));
			}

			add_locals(gen, &types, fn, &fn->block);

			// S_PROC_ID_END
			{
				SYMTYPE sym;
				u32 reclen_offset = (u32)gen->debugS.buffer.len;
				sym.rectyp = S_PROC_ID_END;
				f_prints(gen->debugS.w, F_AS_BYTES(sym));
				patch_reclen(&gen->debugS, reclen_offset);
			}
			
			end_subsection(gen, subsection_base);
		}

		// *** LINES
		{
			// see DumpModC13Lines (microsoft's pdb source code dump)

			u32 subsection_base = begin_subsection(gen, DEBUG_S_LINES);

			{
				struct CV_DebugSLinesHeader_t lines_header;

				lines_header.segCon = 0; // Section number containing the code. To be relocated
				{
					coffRelocation seg_reloc = {0};
					seg_reloc.offset = (u32)gen->debugS.buffer.len + F_OFFSET_OF(struct CV_DebugSLinesHeader_t, segCon);
					seg_reloc.sym_idx = fn->sym_index;
					seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
					f_array_push(&gen->debugS_relocs, seg_reloc);
				}

				lines_header.offCon = 0; // Start offset of the function within the section. To be relocated
				{
					coffRelocation off_reloc = {0};
					off_reloc.offset = (u32)gen->debugS.buffer.len + F_OFFSET_OF(struct CV_DebugSLinesHeader_t, offCon);
					off_reloc.sym_idx = fn->sym_index;
					off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
					f_array_push(&gen->debugS_relocs, off_reloc);
				}

				lines_header.flags = 0;
				lines_header.cbCon = fn->block.end_offset - fn->block.start_offset;
				f_prints(gen->debugS.w, F_AS_BYTES(lines_header));

				struct {
					u32 fileid;
					u32 nLines;
					u32 cbFileBlock; // length of the file block, including the file block header
				} file_block_header;

				file_block_header.fileid = size_of_file_checksum_entry * fn->file_idx; // the 'fileid' seems to encode the offset into the FILECHKSUMS subsection
				file_block_header.nLines = (u32)fn->lines_count;
				file_block_header.cbFileBlock = sizeof(file_block_header) + file_block_header.nLines * sizeof(struct CV_Line_t);
				f_prints(gen->debugS.w, F_AS_BYTES(file_block_header));

				// add the lines

				u32 prev_line_offset = fn->block.start_offset;
				for (u32 i = 0; i < fn->lines_count; i++) {
					cviewLine* line = &fn->lines[i];

					struct CV_Line_t l = {0};
					l.linenumStart = line->line_num;
					// line.deltaLineEnd is only used when column information is stored

					VALIDATE(line->offset >= prev_line_offset); // The lines must be sorted by offset
					prev_line_offset = line->offset;

					l.offset = line->offset - fn->block.start_offset; // This offset is relative to lines_header.offCon (the start offset of the function)

					l.fStatement = 1; // not sure what this field means in practice
					f_prints(gen->debugS.w, F_AS_BYTES(l));
				}
			}

			end_subsection(gen, subsection_base);
		}
	}

	// *** SYMBOLS

	if (gen->desc->globals_count > 0) {
		u32 subsection_base = begin_subsection(gen, DEBUG_S_SYMBOLS);
		
		for (uint i = 0; i < gen->desc->globals_count; i++) {
			cviewGlobal* global = &gen->desc->globals[i];
			
			u32 reclen_offset = (u32)gen->debugS.buffer.len;
			DATASYM32 sym = {0};
			sym.rectyp = S_GDATA32;
			sym.typind = types.to_codeview_type_idx[global->type_idx];

			sym.seg = 0; // Section number of the procedure. To be relocated
			{
				coffRelocation seg_reloc = {0};
				seg_reloc.offset = reclen_offset + F_OFFSET_OF(DATASYM32, seg);
				seg_reloc.sym_idx = global->sym_index;
				seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
				f_array_push(&gen->debugS_relocs, seg_reloc);
			}

			sym.off = 0; // Start offset of the function within the section. To be relocated
			{
				coffRelocation off_reloc = {0};
				off_reloc.offset = reclen_offset + F_OFFSET_OF(DATASYM32, off);
				off_reloc.sym_idx = global->sym_index;
				off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
				f_array_push(&gen->debugS_relocs, off_reloc);
			}

			f_prints(gen->debugS.w, (fString){(u8*)&sym, sizeof(sym) - 1});
			f_prints(gen->debugS.w, global->name);
			f_printb(gen->debugS.w, '\0');

			patch_reclen(&gen->debugS, reclen_offset);
		}

		end_subsection(gen, subsection_base);
	}


	// *** SYMBOLS
	// S_UDT, not sure if this symbol subsection is needed / what it does
#if 0	
	{
		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_SYMBOLS;
		// subsection_header.cbLen
		byte_array_push_as_bytes(&gen->debugS, subsection_header);
		u32 subsection_base = (u32)gen->debugS->len;

		{
			UDTSYM sym = {};
			sym.rectyp = S_UDT;
			sym.typind = 0x1001;
			f_trap();

			u32 reclen_offset = (u32)gen->debugS->len;
			f_array_push_n(&gen->debugS, { (u8*)&sym, F_OFFSET_OF(UDTSYM, name) });
			f_array_push_n(&gen->debugS, F_LIT("MyStruct"));
			f_array_push(&gen->debugS, (u8)'\0');

			sym.reclen = (u16)(gen->debugS->len - (base + 2));
			f_slice_copy(f_slice(*gen->debugS, base, base + 2), F_AS_BYTES(sym.reclen));
		}

		patch_cbLen(&gen->debugS, subsection_base);

		AlignTo4Bytes(gen->debugS); // Subsections must be aligned to 4 byte boundaries.
	}
#endif

	fArray(u8) string_table = f_array_make(temp);
	f_array_push(&string_table, (u8){0}); // Strings seem to begin at index 1

	// *** FILECHKSUMS
	{
		// see DumpModFileChecksums (microsoft's pdb source code dump)
		u32 subsection_base = begin_subsection(gen, DEBUG_S_FILECHKSMS);

		for (uint i = 0; i < gen->desc->files_count; i++) {
			cviewSourceFile* file = &gen->desc->files[i];

			uint len_before = gen->debugS.buffer.len;
			CV_Filedata filedata;

			filedata.offstFileName = (u32)string_table.len; // offset to the filename in the string table
			filedata.cbChecksum = 32; // size of the checksum, in bytes. A SHA256 hash is 32-bytes long
			filedata.ChecksumType = CHKSUM_TYPE_SHA_256;

			VALIDATE(!f_str_contains(file->filepath, F_LIT("/"))); // Only backslashes are allowed!

			f_array_push_n_raw(&string_table, file->filepath.data, file->filepath.len, 1);
			f_array_push(&string_table, (u8){0});

			f_prints(gen->debugS.w, F_AS_BYTES(filedata));

			//f_assert(gen->desc->dbginfo->file_hashes);

			f_prints(gen->debugS.w, F_AS_BYTES(file->hash));

			pad_to_4_bytes_zero(&gen->debugS); // Each entry is aligned to 4 byte boundary

			f_assert(gen->debugS.buffer.len - len_before == size_of_file_checksum_entry);
		}

		end_subsection(gen, subsection_base);
	}

	// *** STRINGTABLE

	{
		// see DumpModStringTable (microsoft's pdb source code dump)
		u32 subsection_base = begin_subsection(gen, DEBUG_S_STRINGTABLE);
		f_prints(gen->debugS.w, (fString){string_table.data, string_table.len});
		end_subsection(gen, subsection_base);
	}
}

void codeview_generate_debug_info(cviewGenerateDebugInfoDesc* desc, fAllocator* alc) {
	// See DumpObjFileSections from the microsoft's pdb source code dump.

	DebugSectionGen gen = {0};
	
	f_init_string_builder(&gen.debugS, alc);
	f_init_string_builder(&gen.debugT, alc);
	
	gen.debugS_relocs = f_array_make(alc);
	gen.desc = desc;
	generate_debug_sections(&gen);

	fArray(coffRelocation) pdata_relocs = f_array_make(alc);
	fArray(u8) pdata_builder = f_array_make(alc);
	fArray(u8) xdata_builder = f_array_make(alc);
	generate_xdata_and_pdata(&pdata_builder, &pdata_relocs, &xdata_builder, desc);

	desc->result.debugS = gen.debugS.buffer.slice;
	desc->result.debugS_relocs = gen.debugS_relocs.slice;
	desc->result.pdata = pdata_builder.slice;
	desc->result.pdata_relocs = pdata_relocs.slice;
	desc->result.xdata = xdata_builder.slice;
	desc->result.debugT = gen.debugT.buffer.slice;
}

