#include "src/foundation/foundation.hpp"

#define coffString fString
#include "coff.h"
#include "codeview.h"

#define VALIDATE(x) F_ASSERT(x)

#define _VC_VER_INC
#include "cvinfo.h"

struct xdata_UnwindCode {
	u8 CodeOffset;
	u8 UnwindOp : 4;
	u8 OpInfo : 4;
};

#pragma pack(push, 1)

struct _TYPTYPE {
	unsigned short len;
	unsigned short leaf;
};

// NOTE: 1-byte alignment
struct _lfArray {
	u16 len;
	unsigned short  leaf;           // LF_ARRAY
	CV_typ_t        elemtype;       // type index of element type
	CV_typ_t        idxtype;        // type index of indexing type
	// followed by variable length data specifying the size in bytes and name
};

// NOTE: 1-byte alignment
struct _lfEnum {
	u16  len;
	unsigned short  leaf;           // LF_ENUM
	unsigned short  count;          // count of number of elements in class
	CV_prop_t       property;       // property attribute field
	CV_typ_t        utype;          // underlying type of the enum
	CV_typ_t        field;          // type index of LF_FIELD descriptor list
	// followed by a length prefixed name of the enum
};

// NOTE: 1-byte alignment
struct _lfMember {
	unsigned short  leaf;           // LF_MEMBER
	CV_fldattr_t    attr;           // u16, attribute mask
	unsigned long   index;          // index of type record for field
	// variable length offset of field followed by length prefixed name of field
};

// NOTE: 1-byte alignment
struct _lfStructure {
	u16 len;
	unsigned short  leaf;           // LF_CLASS, LF_STRUCT, LF_INTERFACE
	unsigned short  count;          // count of number of elements in class
	CV_prop_t       property;       // property attribute field (prop_t)
	CV_typ_t        field;          // type index of LF_FIELD descriptor list
	CV_typ_t        derived;        // type index of derived from list if not zero
	CV_typ_t        vshape;         // type index of vshape table for this class
	// followed by data describing length of structure in bytes and name
};

// NOTE: 1-byte alignment
struct CV_Filedata {
	u32 offstFileName;
	u8  cbChecksum;
	u8  ChecksumType;
};

// NOTE: 1-byte alignment
struct xdata_UnwindInfoHeader {
	u8 Version : 3;
	u8 Flags : 5;
	u8 SizeOfProlog;
	u8 CountOfCodes;
	u8 FrameRegister : 4;
	u8 FrameOffset : 4;
};

// NOTE: 1-byte alignment
struct _lfPointer { // lfPointer
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
};

#pragma pack(pop)

// do we need AlignTo4Bytes?
static void AlignTo4Bytes(fArray(u8)* builder) {
	f_array_resize(builder, F_ALIGN_UP_POW2(builder->len, 4), (u8)0);
};

static void CodeviewPadTo4Bytes(fArray(u8)* builder) {
	uint pad = F_ALIGN_UP_POW2(builder->len, 4) - builder->len;
	if (pad >= 3) f_array_push(builder, (u8)LF_PAD3);
	if (pad >= 2) f_array_push(builder, (u8)LF_PAD2);
	if (pad >= 1) f_array_push(builder, (u8)LF_PAD1);
	F_ASSERT(F_HAS_ALIGNMENT_POW2(builder->len, 4));
};

static void append_so_called_length_prefixed_name(fArray(u8)* builder, coffString name) {
	// ...it's actually not length-prefixed. The comments just say that, because it was like that in old codeview versions.
	f_str_print(builder, name);
	f_str_print(builder, F_LIT("\0"));
	CodeviewPadTo4Bytes(builder);
}

static void patch_reclen(fArray(u8)* builder, u32 reclen_offset) {
	u16 len = (u16)(builder->len - (reclen_offset + 2));
	*(u16*)(builder->data + reclen_offset) = len;
	//f_slice_copy(f_slice(*builder, offset_of_len_field, offset_of_len_field + 2), F_AS_BYTES(len));
}

static void GenerateXDataAndPDataSections(fArray(u8)* pdata_builder, fArray(coffRelocation)* pdata_relocs, fArray(u8)* xdata_builder, cviewGenerateDebugInfoDesc* desc) {
	F_ASSERT(xdata_builder->len == 0);
	F_ASSERT(pdata_builder->len == 0);
	F_ASSERT(pdata_relocs->len == 0);

	s32 prev_sym_index = -1;
	s32 prev_fn_offset = -1;
	for (u32 i = 0; i < desc->functions_count; i++) {
		cviewFunction& fn = desc->functions[i];
		
		// The functions must be sorted! Otherwise the linker will complain.
		VALIDATE((s32)fn.sym_index > prev_sym_index);
		VALIDATE((s32)fn.block.start_offset > prev_fn_offset);
		prev_sym_index = (s32)fn.sym_index;
		prev_fn_offset = (s32)fn.block.start_offset;

		u32 unwind_info_address = (u32)xdata_builder->len;

		// pdata
		{
			// Do we need IMAGE_REL_AMD64_ADDR32NB???
			// "In an object file, an RVA is less meaningful because
			// "memory locations are not assigned.In this case, an RVA would be an address within a section"

			{
				coffRelocation reloc = {};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = fn.section_sym_index;
				f_array_push(pdata_relocs, reloc);

				f_array_push_n(pdata_builder, F_AS_BYTES(fn.block.start_offset)); // Function start address
			}
			{
				coffRelocation reloc = {};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = fn.section_sym_index;
				f_array_push(pdata_relocs, reloc);

				f_array_push_n(pdata_builder, F_AS_BYTES(fn.block.end_offset)); // Function end address
			}
			{
				F_ASSERT(desc->xdata_section_sym_index != 0);
				coffRelocation reloc = {};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = desc->xdata_section_sym_index;
				f_array_push(pdata_relocs, reloc);

				f_array_push_n(pdata_builder, F_AS_BYTES(unwind_info_address));
			}
		}

		// xdata
		{
			F_ASSERT(fn.size_of_initial_sub_rsp_instruction > 0);

			bool is_large = fn.stack_frame_size >= 128;
			xdata_UnwindInfoHeader header = {};
			header.Version = 1;
			header.SizeOfProlog = fn.size_of_initial_sub_rsp_instruction; // the SUB RSP, (*) instruction including the immediate takes 4 bytes
			header.CountOfCodes = is_large ? 2 : 1;
			//header.FrameRegister = 0; // use RSP as the stack base pointer
			f_array_push_n(xdata_builder, F_AS_BYTES(header));

#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2

			if (is_large) {
				VALIDATE(fn.stack_frame_size < F_KIB(512));

				xdata_UnwindCode unwind_code = {}; // "Save a nonvolatile integer register on the stack using a MOV instead of a PUSH"
				unwind_code.CodeOffset = fn.size_of_initial_sub_rsp_instruction; // offset of the end of the instruction
				unwind_code.UnwindOp = UWOP_ALLOC_LARGE;
				unwind_code.OpInfo = 0;
				f_array_push_n(xdata_builder, F_AS_BYTES(unwind_code));

				// "If the operation info equals 0, then the size of the allocation divided by 8 is recorded in the next slot, allowing an allocation up to 512K - 8"
				u16 size = fn.stack_frame_size >> 3;
				F_ASSERT(size * 8 == fn.stack_frame_size);
				f_array_push_n(xdata_builder, F_AS_BYTES(size));
			}
			else {
				// op_info * 8 + 8 == fn.stack_frame_size
				u8 op_info = (fn.stack_frame_size - 8) >> 3;
				F_ASSERT(op_info * 8 + 8 == fn.stack_frame_size);

				xdata_UnwindCode unwind_code = {}; // "Save a nonvolatile integer register on the stack using a MOV instead of a PUSH"
				unwind_code.CodeOffset = fn.size_of_initial_sub_rsp_instruction; // offset of the end of the instruction
				unwind_code.UnwindOp = UWOP_ALLOC_SMALL;
				unwind_code.OpInfo = op_info;
				f_array_push_n(xdata_builder, F_AS_BYTES(unwind_code));

				u16 padding = 0;
				f_array_push_n(xdata_builder, F_AS_BYTES(padding)); // NOTE: unwind code count must be a multiple of two
			}

		}
	}
}

struct GenerateDebugSectionContext {
	fArray(u8)* debugS_builder;
	fArray(coffRelocation)* debugS_relocs;
	fArray(u8)* debugT_builder;

	cviewGenerateDebugInfoDesc* desc;
};

static void GenerateDebugSection_AddLocals(GenerateDebugSectionContext* ctx, fSlice(u32) to_codeview_type_idx, cviewFunction* fn, cviewBlock* parent) {
	for (u32 i = 0; i < parent->locals_count; i++) {
		cviewLocal& local = parent->locals[i];
		VALIDATE(local.name.len < F_U16_MAX);

		REGREL32 sym = {};
		sym.reclen = F_OFFSET_OF(REGREL32, name) - 2 + ((u16)local.name.len + 1);
		sym.rectyp = S_REGREL32;
		sym.off = local.rsp_rel_offset;
		sym.reg = CV_AMD64_RSP;

		// Our API type index to codeview type index

		sym.typind = to_codeview_type_idx[local.type_idx];

		f_array_push_n(ctx->debugS_builder, fString{ (u8*)&sym, F_OFFSET_OF(REGREL32, name) });

		f_array_push_n(ctx->debugS_builder, local.name);
		f_array_push(ctx->debugS_builder, (u8)'\0');
	}

	for (u32 i = 0; i < parent->child_blocks_count; i++) {
		cviewBlock* block = &parent->child_blocks[i];
		{
			BLOCKSYM32 sym = {};
			sym.reclen = sizeof(BLOCKSYM32) - 2;
			sym.rectyp = S_BLOCK32;
			sym.len = block->end_offset - block->start_offset; // block length

			sym.seg = 0; // Section number of the block. To be relocated
			{
				coffRelocation seg_reloc = {};
				seg_reloc.offset = (u32)ctx->debugS_builder->len + F_OFFSET_OF(BLOCKSYM32, seg);
				seg_reloc.sym_idx = fn->sym_index;
				if (seg_reloc.sym_idx == 9) F_BP;
				seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
				f_array_push(ctx->debugS_relocs, seg_reloc);
			}

			sym.off = block->start_offset; // Start offset of the block within the section. To be relocated
			{
				coffRelocation off_reloc = {};
				off_reloc.offset = (u32)ctx->debugS_builder->len + F_OFFSET_OF(BLOCKSYM32, off);
				off_reloc.sym_idx = fn->sym_index;
				if (off_reloc.sym_idx == 9) F_BP;
				off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
				f_array_push(ctx->debugS_relocs, off_reloc);
			}

			f_array_push_n(ctx->debugS_builder, F_AS_BYTES(sym));
		}

		GenerateDebugSection_AddLocals(ctx, to_codeview_type_idx, fn, block);

		{
			u16 reclen = 2;
			u16 rectyp = S_END;
			f_array_push_n(ctx->debugS_builder, F_AS_BYTES(reclen));
			f_array_push_n(ctx->debugS_builder, F_AS_BYTES(rectyp));
		}
	}
};

static void append_variable_length_number(fArray(u8)* buffer, u32 number) {
	// see `PrintNumeric` in microsoft pdb dump.
	// values >= 2^32 are not supported by codeview.
	if (number < 0x8000) {
		f_array_push_n(buffer, f_slice_before(F_AS_BYTES(number), 2));
	}
	else if (number < F_U16_MAX) {
		u16 prefix = LF_USHORT;
		f_array_push_n(buffer, F_AS_BYTES(prefix));
		f_array_push_n(buffer, f_slice_before(F_AS_BYTES(number), 2));
	}
	else {
		u16 prefix = LF_ULONG;
		f_array_push_n(buffer, F_AS_BYTES(prefix));
		f_array_push_n(buffer, f_slice_before(F_AS_BYTES(number), 4));
	}
}

static void generate_cv_type(GenerateDebugSectionContext& ctx,
	fSlice(u32) struct_forward_ref_idx,
	fSlice(u32) to_codeview_type_idx,
	u32* next_custom_type_idx,
	u32 index)
{
	if (to_codeview_type_idx[index] != 0) return;

	cviewType& type = ctx.desc->types[index];

	u32 t = 0;
	
	if (type.tag == cviewTypeTag_Pointer) {
		/*u16 len = 0; // filled in later
		s64 base = ctx.debugT_builder->len;
		f_array_push_n(ctx.debugT_builder, F_AS_BYTES(len));

		CV_Pointer cv_pointer = {};
		cv_pointer.u.leaf = LF_POINTER;

		if (ctx.desc->types[type.Pointer.type_idx].tag == cviewTypeTag_Struct) {
			// Use the forward reference
			cv_pointer.u.utype = struct_forward_ref_idx[type.Pointer.type_idx];
		}
		else {
			GenerateCVType(ctx, struct_forward_ref_idx, to_codeview_type_idx, next_custom_type_idx, type.Pointer.type_idx);
			cv_pointer.u.utype = to_codeview_type_idx[type.Pointer.type_idx];
		}

		cv_pointer.u.attr.ptrtype = CV_PTR_64;
		cv_pointer.u.attr.ptrmode = type.Pointer.cpp_style_reference ? CV_PTR_MODE_REF : CV_PTR_MODE_PTR;
		cv_pointer.u.attr.size = 8;
		f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_pointer));

		len = (u16)(ctx.debugT_builder->len - (base + 2));
		f_slice_copy(f_slice(*ctx.debugT_builder, base, base + 2), F_AS_BYTES(len));

		t = (*next_custom_type_idx)++;*/
		t = T_UINT8;
	}
	else if (type.tag == cviewTypeTag_Int) {
		if (type.size == 1) t = T_INT1;
		else if (type.size == 2) t = T_INT2;
		else if (type.size == 4) t = T_INT4;
		else if (type.size == 8) t = T_INT8;
		else VALIDATE(false);
	}
	else if (type.tag == cviewTypeTag_UnsignedInt) {
		if (type.size == 1) t = T_UINT1;
		else if (type.size == 2) t = T_UINT2;
		else if (type.size == 4) t = T_UINT4;
		else if (type.size == 8) t = T_UINT8;
		else VALIDATE(false);
	}
	else if (type.tag == cviewTypeTag_Enum) {
		// LF_FIELDLIST
		u32 fieldlist_type_idx = 0;
		{
			_TYPTYPE cv_fieldlist = {};
			u32 reclen_offset = (u32)ctx.debugT_builder->len;
			cv_fieldlist.leaf = LF_FIELDLIST;
			f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_fieldlist));

			for (uint field_i = 0; field_i < type.Enum.fields_count; field_i++) {
				F_ASSERT(F_HAS_ALIGNMENT_POW2(ctx.debugT_builder->len, 4));
				cviewEnumField& field = type.Enum.fields[field_i];
				//F_ASSERT(IS_POWER_OF_2(ctx.debugT_builder->len));
				struct CodeviewEnumField { // lfEnumerate
					unsigned short  leaf;       // LF_ENUMERATE
					CV_fldattr_t    attr;       // u16, access
					// variable length value field followed by length-prefixed name
				};

				CodeviewEnumField cv_field = {};
				cv_field.leaf = LF_ENUMERATE;
				cv_field.attr.access = CV_public;
				f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_field));

				append_variable_length_number(ctx.debugT_builder, field.value);
				append_so_called_length_prefixed_name(ctx.debugT_builder, field.name);
			}

			patch_reclen(ctx.debugT_builder, reclen_offset);

			fieldlist_type_idx = (*next_custom_type_idx)++;
		}

		// LF_ENUM
		{
			_lfEnum cv_enum = {};
			u32 reclen_offset = (u32)ctx.debugT_builder->len;
			cv_enum.leaf = LF_ENUM;
			cv_enum.count = type.Enum.fields_count;

			VALIDATE(type.size == 1 || type.size == 2 || type.size == 4 || type.size == 8);
			cv_enum.utype = type.size == 1 ? T_UINT1 :
				type.size == 2 ? T_UINT2 :
				type.size == 4 ? T_UINT4 : T_UINT8;
			cv_enum.field = fieldlist_type_idx;
			f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_enum));
			
			append_so_called_length_prefixed_name(ctx.debugT_builder, type.Enum.name);
			
			patch_reclen(ctx.debugT_builder, reclen_offset);
		}
		//t = T_UINT8;
		t = (*next_custom_type_idx)++;
	}
	else if (type.tag == cviewTypeTag_Array) {
		// LF_ARRAY

		// generate the element type first
		generate_cv_type(ctx, struct_forward_ref_idx, to_codeview_type_idx, next_custom_type_idx, type.Array.elem_type_idx);

		_lfArray cv_array = {};
		u32 reclen_offset = (u32)ctx.debugT_builder->len;
		cv_array.leaf = LF_ARRAY;
		cv_array.elemtype = to_codeview_type_idx[type.Pointer.type_idx];
		cv_array.idxtype = T_UQUAD; // 64-bit unsigned
		f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_array));
		
		append_variable_length_number(ctx.debugT_builder, type.size);
		append_so_called_length_prefixed_name(ctx.debugT_builder, coffString{});

		patch_reclen(ctx.debugT_builder, reclen_offset);
		
		t = (*next_custom_type_idx)++;
	}
	else if (type.tag == cviewTypeTag_Record) {
		// see `strForFieldList` in the microsoft pdb dump

		// first generate the member types
		for (u32 member_i = 0; member_i < type.Record.fields_count; member_i++) {
			cviewStructMember& member = type.Record.fields[member_i];
			generate_cv_type(ctx, struct_forward_ref_idx, to_codeview_type_idx, next_custom_type_idx, member.type_idx);
		}

		// LF_FIELDLIST
		u32 fieldlist_type_idx = 0;
		{

			_TYPTYPE cv_fieldlist = {};
			u32 reclen_offset = (u32)ctx.debugT_builder->len;
			cv_fieldlist.leaf = LF_FIELDLIST;
			f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_fieldlist));

			for (u32 member_i = 0; member_i < type.Record.fields_count; member_i++) {
				cviewStructMember& member = type.Record.fields[member_i];

				_lfMember cv_member = {};
				cv_member.leaf = LF_MEMBER;
				cv_member.attr.access = CV_public;

				cv_member.index = to_codeview_type_idx[member.type_idx]; // codeview type index
				F_ASSERT(cv_member.index != 0);
				f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_member));

				append_variable_length_number(ctx.debugT_builder, member.offset_of_member);
				append_so_called_length_prefixed_name(ctx.debugT_builder, member.name);
			}

			patch_reclen(ctx.debugT_builder, reclen_offset);

			fieldlist_type_idx = (*next_custom_type_idx)++;
		}

		// LF_STRUCTURE
		{
			_lfStructure cv_structure = {};
			u32 reclen_offset = (u32)ctx.debugT_builder->len;

			VALIDATE(type.Record.fields_count < F_U16_MAX);
			VALIDATE(type.size < F_U16_MAX);

			cv_structure.leaf = LF_STRUCTURE;
			cv_structure.count = (u16)type.Record.fields_count;
			//cv_structure.property
			cv_structure.field = fieldlist_type_idx;
			//cv_structure.derived
			//cv_structure.vshape
			f_array_push_n(ctx.debugT_builder, F_AS_BYTES(cv_structure));

			append_variable_length_number(ctx.debugT_builder, type.size);
			append_so_called_length_prefixed_name(ctx.debugT_builder, type.Record.name);

			patch_reclen(ctx.debugT_builder, reclen_offset);
		}

		t = (*next_custom_type_idx)++;
	}
	else F_BP;

	F_ASSERT(t != 0);
	to_codeview_type_idx[index] = t;
}


static void GenerateDebugSections(GenerateDebugSectionContext ctx) {
	fAllocator* temp = f_temp_alc();

	u32 signature = CV_SIGNATURE_C13;

	// -- Types section -------------------------------------------------------

	//fString test_debugT = os_file_read_whole(F_LIT("C:\\dev\\slump\\GMMC\\minimal\\lettuce_debugT.hex"), ctx.desc->allocator);
	//f_array_push_n(ctx.debugT_builder, test_debugT);

	f_array_push_n(ctx.debugT_builder, F_AS_BYTES(signature));

	// We have two different concepts of a type index. The first is the type index provided by the user of the API, pointing
	// to an element in the `CodeView_GenerateDebugInfo_Desc.types` array.
	// The second is the type index that's used in the actual compiled binary. We'll refer to the latter as "codeview type index"
	fSlice(u32) to_codeview_type_idx = f_make_slice_garbage<u32>(ctx.desc->types_count, temp);
	memset(to_codeview_type_idx.data, 0, to_codeview_type_idx.len * sizeof(u32));

	fSlice(u32) struct_forward_ref_idx = f_make_slice_garbage<u32>(ctx.desc->types_count, temp);

	u32 next_custom_type_idx = 0x1000;

	// First create forward references for all the record types

	for (u32 i = 0; i < ctx.desc->types_count; i++) {
		cviewType& type = ctx.desc->types[i];
		if (type.tag == cviewTypeTag_Record) {
			_lfStructure cv_structure = {};
			u32 reclen_offset = (u32)ctx.debugT_builder->len;
			cv_structure.leaf = LF_STRUCTURE;
			cv_structure.property.fwdref = true;
			f_str_print(ctx.debugT_builder, F_AS_BYTES(cv_structure));

			u16 struct_size = 0;
			f_str_print(ctx.debugT_builder, F_AS_BYTES(struct_size));
			append_so_called_length_prefixed_name(ctx.debugT_builder, type.Record.name);

			patch_reclen(ctx.debugT_builder, reclen_offset);

			struct_forward_ref_idx[i] = next_custom_type_idx++;
		}
	}

	// DumpModTypC7 implementation is missing from the microsoft's PDB dump.

	for (u32 i = 0; i < ctx.desc->types_count; i++) {
		generate_cv_type(ctx, struct_forward_ref_idx, to_codeview_type_idx, &next_custom_type_idx, i);
	}

	// -- Symbols section --------------------------------------------------------

	f_array_push_n(ctx.debugS_builder, F_AS_BYTES(signature));

	// *** SYMBOLS

	{
		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_SYMBOLS;
		// subsection_header.cbLen
		f_array_push_n(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		{
			//fString name = F_LIT("C:\\dev\\slump\\GMMC\\minimal\\lettuce.obj");
			VALIDATE(!f_str_contains(ctx.desc->obj_name, F_LIT("/"))); // Only backslashes are allowed!

			OBJNAMESYM objname = {};
			u32 reclen_offset = (u32)ctx.debugS_builder->len;
			objname.rectyp = S_OBJNAME;

			f_array_push_n(ctx.debugS_builder, { (u8*)&objname, sizeof(OBJNAMESYM) - 1 });
			f_array_push_n(ctx.debugS_builder, ctx.desc->obj_name);
			f_array_push(ctx.debugS_builder, (u8)'\0');

			patch_reclen(ctx.debugS_builder, reclen_offset);
		}
		{
			fString name = F_LIT("Microsoft (R) Optimizing Compiler"); // TODO

			u32 reclen_offset = (u32)ctx.debugS_builder->len;
			COMPILESYM3 compile3 = {};
			compile3.rectyp = S_COMPILE3;
			compile3.machine = CV_CFL_X64;

			f_array_push_n(ctx.debugS_builder, { (u8*)&compile3, sizeof(compile3) - 1 });
			f_array_push_n(ctx.debugS_builder, name);
			f_array_push(ctx.debugS_builder, (u8)'\0');

			patch_reclen(ctx.debugS_builder, reclen_offset);
		}

		// cbLen is the size of the subsection in bytes, not including the header itself and not including
		// the padding bytes after the subsection.
		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base;
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

		AlignTo4Bytes(ctx.debugS_builder); // Subsections must be aligned to 4 byte boundaries.
	}

	const uint size_of_file_checksum_entry = 40;

	for (u32 i = 0; i < ctx.desc->functions_count; i++) {
		cviewFunction& fn = ctx.desc->functions[i];

		// *** SYMBOLS
		{

			CV_DebugSSubsectionHeader_t subsection_header;
			subsection_header.type = DEBUG_S_SYMBOLS;
			f_array_push_n(ctx.debugS_builder, F_AS_BYTES(subsection_header));
			u32 subsection_base = (u32)ctx.debugS_builder->len;

			// S_GPROC32_ID
			{
				//fString name = transmute(fString)fn->fn->dbginfo_name;
				//CodeView_Function& fn = ctx.desc->functions[0];
				F_ASSERT(fn.name.len > 0);

				PROCSYM32 proc_sym = {};
				u32 reclen_offset = (u32)ctx.debugS_builder->len;
				proc_sym.rectyp = S_GPROC32_ID;

				proc_sym.seg = 0; // Section number of the procedure. To be relocated
				{
					coffRelocation seg_reloc = {};
					seg_reloc.offset = reclen_offset + F_OFFSET_OF(PROCSYM32, seg);
					seg_reloc.sym_idx = fn.sym_index;
					seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
					f_array_push(ctx.debugS_relocs, seg_reloc);
				}

				proc_sym.off = 0; // Start offset of the function within the section. To be relocated
				{
					coffRelocation off_reloc = {};
					off_reloc.offset = reclen_offset + F_OFFSET_OF(PROCSYM32, off);
					off_reloc.sym_idx = fn.sym_index;
					off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
					f_array_push(ctx.debugS_relocs, off_reloc);
				}

				// in cvdump, this is the "Cb" field. This marks the size of the function in the .text section, in bytes.
				proc_sym.len = fn.block.end_offset - fn.block.start_offset;

				//F_BP;
				proc_sym.typind = 0; // this is an index of the symbol's type
				proc_sym.DbgStart = 0; // this seems to always be zero
				proc_sym.DbgEnd = proc_sym.len - 1; // this seems to usually (not always) be PROCSYM32.len - 1. Not sure what this means.

				f_array_push_n(ctx.debugS_builder, { (u8*)&proc_sym, sizeof(proc_sym) - 1 });
				f_array_push_n(ctx.debugS_builder, fn.name);
				f_array_push(ctx.debugS_builder, (u8)'\0');

				patch_reclen(ctx.debugS_builder, reclen_offset);
			}

			// S_FRAMEPROC

			{
				// see C7FrameProc (microsoft's pdb source code dump)
				FRAMEPROCSYM frameproc = {};
				frameproc.rectyp = S_FRAMEPROC;
				frameproc.reclen = sizeof(FRAMEPROCSYM) - 2;
				frameproc.cbFrame = fn.stack_frame_size; // size of the stack frame
				frameproc.cbPad = 0;
				frameproc.offPad = 0;
				frameproc.cbSaveRegs = 0;
				frameproc.sectExHdlr = 0;
				frameproc.offExHdlr = 0;
				frameproc.flags.fAsyncEH = 1;
				frameproc.flags.fOptSpeed = 1;
				frameproc.flags.encodedLocalBasePointer = 1; // 0=none, 1=RSP, 2=RBP, 3=R13  (rgszRegAMD64[rgFramePointerRegX64[encodedLocalBasePointer]])
				frameproc.flags.encodedParamBasePointer = 1; // same encoding as above
				f_array_push_n(ctx.debugS_builder, F_AS_BYTES(frameproc));
			}


			GenerateDebugSection_AddLocals(&ctx, to_codeview_type_idx, &fn, &fn.block);

			// S_PROC_ID_END
			{
				SYMTYPE sym;
				u32 reclen_offset = (u32)ctx.debugS_builder->len;
				sym.rectyp = S_PROC_ID_END;

				f_array_push_n(ctx.debugS_builder, F_AS_BYTES(sym));

				patch_reclen(ctx.debugS_builder, reclen_offset);
			}


			// locals
			//F_BP;
			// block = &fn.root_block;
			//for (;;) {
			//}

			u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself
			f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

			AlignTo4Bytes(ctx.debugS_builder); // Subsections must be aligned to 4 byte boundaries
		}


		// *** LINES
		{
			// see DumpModC13Lines (microsoft's pdb source code dump)

			CV_DebugSSubsectionHeader_t subsection_header;
			subsection_header.type = DEBUG_S_LINES;
			// subsection_header.cbLen
			f_array_push_n(ctx.debugS_builder, F_AS_BYTES(subsection_header));
			u32 subsection_base = (u32)ctx.debugS_builder->len;

			{
				CV_DebugSLinesHeader_t lines_header;

				lines_header.segCon = 0; // Section number containing the code. To be relocated
				{
					coffRelocation seg_reloc = {};
					seg_reloc.offset = (u32)ctx.debugS_builder->len + F_OFFSET_OF(CV_DebugSLinesHeader_t, segCon);
					seg_reloc.sym_idx = fn.sym_index;
					seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
					f_array_push(ctx.debugS_relocs, seg_reloc);
				}

				lines_header.offCon = 0; // Start offset of the function within the section. To be relocated
				{
					coffRelocation off_reloc = {};
					off_reloc.offset = (u32)ctx.debugS_builder->len + F_OFFSET_OF(CV_DebugSLinesHeader_t, offCon);
					off_reloc.sym_idx = fn.sym_index;
					off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
					f_array_push(ctx.debugS_relocs, off_reloc);
				}

				lines_header.flags = 0;
				lines_header.cbCon = fn.block.end_offset - fn.block.start_offset;
				f_array_push_n(ctx.debugS_builder, F_AS_BYTES(lines_header));

				struct {
					u32 fileid;
					u32 nLines;
					u32 cbFileBlock; // length of the file block, including the file block header
				} file_block_header;

				file_block_header.fileid = size_of_file_checksum_entry * fn.file_idx; // the 'fileid' seems to encode the offset into the FILECHKSUMS subsection
				file_block_header.nLines = (u32)fn.lines_count;
				file_block_header.cbFileBlock = sizeof(file_block_header) + file_block_header.nLines * sizeof(CV_Line_t);
				f_array_push_n(ctx.debugS_builder, F_AS_BYTES(file_block_header));

				// add the lines

				for (u32 i = 0; i < fn.lines_count; i++) {
					cviewLine& line = fn.lines[i];

					CV_Line_t l = {};
					l.linenumStart = line.line_num;
					// line.deltaLineEnd is only used when column information is stored

					VALIDATE(line.offset >= fn.block.start_offset);
					l.offset = line.offset - fn.block.start_offset; // This offset is relative to lines_header.offCon (the start offset of the function)

					l.fStatement = 1; // not sure what this field means in practice
					f_array_push_n(ctx.debugS_builder, F_AS_BYTES(l));
				}
			}

			u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself
			f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

			// Each of the above structures are 4-byte aligned
			F_ASSERT(ctx.debugS_builder->len % 4 == 0); // Subsections must be aligned to 4 byte boundaries
		}
	}

	// *** SYMBOLS
	// S_UDT, not sure if this symbol subsection is needed / what it does
#if 0	
	{
		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_SYMBOLS;
		// subsection_header.cbLen
		f_array_push_n(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		{
			UDTSYM sym = {};
			sym.rectyp = S_UDT;
			sym.typind = 0x1001;
			F_BP;

			u32 reclen_offset = (u32)ctx.debugS_builder->len;
			f_array_push_n(ctx.debugS_builder, { (u8*)&sym, F_OFFSET_OF(UDTSYM, name) });
			f_array_push_n(ctx.debugS_builder, F_LIT("MyStruct"));
			f_array_push(ctx.debugS_builder, (u8)'\0');

			sym.reclen = (u16)(ctx.debugS_builder->len - (base + 2));
			f_slice_copy(f_slice(*ctx.debugS_builder, base, base + 2), F_AS_BYTES(sym.reclen));
		}

		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself and not including the padding bytes after the subsection.
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

		AlignTo4Bytes(ctx.debugS_builder); // Subsections must be aligned to 4 byte boundaries.
	}
#endif

	fArray(u8) string_table = f_array_make<u8>(temp);
	f_array_push(&string_table, (u8)0); // Strings seem to begin at index 1

	// *** FILECHKSUMS
	{
		// see DumpModFileChecksums (microsoft's pdb source code dump)

		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_FILECHKSMS;
		// subsection_header.cbLen
		f_array_push_n(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		for (uint i = 0; i < ctx.desc->files_count; i++) {
			cviewSourceFile* file = &ctx.desc->files[i];

			uint len_before = ctx.debugS_builder->len;
			CV_Filedata filedata;

			filedata.offstFileName = (u32)string_table.len; // offset to the filename in the string table
			filedata.cbChecksum = 32; // size of the checksum, in bytes. A SHA256 hash is 32-bytes long
			filedata.ChecksumType = CHKSUM_TYPE_SHA_256;

			VALIDATE(!f_str_contains(file->filepath, F_LIT("/"))); // Only backslashes are allowed!

			f_array_push_n(&string_table, file->filepath);
			f_array_push(&string_table, (u8)0);

			f_array_push_n(ctx.debugS_builder, F_AS_BYTES(filedata));

			//F_ASSERT(ctx.desc->dbginfo->file_hashes);

			f_array_push_n(ctx.debugS_builder, F_AS_BYTES(file->hash));

			AlignTo4Bytes(ctx.debugS_builder); // Each entry is aligned to 4 byte boundary

			F_ASSERT(ctx.debugS_builder->len - len_before == size_of_file_checksum_entry);
		}

		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

		AlignTo4Bytes(ctx.debugS_builder); // Subsections must be aligned to 4 byte boundaries
	}

	// *** STRINGTABLE

	{
		// see DumpModStringTable (microsoft's pdb source code dump)

		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_STRINGTABLE;
		f_array_push_n(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		f_array_push_n(ctx.debugS_builder, string_table.slice);
		//{
		//	f_array_push(ctx.debugS_builder, (u8)'\0');
		//
		//	fString filepath = ctx.desc->files[0].filepath;
		//	VALIDATE(!f_str_contains(filepath, F_LIT("/"))); // Only backslashes are allowed!
		//
		//	f_array_push_n(ctx.debugS_builder, filepath);
		//	f_array_push(ctx.debugS_builder, (u8)'\0'); // null terminate each string
		//}

		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));
	}
}

extern "C" void codeview_generate_debug_info(cviewGenerateDebugInfoDesc* desc, fAllocator* alc) {
	// See DumpObjFileSections from the microsoft's pdb source code dump.

	fArray(u8) debugS_builder = f_array_make_cap<u8>(1024, alc);
	fArray(u8) debugT_builder = f_array_make_cap<u8>(1024, alc);
	fArray(u8) pdata_builder = f_array_make_cap<u8>(1024, alc);
	fArray(u8) xdata_builder = f_array_make_cap<u8>(1024, alc);

	fArray(coffRelocation) debugS_relocs = f_array_make_cap<coffRelocation>(32, alc);
	fArray(coffRelocation) pdata_relocs = f_array_make_cap<coffRelocation>(32, alc);

	GenerateDebugSections({ &debugS_builder, &debugS_relocs, &debugT_builder, desc });

	GenerateXDataAndPDataSections(&pdata_builder, &pdata_relocs, &xdata_builder, desc);

	desc->result.debugS = debugS_builder.slice;
	desc->result.debugS_relocs = debugS_relocs.slice;
	desc->result.pdata = pdata_builder.slice;
	desc->result.pdata_relocs = pdata_relocs.slice;
	desc->result.xdata = xdata_builder.slice;
	desc->result.debugT = debugT_builder.slice;
}

