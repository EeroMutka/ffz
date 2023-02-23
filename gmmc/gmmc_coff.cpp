#include "src/foundation/foundation.hpp"

#include "gmmc.h"
#include "gmmc_coff.h"

// TODO: We should be pulling out the stuff we use out from the windows headers and documenting it while we're here
#include <Windows.h>

#define _VC_VER_INC
#include "cvinfo.h"

#include <stdio.h> // for printf

// If VALIDATE fails, it means that the user of the library has provided invalid inputs. (assuming there's no bug within the library itself)
#define VALIDATE(x) F_ASSERT(x)

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

static void CodeviewAppendName(fArray(u8)* builder, gmmcString name) {
	f_str_print_il(builder, { F_BITCAST(fString, name), F_LIT("\0") });
	CodeviewPadTo4Bytes(builder);
}

static void CodeviewPatchRecordLength(fArray(u8)* builder, uint offset_of_len_field) {
	u16 len = (u16)(builder->len - (offset_of_len_field + 2));
	F_BP;//f_slice_copy(f_slice(*builder, offset_of_len_field, offset_of_len_field + 2), F_AS_BYTES(len));
}

GMMC_API void coff_create(void(*store_result)(gmmcString, void*), void* store_result_userptr, coffDesc* desc) {
	fAllocator* temp = f_temp_push();
	fArray(u8) string_table = f_array_make_cap<u8>(512, temp);
	
	fArena* arena = f_arena_make_virtual_reserve_fixed(F_GIB(2), NULL);
	
	IMAGE_FILE_HEADER* header = (IMAGE_FILE_HEADER*)f_arena_push(arena, sizeof(IMAGE_FILE_HEADER), 1).data;
	header->Machine = IMAGE_FILE_MACHINE_AMD64;
	header->NumberOfSections = 0;

	header->TimeDateStamp = 0xfefefefe;
	//header->PointerToSymbolTable  filled in later
	//header->NumberOfSymbols;  filled in later
	header->SizeOfOptionalHeader = 0;
	header->Characteristics = 0;

#if 0
	if (desc->type == GMMC_CoffType_Obj) {
	}
	else if (desc->type == GMMC_CoffType_Exe) {
		header->Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
	}
	else F_ASSERT(false);
	if (desc->type == GMMC_CoffType_Exe) {
		IMAGE_OPTIONAL_HEADER64* optional_header = (IMAGE_OPTIONAL_HEADER64*)f_arena_push(arena, sizeof(IMAGE_OPTIONAL_HEADER64)).data;
		optional_header->Magic = 0x20b; // Set the magic number to 0x20b (PE32+)
		optional_header->MajorLinkerVersion = 0x0E; // just copied over from an example exe. Should be fine to set to just 1
		optional_header->MinorLinkerVersion = 0x21; // just copied over from an example exe. Should be fine to set to just 1
		optional_header->SizeOfCode; // TODO
		optional_header->SizeOfInitializedData; // TODO
		optional_header->SizeOfUninitializedData; // TODO
		optional_header->AddressOfEntryPoint; // TODO
		optional_header->BaseOfCode; // TODO

		// required by windows NT
		optional_header->ImageBase = 0x140000000;
		optional_header->SectionAlignment = F_KIB(4);
		optional_header->FileAlignment = 512;
		optional_header->MajorOperatingSystemVersion = 6;
		optional_header->MinorOperatingSystemVersion = 0;
		optional_header->MajorImageVersion = 0;
		optional_header->MinorImageVersion = 0;
		optional_header->MajorSubsystemVersion = 6;
		optional_header->MinorSubsystemVersion = 0;
		optional_header->Win32VersionValue = 0;
		optional_header->SizeOfImage; // TODO
		optional_header->SizeOfHeaders; // TODO
		optional_header->CheckSum = 0;
		optional_header->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI; // Console subsystem
		optional_header->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE;
		optional_header->SizeOfStackReserve = 100000;
		optional_header->SizeOfStackCommit = 100000;
		optional_header->SizeOfHeapReserve = 100000;
		optional_header->SizeOfHeapCommit = 1000;
		optional_header->LoaderFlags = 0;

		optional_header->NumberOfRvaAndSizes; // TODO
		//optional_header->DataDirectory[]; // TODO
	}
#endif

	// section headers
	IMAGE_SECTION_HEADER* sections[16];
	VALIDATE(desc->sections_count < 16);

	for (u32 i = 0; i < desc->sections_count; i++) {
		coffSection& section = desc->sections[i];

		//if (section.name == F_LIT(".drectve")) F_BP;

		IMAGE_SECTION_HEADER* s_header = (IMAGE_SECTION_HEADER*)f_arena_push(arena, sizeof(IMAGE_SECTION_HEADER), 1).data;
		memset(s_header, 0, sizeof(IMAGE_SECTION_HEADER));

		F_ASSERT(section.name.len <= 8);
		memcpy(s_header->Name, section.name.ptr, section.name.len);

		s_header->Misc.PhysicalAddress = 0;
		s_header->VirtualAddress = 0;
		s_header->SizeOfRawData = 0; // filled in later
		s_header->PointerToRawData = 0; // filled in later
		s_header->PointerToRelocations = 0;
		s_header->PointerToLinenumbers = 0;
		s_header->NumberOfRelocations = 0;
		s_header->NumberOfLinenumbers = 0;
		s_header->Characteristics = section.Characteristics;

		sections[header->NumberOfSections] = s_header;
		header->NumberOfSections++;
	}

	//
	//AddSection(F_LIT(".text\0"), IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ);
	//AddSection(F_LIT(".data\0"), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
	//AddSection(F_LIT(".debug$S\0"), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_READ);
	//AddSection(F_LIT(".debug$T\0"), IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_READ);

	// section 1 raw data
	// section 1 relocation table
	// section 2 raw data
	// ...

	fArray(DWORD*) patch_symbol_index_with_real_index = f_array_make_cap<DWORD*>(32, temp);

	for (u32 i = 0; i < desc->sections_count; i++) {
		coffSection& section = desc->sections[i];

		sections[i]->SizeOfRawData = (u32)section.data.len;
		if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			VALIDATE(section.data.ptr == NULL);
		}
		else {
			sections[i]->PointerToRawData = (u32)f_arena_get_contiguous_cursor(arena);
			f_arena_push_str(arena, { section.data.ptr, section.data.len }, 1);
		}
		
		// --- Relocations ---

		// NOTE: relocations are only for object files

		if (section.relocations_count > 0) {
			sections[i]->PointerToRelocations = (u32)f_arena_get_contiguous_cursor(arena);

			VALIDATE(section.relocations_count < F_U16_MAX);
			sections[i]->NumberOfRelocations = (u16)section.relocations_count;

			for (u32 i = 0; i < section.relocations_count; i++) {
				coffRelocation& r = section.relocations[i];
				VALIDATE(r.sym_idx < desc->symbols_count);

				IMAGE_RELOCATION* reloc = (IMAGE_RELOCATION*)f_arena_push(arena, sizeof(IMAGE_RELOCATION), 1).data;
				reloc->VirtualAddress = r.offset;

				f_array_push(&patch_symbol_index_with_real_index, &reloc->SymbolTableIndex);
				reloc->SymbolTableIndex = r.sym_idx;

				reloc->Type = r.type;
			}
		}
	}

	// symbol table
	{

		// Warning: header ptr must still be valid! Since this is an arena, it is.
		header->PointerToSymbolTable = (u32)f_arena_get_contiguous_cursor(arena);

		fSlice(u32) symbol_index_to_real_index = f_make_slice_garbage<u32>(desc->symbols_count, temp);

		u32 real_symbol_index = 0;
		for (u32 i = 0; i < desc->symbols_count; i++) {
			coffSymbol& symbol = desc->symbols[i];
			symbol_index_to_real_index[i] = real_symbol_index;


			//if (symbol.name == F_LIT(".debug$S")) F_BP;

			IMAGE_SYMBOL* s = (IMAGE_SYMBOL*)f_arena_push(arena, sizeof(IMAGE_SYMBOL), 1).data;
			memset(s, 0, sizeof(IMAGE_SYMBOL));

			s->N.Name.Short = 0;
			s->N.Name.Long = 0;
			if (symbol.name.len <= 8) {
				// use short name
				memcpy(s->N.ShortName, symbol.name.ptr, symbol.name.len);
			}
			else {
				// the 'Long' field represents the offset into the string table,
				// where 0 points to the 4-byte string table size field that is encoded at the beginning
				// of the string table.

				s->N.Name.Long = 4 + (u32)string_table.len;

				f_array_push_slice(&string_table, { symbol.name.ptr, symbol.name.len });
				f_array_push(&string_table, (u8)0); // Strings in the string table must be null-terminated
			}

			s->SectionNumber = symbol.section_number;  // special values: IMAGE_SYM_ABSOLUTE, IMAGE_SYM_UNDEFINED, IMAGE_SYM_DEBUG
			s->Value = symbol.value;
			s->Type = symbol.type; // 0x20 means 'function'
			s->StorageClass = symbol.external ? IMAGE_SYM_CLASS_EXTERNAL : IMAGE_SYM_CLASS_STATIC;
			s->NumberOfAuxSymbols = 0;

			if (symbol.is_section) {
				VALIDATE(!symbol.external);

				IMAGE_SECTION_HEADER* section = sections[symbol.section_number - 1];

				IMAGE_AUX_SYMBOL* aux = (IMAGE_AUX_SYMBOL*)f_arena_push(arena, sizeof(IMAGE_AUX_SYMBOL), 1).data;
				memset(aux, 0, sizeof(IMAGE_AUX_SYMBOL));
				aux->Section.Length = section->SizeOfRawData; // I'm not sure if this field is actually used.
				aux->Section.NumberOfRelocations = section->NumberOfRelocations;
				aux->Section.NumberOfLinenumbers = section->NumberOfLinenumbers;
				aux->Section.CheckSum = symbol._checksum;
				aux->Section.Number = 0;
				aux->Section.Selection = 0;
				s->NumberOfAuxSymbols++;

				real_symbol_index++;
			}

			real_symbol_index++;
		}

		for (uint i = 0; i < patch_symbol_index_with_real_index.len; i++) {
			DWORD* idx = patch_symbol_index_with_real_index[i];
			*idx = symbol_index_to_real_index[*idx];
		}

		// note: auxilary symbol structures are counted into NumberOfSymbols.
		// NumberOfSymbols seems to be mainly used for calculating the offset
		// of the string table.
		F_ASSERT((f_arena_get_contiguous_cursor(arena) - header->PointerToSymbolTable) % sizeof(IMAGE_SYMBOL) == 0);
		header->NumberOfSymbols = ((u32)f_arena_get_contiguous_cursor(arena) - header->PointerToSymbolTable) / sizeof(IMAGE_SYMBOL);
	}

	// string table
	{
		u32 s = 4 + (u32)string_table.len; // string table size, including the field itself
		f_arena_push_str(arena, F_AS_BYTES(s), 1);
		f_arena_push_str(arena, string_table.slice, 1);
	}

	// We're done!
	store_result(gmmcString{ f_arena_get_contiguous_base(arena), f_arena_get_contiguous_cursor(arena) }, store_result_userptr);

	f_arena_free(arena);
	f_temp_pop();
}








#ifdef GMMC_CODEVIEW

struct xdata_UnwindCode {
	u8 CodeOffset;
	u8 UnwindOp : 4;
	u8 OpInfo : 4;
};

#pragma pack(push, 1)
struct xdata_UnwindInfoHeader {
	u8 Version : 3;
	u8 Flags : 5;
	u8 SizeOfProlog;
	u8 CountOfCodes;
	u8 FrameRegister : 4;
	u8 FrameOffset : 4;
};
#pragma pack(pop)

static void GenerateXDataAndPDataSections(fArray(u8)* pdata_builder, fArray(coffRelocation)* pdata_relocs, fArray(u8)* xdata_builder, coffCVGenerateDebugInfoDesc* desc) {
	F_ASSERT(xdata_builder->len == 0);
	F_ASSERT(pdata_builder->len == 0);
	F_ASSERT(pdata_relocs->len == 0);

	for (u32 i = 0; i < desc->functions_count; i++) {
		coffCVFunction& fn = desc->functions[i];

		u32 unwind_info_address = (u32)xdata_builder->len;

		// pdata
		{
			{
				coffRelocation reloc = {};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = fn.code_section_sym_index;
				f_array_push(pdata_relocs, reloc);

				f_array_push_slice(pdata_builder, F_AS_BYTES(fn.block.start_offset)); // Function start address
			}
			{
				coffRelocation reloc = {};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = fn.code_section_sym_index;
				f_array_push(pdata_relocs, reloc);

				f_array_push_slice(pdata_builder, F_AS_BYTES(fn.block.end_offset)); // Function end address
			}
			{
				F_ASSERT(desc->xdata_section_sym_index != 0);
				coffRelocation reloc = {};
				reloc.offset = (u32)pdata_builder->len;
				reloc.type = IMAGE_REL_AMD64_ADDR32NB; // relative virtual address
				reloc.sym_idx = desc->xdata_section_sym_index;
				f_array_push(pdata_relocs, reloc);

				f_array_push_slice(pdata_builder, F_AS_BYTES(unwind_info_address));
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
			f_array_push_slice(xdata_builder, F_AS_BYTES(header));

#define UWOP_ALLOC_LARGE 1
#define UWOP_ALLOC_SMALL 2

			if (is_large) {
				VALIDATE(fn.stack_frame_size < F_KIB(512));

				xdata_UnwindCode unwind_code = {}; // "Save a nonvolatile integer register on the stack using a MOV instead of a PUSH"
				unwind_code.CodeOffset = fn.size_of_initial_sub_rsp_instruction; // offset of the end of the instruction
				unwind_code.UnwindOp = UWOP_ALLOC_LARGE;
				unwind_code.OpInfo = 0;
				f_array_push_slice(xdata_builder, F_AS_BYTES(unwind_code));

				// "If the operation info equals 0, then the size of the allocation divided by 8 is recorded in the next slot, allowing an allocation up to 512K - 8"
				u16 size = fn.stack_frame_size >> 3;
				F_ASSERT(size * 8 == fn.stack_frame_size);
				f_array_push_slice(xdata_builder, F_AS_BYTES(size));
			}
			else {
				// op_info * 8 + 8 == fn.stack_frame_size
				u8 op_info = (fn.stack_frame_size - 8) >> 3;
				F_ASSERT(op_info * 8 + 8 == fn.stack_frame_size);

				xdata_UnwindCode unwind_code = {}; // "Save a nonvolatile integer register on the stack using a MOV instead of a PUSH"
				unwind_code.CodeOffset = fn.size_of_initial_sub_rsp_instruction; // offset of the end of the instruction
				unwind_code.UnwindOp = UWOP_ALLOC_SMALL;
				unwind_code.OpInfo = op_info;
				f_array_push_slice(xdata_builder, F_AS_BYTES(unwind_code));

				u16 padding = 0;
				f_array_push_slice(xdata_builder, F_AS_BYTES(padding)); // NOTE: unwind code count must be a multiple of two
			}

		}
	}
}

struct GenerateDebugSectionContext {
	fArray(u8)* debugS_builder;
	fArray(coffRelocation)* debugS_relocs;
	fArray(u8)* debugT_builder;

	coffCVGenerateDebugInfoDesc* desc;
};

static void GenerateDebugSection_AddLocals(GenerateDebugSectionContext* ctx, fSlice(u32) to_codeview_type_idx, coffCVFunction* fn, coffCVBlock* parent) {
	for (u32 i = 0; i < parent->locals_count; i++) {
		coffCVLocal& local = parent->locals[i];
		VALIDATE(local.name.len < F_U16_MAX);

		REGREL32 sym = {};
		sym.reclen = F_OFFSET_OF(REGREL32, name) - 2 + ((u16)local.name.len + 1);
		sym.rectyp = S_REGREL32;
		sym.off = local.rsp_rel_offset;
		sym.reg = CV_AMD64_RSP;

		// Our API type index to codeview type index

		sym.typind = to_codeview_type_idx[local.type_idx];

		f_array_push_slice(ctx->debugS_builder, fString{ (u8*)&sym, F_OFFSET_OF(REGREL32, name) });

		f_array_push_slice(ctx->debugS_builder, F_BITCAST(fString, local.name));
		f_array_push(ctx->debugS_builder, (u8)'\0');
	}

	for (u32 i = 0; i < parent->child_blocks_count; i++) {
		coffCVBlock* block = &parent->child_blocks[i];
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

			f_array_push_slice(ctx->debugS_builder, F_AS_BYTES(sym));
		}

		GenerateDebugSection_AddLocals(ctx, to_codeview_type_idx, fn, block);

		{
			u16 reclen = 2;
			u16 rectyp = S_END;
			f_array_push_slice(ctx->debugS_builder, F_AS_BYTES(reclen));
			f_array_push_slice(ctx->debugS_builder, F_AS_BYTES(rectyp));
		}
	}
};

#pragma pack(push, 1) // specify 1-byte alignment
struct CV_Pointer { // lfPointer
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


struct CV_Structure { // see lfStructure
	u16 len;
	unsigned short  leaf;           // LF_CLASS, LF_STRUCT, LF_INTERFACE
	unsigned short  count;          // count of number of elements in class
	CV_prop_t       property;       // property attribute field (prop_t)
	CV_typ_t        field;          // type index of LF_FIELD descriptor list
	CV_typ_t        derived;        // type index of derived from list if not zero
	CV_typ_t        vshape;         // type index of vshape table for this class
	// followed by data describing length of structure in bytes and name
};

static void CodeviewAppendVariableLengthNumber(fArray(u8)* buffer, u32 number) {
	// see `PrintNumeric` in microsoft pdb dump.
	// values >= 2^32 are not supported by codeview.
	if (number < 0x8000) {
		f_array_push_slice(buffer, f_slice_before(F_AS_BYTES(number), 2));
	}
	else if (number < F_U16_MAX) {
		u16 prefix = LF_USHORT;
		f_array_push_slice(buffer, F_AS_BYTES(prefix));
		f_array_push_slice(buffer, f_slice_before(F_AS_BYTES(number), 2));
	}
	else {
		u16 prefix = LF_ULONG;
		f_array_push_slice(buffer, F_AS_BYTES(prefix));
		f_array_push_slice(buffer, f_slice_before(F_AS_BYTES(number), 4));
	}
}

static void GenerateCVType(GenerateDebugSectionContext& ctx,
	fSlice(u32) struct_forward_ref_idx,
	fSlice(u32) to_codeview_type_idx,
	u32* next_custom_type_idx,
	u32 index)
{
	if (to_codeview_type_idx[index] != 0) return;

	coffCVType& type = ctx.desc->types[index];

	u32 t = 0;

	struct CodeviewType { // TYPTYPE 
		unsigned short len;
		unsigned short leaf;
	};

	if (type.tag == coffCVTypeTag_Pointer) {
		/*u16 len = 0; // filled in later
		s64 base = ctx.debugT_builder->len;
		f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(len));

		CV_Pointer cv_pointer = {};
		cv_pointer.u.leaf = LF_POINTER;

		if (ctx.desc->types[type.Pointer.type_idx].tag == coffCVTypeTag_Struct) {
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
		f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_pointer));

		len = (u16)(ctx.debugT_builder->len - (base + 2));
		f_slice_copy(f_slice(*ctx.debugT_builder, base, base + 2), F_AS_BYTES(len));

		t = (*next_custom_type_idx)++;*/
		t = T_UINT8;
	}
	else if (type.tag == coffCVTypeTag_Int) {
		if (type.size == 1) t = T_INT1;
		else if (type.size == 2) t = T_INT2;
		else if (type.size == 4) t = T_INT4;
		else if (type.size == 8) t = T_INT8;
		else VALIDATE(false);
	}
	else if (type.tag == coffCVTypeTag_UnsignedInt) {
		if (type.size == 1) t = T_UINT1;
		else if (type.size == 2) t = T_UINT2;
		else if (type.size == 4) t = T_UINT4;
		else if (type.size == 8) t = T_UINT8;
		else VALIDATE(false);
	}
	else if (type.tag == coffCVTypeTag_Enum) {
		// LF_FIELDLIST
		u32 fieldlist_type_idx = 0;
		{
			uint base = ctx.debugT_builder->len;
			CodeviewType cv_fieldlist = {};
			cv_fieldlist.len = 0; // filled in later
			cv_fieldlist.leaf = LF_FIELDLIST;
			f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_fieldlist));

			for (uint field_i = 0; field_i < type.Enum.fields_count; field_i++) {
				F_ASSERT(F_HAS_ALIGNMENT_POW2(ctx.debugT_builder->len, 4));
				coffCVEnumField& field = type.Enum.fields[field_i];
				//F_ASSERT(IS_POWER_OF_2(ctx.debugT_builder->len));
				struct CodeviewEnumField { // lfEnumerate
					unsigned short  leaf;       // LF_ENUMERATE
					CV_fldattr_t    attr;       // u16, access
					// variable length value field followed by length-prefixed name
				};

				CodeviewEnumField cv_field = {};
				cv_field.leaf = LF_ENUMERATE;
				cv_field.attr.access = CV_public;
				f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_field));

				CodeviewAppendVariableLengthNumber(ctx.debugT_builder, field.value);
				CodeviewAppendName(ctx.debugT_builder, field.name);
			}

			CodeviewPatchRecordLength(ctx.debugT_builder, base);

			fieldlist_type_idx = (*next_custom_type_idx)++;
		}

		// LF_ENUM
		{
			struct { // see lfEnum
				unsigned short  len;
				unsigned short  leaf;           // LF_ENUM
				unsigned short  count;          // count of number of elements in class
				CV_prop_t       property;       // property attribute field
				CV_typ_t        utype;          // underlying type of the enum
				CV_typ_t        field;          // type index of LF_FIELD descriptor list
				// followed by a length-prefixed name of the enum
			} cv_enum = {};

			uint base = ctx.debugT_builder->len; // cv_enum.len is filled in later
			cv_enum.leaf = LF_ENUM;
			cv_enum.count = type.Enum.fields_count;

			VALIDATE(type.size == 1 || type.size == 2 || type.size == 4 || type.size == 8);
			cv_enum.utype = type.size == 1 ? T_UINT1 :
				type.size == 2 ? T_UINT2 :
				type.size == 4 ? T_UINT4 : T_UINT8;
			cv_enum.field = fieldlist_type_idx;
			f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_enum));
			CodeviewAppendName(ctx.debugT_builder, type.Enum.name);
			CodeviewPatchRecordLength(ctx.debugT_builder, base);
		}
		//t = T_UINT8;
		t = (*next_custom_type_idx)++;
	}
	else if (type.tag == coffCVTypeTag_Struct) {
		// see `strForFieldList` in the microsoft pdb dump

		// first generate the member types
		for (u32 member_i = 0; member_i < type.Struct.fields_count; member_i++) {
			coffCVStructMember& member = type.Struct.fields[member_i];
			GenerateCVType(ctx, struct_forward_ref_idx, to_codeview_type_idx, next_custom_type_idx, member.type_idx);
		}

		// LF_FIELDLIST
		u32 fieldlist_type_idx = 0;
		{
			uint base = ctx.debugT_builder->len;
			//lfFieldList
			CodeviewType cv_fieldlist = {};
			cv_fieldlist.len = 0; // filled in later
			cv_fieldlist.leaf = LF_FIELDLIST;
			f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_fieldlist));

			for (u32 member_i = 0; member_i < type.Struct.fields_count; member_i++) {
				coffCVStructMember& member = type.Struct.fields[member_i];
				struct _lfMember { // lfMember
					unsigned short  leaf;           // LF_MEMBER

					CV_fldattr_t    attr;           // u16, attribute mask
					unsigned long   index;          // index of type record for field
					// variable length offset of field followed
					// by length prefixed (@em: NOT length-prefixed! it's null-terminated in the latest codeview version) name of field
				};

				_lfMember cv_member = {};
				cv_member.leaf = LF_MEMBER;
				cv_member.attr.access = CV_public;

				cv_member.index = to_codeview_type_idx[member.type_idx]; // codeview type index
				F_ASSERT(cv_member.index != 0);
				f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_member));

				CodeviewAppendVariableLengthNumber(ctx.debugT_builder, member.offset_of_member);
				CodeviewAppendName(ctx.debugT_builder, member.name);
			}

			CodeviewPatchRecordLength(ctx.debugT_builder, base);

			fieldlist_type_idx = (*next_custom_type_idx)++;
		}

		// LF_STRUCTURE
		{
			uint base = ctx.debugT_builder->len;
			CV_Structure cv_structure = {};

			VALIDATE(type.Struct.fields_count < F_U16_MAX);
			VALIDATE(type.size < F_U16_MAX);

			cv_structure.leaf = LF_STRUCTURE;
			cv_structure.count = (u16)type.Struct.fields_count;
			//cv_structure.property
			cv_structure.field = fieldlist_type_idx;
			//cv_structure.derived
			//cv_structure.vshape
			f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(cv_structure));

			CodeviewAppendVariableLengthNumber(ctx.debugT_builder, type.size);
			CodeviewAppendName(ctx.debugT_builder, type.Struct.name);

			CodeviewPatchRecordLength(ctx.debugT_builder, base);
		}

		t = (*next_custom_type_idx)++;
	}
	else F_BP;

	F_ASSERT(t != 0);
	to_codeview_type_idx[index] = t;
}


static void GenerateDebugSections(GenerateDebugSectionContext ctx) {
	fAllocator* temp = f_temp_push();


	u32 signature = CV_SIGNATURE_C13;

	// -- Types section -------------------------------------------------------

	//fString test_debugT = os_file_read_whole(F_LIT("C:\\dev\\slump\\GMMC\\minimal\\lettuce_debugT.hex"), ctx.desc->allocator);
	//f_array_push_slice(ctx.debugT_builder, test_debugT);

	f_array_push_slice(ctx.debugT_builder, F_AS_BYTES(signature));

	// We have two different concepts of a type index. The first is the type index provided by the user of the API, pointing
	// to an element in the `CodeView_GenerateDebugInfo_Desc.types` array.
	// The second is the type index that's used in the actual compiled binary. We'll refer to the latter as "codeview type index"
	fSlice(u32) to_codeview_type_idx = f_make_slice_garbage<u32>(ctx.desc->types_count, temp);
	memset(to_codeview_type_idx.data, 0, to_codeview_type_idx.len * sizeof(u32));

	fSlice(u32) struct_forward_ref_idx = f_make_slice_garbage<u32>(ctx.desc->types_count, temp);

	u32 next_custom_type_idx = 0x1000;

	// First create forward references for all the struct types

	for (u32 i = 0; i < ctx.desc->types_count; i++) {
		coffCVType& type = ctx.desc->types[i];
		if (type.tag == coffCVTypeTag_Struct) {
			uint base = ctx.debugT_builder->len;
			CV_Structure cv_structure = {};
			const int x = sizeof(CV_Structure);
			//cv_structure.len // filled in later
			cv_structure.leaf = LF_STRUCTURE;
			cv_structure.property.fwdref = true;
			f_str_print(ctx.debugT_builder, F_AS_BYTES(cv_structure));

			u16 struct_size = 0;
			f_str_print(ctx.debugT_builder, F_AS_BYTES(struct_size));
			CodeviewAppendName(ctx.debugT_builder, type.Struct.name);

			CodeviewPatchRecordLength(ctx.debugT_builder, base);

			struct_forward_ref_idx[i] = next_custom_type_idx++;
		}
	}

	// DumpModTypC7 implementation is missing from the microsoft's PDB dump.

	for (u32 i = 0; i < ctx.desc->types_count; i++) {
		GenerateCVType(ctx, struct_forward_ref_idx, to_codeview_type_idx, &next_custom_type_idx, i);
	}

	// -- Symbols section --------------------------------------------------------

	f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(signature));

	// *** SYMBOLS

	{
		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_SYMBOLS;
		// subsection_header.cbLen
		f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		{
			//fString name = F_LIT("C:\\dev\\slump\\GMMC\\minimal\\lettuce.obj");
			VALIDATE(!f_str_contains(F_BITCAST(fString, ctx.desc->obj_name), F_LIT("/"))); // Only backslashes are allowed!

			uint base = ctx.debugS_builder->len;
			OBJNAMESYM objname = {};
			// .reclen is filled in later
			objname.rectyp = S_OBJNAME;

			f_array_push_slice(ctx.debugS_builder, { (u8*)&objname, sizeof(OBJNAMESYM) - 1 });
			f_array_push_slice(ctx.debugS_builder, F_BITCAST(fString, ctx.desc->obj_name));
			f_array_push(ctx.debugS_builder, (u8)'\0');

			CodeviewPatchRecordLength(ctx.debugS_builder, base);
		}
		{
			fString name = F_LIT("Microsoft (R) Optimizing Compiler"); // TODO

			uint base = ctx.debugS_builder->len;
			COMPILESYM3 compile3 = {};
			// .reclen is filled in later
			compile3.rectyp = S_COMPILE3;
			compile3.machine = CV_CFL_X64;

			f_array_push_slice(ctx.debugS_builder, { (u8*)&compile3, sizeof(compile3) - 1 });
			f_array_push_slice(ctx.debugS_builder, name);
			f_array_push(ctx.debugS_builder, (u8)'\0');

			CodeviewPatchRecordLength(ctx.debugS_builder, base);
		}

		// cbLen is the size of the subsection in bytes, not including the header itself and not including
		// the padding bytes after the subsection.
		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base;
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

		AlignTo4Bytes(ctx.debugS_builder); // Subsections must be aligned to 4 byte boundaries.
	}

	const uint size_of_file_checksum_entry = 40;

	for (u32 i = 0; i < ctx.desc->functions_count; i++) {
		coffCVFunction& fn = ctx.desc->functions[i];

		// *** SYMBOLS
		{

			CV_DebugSSubsectionHeader_t subsection_header;
			subsection_header.type = DEBUG_S_SYMBOLS;
			f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(subsection_header));
			u32 subsection_base = (u32)ctx.debugS_builder->len;

			// S_GPROC32_ID
			{
				//fString name = transmute(fString)fn->fn->dbginfo_name;
				//CodeView_Function& fn = ctx.desc->functions[0];
				F_ASSERT(fn.name.len > 0);

				PROCSYM32 proc_sym = {};
				proc_sym.rectyp = S_GPROC32_ID;

				proc_sym.seg = 0; // Section number of the procedure. To be relocated
				{
					coffRelocation seg_reloc = {};
					seg_reloc.offset = (u32)ctx.debugS_builder->len + F_OFFSET_OF(PROCSYM32, seg);
					seg_reloc.sym_idx = fn.sym_index;
					//if (seg_reloc.sym_idx == 9) F_BP;
					seg_reloc.type = IMAGE_REL_AMD64_SECTION; // IMAGE_REL_X_SECTION sets the relocated value to be the section number of the target symbol
					f_array_push(ctx.debugS_relocs, seg_reloc);
				}

				proc_sym.off = 0; // Start offset of the function within the section. To be relocated
				{
					coffRelocation off_reloc = {};
					off_reloc.offset = (u32)ctx.debugS_builder->len + F_OFFSET_OF(PROCSYM32, off);
					off_reloc.sym_idx = fn.sym_index;
					//if (off_reloc.sym_idx == 9) F_BP;
					off_reloc.type = IMAGE_REL_AMD64_SECREL; // IMAGE_REL_X_SECREL sets the relocated value to be the offset of the target symbol from the beginning of its section
					f_array_push(ctx.debugS_relocs, off_reloc);
				}

				// in cvdump, this is the "Cb" field. This marks the size of the function in the .text section, in bytes.
				proc_sym.len = fn.block.end_offset - fn.block.start_offset;

				//F_BP;
				proc_sym.typind = 0; // this is an index of the symbol's type
				proc_sym.DbgStart = 0; // this seems to always be zero
				proc_sym.DbgEnd = proc_sym.len - 1; // this seems to usually (not always) be PROCSYM32.len - 1. Not sure what this means.

				uint base = ctx.debugS_builder->len;
				f_array_push_slice(ctx.debugS_builder, { (u8*)&proc_sym, sizeof(proc_sym) - 1 });
				f_array_push_slice(ctx.debugS_builder, F_BITCAST(fString, fn.name));
				f_array_push(ctx.debugS_builder, (u8)'\0');

				CodeviewPatchRecordLength(ctx.debugS_builder, base);
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
				f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(frameproc));
			}


			GenerateDebugSection_AddLocals(&ctx, to_codeview_type_idx, &fn, &fn.block);

			// S_PROC_ID_END
			{
				SYMTYPE sym;
				//sym.reclen = sizeof(SYMTYPE) - 2;
				sym.rectyp = S_PROC_ID_END;

				uint base = ctx.debugS_builder->len;
				f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(sym));

				CodeviewPatchRecordLength(ctx.debugS_builder, base);
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
			f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(subsection_header));
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
				f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(lines_header));

				struct {
					u32 fileid;
					u32 nLines;
					u32 cbFileBlock; // length of the file block, including the file block header
				} file_block_header;

				file_block_header.fileid = size_of_file_checksum_entry * fn.file_idx; // the 'fileid' seems to encode the offset into the FILECHKSUMS subsection
				file_block_header.nLines = (u32)fn.lines_count;
				file_block_header.cbFileBlock = sizeof(file_block_header) + file_block_header.nLines * sizeof(CV_Line_t);
				f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(file_block_header));

				// add the lines

				for (u32 i = 0; i < fn.lines_count; i++) {
					coffCVLine& line = fn.lines[i];

					CV_Line_t l = {};
					l.linenumStart = line.line_num;
					// line.deltaLineEnd is only used when column information is stored

					VALIDATE(line.offset >= fn.block.start_offset);
					l.offset = line.offset - fn.block.start_offset; // This offset is relative to lines_header.offCon (the start offset of the function)

					l.fStatement = 1; // not sure what this field means in practice
					f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(l));
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
		f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		{
			UDTSYM sym = {};
			sym.rectyp = S_UDT;
			sym.typind = 0x1001;
			F_BP;

			uint base = ctx.debugS_builder->len;
			f_array_push_slice(ctx.debugS_builder, { (u8*)&sym, F_OFFSET_OF(UDTSYM, name) });
			f_array_push_slice(ctx.debugS_builder, F_LIT("MyStruct"));
			f_array_push(ctx.debugS_builder, (u8)'\0');

			sym.reclen = (u16)(ctx.debugS_builder->len - (base + 2));
			f_slice_copy(f_slice(*ctx.debugS_builder, base, base + 2), F_AS_BYTES(sym.reclen));
		}

		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself and not including the padding bytes after the subsection.
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));

		AlignTo4Bytes(ctx.debugS_builder); // Subsections must be aligned to 4 byte boundaries.
	}
#endif

	fArray(u8) string_table = f_array_make<u8>(ctx.desc->allocator);
	f_array_push(&string_table, (u8)0); // Strings seem to begin at index 1

	// *** FILECHKSUMS
	{
		// see DumpModFileChecksums (microsoft's pdb source code dump)

		CV_DebugSSubsectionHeader_t subsection_header;
		subsection_header.type = DEBUG_S_FILECHKSMS;
		// subsection_header.cbLen
		f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		for (uint i = 0; i < ctx.desc->files_count; i++) {
			coffCVSourceFile* file = &ctx.desc->files[i];

			uint len_before = ctx.debugS_builder->len;

#pragma pack(push, 1) // specify 1-byte alignment
			struct {
				DWORD offstFileName;
				BYTE  cbChecksum;
				BYTE  ChecksumType;
			} filedata;
#pragma pack(pop)

			filedata.offstFileName = (u32)string_table.len; // offset to the filename in the string table
			filedata.cbChecksum = 32; // size of the checksum, in bytes. A SHA256 hash is 32-bytes long
			filedata.ChecksumType = CHKSUM_TYPE_SHA_256;

			fString filepath = F_BITCAST(fString, file->filepath);
			VALIDATE(!f_str_contains(filepath, F_LIT("/"))); // Only backslashes are allowed!

			f_array_push_slice(&string_table, filepath);
			f_array_push(&string_table, (u8)0);

			f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(filedata));

			//F_ASSERT(ctx.desc->dbginfo->file_hashes);

			f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(file->hash));

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
		f_array_push_slice(ctx.debugS_builder, F_AS_BYTES(subsection_header));
		u32 subsection_base = (u32)ctx.debugS_builder->len;

		f_array_push_slice(ctx.debugS_builder, string_table.slice);
		//{
		//	f_array_push(ctx.debugS_builder, (u8)'\0');
		//
		//	fString filepath = F_BITCAST(fString, ctx.desc->files[0].filepath);
		//	VALIDATE(!f_str_contains(filepath, F_LIT("/"))); // Only backslashes are allowed!
		//
		//	f_array_push_slice(ctx.debugS_builder, filepath);
		//	f_array_push(ctx.debugS_builder, (u8)'\0'); // null terminate each string
		//}

		u32 cbLen = (u32)ctx.debugS_builder->len - subsection_base; // cbLen is the size of the subsection in bytes, not including the header itself
		f_slice_copy(f_slice(*ctx.debugS_builder, subsection_base - 4, subsection_base), F_AS_BYTES(cbLen));
	}

	f_temp_pop();
}

GMMC_API coffCVGenerateDebugInfoResult coff_generate_debug_info(coffCVGenerateDebugInfoDesc* desc)
{
	// See DumpObjFileSections from the microsoft's pdb source code dump.
	// It's crazy how badly written all of the code in that release is. Just crazy.
	// Though, at least it's relatively easy to reverse-engineer, unlike LLVM's source code.

	// CodeView data section begins with a magic signature.

	fArray(u8) debugS_builder = f_array_make_cap<u8>(1024, desc->allocator);
	fArray(u8) debugT_builder = f_array_make_cap<u8>(1024, desc->allocator);
	fArray(u8) pdata_builder = f_array_make_cap<u8>(1024, desc->allocator);
	fArray(u8) xdata_builder = f_array_make_cap<u8>(1024, desc->allocator);

	fArray(coffRelocation) debugS_relocs = f_array_make_cap<coffRelocation>(32, desc->allocator);
	fArray(coffRelocation) pdata_relocs = f_array_make_cap<coffRelocation>(32, desc->allocator);
	
	GenerateDebugSections({ &debugS_builder, &debugS_relocs, &debugT_builder, desc });
	
	GenerateXDataAndPDataSections(&pdata_builder, &pdata_relocs, &xdata_builder, desc);

	coffCVGenerateDebugInfoResult result = {};
	result.debugS = debugS_builder.slice;
	result.debugS_relocs = debugS_relocs.slice;
	result.pdata = pdata_builder.slice;
	result.pdata_relocs = pdata_relocs.slice;
	result.xdata = xdata_builder.slice;
	result.debugT = debugT_builder.slice;
	return result;
}

#endif

#if 0
void GMMC_CreateHardcodedMinimalCoff(GMMC_CoffType type) {
	fArena arena = MakeArena(GiB(1), &_global_allocator);
	defer(DestroyArena(arena));

	// https://wiki.osdev.org/PE

	if (type == GMMC_CoffType_Exe) {
		// allocate DOS stub
		fString dos_stub = f_arena_push(&arena, 0xC8);
		memset(dos_stub.data, 0, dos_stub.len);
		memcpy(dos_stub.data, GMMC_default_MS_dos_stub, 128);
		F_ASSERT(*(u32*)(dos_stub.data + 0x3C) == 0xC8); // pointer to the PE signature

		// the signature will be placed at 0xC8
		fString pe_signature = f_arena_push(&arena, sizeof(u32));
		copy(pe_signature, F_LIT("PE\0\0"));
	}

	{
		const int y = sizeof(IMAGE_FILE_HEADER);
		const int x = sizeof(IMAGE_SECTION_HEADER);
		const int z = sizeof(IMAGE_SYMBOL);
	}


	IMAGE_FILE_HEADER* header = (IMAGE_FILE_HEADER*)f_arena_push(&arena, sizeof(IMAGE_FILE_HEADER)).data;
	header->Machine = IMAGE_FILE_MACHINE_AMD64;
	header->NumberOfSections = 2;

	header->TimeDateStamp = 0x63583C44;
	//header->PointerToSymbolTable is filled in later
	//header->NumberOfSymbols; // filled in later
	header->SizeOfOptionalHeader = 0;

	header->Characteristics = 0;

	// section headers
	IMAGE_SECTION_HEADER* sections[16];
	{
		{
			sections[0] = (IMAGE_SECTION_HEADER*)f_arena_push(&arena, sizeof(IMAGE_SECTION_HEADER)).data;
			const char* name = ".text$mn\0";
			memcpy(sections[0]->Name, name, sizeof(name));
			sections[0]->Misc.PhysicalAddress = 0;
			sections[0]->VirtualAddress = 0;
			sections[0]->SizeOfRawData = 0;
			sections[0]->PointerToRawData = 0;
			sections[0]->PointerToRelocations = 0;
			sections[0]->PointerToLinenumbers = 0;
			sections[0]->NumberOfRelocations = 0;
			sections[0]->NumberOfLinenumbers = 0;
			sections[0]->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
		}
		{
			sections[1] = (IMAGE_SECTION_HEADER*)f_arena_push(&arena, sizeof(IMAGE_SECTION_HEADER)).data;
			const char* name = ".data\0";
			memcpy(sections[1]->Name, name, sizeof(name));
			sections[1]->Misc.PhysicalAddress = 0;
			sections[1]->VirtualAddress = 0;
			sections[1]->SizeOfRawData = 0;
			sections[1]->PointerToRawData = 0;
			sections[1]->PointerToRelocations = 0;
			sections[1]->PointerToLinenumbers = 0;
			sections[1]->NumberOfRelocations = 0;
			sections[1]->NumberOfLinenumbers = 0;
			sections[1]->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_16BYTES | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
		}
	}

	IMAGE_RELOCATION* mybyte_reloc;
	// section 1 raw data
	// section 1 relocation table
	// section 2 raw data
	// ...
	{
		{
			static u8 section_1_data[] = { 0x48, 0x33, 0xC0, 0x8A, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3 };

			sections[0]->SizeOfRawData = LEN(section_1_data);
			sections[0]->PointerToRawData = (u32)arena.pos;
			f_arena_push_str(&arena, C_ARRAY_SLICE(section_1_data));

			// NOTE: relocations are only for object files
			sections[0]->PointerToRelocations = (u32)arena.pos;
			sections[0]->NumberOfRelocations = 1;

			mybyte_reloc = (IMAGE_RELOCATION*)f_arena_push(&arena, sizeof(IMAGE_RELOCATION)).data;
			mybyte_reloc->VirtualAddress = 0x5;
			//mybyte_reloc->SymbolTableIndex
			mybyte_reloc->Type = IMAGE_REL_AMD64_REL32;
		}

		{
			static u8 section_2_data[] = { 69 };
			sections[1]->SizeOfRawData = LEN(section_2_data);
			sections[1]->PointerToRawData = (u32)arena.pos;
			f_arena_push_str(&arena, C_ARRAY_SLICE(section_2_data));
		}
	}
	//F_ASSERT(arena.pos == 280);

// symbol table
	{
		// WARNING: header ptr must still be valid! Since this is an arena, it is.
		header->PointerToSymbolTable = (u32)arena.pos;

		{
			IMAGE_SYMBOL* s = (IMAGE_SYMBOL*)f_arena_push(&arena, sizeof(IMAGE_SYMBOL)).data;
			const char* name = ".text$mn";
			memcpy(s->N.ShortName, name, sizeof(name));
			s->value = 0;
			s->SectionNumber = 1;
			s->Type = IMAGE_SYM_TYPE_NULL;
			s->StorageClass = IMAGE_SYM_CLASS_STATIC;
			s->NumberOfAuxSymbols = 1;

			IMAGE_AUX_SYMBOL* aux = (IMAGE_AUX_SYMBOL*)f_arena_push(&arena, sizeof(IMAGE_AUX_SYMBOL)).data;
			aux->Section.Length = 8;
			aux->Section.NumberOfRelocations = 0;
			aux->Section.NumberOfLinenumbers = 0;
			aux->Section.CheckSum = 0;
			aux->Section.Number = 0;
			aux->Section.Selection = 0;

		}
		{
			IMAGE_SYMBOL* s = (IMAGE_SYMBOL*)f_arena_push(&arena, sizeof(IMAGE_SYMBOL)).data;
			const char* name = ".data\0";
			memcpy(s->N.ShortName, name, sizeof(name));
			s->value = 0;
			s->SectionNumber = 2;
			s->Type = IMAGE_SYM_TYPE_NULL;
			s->StorageClass = IMAGE_SYM_CLASS_STATIC;
			s->NumberOfAuxSymbols = 1;

			IMAGE_AUX_SYMBOL* aux = (IMAGE_AUX_SYMBOL*)f_arena_push(&arena, sizeof(IMAGE_AUX_SYMBOL)).data;
			aux->Section.Length = 0;
			aux->Section.NumberOfRelocations = 0;
			aux->Section.NumberOfLinenumbers = 0;
			aux->Section.CheckSum = 0;
			aux->Section.Number = 0;
			aux->Section.Selection = 0;

		}

		{
			// SymbolTableIndex counts in the auxilery symbol structures as well
			mybyte_reloc->SymbolTableIndex = ((u32)arena.pos - header->PointerToSymbolTable) / sizeof(IMAGE_SYMBOL);

			IMAGE_SYMBOL* s = (IMAGE_SYMBOL*)f_arena_push(&arena, sizeof(IMAGE_SYMBOL)).data;
			const char* name = "MyByte\0";
			memcpy(s->N.ShortName, name, sizeof(name));
			s->value = 0;
			s->SectionNumber = 2;
			s->Type = IMAGE_SYM_TYPE_NULL;
			s->StorageClass = IMAGE_SYM_CLASS_STATIC;
			s->NumberOfAuxSymbols = 0;
		}
		{
			IMAGE_SYMBOL* s = (IMAGE_SYMBOL*)f_arena_push(&arena, sizeof(IMAGE_SYMBOL)).data;
			const char* name = "coolfn\0";
			memcpy(s->N.ShortName, name, sizeof(name));
			s->value = 0;
			s->SectionNumber = 1;
			s->Type = 0x20; // 0x20 means 'function'
			s->StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
			s->NumberOfAuxSymbols = 0;
		}

		// note: auxilary symbol structures are counted into NumberOfSymbols. NumberOfSymbols seems to just be used for calculating the offset
		// of the string table.
		F_ASSERT((arena.pos - header->PointerToSymbolTable) % sizeof(IMAGE_SYMBOL) == 0);
		header->NumberOfSymbols = ((u32)arena.pos - header->PointerToSymbolTable) / sizeof(IMAGE_SYMBOL);
	}

	// string table
	{
		// string table size, including the field itself
		u32 s = 4;
		f_arena_push_str(&arena, F_AS_BYTES(s));
	}

	F_ASSERT(os_write_entire_file(F_LIT("minimal/gen_cool_function.obj"), { arena.mem, (uint)arena.pos }));
	//F_BP;
}
#endif
