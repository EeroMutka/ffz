#include "src/foundation/foundation.h"

#define coffString fString
#include "coff.h"

// TODO: We should be pulling out the stuff we use out from the windows headers and documenting it while we're here
#include <Windows.h>

#include <stdio.h> // for printf

// If VALIDATE fails, it means that the user of the library has provided invalid inputs. (assuming there's no bug within the library itself)
#define VALIDATE(x) f_assert(x)

COFF_API void coff_create(void(*store_result)(coffString, void*), void* store_result_userptr, coffDesc* desc) {
	fArray(u8) string_table = f_array_make(f_temp_alc());
	
	fArena* arena = f_arena_make_virtual_reserve_fixed(F_GIB(2), NULL);
	
	IMAGE_FILE_HEADER* header = (IMAGE_FILE_HEADER*)f_arena_push_zero(arena, sizeof(IMAGE_FILE_HEADER), 1);
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
	else f_assert(false);
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
		coffSection section = desc->sections[i];

		IMAGE_SECTION_HEADER* s_header = (IMAGE_SECTION_HEADER*)f_arena_push_zero(arena, sizeof(IMAGE_SECTION_HEADER), 1);

		f_assert(section.name.len <= 8);
		memcpy(s_header->Name, section.name.data, section.name.len);

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

	fArray(DWORD*) patch_symbol_index_with_real_index = f_array_make(f_temp_alc());

	for (u32 i = 0; i < desc->sections_count; i++) {
		coffSection section = desc->sections[i];

		sections[i]->SizeOfRawData = (u32)section.data.len;
		if (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
			VALIDATE(section.data.data == NULL);
		}
		else {
			sections[i]->PointerToRawData = (u32)f_arena_get_contiguous_cursor(arena);
			f_arena_push(arena, section.data, 1);
		}
		
		// --- Relocations ---

		// NOTE: relocations are only for object files

		if (section.relocations_count > 0) {
			sections[i]->PointerToRelocations = (u32)f_arena_get_contiguous_cursor(arena);

			VALIDATE(section.relocations_count < F_U16_MAX);
			sections[i]->NumberOfRelocations = (u16)section.relocations_count;

			for (u32 i = 0; i < section.relocations_count; i++) {
				coffRelocation r = section.relocations[i];
				VALIDATE(r.sym_idx < desc->symbols_count);

				IMAGE_RELOCATION* reloc = (IMAGE_RELOCATION*)f_arena_push_zero(arena, sizeof(IMAGE_RELOCATION), 1);
				reloc->VirtualAddress = r.offset;

				DWORD* patch_sym_idx = &reloc->SymbolTableIndex;
				f_array_push(&patch_symbol_index_with_real_index, patch_sym_idx);
				reloc->SymbolTableIndex = r.sym_idx;

				reloc->Type = r.type;
			}
		}
	}

	// symbol table
	{

		// Warning: header ptr must still be valid! Since this is an arena, it is.
		header->PointerToSymbolTable = (u32)f_arena_get_contiguous_cursor(arena);

		u32* symbol_index_to_real_index = f_mem_alloc_n(u32, desc->symbols_count, f_temp_alc());

		u32 real_symbol_index = 0;
		for (u32 i = 0; i < desc->symbols_count; i++) {
			coffSymbol symbol = desc->symbols[i];
			symbol_index_to_real_index[i] = real_symbol_index;

			//if (symbol.name == F_LIT(".debug$S")) f_trap();

			IMAGE_SYMBOL* s = (IMAGE_SYMBOL*)f_arena_push_zero(arena, sizeof(IMAGE_SYMBOL), 1);

			s->N.Name.Short = 0;
			s->N.Name.Long = 0;
			if (symbol.name.len <= 8) {
				// use short name
				memcpy(s->N.ShortName, symbol.name.data, symbol.name.len);
			}
			else {
				// the 'Long' field represents the offset into the string table,
				// where 0 points to the 4-byte string table size field that is encoded at the beginning
				// of the string table.

				s->N.Name.Long = 4 + (u32)string_table.len;

				f_array_push_n_raw(&string_table, symbol.name.data, symbol.name.len, 1);
				u8 zero = 0;
				f_array_push(&string_table, zero); // Strings in the string table must be null-terminated
			}

			s->SectionNumber = symbol.section_number;  // special values: IMAGE_SYM_ABSOLUTE, IMAGE_SYM_UNDEFINED, IMAGE_SYM_DEBUG
			s->Value = symbol.value;
			s->Type = symbol.type; // 0x20 means 'function'
			s->StorageClass = symbol.is_external ? IMAGE_SYM_CLASS_EXTERNAL : IMAGE_SYM_CLASS_STATIC;
			s->NumberOfAuxSymbols = 0;

			if (symbol.is_section) {
				VALIDATE(!symbol.is_external);

				IMAGE_SECTION_HEADER* section = sections[symbol.section_number - 1];

				IMAGE_AUX_SYMBOL* aux = (IMAGE_AUX_SYMBOL*)f_arena_push_zero(arena, sizeof(IMAGE_AUX_SYMBOL), 1);
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
			DWORD* idx = f_array_get(DWORD*, patch_symbol_index_with_real_index, i);
			*idx = symbol_index_to_real_index[*idx];
		}

		// note: auxilary symbol structures are counted into NumberOfSymbols.
		// NumberOfSymbols seems to be mainly used for calculating the offset
		// of the string table.
		f_assert((f_arena_get_contiguous_cursor(arena) - header->PointerToSymbolTable) % sizeof(IMAGE_SYMBOL) == 0);
		header->NumberOfSymbols = ((u32)f_arena_get_contiguous_cursor(arena) - header->PointerToSymbolTable) / sizeof(IMAGE_SYMBOL);
	}

	// string table
	{
		u32 s = 4 + (u32)string_table.len; // string table size, including the field itself
		f_arena_push(arena, F_AS_BYTES(s), 1);
		f_arena_push(arena, (fString){string_table.data, string_table.len}, 1);
	}

	// We're done!
	store_result((coffString){ f_arena_get_contiguous_base(arena), f_arena_get_contiguous_cursor(arena) }, store_result_userptr);

	f_arena_free(arena);
	//f_temp_pop();
}


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
		f_assert(*(u32*)(dos_stub.data + 0x3C) == 0xC8); // pointer to the PE signature

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
	//f_assert(arena.pos == 280);

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
		f_assert((arena.pos - header->PointerToSymbolTable) % sizeof(IMAGE_SYMBOL) == 0);
		header->NumberOfSymbols = ((u32)arena.pos - header->PointerToSymbolTable) / sizeof(IMAGE_SYMBOL);
	}

	// string table
	{
		// string table size, including the field itself
		u32 s = 4;
		f_arena_push_str(&arena, F_AS_BYTES(s));
	}

	f_assert(os_write_entire_file(F_LIT("minimal/gen_cool_function.obj"), { arena.mem, (uint)arena.pos }));
	//f_trap();
}

#endif