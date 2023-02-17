#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"
#include "ffz_lib.h"

#include "ffz_backend_c0.h"
#include "ffz_backend_tb.h"

#include "microsoft_craziness.h"

#include <stdio.h>

#define OPT(x) x

// idea: typed array indexing. e.g.
// #TypeIdx: distinct int
// sizes: [,TypeIdx]u32
// sizes: [6, TypeIdx]u32
// 
// When iterating, the index type will be automatically the slice's index type:
// for i in sizes {} // i will be of type TypeIdx

void ffz_log_pretty_error(ffzParser* parser, String error_kind, ffzLocRange loc, String error, bool extra_newline = false) {
	Allocator* temp = temp_push(); defer(temp_pop());
	os_print_colored(error_kind, ConsoleAttribute_Red | ConsoleAttribute_Intensify);
	os_print(LIT("("));
	
	os_print_colored(parser->source_code_filepath, ConsoleAttribute_Green | ConsoleAttribute_Red | ConsoleAttribute_Intensify);

	String line_num_str = str_from_uint(AS_BYTES(loc.start.line_num), temp);

	os_print(LIT(":"));
	os_print_colored(line_num_str, ConsoleAttribute_Green | ConsoleAttribute_Red);
	os_print(LIT(":"));
	os_print_colored(str_from_uint(AS_BYTES(loc.start.column_num), temp), ConsoleAttribute_Green | ConsoleAttribute_Red);
	os_print(LIT(")\n  "));
	os_print(error);
	os_print(LIT("\n"));
	if (extra_newline) os_print(LIT("\n"));

	//String src_file = parser->src_file_contents[start.file_index];

	// Scan left until the start of the line
	uint line_start_offset = loc.start.offset;
	for (;;) {
		uint prev = line_start_offset;
		u8 r = (u8)str_prev_rune(parser->source_code, &prev);
		if (r == 0 || r == '\n') break;
		line_start_offset = prev;
	}

	u16 code_color = ConsoleAttribute_Green | ConsoleAttribute_Red;

	String src_line_separator = LIT(":    ");
	os_print_colored(line_num_str, ConsoleAttribute_Intensify);
	os_print_colored(src_line_separator, ConsoleAttribute_Intensify);
	String start_str = str_replace(slice(parser->source_code, line_start_offset, loc.start.offset), LIT("\t"), LIT("    "), temp);
	os_print_colored(start_str, code_color);
	
	{
		uint offset = loc.start.offset;
		for (uint i = 0;; i++) {
			rune r = (u8)str_next_rune(parser->source_code, &offset);
			if (r == 0 || r == '\n') break;

			u8 r_utf8[4];
			String r_str = { r_utf8, str_encode_rune(r_utf8, r) };
			os_print_colored(r_str, offset <= loc.end.offset ? (ConsoleAttribute_Red | ConsoleAttribute_Intensify) : code_color);
		}
		os_print(LIT("\n"));
	}

	{
		// write the ^^^ characters

		//for (i64 i=0; i<
		uint num_spaces = line_num_str.len + src_line_separator.len + str_rune_count(start_str);
		for (uint i = 0; i < num_spaces; i++) os_print(LIT(" "));

		uint offset = loc.start.offset;
		for (uint i = 0; offset < loc.end.offset; i++) {
			rune r = (u8)str_next_rune(parser->source_code, &offset);
			if (r == 0 || r == '\n') break;

			os_print_colored(LIT("^"), ConsoleAttribute_Red);
		}
	}
}

static bool _parse_and_check_directory(ffzProject* project, String directory, ffzChecker** out_checker, String _dbg_module_import_name) {
	ASSERT(os_path_is_absolute(directory)); // directory is also supposed to be minimal (not contain .././)
	Allocator* temp = temp_push(); defer(temp_pop());

	auto checker_insertion = map64_insert(&project->checked_module_from_directory, str_hash64_ex(directory, 0),
		(ffzChecker*)0, MapInsert_DoNotOverride);
	if (!checker_insertion.added) {
		*out_checker = *checker_insertion._unstable_ptr;
		return true;
	}

	ffzChecker* checker = mem_clone(ffzChecker{}, temp);
	*checker_insertion._unstable_ptr = checker;
	*out_checker = checker;

	checker->alc = temp;
	checker->project = project;
	checker->self_idx = (ffzCheckerIndex)array_push(&project->checkers, checker);

	checker->definition_map = make_map64<ffzNodeIdentifier*>(checker->alc);
	//checker->definition_from_node = make_map64_cap<ffzNodeIdentifier*>(1024, checker->alc);
	checker->cache = make_map64<ffzCheckedExpr>(checker->alc);
	checker->type_from_hash = make_map64<ffzType*>(checker->alc);
	checker->poly_instantiations = make_map64<ffzPolyInst>(checker->alc);
	checker->poly_instantiation_sites = make_map64<ffzPolyInstHash>(checker->alc);
	checker->record_field_from_name = make_map64<ffzTypeRecordFieldUse*>(checker->alc);
	checker->enum_value_from_name = make_map64<u64>(checker->alc);
	checker->enum_value_is_taken = make_map64<ffzNode*>(checker->alc);
	checker->imported_modules = make_map64<ffzChecker*>(checker->alc);

	checker->pointer_size = 8;
	{
		u32 a = ffzKeyword_u8;
		checker->builtin_types[ffzKeyword_u8-a] = { ffzTypeTag_SizedUint, 1, 1 };
		checker->builtin_types[ffzKeyword_u16-a] = { ffzTypeTag_SizedUint, 2, 2 };
		checker->builtin_types[ffzKeyword_u32-a] = { ffzTypeTag_SizedUint, 4, 4 };
		checker->builtin_types[ffzKeyword_u64-a] = { ffzTypeTag_SizedUint, 8, 8 };
		
		checker->builtin_types[ffzKeyword_s8-a] = { ffzTypeTag_SizedInt, 1, 1 };
		checker->builtin_types[ffzKeyword_s16-a] = { ffzTypeTag_SizedInt, 2, 2 };
		checker->builtin_types[ffzKeyword_s32-a] = { ffzTypeTag_SizedInt, 4, 4 };
		checker->builtin_types[ffzKeyword_s64-a] = { ffzTypeTag_SizedInt, 8, 8 };
		
		checker->builtin_types[ffzKeyword_uint-a] = { ffzTypeTag_Uint, checker->pointer_size, checker->pointer_size };
		checker->builtin_types[ffzKeyword_int-a] = { ffzTypeTag_Int, checker->pointer_size, checker->pointer_size };
		
		checker->builtin_types[ffzKeyword_bool-a] = { ffzTypeTag_Bool, 1, 1 };
		checker->builtin_types[ffzKeyword_string-a] = { ffzTypeTag_String, checker->pointer_size*2, checker->pointer_size };
	}

	checker->report_error = [](ffzChecker* checker, Slice<ffzNode*> poly_path, ffzNode* at, String error) {
		ffzParser* parser = checker->project->parsers_dependency_sorted[at->parser_idx];
		
		ffz_log_pretty_error(parser, LIT("Semantic error "), at->loc, error, true);
		for (uint i = poly_path.len - 1; i < poly_path.len; i++) {
			ffz_log_pretty_error(parser, LIT("\n  ...inside instantiation "), poly_path[i]->loc, LIT(""), false);
		}
		BP;
	};

#ifdef _DEBUG
	checker->_dbg_module_import_name = _dbg_module_import_name;
#endif

	struct FileVisitData {
		Array<String> files;
		String directory;
	} visit;
	visit.files = make_array<String>(temp);
	visit.directory = directory;

	if (!os_visit_directory(directory,
		[](const OS_VisitDirectoryInfo* info, void* userptr) -> OS_VisitDirectoryResult {
			FileVisitData* visit = (FileVisitData*)userptr;

			if (!info->is_directory && str_path_extension(info->name) == LIT("ffz") && info->name.data[0] == '.') {
				String filepath = str_join_il(visit->files.allocator, { visit->directory, LIT("\\"), info->name });
				array_push(&visit->files, filepath);
			}

			return OS_VisitDirectoryResult_Continue;
		}, &visit))
	{
		BP; // directory doesn't exist!
	}

		Slice<ffzParser*> parsers_dependency_sorted = make_slice_garbage<ffzParser*>(visit.files.len, temp);
		for (uint i = 0; i < visit.files.len; i++) {
			ffzParser* parser = mem_clone(ffzParser{}, temp);
			parsers_dependency_sorted[i] = parser;

			String file_contents;
			ASSERT(os_file_read_whole(visit.files[i], temp, &file_contents));

			parser->project = project;
			parser->self_idx = (ffzParserIndex)array_push(&project->parsers_dependency_sorted, parser);

			parser->alc = temp;
			parser->checker_idx = checker->self_idx;
			parser->source_code = file_contents;
			parser->source_code_filepath = visit.files[i];
			parser->report_error = [](ffzParser* parser, ffzLocRange at, String error) {
				ffz_log_pretty_error(parser, LIT("Syntax error "), at, error, true);
				BP;
			};

			parser->pos.offset = 0;
			parser->pos.line_num = 1;
			parser->pos.column_num = 1;
			parser->module_imports.alc = parser->alc;
			parser->tag_decl_lists.alc = parser->alc;

			ffzOk ok = ffz_parse(parser);
			if (!ok.ok) return false;

			
			{ // add linker inputs
				{
					ffzNodeTagDecl** first_linker_input = (ffzNodeTagDecl**)map64_get_raw(&parser->tag_decl_lists, str_hash64_ex(LIT("link_library"), 0));
					for (ffzNodeTagDecl* n = first_linker_input ? *first_linker_input : NULL; n; n = n->same_tag_next) {
						ASSERT(n->rhs->kind == ffzNodeKind_StringLiteral);
						String input = os_path_to_absolute(directory, FFZ_AS(n->rhs, StringLiteral)->zero_terminated_string, parser->alc);
						array_push(&project->linker_inputs, input);
					}
				}
				{
					ffzNodeTagDecl** first_linker_input = (ffzNodeTagDecl**)map64_get_raw(&parser->tag_decl_lists, str_hash64_ex(LIT("link_system_library"), 0));
					for (ffzNodeTagDecl* n = first_linker_input ? *first_linker_input : NULL; n; n = n->same_tag_next) {
						ASSERT(n->rhs->kind == ffzNodeKind_StringLiteral);
						array_push(&project->linker_inputs, FFZ_AS(n->rhs,StringLiteral)->zero_terminated_string);
					}
				}
			}


			if (true) {
				os_print(LIT("PRINTING AST: ======================================================\n"));
				Array<u8> builder = make_array_cap<u8>(64, temp);
				for (ffzNode* n = parser->root->children.first; n; n = n->next) {
					str_print_il(&builder, { ffz_print_ast(temp, n), LIT("\n") });
				}
				os_print(builder.slice);
				os_print(LIT("====================================================================\n\n"));
				int a = 250;
			}

			for (uint i = 0; i < parser->module_imports.len; i++) {
				ffzNodeKeyword* import_keyword = &((ffzNodeKeyword*)parser->module_imports.data)[i];
				ASSERT(import_keyword->parent && import_keyword->parent->kind == ffzNodeKind_Operator);
				
				ffzNodeOperator* import_op = FFZ_AS(import_keyword->parent,Operator);
				ASSERT(import_op->kind == ffzOperatorKind_PostRoundBrackets && ffz_get_child_count(FFZ_BASE(import_op)) == 1);
				
				ffzNode* import_name_node = ffz_get_child(FFZ_BASE(import_op), 0);
				ASSERT(import_name_node->kind == ffzNodeKind_StringLiteral);
				String import_name = FFZ_AS(import_name_node,StringLiteral)->zero_terminated_string;

				if (os_path_is_absolute(import_name)) BP;
				//BP;
				//String name = n->Statement.lhs_expression->Identifier.name;
				String child_directory = os_path_to_absolute(directory, import_name, temp);

				// Compile the imported module.

				ffzChecker* child_checker = NULL;
				bool ok = _parse_and_check_directory(project, child_directory, &child_checker, str_path_tail(child_directory));
				if (!ok) return false;

				map64_insert(&checker->imported_modules, (u64)import_op, child_checker);
			}

			//if (parser->module_imports) {
			//	if (parser->module_imports->kind != ffzNodeKind_Scope) BP;
			//
			//	for FFZ_EACH_NODE(n, parser->module_imports->Scope.nodes) {
			//		if (n->kind != ffzNodeKind_Statement) BP;
			//		if (!stmt_is_constant_decl(n)) BP;
			//	}
			//}
		}

		// checker stage
		{
			//ffzCheckerStackFrame root_frame = {};
			//ffzCheckerScope root_scope = {};
			//checker->current_scope = &root_scope;
			//array_push(&checker->stack, &root_frame);
			
			// We need to first add top-level declarations from all files before proceeding  :EarlyTopLevelDeclarations
			for (uint i = 0; i < parsers_dependency_sorted.len; i++) {
				ffzParser* parser = parsers_dependency_sorted[i];
				//root_scope.parser = parser;
				//checker->report_error_userptr = parser;

				if (!ffz_instanceless_check(checker, FFZ_BASE(parser->root), false).ok) {
					return false;
				}
			}

			for (uint i = 0; i < parsers_dependency_sorted.len; i++) {
				ffzParser* parser = parsers_dependency_sorted[i];
				//root_scope.parser = parser;
				//checker->report_error_userptr = parser;
				
				// Note that the root node of a parser should not introduce a new scope. Instead, the root-scope should be the module scope.
				for FFZ_EACH_CHILD(n, parser->root) {
					if (!ffz_check_toplevel_statement(checker, ffzNodeInst{ n, 0 }).ok) {
						return false;
					}
				}
			}
			//array_pop(&checker->stack);
		}

		return true;
}

bool ffz_parse_and_check_directory(ffzProject* project, String directory) {
	ffzChecker* checker;
	return _parse_and_check_directory(project, directory, &checker, {});
}

bool ffz_build_directory(String directory) {
	Allocator* temp = temp_push(); defer(temp_pop());

	ffzProject project = {};
	project.module_name = str_path_tail(directory);
	project.checked_module_from_directory = make_map64<ffzChecker*>(temp);
	project.checkers = make_array<ffzChecker*>(temp);
	project.parsers_dependency_sorted = make_array<ffzParser*>(temp);
	project.linker_inputs = make_array<String>(temp);
	
	String ffz_build_dir = os_path_to_absolute(directory, LIT(".ffz"), temp);
	//os_delete_directory(ffz_build_dir); // deleting a directory causes problems when visual studio is attached to the thing. Even if this is allowed to fail, it will still take a long time.
	ASSERT(os_make_directory(ffz_build_dir));

	if (!ffz_parse_and_check_directory(&project, directory)) return false;

	//ffzBackend gen = {};
	//gen.project = &project;
	//gen.gmmc = gmmc_init();
	//gen.allocator = temp;
	//gen.proc_gen = make_map64<ffzBackendProcGenerated>(gen.allocator);
	//gen.gmmc_proc_signature_from_type = make_map64<gmmcProcSignature*>(gen.allocator);
	//gen.gmmc_definition_value = make_map64<gmmcValue*>(gen.allocator);
	//gen.to_gmmc_type_idx = make_map64<gmmcDITypeIdx>(gen.allocator);
	////gen.file_idx_from_parser = make_map64<u32>(gen.allocator);
	//gen.gmmc_types = make_array_cap<gmmcDIType>(64, gen.allocator);
	//
	//static u8 _true = 1;
	//gen.gmmc_true = gmmc_val_constant(gen.gmmc, 1, &_true);
	//static u8 _false = 0;
	//gen.gmmc_false = gmmc_val_constant(gen.gmmc, 1, &_false);
	//
	String objname = STR_JOIN(temp, ffz_build_dir, LIT("\\"), project.module_name, LIT(".obj"));
	//
	ASSERT(os_set_working_dir(ffz_build_dir));
	//ffz_c0_generate(&project, "generated.c");
	ffz_tb_generate(&project, objname);

	WinSDK_Find_Result windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
	String msvc_directory = str_from_utf16(windows_sdk.vs_exe_path, temp); // contains cl.exe, link.exe
	String windows_sdk_include_base_path = str_from_utf16(windows_sdk.windows_sdk_include_base, temp); // contains <string.h>, etc
	String windows_sdk_um_library_path = str_from_utf16(windows_sdk.windows_sdk_um_library_path, temp); // contains kernel32.lib, etc
	String windows_sdk_ucrt_library_path = str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, temp); // contains libucrt.lib, etc
	String vs_library_path = str_from_utf16(windows_sdk.vs_library_path, temp); // contains MSVCRT.lib etc
	String vs_include_path = str_from_utf16(windows_sdk.vs_include_path, temp); // contains vcruntime.h

#if 0
	{
		Array<String> msvc_args = make_array<String>(temp);
		array_push(&msvc_args, STR_JOIN(temp, msvc_directory, LIT("\\cl.exe")));
		array_push(&msvc_args, LIT("/Zi"));
		array_push(&msvc_args, LIT("/std:c11"));
		array_push(&msvc_args, LIT("/Ob1")); // enable inlining
		array_push(&msvc_args, LIT("/MDd")); // raylib uses this setting
		array_push(&msvc_args, LIT("generated.c"));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/I"), windows_sdk_include_base_path, LIT("\\shared")));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/I"), windows_sdk_include_base_path, LIT("\\ucrt")));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/I"), windows_sdk_include_base_path, LIT("\\um")));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/I"), vs_include_path));
		
		array_push(&msvc_args, LIT("/link"));
		array_push(&msvc_args, LIT("/INCREMENTAL:NO"));
		array_push(&msvc_args, LIT("/MACHINE:X64"));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/LIBPATH:"), windows_sdk_um_library_path));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		array_push(&msvc_args, STR_JOIN(temp, LIT("/LIBPATH:"), vs_library_path));
		
		for (uint i = 0; i < project.linker_inputs.len; i++) {
			array_push(&msvc_args, project.linker_inputs[i]);
		}

		printf("Running cl.exe: \n");
		u32 exit_code;
		if (!os_run_command(msvc_args.slice, ffz_build_dir, &exit_code)) return false;
		if (exit_code != 0) return false;
	}
#endif

#if 1
	{
		Array<String> linker_args = make_array<String>(temp);
		array_push(&linker_args, STR_JOIN(temp, msvc_directory, LIT("\\link.exe")));
		
		// Note that we should not put quotation marks around the path. It's because of some weird rules with how command line arguments are combined into one string on windows.
		array_push(&linker_args, STR_JOIN(temp, LIT("/LIBPATH:"), windows_sdk_um_library_path));
		array_push(&linker_args, STR_JOIN(temp, LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		array_push(&linker_args, STR_JOIN(temp, LIT("/LIBPATH:"), vs_library_path));
		array_push(&linker_args, LIT("/INCREMENTAL:NO"));     // incremental linking would break things with the way we're generating OBJ files
		array_push(&linker_args, LIT("/DEBUG"));
		array_push(&linker_args, LIT("/NODEFAULTLIB")); // disable linking to CRT
		array_push(&linker_args, LIT("/SUBSYSTEM:WINDOWS"));
		array_push(&linker_args, LIT("/ENTRY:ffz_entry"));
		array_push(&linker_args, LIT("/OUT:.ffz/.exe"));
		array_push(&linker_args, objname);

		for (uint i = 0; i < project.linker_inputs.len; i++) {
			array_push(&linker_args, project.linker_inputs[i]);
		}

		printf("Running linker: \n");
		for (uint i = 0; i < linker_args.len; i++) {
			printf("\"%s\" ", str_to_cstring(linker_args[i], temp));
		}
		printf("\n\n");
		
		u32 exit_code;
		if (!os_run_command(linker_args.slice, directory, &exit_code)) return false; // @leak: WinSDK_free_resources
		if (exit_code != 0) return false; // @leak: WinSDK_free_resources
	}
#endif
	
	WinSDK_free_resources(&windows_sdk);

	// deinit_leak_tracker();
	// GMMC_Deinit(gen.gmmc);

	os_print_colored(LIT("Compile succeeded!\n"), ConsoleAttribute_Green | ConsoleAttribute_Intensify);
	return true;
}
