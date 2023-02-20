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

void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline = false) {
	fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop());
	f_os_print_color(error_kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
	f_os_print(F_LIT("("));
	
	f_os_print_color(parser->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);

	fString line_num_str = f_str_from_uint(F_AS_BYTES(loc.start.line_num), temp);

	f_os_print(F_LIT(":"));
	f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(":"));
	f_os_print_color(f_str_from_uint(F_AS_BYTES(loc.start.column_num), temp), fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(")\n  "));
	f_os_print(error);
	f_os_print(F_LIT("\n"));
	if (extra_newline) f_os_print(F_LIT("\n"));

	//String src_file = parser->src_file_contents[start.file_index];

	// Scan left until the start of the line
	uint line_start_offset = loc.start.offset;
	for (;;) {
		uint prev = line_start_offset;
		u8 r = (u8)f_str_prev_rune(parser->source_code, &prev);
		if (r == 0 || r == '\n') break;
		line_start_offset = prev;
	}

	u16 code_color = fConsoleAttribute_Green | fConsoleAttribute_Red;

	fString src_line_separator = F_LIT(":    ");
	f_os_print_color(line_num_str, fConsoleAttribute_Intensify);
	f_os_print_color(src_line_separator, fConsoleAttribute_Intensify);
	fString start_str = f_str_replace(f_slice(parser->source_code, line_start_offset, loc.start.offset), F_LIT("\t"), F_LIT("    "), temp);
	f_os_print_color(start_str, code_color);
	
	{
		uint offset = loc.start.offset;
		for (uint i = 0;; i++) {
			rune r = (u8)f_str_next_rune(parser->source_code, &offset);
			if (r == 0 || r == '\n') break;

			u8 r_utf8[4];
			fString r_str = { r_utf8, f_str_encode_rune(r_utf8, r) };
			f_os_print_color(r_str, offset <= loc.end.offset ? (fConsoleAttribute_Red | fConsoleAttribute_Intensify) : code_color);
		}
		f_os_print(F_LIT("\n"));
	}

	{
		// write the ^^^ characters

		//for (i64 i=0; i<
		uint num_spaces = line_num_str.len + src_line_separator.len + f_str_rune_count(start_str);
		for (uint i = 0; i < num_spaces; i++) f_os_print(F_LIT(" "));

		uint offset = loc.start.offset;
		for (uint i = 0; offset < loc.end.offset; i++) {
			rune r = (u8)f_str_next_rune(parser->source_code, &offset);
			if (r == 0 || r == '\n') break;

			f_os_print_color(F_LIT("^"), fConsoleAttribute_Red);
		}
	}
}

static bool _parse_and_check_directory(ffzProject* project, fString directory, ffzChecker** out_checker, fString _dbg_module_import_name) {
	F_ASSERT(f_files_path_is_absolute(directory)); // directory is also supposed to be minimal (not contain .././)
	fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop());

	auto checker_insertion = f_map64_insert(&project->checked_module_from_directory, f_hash64_str_ex(directory, 0),
		(ffzChecker*)0, fMapInsert_DoNotOverride);
	if (!checker_insertion.added) {
		*out_checker = *checker_insertion._unstable_ptr;
		return true;
	}

	ffzChecker* checker = ffz_checker_init(temp);
	*checker_insertion._unstable_ptr = checker;
	checker->project = project;
	checker->self_idx = (ffzCheckerIndex)f_array_push(&project->checkers, checker);
	
	checker->report_error = [](ffzChecker* checker, fSlice(ffzNode*) poly_path, ffzNode* at, fString error) {
		ffzParser* parser = checker->project->parsers_dependency_sorted[at->parser_idx];

		ffz_log_pretty_error(parser, F_LIT("Semantic error "), at->loc, error, true);
		for (uint i = poly_path.len - 1; i < poly_path.len; i++) {
			ffz_log_pretty_error(parser, F_LIT("\n  ...inside instantiation "), poly_path[i]->loc, F_LIT(""), false);
		}
		F_BP;
	};

	*out_checker = checker;

#ifdef _DEBUG
	checker->_dbg_module_import_name = _dbg_module_import_name;
#endif

	struct FileVisitData {
		fArray(fString) files;
		fString directory;
	} visit;
	visit.files = f_array_make<fString>(temp);
	visit.directory = directory;

	if (!f_files_visit_directory(directory,
		[](const fVisitDirectoryInfo* info, void* userptr) -> fVisitDirectoryResult {
			FileVisitData* visit = (FileVisitData*)userptr;

			if (!info->is_directory && f_str_path_extension(info->name) == F_LIT("ffz") && info->name.data[0] == '.') {
				fString filepath = f_str_join_il(visit->files.alc, { visit->directory, F_LIT("\\"), info->name });
				f_array_push(&visit->files, filepath);
			}

			return fVisitDirectoryResult_Continue;
		}, &visit))
	{
		F_BP; // directory doesn't exist!
	}

		fSlice(ffzParser*) parsers_dependency_sorted = f_make_slice_garbage<ffzParser*>(visit.files.len, temp);
		for (uint i = 0; i < visit.files.len; i++) {
			ffzParser* parser = f_mem_clone(ffzParser{}, temp);
			parsers_dependency_sorted[i] = parser;

			fString file_contents;
			F_ASSERT(f_files_read_whole(visit.files[i], temp, &file_contents));

			parser->project = project;
			parser->self_idx = (ffzParserIndex)f_array_push(&project->parsers_dependency_sorted, parser);

			parser->alc = temp;
			parser->checker_idx = checker->self_idx;
			parser->source_code = file_contents;
			parser->source_code_filepath = visit.files[i];
			parser->report_error = [](ffzParser* parser, ffzLocRange at, fString error) {
				ffz_log_pretty_error(parser, F_LIT("Syntax error "), at, error, true);
				F_BP;
			};

			parser->pos.offset = 0;
			parser->pos.line_num = 1;
			parser->pos.column_num = 1;
			parser->module_imports = f_array_make<ffzNodeKeyword*>(parser->alc);
			parser->tag_decl_lists = f_map64_make<ffzNodeTagDecl*>(parser->alc);

			ffzOk ok = ffz_parse(parser);
			if (!ok.ok) return false;

			
			{ // add linker inputs
				{
					//f_map64_get(
					auto foo = f_map64_get(&parser->tag_decl_lists, f_hash64_str_ex(F_LIT("link_library"), 0));
					ffzNodeTagDecl** first_linker_input = foo;
					for (ffzNodeTagDecl* n = first_linker_input ? *first_linker_input : NULL; n; n = n->same_tag_next) {
						F_ASSERT(n->rhs->kind == ffzNodeKind_StringLiteral);
						fString input = f_files_path_to_absolute(directory, FFZ_AS(n->rhs, StringLiteral)->zero_terminated_string, parser->alc);
						f_array_push(&project->linker_inputs, input);
					}
				}
				{
					ffzNodeTagDecl** first_linker_input = f_map64_get(&parser->tag_decl_lists, f_hash64_str_ex(F_LIT("link_system_library"), 0));
					for (ffzNodeTagDecl* n = first_linker_input ? *first_linker_input : NULL; n; n = n->same_tag_next) {
						F_ASSERT(n->rhs->kind == ffzNodeKind_StringLiteral);
						f_array_push(&project->linker_inputs, FFZ_AS(n->rhs,StringLiteral)->zero_terminated_string);
					}
				}
			}


			if (true) {
				f_os_print(F_LIT("PRINTING AST: ======================================================\n"));
				fArray(u8) builder = f_array_make_cap<u8>(64, temp);
				for (ffzNode* n = parser->root->children.first; n; n = n->next) {
					f_str_print_il(&builder, { ffz_print_ast(temp, n), F_LIT("\n") });
				}
				f_os_print(builder.slice);
				f_os_print(F_LIT("====================================================================\n\n"));
				int a = 250;
			}

			for (uint i = 0; i < parser->module_imports.len; i++) {
				ffzNodeKeyword* import_keyword = parser->module_imports[i];
				F_ASSERT(import_keyword->parent && import_keyword->parent->kind == ffzNodeKind_Operator);
				
				ffzNodeOperator* import_op = FFZ_AS(import_keyword->parent,Operator);
				F_ASSERT(import_op->op_kind == ffzOperatorKind_PostRoundBrackets && ffz_get_child_count(FFZ_BASE(import_op)) == 1);
				
				ffzNode* import_name_node = ffz_get_child(FFZ_BASE(import_op), 0);
				F_ASSERT(import_name_node->kind == ffzNodeKind_StringLiteral);
				fString import_name = FFZ_AS(import_name_node,StringLiteral)->zero_terminated_string;

				if (f_files_path_is_absolute(import_name)) F_BP;
				//BP;
				//String name = n->Statement.lhs_expression->Identifier.name;
				fString child_directory = f_files_path_to_absolute(directory, import_name, temp);

				// Compile the imported module.

				ffzChecker* child_checker = NULL;
				bool ok = _parse_and_check_directory(project, child_directory, &child_checker, f_str_path_tail(child_directory));
				if (!ok) return false;

				f_map64_insert(&checker->imported_modules, (u64)import_op, child_checker);
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

bool ffz_parse_and_check_directory(ffzProject* project, fString directory) {
	ffzChecker* checker;
	return _parse_and_check_directory(project, directory, &checker, {});
}

bool ffz_build_directory(fString directory) {
	fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop());

	ffzProject project = {};
	project.module_name = f_str_path_tail(directory);
	project.checked_module_from_directory = f_map64_make<ffzChecker*>(temp);
	project.checkers = f_array_make<ffzChecker*>(temp);
	project.parsers_dependency_sorted = f_array_make<ffzParser*>(temp);
	project.linker_inputs = f_array_make<fString>(temp);
	
	fString ffz_build_dir = f_files_path_to_absolute(directory, F_LIT(".ffz"), temp);
	//os_delete_directory(ffz_build_dir); // deleting a directory causes problems when visual studio is attached to the thing. Even if this is allowed to fail, it will still take a long time.
	F_ASSERT(f_files_make_directory(ffz_build_dir));

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
	fString objname = F_STR_JOIN(temp, ffz_build_dir, F_LIT("\\"), project.module_name, F_LIT(".obj"));
	//
	F_ASSERT(f_os_set_working_dir(ffz_build_dir));
	//ffz_c0_generate(&project, "generated.c");
	ffz_tb_generate(&project, objname);

	WinSDK_Find_Result windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
	fString msvc_directory = f_str_from_utf16(windows_sdk.vs_exe_path, temp); // contains cl.exe, link.exe
	fString windows_sdk_include_base_path = f_str_from_utf16(windows_sdk.windows_sdk_include_base, temp); // contains <string.h>, etc
	fString windows_sdk_um_library_path = f_str_from_utf16(windows_sdk.windows_sdk_um_library_path, temp); // contains kernel32.lib, etc
	fString windows_sdk_ucrt_library_path = f_str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, temp); // contains libucrt.lib, etc
	fString vs_library_path = f_str_from_utf16(windows_sdk.vs_library_path, temp); // contains MSVCRT.lib etc
	fString vs_include_path = f_str_from_utf16(windows_sdk.vs_include_path, temp); // contains vcruntime.h

#if 0
	{
		Array<String> msvc_args = make_array<String>(temp);
		array_push(&msvc_args, STR_JOIN(temp, msvc_directory, F_LIT("\\cl.exe")));
		array_push(&msvc_args, F_LIT("/Zi"));
		array_push(&msvc_args, F_LIT("/std:c11"));
		array_push(&msvc_args, F_LIT("/Ob1")); // enable inlining
		array_push(&msvc_args, F_LIT("/MDd")); // raylib uses this setting
		array_push(&msvc_args, F_LIT("generated.c"));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\shared")));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\ucrt")));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), windows_sdk_include_base_path, F_LIT("\\um")));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/I"), vs_include_path));
		
		array_push(&msvc_args, F_LIT("/link"));
		array_push(&msvc_args, F_LIT("/INCREMENTAL:NO"));
		array_push(&msvc_args, F_LIT("/MACHINE:X64"));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		array_push(&msvc_args, STR_JOIN(temp, F_LIT("/LIBPATH:"), vs_library_path));
		
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
		fArray(fString) linker_args = f_array_make<fString>(temp);
		f_array_push(&linker_args, F_STR_JOIN(temp, msvc_directory, F_LIT("\\link.exe")));
		
		// Note that we should not put quotation marks around the path. It's because of some weird rules with how command line arguments are combined into one string on windows.
		f_array_push(&linker_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		f_array_push(&linker_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		f_array_push(&linker_args, F_STR_JOIN(temp, F_LIT("/LIBPATH:"), vs_library_path));
		f_array_push(&linker_args, F_LIT("/INCREMENTAL:NO"));     // incremental linking would break things with the way we're generating OBJ files
		f_array_push(&linker_args, F_LIT("/DEBUG"));
		
		// f_array_push(&linker_args, F_LIT("/NODEFAULTLIB")); // disable linking to CRT

		bool console_app = true;
		f_array_push(&linker_args, console_app ? F_LIT("/SUBSYSTEM:CONSOLE") : F_LIT("/SUBSYSTEM:WINDOWS"));
		//if (!console_app) f_array_push(&linker_args, F_LIT("/ENTRY:ffz_entry"));

		f_array_push(&linker_args, F_LIT("/OUT:.ffz/.exe"));
		f_array_push(&linker_args, objname);

		for (uint i = 0; i < project.linker_inputs.len; i++) {
			f_array_push(&linker_args, project.linker_inputs[i]);
		}

		printf("Running linker: \n");
		for (uint i = 0; i < linker_args.len; i++) {
			printf("\"%s\" ", f_str_to_cstr(linker_args[i], temp));
		}
		printf("\n\n");
		
		u32 exit_code;
		if (!f_os_run_command(linker_args.slice, directory, &exit_code)) return false; // @leak: WinSDK_free_resources
		if (exit_code != 0) return false; // @leak: WinSDK_free_resources
	}
#endif
	
	WinSDK_free_resources(&windows_sdk);

	// deinit_leak_tracker();
	// GMMC_Deinit(gen.gmmc);

	f_os_print_color(F_LIT("Compile succeeded!\n"), fConsoleAttribute_Green | fConsoleAttribute_Intensify);
	return true;
}
