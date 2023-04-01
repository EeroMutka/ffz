// Command line ffz compiler

#define F_INCLUDE_OS
#include "../foundation/foundation.hpp"

#include "../ffz_ast.h"
#include "../ffz_checker.h"

//#include <Windows.h>
//#include <math.h>
//
//#include "gmmc/gmmc.h" // for gmmc_test

bool ffz_backend_gen_executable_gmmc(ffzProject* project, fString build_dir, fString name);


void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline = false) {
	f_os_print_color(error_kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
	f_os_print(F_LIT("("));

	f_os_print_color(parser->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);

	fString line_num_str = f_str_from_uint(loc.start.line_num, 10, f_temp_alc());

	f_os_print(F_LIT(":"));
	f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(":"));
	f_os_print_color(f_str_from_uint(loc.start.column_num, 10, f_temp_alc()), fConsoleAttribute_Green | fConsoleAttribute_Red);
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
	fString start_str = f_str_replace(f_slice(parser->source_code, line_start_offset, loc.start.offset), F_LIT("\t"), F_LIT("    "), f_temp_alc());
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

static bool parse_and_check_directory(ffzProject* project, fString _directory, ffzModule** out_checker) {
	fString directory;
	if (!f_files_path_to_canonical({}, _directory, f_temp_alc(), &directory)) {
		f_cprint("Invalid directory: \"~s\"\n", directory);
		return false;
	}

	auto checker_insertion = f_map64_insert(&project->checked_module_from_directory, f_hash64_str_ex(directory, 0),
		(ffzModule*)0, fMapInsert_DoNotOverride);
	if (!checker_insertion.added) {
		*out_checker = *checker_insertion._unstable_ptr;
		return true;
	}

	ffzModule* module = ffz_project_add_new_module(project, f_temp_alc());
	*checker_insertion._unstable_ptr = module;
	*out_checker = module;

	module->report_error = [](ffzModule* checker, fSlice(ffzNode*) poly_path, ffzNode* at, fString error) {
		ffzParser* parser = checker->project->parsers[at->id.parser_id];

		ffz_log_pretty_error(parser, F_LIT("Semantic error "), at->loc, error, true);
		for (uint i = poly_path.len - 1; i < poly_path.len; i++) {
			ffz_log_pretty_error(parser, F_LIT("\n  ...inside instantiation "), poly_path[i]->loc, F_LIT(""), false);
		}

		int a = 50;
	};

	struct FileVisitData {
		fArray(fString) files;
		fString directory;
	} visit;
	visit.files = f_array_make<fString>(f_temp_alc());
	visit.directory = directory;

	if (!f_files_visit_directory(directory,
		[](const fVisitDirectoryInfo* info, void* userptr) -> fVisitDirectoryResult {
			FileVisitData* visit = (FileVisitData*)userptr;

			if (!info->is_directory && f_str_path_extension(info->name) == F_LIT("ffz") && info->name.data[0] != '!') {
				fString filepath = f_str_join_il(visit->files.alc, { visit->directory, F_LIT("\\"), info->name });
				f_array_push(&visit->files, filepath);
			}

			return fVisitDirectoryResult_Continue;
		}, &visit))
	{
		__debugbreak(); //printf("Directory `~s` does not exist!\n", directory);
		return false;
	}

	module->parsers = f_make_slice_garbage<ffzParser*>(visit.files.len, module->alc);
	for (uint i = 0; i < visit.files.len; i++) {
		ffzParser* parser = f_mem_clone(ffzParser{}, f_temp_alc());
		module->parsers[i] = parser;

		fString file_contents;
		f_assert(f_files_read_whole(visit.files[i], f_temp_alc(), &file_contents));

		parser->project = project;
		parser->module = module;
		parser->alc = f_temp_alc();
		parser->id = (ffzParserID)f_array_push(&project->parsers, parser);
		parser->source_code = file_contents;
		parser->source_code_filepath = visit.files[i];
		parser->keyword_from_string = &project->keyword_from_string;
		parser->report_error = [](ffzParser* parser, ffzLocRange at, fString error) {
			ffz_log_pretty_error(parser, F_LIT("Syntax error "), at, error, true);
			f_trap();
		};

		parser->module_imports = f_array_make<ffzNodeKeyword*>(parser->alc);
		//parser->tag_decl_lists = f_map64_make<ffzNodeTagDecl*>(parser->alc);

		ffzOk ok = ffz_parse(parser);
		if (!ok.ok) return false;

		if (false) {
			u8 console_buf[4096];
			fBufferedWriter console_writer;
			fWriter* w = f_open_buffered_writer(f_get_stdout(), console_buf, F_LEN(console_buf), &console_writer);

			f_print(w, "PRINTING AST: ======================================================\n");
			for (ffzNode* n = parser->root->first_child; n; n = n->next) {
				ffz_print_ast(w, n);
				f_print(w, "\n");
			}
			f_print(w, "====================================================================\n\n");

			f_flush_buffered_writer(&console_writer);
		}

		// resolve imports
		for (uint i = 0; i < parser->module_imports.len; i++) {
			ffzNodeKeyword* import_keyword = parser->module_imports[i];

			ffzNodeOp* import_op = import_keyword->parent;
			f_assert(import_op && import_op->kind == ffzNodeKind_PostRoundBrackets && ffz_get_child_count(import_op) == 1);

			ffzNode* import_name_node = ffz_get_child(import_op, 0);
			f_assert(import_name_node->kind == ffzNodeKind_StringLiteral);
			fString import_path = import_name_node->StringLiteral.zero_terminated_string;

			// : means that the path is relative to the modules directory shipped with the compiler
			if (f_str_starts_with(import_path, F_LIT(":"))) {
				import_path = F_STR_T_JOIN(project->modules_directory, F_LIT("/"), f_str_slice_after(import_path, 1));
			}
			else {
				// let's make the import path absolute
				if (!f_files_path_to_canonical(module->directory, import_path, f_temp_alc(), &import_path)) {
					f_trap();
				}
			}

			// Compile the imported module.

			ffzModule* child_checker = NULL;
			bool ok = parse_and_check_directory(project, import_path, &child_checker);
			if (!ok) return false;

			f_map64_insert(&module->imported_modules, import_op->id.global_id, child_checker);
		}

		// Now that imported modules have been checked, we can add our module to the dependency-sorted array
		f_array_push(&project->checkers_dependency_sorted, module);
	}

	// checker stage
	{
		// We need to first add top-level declarations from all files before proceeding  :EarlyTopLevelDeclarations
		for (uint i = 0; i < module->parsers.len; i++) {
			ffzParser* parser = module->parsers[i];

			if (!ffz_instanceless_check(module, parser->root, false).ok) {
				return false;
			}
		}

		for (uint i = 0; i < module->parsers.len; i++) {
			ffzParser* parser = module->parsers[i];

			// Note that the root node of a parser should not introduce a new scope. Instead, the
			// root-scope should be the module scope.

			for (ffzNode* n = parser->root->first_child; n; n = n->next) {
				ffzNodeInst inst = ffz_get_toplevel_inst(module, n);

				// Standalone tags are skipped by FFZ_EACH_CHILD so treat them specially here.
				// This is a bit dumb way to do this, but right now standalone tags are only checked at top-level. We should
				// probably check them recursively in instanceless_check() or something. :StandaloneTagTopLevel
				if (n->flags & ffzNodeFlag_IsStandaloneTag) {
					if (!check_tag(module, inst).ok) {
						return false;
					}
					continue;
				}

				if (!ffz_check_toplevel_statement(module, n).ok) {
					f_trap();
					return false;
				}
			}
		}

		for (uint i = 0; i < module->extern_libraries.len; i++) {
			fString input = module->extern_libraries[i];
			if (input == F_LIT("?")) continue;

			if (f_str_cut_start(&input, F_LIT(":"))) {
				f_array_push(&project->link_system_libraries, input);
			}
			else {
				f_assert(f_files_path_to_canonical(directory, input, f_temp_alc(), &input));
				f_array_push(&project->link_libraries, input);
			}
		}
	}

	return true;
}


int main(int argc, const char* argv[]) {
	f_init();

	if (argc <= 1) {
		f_cprint("Please provide a directory to compile!\n");
		return 1;
	}
	
	fString dir = f_str_from_cstr(argv[1]);
	fString exe_path = f_os_get_executable_path(f_temp_alc());
	fString ffz_dir = f_str_path_dir(f_str_path_dir(exe_path));
	fString modules_dir = F_STR_T_JOIN(ffz_dir, F_LIT("/modules"));

	fArena* arena = _f_temp_arena;
	ffzProject* p = ffz_init_project(arena, modules_dir);

	ffzModule* checker;
	if (!parse_and_check_directory(p, dir, &checker)) return false;

	fString project_name = f_str_path_tail(dir);
	fString build_dir = F_STR_T_JOIN(dir, F_LIT("\\.build"));
	f_assert(f_files_make_directory(build_dir));

#if defined(FFZ_BUILD_INCLUDE_TB)
	if (!ffz_backend_gen_executable_tb(p)) {
		return 1;
	}
#elif defined(FFZ_BUILD_INCLUDE_GMMC)
	if (!ffz_backend_gen_executable_gmmc(p, build_dir, project_name)) {
		return 1;
	}
#else
#error
#endif

	f_os_print_color(F_LIT("Compile succeeded!\n"), fConsoleAttribute_Green | fConsoleAttribute_Intensify);

	f_deinit();
	return 0;
}
