// Command line ffz compiler

#define F_INCLUDE_OS
#include "../foundation/foundation.hpp"

#include "../ffz_ast.h"
#include "../ffz_checker.h"

//#include <Windows.h>
//#include <math.h>
//
//#include "gmmc/gmmc.h" // for gmmc_test

bool ffz_backend_gen_executable_gmmc(ffzModule* root_module, fString build_dir, fString name);


struct ErrorCallbackPassed {
	fString error_kind;
};

void log_pretty_error(ffzParser* p, ffzNode* node, ffzLocRange loc, fString error, void* userdata) {
	ErrorCallbackPassed* passed = (ErrorCallbackPassed*)userdata;
	
	f_os_print_color(passed->error_kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
	f_os_print(F_LIT("("));

	f_os_print_color(p->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);

	fString line_num_str = f_str_from_uint(loc.start.line_num, 10, f_temp_alc());

	f_os_print(F_LIT(":"));
	f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(":"));
	f_os_print_color(f_str_from_uint(loc.start.column_num, 10, f_temp_alc()), fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(")\n  "));
	f_os_print(error);
	f_os_print(F_LIT("\n"));
	//if (extra_newline) f_os_print(F_LIT("\n"));

	// Scan left until the start of the line
	uint line_start_offset = loc.start.offset;
	for (;;) {
		uint prev = line_start_offset;
		u8 r = (u8)f_str_prev_rune(p->source_code, &prev);
		if (r == 0 || r == '\n') break;
		line_start_offset = prev;
	}

	u16 code_color = fConsoleAttribute_Green | fConsoleAttribute_Red;

	fString src_line_separator = F_LIT(":    ");
	f_os_print_color(line_num_str, fConsoleAttribute_Intensify);
	f_os_print_color(src_line_separator, fConsoleAttribute_Intensify);
	fString start_str = f_str_replace(f_slice(p->source_code, line_start_offset, loc.start.offset), F_LIT("\t"), F_LIT("    "), f_temp_alc());
	f_os_print_color(start_str, code_color);

	{
		uint offset = loc.start.offset;
		for (uint i = 0;; i++) {
			rune r = (u8)f_str_next_rune(p->source_code, &offset);
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
			rune r = (u8)f_str_next_rune(p->source_code, &offset);
			if (r == 0 || r == '\n') break;

			f_os_print_color(F_LIT("^"), fConsoleAttribute_Red);
		}
	}

	f_trap();
}

static void dump_module_ast(ffzModule* m) {
	u8 console_buf[4096];
	fBufferedWriter console_writer;
	fWriter* w = f_open_buffered_writer(f_get_stdout(), console_buf, F_LEN(console_buf), &console_writer);
	f_print(w, "PRINTING AST: ======================================================\n");

	for (ffzNode* n = m->root->first_child; n; n = n->next) {
		ffz_print_ast(w, n);
		f_print(w, "\n");
	}

	f_print(w, "====================================================================\n\n");
	f_flush_buffered_writer(&console_writer);

}

static fOpt(ffzModule*) parse_and_check_directory(ffzProject* project, fString directory) {
	fArena* module_arena = _f_temp_arena; // TODO

	ErrorCallbackPassed error_cb_passed = {};
	error_cb_passed.error_kind = F_LIT("Syntax error ");
	ffzErrorCallback error_cb = { log_pretty_error, &error_cb_passed };

	fOpt(ffzModule*) module = ffz_project_add_module_from_filesystem(project, directory, module_arena, error_cb);
	if (!module) return NULL;

	if (!module->checked) {
		if (!ffz_module_resolve_imports(module,
			[](fString path, void* userdata) -> ffzModule* {
				ffzModule* module = (ffzModule*)userdata;

				// `:` means that the path is relative to the modules directory shipped with the compiler
				if (f_str_starts_with(path, F_LIT(":"))) {
					path = F_STR_T_JOIN(module->project->modules_directory, F_LIT("/"), f_str_slice_after(path, 1));
				}
				else {
					// let's make the import path absolute
					if (!f_files_path_to_canonical(module->directory, path, f_temp_alc(), &path)) {
						f_trap();
					}
				}

				ffzModule* imported = parse_and_check_directory(module->project, path);
				return imported;

			}, module, error_cb)) return NULL;


		error_cb_passed.error_kind = F_LIT("Semantic error ");
		if (!ffz_module_check_single(module, error_cb)) return NULL;
	}

	dump_module_ast(module);

	return module;
	//module->report_error = [](ffzModule* checker, fSlice(ffzNode*) poly_path, ffzNode* at, fString error) {
	//	ffzParser* parser = checker->project->parsers[at->id.parser_id];
	//
	//	ffz_log_pretty_error(parser, F_LIT("Semantic error "), at->loc, error, true);
	//	for (uint i = poly_path.len - 1; i < poly_path.len; i++) {
	//		ffz_log_pretty_error(parser, F_LIT("\n  ...inside instantiation "), poly_path[i]->loc, F_LIT(""), false);
	//	}
	//
	//	int a = 50;
	//};

	//module->parsers = f_make_slice_garbage<ffzParser*>(visit.files.len, module->alc);
	
}

int main(int argc, const char* argv[]) {
	//fHash64 h1 = f_hash64_start();
	//f_hash64_update(&h1, 0);
	//f_hash64_update(&h1, 1);
	//
	//fHash64 h2 = f_hash64_start();
	//f_hash64_update(&h2, 1);
	//f_hash64_update(&h2, 0);

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

	ffzModule* root_module = parse_and_check_directory(p, dir);
	if (root_module == NULL) return false;

	fString project_name = f_str_path_tail(dir);
	fString build_dir = F_STR_T_JOIN(dir, F_LIT("\\.build"));
	f_assert(f_files_make_directory(build_dir));
	
#if defined(FFZ_BUILD_INCLUDE_TB)
	if (!ffz_backend_gen_executable_tb(p)) {
		return 1;
	}
#elif defined(FFZ_BUILD_INCLUDE_GMMC)
	if (!ffz_backend_gen_executable_gmmc(root_module, build_dir, project_name)) {
		return 1;
	}
#else
#error
#endif

	f_os_print_color(F_LIT("Compile succeeded!\n"), fConsoleAttribute_Green | fConsoleAttribute_Intensify);

	f_deinit();
	return 0;
}
