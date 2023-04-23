
// Command line ffz compiler

#define F_INCLUDE_OS
#include "../foundation/foundation.h"

#include "../ffz_ast.h"
#include "../ffz_checker.h"

#include "../tracy/tracy/TracyC.h"

//#include <Windows.h>
//#include <math.h>
//
//#include "gmmc/gmmc.h" // for gmmc_test

bool ffz_backend_gen_executable_gmmc(ffzModule* root_module, fString build_dir, fString name);

static fOpt(ffzModule*) parse_and_check_directory(ffzProject* project, fString directory);

//struct ErrorCallbackPassed {
//	fString error_kind;
//};

void log_pretty_error(ffzError error, fString kind) {
	//ErrorCallbackPassed* passed = (ErrorCallbackPassed*)userdata;
	
	f_os_print_color(kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
	f_os_print(F_LIT("("));

	f_assert(error.source); // TODO

	f_os_print_color(error.source->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);

	fString line_num_str = f_str_from_uint(error.location.start.line_num, 10, f_temp_alc());

	f_os_print(F_LIT(":"));
	f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(":"));
	f_os_print_color(f_str_from_uint(error.location.start.column_num, 10, f_temp_alc()), fConsoleAttribute_Green | fConsoleAttribute_Red);
	f_os_print(F_LIT(")\n  "));
	f_os_print(error.message);
	f_os_print(F_LIT("\n"));
	//if (extra_newline) f_os_print(F_LIT("\n"));

	// Scan left until the start of the line
	uint line_start_offset = error.location.start.offset;
	for (;;) {
		uint prev = line_start_offset;
		u8 r = (u8)f_str_prev_rune(error.source->source_code, &prev);
		if (r == 0 || r == '\n') break;
		line_start_offset = prev;
	}

	u16 code_color = fConsoleAttribute_Green | fConsoleAttribute_Red;

	fString src_line_separator = F_LIT(":    ");
	f_os_print_color(line_num_str, fConsoleAttribute_Intensify);
	f_os_print_color(src_line_separator, fConsoleAttribute_Intensify);
	
	fString start_str = f_str_slice(error.source->source_code, line_start_offset, error.location.start.offset);
	start_str = f_str_replace(start_str, F_LIT("\t"), F_LIT("    "), f_temp_alc());
	f_os_print_color(start_str, code_color);

	{
		uint offset = error.location.start.offset;
		for (;;) {
			rune r = (u8)f_str_next_rune(error.source->source_code, &offset);
			if (r == 0 || r == '\n') break;

			u8 r_utf8[4];
			fString r_str = { r_utf8, f_str_encode_rune(r_utf8, r) };
			f_os_print_color(r_str, offset <= error.location.end.offset ? (fConsoleAttribute_Red | fConsoleAttribute_Intensify) : code_color);
		}
		f_os_print(F_LIT("\n"));
	}

	{
		// write the ^^^ characters

		//for (i64 i=0; i<
		uint num_spaces = line_num_str.len + src_line_separator.len + f_str_rune_count(start_str);
		for (uint i = 0; i < num_spaces; i++) f_os_print(F_LIT(" "));

		uint offset = error.location.start.offset;
		while (offset < error.location.end.offset) {
			rune r = (u8)f_str_next_rune(error.source->source_code, &offset);
			if (r == 0 || r == '\n') break;

			f_os_print_color(F_LIT("^"), fConsoleAttribute_Red);
		}
	}
	f_os_print(F_LIT("\n"));
}

inline void log_pretty_syntax_error(ffzError error) { log_pretty_error(error, F_LIT("Syntax error ")); }
inline void log_pretty_semantic_error(ffzError error) { log_pretty_error(error, F_LIT("Semantic error ")); }

const bool DEBUG_PRINT_AST = false;

static void dump_module_ast(ffzModule* m, fString dir) {
	u8 console_buf[4096];
	fBufferedWriter console_writer;
	fWriter* w = f_open_buffered_writer(f_get_stdout(), console_buf, F_LEN(console_buf), &console_writer);
	f_print(w, "PRINTING AST: (~s) ======================================================\n", dir);
	
	for (ffzNode* n = m->root->first_child; n; n = n->next) {
		ffz_print_ast(w, n);
		f_print(w, "\n");
	}

	f_print(w, "====================================================================\n\n");
	f_flush_buffered_writer(&console_writer);
}

static fOpt(ffzModule*) resolve_import(fString path, void* userdata) {
	ffzModule* module = (ffzModule*)userdata;

	// `:` means that the path is relative to the modules directory shipped with the compiler
	if (f_str_starts_with(path, F_LIT(":"))) {
		fString slash = F_LIT("/");
		
		path = f_str_join_tmp(module->project->modules_directory, slash, f_str_slice_after(path, 1));
	}
	else {
		// let's make the import path absolute
		if (!f_files_path_to_canonical(module->directory, path, f_temp_alc(), &path)) {
			f_trap();
		}
	}

	fOpt(ffzModule*) imported = parse_and_check_directory(module->project, path);
	return imported;
}

static fOpt(ffzModule*) parse_and_check_directory(ffzProject* project, fString directory) {
	TracyCZone(tr, true);
	fArena* module_arena = _f_temp_arena; // TODO

	ffzError err;
	fOpt(ffzModule*) module = ffz_project_add_module_from_filesystem(project, directory, module_arena, &err);

	if (module && !module->checked) {
		
		if (!ffz_module_resolve_imports_(module, resolve_import, module).ok) {
			err = module->error;
			module = NULL;
		}

		if (module && !ffz_module_check_single_(module).ok) {
			err = module->error;
			module = NULL;
		}
		
		if (module && DEBUG_PRINT_AST) {
			dump_module_ast(module, directory);
		}
	}

	if (!module) {
		log_pretty_syntax_error(err);
	}

	TracyCZoneEnd(tr);
	return module;
}

int main(int argc, const char* argv[]) {
	TracyCZone(tr, true);

	//fHash64 h1 = f_hash64_start();
	//f_hash64_update(&h1, 0);
	//f_hash64_update(&h1, 1);
	//
	//fHash64 h2 = f_hash64_start();
	//f_hash64_update(&h2, 1);
	//f_hash64_update(&h2, 0);

	f_init();

	bool ok = true;
	if (argc <= 1) {
		f_cprint("Please provide a directory to compile!\n");
		ok = false;
	}

	if (ok) {
		fSliceRaw my_strings = f_slice_lit(fString, F_LIT("heyy"), F_LIT("sailor"));
		F_UNUSED(my_strings);

		fString dir = f_str_from_cstr(argv[1]);
		fString exe_path = f_os_get_executable_path(f_temp_alc());
		fString ffz_dir = f_str_path_dir(f_str_path_dir(exe_path));
		fString modules_dir = f_str_join_tmp(ffz_dir, F_LIT("/modules"));

		fArena* arena = _f_temp_arena;
		ffzProject* p = ffz_init_project(arena, modules_dir);

		ffzModule* root_module = parse_and_check_directory(p, dir);
		if (root_module == NULL) return false;

		fString project_name = f_str_path_tail(dir);
		fString build_dir = f_str_join_tmp(dir, F_LIT("\\.build"));
		f_assert(f_files_make_directory(build_dir));
	
#if defined(FFZ_BUILD_INCLUDE_TB)
		ok = ffz_backend_gen_executable_tb(p);
	#elif defined(FFZ_BUILD_INCLUDE_GMMC)
	
		// hmm.. if we want to reduce memory usage / increase cache efficiency and speed, I think we could
		// consider building a procedure after right after checking it, then throwing away the AST nodes.
		// Or maybe only do that for GMMC nodes.

		ok = ffz_backend_gen_executable_gmmc(root_module, build_dir, project_name);
	#else
	#error
	#endif
	}

	if (ok) {
		f_os_print_color(F_LIT("Compile succeeded!\n"), fConsoleAttribute_Green | fConsoleAttribute_Intensify);
	}

	//f_deinit();
	
	TracyCZoneEnd(tr);
	return ok ? 0 : 1;
}
