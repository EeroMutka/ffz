
// Command line compiler for FFZ

// --------------------------

#define DEBUG_PRINT_AST false

// --------------------------


#define F_DEF_INCLUDE_OS
//#define F_DEF_TRAP() f_os_error_popup(F_LIT("Debug-trap!"), F_LIT("The program reached an invalid state."))
#include "../foundation/foundation.h"

#include "../ffz_ast.h"
#include "../ffz_checker.h"

#include "../tracy/tracy/TracyC.h"

#define TRY(x) FFZ_TRY(x)

#define ERR(alc, node, fmt, ...) return ffz_make_error_at_node(node, f_aprint(alc, fmt, __VA_ARGS__), alc);

//#include <Windows.h>
//#include <math.h>
//
//#include "gmmc/gmmc.h" // for gmmc_test

typedef struct Build {
	fArena* temp;
	ffzProject* project;
	fMap64(ffzModule*) module_from_directory;
	fMap64(ffzModule*) module_from_import_op; // key: ffzNode*
	fString modules_directory;
} Build;


bool ffz_backend_gen_executable_gmmc(ffzModule* root_module, fString build_dir, fString name);

static fOpt(ffzError*) parse_and_check_directory(Build* build, fString directory, ffzModule** out_module);

void log_pretty_error(ffzError error, fString kind) {
	fTempScope temp = f_temp_push();
	
	// C-style error messages can be useful in Visual Studio output console, to be able to double click the code location
	bool c_style = true;
	if (!c_style) {
		f_os_print_color(kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
	}
	
	fString line_num_str;
	if (error.source) {
		line_num_str = f_str_from_uint(error.location.start.line_num, 10, temp.arena);

		if (c_style) {
			f_os_print_color(error.source->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);
			f_os_print(F_LIT("("));
			f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
			f_os_print(F_LIT(","));
			f_os_print_color(f_str_from_uint(error.location.start.column_num, 10, temp.arena), fConsoleAttribute_Green | fConsoleAttribute_Red);
			f_os_print(F_LIT("):\n "));
			f_os_print_color(kind, fConsoleAttribute_Red | fConsoleAttribute_Intensify);
			f_os_print(F_LIT(": "));
		}
		else {
			f_os_print(F_LIT("("));
			f_os_print_color(error.source->source_code_filepath, fConsoleAttribute_Green | fConsoleAttribute_Red | fConsoleAttribute_Intensify);

			f_os_print(F_LIT(":"));
			f_os_print_color(line_num_str, fConsoleAttribute_Green | fConsoleAttribute_Red);
			f_os_print(F_LIT(":"));
			f_os_print_color(f_str_from_uint(error.location.start.column_num, 10, temp.arena), fConsoleAttribute_Green | fConsoleAttribute_Red);
			f_os_print(F_LIT(")\n  "));
		}
	}

	f_os_print(error.message);
	f_os_print(F_LIT("\n"));

	if (error.source) {
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
		start_str = f_str_replace(start_str, F_LIT("\t"), F_LIT("    "), temp.arena);
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
	}
	f_os_print(F_LIT("\n"));
	f_temp_pop(temp);
}

//inline void log_pretty_syntax_error(ffzError error) { log_pretty_error(error, F_LIT("Syntax error ")); }
//inline void log_pretty_semantic_error(ffzError error) { log_pretty_error(error, F_LIT("Semantic error ")); }
typedef struct FileVisitData {
	fArray(fString) files;
	fString directory;
} FileVisitData;

static fVisitDirectoryResult file_visitor(const fVisitDirectoryInfo* info, void* userptr) {
	FileVisitData* visit = userptr;

	if (!info->is_directory &&
		f_str_equals(f_str_path_extension(info->name), F_LIT("ffz")) &&
		info->name.data[0] != '!')
	{
		fString filepath = f_str_join(visit->files.arena, visit->directory, F_LIT("\\"), info->name);
		f_array_push(&visit->files, filepath);
	}

	return fVisitDirectoryResult_Continue;
}

/*static fOpt(ffzError*) module_from_path(Build* build, fString path, ffzModule* mod, ffzModule** out_module) {

	// `:` means that the path is relative to the modules directory shipped with the compiler
	if (f_str_starts_with(path, F_LIT(":"))) {
		fString slash = F_LIT("/");
		path = f_str_join_tmp(build->modules_directory, slash, f_str_slice_after(path, 1));
	}
	else {
		// let's make the import path absolute
		if (!f_files_path_to_canonical(mod->directory, path, f_temp_alc(), &path)) {
			f_trap();
		}
	}

	TRY(parse_and_check_directory(build, path, out_module));
	return NULL;
}*/

fOpt(ffzError*) add_module_from_filesystem(Build* build, fString absolute_directory, ffzModule** out_module) {

	if (!f_files_path_to_canonical((fString){0}, absolute_directory, build->temp, &absolute_directory)) {
		f_trap();
	}

	fMapInsertResult module_exists = f_map64_insert(&build->module_from_directory, f_hash64_str_ex(absolute_directory, 0), (ffzModule*){0}, fMapInsert_DoNotOverride);
	if (!module_exists.added) {
		*out_module = *(ffzModule**)module_exists._unstable_ptr;
		return NULL;
	}

	ffzModule* mod = ffz_new_module(build->project, build->project->bank.arena);
	*(ffzModule**)module_exists._unstable_ptr = mod;
	mod->directory = absolute_directory;

	FileVisitData visit;
	visit.files = f_array_make(build->temp);
	visit.directory = absolute_directory;

	if (!f_files_visit_directory(absolute_directory, file_visitor, &visit)) {
		f_trap();
		return NULL; // TODO: error report
	}

	for (uint i = 0; i < visit.files.len; i++) {
		fString file_data = f_array_get(fString, visit.files, i);
		fString file_contents;
		f_assert(f_files_read_whole(file_data, build->temp, &file_contents));

		ffzParseResult parse_result;
		TRY(ffz_parse_scope(mod, file_contents, file_data, &parse_result));

		// What we could then do is have a queue for top-level nodes that need to be (re)checked.
		// When expanding polymorph nodes, push those nodes to the end of the queue. Or if the
		// user wants to modify the tree, they can push the modified nodes to the end of the queue
		// to be re-checked.

		for (ffzNode* n = parse_result.node->first_child; n; n = n->next) {
			n->parent = NULL; // ffz_module_add_top_level_node requires the parent to be NULL
			ffz_module_add_top_level_node_(mod, n);
		}

		// Loop through the imports and check the imported modules. Hmm, this is a weird middle ground between the parser stage and checker stage.
		// Maybe we should put the checking in the parser or make it its own AST node kind, i.e. `#Basic: import "Basic"`. That might be the wisest.
		
		// The checker needs to fill the maps from ident -> module and module -> ident.

		f_for_array(ffzNode*, parse_result.import_keywords, it) {
			ffzNodeOp* import_op = it.elem->parent;
			f_assert(import_op && import_op->kind == ffzNodeKind_PostRoundBrackets && ffz_get_child_count(import_op) == 1); // TODO: error report
			
			ffzNode* import_decl = import_op->parent;
			f_assert(import_decl && import_decl->kind == ffzNodeKind_Declare); // TODO: error report
			
			ffzNode* import_name_node = ffz_get_child(import_op, 0);
			f_assert(import_name_node->kind == ffzNodeKind_StringLiteral); // TODO: error report
			fString import_path = import_name_node->StringLiteral.zero_terminated_string;
			
			// `:` means that the path is relative to the modules directory shipped with the compiler
			if (f_str_starts_with(import_path, F_LIT(":"))) {
				fString slash = F_LIT("/");
				import_path = f_str_join(build->temp, build->modules_directory, slash, f_str_slice_after(import_path, 1));
			}
				
			// let's make the import path absolute
			if (!f_files_path_to_canonical(mod->directory, import_path, build->temp, &import_path)) {
				ERR(build->temp, import_decl, "Failed to import module; directory `~s` does not exist.", import_path);
			}

			fOpt(ffzModule*) imported_module;
			TRY(parse_and_check_directory(build, import_path, &imported_module));

			f_map64_insert(&build->module_from_import_op, (u64)import_op, imported_module, fMapInsert_AssertUnique);
			//f_map64_insert(&m->module_from_import_decl, (u64)import_decl, imported_module, fMapInsert_AssertUnique);
			//f_map64_insert(&m->import_decl_from_module, (u64)imported_module, import_decl, fMapInsert_AssertUnique); // TODO: error report
		}

		//if (!ffz_module_resolve_imports_(module, resolve_import, module).ok) {
		//	f_trap();//err = module->error;
		//	module = NULL;
		//}
		
		//f_array_push_n(&module->pending_import_keywords, parse_result.import_keywords);
	}

	*out_module = mod;
	return NULL;
}

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

static fOpt(ffzModule*) module_from_import(ffzModule* mod, ffzNode* import_node) {
	Build* build = mod->userdata;
	fOpt(ffzModule**) imported = f_map64_get_raw(&build->module_from_import_op, (u64)import_node);
	return imported ? *imported : NULL;
}

static fOpt(ffzError*) parse_and_check_directory(Build* build, fString absolute_directory, ffzModule** out_module) {
	//TracyCZone(tr, true);

	ffzModule* mod;
	TRY(add_module_from_filesystem(build, absolute_directory, &mod));
	
	if (DEBUG_PRINT_AST) {
		dump_module_ast(mod, absolute_directory);
	}

	if (mod->checker == NULL) {
		mod->userdata = build;
		TRY(ffz_check_module(mod, module_from_import, mod->arena));
	}

	//TracyCZoneEnd(tr);
	*out_module = mod;
	return NULL;
}

int main(int argc, const char* argv[]) {
	TracyCZone(tr, true);
	f_init();
	fTempScope temp = f_temp_push();

	bool ok = true;
	if (argc <= 1) {
		f_cprint("Please provide a directory to compile!\n");
		ok = false;
	}
	
	fString exe_path = f_os_get_executable_path(temp.arena);
	fString ffz_dir = f_str_path_dir(f_str_path_dir(exe_path));
	fString modules_dir = f_str_join(temp.arena, ffz_dir, F_LIT("/modules"));

	Build build = {
		.temp = temp.arena,
		.module_from_directory = f_map64_make_raw(sizeof(ffzModule*), temp.arena),
		.module_from_import_op = f_map64_make_raw(sizeof(ffzModuleChecker*), temp.arena),
		.modules_directory = modules_dir,
	};

	fString dir;
	fOpt(ffzModule*) root_module;
	if (ok) {
		fSliceRaw my_strings = f_slice_lit(fString, F_LIT("heyy"), F_LIT("sailor"));
		F_UNUSED(my_strings);

		dir = f_str_from_cstr(argv[1]);

		build.project = ffz_init_project(temp.arena);

		fOpt(ffzError*) err = parse_and_check_directory(&build, dir, &root_module);
		if (err) {
			log_pretty_error(*err, F_LIT("Error"));
			ok = false;
		}
	}

	if (ok) {
		fString project_name = f_str_path_tail(dir);
		fString build_dir = f_str_join(temp.arena, dir, F_LIT("\\.build"));
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
	
	f_temp_pop(temp);
	TracyCZoneEnd(tr);
	return ok ? 0 : 1;
}
