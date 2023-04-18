#include "../foundation/foundation.hpp"

#include "../ffz_ast.h"
#include "../ffz_checker.h"

int main__() {
	// Compile a program that contains `#return_error: proc(err : string) { trap() }`, then replace all calls
	// to that procedure with a return statement that returns the first argument
	
	// the plan:
	// - build the main module
	// - lookup `return_error`
	// - iterate all references to that definition
	// - if it's the target of a procedure call, replace that procedure call AST node with a return node that we generate
	//    - we can generate the return node by simply building a string.
	//      We should have a function to get the string from an AST node, so we can easily do something like:
	//   
	//    *node = ffz_parse(module, f_tprint("ret ~s", ffz_node_get_string(argument_node)))
	// 
	// - build the main module again fresh

	return 0;
}

int main() {
	// find all casts that cast from u16 -> u8 and insert a runtime if-check that traps if the
	// value doesn't fit.

	// so we first need to find all of the cast expressions.
	// I guess during checking we could provide a callback for each visited node, after determining their type.

	// inside the callback, we check if it's a type-cast and the left side is u8 and the argument type is u16.
	// hmm.... it's not possible to modify the AST in a way where we'd add this check only for the u16->u8 case.
	// It's just a natural limit of the system. Since this check can't be done within the language itself, it can't
	// be done by the metaprogram either.

	// A solution could be to build an "expanded tree" as an intermediate step that flattens out the polymorphism.
	// Then, you could easily modify this expanded tree.
	// hmm, this kind of sounds like a good idea. The AST would be completely ignored after converting to
	// the semantic tree.
	// The checker would only operate on the semantic tree.
	
	// Another solution would be to take the GMMC IR and add a modification step to it.

	// ANode = abstract node
	// SNode = semantic node
	
	return 0;
}


/*
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


	fString extra_definitions = F_LIT("#ground_truth: struct{truth: string}");
	
	// build the program

	// find the $ground_truth tag

	// run the program and capture its output

	// compare the output to the ground truth
	
	f_deinit();
	return 0;
}
*/