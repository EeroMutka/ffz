#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include <stdio.h>

#include <Windows.h>

int main(int argc, const char* argv[]) {
	int x = -21;
	//printf("args: ");
	//for (uint i = 0; i < argc; i++) {
	//	printf("\"%s\", ", argv[i]);
	//}
	//printf("\n");
	//fAllocator* temp = f_temp_push();
	f_init();
	
	if (argc <= 1) {
		printf("Please provide a directory to compile!\n");
		return 1;
	}

	if (argc <= 1) {
		printf("Please provide a directory to compile!\n");
		return 1;
	}
	
	fString dir = f_str_from_cstr(argv[1]);
	fString exe_path = f_os_t_get_executable_path();
	fString compiler_install_dir = f_str_path_dir(f_str_path_dir(exe_path));

	if (!ffz_build_directory(dir, compiler_install_dir)) return 1;
	
	f_deinit();
	return 0;
}
