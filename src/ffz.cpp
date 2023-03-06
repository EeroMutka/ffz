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
	//COLOR_BACKGROUND
	//printf("\n");
	fAllocator* temp = f_temp_push();
	
	if (argc <= 1) {
		printf("Please provide a directory to compile!\n");
		return 1;
	}

	fString dir = f_files_path_to_absolute(fString{}, f_str_from_cstr(argv[1]), temp);
	fString compiler_install_dir = f_str_path_dir(f_str_path_dir(f_os_get_executable_path(temp)));

	if (!ffz_build_directory(dir, compiler_install_dir)) return 1;
	
	return 0;
}
