#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include <stdio.h>

int main(int argc, const char* argv[]) {

	//gmmc_test();

	//s64 val;
	//bool ok = f_str_to_s64(F_LIT("259012390"), 16, &val);
	//s64 test = 0x259012390;

	//printf("args: ");
	//for (uint i = 0; i < argc; i++) {
	//	printf("\"%s\", ", argv[i]);
	//}
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
