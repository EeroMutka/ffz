#include "foundation/foundation.hpp"

#include "ffz_lib.h"
#include "ffz_ast.h"
#include "ffz_checker.h"

#include <stdio.h>

int main(int argc, const char* argv[]) {
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
	if (!ffz_build_directory(dir)) return 1;
	
	return 0;
}
