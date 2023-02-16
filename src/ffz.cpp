#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"
#include "ffz_lib.h"

#include <stdio.h>

int main(int argc, const char* argv[]) {
	//printf("args: ");
	//for (uint i = 0; i < argc; i++) {
	//	printf("\"%s\", ", argv[i]);
	//}
	//printf("\n");
	
	Allocator* temp = temp_push();
	
	if (argc == 0) {
		printf("Please provide a directory to compile!\n");
		return 1;
	}

	String dir = os_path_to_absolute(String{}, str_from_cstring(argv[1]), temp);
	if (!ffz_build_directory(dir)) return 1;
	
	return 0;
}
