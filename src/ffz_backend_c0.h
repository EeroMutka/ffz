#if 0
//
// ffz_gen_gmmc is a module within ffz whose purpose is to take a checked program,
// and generate an executable program (or a dynamic library) from it, using the GMMC library.
//

#include "c0/src/c0.h"
#include "ffz_backend_tb.h"


struct ffzGenC0 {
	ffzProject* project;
	Allocator* alc;
	C0Gen* c0;

	C0Proc* c0_proc; // current proc

	ffzChecker* checker;
	Array<C0Proc*> c0_procs;
	
	Map64<C0AggType*> type_to_c0; // key: ffzType*
	Map64<C0Instr*> c0_instr_from_definition; // key: ffzNodeInstHash
	//Map64<C0Constant> c0_constant_from_definition; // key: ffzNodeInstHash
	Map64<C0Constant> c0_constant_from_constant; // key: ffzConstantHash
	Map64<C0Global*> c0_global_from_constant; // key: ffzConstantHash
	u64 dummy_name_counter;
};

void ffz_c0_generate(ffzProject* project, const char* generated_c_file);
#endif