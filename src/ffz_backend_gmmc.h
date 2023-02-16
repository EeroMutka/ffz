//
// ffz_gen_gmmc is a submodule within ffz whose purpose is to take a checked program,
// and generate an executable program (or a dynamic library) from it, using the GMMC library.
//

typedef u64 GMMC_DI_Type_Hash;

struct ffzBackendProcGenerated {
	OPT(gmmcProcedure*) gmmc_proc; // NULL if extern procedure
	//GMMC_ProcedureSignature* gmmc_proc_sig;
	gmmcValue* gmmc_proc_value;
};

struct ffzBackendProc {
	gmmcProcedure* gmmc_proc;
	ffzNodeOperatorInst inst;
	ffzType* proc_type;

	//Array<GMMC_Value*> gmmc_locals;
	Array<gmmcOp*> gmmc_ops;

	Array<gmmcDILocal> dbginfo_locals;

	bool disable_setting_dbginfo_pos;
};

struct ffzBackend {
	ffzProject* project;
	gmmcBuilder* gmmc;
	Allocator* allocator;

	// state
	ffzChecker* checker;
	OPT(ffzBackendProc*) curr_proc;

	gmmcValue* gmmc_true;
	gmmcValue* gmmc_false;

	Map64<ffzBackendProcGenerated> proc_gen; // key: PolyInstHash. maybe this should be stored directly in the Type structure
	Map64<gmmcProcSignature*> gmmc_proc_signature_from_type; // key: Type*
	Map64<gmmcValue*> gmmc_definition_value; // key: AstNodePolyInstHash
	Map64<gmmcDITypeIdx> to_gmmc_type_idx; // key: Type*

	Array<gmmcDIType> gmmc_types;

	uint dummy_name_counter;
};

void ffz_gmmc_generate(ffzProject* project, ffzBackend* gen, String objname);
