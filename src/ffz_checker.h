//
// ffz_checker is a submodule within ffz whose purpose is to check if a given ffz program is valid or not.
// This includes figuring out the types of expressions and checking if they match, substituting polymorphic types and making them concrete,
// amongst other things. While doing so, the checker caches information about the program, such as type information, that can be useful in later stages.
// The checker takes in an abstract syntax tree form of a program as input, so it is dependend on "ffz_ast.h".
// 

// 
// FFZ is a small, statically typed, compiled programming language
// with the goal of being practical, enjoyable to use, and to give
// full control to the programmer. And, its reference implementation is
// written as a modular library in <10k lines of well-commented C++!
// 
// A big goal for FFZ is giving the programmer tools to use the
// programming language as a library, and to deal with the code however they like.
// Most programming languages nowadays have large and complicated compilers that make anything
// else than strictly following their rulebook with the compilation process really difficult.
// What if you want to write an analysis tool for your code? Or make the compiler automatically
// insert profiling code in every function entry and exit points? Or what if you want to parse your code into
// an AST, and automatically generate shader code for a graphics card API?
// What if you want to write a simple text editor, and want to syntax-highlight the code,
// or a utility that automatically renames an identifier across an entire project?
// Exposing this kind of functionality is not a difficult problem, yet we somehow feel so powerless
// with the programming languages of the modern age, and being self-reliant is really difficult.
// 
// In addition to bad tooling, the inherent complexity of a programming langage plays a
// large factor with the ease of writing tools for it. If you wanted to write a static analysis
// tool for C++ or rust, it'd be an enormous project, whereas if you only need to support
// a handful of language features, hand-crafting the tools becomes more manageable.
// 
// The code you write is YOURS, and you should have competent tools available to inspect, modify and
// generate it from code in any way you like. Additionally, the compiler should be written in a clear
// and understandable way, so that a programmer can learn from it or customize the language to
// their liking. That's just not the reality of programming in C++
// 
// Also, the goal isn't to "take over" the programming world, or to convince
// everyone to use this language. The goal of FFZ is to simply provide
// a programming toolbox that someone might find value in, even if they were the only
// person using it, and that the language can be useful even without a giant ecosystem around it.
// And if that goal is met, this project is a success in my books! Meaningful
// programs and libraries can absolutely be written in other languages, and FFZ lets you
// import/export code across languages using the standard C ABI with very little effort.
// 
//
// The compiler will be maintained in C++, even when a self-hosted compiler is implemented.
// This shouldn't be a problem since the goal is to be simple to implement. The goal is <5k LOC in C++
// 

// Global, project-wide unique index for ffzNode.
//typedef u32 ffzNodeIdx;

//#define FFZ_NO_POLYMORPH_IDX 0
//typedef struct { u32 idx; } ffzPolymorphIdx;

typedef struct ffzChecker ffzChecker;
typedef struct ffzParser ffzParser;
typedef struct ffzType ffzType;
typedef struct ffzConstant ffzConstant;
typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
typedef struct ffzPolymorph ffzPolymorph;

typedef struct ffzCheckedExpr {
	ffzType* /*opt*/ type;
	ffzConstant* /*opt*/ const_val;
} ffzCheckedExpr;

// About hashing:
// Hashes should be fully deterministic across compilations.
// The hashes shouldn't depend on any runtime address / the compilers memory allocation strategy.
// Instead, they should only depend on the input program.
typedef u64 ffzHash; // TODO: increase this to 128 bits.
typedef ffzHash ffzNodeInstHash;
typedef ffzHash ffzPolymorphHash; // PolyInstHash should be consistent across modules across identical code!
typedef ffzHash ffzTypeHash; // Should be consistent across modules across identical code!
typedef ffzHash ffzConstantHash; // Should be consistent across modules across identical code!

/*typedef union ffzCheckerRelID {
	struct {
		ffzCheckerID checker_id;
		ffzCheckerLocalID local_id;
	};
	u64 global_id;
} ffzCheckerRelID;*/

typedef enum ffzTypeTag {
	ffzTypeTag_Invalid,

	ffzTypeTag_Raw,
	ffzTypeTag_Type,
	ffzTypeTag_PolyProc, // this is the type of an entire polymorphic procedure including a body
	ffzTypeTag_PolyRecord, // nothing should ever actually have the type of this - but a polymorphic struct type definition will type type to this
	ffzTypeTag_Module,

	ffzTypeTag_Bool,
	ffzTypeTag_Pointer,

	// :TypeIsInteger
	ffzTypeTag_SizedInt, // maybe SizedInt/SizedUint could be a flag if we would have flags in types?
	ffzTypeTag_SizedUint,
	ffzTypeTag_Int,
	ffzTypeTag_Uint,

	ffzTypeTag_Float,
	ffzTypeTag_Proc,
	ffzTypeTag_Record,
	ffzTypeTag_Enum,
	ffzTypeTag_Slice,
	ffzTypeTag_String, // string has the semantics of `#string: distinct []u8` with a custom iterator attached
	ffzTypeTag_FixedArray,
} ffzTypeTag;

//ffzToken token_from_node(ffzProject* project, ffzNode* node);



// Hmm. We could store a compressed version of NodeInst in our data structures (down to 8 bytes from 16)
// but then we'd have to build atomic arrays
// typedef struct ffzNodeInstSlim { ffzNodeIdx node; ffzPolyInstIdx poly_inst; } ffzNodeInstSlim;

typedef struct ffzNodeInst {
	ffzNode* node;
	ffzPolymorph* polymorph;
} ffzNodeInst;

typedef ffzNodeInst ffzNodeInst;
typedef ffzNodeInst ffzNodeIdentifierInst;
typedef ffzNodeInst ffzNodeDotInst;
typedef ffzNodeInst ffzNodePolyParamListInst;
typedef ffzNodeInst ffzNodeKeywordInst;
typedef ffzNodeInst ffzNodeOpInst;
typedef ffzNodeInst ffzNodeOpDeclareInst;
typedef ffzNodeInst ffzNodeOpAssignInst;
typedef ffzNodeInst ffzNodeIfInst;
typedef ffzNodeInst ffzNodeForInst;
typedef ffzNodeInst ffzNodeProcTypeInst;
typedef ffzNodeInst ffzNodeRecordInst;
typedef ffzNodeInst ffzNodeEnumInst;
typedef ffzNodeInst ffzNodeScopeInst;
typedef ffzNodeInst ffzNodeReturnInst;
typedef ffzNodeInst ffzNodeIntLiteralInst;
typedef ffzNodeInst ffzNodeStringLiteralInsts;

struct ffzDefinitionPath {
	ffzNode* parent_scope; // NULL for top-level scope
	fString name;
};

typedef struct ffzPolymorph {
	ffzPolymorphHash hash;
	ffzChecker* checker;

	ffzNodeInst node;
	fSlice(ffzCheckedExpr) parameters;
} ffzPolymorph;


struct ffzType;

/*typedef struct ffzCheckerStackFrame ffzCheckerStackFrame;
struct ffzCheckerStackFrame {
	ffzParser* parser;
	ffzNodeInst scope;
	//Slice<AstNode*> poly_path; // this is only for error reporting

	// TODO: cleanup
	OPT(ffzNodeInst) current_proc;
	OPT(ffzType*) current_proc_type;
};*/

typedef struct ffzCheckerScope {
	ffzNode* node;
	ffzCheckerScope* parent;
} ffzCheckerScope;

typedef struct ffzTypeRecordField {
	fString name;
	ffzType* type;
	u32 offset;
	ffzNodeOpDeclareInst decl; // not always used, i.e. for slice type fields
} ffzTypeRecordField;

typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
struct ffzTypeRecordFieldUse {
	ffzType* type;
	u32 offset;
};

typedef struct ffzTypeProcParameter {
	ffzNodeIdentifier* name;
	ffzType* type;
} ffzTypeProcParameter;

typedef struct ffzTypeEnumField {
	fString name;
	u64 value;
} ffzTypeEnumField;

typedef struct ffzType {
	ffzTypeTag tag;
	u32 size;
	u32 align;

	ffzTypeHash hash;
	ffzCheckerID checker_id;
	ffzNodeInst unique_node; // available for struct, union, enum, and proc types.

	fSlice(ffzTypeRecordField) record_fields; // available for struct, union, slice types and the string type.

	union {
		struct {
			//ffzNodeProcTypeInst type_node;
			fSlice(ffzTypeProcParameter) in_params;
			ffzTypeProcParameter* /*opt*/ out_param;
		} Proc, PolyProc;

		struct {
			bool is_union; // otherwise struct
		} Record, PolyRecord;

		struct {
			ffzType* internal_type;
			fSlice(ffzTypeEnumField) fields;
		} Enum;

		struct {
			ffzType* elem_type;
		} fSlice;

		struct {
			ffzType* elem_type;
			s32 length; // -1 means length is inferred by [?]
		} FixedArray;

		struct {
			ffzType* /*opt*/ pointer_to;
		} Pointer;
	};
} ffzType;

typedef struct ffzProject {
	fAllocator* persistent_allocator;
	fString module_name;
	fMap64(ffzChecker*) checked_module_from_directory; // key: str_hash_meow64(absolute_path_of_directory)

	fArray(fString) link_libraries;
	fArray(fString) link_system_libraries;

	fArray(ffzChecker*) checkers; // key: ffzCheckerIndex
	fArray(ffzParser*) parsers_dependency_sorted; // key: ffzParserIndex // dependency sorted from leaf modules towards higher-level modules	

	u32 pointer_size;

	KeywordFromStringMap keyword_from_string;
} ffzProject;

typedef struct ffzConstant {
	union {
		s8 s8_;
		s16 s16_;
		s32 s32_;
		s64 s64_;
		u8 u8_;
		u16 u16_;
		u32 u32_;
		u64 u64_;
		u16 f16_;
		f32 f32_;
		f64 f64_;
		bool bool_;
		ffzConstant* /*opt*/ ptr;

		ffzType* type;
		ffzChecker* module;
		fString string_zero_terminated; // length doesn't contain the zero termination.

		// tightly-packed array of ffzConstant. i.e. if this is an array of u8,
		// the n-th element would be ((ffzConstant*)((u8*)array_elems + n))->_u8.
		// You can use ffz_constant_fixed_array_get() to get an element from it.
		void* fixed_array_elems; // or NULL for zero-initialized
		
		// ProcType if @extern proc, otherwise Operator.
		// Currently, procedure definitions are actually categorized as "operators" in the AST,
		// because they have the form of `procedure_type{}`, which might seem a bit strange at first.
		ffzNodeInst proc_node;
		
		fSlice(ffzConstant) record_fields; // or empty for zero-initialized
	};
} ffzConstant;

typedef u64 ffzFieldHash;
typedef u64 ffzEnumValueHash;

// Checker is responsible for checking some chunk of code (currently must be a single module) and caching information about it.
struct ffzChecker {
	ffzProject* project; // should we make this void*?
	ffzCheckerID id;
	fAllocator* alc;

	//ffzCheckerLocalID next_local_id;

#ifdef _DEBUG
	fString _dbg_module_import_name;
#endif

	// implicit state for the current checker invocation
	//OPT(ffzNodeInst) parent_proc;
	//OPT(ffzType*) parent_proc_type;
	ffzCheckerScope* current_scope;
	fMap64Raw checked_identifiers; // key: ffz_hash_poly_inst. This is to detect cycles. We could reduce the memory footprint here by removing things as we go...

	// "declaration" is when it has a `:` token, e.g.  foo: 20  is a declaration.
	// "definition" is also a declaration, but it's not parsed into the AST as that form. e.g. in  struct[T]{...}  the polymorphic argument T is a definition.
	
	fMap64(ffzNodeIdentifier*) definition_map; // key: ffz_hash_declaration_path
	//fMap64(ffzNodeIdentifierInst) definition_map; // key: 

	fMap64(ffzCheckedExpr) cache; // key: ffz_hash_node_inst. Statements have NULL entries.
	fMap64(ffzPolymorph*) poly_instantiation_sites; // key: ffz_hash_node_inst
	
	fMap64(ffzType*) type_from_hash; // key: TypeHash
	fMap64(ffzPolymorph*) poly_from_hash; // key: ffz_hash_poly_inst
	
	// Contains a list of all tag instances, within this module, of each type.
	fMap64(fArray(ffzNodeInst)) all_tags_of_type; // key: TypeHash
	
	fMap64(ffzTypeRecordFieldUse*) field_from_name_map; // key: FieldHash

	// Only required during checking.
	fMap64(u64) enum_value_from_name; // key: FieldHash.
	fMap64(ffzNode*) enum_value_is_taken; // key: EnumValuekey

	fMap64(ffzChecker*) imported_modules; // key: AstNode.id.global_id

	void(*report_error)(ffzChecker* c, fSlice(ffzNode*) poly_path, ffzNode* at, fString error);
	
	ffzType* type_type;
	ffzType* module_type;
	ffzType* builtin_types[ffzKeyword_ex_extern + 1 - ffzKeyword_u8];
};

//#define FFZ_INST_AS(node,kind) (*(ffzNode##kind##Inst*)&(node))
//#define FFZ_INST_(ffzNode*)node (*(ffzNodeInst*)&(node))

#define FFZ_EACH_CHILD_INST(n, parent) (\
	ffzNodeInst n = {(parent.node) ? (parent).node->first_child : NULL, (parent).polymorph};\
	n.node = ffz_skip_standalone_tags(n.node);\
	n.node = n.node->next)

#define FFZ_INST_CHILD(T, parent, child_access) T { (parent).node->child_access, (parent).poly_inst }

//#define FFZ_NODE_INST(p, n) ffzNodeInst{ (n), (p).poly_inst }

ffzType* /*opt*/ ffz_builtin_type(ffzChecker* c, ffzKeyword keyword);

void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline);

bool ffz_parse_and_check_directory(ffzProject* p, fString directory);

bool ffz_build_directory(fString directory);

inline bool ffz_type_is_integer(ffzTypeTag tag) { return tag >= ffzTypeTag_SizedInt && tag <= ffzTypeTag_Uint; }
inline bool ffz_type_is_signed_integer(ffzTypeTag tag) { return tag == ffzTypeTag_SizedInt || tag == ffzTypeTag_Int; }

inline bool ffz_type_is_pointer_ish(ffzTypeTag tag) { return tag == ffzTypeTag_Pointer || tag == ffzTypeTag_Proc; }
inline bool ffz_type_is_integer_ish(ffzTypeTag tag) {
	return ffz_type_is_integer(tag) || tag == ffzTypeTag_Enum || tag == ffzTypeTag_Bool || tag == ffzTypeTag_Pointer || tag == ffzTypeTag_Proc;
}

u32 ffz_get_encoded_constant_size(ffzType* type);
ffzConstant ffz_constant_fixed_array_get(ffzType* array_type, ffzConstant* array, u32 index);

ffzNodeInst ffz_get_child_inst(ffzNodeInst parent, u32 idx);

ffzType* ffz_ground_type(ffzCheckedExpr checked); // TODO: get rid of this?
bool ffz_type_is_grounded(ffzType* type); // a type is grounded when a runtime variable may have that type.
bool ffz_type_can_be_checked_for_equality(ffzType* type);

fString ffz_type_to_string(ffzProject* p, ffzType* type);
const char* ffz_type_to_cstring(ffzProject* p, ffzType* type);

fString ffz_constant_to_string(ffzProject* p, ffzCheckedExpr constant);
const char* ffz_constant_to_cstring(ffzProject* p, ffzCheckedExpr constant);

//ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value);
ffzNodeInstHash ffz_hash_node_inst(ffzNodeInst inst);
//u64 ffz_hash_declaration_path(ffzDefinitionPath path);
//ffzMemberHash ffz_hash_member(ffzType* type, fString member_name);
ffzConstantHash ffz_hash_constant(ffzCheckedExpr constant);

inline ffzNodeInst ffz_get_toplevel_inst(ffzChecker* c, ffzNode* node) { return ffzNodeInst{node, NULL}; }
//ffzPolyInstHash ffz_hash_poly_inst(ffzPolyInst inst);

// -- Checker operations --------------------------------------------------------------

ffzOk ffz_check_toplevel_statement(ffzChecker* c, ffzNode* node);
ffzOk ffz_instanceless_check(ffzChecker* c, ffzNode* node, bool recursive);

ffzChecker* ffz_checker_init(ffzProject* p, fAllocator* allocator);

// -- Accessing cached data -----------------------------------------------------------

// hmm.. maybe we should store the checker directly in the Node.
inline ffzChecker* ffz_checker_from_node(ffzProject* p, ffzNode* node) { return p->parsers_dependency_sorted[node->id.parser_id]->checker; }
inline ffzChecker* ffz_checker_from_inst(ffzProject* p, ffzNodeInst inst) {
	return inst.polymorph ? inst.polymorph->checker : ffz_checker_from_node(p, inst.node);
}

bool ffz_find_top_level_declaration(ffzChecker* c, fString name, ffzNodeOpDeclare* out_decl);

ffzNodeInst ffz_get_instantiated_expression(ffzProject* p, ffzNodeInst node); // do we need this?

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out);
//fSlice(ffzTypeRecordField) ffz_type_get_record_fields(ffzChecker* c, ffzType* type);

ffzCheckedExpr ffz_expr_get_checked(ffzProject* p, ffzNodeInst node);
inline ffzType* ffz_expr_get_type(ffzProject* p, ffzNodeInst node) { return ffz_expr_get_checked(p, node).type; }
inline ffzConstant* ffz_expr_get_evaluated_constant(ffzProject* p, ffzNodeInst node) { return ffz_expr_get_checked(p, node).const_val; }

ffzCheckedExpr ffz_decl_get_checked(ffzProject* p, ffzNodeOpDeclareInst decl);
inline ffzType* ffz_decl_get_type(ffzProject* p, ffzNodeOpDeclareInst node) { return ffz_decl_get_checked(p, node).type; }
inline ffzConstant* ffz_decl_get_evaluated_constant(ffzProject* p, ffzNodeOpDeclareInst node) { return ffz_decl_get_checked(p, node).const_val; }

// "definition" is the identifier of a value that defines the name of the value.
// e.g. in  foo: int  the "foo" identifier would be a definition.
ffzNodeIdentifierInst ffz_get_definition(ffzProject* p, ffzNodeIdentifierInst ident);

bool ffz_get_decl_if_definition(ffzNodeIdentifierInst node, ffzNodeOpDeclareInst* out_decl); // hmm... this is a bit weird.
//bool ffz_definition_is_constant(ffzNodeIdentifier* definition);

//bool ffz_decl_is_constant(ffzNodeDeclaration* decl);
bool ffz_decl_is_runtime_value(ffzNodeOpDeclare* decl);

bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee);

// Returns NULL if not found
ffzConstant* ffz_get_tag(ffzProject* p, ffzNodeInst node, ffzType* tag_type);
