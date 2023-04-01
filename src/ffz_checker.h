//
// The purpose of checker is to check if a given ffz program is valid or not.
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

typedef struct ffzModule ffzModule;
typedef struct ffzParser ffzParser;
typedef struct ffzType ffzType;
typedef struct ffzConstant ffzConstant;
typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
typedef struct ffzPolymorph ffzPolymorph;

typedef struct ffzCheckedInst {
	fOpt(ffzType*) type;
	fOpt(ffzConstant*) const_val;
} ffzCheckedInst;

// About hashing:
// Hashes should be fully deterministic across compilations.
// The hashes shouldn't depend on any runtime address / the compilers memory allocation strategy.
// Instead, they should only depend on the input program.
typedef u64 ffzHash; // TODO: increase this to 128 bits.
typedef ffzHash ffzNodeInstHash;
typedef ffzHash ffzPolymorphHash; // PolyInstHash should be consistent across modules across identical code!
typedef ffzHash ffzTypeHash; // Should be consistent across modules across identical code!
typedef ffzHash ffzConstantHash; // Should be consistent across modules across identical code!

typedef enum ffzTypeTag {
	ffzTypeTag_Invalid,

	ffzTypeTag_Raw,       // `raw`
	ffzTypeTag_Undefined, // the type of the expression `~~`
	//ffzTypeTag_Eater, // the type of the expression `_`
	ffzTypeTag_Type,
	ffzTypeTag_PolyProc, // this is the type of an entire polymorphic procedure including a body
	ffzTypeTag_PolyRecord, // nothing should ever actually have the type of this - but a polymorphic struct type definition will type type to this
	ffzTypeTag_Module,

	ffzTypeTag_Bool,
	ffzTypeTag_Pointer,

	// :type_is_integer
	ffzTypeTag_Sint, // 's8', 's16', ...
	ffzTypeTag_Uint, // 'u8', 'u16', ...
	ffzTypeTag_DefaultSint, // 'int'
	ffzTypeTag_DefaultUint, // 'uint'

	ffzTypeTag_Float,
	ffzTypeTag_Proc,
	ffzTypeTag_Record,
	ffzTypeTag_Enum,
	ffzTypeTag_Slice,
	ffzTypeTag_String, // string has the semantics of `#string: distinct []u8` with a custom iterator attached
	ffzTypeTag_FixedArray,
} ffzTypeTag;

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
	ffzModule* checker;

	ffzNodeInst node;
	fSlice(ffzCheckedInst) parameters;
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
		ffzModule* module;
		fString string_zero_terminated; // length doesn't contain the zero termination.

		// tightly-packed array of ffzConstant. i.e. if this is an array of u8,
		// the n-th element would be ((ffzConstant*)((u8*)array_elems + n))->_u8.
		// You can use ffz_constant_fixed_array_get() to get an element from it.
		void* fixed_array_elems; // or NULL for zero-initialized

		// ProcType if extern proc, otherwise Operator.
		// Currently, procedure definitions are actually categorized as "operators" in the AST,
		// because they have the form of `procedure_type{}`, which might seem a bit strange.
		ffzNodeInst proc_node;

		fSlice(ffzConstant) record_fields; // or empty for zero-initialized
	};
} ffzConstant;

typedef struct ffzField {
	fString name;
	ffzNodeOpDeclareInst decl; // not always used, i.e. for slice type fields
	
	ffzConstant default_value;
	bool has_default_value;

	u32 offset; // ignored for procedure parameters
	ffzType* type;
} ffzNamedField;

typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
struct ffzTypeRecordFieldUse {
	ffzType* type;
	u32 offset;
};

//typedef struct ffzTypeProcParameter {
//	ffzNodeIdentifier* name;
//	ffzType* type;
//} ffzTypeProcParameter;

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

	fSlice(ffzField) record_fields; // available for struct, union, slice types and the string type.

	union {
		struct {
			fSlice(ffzField) in_params;
			fOpt(ffzType*) return_type;
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
		} Slice;

		struct {
			ffzType* elem_type;
			s32 length; // -1 means length is inferred by [?]
		} FixedArray;

		struct {
			ffzType* pointer_to;
		} Pointer;
	};
} ffzType;


typedef struct ffzProject {
	fAllocator* persistent_allocator;
	
	// `modules_directory` can be an empty string, in which case
	// importing modules using the `:` prefix is not allowed.
	fString modules_directory;

	fMap64(ffzModule*) checked_module_from_directory; // key: str_hash_meow64(absolute_path_of_directory)

	fArray(fString) link_libraries;
	fArray(fString) link_system_libraries;

	fArray(ffzModule*) checkers; // key: ffzCheckerID
	fArray(ffzParser*) parsers; // key: ffzParserID
	
	fArray(ffzModule*) checkers_dependency_sorted; // topologically sorted from leaf modules towards higher-level modules
	
	u32 pointer_size;

	KeywordFromStringMap keyword_from_string;
} ffzProject;

typedef u64 ffzFieldHash;
typedef u64 ffzEnumValueHash;

struct ffzModule {
	ffzProject* project;
	
	fAllocator* alc;
	ffzCheckerID id;

	fString directory; // imports in this module will be relative to this directory

	fSlice(ffzParser*) parsers;

	// implicit state for the current checker invocation
	ffzCheckerScope* current_scope;
	fMap64Raw checked_identifiers; // key: ffz_hash_poly_inst. This is to detect cycles. We could reduce the memory footprint here by removing things as we go...

	// "declaration" is when it has a `:` token, e.g.  foo: 20  is a declaration.
	// "definition" is also a declaration, but it's not parsed into the AST as that form.
	// e.g. in  struct[T]{...}  the polymorphic argument T is a definition.
	
	fMap64(ffzNodeIdentifier*) definition_map; // key: ffz_hash_declaration_path

	// * key: ffz_hash_node_inst
	// * Statements have NULL entries, except declarations, which cache the type
	//   (and maybe constant value) of the declaration.
	fMap64(ffzCheckedInst) cache;

	fMap64(ffzPolymorph*) poly_instantiation_sites; // key: ffz_hash_node_inst
	
	fMap64(ffzType*) type_from_hash; // key: TypeHash
	fMap64(ffzPolymorph*) poly_from_hash; // key: ffz_hash_poly_inst
	
	// Contains a list of all tag instances, within this module, of each type.
	fMap64(fArray(ffzNodeInst)) all_tags_of_type; // key: TypeHash
	
	fMap64(ffzTypeRecordFieldUse*) field_from_name_map; // key: FieldHash
	
	// Only required during checking.
	fMap64(u64) enum_value_from_name; // key: FieldHash.
	fMap64(ffzNode*) enum_value_is_taken; // key: EnumValuekey

	fArray(fString) extern_libraries; // TODO: deduplicate

	fMap64(ffzModule*) imported_modules; // key: AstNode.id.global_id

	void(*report_error)(ffzModule* c, fSlice(ffzNode*) poly_path, ffzNode* at, fString error);
	
	ffzType* type_type;
	ffzType* module_type;
	u64 next_pseudo_node_idx;
	ffzType* builtin_types[ffzKeyword_COUNT];
};

#define FFZ_EACH_CHILD_INST(n, parent) (\
	ffzNodeInst n = {(parent.node) ? (parent).node->first_child : NULL, (parent).polymorph};\
	n.node = ffz_skip_standalone_tags(n.node);\
	n.node = n.node->next)

#define FFZ_INST_CHILD(T, parent, child_access) T { (parent).node->child_access, (parent).poly_inst }

ffzType* /*opt*/ ffz_builtin_type(ffzModule* c, ffzKeyword keyword);

//void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline);

bool ffz_parse_and_check_directory(ffzProject* p, fString directory);

inline bool ffz_keyword_is_bitwise_op(ffzKeyword keyword) { return keyword >= ffzKeyword_bit_and && keyword <= ffzKeyword_bit_not; }

inline bool ffz_node_is_keyword(ffzNode* node, ffzKeyword keyword) { return node->kind == ffzNodeKind_Keyword && node->Keyword.keyword == keyword; }


inline bool ffz_type_is_integer(ffzTypeTag tag) { return tag >= ffzTypeTag_Sint && tag <= ffzTypeTag_DefaultUint; }
inline bool ffz_type_is_signed_integer(ffzTypeTag tag) { return tag == ffzTypeTag_Sint || tag == ffzTypeTag_DefaultSint; }
inline bool ffz_type_is_unsigned_integer(ffzTypeTag tag) { return tag == ffzTypeTag_Uint || tag == ffzTypeTag_DefaultUint; }
inline bool ffz_type_is_float(ffzTypeTag tag) { return tag == ffzTypeTag_Float; }

// integer/pointer_ish types mean that the internal representation of the type is as such:
inline bool ffz_type_is_pointer_ish(ffzTypeTag tag) { return tag == ffzTypeTag_Pointer || tag == ffzTypeTag_Proc; }
inline bool ffz_type_is_integer_ish(ffzTypeTag tag) { return ffz_type_is_integer(tag) || tag == ffzTypeTag_Enum; }

inline bool ffz_type_is_slice_ish(ffzTypeTag tag) { return tag == ffzTypeTag_Slice || tag == ffzTypeTag_String; }
inline bool ffz_type_is_pointer_sized_integer(ffzProject* p, ffzType* type) { return ffz_type_is_integer(type->tag) && type->size == p->pointer_size; }

u32 ffz_get_encoded_constant_size(ffzType* type);
ffzConstant ffz_constant_fixed_array_get(ffzType* array_type, ffzConstant* array, u32 index);

ffzNodeInst ffz_get_child_inst(ffzNodeInst parent, u32 idx);

bool ffz_type_is_concrete(ffzType* type); // a type is grounded when a runtime variable may have that type.

bool ffz_type_is_comparable_for_equality(ffzType* type); // supports ==, !=
bool ffz_type_is_comparable(ffzType* type); // supports <, >, et al.

fString ffz_type_to_string(ffzProject* p, ffzType* type);
char* ffz_type_to_cstring(ffzProject* p, ffzType* type);

fString ffz_constant_to_string(ffzProject* p, ffzCheckedInst constant);
char* ffz_constant_to_cstring(ffzProject* p, ffzCheckedInst constant);

//ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value);
ffzNodeInstHash ffz_hash_node_inst(ffzNodeInst inst);
//u64 ffz_hash_declaration_path(ffzDefinitionPath path);
//ffzMemberHash ffz_hash_member(ffzType* type, fString member_name);
ffzConstantHash ffz_hash_constant(ffzCheckedInst constant);

inline ffzNodeInst ffz_get_toplevel_inst(ffzModule* c, ffzNode* node) { return ffzNodeInst{node, NULL}; }

// -- High level compiler API --------------------------------------------------------------

ffzProject* ffz_init_project(fArena* arena, fString modules_directory);

// So metaprogramming - I'd like to
// 
// A. tester metaprogram.
// 
// 
// B. Get all procedures that have a @MyProfiler.Profile tag, and insert calls to 'str.printf' at the entry
// and exist points of the procedure. This should work even if the 'str' module isn't explicitly imported by the source code.
// 
// C. Compile a program that contains `#return_error: proc(err: string) { trap() }`, then replace all calls
// to that procedure with a return statement that returns the first argument
// 
// Now something that requires some polymorphism!
// D. find all casts that cast from u16 -> u8 and insert a runtime if-check that traps if the
//    value doesn't fit.
// 
//

ffzModule* ffz_project_add_new_module(ffzProject* p, fAllocator* allocator);


void ffz_module_add_code_string(ffzModule* m, fString code);

// The node must be a top-level node and have it's parent field set to NULL.
void ffz_module_add_code_node(ffzModule* m, ffzNode* node);


//void ffz_module_resolve_imports(ffzModule* m, ffzModule*(*module_from_path)(fString path, void* userdata), void* userdata);

void ffz_module_get_imports(ffzModule* m, fSlice(ffzModule*)* out_imports);

// When you call ffz_module_check_single, all imported modules must have already been checked.
ffzOk ffz_module_check_single(ffzModule* m);



// we could give you a flat array of all the types in your program
// - and procedures
// - and standalone tags


// TODO: CLEANUP
ffzOk ffz_check_toplevel_statement(ffzModule* c, ffzNode* node);
ffzOk ffz_instanceless_check(ffzModule* c, ffzNode* node, bool recursive);

// -- Accessing cached data -----------------------------------------------------------

inline ffzModule* ffz_checker_from_node(ffzProject* p, ffzNode* node) {
	// ok... I think we should just store a pointer to the parser in the node.
	return p->parsers[node->id.parser_id]->module;
}
inline ffzModule* ffz_checker_from_inst(ffzProject* p, ffzNodeInst inst) {
	return inst.polymorph ? inst.polymorph->checker : ffz_checker_from_node(p, inst.node);
}

bool ffz_find_top_level_declaration(ffzModule* c, fString name, ffzNodeOpDeclare* out_decl);

ffzNodeInst ffz_parent_inst(ffzProject* p, ffzNodeInst node);

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out);

ffzCheckedInst ffz_get_checked(ffzProject* p, ffzNodeInst node);
inline ffzType* ffz_get_type(ffzProject* p, ffzNodeInst node) { return ffz_get_checked(p, node).type; }
inline ffzConstant* ffz_get_evaluated_constant(ffzProject* p, ffzNodeInst node) { return ffz_get_checked(p, node).const_val; }

// "definition" is the identifier of a value that defines the name of the value.
// e.g. in  foo: int  the "foo" identifier would be a definition.
ffzNodeIdentifierInst ffz_get_definition(ffzProject* p, ffzNodeIdentifierInst ident);

bool ffz_find_field_by_name(fSlice(ffzField) fields, fString name, u32* out_index);

// 
// Given an argument list (either a post-curly-brackets initializer or a procedure call) that might contain
// both unnamed as well as named arguments, this procedure will give the arguments
// in a flat list in the same order as the `fields` array. Note that some arguments might not exist,
// so those will have just have the default value of ffzNodeInst{}
// 
void ffz_get_arguments_flat(ffzNodeInst arg_list, fSlice(ffzField) fields, fSlice(ffzNodeInst)* out_arguments, fAllocator* alc);

bool ffz_constant_is_zero(ffzConstant constant);

inline fString ffz_decl_get_name(ffzNodeOpDeclare* decl) { return decl->Op.left->Identifier.name; }

//bool ffz_decl_is_runtime_variable(ffzNodeOpDeclare* decl);
bool ffz_decl_is_local_variable(ffzNodeOpDeclare* decl);
bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl);
inline bool ffz_decl_is_parameter(ffzNodeOpDeclare* decl) { return decl->parent->kind == ffzNodeKind_ProcType; }

inline bool ffz_decl_is_variable(ffzNodeOpDeclare* decl) {
	return ffz_decl_is_local_variable(decl) || ffz_decl_is_parameter(decl) || ffz_decl_is_global_variable(decl);
}

bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee);

// Returns NULL if not found
ffzConstant* ffz_get_tag_of_type(ffzProject* p, ffzNodeInst node, ffzType* tag_type);
inline ffzConstant* ffz_get_tag(ffzProject* p, ffzNodeInst node, ffzKeyword tag) { return ffz_get_tag_of_type(p, node, ffz_builtin_type(ffz_checker_from_inst(p, node), tag)); }
//c->project, inst, ffz_builtin_type(c, ))
