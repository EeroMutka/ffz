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

// TODO: make ffz_checker.cpp, etc, compile both in C99 and C++.
//       Compiling in C++ would have the benefit of slice and map types being visualizable in the debugger!
//       ALSO: this way we COULD make the entire library a single-header library if we wanted to!
//       ... buut to be honest, idk if that's a good idea. It's probably nicer to have the separation of files, even for end users who want to tweak the library.
//           IDK! And if we go down the single-header library route, we'd probably want to get back to using libc more, as in with the file IO.

// About caching/threading the checker:
// Imagine you're writing a little program and you're importing a big game engine module. Module-level multithreading doesn't help here.
// Caching is the solution. Most of the times you compile a program, you won't have edited multiple modules, so it makes sense to cache
// the checked modules.

#define F_MINIMAL_INCLUDE
#include "foundation/foundation.h"

#ifdef __cplusplus
#define FFZ_CAPI extern "C"
#else
#define FFZ_CAPI
#endif

// hmm... should we have a single thread-local ffzProject? That'd make things a bit less verbose.

typedef struct ffzModule ffzModule;
typedef struct ffzParser ffzParser;
typedef struct ffzType ffzType;
typedef struct ffzConstantData ffzConstantData;
typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
//typedef struct ffzPolymorph ffzPolymorph;

typedef uint32_t ffzSourceID;
#define FFZ_SOURCE_ID_NONE 0xFFFFFFFF

//typedef uint32_t ffzParserLocalID;
typedef uint32_t ffzModuleID;
typedef uint32_t ffzCheckerLocalID;

typedef uint32_t ffzPolymorphID;
#define FFZ_POLYMORPH_ID_NONE 0xFFFFFFFF

typedef struct ffzNode ffzNode;
typedef ffzNode ffzNodeOpDeclare;
typedef ffzNode ffzNodeOpAssign;
typedef ffzNode ffzNodeIdentifier;
typedef ffzNode ffzNodeKeyword;
typedef ffzNode ffzNodeOp;
typedef ffzNode ffzNodeIf;
typedef ffzNode ffzNodeFor;
typedef ffzNode ffzNodeProcType;
typedef ffzNode ffzNodeRecord;
typedef ffzNode ffzNodeEnum;
typedef ffzNode ffzNodeScope;
typedef ffzNode ffzNodeReturn;
typedef ffzNode ffzNodeIntLiteral;
typedef ffzNode ffzNodeStringLiteral;
typedef ffzNode ffzNodeThisValueDot;
typedef ffzNode ffzNodeBlank;
typedef ffzNode ffzNodePolyParamList;

typedef struct ffzProject ffzProject;
typedef struct ffzModule ffzModule;

typedef uint64_t ffzHash; // TODO: increase this to 128 bits.

// We could make hashes fully deterministic across multiple compilations (not dependend on any runtime addresses),
// but right now they do depend on runtime addresses. See `ffz_hash_node`

// * project-global (different nodes in different modules must not share a hash). This is so that
//   types that use the node hash as their identity can be checked compatibility across modules.
// 
// * EXCEPT: Say module X and Y instantiate an identical polymorphic definition from module Z.
//   In that case, the duplicated nodes in both X and Y will get the same NodeHash. This is so
//   that if it's for example a record definition, the record will get the same hash and thus 
//   the types will be compatible.
//   or maybe this exception should only live in the ffzTypeHash and ffzConstantHash. ugh.
typedef ffzHash ffzNodeHash;

// This should be project-global; see the note about exception at ffzNodeHash
typedef ffzHash ffzPolymorphHash;  // local to the module (different polymorphs in different modules may share a hash)


typedef ffzHash ffzTypeHash;       // project-global
typedef ffzHash ffzConstantHash;   // project-global
typedef ffzHash ffzFieldHash;
typedef ffzHash ffzEnumValueHash;

typedef struct ffzOk { bool ok; } ffzOk;
const static ffzOk FFZ_OK = { true };

typedef enum ffzNodeKind { // synced with `ffzNodeKind_to_string`
	ffzNodeKind_INVALID,

	ffzNodeKind_Blank,

	ffzNodeKind_Identifier,
	ffzNodeKind_PolyExpr,      // poly[X, Y, ...] Z
	ffzNodeKind_Keyword,
	ffzNodeKind_ThisDot,  // .
	ffzNodeKind_ProcType,
	ffzNodeKind_Record,
	ffzNodeKind_Enum,
	ffzNodeKind_Return,
	ffzNodeKind_If,
	ffzNodeKind_For,
	ffzNodeKind_Scope,
	ffzNodeKind_IntLiteral,
	ffzNodeKind_StringLiteral,
	ffzNodeKind_FloatLiteral,

	// -- Operators ----------------------
	// :ffz_node_is_operator

	ffzNodeKind_Declare,            // x : y
	ffzNodeKind_Assign,             // x = y

	ffzNodeKind_Add,                // x + y
	ffzNodeKind_Sub,                // x - y
	ffzNodeKind_Mul,                // x * y
	ffzNodeKind_Div,                // x / y
	ffzNodeKind_Modulo,             // x % y

	ffzNodeKind_MemberAccess,       // x . y

	// :ffz_op_is_comparison
	ffzNodeKind_Equal,              // x == y
	ffzNodeKind_NotEqual,           // x != y
	ffzNodeKind_Less,               // x < y
	ffzNodeKind_LessOrEqual,        // x <= y
	ffzNodeKind_Greater,            // x > y
	ffzNodeKind_GreaterOrEqual,     // x >= y

	ffzNodeKind_LogicalAND,         // x && y
	ffzNodeKind_LogicalOR,          // x || y

	// :ffz_op_is_prefix
	ffzNodeKind_PreSquareBrackets,  // [...]x
	ffzNodeKind_UnaryMinus,         // -x
	ffzNodeKind_UnaryPlus,          // +x
	ffzNodeKind_AddressOf,          // &x
	ffzNodeKind_PointerTo,          // ^x
	ffzNodeKind_LogicalNOT,         // !x

	// :ffz_op_is_postfix
	ffzNodeKind_PostSquareBrackets, // x[...]
	ffzNodeKind_PostRoundBrackets,  // x(...)
	ffzNodeKind_PostCurlyBrackets,  // x{...}
	ffzNodeKind_Dereference,        // x^

	ffzNodeKind_COUNT,
} ffzNodeKind;

typedef uint8_t ffzNodeFlags;
enum {
	ffzNodeFlag_IsStandaloneTag = 1 << 0,
};

typedef enum ffzKeyword { // synced with `ffzKeyword_to_string`
	ffzKeyword_INVALID,

	ffzKeyword_Eater,        // _
	ffzKeyword_QuestionMark, // ?
	ffzKeyword_Undefined,    // ~~
	ffzKeyword_dbgbreak,
	ffzKeyword_size_of,
	ffzKeyword_align_of,
	ffzKeyword_import,
	// TODO: type_of?
	// TODO: offset_of?

	ffzKeyword_true,
	ffzKeyword_false,

	ffzKeyword_u8,
	ffzKeyword_u16,
	ffzKeyword_u32,
	ffzKeyword_u64,
	ffzKeyword_s8,
	ffzKeyword_s16,
	ffzKeyword_s32,
	ffzKeyword_s64,
	ffzKeyword_f32,
	ffzKeyword_f64,
	ffzKeyword_int,
	ffzKeyword_uint,
	ffzKeyword_bool,
	ffzKeyword_raw,
	ffzKeyword_string,

	// :ffz_keyword_is_bitwise_op
	ffzKeyword_bit_and,
	ffzKeyword_bit_or,
	ffzKeyword_bit_xor,
	ffzKeyword_bit_shl,
	ffzKeyword_bit_shr,
	ffzKeyword_bit_not,

	// -- Extended keywords ------------------------------------------------
	// I think we should just make these keywords into regular keywords. Decide on a set that we ship with the core language and any extensions
	// will be extensions, not global keywords. ...idk
	ffzKeyword_FIRST_EXTENDED,
	ffzKeyword_extern = ffzKeyword_FIRST_EXTENDED,
	ffzKeyword_using,
	ffzKeyword_global,
	ffzKeyword_module_defined_entry,

	ffzKeyword_COUNT,
} ffzKeyword;

typedef struct ffzLoc {
	uint32_t line_num; // As in text files, starts at 1
	uint32_t column_num;
	uint32_t offset;
} ffzLoc;

typedef struct ffzLocRange {
	ffzLoc start;
	ffzLoc end;
} ffzLocRange;

typedef struct ffzCheckInfo {
	bool is_local_variable; // TODO: turn this into a flags

	//ffzPolymorphID polymorphed_from; // by default this is FFZ_POLYMORPH_ID_NONE
	// this is a weird edge case.
	ffzPolymorphID use_polymorph_hash_as_node_hash; // by default this is FFZ_POLYMORPH_ID_NONE

	// NOTE: declarations also cache the type (and constant) here, even though declarations are not expressions.
	fOpt(ffzType*) type;
	fOpt(ffzConstantData*) constant;
} ffzCheckInfo;


//
// An ffzNode can have a list of child nodes. These are called its "main children". In addition, a node can have
// "secondary children". For example, an If-node has two secondary children - one for the true scope and another for the false scope.
// Secondary children are always one-off nodes and cannot be lists (A secondary child slot can hold 0 or 1 nodes).
//
// ffzCursor is a way to refer to a location in the AST where a node can be inserted,
// i.e. between two nodes. It can also be at the beginning or end of a (potentially empty) child node list.
// A cursor may also point to the beginning/left side of a secondary child slot.
//
typedef struct ffzCursor {
	ffzNode* parent;
	fOpt(ffzNode*)* pp_node; // This will point either to the `first_child` or `next` field, or to one of the secondary child fields.
} ffzCursor;

struct ffzNode {
	ffzNodeKind kind;
	ffzNodeFlags flags;
	
	ffzSourceID source_id; // can be FFZ_SOURCE_ID_NONE
	ffzModuleID module_id;
	
	ffzLocRange loc;

	ffzNode* first_tag;
	ffzNode* parent;
	ffzNode* next;
	ffzNode* first_child; // first main child

	bool has_checked; // TODO: have a flip-flop re-checking
	//bool TEST___expanded_from_poly;
	ffzCheckInfo checked;

	// There is one benefit from having the node be a union, which is that we can do easy in-place replacement of nodes without having to store the
	// prev - pointer. Maybe we should just store the prev pointer.
	// :InPlaceNodeModification

	union {
		struct {
			fString name;
			bool is_constant; // has # in front?

			// When instantiating a polymorphic definition, i.e. Array[int], that node will be replaced with an identifier referring
			// to the copied instance. It might look something like "Array__poly_12". This way of instantiating polymorphs is nice, because
			// it means that any tools that deal with the FFZ tree don't have to worry about polymorphism at all, except of course the checker which
			// generates the instantiations. But it also means that using the generated name, we would get bad error messages.
			// So, the checker also generates an optional `pretty_name`, which will be displayed in error messages over `name` when it's non-empty.
			fString pretty_name;
			
			// hmm... Or maybe we could do something like prefix generated names with `\`, so it'd be like `\Array[u32]` and parse things starting with \
			// in the parser until whitespace into a single identifier. Then the backend could see that it starts with \ and wrangle a name for it.
			// Just an idea.

			// ffzNode* chk_definition; // resolved during the checker stage
			// ffzNode* chk_next_use;   // resolved during the checker stage
		} Identifier;

		struct {
			ffzNode* expr;
		} PolyExpr;

		struct {
			ffzKeyword keyword;
		} Keyword;

		struct {
			fOpt(ffzNode*) left;
			fOpt(ffzNode*) right;
		} Op;

		struct {
			ffzNode* condition;
			ffzNode* true_scope;
			fOpt(ffzNode*) else_scope;
		} If;

		struct {
			fOpt(ffzNode*) header_stmts[3];
			ffzNode* scope;
		} For;

		struct {
			fOpt(ffzNode*) out_parameter;
		} ProcType;

		struct {
			bool is_union;
		} Record;

		struct {
			ffzNode* internal_type;
		} Enum;

		struct {
			fOpt(ffzNode*) value;
		} Return;

		struct {
			double value; // NOTE: doubles can hold all the values that a float can.
		} FloatLiteral;

		struct {
			uint64_t value;
			uint8_t was_encoded_in_base; // this is mainly here for printing the AST back into text
		} IntLiteral;

		struct {
			fString zero_terminated_string;
		} StringLiteral;
	};
};

// hmm... I don't think we really need the error callback, we could trivially return the error message, location, etc as a result. TODO!
typedef struct ffzErrorCallback {
	// `node` will be NULL during the parser stage
	void(*callback)(ffzParser* parser, ffzNode* node, ffzLocRange location, fString error, void* userdata);
	void* userdata;
} ffzErrorCallback;

// Parser is responsible for parsing a single file / string of source code
struct ffzParser {
	ffzModule* module;       // unused in the parser stage
	ffzSourceID self_id;

	fMap64(ffzKeyword)* keyword_from_string; // key: f_hash64_str(str);

	fString source_code;
	fString source_code_filepath;

	ffzNode* root; // should we even store this here? Maybe we should return it from the parsing procedures instead.

	fAllocator* alc;
	//ffzParserLocalID next_local_id;

	fArray(ffzNode*) import_keywords;

	bool stop_at_curly_brackets;

	ffzErrorCallback error_cb;
};

typedef enum ffzTypeTag {
	ffzTypeTag_Invalid,

	ffzTypeTag_Raw,       // `raw`
	ffzTypeTag_Undefined, // the type of the expression `~~`

	ffzTypeTag_Type,
	ffzTypeTag_PolyExpr,
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

struct ffzDefinitionPath {
	ffzNode* parent_scope; // NULL for top-level scope
	fString name;
};

// if we wanted to pack the ffzConstantData structure down, then we would read bad memory in a few places  :PackConstantTroubles
typedef struct ffzConstantData {
	union {
		uint64_t  _uint;
		int64_t   _sint;
		double   _float;
		bool      _bool;
		
		//fOpt(ffzConstantData*) ptr; // hmm... why is this optional?
		ffzConstantData* ptr;

		ffzType* type;
		ffzModule* module;
		fString string_zero_terminated; // length doesn't contain the zero termination.

		// tightly-packed array of ffzConstantData. i.e. if this is an array of u8,
		// the n-th element would be ((ffzConstantData*)((u8*)array_elems + n))->_u8.
		// You can use ffz_constant_fixed_array_get() to get an element from it.
		fOpt(void*) fixed_array_elems; // or NULL for zero-initialized

		// `proc-type` if extern proc, otherwise `post-curly-brackets`.
		// Currently, procedure definitions are actually categorized as "operators" in the AST,
		// because they have the form of `procedure_type{}`, which might seem a bit strange.
		ffzNode* proc_node;

		fSlice(ffzConstantData) record_fields; // or empty for zero-initialized
	};
} ffzConstantData;

typedef struct ffzConstant {
	ffzType* type;
	ffzConstantData* data;
} ffzConstant;

typedef struct ffzPolymorph {
	ffzNode* poly_def;
	fSlice(ffzConstant) parameters;
} ffzPolymorph;

typedef struct ffzField {
	fString name;
	fOpt(ffzNodeOpDeclare*) decl; // not always used, i.e. for slice type fields
	
	ffzConstantData default_value;
	bool has_default_value;

	uint32_t offset; // ignored for procedure parameters
	ffzType* type;
} ffzNamedField;

typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
struct ffzTypeRecordFieldUse {
	ffzType* type;
	uint32_t offset;
};

typedef struct ffzTypeEnumField {
	fString name;
	uint64_t value;
} ffzTypeEnumField;

typedef struct ffzType {
	ffzTypeTag tag;
	uint32_t size;
	uint32_t align;

	ffzTypeHash hash;
	ffzModuleID checker_id;
	fOpt(ffzNode*) unique_node; // available for struct, union, enum, poly-def, and proc types.

	fSlice(ffzField) record_fields; // available for struct, union, slice types and the string type.

	union {
		struct {
			fSlice(ffzField) in_params;
			fOpt(ffzType*) return_type;
		} Proc;

		struct {
			bool is_union; // otherwise struct
		} Record;

		struct {
			ffzType* internal_type;
			fSlice(ffzTypeEnumField) fields;
		} Enum;

		struct {
			ffzType* elem_type;
		} Slice;

		struct {
			ffzType* elem_type;
			int32_t length; // -1 means length is inferred by [?]
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

	fArray(fString) link_libraries;
	fArray(fString) link_system_libraries;

	// having the parsers array in the project instead of per-module is convenient for the backend
	fArray(ffzParser*) parsers; // key: ffzParserID

	fArray(ffzModule*) checkers; // key: ffzCheckerID
	
	fArray(ffzModule*) checkers_dependency_sorted; // topologically sorted from leaf modules towards higher-level modules
	
	uint32_t pointer_size;

	fMap64(ffzKeyword) keyword_from_string;
	
	struct {
		fMap64(ffzModule*) module_from_directory;
	} filesystem_helpers;
} ffzProject;

struct ffzModule {
	ffzProject* project;
	bool checked;

	fAllocator* alc;
	ffzModuleID self_id;

	fString directory; // imports in this module will be relative to this directory

	ffzErrorCallback error_cb;

	// In order to be able to quickly lookup in any scope for a variable by its name,
	// we need to build a hash map for this purpose.
	// We could build this during parsing, but then we couldn't easily do stuff like
	// 1. parse 2. check 3. modify 4. check again, because the definitions would be filled in the parsing stage.

	fMap64(ffzNodeIdentifier*) definition_map; // key: ffz_hash_declaration_path
	uint32_t next_flat_index;

	fArray(ffzNode*) pending_import_keywords;

	ffzNode* root;
	ffzNode* root_last_child;

	// implicit state for the current checker invocation
	//ffzCheckerScope* current_scope;
	
	fMap64Raw checked_identifiers; // key: ffz_hash_poly_inst. This is to detect cycles. We could reduce the memory footprint here by removing things as we go...

	// * key: ffz_hash_node_inst
	// * Statements have NULL entries, except declarations, which cache the type
	//   (and maybe constant value) of the declaration.
	//fMap64(ffzCheckedInst) cache;

	//fMap64(ffzPolymorph*) poly_instantiation_sites; // key: ffz_hash_node_inst
	
	fMap64(ffzType*) type_from_hash; // key: TypeHash
	
	fMap64(ffzPolymorphID) poly_from_hash; // key: ffz_hash_poly_inst
	fArray(ffzPolymorph) polymorphs; // index into this using ffzPolymorphID
	
	// Contains a list of all tag instances, within this module, of each type.
	// fMap64(fArray(ffzNodeInst)) all_tags_of_type; // key: TypeHash
	
	fMap64(ffzTypeRecordFieldUse*) field_from_name_map; // key: FieldHash
	
	// Only required during checking.
	fMap64(u64) enum_value_from_name; // key: FieldHash.
	fMap64(ffzNode*) enum_value_is_taken; // key: EnumValuekey

	fMap64(fString) extern_libraries;

	// An `import` node must always be part of a declaration, and must uniquely import a module that
	// hasn't been imported previously. This restriction exists, so that we have a way
	// of mapping from module import to an import name. This property is useful for instance in error
	// reporting, and polymorph instantiation code.

	fMap64(ffzNode*) import_decl_from_module;   // key: ffzModule*
	fMap64(ffzModule*) module_from_import_decl; // key: ffzNode*

	ffzType* type_type;
	ffzType* module_type;
	//ffzParserLocalID next_pseudo_node_idx;
	ffzType* builtin_types[ffzKeyword_COUNT];
};

#define FFZ_EACH_CHILD(n, parent) (ffzNode* n = (parent) ? parent->first_child : NULL; n = ffz_skip_standalone_tags(n); n = n->next)

// -- Builder -------------------------------------------

inline fOpt(ffzNode*) ffz_get_node_at_cursor(ffzCursor* at) { return *at->pp_node; }

// Replace the node at the cursor with another node, and update the cursor keeping it in place.
FFZ_CAPI void ffz_replace_node(ffzCursor* at, ffzNode* with);

// Insert a new node at the cursor, and update the cursor keeping it in place.
FFZ_CAPI void ffz_insert_node(ffzCursor* at, ffzNode* node);

// Remove a node at the cursor, and update the cursor keeping it in place.
FFZ_CAPI void ffz_remove_node(ffzCursor* at);

// clones `node` into the module `m`
FFZ_CAPI ffzNode* ffz_clone_node(ffzModule* m, ffzNode* node);

// module-allocated node
FFZ_CAPI ffzNode* ffz_new_node(ffzModule* m, ffzNodeKind kind);

// Helper functions for getting a cursor to a secondary child node
inline ffzCursor ffz_cursor_poly_expr(ffzNode* node) { ffzCursor c = { node, &node->PolyExpr.expr }; return c; }
inline ffzCursor ffz_cursor_op_left(ffzNode* node) { ffzCursor c = { node, &node->Op.left }; return c; }
inline ffzCursor ffz_cursor_op_right(ffzNode* node) { ffzCursor c = { node, &node->Op.right }; return c; }
inline ffzCursor ffz_cursor_if_condition(ffzNode* node) { ffzCursor c = { node, &node->If.condition }; return c; }
inline ffzCursor ffz_cursor_if_true_scope(ffzNode* node) { ffzCursor c = { node, &node->If.true_scope }; return c; }
inline ffzCursor ffz_cursor_if_false_scope(ffzNode* node) { ffzCursor c = { node, &node->If.else_scope }; return c; }
inline ffzCursor ffz_cursor_for_header_stmt(ffzNode* node, uint32_t i) { ffzCursor c = { node, &node->For.header_stmts[i] }; return c; }
inline ffzCursor ffz_cursor_for_scope(ffzNode* node) { ffzCursor c = { node, &node->For.scope }; return c; }
inline ffzCursor ffz_cursor_proc_type_out_parameter(ffzNode* node) { ffzCursor c = { node, &node->ProcType.out_parameter }; return c; }
inline ffzCursor ffz_cursor_ret_value(ffzNode* node) { ffzCursor c = { node, &node->Return.value }; return c; }

// -- Parser --------------------------------------------

inline ffzLocRange ffz_loc_to_range(ffzLoc loc) {
	ffzLocRange range = { loc, loc };
	return range;
};

inline ffzLoc ffz_loc_min(ffzLoc a, ffzLoc b) { return a.offset < b.offset ? a : b; }
inline ffzLoc ffz_loc_max(ffzLoc a, ffzLoc b) { return a.offset > b.offset ? a : b; }

inline ffzLocRange ffz_loc_range_union(ffzLocRange a, ffzLocRange b) {
	ffzLocRange range = { ffz_loc_min(a.start, b.start), ffz_loc_max(a.end, b.end) };
	return range;
}

// 0 is returned if not a bracket operator
FFZ_CAPI uint8_t ffz_get_bracket_op_open_char(ffzNodeKind kind);
FFZ_CAPI uint8_t ffz_get_bracket_op_close_char(ffzNodeKind kind);

inline bool ffz_keyword_is_extended(ffzKeyword keyword) { return keyword >= ffzKeyword_FIRST_EXTENDED; }

inline bool ffz_node_is_operator(ffzNodeKind kind) { return kind >= ffzNodeKind_Declare && kind <= ffzNodeKind_Dereference; }
inline bool ffz_op_is_prefix(ffzNodeKind kind) { return kind >= ffzNodeKind_PreSquareBrackets && kind <= ffzNodeKind_LogicalNOT; }
//inline bool ffz_op_is_infix(ffzNodeKind kind) { f_trap(); return false; } // { return kind >= ffzNodeKind_PreSquareBrackets && kind <= ffzNodeKind_LogicalNOT; }
inline bool ffz_op_is_postfix(ffzNodeKind kind) { return kind >= ffzNodeKind_PostSquareBrackets && kind <= ffzNodeKind_Dereference; }
inline bool ffz_op_is_comparison(ffzNodeKind kind) { return kind >= ffzNodeKind_Equal && kind <= ffzNodeKind_GreaterOrEqual; }
//inline bool ffz_operator_is_arithmetic(ffzNodeKind kind) { return kind >= ffzNodeKind_Add && kind <= ffzNodeKind_Modulo; }

// These both return an empty string if the node's parent is not a declaration, or the node itself is NULL
FFZ_CAPI fString ffz_get_parent_decl_name(fOpt(ffzNode*) node); 
FFZ_CAPI fString ffz_get_parent_decl_pretty_name(fOpt(ffzNode*) node);

FFZ_CAPI uint32_t ffz_get_child_index(ffzNode* child); // will assert if child is not part of its parent
FFZ_CAPI ffzNode* ffz_get_child(ffzNode* parent, uint32_t idx);
FFZ_CAPI uint32_t ffz_get_child_count(fOpt(ffzNode*) parent); // returns 0 if parent is NULL

FFZ_CAPI uint32_t ffz_operator_get_precedence(ffzNodeKind kind);

FFZ_CAPI fString ffz_keyword_to_string(ffzKeyword keyword);

FFZ_CAPI fString ffz_node_kind_to_string(ffzNodeKind kind);

FFZ_CAPI fString ffz_node_kind_to_op_string(ffzNodeKind kind);

// ffz_parse_scope is for parsing i.e. a source code file that has multiple nodes in it, whereas
// ffz_parse_node is for parsing a single node.
FFZ_CAPI ffzOk ffz_parse_scope(ffzParser* p);
FFZ_CAPI ffzOk ffz_parse_node(ffzParser* p);

FFZ_CAPI fOpt(ffzNode*) ffz_skip_standalone_tags(fOpt(ffzNode*) node);

FFZ_CAPI void ffz_print_ast(fWriter* w, ffzNode* node);
FFZ_CAPI fString ffz_node_to_string(ffzProject* p, ffzNode* node, bool try_to_use_source, fAllocator* alc);

// ------------------------------------------------------

fOpt(ffzType*) ffz_builtin_type(ffzModule* c, ffzKeyword keyword);

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

uint32_t ffz_get_encoded_constant_size(ffzType* type);
ffzConstantData ffz_constant_fixed_array_get(ffzConstant constant, uint32_t index);

bool ffz_type_is_concrete(ffzType* type); // a type is grounded when a runtime variable may have that type.

bool ffz_type_is_comparable_for_equality(ffzType* type); // supports ==, !=
bool ffz_type_is_comparable(ffzType* type); // supports <, >, et al.

fString ffz_type_to_string(ffzProject* p, ffzType* type);
//char* ffz_type_to_cstring(ffzProject* p, ffzType* type);

fString ffz_constant_to_string(ffzProject* p, ffzConstantData* constant, ffzType* type);
//char* ffz_constant_to_cstring(ffzProject* p, ffzConstantData* constant, ffzType* type);

ffzNode* ffz_constant_to_node(ffzModule* m, ffzNode* parent, ffzConstant constant);

//ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value);
//ffzNodeHash ffz_hash_node(ffzNode* node);
//u64 ffz_hash_declaration_path(ffzDefinitionPath path);
//ffzMemberHash ffz_hash_member(ffzType* type, fString member_name);
//ffzConstantHash ffz_hash_constant(ffzCheckedInst constant);

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

ffzModule* ffz_project_add_module(ffzProject* p, fArena* module_arena);

//ffzParser* ffz_module_add_parser(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb);

// Parses the source code immediately, returning true if success.
// `filepath` is otherwise ignored, but it's passed down to the error callback.
//bool ffz_module_add_code_string(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb);

// The node must be a top-level node and have it's parent field set to NULL.
ffzOk ffz_module_add_top_level_node(ffzModule* m, ffzNode* node);

bool ffz_module_resolve_imports(ffzModule* m, ffzModule*(*module_from_path)(fString path, void* userdata), void* userdata, ffzErrorCallback error_cb);

// When you call ffz_module_check_single, all imported modules must have already been checked.
bool ffz_module_check_single(ffzModule* m, ffzErrorCallback error_cb);


// --- OS layer helpers ---

// This automatically adds all files in the directory into the module.
// If this has already been called before with identical directory, then that previously created module is returned.
// Returns NULL if the directory does not exist, or if any of the source code files failed to parse.
fOpt(ffzModule*) ffz_project_add_module_from_filesystem(ffzProject* p, fString directory, fArena* module_arena, ffzErrorCallback error_cb);

//void ffz_module_resolve_imports_using_fileystem(ffzModule* m, fSlice(ffzModule*)* out_imports);

// ---


// we could give you a flat array of all the types in your program
// - and procedures
// - and standalone tags


// TODO: CLEANUP
//ffzOk ffz_check_toplevel_statement(ffzModule* c, ffzNode* node);
//ffzOk ffz_instanceless_check(ffzModule* c, ffzNode* node, bool recursive);

// -- Accessing cached data -----------------------------------------------------------

//bool ffz_find_top_level_declaration(ffzModule* c, fString name, ffzNodeOpDeclare* out_decl);

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out);

// "definition" is the identifier of a value that defines the name of the value.
// e.g. in `foo: int`, the foo identifier would be a definition.
fOpt(ffzNodeIdentifier*) ffz_find_definition(ffzProject* p, ffzNodeIdentifier* ident);

bool ffz_find_field_by_name(fSlice(ffzField) fields, fString name, uint32_t* out_index);

// * Return the name of an import declaration, given an imported module.
//     e.g. if module `m` contains `#Foo: import("imported_module")`, then the returned value would be "Foo"
// * If `imported_module` is not imported by `m`, an empty string is returned.
fString ffz_get_import_name(ffzModule* m, ffzModule* imported_module);

// 
// Given an argument list (either a post-curly-brackets initializer or a procedure call) that might contain
// both unnamed as well as named arguments, this procedure will give the arguments
// in a flat list in the same order as the `fields` array. Note that some arguments might not exist,
// so those will have just have the default value of ffzNodeInst{}
// 
void ffz_get_arguments_flat(ffzNode* arg_list, fSlice(ffzField) fields, fSlice(ffzNode*)* out_arguments, fAllocator* alc);

bool ffz_constant_is_zero(ffzConstantData constant);



inline fString ffz_decl_get_name(ffzNodeOpDeclare* decl) { return decl->Op.left->Identifier.name; }

//bool ffz_decl_is_runtime_variable(ffzNodeOpDeclare* decl);
bool ffz_decl_is_local_variable(ffzNodeOpDeclare* decl);
bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl);
inline bool ffz_decl_is_parameter(ffzNodeOpDeclare* decl) { return decl->parent && decl->parent->kind == ffzNodeKind_ProcType; }

inline bool ffz_decl_is_variable(ffzNodeOpDeclare* decl) {
	return ffz_decl_is_parameter(decl) || ffz_decl_is_global_variable(decl) || ffz_decl_is_local_variable(decl);
}

bool ffz_is_code_scope(ffzNode* node);

fOpt(ffzNode*) ffz_this_dot_get_assignee(ffzNodeThisValueDot* dot);

fOpt(ffzConstantData*) ffz_get_tag_of_type(ffzProject* p, ffzNode* node, ffzType* tag_type);
fOpt(ffzConstantData*) ffz_get_tag(ffzProject* p, ffzNode* node, ffzKeyword tag);

