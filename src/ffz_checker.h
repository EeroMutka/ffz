//
// The purpose of checker is to check if a given ffz program is valid or not.
// This includes figuring out the types of expressions and checking if they match, substituting polymorphic types and making them concrete,
// amongst other things. While doing so, the checker caches information about the program, such as type information, that can be useful in later stages.
// The checker takes in an abstract syntax tree form of a program as input, so it is dependend on "ffz_ast.h".
// 



// FFZ is a statically typed, compiled programming language for data-oriented programming
// with the goal of being debuggable and enjoyable to use. And, it is written as a modular
// library consisting of <10k lines of well-commented C code!
// 
// 
// FFZ is a statically typed, compiled programming language
// with the goal of being practical, debuggable, enjoyable to use, and
// giving full control to the programmer. And, it is written as a modular
// library consisting of <10k lines of well-commented C code!
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
// the checked modules. Then it kinda makes sense to not use pointers, but offsets instead so you can just load a checked module into memory.
// As for the backend, the cached modules don't need to be fed into the backend at all, as the object files are already generated.
// 
// One cool thing about caching could be that you could use it as a reflection tool. In your program, you could just load the cached binary
// and get direct access to FULL semantic information of the project, including the AST tree.
// 
// Where should we put the polymorph instantiations? If we wanted to have a global table of them, then we have a problem if a cached module contains
// them. When loading a cached module, we'd have to enumerate the instantiations in the cached data and add them to the global table.
// soo.. put them in the module who instantiates.
//

#define F_DEF_MINIMAL_INCLUDE
#include "foundation/foundation.h"

// When FFZ_DEBUG_USE_POINTERS is enabled, disable caching and also use deterministic addresses (allocate everything from one arena)
//#define FFZ_DEBUG_USE_POINTERS

typedef struct ffzProject ffzProject;
typedef struct ffzModule ffzModule;
typedef struct ffzModuleChecker ffzModuleChecker;
typedef struct ffzSource ffzSource;
typedef struct ffzType ffzType;
typedef union ffzDatum ffzDatum;
typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;

//typedef uint32_t ffzPolymorphID;
//#define FFZ_POLYMORPH_ID_NONE 0

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

typedef uint64_t ffzHash; // TODO: increase this to 128 bits.

// We could make hashes fully deterministic across multiple compilations (not dependend on any runtime addresses),
// but right now they do depend on runtime addresses. See `ffz_hash_node`

typedef ffzHash ffzNodeHash;

// VERY OLD COMMENT:
// ffzExpressionHash is usually the same thing as ffzNodeHash. But there is an exception:
// Say module X defines and instantiates a polymorphic expression. Module Y imports X, and makes an identical
// instantiation to the one in module X. The instantiations are copied into both modules and will get their own nodes.
// This is done so that we can individually cache the modules and still have it all work (i.e. say the module exposes a struct that uses a local instantiation as a field).
// So in this case, ffzExpressionHash will hash to the same thing for the instantiated node in both modules.
// 
// NOTE: currently the child nodes of the instantations will get different hashes in different instantiations/modules.
//typedef ffzHash ffzExpressionHash;

typedef ffzHash ffzPolymorphHash;  // project-global (e.g. if module X and Y instantiate identical polymorph from module Z, they will have the same hash)
typedef ffzHash ffzTypeHash;       // project-global (e.g. if module X and Y both use the type [15]^int, they will have the same hash)
typedef ffzHash ffzConstantHash;   // project-global (e.g. if module X and Y both use the value int(6123), they will have the same hash)
typedef ffzHash ffzFieldHash;
typedef ffzHash ffzEnumValueHash;

typedef enum ffzNodeKind {
	ffzNodeKind_INVALID,

	ffzNodeKind_Blank,

	ffzNodeKind_Identifier,
	ffzNodeKind_PolyDef,  // poly[X, Y, ...] Z
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
	ffzNodeKind_GeneratedConstant, // this is an imaginary node, as it cannot be represented in source code form.

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

typedef enum ffzKeyword {
	ffzKeyword_INVALID,

	ffzKeyword_Eater,        // _
	//ffzKeyword_QuestionMark, // ?
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
	ffzKeyword_type,
	ffzKeyword_string,

	// :ffz_keyword_is_bitwise_op
	ffzKeyword_bit_and,
	ffzKeyword_bit_or,
	ffzKeyword_bit_xor,
	ffzKeyword_bit_shl,
	ffzKeyword_bit_shr,
	ffzKeyword_bit_not,
	
	ffzKeyword_build_option,

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
	uint32_t column_num; // Character number in the line, starting from 1
	uint32_t offset;
} ffzLoc;

typedef struct ffzLocRange {
	ffzLoc start;
	ffzLoc end;
} ffzLocRange;

typedef struct ffzValue {
	ffzType* type;
	ffzDatum* datum;
} ffzValue;

typedef struct ffzPolymorph {
	fSlice(ffzValue) parameters;
	ffzNode* poly_def;
	ffzNode* instantiated_node; // This will be the deep-copied node tree, with references to the polymorphic parameters replaced with GeneratedConstant-nodes
} ffzPolymorph;

typedef struct ffzCheckInfo {
	// TODO: turn these into flags
	bool is_local_variable;
	bool is_undefined;

	fOpt(ffzPolymorph*) call_implicit_poly;
	//ffzPolymorphID call_implicit_poly_id;

	union {
		struct {
			// NOTE: declarations also cache the type (and constant) here, even though declarations are not expressions.
			fOpt(ffzType*) type;
			fOpt(ffzDatum*) const_val;
		};
		ffzValue constant;
	};
} ffzCheckInfo;

//
// An ffzNode can have a list of child nodes. These are called its "main children". In addition, a node can have
// "secondary children". For example, an If-node has two secondary children - one for the true scope and another for the false scope.
// Secondary children are always one-off nodes and cannot be lists (A secondary child slot can hold 0 or 1 nodes).
//
// ffzCursor is a way to point to a location in the AST where a node can be inserted,
// i.e. between two nodes. It can also point to the beginning or end of a (potentially empty) child node list.
// A cursor may also point to a secondary child field.
//
typedef struct ffzCursor {
	ffzNode* parent;
	ffzNode** pp_node; // This will point either to the `first_child` or `next` field, or to a secondary child field.
} ffzCursor;


struct ffzNode {
	ffzNodeKind kind;
	ffzNodeFlags flags;
	
	// This is the only part of ffzNode that is not directly serializable.
	// It'd just be too annoying to have to pass ffzSourceID + ffzProject* everywhere.
	// So when loading a cached module, we need to loop through all the nodes once and patch this.
	
	// NOTE: module and the module of `loc_src` might be different! Say module X instantiates a polymorphic definition from module Y. The new nodes
	// will be added to module X, but they will still refer to the source from module Y, as that will be used for their source code location.
	ffzModule* _module;

	//ffzPolymorphID is_instantiation_root_of_poly; // by default this is FFZ_POLYMORPH_ID_NONE
	
	// We could make `loc_source` into an index. The following two members are optional, because you may generate
	// nodes on the fly.
	fOpt(ffzSource*) loc_source;
	ffzLocRange loc;

	// ************* A huge goal of FFZ is to be simple. So let's do the simple thing for pointers. *************
	fOpt(ffzNode*) first_tag;
	fOpt(ffzNode*) parent;
	fOpt(ffzNode*) next;
	fOpt(ffzNode*) first_child; // first main child

	// There is one benefit from having the node be a union, which is that we can do easy in-place replacement of nodes without having to store the
	// prev - pointer. Maybe we should just store the prev pointer.
	// :InPlaceNodeModification

	union {
		struct {
			fString name;
			bool is_constant; // has # in front?
		} Identifier;

		struct {
			ffzNode* expr;
		} PolyDef;

		struct {
			ffzKeyword keyword;
		} Keyword;

		struct {
			ffzNode* left;  // optional
			ffzNode* right; // optional
		} Op;

		struct {
			ffzNode* condition;
			ffzNode* true_scope;
			ffzNode* false_scope; // optional
		} If;

		struct {
			ffzNode* header_stmts[3]; // optional
			ffzNode* scope;
		} For;

		struct {
			ffzNode* out_parameter; // optional
		} ProcType;

		struct {
			bool is_union;
		} Record;

		struct {
			ffzNode* internal_type;
		} Enum;

		struct {
			ffzNode* value; // optional
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

		struct {
			ffzValue constant;
		} GeneratedConstant;
	};
};

typedef struct ffzError {
	fOpt(ffzNode*) node;
	fOpt(ffzSource*) source;
	ffzLocRange location;
	fString message;
} ffzError;

// Error handling helper macros

#define FFZ_TRY(x) { \
	fOpt(ffzError*) _x = x; \
	if (_x) return _x; \
}

typedef struct ffzSource {
	ffzModule* _module;
	//ffzSourceID self_id; // TODO: remove this

	fString source_code;
	fString source_code_filepath;
} ffzSource;

// hmm, maybe we should merge ffzParseResult and ffzSource
typedef struct ffzParseResult {
	ffzSource* source;
	fOpt(ffzNode*) node; // if NULL, the parsing failed
	fSlice(ffzNode*) import_keywords;
} ffzParseResult;

typedef enum ffzTypeTag {
	ffzTypeTag_Invalid,

	ffzTypeTag_Raw,       // `raw`
	ffzTypeTag_Undefined, // the type of the expression `~~`

	ffzTypeTag_Type,

	// NOTE: only polymorphic regions in the AST can contain these Poly* types.
	ffzTypeTag_PolyDef,   // i.e. #Array: poly[T] struct{...}
	ffzTypeTag_PolyParam, // i.e. the type of `foo` in `#X: poly[T] proc(foo: T)` would be `PolyParam`
	
	ffzTypeTag_Module,

	ffzTypeTag_Bool,
	ffzTypeTag_Pointer,

	// :type_is_integer
	ffzTypeTag_Sint, // `s8`, `s16`, ...
	ffzTypeTag_Uint, // `u8`, `u16`, ...
	ffzTypeTag_DefaultSint, // `int`
	ffzTypeTag_DefaultUint, // `uint`

	ffzTypeTag_Float,
	ffzTypeTag_Proc,
	ffzTypeTag_Record,
	ffzTypeTag_Enum,
	ffzTypeTag_Slice,
	ffzTypeTag_String, // string has the semantics of `#string: distinct []u8` with a custom iterator attached
	ffzTypeTag_FixedArray,
	
	//ffzTypeTag_Extra,
} ffzTypeTag;

struct ffzDefinitionPath {
	ffzNode* parent_scope; // NULL for top-level scope
	fString name;
};

// A "field" can mean any of the following: a struct member, an enum member, or a procedure parameter.
typedef struct ffzField {
	fString name;
	//fOpt(ffzNodeOpDeclare*) decl; // not always used, i.e. for slice type fields
	
	fOpt(ffzDatum*) default_value; // NULL means no default value
	//bool has_default_value;

	bool has_using; // only for struct members

	uint32_t offset; // ignored for procedure parameters / enum members
	ffzType* type;
} ffzField;

typedef struct ffzTypeRecordFieldUse {
	ffzField* src_field;
	uint32_t offset; // offset relative to the base address of the root
	fSlice(uint32_t) index_path; // path to the target member from the root
} ffzTypeRecordFieldUse;

typedef struct ffzTypeEnumField {
	fString name;
	int64_t value;
} ffzTypeEnumField;

typedef struct ffzType {
	ffzTypeTag tag;
	struct { bool x; } is_concrete; // Concrete types are types which can be used as runtime values. i.e. `type`, `module`, are not concrete.
	uint32_t size;
	uint32_t align;

	//ffzTypeHash hash;
	
	// This is here so that it's possible to, for example, get to the enum field map (stored per module) from just a checked node.
	// With cached modules, I guess we could treat the ModuleIDs as a slot array, where when creating a new module we make sure to not take
	// an index that has already been taken.
	// hmm... but do we then need it? we could then just do unique_node->module_id instead
	// ffzModuleID checker_id;

	fOpt(ffzNode*) distinct_node; // Available for struct, union, enum
	
	fSlice(ffzField) record_fields; // available for struct, union, slice types and the string type.
	
	fOpt(ffzPolymorph*) polymorphed_from;

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
			
			// In polymorphic nodes (ffz_node_is_polymorphic), this may be of type PolyParam. Otherwise must be `uint`.
			ffzValue length;
		} FixedArray;

		struct {
			ffzType* pointer_to;
		} Pointer;

		struct {
			ffzNode* param_node;
		} PolyParam;

		struct {
			uint32_t id;
		} Extra;
	};
} ffzType;

typedef struct ffzDatumRecord {
	fSlice(ffzDatum*) fields;
} ffzDatumRecord;

typedef struct ffzDatumPtr {
	// A pointer can be represented as either a pointer to another constant, or a literal integer value.
	uint64_t as_int;
	fOpt(ffzDatum*) as_ptr_to_constant; // if NULL, `as_int` is used instead
} ffzDatumPtr;

/*
 Packed representation of a compile-time known value.
*/
typedef union ffzDatum {
	int8_t  _s8;  int16_t _s16;  int32_t _s32;  int64_t _s64;
	uint8_t _u8; uint16_t _u16; uint32_t _u32; uint64_t _u64;
	uint64_t __uint;
	int64_t __int;

	float      _f32;
	double     _f64;
	bool      _bool;

	ffzDatumPtr ptr;
	fString string_zero_terminated; // length doesn't contain the zero termination.
	ffzDatumRecord record;
	
	// used for constant arrays/slices
	// TODO: we could tightly pack this array. However, then we would have to re-think about this:
	// if we don't intern the constants, then we can't compare their pointers anymore.
	// Could we intern non-basic types, but intern all others? idk.
	fSlice(ffzDatum*) array;
	
	// -- Compile time only values --
	
	ffzType type; // you can safely cast (ffzConstantData*) into (ffzType*) and the other way with `ffz_as_constant`
	ffzModule* module;

	// for procedures and poly-expressions.
	// NOTE: When an extern procedure, `node` will point to the ProcType node that is tagged @extern,
	// since there is no procedure body.
	ffzNode* node;
} ffzDatum;

// ffzProject contains read-only information about the project.
typedef struct ffzProject {
	uint32_t pointer_size;
	fMap64(ffzKeyword) keyword_from_string; // Constant lookup table

	ffzType* type_module;
	ffzType* type_poly_def;
	ffzType* builtin_types[ffzKeyword_COUNT];
	u32 next_extra_type_id;
	
	uint32_t next_module_id;

	// The bank is a global cache for semantic information across a project.
	// Sharing a cache means that comparing two types/constants for equality is a matter of comparing the pointers.
	struct {
		fAllocator* alc; // maybe switch this to Arena?
		fMap64(ffzType*) type_from_hash; // key: TypeHash
		fMap64(ffzDatum*) constant_from_hash; // key: ConstantHash
		fMap64(ffzTypeRecordFieldUse) field_from_name_map; // key: FieldHash
	} bank;

	/*
	fAllocator* persistent_allocator;

	// `modules_directory` can be an empty string, in which case
	// importing modules using the `:` prefix is not allowed.
	fString modules_directory;

	fArray(fString) link_libraries;
	fArray(fString) link_system_libraries;

	// having the sources array in the project instead of per-module is convenient for the backend
	fArray(ffzSource*) sources; // key: ffzSourceID

	fArray(ffzModule*) checkers; // key: ffzCheckerID

	//fArray(ffzModule*) checkers_dependency_sorted; // topologically sorted from leaf modules towards higher-level modules

	struct {
		fMap64(ffzModule*) module_from_directory;
	} filesystem_helpers;
	
	// Types and constants are stored into a project-wide cache. The benefit of this is that
	// comparing types / constants can be done by just testing pointers for equality.
	//
	// Hmm. ffzNode shouldn't ever get bound to a type/polymorph/constant info, it should rather be ffzNode + checker id, since that's
	// the combination that refers to the semantic info.
	//
	// Hmm, right now we're hashing the ffzNode pointers into some of the types, but that's a bit error prone if we were to
	// check, then free the nodes, create new nodes, and check again. I guess when hashing a node, we should hash the checker id
	// as well, and just say that you can't delete individual nodes from a module - you may wipe the entire module at once.
	*/
} ffzProject;

typedef struct ffzModuleChecker {
	ffzModule* mod;
	ffzProject* project;

	fAllocator* alc; // maybe replace this with arena?
	uint32_t id;

	bool finished;
	
	fArray(ffzModule*) imported_modules;

	// -- internal --------------------------------
	
	fOpt(ffzModule*)(*module_from_import)(ffzModule*, ffzNode*);

	// Immediate checker state
	fOpt(ffzPolymorph*) instantiating_poly;
	bool is_inside_polymorphic_node;

	// Maybe instead of this `infos` map, we should store the info in the node along with a generational index that matches the id of the checker.
	fMap64(ffzCheckInfo) infos; // key: ffzNode*

	/*
	 In order to be able to quickly lookup in any scope for a variable by its name,
	 we need to build a hash map for this purpose.
	 We could build this during parsing, but then we couldn't easily do stuff like
	 1. parse 2. check 3. modify 4. check again, because the definitions would be filled in the parsing stage.
	*/
	fMap64(ffzNodeIdentifier*) definition_map; // key: ffz_hash_declaration_path

	//fMap64Raw checked_identifiers; // key: ffz_hash_poly_inst. This is to detect cycles. We could reduce the memory footprint here by removing things as we go...
	
	fMap64(ffzPolymorph*) poly_from_hash;
	//fArray(ffzPolymorph) polymorphs; // index into this using ffzPolymorphID

	// Contains a list of all tags within this module for any given type.
	// NOTE: all nodes in this array must contain a checked constant
	fMap64(fArray(ffzNode*)) all_tags_of_type;

	// Only required during checking.
	fMap64(s64) enum_value_from_name; // key: FieldHash.
	fMap64(ffzNode*) enum_value_is_taken; // key: EnumValuekey

	//fArray(ffzNode*) _extern_libraries; // Array of all `extern` keywords in the module

	// An `import` node must always be part of a declaration, and must uniquely import a module that
	// hasn't been imported previously. This restriction exists, so that we have a way of mapping
	// imported module to an import name. This is useful for instance in error messages.

	//fMap64(ffzNode*) import_decl_from_module;   // key: ffzModule*
	//fMap64(ffzModule*) module_from_import_decl; // key: ffzNode*
} ffzModuleChecker;

struct ffzModule {
	ffzProject* project;
	fAllocator* alc;

	uint32_t self_id;
	uint32_t next_checker_ctx_id;

	fString directory; // imports in this module will be relative to this directory. ...Should we even have this here? maybe not. Though its a good debug string.
	
	// So a module has an associated checker. When you do`ffz_checked_get_info(node)`, it will implicitly use the
	// active context to look for the checked info.
	fOpt(ffzModuleChecker*) checker;

	ffzNode* root;
	ffzNode* root_last_child;

	void* userdata; // ignored by the library
};

#ifdef __cplusplus
extern "C" {
#endif

// -- Node utilities ------------------------------------

ffzNode ffz_node_default();

inline ffzModule* ffz_module_of_node(ffzNode* n) { return n->_module; }

//inline fOpt(ffzNode*) _ffz_skip_standalone_tags(fOpt(ffzNode*) node);
#define FFZ_EACH_CHILD(n, parent) (ffzNode* n = (parent) ? parent->first_child : NULL; \
(ffz_skip_standalone_tags(&n), n); n = n->next)

// -- Builder -------------------------------------------

inline fOpt(ffzNode*) ffz_get_node_at_cursor(ffzCursor at) { return *at.pp_node; }

// Replace the node at the cursor with another node, and update the cursor keeping it in place.
void ffz_replace_node(ffzCursor at, ffzNode* with);

// Insert a new node at the cursor, and update the cursor keeping it in place.
void ffz_insert_node(ffzCursor at, ffzNode* node);

// Remove a node at the cursor, and update the cursor keeping it in place.
void ffz_remove_node(ffzCursor at);

// clones `node` into the module `m`. It will be added to the `extra_nodes` source.
ffzNode* ffz_clone_node(ffzModule* m, ffzNode* node);

ffzNode* ffz_new_node(ffzModule* m, ffzNodeKind kind);

// Helper functions for getting a cursor to a secondary child node
inline ffzCursor ffz_cursor_poly_def(ffzNode* node) { ffzCursor c = { node, &node->PolyDef.expr }; return c; }
inline ffzCursor ffz_cursor_op_left(ffzNode* node) { ffzCursor c = { node, &node->Op.left }; return c; }
inline ffzCursor ffz_cursor_op_right(ffzNode* node) { ffzCursor c = { node, &node->Op.right }; return c; }
inline ffzCursor ffz_cursor_if_condition(ffzNode* node) { ffzCursor c = { node, &node->If.condition }; return c; }
inline ffzCursor ffz_cursor_if_true_scope(ffzNode* node) { ffzCursor c = { node, &node->If.true_scope }; return c; }
inline ffzCursor ffz_cursor_if_false_scope(ffzNode* node) { ffzCursor c = { node, &node->If.false_scope }; return c; }
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
uint8_t ffz_get_bracket_op_open_char(ffzNodeKind kind);
uint8_t ffz_get_bracket_op_close_char(ffzNodeKind kind);

inline bool ffz_keyword_is_extended(ffzKeyword keyword) { return keyword >= ffzKeyword_FIRST_EXTENDED; }

inline bool ffz_node_is_operator(ffzNodeKind kind) { return kind >= ffzNodeKind_Declare && kind <= ffzNodeKind_Dereference; }
inline bool ffz_op_is_prefix(ffzNodeKind kind) { return kind >= ffzNodeKind_PreSquareBrackets && kind <= ffzNodeKind_LogicalNOT; }
//inline bool ffz_op_is_infix(ffzNodeKind kind) { f_trap(); return false; } // { return kind >= ffzNodeKind_PreSquareBrackets && kind <= ffzNodeKind_LogicalNOT; }
inline bool ffz_op_is_postfix(ffzNodeKind kind) { return kind >= ffzNodeKind_PostSquareBrackets && kind <= ffzNodeKind_Dereference; }
inline bool ffz_op_is_comparison(ffzNodeKind kind) { return kind >= ffzNodeKind_Equal && kind <= ffzNodeKind_GreaterOrEqual; }
//inline bool ffz_operator_is_arithmetic(ffzNodeKind kind) { return kind >= ffzNodeKind_Add && kind <= ffzNodeKind_Modulo; }

inline bool ffz_node_is_top_level(ffzNode* node) { return node->parent->parent == NULL; }

// These both return an empty string if the node's parent is not a declaration, or the node itself is NULL
fString ffz_get_parent_decl_name(fOpt(ffzNode*) node);
//fString ffz_get_parent_decl_pretty_name(fOpt(ffzNode*) node);

uint32_t ffz_get_child_index(ffzNode* child); // will assert if child is not part of its parent
ffzNode* ffz_get_child(ffzNode* parent, uint32_t idx);
uint32_t ffz_get_child_count(fOpt(ffzNode*) parent); // returns 0 if parent is NULL

fString ffz_keyword_to_string(ffzKeyword keyword);

fString ffz_node_kind_to_string(ffzNodeKind kind);

fString ffz_node_kind_to_op_string(ffzNodeKind kind);

// ffz_parse_scope is for parsing i.e. a source code file that has multiple nodes in it, whereas
// ffz_parse_node is for parsing a single node.
fOpt(ffzError*) ffz_parse_scope(ffzModule* m, fString file_contents, fString file_path, ffzParseResult* out_result);
fOpt(ffzError*) ffz_parse_node(ffzModule* m, fString file_contents, fString file_path, ffzParseResult* out_result);

void ffz_skip_standalone_tags(fOpt(ffzNode*)* node);

void ffz_print_ast(fWriter* w, ffzNode* node);
fString ffz_node_to_string(ffzProject* p, ffzNode* node, bool try_to_use_source, fAllocator* alc);

// ------------------------------------------------------

ffzType* ffz_type_type();

// TODO: make the following types not require passing the project
ffzType* ffz_type_u8(ffzProject* p);
ffzType* ffz_type_u16(ffzProject* p);
ffzType* ffz_type_u32(ffzProject* p);
ffzType* ffz_type_u64(ffzProject* p);
ffzType* ffz_type_s8(ffzProject* p);
ffzType* ffz_type_s16(ffzProject* p);
ffzType* ffz_type_s32(ffzProject* p);
ffzType* ffz_type_s64(ffzProject* p);
ffzType* ffz_type_uint(ffzProject* p);
ffzType* ffz_type_int(ffzProject* p);
ffzType* ffz_type_bool(ffzProject* p);
ffzType* ffz_type_raw(ffzProject* p);

ffzType* ffz_type_string(ffzProject* p);

// tag-types
ffzType* ffz_type_extern(ffzProject* p);
ffzType* ffz_type_using(ffzProject* p);
ffzType* ffz_type_global(ffzProject* p);
ffzType* ffz_type_module_defined_entry(ffzProject* p);
ffzType* ffz_type_build_option(ffzProject* p);


//void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline);

//bool ffz_parse_and_check_directory(ffzProject* p, fString directory);

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

//uint32_t ffz_get_encoded_constant_size(ffzType* type);
//ffzConstant ffz_constant_array_get_elem(ffzConstant constant, uint32_t index);

// a type is grounded when a runtime variable may have that type.
inline bool ffz_type_is_concrete(ffzType* type) { return type->is_concrete.x; }

bool ffz_type_is_comparable_for_equality(ffzType* type); // supports ==, !=
bool ffz_type_is_comparable(ffzType* type); // supports <, >, et al.

fString ffz_type_to_string(ffzType* type, fAllocator* alc);
//char* ffz_type_to_cstring(ffzProject* p, ffzType* type);

fString ffz_constant_to_string(ffzProject* p, ffzValue constant);
//char* ffz_constant_to_cstring(ffzProject* p, ffzConstantData* constant, ffzType* type);

ffzNode* ffz_constant_to_node(ffzModule* m, ffzValue constant);

ffzNode* ffz_type_to_node(ffzModule* m, ffzType* type);

//ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value);
//ffzNodeHash ffz_hash_node(ffzNode* node);
//ffzExpressionHash ffz_hash_expression(ffzNode* node);
//u64 ffz_hash_declaration_path(ffzDefinitionPath path);
//ffzMemberHash ffz_hash_member(ffzType* type, fString member_name);
//ffzConstantHash ffz_hash_constant(ffzCheckedInst constant);

// -- High level compiler API --------------------------------------------------------------

ffzProject* ffz_init_project(fArena* arena);

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
// D. Tool to rename an identifier - get the identifier at line+column and rename all references to that identifier.
//    It'd be cool to be able to quickly write code-modifying tools like this. It'd be nice if the code was preserved
//    perfectly otherwise when AST printing (comments, whitespace, underscores in numeric literals, etc)
// 
// Now something that requires some polymorphism!
// E. find all casts that cast from u16 -> u8 and insert a runtime if-check that traps if the
//    value doesn't fit.
// 
//

ffzModule* ffz_new_module(ffzProject* p, fAllocator* alc);

//ffzParser* ffz_module_add_parser(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb);

// Parses the source code immediately, returning true if success.
// `filepath` is otherwise ignored, but it's passed down to the error callback.
//bool ffz_module_add_code_string(ffzModule* m, fString code, fString filepath, ffzErrorCallback error_cb);

// The node must be a top-level node and have it's parent field set to NULL.
void ffz_module_add_top_level_node_(ffzModule* m, ffzNode* node);

fOpt(ffzError*) ffz_module_resolve_imports_(ffzModule* m, ffzModule* (*module_from_path)(fString path, void* userdata), void* userdata);

/*
 `module_from_import` should return the fully-checked module imported by an import node.
*/
fOpt(ffzError*) ffz_check_module(ffzModule* mod, fOpt(ffzModule*)(*module_from_import)(ffzModule*, ffzNode*), fAllocator* alc);


// --- OS layer helpers ---
// hmm, at least for now, let's try to keep the filesystem completely away from the FFZ library itself.

// ---

// we could give you a flat array of all the types in your program
// - and procedures
// - and standalone tags

ffzType* ffz_make_type_ptr(ffzProject* p, ffzType* pointer_to);
ffzType* ffz_make_type_slice(ffzProject* p, ffzType* elem_type);
ffzType* ffz_make_type_fixed_array(ffzProject* p, ffzType* elem_type, ffzValue length); // TODO: replace `length` here with an uint

inline ffzValue ffz_type_as_val(ffzType* type) { ffzValue c = {ffz_type_type(), (ffzDatum*)type}; return c; }

//ffzValue ffz_make_val_ptr_to(ffzProject* p)
ffzValue ffz_val_ptr_as_int(ffzProject* p, u64 value, ffzType* type);

ffzValue ffz_val_u8(ffzProject* p, u8 value);
ffzValue ffz_val_u16(ffzProject* p, u16 value);
ffzValue ffz_val_u32(ffzProject* p, u32 value);
ffzValue ffz_val_u64(ffzProject* p, u64 value);
ffzValue ffz_val_s8(ffzProject* p, s8 value);
ffzValue ffz_val_s16(ffzProject* p, s16 value);
ffzValue ffz_val_s32(ffzProject* p, s32 value);
ffzValue ffz_val_s64(ffzProject* p, s64 value);
ffzValue ffz_val_uint(ffzProject* p, u64 value);
ffzValue ffz_val_int(ffzProject* p, s64 value);

// NOTE: the value must be null-terminated (length shouldn't include null termination)!!
ffzValue ffz_val_string(ffzProject* p, fString value);

bool ffz_default_value_of_type(ffzProject* p, ffzType* type, ffzValue* out_val);

// -- Accessing data cached by the checker ------------------------------------------------------

// When calling any of the following functions, any modules that the parameters might be referring to must have been already checked.

inline ffzModuleChecker* ffz_get_checker(ffzNode* node) {
	f_assert(node->_module->checker != NULL); return node->_module->checker;
}

bool ffz_checked_has_info(ffzNode* node);
ffzCheckInfo ffz_checked_get_info(ffzNode* node);

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out);

// Find the field that is tagged @using and has type []T or [N]T. Returns true if exactly one such field is found.
// e.g. with `struct{a: int, @using b: []int}`, the field `b` would be returned.
// This functionality is mainly there to make it possible to create custom array types that support the subscript operator.
// Currently, this does not do a recursive search (i.e. it won't detect a field that is inside another field with @using.)
bool ffz_find_subscriptable_base_type(ffzType* type, ffzTypeRecordFieldUse* out);

// "definition" is the identifier of a value that defines the name of the value.
// e.g. in `foo: int`, the foo identifier would be a definition.
fOpt(ffzNodeIdentifier*) ffz_find_definition(ffzNodeIdentifier* ident);

bool ffz_find_field_by_name(fSlice(ffzField) fields, fString name, uint32_t* out_index);

/*
 Return the name of an import declaration, given an imported module.
    e.g. if module `m` contains `#Foo: import("imported_module")`, then the returned value would be "Foo"
 If `imported_module` is not imported by `m`, an empty string is returned.
*/
fString ffz_get_import_name(ffzModule* m, ffzModule* imported_module);

/*
 Given an argument list (either a post-curly-brackets initializer or a procedure call) that might contain
 both unnamed as well as named arguments, this procedure will give the arguments
 in a flat list in the same order as the `fields` array. Note that some arguments might not exist -
 those elements will be set to NULL.
*/
void ffz_get_arguments_flat(ffzNode* arg_list, fSlice(ffzField) fields, fSlice(fOpt(ffzNode*))* out_arguments, fAllocator* alc);

inline ffzValue ffz_val(ffzType* type, ffzDatum* data) { ffzValue c = {type, data}; return c; }

//ffzConstantData* ffz_zero_value_constant();

bool ffz_node_is_polymorphic(ffzNode* node);

inline fString ffz_decl_get_name(ffzNodeOpDeclare* decl) { return decl->Op.left->Identifier.name; }

bool ffz_checked_decl_is_local_variable(ffzNodeOpDeclare* decl);
bool ffz_decl_is_global_variable(ffzNodeOpDeclare* decl);
inline bool ffz_decl_is_parameter(ffzNodeOpDeclare* decl) { return decl->parent != NULL && decl->parent->kind == ffzNodeKind_ProcType; }

inline bool ffz_checked_decl_is_variable(ffzNodeOpDeclare* decl) {
	return ffz_decl_is_parameter(decl) || ffz_decl_is_global_variable(decl) || ffz_checked_decl_is_local_variable(decl);
}

bool ffz_default_value_of_type(ffzProject* p, ffzType* type, ffzValue* out_val);

/*
* With procedure calls, it seems easy to get the target procedure of a call, i.e. `print` in `print("Hi")` - just take the
  left-hand side child node! However, it's not as easy as that, because you might be implicitly calling a polymorphic procedure.
  To solve this, you can use `ffz_call_get_target_procedure`, which always gives you the instantiated procedure node of a call.
* Returns NULL if the left side is not constant.
*/
fOpt(ffzNode*) ffz_call_get_constant_target_procedure(ffzNode* call);

fOpt(ffzNode*) ffz_checked_this_dot_get_assignee(ffzNodeThisValueDot* dot);

fOpt(ffzDatum*) ffz_checked_get_tag(ffzNode* node, ffzType* tag_type);


#ifdef __cplusplus
} // extern "C"
#endif