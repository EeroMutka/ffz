//
// ffz_ast is a submodule within ffz that does not depend on anything else.
// It contains code to parse source code into an abstract syntax tree representation,
// and utilities for dealing with the tree.
//

#define F_MINIMAL_INCLUDE
#include "foundation/foundation.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef u32 ffzParserID;
typedef u32 ffzParserLocalID;
typedef u32 ffzCheckerID;
typedef u32 ffzCheckerLocalID;

typedef struct ffzNode ffzNode;

typedef struct ffzOk { bool ok; } ffzOk;
const static ffzOk FFZ_OK = { true };

typedef enum ffzNodeKind { // synced with `ffzNodeKind_to_string`
	ffzNodeKind_INVALID,

	ffzNodeKind_Blank,

	ffzNodeKind_Identifier,
	ffzNodeKind_PolyParamList,
	ffzNodeKind_Keyword,
	ffzNodeKind_ThisValueDot,
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

typedef u8 ffzNodeFlags;
enum {
	ffzNodeFlag_IsStandaloneTag = 1 << 0,
};

// TODO: remove this too
typedef enum ffzKeyword { // synced with `ffzKeyword_to_string`
	ffzKeyword_INVALID,
	
	ffzKeyword_Underscore,
	ffzKeyword_QuestionMark,
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
	ffzKeyword_FIRST_EXTENDED,
	ffzKeyword_extern = ffzKeyword_FIRST_EXTENDED,
	ffzKeyword_using,
	ffzKeyword_global,
	ffzKeyword_module_defined_entry,

	ffzKeyword_COUNT,
} ffzKeyword;

typedef struct ffzLoc {
	u32 line_num; // As in text files, starts at 1
	u32 column_num;
	u32 offset;
} ffzLoc;

typedef struct ffzLocRange {
	ffzLoc start;
	ffzLoc end;
} ffzLocRange;

typedef union ffzParserRelID {
	struct {
		ffzParserID parser_id;
		ffzParserLocalID local_id;
	};
	u64 global_id;
} ffzParserRelID;

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
typedef ffzNode ffzNodeScope;
typedef ffzNode ffzNodeThisValueDot;
typedef ffzNode ffzNodeBlank;
typedef ffzNode ffzNodeIntLiteral;
typedef ffzNode ffzNodePolyParamList;

struct ffzNode {
	ffzNodeKind kind;
	ffzNodeFlags flags;
	ffzParserRelID id;
	ffzLocRange loc;
	ffzNode* first_tag;
	ffzNode* parent;
	ffzNode* next;
	ffzNode* first_child;

	union {
		struct {
			fString name;
			bool is_constant; // has # in front? ... maybe this field should be removed and just be stored in the StmtTargets
		} Identifier; // maybe we should just call this "Name" or "Ident"?

		struct { ffzKeyword keyword; } Keyword;

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
			ffzNode* header_stmts[3];
			ffzNode* scope; // hmm... maybe we don't even need a separate scope node?
		} For;

		struct {
			fOpt(ffzNodePolyParamList*) polymorphic_parameters;
			fOpt(ffzNode*) out_parameter;
		} ProcType;
		
		struct {
			fOpt(ffzNodePolyParamList*) polymorphic_parameters;
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
			u64 value;
			u8 was_encoded_in_base; // this is mainly here for if you want to print the AST
		} IntLiteral;
		
		struct {
			fString zero_terminated_string;
		} StringLiteral;
	};
};

typedef fMap64(ffzKeyword) KeywordFromStringMap; // key: f_hash64_str(str);

typedef struct ffzProject ffzProject;
typedef struct ffzChecker ffzChecker;

// Parser is responsible for parsing a single file / string of source code
typedef struct ffzParser ffzParser;
struct ffzParser {
	ffzProject* project;     // unused in the parser stage
	ffzChecker* checker;     // unused in the parser stage
	ffzParserID id;          // this index will be saved into the generated AstNode structures
	
	KeywordFromStringMap* keyword_from_string;

	fString source_code;
	fString source_code_filepath; // The filepath is displayed in error messages, but not used anywhere else.

	ffzNodeScope* root;
	fAllocator* alc;
	ffzParserLocalID next_local_id;

	fArray(ffzNodeKeyword*) module_imports;

	bool stop_at_curly_brackets;
	//ffzLoc pos;

	void(*report_error)(ffzParser* parser, ffzLocRange at, fString error);
};

//#define FFZ_AS(node,kind) ((ffzNode##kind*)node)
//#define FFZ_(ffzNode*)node ((ffzNode*)node)

#define FFZ_EACH_CHILD(n, parent) (ffzNode* n = (parent) ? parent->first_child : NULL; n = ffz_skip_standalone_tags(n); n = n->next)

#ifdef __cplusplus
#define FFZ_STRUCT_INIT(type) type
#else
#define FFZ_STRUCT_INIT(type) (type)
#endif

inline ffzLocRange ffz_loc_to_range(ffzLoc loc) { return FFZ_STRUCT_INIT(ffzLocRange) { loc, loc }; };
inline ffzLoc ffz_loc_min(ffzLoc a, ffzLoc b) { return a.offset < b.offset ? a : b; }
inline ffzLoc ffz_loc_max(ffzLoc a, ffzLoc b) { return a.offset > b.offset ? a : b; }
inline ffzLocRange ffz_loc_range_union(ffzLocRange a, ffzLocRange b) {
	return FFZ_STRUCT_INIT(ffzLocRange) { ffz_loc_min(a.start, b.start), ffz_loc_max(a.end, b.end) };
}

inline bool ffz_keyword_is_bitwise_op(ffzKeyword keyword) { return keyword >= ffzKeyword_bit_and && keyword <= ffzKeyword_bit_not; }
inline bool ffz_keyword_is_extended(ffzKeyword keyword) { return keyword >= ffzKeyword_FIRST_EXTENDED; }

inline bool ffz_node_is_operator(ffzNodeKind kind) { return kind >= ffzNodeKind_Declare && kind <= ffzNodeKind_Dereference; }
inline bool ffz_op_is_prefix(ffzNodeKind kind) { return kind >= ffzNodeKind_PreSquareBrackets && kind <= ffzNodeKind_LogicalNOT; }
//inline bool ffz_op_is_infix(ffzNodeKind kind) { F_BP; return false; } // { return kind >= ffzNodeKind_PreSquareBrackets && kind <= ffzNodeKind_LogicalNOT; }
inline bool ffz_op_is_postfix(ffzNodeKind kind) { return kind >= ffzNodeKind_PostSquareBrackets && kind <= ffzNodeKind_Dereference; }
inline bool ffz_op_is_comparison(ffzNodeKind kind) { return kind >= ffzNodeKind_Equal && kind <= ffzNodeKind_GreaterOrEqual; }
//inline bool ffz_operator_is_arithmetic(ffzNodeKind kind) { return kind >= ffzNodeKind_Add && kind <= ffzNodeKind_Modulo; }

// 0 is returned if not a bracket operator
u8 ffz_get_bracket_op_open_char(ffzNodeKind kind);
u8 ffz_get_bracket_op_close_char(ffzNodeKind kind);

//fOpt(ffzNode*) ffz_get_compiler_tag_by_name(ffzNode* node, fString tag);
//fOpt(ffzNode*) ffz_get_tag_by_name(ffzNode* node, fString tag);

//u32 ffz_poly_parameter_get_index(ffzNode* node);
//u32 ffz_parameter_get_index(ffzNode* node);
//u32 ffz_operator_child_get_index(ffzNode* node);
//u32 ffz_enum_child_get_index(ffzNode* node);
//u32 ffz_scope_child_get_index(ffzNode* node);

// should we flatten it so we can talk about ffzNodeDeclarations?

fString ffz_get_parent_decl_name(fOpt(ffzNode*) node); // returns an empty string if the node's parent is not a declaration, or the node itself is NULL


u32 ffz_get_child_index(ffzNode* child); // will assert if child is not part of its parent
ffzNode* ffz_get_child(ffzNode* parent, u32 idx);
u32 ffz_get_child_count(fOpt(ffzNode*) parent); // returns 0 if parent is NULL

//ffzToken ffz_token_from_node(ffzParser* parser, ffzNode* node);
u32 ffz_operator_get_precedence(ffzNodeKind kind);

fString ffz_keyword_to_string(ffzKeyword keyword);
//char* ffz_keyword_to_cstring(ffzKeyword keyword);

fString ffz_node_kind_to_string(ffzNodeKind kind);
//char* ffz_node_kind_to_cstring(ffzNodeKind kind);

fString ffz_node_kind_to_op_string(ffzNodeKind kind);
//char* ffz_node_kind_to_op_cstring(ffzNodeKind kind);


ffzOk ffz_parse(ffzParser* p);

fOpt(ffzNode*) ffz_skip_standalone_tags(fOpt(ffzNode*) node);

void ffz_print_ast(fWriter* w, ffzNode* node);

#ifdef __cplusplus
} // extern "C"
#endif