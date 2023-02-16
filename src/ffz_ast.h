//
// ffz_ast is a submodule within ffz that does not depend on anything else.
// It contains code to parse source code into an abstract syntax tree representation,
// and utilities for dealing with the tree.
//

struct ffzProject;
union ffzNode;
typedef u32 ffzParserIndex;
typedef u32 ffzCheckerIndex;

struct ffzOk { bool ok; };

typedef enum ffzNodeKind { // synced with `ffzNodeKind_String`
	ffzNodeKind_Invalid,

	// CompilerTagDecls and UserTagDecls are skipped by skip_tag_decls()
	ffzNodeKind_Blank,
	ffzNodeKind_CompilerTagDecl,
	ffzNodeKind_UserTagDecl,

	ffzNodeKind_CompilerTag,
	ffzNodeKind_UserTag,

	ffzNodeKind_Declaration,
	ffzNodeKind_Assignment,
	ffzNodeKind_Identifier,
	ffzNodeKind_PolyParamList,
	ffzNodeKind_Keyword,
	ffzNodeKind_Dot,
	ffzNodeKind_Operator,
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
	
	ffzNodeKind_COUNT,
} ffzNodeKind;

typedef enum ffzKeyword { // synced with `KeywordKind_String`
	ffzKeyword_Invalid,
	ffzKeyword_Underscore, // TODO: remove this? and replace with _Blank
	ffzKeyword_QuestionMark,
	ffzKeyword_dbgbreak,
	ffzKeyword_size_of,
	ffzKeyword_import,
	// TODO: offset_of?
	// TODO: align_of?

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
	ffzKeyword_int,
	ffzKeyword_uint,
	ffzKeyword_bool,
	ffzKeyword_string,

	// :ffz_keyword_is_bitwise_op
	ffzKeyword_bit_and,
	ffzKeyword_bit_or,
	ffzKeyword_bit_xor,
	ffzKeyword_bit_not,
} ffzKeyword;

typedef enum ffzOperatorKind { // synced with ffzOperatorKind_String
	ffzOperatorKind_Invalid = 0,

	// :OperatorIsArithmetic
	ffzOperatorKind_Add,
	ffzOperatorKind_Sub,
	ffzOperatorKind_Mul,
	ffzOperatorKind_Div,
	ffzOperatorKind_Modulo,

	ffzOperatorKind_MemberAccess, // the . operator

	// :OperatorIsComparison
	ffzOperatorKind_Equal,
	ffzOperatorKind_NotEqual,
	ffzOperatorKind_Less,
	ffzOperatorKind_LessOrEqual,
	ffzOperatorKind_Greater,
	ffzOperatorKind_GreaterOrEqual,

	ffzOperatorKind_PreSquareBrackets,
	ffzOperatorKind_PostRoundBrackets,
	ffzOperatorKind_PostSquareBrackets,
	ffzOperatorKind_PostCurlyBrackets,

	ffzOperatorKind_ShiftL, // maybe we should make bit-shifts like function-calls, the same way as bit_or/bit_and? bit_shl()/bit_shr()?
	ffzOperatorKind_ShiftR,

	ffzOperatorKind_LogicalAND,
	ffzOperatorKind_LogicalOR,

	// :OperatorIsPreUnary
	ffzOperatorKind_UnaryMinus,
	ffzOperatorKind_UnaryPlus,
	ffzOperatorKind_UnaryMemberAccess,
	ffzOperatorKind_AddressOf,
	ffzOperatorKind_PointerTo,
	ffzOperatorKind_LogicalNOT,

	// :OperatorIsPostUnary
	ffzOperatorKind_Dereference,

	ffzOperatorKind_Count,
} ffzOperatorKind;

struct ffzLoc {
	u32 line_num; // As in text files, starts at 1
	u32 column_num;
	u32 offset;
};

typedef struct {
	ffzLoc start;
	ffzLoc end;
} ffzLocRange;

typedef struct ffzNodeList {
	ffzNode* first; // can be NULL
} ffzNodeList;

struct ffzNodeAssignment;
struct ffzNodeTag;
struct ffzNodeTagDecl;
struct ffzNodeIdentifier;
struct ffzNodeKeyword;
struct ffzNodeOperator;
struct ffzNodeIf;
struct ffzNodeFor;
struct ffzNodeProcType;
struct ffzNodeRecord;
struct ffzNodeEnum;
struct ffzNodeScope;
struct ffzNodeReturn;
struct ffzNodeIntLiteral;
struct ffzNodeStringLiteral;

#define FFZ_NODE_BASE struct {\
	ffzNodeKind kind;\
	ffzParserIndex parser_idx;\
	ffzLocRange loc;\
	ffzNodeTag* first_tag;\
	ffzNode* parent;\
	ffzNode* next;\
	ffzNodeList children;\
}

typedef struct ffzNodeAssignment {
	FFZ_NODE_BASE;
	ffzNode* lhs;
	ffzNode* rhs;
} ffzNodeTargeted;

typedef struct ffzNodeDeclaration {
	FFZ_NODE_BASE;
	ffzNodeIdentifier* name; // TODO: rename this to "definition"?
	ffzNode* rhs;
} ffzNodeDeclaration;

typedef struct ffzNodeTag {
	FFZ_NODE_BASE;
	String tag;
	// TODO: tag argument? it should be able to hold an arbitrary AST tree inside
} ffzNodeTag;

typedef struct ffzNodeTagDecl {
	FFZ_NODE_BASE;
	String tag;
	ffzNode* rhs;
	
	ffzNodeTagDecl* same_tag_next;
} ffzNodeTagDecl;

typedef struct ffzNodeIdentifier {
	FFZ_NODE_BASE;
	String name;
	bool is_constant; // has # in front? ... maybe this field should be removed and just be stored in the StmtTargets
} ffzNodeIdentifier;

typedef struct ffzNodeKeyword {
	FFZ_NODE_BASE;
	ffzKeyword keyword;
} ffzNodeKeyword;

typedef struct ffzNodeOperator {
	FFZ_NODE_BASE; // if this is a post/pre-scope-op, the nodes inside the scope are stored in `children`
	ffzOperatorKind op_kind;

	OPT(ffzNode*) left;
	OPT(ffzNode*) right;
} ffzNodeOperator;

typedef struct ffzNodeIf {
	FFZ_NODE_BASE;
	ffzNode* condition;
	ffzNode* true_scope;
	OPT(ffzNode*) else_scope;
} ffzNodeIf;

typedef struct ffzNodeFor {
	FFZ_NODE_BASE;
	ffzNode* header_stmts[3];
	ffzNode* scope; // hmm... maybe we don't even need a separate scope node?
} ffzNodeFor;

typedef struct ffzNodePolyParamList { FFZ_NODE_BASE; } ffzNodePolyParamList;

typedef struct ffzNodeProcType {
	FFZ_NODE_BASE; // the input parameters are encoded in `children`
	OPT(ffzNodePolyParamList*) polymorphic_parameters;
	OPT(ffzNode*) out_parameter;
} ffzNodeProcType;

typedef struct ffzNodeRecord {
	FFZ_NODE_BASE; // the struct fields are encoded in `children`
	OPT(ffzNodePolyParamList*) polymorphic_parameters;
	bool is_union;
} ffzNodeRecord;

typedef struct ffzNodeEnum {
	FFZ_NODE_BASE; // the enum fields are encoded in `children`
	ffzNode* internal_type;
} ffzNodeEnum;

typedef struct ffzNodeScope { FFZ_NODE_BASE; } ffzNodeScope;
typedef struct ffzNodeDot { FFZ_NODE_BASE; } ffzNodeDot;
typedef struct ffzNodeBlank { FFZ_NODE_BASE; } ffzNodeBlank;

typedef struct ffzNodeReturn {
	FFZ_NODE_BASE;
	OPT(ffzNode*) value;
} ffzNodeReturn;

typedef struct ffzNodeIntLiteral {
	FFZ_NODE_BASE;
	u64 value;
} ffzNodeIntLiteral;

typedef struct ffzNodeStringLiteral {
	FFZ_NODE_BASE;
	String zero_terminated_string;
} ffzNodeStringLiteral;

typedef union ffzNode {
	FFZ_NODE_BASE;
	ffzNodeAssignment Assignment;
	ffzNodeDeclaration Declaration;
	ffzNodeTag Tag;
	ffzNodeTagDecl TagDecl;
	ffzNodeIdentifier Identifier;
	ffzNodeKeyword Keyword;
	ffzNodeOperator Operator;
	ffzNodeIf If;
	ffzNodeFor For;
	ffzNodePolyParamList PolyParamList;
	ffzNodeProcType ProcType;
	ffzNodeRecord Record;
	ffzNodeEnum Enum;
	ffzNodeReturn Return;
	ffzNodeIntLiteral IntLiteral;
	ffzNodeStringLiteral StringLiteral;
} ffzNode;


// Parser is responsible for parsing a single file / string of source code
typedef struct ffzParser {
	ffzProject* project;         // unused in the parser stage
	ffzParserIndex self_idx;     // this index will be saved into the generated AstNode structures
	ffzCheckerIndex checker_idx; // unused in the parser stage

	String source_code;
	String source_code_filepath; // The filepath is displayed in error messages, but not used anywhere else.

	ffzNodeScope* root;
	Allocator* alc;

	Array<ffzNodeKeyword*> module_imports;
	Map64<ffzNodeTagDecl*> tag_decl_lists; // key: str_hash64(tag, 0)

	bool stop_at_curly_brackets;
	ffzLoc pos;

	void(*report_error)(ffzParser* parser, ffzLocRange at, String error);
} ffzParser;

#define FFZ_AS(node,kind) ((ffzNode##kind*)node)
#define FFZ_BASE(node) ((ffzNode*)node)

#define FFZ_EACH_CHILD(n, parent) (ffzNode* n = (parent) ? FFZ_BASE(parent)->children.first : NULL; n = ffz_skip_tag_decls(n); n = n->next)

inline ffzLocRange ffz_loc_to_range(ffzLoc loc) { return { loc, loc }; };
inline ffzLoc ffz_loc_min(ffzLoc a, ffzLoc b) { return a.offset < b.offset ? a : b; }
inline ffzLoc ffz_loc_max(ffzLoc a, ffzLoc b) { return a.offset > b.offset ? a : b; }
inline ffzLocRange ffz_loc_range_union(ffzLocRange a, ffzLocRange b) {
	return { ffz_loc_min(a.start, b.start), ffz_loc_max(a.end, b.end) };
}

inline bool ffz_keyword_is_bitwise_op(ffzKeyword keyword) { return keyword >= ffzKeyword_bit_and && keyword <= ffzKeyword_bit_not; }

inline bool ffz_op_is_pre_unary(ffzOperatorKind kind) { return kind >= ffzOperatorKind_UnaryMinus && kind <= ffzOperatorKind_LogicalNOT; }
inline bool ffz_op_is_post_unary(ffzOperatorKind kind) { return kind == ffzOperatorKind_Dereference; }
inline bool ffz_op_is_comparison(ffzOperatorKind kind) { return kind >= ffzOperatorKind_Equal && kind <= ffzOperatorKind_GreaterOrEqual; }
inline bool ffz_op_is_shift(ffzOperatorKind kind) { return kind == ffzOperatorKind_ShiftL || kind == ffzOperatorKind_ShiftR; }
inline bool ffz_op_is_arithmetic(ffzOperatorKind kind) { return kind >= ffzOperatorKind_Add && kind <= ffzOperatorKind_Modulo; }

OPT(ffzNodeTag*) ffz_node_get_compiler_tag(ffzNode* node, String tag);
OPT(ffzNodeTag*) ffz_node_get_user_tag(ffzNode* node, String tag);

//u32 ffz_poly_parameter_get_index(ffzNode* node);
//u32 ffz_parameter_get_index(ffzNode* node);
//u32 ffz_operator_child_get_index(ffzNode* node);
//u32 ffz_enum_child_get_index(ffzNode* node);
//u32 ffz_scope_child_get_index(ffzNode* node);

OPT(ffzNodeDeclaration*) ffz_get_parent_decl(OPT(ffzNode*) node); // returns NULL if node->parent is not a declaration, or the node itself is NULL
String ffz_get_parent_decl_name(OPT(ffzNode*) node); // returns an empty string if the node's parent is not a declaration, or the node itself is NULL

u32 ffz_get_child_index(ffzNode* child); // will assert if child is not part of its parent
ffzNode* ffz_get_child(ffzNode* parent, u32 idx);
u32 ffz_get_child_count(OPT(ffzNode*) parent); // returns 0 if parent is NULL

//ffzToken ffz_token_from_node(ffzParser* parser, ffzNode* node);

String ffz_node_kind_to_string(ffzNodeKind kind);
const char* ffz_node_kind_to_cstring(ffzNodeKind kind);

ffzOk ffz_parse(ffzParser* p);

OPT(ffzNode*) ffz_skip_tag_decls(OPT(ffzNode*) node);

String ffz_print_ast(Allocator* alc, ffzNode* node);

