//
// ffz_ast is a submodule within ffz that does not depend on anything else.
// It contains code to parse source code into an abstract syntax tree representation,
// and utilities for dealing with the tree.
//

#ifdef __cplusplus
extern "C" {
#endif

typedef u32 ffzParserID;
typedef u32 ffzParserLocalID;
typedef u32 ffzCheckerID;
typedef u32 ffzCheckerLocalID;

typedef union ffzNode ffzNode;

typedef struct ffzOk { bool ok; } ffzOk;

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


typedef enum ffzKeyword { // synced with `ffz_keyword_to_string`
	ffzKeyword_Invalid,
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

typedef struct ffzNodeList {
	ffzNode* first; // can be NULL
} ffzNodeList;

typedef struct ffzLoc {
	u32 line_num; // As in text files, starts at 1
	u32 column_num;
	u32 offset;
} ffzLoc;

typedef struct ffzLocRange {
	ffzLoc start;
	ffzLoc end;
} ffzLocRange;

typedef struct ffzNodeAssignment ffzNodeAssignment;
typedef struct ffzNodeTag ffzNodeTag;
typedef struct ffzNodeTagDecl ffzNodeTagDecl;
typedef struct ffzNodeIdentifier ffzNodeIdentifier;
typedef struct ffzNodeKeyword ffzNodeKeyword;
typedef struct ffzNodeOperator ffzNodeOperator;
typedef struct ffzNodeIf ffzNodeIf;
typedef struct ffzNodeFor ffzNodeFor;
typedef struct ffzNodeProcType ffzNodeProcType;
typedef struct ffzNodeRecord ffzNodeRecord;
typedef struct ffzNodeEnum ffzNodeEnum;
typedef struct ffzNodeScope ffzNodeScope;
typedef struct ffzNodeReturn ffzNodeReturn;
typedef struct ffzNodeIntLiteral ffzNodeIntLiteral;
typedef struct ffzNodeStringLiteral ffzNodeStringLiteral;

typedef union ffzParserRelID {
	struct {
		ffzParserID parser_id;
		ffzParserLocalID local_id;
	};
	u64 global_id;
} ffzParserRelID;

#define FFZ_NODE_BASE struct { \
ffzNodeKind kind; \
ffzParserRelID id; \
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
	fString tag;
	// TODO: tag argument? it should be able to hold an arbitrary AST tree inside
} ffzNodeTag;

typedef struct ffzNodeTagDecl {
	FFZ_NODE_BASE;
	fString tag;
	ffzNode* rhs;

	ffzNodeTagDecl* same_tag_next;
} ffzNodeTagDecl;

typedef struct ffzNodeIdentifier {
	FFZ_NODE_BASE;
	fString name;
	bool is_constant; // has # in front? ... maybe this field should be removed and just be stored in the StmtTargets
} ffzNodeIdentifier;

typedef struct ffzNodeKeyword {
	FFZ_NODE_BASE;
	ffzKeyword keyword;
} ffzNodeKeyword;

typedef struct ffzNodeOperator {
	FFZ_NODE_BASE; // if this is a post/pre-scope-op, the nodes inside the scope are stored in `children`
	ffzOperatorKind op_kind;

	fOpt(ffzNode*) left;
	fOpt(ffzNode*) right;
} ffzNodeOperator;

typedef struct ffzNodeIf {
	FFZ_NODE_BASE;
	ffzNode* condition;
	ffzNode* true_scope;
	fOpt(ffzNode*) else_scope;
} ffzNodeIf;

typedef struct ffzNodeFor {
	FFZ_NODE_BASE;
	ffzNode* header_stmts[3];
	ffzNode* scope; // hmm... maybe we don't even need a separate scope node?
} ffzNodeFor;

typedef struct ffzNodePolyParamList { FFZ_NODE_BASE; } ffzNodePolyParamList;

typedef struct ffzNodeProcType {
	FFZ_NODE_BASE; // the input parameters are encoded in `children`
	fOpt(ffzNodePolyParamList*) polymorphic_parameters;
	fOpt(ffzNode*) out_parameter;
} ffzNodeProcType;

typedef struct ffzNodeRecord {
	FFZ_NODE_BASE; // the struct fields are encoded in `children`
	fOpt(ffzNodePolyParamList*) polymorphic_parameters;
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
	fOpt(ffzNode*) value;
} ffzNodeReturn;

typedef struct ffzNodeIntLiteral {
	FFZ_NODE_BASE;
	u64 value;
	u8 was_encoded_in_base; // this is mainly here for if you want to print the AST
} ffzNodeIntLiteral;

typedef struct ffzNodeStringLiteral {
	FFZ_NODE_BASE;
	fString zero_terminated_string;
} ffzNodeStringLiteral;

union ffzNode {
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
};

// synced with `ffzNodeKind`
static const fString ffzNodeKind_String[] = {
	F_LIT_COMP("invalid"),
	F_LIT_COMP("blank"),
	F_LIT_COMP("compiler-tag-declaration"),
	F_LIT_COMP("user-tag-declaration"),
	F_LIT_COMP("compiler-tag"),
	F_LIT_COMP("user-tag"),
	F_LIT_COMP("declaration"),
	F_LIT_COMP("assignment"),
	F_LIT_COMP("identifier"),
	F_LIT_COMP("polymorphic-parameter"),
	F_LIT_COMP("keyword"),
	F_LIT_COMP("dot"),
	F_LIT_COMP("operator"),
	F_LIT_COMP("proc-type"),
	F_LIT_COMP("struct"),
	F_LIT_COMP("enum"),
	F_LIT_COMP("return"),
	F_LIT_COMP("if"),
	F_LIT_COMP("for"),
	F_LIT_COMP("scope"),
	F_LIT_COMP("int-literal"),
	F_LIT_COMP("string-literal"),
	F_LIT_COMP("float-literal"),
};

const static fString ffz_keyword_to_string[] = { // synced with `ffzKeyword`
	{0},
	F_LIT_COMP("_"),
	F_LIT_COMP("?"),
	F_LIT_COMP("dbgbreak"),
	F_LIT_COMP("size_of"),
	F_LIT_COMP("align_of"),
	F_LIT_COMP("import"),
	F_LIT_COMP("true"),
	F_LIT_COMP("false"),
	F_LIT_COMP("u8"),
	F_LIT_COMP("u16"),
	F_LIT_COMP("u32"),
	F_LIT_COMP("u64"),
	F_LIT_COMP("s8"),
	F_LIT_COMP("s16"),
	F_LIT_COMP("s32"),
	F_LIT_COMP("s64"),
	F_LIT_COMP("int"),
	F_LIT_COMP("uint"),
	F_LIT_COMP("bool"),
	F_LIT_COMP("raw"),
	F_LIT_COMP("string"),
	F_LIT_COMP("bit_and"),
	F_LIT_COMP("bit_or"),
	F_LIT_COMP("bit_xor"),
	F_LIT_COMP("bit_shl"),
	F_LIT_COMP("bit_shr"),
	F_LIT_COMP("bit_not"),
};

typedef struct ffzProject ffzProject;
typedef struct ffzChecker ffzChecker;

// Parser is responsible for parsing a single file / string of source code
typedef struct ffzParser ffzParser;
struct ffzParser {
	ffzProject* project;     // unused in the parser stage
	ffzChecker* checker;     // unused in the parser stage
	ffzParserID id;          // this index will be saved into the generated AstNode structures

	fString source_code;
	fString source_code_filepath; // The filepath is displayed in error messages, but not used anywhere else.

	ffzNodeScope* root;
	fAllocator* alc;
	ffzParserLocalID next_local_id;

	fArray(ffzNodeKeyword*) module_imports;
	fMap64(ffzNodeTagDecl*) tag_decl_lists; // key: str_hash64(tag, 0)

	bool stop_at_curly_brackets;
	ffzLoc pos;

	void(*report_error)(ffzParser* parser, ffzLocRange at, fString error);
};

#define FFZ_AS(node,kind) ((ffzNode##kind*)node)
#define FFZ_BASE(node) ((ffzNode*)node)

#define FFZ_EACH_CHILD(n, parent) (ffzNode* n = (parent) ? FFZ_BASE(parent)->children.first : NULL; n = ffz_skip_tag_decls(n); n = n->next)

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

inline bool ffz_op_is_pre_unary(ffzOperatorKind kind) { return kind >= ffzOperatorKind_UnaryMinus && kind <= ffzOperatorKind_LogicalNOT; }
inline bool ffz_op_is_post_unary(ffzOperatorKind kind) { return kind == ffzOperatorKind_Dereference; }
inline bool ffz_op_is_comparison(ffzOperatorKind kind) { return kind >= ffzOperatorKind_Equal && kind <= ffzOperatorKind_GreaterOrEqual; }
//inline bool ffz_op_is_shift(ffzOperatorKind kind) { return kind == ffzOperatorKind_ShiftL || kind == ffzOperatorKind_ShiftR; }
inline bool ffz_op_is_arithmetic(ffzOperatorKind kind) { return kind >= ffzOperatorKind_Add && kind <= ffzOperatorKind_Modulo; }

fOpt(ffzNodeTag*) ffz_node_get_compiler_tag(ffzNode* node, fString tag);
fOpt(ffzNodeTag*) ffz_node_get_user_tag(ffzNode* node, fString tag);

//u32 ffz_poly_parameter_get_index(ffzNode* node);
//u32 ffz_parameter_get_index(ffzNode* node);
//u32 ffz_operator_child_get_index(ffzNode* node);
//u32 ffz_enum_child_get_index(ffzNode* node);
//u32 ffz_scope_child_get_index(ffzNode* node);

fOpt(ffzNodeDeclaration*) ffz_get_parent_decl(fOpt(ffzNode*) node); // returns NULL if node->parent is not a declaration, or the node itself is NULL
fString ffz_get_parent_decl_name(fOpt(ffzNode*) node); // returns an empty string if the node's parent is not a declaration, or the node itself is NULL

u32 ffz_get_child_index(ffzNode* child); // will assert if child is not part of its parent
ffzNode* ffz_get_child(ffzNode* parent, u32 idx);
u32 ffz_get_child_count(fOpt(ffzNode*) parent); // returns 0 if parent is NULL

//ffzToken ffz_token_from_node(ffzParser* parser, ffzNode* node);

fString ffz_node_kind_to_string(ffzNodeKind kind);
const char* ffz_node_kind_to_cstring(ffzNodeKind kind);

ffzOk ffz_parse(ffzParser* p);

fOpt(ffzNode*) ffz_skip_tag_decls(fOpt(ffzNode*) node);

fString ffz_print_ast(fAllocator* alc, ffzNode* node);

#ifdef __cplusplus
} // extern "C"
#endif