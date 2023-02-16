#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"
#include "ffz_lib.h"

#define TRY(x) { if ((x).ok == false) return ffzOk{false}; }

#define ERR(p, at, fmt, ...) { \
	p->report_error(p, at, str_format(p->alc, fmt, __VA_ARGS__)); \
	return ffzOk{false}; \
}

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

struct Token {
	union {
		struct { ffzLoc start; ffzLoc end; };
		ffzLocRange range;
	};
	String str;
};

// synced with OperatorKind
const String ffzOperatorKind_String[] = {
	LIT(""),

	LIT("+"),
	LIT("-"),
	LIT("*"),
	LIT("/"),
	LIT("%"),

	LIT("."),

	LIT("=="),
	LIT("!="),
	LIT("<"),
	LIT("<="),
	LIT(">"),
	LIT(">="),

	LIT("\0"),
	LIT("\0"),
	LIT("\0"),
	LIT("\0"),

	LIT("<<"),
	LIT(">>"),

	LIT("&&"),
	LIT("||"),

	LIT("-"),
	LIT("+"),
	LIT("."),
	LIT("&"),
	LIT("^"),
	LIT("!"),

	LIT("^"),
};

STATIC_ASSERT(LEN(ffzOperatorKind_String) == ffzOperatorKind_Count);

const String KeywordKind_String[] = { // synced with `KeywordKind`
	{},
	LIT("_"),
	LIT("?"),
	LIT("dbgbreak"),
	LIT("size_of"),
	LIT("import"),
	LIT("true"),
	LIT("false"),
	LIT("u8"),
	LIT("u16"),
	LIT("u32"),
	LIT("u64"),
	LIT("s8"),
	LIT("s16"),
	LIT("s32"),
	LIT("s64"),
	LIT("int"),
	LIT("uint"),
	LIT("bool"),
	LIT("string"),
	LIT("bit_and"),
	LIT("bit_or"),
	LIT("bit_xor"),
	LIT("bit_not"),
	LIT("%"),
};

// synced with `ffzNodeKind`
const String ffzNodeKind_String[] = {
	LIT("[invalid]"),
	LIT("blank"),
	LIT("compiler-tag-declaration"),
	LIT("user-tag-declaration"),
	LIT("compiler-tag"),
	LIT("user-tag"),
	LIT("declaration"),
	LIT("assignment"),
	LIT("identifier"),
	LIT("polymorphic-parameter"),
	LIT("keyword"),
	LIT("dot"),
	LIT("operator"),
	LIT("proc-type"),
	LIT("struct"),
	LIT("enum"),
	LIT("return"),
	LIT("if"),
	LIT("for"),
	LIT("scope"),
	LIT("int-literal"),
	LIT("string-literal"),
	LIT("float-literal"),
}; STATIC_ASSERT(ffzNodeKind_COUNT == LEN(ffzNodeKind_String));

String ffz_node_kind_to_string(ffzNodeKind kind) { return ffzNodeKind_String[kind]; }
const char* ffz_node_kind_to_cstring(ffzNodeKind kind) { return (const char*)ffzNodeKind_String[kind].data; }

// Same as in C https://en.cppreference.com/w/c/language/operator_precedence
static uint op_get_precedence(ffzOperatorKind kind) {
	//if (op == ffzOperatorKind_MemberAccess) return 11;
	if (kind == ffzOperatorKind_Mul || kind == ffzOperatorKind_Div || kind == ffzOperatorKind_Modulo) return 10;
	if (kind == ffzOperatorKind_Add || kind == ffzOperatorKind_Sub) return 9;
	if (kind == ffzOperatorKind_ShiftL || kind == ffzOperatorKind_ShiftR) return 8;
	if (kind == ffzOperatorKind_Less || kind == ffzOperatorKind_LessOrEqual || kind == ffzOperatorKind_Greater || kind == ffzOperatorKind_GreaterOrEqual) return 7;
	if (kind == ffzOperatorKind_Equal || kind == ffzOperatorKind_NotEqual) return 6;
	if (kind == ffzOperatorKind_LogicalAND) return 5;
	if (kind == ffzOperatorKind_LogicalOR) return 4;
	ASSERT(false);
	return 0;
}

static void _print_ast(Array<u8>* builder, ffzNode* node, uint tab_level) {
	Allocator* temp = temp_push();
	if (false) {
		str_print(builder, LIT(" <"));
		str_print(builder, ffzNodeKind_String[node->kind]);
		str_printf(builder, "|%d:%d-%d:%d", node->loc.start.line_num, node->loc.start.column_num, node->loc.end.line_num, node->loc.end.column_num);
			//str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		//str_print(builder, LIT(", line="));
		//str_print(builder, str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		str_print(builder, LIT(">"));
	}
	
	for (ffzNodeTag* tag = node->first_tag; tag; tag = (ffzNodeTag*)tag->next) {
		str_print(builder, tag->kind == ffzNodeKind_CompilerTag ? LIT("@") : LIT("~"));
		str_print(builder, tag->tag);
		str_print(builder, LIT(" "));
	}

	switch (node->kind) {
	case ffzNodeKind_Declaration: {
		_print_ast(builder, AS(node,Targeted)->lhs, tab_level);
		str_print(builder, LIT(": "));
		_print_ast(builder, AS(node,Targeted)->rhs, tab_level);
	} break;

	case ffzNodeKind_Assignment: {
		_print_ast(builder, AS(node, Targeted)->lhs, tab_level);
		str_print(builder, LIT("= "));
		_print_ast(builder, AS(node, Targeted)->rhs, tab_level);
	} break;

	case ffzNodeKind_Keyword: {
		str_print(builder, KeywordKind_String[AS(node,Keyword)->keyword]);
	} break;

	case ffzNodeKind_UserTagDecl: // fallthrough
	case ffzNodeKind_CompilerTagDecl: {
		str_print_il(builder, { LIT("@"), AS(node,TagDecl)->tag, LIT(": ") });
		_print_ast(builder, AS(node,TagDecl)->rhs, tab_level);
	} break;

	case ffzNodeKind_Operator: {
		ffzNodeOperator* op = AS(node,Operator);
		if (op->op_kind == ffzOperatorKind_PostRoundBrackets ||
			op->op_kind == ffzOperatorKind_PostSquareBrackets ||
			op->op_kind == ffzOperatorKind_PostCurlyBrackets)
		{
			_print_ast(builder, op->left, tab_level);

			struct BracketChars { u8 open; u8 close; };
			BracketChars bracket_chars = op->op_kind == ffzOperatorKind_PostRoundBrackets ? BracketChars{ '(', ')' } :
				op->op_kind == ffzOperatorKind_PostSquareBrackets ? BracketChars{ '[', ']' } : BracketChars{ '{','}' };

			bool multi_line = op->op_kind == ffzOperatorKind_PostCurlyBrackets;// node->Operator.arguments.first&& node->Operator.arguments.first->next;
			if (multi_line) {
				str_print(builder, LIT(" "));
				array_push(builder, bracket_chars.open);
				str_print(builder, LIT("\n"));
				for (ffzNode* n = node->children.first; n; n = n->next) {
					str_print_repeat(builder, LIT("\t"), tab_level + 1);
					_print_ast(builder, n, tab_level + 1);
					str_print(builder, LIT("\n"));
				}
				str_print_repeat(builder, LIT("\t"), tab_level);
			}
			else {
				array_push(builder, bracket_chars.open);
				for (ffzNode* n = node->children.first; n; n = n->next) {
					if (n != node->children.first) str_print(builder, LIT(", "));
					_print_ast(builder, n, tab_level + (uint)multi_line);
				}
			}
			array_push(builder, bracket_chars.close);

		}
		else if (op->op_kind == ffzOperatorKind_PreSquareBrackets) {
			array_push(builder, (u8)'[');
			for (ffzNode* n = node->children.first; n; n = n->next) {
				if (n != node->children.first) str_print(builder, LIT(", "));
				_print_ast(builder, n, tab_level);
			}
			array_push(builder, (u8)']');

			_print_ast(builder, op->right, tab_level);
		}
		else if (ffz_op_is_pre_unary(op->op_kind)) {
			str_print(builder, ffzOperatorKind_String[op->op_kind]);
			_print_ast(builder, op->right, tab_level);
		}
		else if (ffz_op_is_post_unary(op->op_kind)) {
			_print_ast(builder, op->left, tab_level);
			str_print(builder, ffzOperatorKind_String[op->op_kind]);
		}
		//else if (node->Operator.op == ffzOperatorKind_MemberAccess) {
		//	PrintAst(builder, node->Operator.left, tab_level);
		//	str_print(builder, LIT("."));
		//	PrintAst(builder, node->Operator.right, tab_level);
		//}
		else {
			str_print(builder, LIT("("));
			_print_ast(builder, op->left, tab_level);

			str_print(builder, LIT(" "));
			str_print(builder, ffzOperatorKind_String[op->op_kind]);
			str_print(builder, LIT(" "));

			_print_ast(builder, op->right, tab_level);
			str_print(builder, LIT(")"));
		}
	} break;

	case ffzNodeKind_Identifier: {
		if (AS(node,Identifier)->is_constant) str_print(builder, LIT("#"));
		str_print(builder, AS(node,Identifier)->name);
	} break;

	case ffzNodeKind_Record: {
		ffzNodeRecord* record = AS(node,Record);
		str_print(builder, record->is_union ? LIT("union") : LIT("struct"));

		if (record->polymorphic_parameters) {
			_print_ast(builder, BASE(record->polymorphic_parameters), tab_level);
		}
		str_print(builder, LIT("{"));
		for (ffzNode* n = node->children.first; n; n = n->next) {
			if (n != node->children.first) str_print(builder, LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		str_print(builder, LIT("}"));
	} break;

	case ffzNodeKind_Enum: {
		str_print(builder, LIT("enum"));
		if (AS(node,Enum)->internal_type) {
			str_print(builder, LIT(", "));
			_print_ast(builder, AS(node,Enum)->internal_type, tab_level);
		}
		str_print(builder, LIT(" {"));
		for (ffzNode* n = node->children.first; n; n = n->next) {
			if (n != node->children.first) str_print(builder, LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		str_print(builder, LIT("}"));
	} break;

	case ffzNodeKind_ProcType: {
		ffzNodeProcType* node_proc = AS(node,ProcType);
		str_print(builder, LIT("proc"));
		
		if (node_proc->polymorphic_parameters) {
			_print_ast(builder, BASE(node_proc->polymorphic_parameters), tab_level);
		}

		if (node->children.first) {
			str_print(builder, LIT("("));
			for (ffzNode* n = node->children.first; n; n = n->next) {
				if (n != node->children.first) str_print(builder, LIT(", "));
				_print_ast(builder, n, tab_level);
			}
			str_print(builder, LIT(")"));
		}

		if (node_proc->out_parameter) {
			str_print(builder, LIT(" => "));
			_print_ast(builder, node_proc->out_parameter, tab_level);
			str_print(builder, LIT(""));
		}

		//str_print(builder, LIT(" {\n"));
		//for (AstNode* n = node->Procedure.nodes.first; n; n = n->next) {
		//	for (int j = 0; j < tab_level + 1; j++) str_print(builder, LIT("    "));
		//	_print_ast(builder, n, tab_level + 1);
		//
		//	str_print(builder, LIT("\n"));
		//}
		//for (int j=0; j< tab_level; j++) str_print(builder, LIT("    "));
		//str_print(builder, LIT("}\n"));

	} break;

	case ffzNodeKind_Return: {
		str_print(builder, LIT("ret"));

		if (AS(node,Return)->value) {
			str_print(builder, LIT(" "));
			_print_ast(builder, AS(node,Return)->value, tab_level);
		}
	} break;

	case ffzNodeKind_Scope: {
		str_print(builder, LIT("{\n"));

		for (ffzNode* n = node->children.first; n; n = n->next) {
			for (int j = 0; j < tab_level + 1; j++) str_print(builder, LIT("    "));
			_print_ast(builder, n, tab_level + 1);

			str_print(builder, LIT("\n"));
		}

		for (int j = 0; j < tab_level; j++) str_print(builder, LIT("    "));
		str_print(builder, LIT("}\n"));
	} break;

	case ffzNodeKind_IntLiteral: {
		str_print(builder, str_from_uint(AS_BYTES(AS(node,IntLiteral)->value), temp));
	} break;

	case ffzNodeKind_StringLiteral: {
		// TODO: print escaped strings
		str_print(builder, LIT("\""));
		str_print(builder, AS(node,StringLiteral)->zero_terminated_string);
		str_print(builder, LIT("\""));
	} break;

	//case ffzNodeKind_FloatLiteral: {
	//	str_print(builder, str_from_float(temp, AS_BYTES(node->Float.value)));
	//} break;

	case ffzNodeKind_If: {
		str_print(builder, LIT("if "));
		_print_ast(builder, AS(node,If)->condition, tab_level);
		str_print(builder, LIT(" "));
		ASSERT(AS(node,If)->true_scope);
		_print_ast(builder, AS(node,If)->true_scope, tab_level);

		if (AS(node,If)->else_scope) {
			for (int j = 0; j < tab_level; j++) str_print(builder, LIT("    "));
			str_print(builder, LIT("else \n"));
			_print_ast(builder, AS(node,If)->else_scope, tab_level);
		}

	} break;

	case ffzNodeKind_For: {
		str_print(builder, LIT("for "));
		for (int i = 0; i < 3; i++) {
			if (AS(node,For)->header_stmts[i]) {
				if (i > 0) str_print(builder, LIT(", "));
				_print_ast(builder, AS(node,For)->header_stmts[i], tab_level);
			}
		}

		str_print(builder, LIT(" "));
		_print_ast(builder, AS(node,For)->scope, tab_level);
	} break;

	case ffzNodeKind_Blank: { str_print(builder, LIT("_")); } break;
	case ffzNodeKind_Dot: { str_print(builder, LIT(".")); } break;

	case ffzNodeKind_PolyParamList: {
		str_print(builder, LIT("["));
		for (ffzNode* n = node->children.first; n; n = n->next) {
			if (n != node->children.first) str_print(builder, LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		str_print(builder, LIT("]"));
	} break;

	default: BP;
	}
	temp_pop();
}

String ffz_print_ast(Allocator* alc, ffzNode* node) {
	Array<u8> builder = make_array_cap<u8>(512, alc);
	_print_ast(&builder, node, 0);
	return builder.slice;
}

static ffzOk parse_expression(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets = false);
static ffzOk parse_value(ffzParser* p, ffzNode* parent, ffzNode** out);

#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\r')

// returns an empty token when the end of file is reached.
static ffzOk maybe_eat_next_token(ffzParser* p, ffzLoc* pos, bool ignore_newlines, Token* out) {
	enum CharType {
		CharType_Alphanumeric,
		CharType_Whitespace,
		CharType_Symbol,
	};

	CharType prev_type = CharType_Whitespace;
	s32 prev_r;

	ffzLocRange token_range = ffz_loc_to_range(*pos);
	
	bool inside_line_comment = false;

	for (;;) {
		uint next = pos->offset;
		rune r = str_next_rune(p->source_code, &next);
		if (!r) break;

		CharType type = CharType_Symbol;
		if ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r > 128) {
			type = CharType_Alphanumeric;
		}
		else if (IS_WHITESPACE(r)) {
			type = CharType_Whitespace;
		}
		else if (ignore_newlines && r == '\n') {
			type = CharType_Whitespace;
		}
		// everything else counts as a symbol

		if (prev_type == CharType_Symbol && prev_r == '/' && r == '/') {
			inside_line_comment = true;
		}

		if (!inside_line_comment && prev_type != CharType_Whitespace && type != prev_type) break;

		if (!inside_line_comment && prev_type == CharType_Symbol) {
			// We need to manually check for some cases where symbols should be joined.
			// e.g. <= << >> == !=
			bool join_symbol = false;
			if (prev_r == '|') join_symbol = true; // ||
			if (prev_r == '&') join_symbol = true; // &&
			if (prev_r == '=') join_symbol = true; // ==
			if (prev_r == '<') join_symbol = true; // <<, <=
			if (prev_r == '>') join_symbol = true; // >>, >=
			if (prev_r == '!' && r == '=') join_symbol = true; // != should join, but e.g. !! and !~ shouldn't join
			if (prev_r == '*' && r == '/') join_symbol = true; // join comment block enders

			// Skip comment blocks
			if (prev_r == '/' && r == '*') {
				ffzLoc start = *pos;
				for (;;) {
					Token tok;
					TRY(maybe_eat_next_token(p, pos, true, &tok));
					if (tok.str == LIT("*/")) break;
					if (tok.str.len == 0) {
						ERR(p, ffz_loc_to_range(start), "File ended unexpectedly; no matching */ found for comment block.");
					}
				}

				prev_type = CharType_Whitespace;
				token_range = ffz_loc_to_range(*pos);
				continue;
			}

			if (!join_symbol) {
				break;
			}
		}

		if (r == '\n') {
			pos->line_num += 1;
			pos->column_num = 0;
			inside_line_comment = false;
		}

		pos->offset = (u32)next;
		pos->column_num += 1;

		if (type == CharType_Whitespace) token_range.start = *pos;
		token_range.end = *pos;

		prev_type = type;
		prev_r = r;
	}

	out->range = token_range;
	out->str = slice(p->source_code, token_range.start.offset, token_range.end.offset);
	return { true };
}

static ffzOk eat_next_token(ffzParser* p, ffzLoc* pos, bool ignore_newlines, const char* task_verb, Token* out) {
	TRY(maybe_eat_next_token(p, pos, ignore_newlines, out));
	if (out->str.len == 0) {
		ERR(p, ffz_loc_to_range(*pos), "File ended unexpectedly when %s.", task_verb);
	}
	return { true };
}

static ffzOk parse_statement_separator(ffzParser* p, ffzLoc* pos) {
	Token tok;
	TRY(eat_next_token(p, pos, false, "parsing a statement separator", &tok));
	if (tok.str != LIT("\n") && tok.str != LIT(",")) {
		ERR(p, tok.range, "Expected a statement separator character (either a comma or a newline).");
	}
	return { true };
}

static ffzOk peek_next_token(ffzParser* p, ffzLoc pos, bool ignore_newlines, const char* task_verb, Token* out) {
	return eat_next_token(p, &pos, ignore_newlines, task_verb, out);
}

static ffzOk maybe_peek_next_token(ffzParser* p, ffzLoc pos, bool ignore_newlines, Token* out) {
	return maybe_eat_next_token(p, &pos, ignore_newlines, out);
}

//static void node_add_range_to_parent(ffzNode* parent, ffzNode* child) {
//	if (child->end_pos.offset_into_file > parent->end_pos.offset_into_file) {
//		parent->end_pos = child->end_pos;
//	}
//	if (child->start_pos.offset_into_file < parent->start_pos.offset_into_file) {
//		parent->start_pos = child->start_pos;
//	}
//}


// tok.str field is ignored
template<typename T>
static T* make_node(ffzParser* p, ffzNode* parent, ffzLocRange range, ffzNodeKind kind) {
	T* node = mem_clone(T{}, p->alc);
	node->parser_idx = p->self_idx;
	node->parent = parent;
	node->kind = kind;
	node->loc = range;
	return node;
}

static ffzOk parse_node(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets = false);

static ffzOk parse_possible_tag_decls(ffzParser* p, ffzNode* parent, OPT(ffzNode**) p_prev, OPT(ffzNode**) p_first) {
	for (;;) {
		Token tok;
		ffzLoc pos = p->pos;
		TRY(maybe_eat_next_token(p, &pos, true, &tok));

		ffzNodeKind kind = ffzNodeKind_Invalid;
		if (tok.str == LIT("@")) kind = ffzNodeKind_CompilerTagDecl;
		if (tok.str == LIT("~")) kind = ffzNodeKind_UserTagDecl;
		if (kind) {
			Token after_tag;
			TRY(maybe_eat_next_token(p, &pos, true, &tok));
			TRY(maybe_eat_next_token(p, &pos, true, &after_tag));
			if (after_tag.str == LIT(":")) {
				ffzNodeTagDecl* tag_decl = make_node<ffzNodeTagDecl>(p, parent, tok.range, kind);
				
				auto first = map64_insert(&p->tag_decl_lists, str_hash64_ex(tok.str, 0), tag_decl, MapInsert_DoNotOverride);
				if (!first.added) {
					tag_decl->same_tag_next = *first._unstable_ptr;
					*first._unstable_ptr = tag_decl;
				}
				
				tag_decl->tag = tok.str;
				p->pos = pos;
				TRY(parse_expression(p, BASE(tag_decl), &tag_decl->rhs));

				if (*p_prev) (*p_prev)->next = BASE(tag_decl);
				else (*p_first) = BASE(tag_decl);
				*p_prev = BASE(tag_decl);
				continue;
			}
		}
		break;
	}
	return { true };
}

static ffzOk parse_node_list(ffzParser* p, ffzNode* parent, u8 bracket_close_char) {
	String bracket_close = bracket_close_char ? String{&bracket_close_char, 1} : String{};

	OPT(ffzNode*) prev = NULL;
	OPT(ffzNode*) first = NULL;

	for (u32 i = 0;; i++) {
		ffzLoc after_next = p->pos;
		
		HITS(__c, 0);
		
		Token tok;
		TRY(maybe_peek_next_token(p, p->pos, true, &tok));
		if (tok.str == bracket_close) {
			p->pos = tok.end;
			parent->loc.end = tok.end;
			break;
		}
		
		bool was_comma = false;
		if (i > 0) {
			TRY(maybe_peek_next_token(p, p->pos, false, &tok));
			was_comma = tok.str == LIT(",");
			if (tok.str != LIT("\n") && !was_comma) {
				ERR(p, tok.range, "Expected a node separator character (either a comma or a newline).");
			}
			p->pos = tok.end;
		}
		
		ffzNode* n;
		TRY(maybe_peek_next_token(p, p->pos, false, &tok));
		if ((tok.str == bracket_close && was_comma) || tok.str == LIT(",")) {
			n = BASE(make_node<ffzNodeBlank>(p, parent, tok.range, ffzNodeKind_Blank));
		}
		else {
			TRY(parse_possible_tag_decls(p, parent, &prev, &first));
			TRY(parse_node(p, parent, &n));
		}

		if (prev) prev->next = n;
		else first = n;
		prev = n;
	}
	parent->children = ffzNodeList{ first };
	return { true };
}


static bool is_alnum_or_underscore(rune r) { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_'; }

static ffzOk parse_possible_tags(ffzParser* p, OPT(ffzNodeTag*)* out_tag) {
	*out_tag = NULL;
	Token tok;
	TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	if (tok.str.len > 0) {
		ffzNodeKind kind = ffzNodeKind_Invalid;
		if (tok.str == LIT("~")) kind = ffzNodeKind_UserTag;
		if (tok.str == LIT("@")) kind = ffzNodeKind_CompilerTag;
		if (kind != ffzNodeKind_Invalid) {
			p->pos = tok.end;
			TRY(eat_next_token(p, &p->pos, true, "parsing a tag", &tok));

			ffzNodeTag* node = make_node<ffzNodeTag>(p, NULL, tok.range, kind);
			node->tag = tok.str;
			if (!is_alnum_or_underscore(tok.str[0])) {
				ERR(p, tok.range, "TODO");
			}
			TRY(parse_possible_tags(p, (ffzNodeTag**)&node->next));
			*out_tag = node;
		}
	}
	return { true };
}

// Normally, we want to parse the tags before parsing and making the node they will be attached to.
// This procedure allows us to set the tags after the fact.
static void assign_possible_tags_to_node(ffzNode* node, OPT(ffzNodeTag*) first_tag) {
	node->first_tag = first_tag;
	for (ffzNodeTag* tag = first_tag; tag; tag = (ffzNodeTag*)tag->next) {
		tag->parent = node;
	}
}

static ffzOk parse_node(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets) {
	ffzNode* result = NULL;

	ffzNodeTag* first_tag;
	TRY(parse_possible_tags(p, &first_tag));

	// check for ret / break / etc statements
	ffzLoc after_next = p->pos;
	Token tok;
	TRY(eat_next_token(p, &after_next, true, "parsing a statement", &tok));

	// TODO: eif - short for 'else; if'. The reason for this is to allow for easier alignment in many cases.
	// maybe we could then also enforce the use of ; for else statement.
	// if  a > 0; thing()
	// eif b > 0; other_thing()
	// else;      third_thing()

	if (tok.str == LIT("if")) {
		p->pos = after_next;
		ffzNodeIf* if_stmt = make_node<ffzNodeIf>(p, parent, tok.range, ffzNodeKind_If);
		TRY(parse_expression(p, BASE(if_stmt), &if_stmt->condition, true));
		TRY(parse_node(p, BASE(if_stmt), &if_stmt->true_scope));

		after_next = p->pos;
		TRY(maybe_eat_next_token(p, &after_next, true, &tok));
		if (tok.str == LIT("else")) {
			p->pos = after_next;
			TRY(parse_node(p, BASE(if_stmt), &if_stmt->else_scope));
		}
		if_stmt->loc.end = p->pos;
		result = BASE(if_stmt);
	}
	else if (tok.str == LIT("for")) {
		p->pos = after_next;
		ffzNodeFor* for_loop = make_node<ffzNodeFor>(p, parent, tok.range, ffzNodeKind_For);
		for (int i = 0; i < 3; i++) {
			ffzLoc after_next = p->pos;
			Token next_tok;
			TRY(eat_next_token(p, &after_next, true, "parsing a for-loop header", &next_tok));
			if (next_tok.str == LIT("{")) break;

			if (i > 0) {
				TRY(parse_statement_separator(p, &p->pos));
			}

			after_next = p->pos;
			TRY(eat_next_token(p, &after_next, true, "parsing a for-loop header", &next_tok));
			if (next_tok.str == LIT(",")) continue;

			ffzNode* stmt;
			TRY(parse_node(p, BASE(for_loop), &stmt, true));
			for_loop->header_stmts[i] = stmt;
		}

		TRY(parse_node(p, BASE(for_loop), &for_loop->scope));
		for_loop->loc.end = p->pos;
		result = BASE(for_loop);
	}
	else if (tok.str == LIT("ret")) {
		p->pos = after_next;
		ffzNodeReturn* ret = make_node<ffzNodeReturn>(p, parent, tok.range, ffzNodeKind_Return);

		TRY(maybe_eat_next_token(p, &after_next, false, &tok)); // With return statements, newlines do matter!
		if (tok.str == LIT("\n")) {
			p->pos = after_next;
		}
		else {
			TRY(parse_expression(p, BASE(ret), &ret->value));
		}
		ret->loc.end = p->pos;
		result = BASE(ret);
	}

	// first parse the expression on the left hand side

	if (!result) {
		TRY(parse_expression(p, parent, &result, stop_at_curly_brackets));

		ffzLoc after_next = p->pos;
		Token tok;
		TRY(maybe_eat_next_token(p, &after_next, false, &tok));

		if (tok.str.len == 1 && tok.str.data[0] == ':') {
			if (result->kind != ffzNodeKind_Identifier) {
				ERR(p, tok.range, "left-hand-side of a declaration must be an identifier.");
			}

			ffzNodeDeclaration* decl = make_node<ffzNodeDeclaration>(p, parent, result->loc, ffzNodeKind_Declaration);
			result->parent = BASE(decl);
			decl->name = AS(result,Identifier);
			
			p->pos = after_next;
			TRY(parse_expression(p, BASE(decl), &decl->rhs, stop_at_curly_brackets));
			decl->loc.end = decl->rhs->loc.end;
			result = BASE(decl);
		}
		else if (tok.str.len == 1 && tok.str.data[0] == '=') {
			ffzNodeAssignment* assignment = make_node<ffzNodeAssignment>(p, parent, result->loc, ffzNodeKind_Assignment);
			result->parent = BASE(assignment);
			assignment->lhs = result;

			p->pos = after_next;
			TRY(parse_expression(p, BASE(assignment), &assignment->rhs, stop_at_curly_brackets));
			assignment->loc.end = assignment->rhs->loc.end;
			result = BASE(assignment);
		}
	}

	assign_possible_tags_to_node(result, first_tag);

	*out = result;
	return { true };
}

static ffzOk parse_enum(ffzParser* p, ffzNode* parent, ffzLocRange range, ffzNodeEnum** out) {
	ffzNodeEnum* node = make_node<ffzNodeEnum>(p, parent, range, ffzNodeKind_Enum);
	Token tok;
	TRY(eat_next_token(p, &p->pos, true, "parsing an enum", &tok));

	if (tok.str == LIT(",")) {
		TRY(parse_expression(p, BASE(node), &node->internal_type, true));
		TRY(eat_next_token(p, &p->pos, true, "parsing an enum", &tok));
	}

	if (tok.str != LIT("{")) ERR(p, tok.range, "Expected a `{`");
	TRY(parse_node_list(p, BASE(node), '}'));
	*out = node;
	return { true };
}

//ffzToken ffz_token_from_node(ffzParser* p, ffzNode* node) {
//	ffzToken result = { node->start_pos, node->end_pos,
//		str_slice(p->source_code, node->start_pos.offset_into_file, node->end_pos.offset_into_file) };
//}

static ffzOk maybe_parse_polymorphic_parameter_list(ffzParser* p, ffzNode* parent, ffzNodePolyParamList** out) {
	Token tok;
	TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	if (tok.str == LIT("[")) {
		p->pos = tok.end;
		ffzNodePolyParamList* node = make_node<ffzNodePolyParamList>(p, parent, tok.range, ffzNodeKind_PolyParamList);
		TRY(parse_node_list(p, BASE(node), ']'));
		*out = node;
	}
	return { true };
}

static ffzOk parse_struct(ffzParser* p, ffzNode* parent, ffzLocRange range, bool is_union, ffzNodeRecord** out) {
	ffzNodeRecord* node = make_node<ffzNodeRecord>(p, parent, range, ffzNodeKind_Record);
	TRY(maybe_parse_polymorphic_parameter_list(p, BASE(node), &node->polymorphic_parameters));

	Token tok;
	TRY(eat_next_token(p, &p->pos, true, "parsing a struct", &tok));
	if (tok.str != LIT("{")) ERR(p, tok.range, "Expected a `{`");

	TRY(parse_node_list(p, BASE(node), '}'));

	node->is_union = is_union;
	*out = node;
	return { true };
}

static ffzOk eat_expected_token(ffzParser* p, String expected) {
	Token tok;
	TRY(maybe_eat_next_token(p, &p->pos, true, &tok));
	if (tok.str != expected) ERR(p, tok.range, "Expected \"%s\"; got \"%s\"", str_to_cstring(expected, p->alc), str_to_cstring(tok.str, p->alc));
	return { true };
}

static ffzOk parse_proc_type(ffzParser* p, ffzNode* parent, ffzLocRange range, ffzNodeProcType** out) {
	ffzNodeProcType* _proc = make_node<ffzNodeProcType>(p, parent, range, ffzNodeKind_ProcType);
	TRY(maybe_parse_polymorphic_parameter_list(p, BASE(_proc), &_proc->polymorphic_parameters));

	Token tok;
	TRY(peek_next_token(p, p->pos, true, "parsing a procedure", &tok));

	//if (tok.str == LIT("[")) {
	//	BP;//p->pos = tok.end;
	//	//TRY(parse_node_list(p, BASE(proc), ']', &proc->ProcType.polymorphic_parameters));
	//	//TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	//}

	if (tok.str == LIT("(")) {
		p->pos = tok.end;
		TRY(parse_node_list(p, BASE(_proc), ')'));
		TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	}

	if (tok.str == LIT("=>")) {
		p->pos = tok.end;
		TRY(eat_expected_token(p, LIT("(")));
		TRY(parse_node(p, BASE(_proc), &_proc->out_parameter));
		TRY(eat_expected_token(p, LIT(")")));
	}
	_proc->loc.end = p->pos;
	*out = _proc;
	return { true };
}

static ffzOk parse_string_literal(ffzParser* p, String* out) {
	Array<u8> builder = make_array_cap<u8>(64, p->alc);

	ffzLoc start_pos = p->pos;

	for (;;) {
		uint next = p->pos.offset;
		rune r = str_next_rune(p->source_code, &next);
		if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.");
		if (r == '\n') {
			p->pos.line_num++;
			p->pos.column_num = 0;
		}

		if (r == '\\') {
			r = str_next_rune(p->source_code, &next);
			if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.");
			if (r == '\n') {
				p->pos.line_num++;
				p->pos.column_num = 0;
			}

			p->pos.offset = (u32)next;
			p->pos.column_num += 1;

			if (r == 'a')       array_push(&builder, (u8)'\a');
			else if (r == 'b')  array_push(&builder, (u8)'\b');
			else if (r == 'f')  array_push(&builder, (u8)'\f');
			else if (r == 'f')  array_push(&builder, (u8)'\f');
			else if (r == 'n')  array_push(&builder, (u8)'\n');
			else if (r == 'r')  array_push(&builder, (u8)'\r');
			else if (r == 't')  array_push(&builder, (u8)'\t');
			else if (r == 'v')  array_push(&builder, (u8)'\v');
			else if (r == '\\') array_push(&builder, (u8)'\\');
			else if (r == '\'') array_push(&builder, (u8)'\'');
			else if (r == '\"') array_push(&builder, (u8)'\"');
			else if (r == '?')  array_push(&builder, (u8)'\?');
			else if (r == '0')  array_push(&builder, (u8)0); // parsing octal characters is not supported like in C, with the exception of \0
			else if (r == 'x') {
				//if (p->pos.remaining.len < 2) PARSER_ERROR(p, p->pos, LIT("File ended unexpectedly when parsing a string literal."));
				ASSERT(p->pos.offset + 2 <= p->source_code.len);

				String byte = slice(p->source_code, p->pos.offset, p->pos.offset + 2);
				p->pos.offset += 2;
				p->pos.column_num += 2;

				s64 byte_value;
				if (str_to_s64(byte, 16, &byte_value)) {
					array_push(&builder, (u8)byte_value);
				}
				else ERR(p, { p->pos }, "Failed parsing a hexadecimal byte.");
			}
			else ERR(p, { p->pos }, "Invalid escape sequence.");
		}
		else {
			String codepoint = slice(p->source_code, p->pos.offset, next);
			p->pos.offset = (u32)next;
			p->pos.column_num += 1;

			if (r == '\"') break;
			if (r == '\r') continue; // Ignore carriage returns

			array_push_slice(&builder, codepoint);
		}
	}

	array_push(&builder, (u8)'\0');
	*out = slice_before(builder.slice, builder.slice.len - 1);
	return { true };
}

// TODO: in checker, add a check to make sure there aren't multiple tags with the same identifier
OPT(ffzNodeTag*) ffz_node_get_compiler_tag(ffzNode* node, String tag) {
	for (ffzNodeTag* n = node->first_tag; n; n = (ffzNodeTag*)n->next) {
		if (n->kind == ffzNodeKind_CompilerTag && n->tag == tag) return n;
	}
	return NULL;
}

OPT(ffzNodeTag*) ffz_node_get_user_tag(ffzNode* node, String tag) {
	for (ffzNodeTag* n = node->first_tag; n; n = (ffzNodeTag*)n->next) {
		if (n->kind == ffzNodeKind_UserTag && n->tag == tag) return n;
	}
	return NULL;
}

OPT(ffzNodeDeclaration*) ffz_get_parent_decl(OPT(ffzNode*) node) {
	return node && node->parent->kind == ffzNodeKind_Declaration ? AS(node->parent,Declaration) : NULL;
}

String ffz_get_parent_decl_name(OPT(ffzNode*) node) {
	ffzNodeDeclaration* decl = ffz_get_parent_decl(node);
	return decl ? decl->name->name : String{};
}

static ffzOk parse_value_recursing_to_left(ffzParser* p, ffzNode* parent, ffzNode** out) {
	ffzNodeTag* first_tag;
	TRY(parse_possible_tags(p, &first_tag));

	Token tok;
	//ffzNodePosition pos_before = p->pos;
	TRY(eat_next_token(p, &p->pos, true, "parsing a value", &tok));

	s64 numeric;
	if (str_to_s64(tok.str, 10, &numeric)) {
		ffzNodeIntLiteral* node = make_node<ffzNodeIntLiteral>(p, parent, tok.range, ffzNodeKind_IntLiteral);
		node->value = numeric;
		*out = BASE(node);
		return { true };
	}

	ffzNode* result = NULL;

	u8 c = tok.str.data[0];

	if (c == '{') {
		result = BASE(make_node<ffzNodeScope>(p, parent, tok.range, ffzNodeKind_Scope));
		TRY(parse_node_list(p, result, '}'));
	}
	else if (c == '(') {
		TRY(parse_expression(p, parent, &result));
		TRY(eat_expected_token(p, LIT(")")));
	}
	else if (c == '\"') {
		ffzNodeStringLiteral* lit = make_node<ffzNodeStringLiteral>(p, parent, tok.range, ffzNodeKind_StringLiteral);
		TRY(parse_string_literal(p, &lit->zero_terminated_string));
		lit->loc.end = p->pos;
		result = BASE(lit);
	}
	else if (tok.str == LIT("proc")) {
		TRY(parse_proc_type(p, parent, tok.range, (ffzNodeProcType**)&result));
	}
	else if (tok.str == LIT("enum")) {
		TRY(parse_enum(p, parent, tok.range, (ffzNodeEnum**)&result));
	}
	else if (tok.str == LIT("struct")) {
		TRY(parse_struct(p, parent, tok.range, false, (ffzNodeRecord**)&result));
	}
	else if (tok.str == LIT("union")) {
		TRY(parse_struct(p, parent, tok.range, true, (ffzNodeRecord**)&result));
	}
	else if (is_alnum_or_underscore(c) || c == '#' || c == '?') {
		for (uint i = 0; i < LEN(KeywordKind_String); i++) {
			if (tok.str == KeywordKind_String[i]) {
				result = BASE(make_node<ffzNodeKeyword>(p, parent, tok.range, ffzNodeKind_Keyword));
				result->Keyword.keyword = (ffzKeyword)i;
				
				if (i == ffzKeyword_import) {
					array_push(&p->module_imports, AS(result,Keyword));
				}

				break;
			}
		}


		if (!result) {
			// identifier!
			result = BASE(make_node<ffzNodeIdentifier>(p, parent, tok.range, ffzNodeKind_Identifier));
			if (c == '#') {
				AS(result,Identifier)->is_constant = true;
				TRY(eat_next_token(p, &p->pos, true, "parsing an identifier", &tok));
				c = tok.str.data[0];

				if (!is_alnum_or_underscore(c)) {
					ERR(p, tok.range, "Invalid character for constant identifier.");
				}
			}
			AS(result,Identifier)->name = tok.str;
		}
	}
	else if (c == '.') {
		Token next;
		TRY(maybe_peek_next_token(p, p->pos, true, &next));
		if (next.str.len == 0 || !is_alnum_or_underscore(next.str[0])) { // otherwise it's an unary member access
			result = BASE(make_node<ffzNodeDot>(p, parent, tok.range, ffzNodeKind_Dot));
		}
	}
	//else if (c == ',') {
	//	//p->pos = pos_before;
	//	
	//}

	if (!result) {
		ffzOperatorKind kind = ffzOperatorKind_Invalid;
		if (c == '-') kind = ffzOperatorKind_UnaryMinus;
		else if (c == '+') kind = ffzOperatorKind_UnaryPlus;
		else if (c == '.') kind = ffzOperatorKind_UnaryMemberAccess;
		else if (c == '&') kind = ffzOperatorKind_AddressOf;
		else if (c == '!') kind = ffzOperatorKind_LogicalNOT;
		else if (c == '^') kind = ffzOperatorKind_PointerTo;
		else if (c == '[') kind = ffzOperatorKind_PreSquareBrackets;
		if (kind) {
			result = BASE(make_node<ffzNodeOperator>(p, parent, tok.range, ffzNodeKind_Operator));
			AS(result,Operator)->op_kind = kind;

			if (kind == ffzOperatorKind_PreSquareBrackets) {
				TRY(parse_node_list(p, result, ']'));
			}

			bool recurse_to_left = /*c == '^' || */kind == ffzOperatorKind_PreSquareBrackets;

			// ^int(20) should parse as (^int)(20), while -int(20) should parse as -(int(20))
			// hmm... and '.' should have even higher priority, i.e.  ^Basic.Allocator should be ^(Basic.Allocator)
			if (recurse_to_left) {
				TRY(parse_value_recursing_to_left(p, result, &AS(result,Operator)->right));
			}
			else {
				TRY(parse_value(p, result, &AS(result,Operator)->right));
			}
			result->loc.end = AS(result,Operator)->right->loc.end;
		}
	}

	if (!result) ERR(p, tok.range, "Failed parsing a value; unexpected token `%s`\n", str_to_cstring(tok.str, p->alc));
	assign_possible_tags_to_node(result, first_tag);

	*out = result;
	return { true };
}

static ffzOk parse_value(ffzParser* p, ffzNode* parent, ffzNode** out) {
	ffzNode* result;
	TRY(parse_value_recursing_to_left(p, parent, &result));

	// An expression chain is formed at the end of an expression when there is a
	// a function call, the subscript ([]) operator, a post-unary operator such as the dereference (^) operator.
	// Currently the dereference operator is the only post-unary operator.
	// Multiple of these operations can be chained together in a row.

	for (;;) {
		ffzLoc after_next = p->pos;
		//if (after_next.offset_into_file < p->source_code.len && IS_WHITESPACE(p->source_code[after_next.offset_into_file])) break; // break by space

		Token next;
		TRY(maybe_eat_next_token(p, &after_next, true, &next));
		if (next.str.len == 0) break;

		ffzOperatorKind op_kind = ffzOperatorKind_Invalid;
		if (next.str.data[0] == '^') op_kind = ffzOperatorKind_Dereference;
		if (next.str.data[0] == '.') op_kind = ffzOperatorKind_MemberAccess;
		if (op_kind) {
			p->pos = after_next;
			ffzNodeOperator* op = make_node<ffzNodeOperator>(p, parent, { result->loc.start, next.range.end }, ffzNodeKind_Operator);
			op->op_kind = op_kind;
			op->left = result;
			result->parent = BASE(op);

			if (op_kind == ffzOperatorKind_MemberAccess) {
				TRY(parse_value_recursing_to_left(p, BASE(op), &op->right));
				op->loc.end = op->right->loc.end;
			}
			result = BASE(op);
			continue;
		}

		// Post brackets can't be curly, because that would cause an ambuguity when parsing if-statements.
		// e.g.  if SomeMacro{f32} {...}
		//       should that parse into if SomeMacro {...}
		// We could fix this if we make whitespace significant (e.g. macro{T} is valid, but macro {T} is not) or
		// we could reserve some other syntax for macros, such as Vector3[f32]. I'm leaning towards the [] syntax for macros.
		// Even in Odin, this is ambiguous! "if Vector3{1, 2, 3}.x > 0 {}" will give you a syntax error.
		// EDIT: we need post-curly-brackets for struct initialization, because of anonymous struct literals...
		// hmm.. maybe we should only have this rule inside of if-statement conditions. Or just not allow constructing structs inside of ifs.

		u8 close_bracket_char = 0;
		if (next.str.data[0] == '(') {
			op_kind = ffzOperatorKind_PostRoundBrackets;
			close_bracket_char = ')';
		}
		else if (next.str.data[0] == '[') {
			op_kind = ffzOperatorKind_PostSquareBrackets;
			close_bracket_char = ']';
		}
		else if (!p->stop_at_curly_brackets && next.str.data[0] == '{') {
			op_kind = ffzOperatorKind_PostCurlyBrackets;
			close_bracket_char = '}';
		}
		if (op_kind) {
			p->pos = after_next;
			ffzNodeOperator* op = make_node<ffzNodeOperator>(p, parent, { result->loc.start, p->pos }, ffzNodeKind_Operator);
			op->op_kind = op_kind;
			op->left = result;
			result->parent = BASE(op);

			TRY(parse_node_list(p, BASE(op), close_bracket_char));
			result = BASE(op);
			continue;
		}

		break; // End of the chain
	}
	*out = result;
	return { true };
}

static ffzNodeOperator* find_root_operator(Slice<ffzNodeOperator*> chain) {

	// Find the operator with the lowest precedence (pick the right-most
	// one if there are multiple operators with the same precedence)
	// and recursively call FindRoot on both sides until no operators
	// are left on either side
	// e.g.
	// 
	//    a * b + c * d > e + f * g + h / i * j
	//                 / \
	//  (a * b + c * d)   (e + f * g + h / i * j)
	//        / \                   / \
	// (a * b)   (c * d)  (e + f * g)  (h / i * j)
	//                        \              /
	//                        (f * g)  (h / i)
	//

	ASSERT(chain.len > 0);
	if (chain.len == 1) return chain[0];

	uint lowest_prec_i = 0;
	uint lowest_prec = U64_MAX;
	for (uint i = chain.len - 1; i < chain.len; i--) {
		ASSERT(chain[i]->kind == ffzNodeKind_Operator);
		uint prec = op_get_precedence(chain[i]->op_kind);
		if (prec < lowest_prec) {
			lowest_prec = prec;
			lowest_prec_i = i;
		}
	}

	if (lowest_prec_i > 0) {
		ffzNode* left = BASE(find_root_operator(slice_before(chain, lowest_prec_i)));
		left->parent = BASE(chain[lowest_prec_i]);
		chain[lowest_prec_i]->left = left;
	}
	if (lowest_prec_i < chain.len - 1) {
		ffzNode* right = BASE(find_root_operator(slice_after(chain, lowest_prec_i + 1)));
		right->parent = BASE(chain[lowest_prec_i]);
		chain[lowest_prec_i]->right = right;
	}

	return chain[lowest_prec_i];
}

static ffzOk parse_expression(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets) { HITS(_c, 0);
	bool stop_bef = p->stop_at_curly_brackets; defer(p->stop_at_curly_brackets = stop_bef);
	p->stop_at_curly_brackets = stop_at_curly_brackets;

	// For a simplified example of operator parsing, see the `math_expr_compiler.cpp` demo for GMMC.
	Array<ffzNodeOperator*> operator_chain = make_array_cap<ffzNodeOperator*>(8, p->alc);

	ffzNode* prev = NULL;
	bool expecting_value = true;

	for (;;) {
		ffzNode* node = NULL;
		if (expecting_value) {
			TRY(parse_value(p, parent, &node));
			if (prev) {
				AS(prev,Operator)->right = node;
				prev->loc.end = node->loc.end;
				node->parent = prev;
			}
		}
		else {
			// Check to see if the next token is an operator.

			ffzLoc after_next = p->pos;
			Token tok;
			TRY(maybe_eat_next_token(p, &after_next, true, &tok));
			if (tok.str.len == 0 || tok.str == LIT(")")) break;

			// this should be a hash table
			const ffzOperatorKind TwoSidedOperators[] = {
				ffzOperatorKind_Add,
				ffzOperatorKind_Sub,
				ffzOperatorKind_Mul,
				ffzOperatorKind_Div,
				ffzOperatorKind_Modulo,
				ffzOperatorKind_Equal,
				ffzOperatorKind_NotEqual,
				ffzOperatorKind_Less,
				ffzOperatorKind_LessOrEqual,
				ffzOperatorKind_Greater,
				ffzOperatorKind_GreaterOrEqual,
				ffzOperatorKind_ShiftL,
				ffzOperatorKind_ShiftR,
				ffzOperatorKind_LogicalAND,
				ffzOperatorKind_LogicalOR,
			};

			ffzOperatorKind kind = ffzOperatorKind_Invalid;
			for (int i = 0; i < LEN(TwoSidedOperators); i++) {
				ffzOperatorKind test = TwoSidedOperators[i];
				if (ffzOperatorKind_String[test] == tok.str) {
					kind = test;
					break;
				}
			}
			if (kind == ffzOperatorKind_Invalid) break;

			node = BASE(make_node<ffzNodeOperator>(p, parent, { prev->loc.start, tok.end }, ffzNodeKind_Operator));
			AS(node,Operator)->op_kind = kind;
			AS(node,Operator)->left = prev;
			prev->parent = node;

			array_push(&operator_chain, AS(node,Operator));
			p->pos = after_next;
		}

		expecting_value = !expecting_value;
		prev = node;
	}

	ffzNode* root = prev;
	if (operator_chain.len > 0) {
		root = BASE(find_root_operator(operator_chain.slice));
	}

	if (!root) ERR(p, {}, "Empty expression.");
	*out = root;
	return { true };
}

ffzOk ffz_parse(ffzParser* p) {
	p->root = make_node<ffzNodeScope>(p, NULL, {}, ffzNodeKind_Scope);
	TRY(parse_node_list(p, BASE(p->root), 0));
	return { true };
}

OPT(ffzNode*) ffz_skip_tag_decls(OPT(ffzNode*) node) {
	for (; node && (node->kind >= ffzNodeKind_CompilerTagDecl && node->kind <= ffzNodeKind_UserTagDecl); node = node->next) {}
	return node;
}

ffzNode* ffz_get_child(ffzNode* parent, u32 idx) {
	u32 i = 0;
	for FFZ_EACH_CHILD(n, parent) {
		if (i == idx) return n;
		i++;
	}
	ASSERT(false);
	return NULL;
}

u32 ffz_get_child_count(OPT(ffzNode*) parent) {
	if (!parent) return 0;
	u32 i = 0;
	for FFZ_EACH_CHILD(n, parent) i++;
	return i;
}

u32 ffz_get_child_index(ffzNode* child) {
	u32 idx = 0;
	for FFZ_EACH_CHILD(n, child->parent) {
		if (n == child) return idx;
		idx++;
	}
	ASSERT(false);
	return U32_MAX;
}