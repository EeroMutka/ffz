#define FOUNDATION_HELPER_MACROS
#include "foundation/foundation.h"

#include "ffz_ast.h"

#define TRY(x) { if ((x).ok == false) return (ffzOk){false}; }

#define OPT(ptr) ptr

#define ERR(state, at, fmt, ...) { \
	state->parser->report_error(state->parser, at, f_str_format(state->parser->alc, fmt, __VA_ARGS__)); \
	return FFZ_OK; \
}

//#define AS(node,kind) FFZ_AS(node, kind)
//#define (ffzNode*)node FFZ_(ffzNode*)node

#define SLICE_BEFORE(T, slice, mid) (fSliceRaw){(T*)slice.data, (mid)}
#define SLICE_AFTER(T, slice, mid) (fSliceRaw){(T*)slice.data + (mid), (slice.len) - (mid)}
#define fSlice(T) fSliceRaw
#define Array(T) fArrayRaw

typedef struct Token {
	union {
		struct { ffzLoc start; ffzLoc end; };
		ffzLocRange range;
	};
	fString str;
	u32 small;
} Token;

const ffzOk FFZ_OK = { true };

// synced with `ffzNodeKind`
static const fString ffzNodeKind_to_string[] = {
	F_LIT_COMP("invalid"),
	F_LIT_COMP("blank"),
	F_LIT_COMP("identifier"),
	F_LIT_COMP("polymorphic-parameter"),
	F_LIT_COMP("keyword"),
	F_LIT_COMP("dot"),
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
	F_LIT_COMP(":"),
	F_LIT_COMP("="),
	F_LIT_COMP("+"),
	F_LIT_COMP("-"),
	F_LIT_COMP("*"),
	F_LIT_COMP("/"),
	F_LIT_COMP("%"),
	F_LIT_COMP("."),
	F_LIT_COMP("=="),
	F_LIT_COMP("!="),
	F_LIT_COMP("<"),
	F_LIT_COMP("<="),
	F_LIT_COMP(">"),
	F_LIT_COMP(">="),
	F_LIT_COMP("&&"),
	F_LIT_COMP("||"),
	F_LIT_COMP("pre-square-brackets"),
	F_LIT_COMP("-"),
	F_LIT_COMP("+"),
	F_LIT_COMP("&"),
	F_LIT_COMP("^"),
	F_LIT_COMP("!"),
	F_LIT_COMP("post-square-brackets"),
	F_LIT_COMP("post-round-brackets"),
	F_LIT_COMP("post-curly-brackets"),
	F_LIT_COMP("^"),
};

const static fString ffzKeyword_to_string[] = { // synced with `ffzKeyword`
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

F_STATIC_ASSERT(F_LEN(ffzNodeKind_to_string) == ffzNodeKind_COUNT);
F_STATIC_ASSERT(F_LEN(ffzKeyword_to_string) == ffzKeyword_COUNT);

fString ffz_node_kind_to_string(ffzNodeKind kind) { return ffzNodeKind_to_string[kind]; }
char* ffz_node_kind_to_cstring(ffzNodeKind kind) { return (char*)ffzNodeKind_to_string[kind].data; }
fString ffz_keyword_to_string(ffzKeyword keyword) { return ffzKeyword_to_string[keyword]; }
char* ffz_keyword_to_cstring(ffzKeyword keyword) { return (char*)ffzKeyword_to_string[keyword].data; }

// NOTE: The operators that exist in C have the same precedence as in C
// https://en.cppreference.com/w/c/language/operator_precedence
u32 ffz_operator_get_precedence(ffzNodeKind kind) {
	switch (kind) {
	case ffzNodeKind_MemberAccess: return 13;
	case ffzNodeKind_PostSquareBrackets: return 12;
	case ffzNodeKind_PointerTo: // fallthrough
	case ffzNodeKind_PreSquareBrackets: return 11;
	case ffzNodeKind_PostRoundBrackets: // fallthrough
	case ffzNodeKind_PostCurlyBrackets: return 10;
	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_AddressOf: // fallthrough
	case ffzNodeKind_LogicalNOT: // fallthrough
	case ffzNodeKind_UnaryPlus: return 9;
	case ffzNodeKind_Dereference: return 8;
	case ffzNodeKind_Mul: // fallthrough
	case ffzNodeKind_Div: // fallthrough
	case ffzNodeKind_Modulo: return 7;
	case ffzNodeKind_Add: return 6;
	case ffzNodeKind_Sub: return 5;
	case ffzNodeKind_Less: // fallthrough
	case ffzNodeKind_LessOrEqual: // fallthrough
	case ffzNodeKind_Greater: // fallthrough
	case ffzNodeKind_GreaterOrEqual: return 4;
	case ffzNodeKind_Equal: // fallthrough
	case ffzNodeKind_NotEqual: return 3;
	case ffzNodeKind_LogicalAND: return 2;
	case ffzNodeKind_LogicalOR: return 1;
	case ffzNodeKind_Declare: // fallthrough
	case ffzNodeKind_Assign: return 0;
	default: F_ASSERT(false);
	}
	return 0;
}

u8 ffz_get_bracket_op_open_char(ffzNodeKind kind) {
	switch (kind) {
	case ffzNodeKind_PreSquareBrackets: return '[';
	case ffzNodeKind_PostSquareBrackets: return '[';
	case ffzNodeKind_PostRoundBrackets: return '(';
	case ffzNodeKind_PostCurlyBrackets: return '{';
	}
	return 0;
}

u8 ffz_get_bracket_op_close_char(ffzNodeKind kind) {
	switch (kind) {
	case ffzNodeKind_PreSquareBrackets: return ']';
	case ffzNodeKind_PostSquareBrackets: return ']';
	case ffzNodeKind_PostRoundBrackets: return ')';
	case ffzNodeKind_PostCurlyBrackets: return '}';
	}
	return 0;
}

static void _print_ast(fArrayRaw* builder, ffzNode* node, uint tab_level) {
	fAllocator* temp = f_temp_push();
	if (false) {
		f_str_print(builder, F_LIT(" <"));
		f_str_print(builder, ffzNodeKind_to_string[node->kind]);
		f_str_printf(builder, "|%d:%d-%d:%d", node->loc.start.line_num, node->loc.start.column_num, node->loc.end.line_num, node->loc.end.column_num);
			//str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		//str_print(builder, F_LIT(", line="));
		//str_print(builder, str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		f_str_print(builder, F_LIT(">"));
	}
	
	if (node->flags & ffzNodeFlag_IsStandaloneTag) {
		f_str_print(builder, F_LIT("\\"));
	}

	for (ffzNode* tag = node->first_tag; tag; tag = tag->next) {
		f_str_print(builder, F_LIT("@"));
		_print_ast(builder, tag, tab_level);
		f_str_print(builder, F_LIT(" "));
	}

	switch (node->kind) {
	//case ffzNodeKind_Declare: {
	//	
	//	_print_ast(builder, node.Targeted)->lhs, tab_level);
	//	f_str_print(builder, F_LIT(": "));
	//	_print_ast(builder, AS(node,Targeted)->rhs, tab_level);
	//} break;
	//
	//case ffzNodeKind_Assignment: {
	//	_print_ast(builder, AS(node, Targeted)->lhs, tab_level);
	//	f_str_print(builder, F_LIT("= "));
	//	_print_ast(builder, AS(node, Targeted)->rhs, tab_level);
	//} break;

	case ffzNodeKind_Keyword: {
		f_str_print(builder, ffzKeyword_to_string[node->Keyword.keyword]);
	} break;

	//case ffzNodeKind_UserTagDecl: // fallthrough
	//case ffzNodeKind_CompilerTagDecl: {
	//	f_str_print(builder, F_LIT("@"));
	//	f_str_print(builder, AS(node, TagDecl)->tag);
	//	f_str_print(builder, F_LIT(": "));
	//	_print_ast(builder, AS(node,TagDecl)->rhs, tab_level);
	//} break;

	case ffzNodeKind_PostRoundBrackets: // fallthrough
	case ffzNodeKind_PostSquareBrackets: // fallthrough
	case ffzNodeKind_PostCurlyBrackets: {
		f_str_print_rune(builder, '(');
		_print_ast(builder, node->Op.left, tab_level);

		u8 open_char = ffz_get_bracket_op_open_char(node->kind);
		u8 close_char = ffz_get_bracket_op_close_char(node->kind);

		bool multi_line = node->kind == ffzNodeKind_PostCurlyBrackets;
		if (multi_line) {
			f_str_print_rune(builder, ' ');
			f_str_print_rune(builder, open_char);
			f_str_print_rune(builder, '\n');
			for (ffzNode* n = node->first_child; n; n = n->next) {
				f_str_print_repeat(builder, F_LIT("\t"), tab_level + 1);
				_print_ast(builder, n, tab_level + 1);
				f_str_print(builder, F_LIT("\n"));
			}
			f_str_print_repeat(builder, F_LIT("\t"), tab_level);
		}
		else {
			f_str_print_rune(builder, open_char);
			for (ffzNode* n = node->first_child; n; n = n->next) {
				if (n != node->first_child) f_str_print(builder, F_LIT(", "));
				_print_ast(builder, n, tab_level + (uint)multi_line);
			}
		}
		f_str_print_rune(builder, close_char);
		f_str_print_rune(builder, ')');
	} break;

	case ffzNodeKind_PreSquareBrackets: {
		f_str_print_rune(builder, '[');
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_str_print(builder, F_LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		f_str_print_rune(builder, ']');
		_print_ast(builder, node->Op.right, tab_level);
	} break;

	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_UnaryPlus: // fallthrough
	case ffzNodeKind_AddressOf: // fallthrough
	case ffzNodeKind_PointerTo: // fallthrough
	case ffzNodeKind_LogicalNOT: {
		f_str_print_rune(builder,'(');
		f_str_print(builder, ffzNodeKind_to_string[node->kind]);
		_print_ast(builder, node->Op.right, tab_level);
		f_str_print_rune(builder,')');
	} break;

	// postfix operator
	case ffzNodeKind_Dereference: {
		f_str_print_rune(builder,'(');
		_print_ast(builder, node->Op.left, tab_level);
		f_str_print(builder, ffzNodeKind_to_string[node->kind]);
		f_str_print_rune(builder,')');
	} break;
	
	case ffzNodeKind_Identifier: {
		if (node->Identifier.is_constant) f_str_print(builder, F_LIT("#"));
		f_str_print(builder, node->Identifier.name);
	} break;

	case ffzNodeKind_Record: {
		f_str_print(builder, node->Record.is_union ? F_LIT("union") : F_LIT("struct"));

		if (node->Record.polymorphic_parameters) {
			_print_ast(builder, node->Record.polymorphic_parameters, tab_level);
		}
		f_str_print(builder, F_LIT("{"));
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_str_print(builder, F_LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		f_str_print(builder, F_LIT("}"));
	} break;

	case ffzNodeKind_Enum: {
		f_str_print(builder, F_LIT("enum"));
		if (node->Enum.internal_type) {
			f_str_print(builder, F_LIT(", "));
			_print_ast(builder, node->Enum.internal_type, tab_level);
		}
		f_str_print(builder, F_LIT(" {"));
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_str_print(builder, F_LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		f_str_print(builder, F_LIT("}"));
	} break;

	case ffzNodeKind_ProcType: {
		f_str_print(builder, F_LIT("proc"));
		
		if (node->ProcType.polymorphic_parameters) {
			_print_ast(builder, node->ProcType.polymorphic_parameters, tab_level);
		}

		if (node->first_child) {
			f_str_print(builder, F_LIT("("));
			for (ffzNode* n = node->first_child; n; n = n->next) {
				if (n != node->first_child) f_str_print(builder, F_LIT(", "));
				_print_ast(builder, n, tab_level);
			}
			f_str_print(builder, F_LIT(")"));
		}

		if (node->ProcType.out_parameter) {
			f_str_print(builder, F_LIT(" => "));
			_print_ast(builder, node->ProcType.out_parameter, tab_level);
			f_str_print(builder, F_LIT(""));
		}

		//str_print(builder, F_LIT(" {\n"));
		//for (AstNode* n = node->Procedure.nodes.first; n; n = n->next) {
		//	for (int j = 0; j < tab_level + 1; j++) str_print(builder, F_LIT("    "));
		//	_print_ast(builder, n, tab_level + 1);
		//
		//	str_print(builder, F_LIT("\n"));
		//}
		//for (int j=0; j< tab_level; j++) str_print(builder, F_LIT("    "));
		//str_print(builder, F_LIT("}\n"));

	} break;

	case ffzNodeKind_Return: {
		f_str_print(builder, F_LIT("ret"));

		if (node->Return.value) {
			f_str_print(builder, F_LIT(" "));
			_print_ast(builder, node->Return.value, tab_level);
		}
	} break;

	case ffzNodeKind_Scope: {
		f_str_print(builder, F_LIT("{\n"));

		for (ffzNode* n = node->first_child; n; n = n->next) {
			for (int j = 0; j < tab_level + 1; j++) f_str_print(builder, F_LIT("    "));
			_print_ast(builder, n, tab_level + 1);

			f_str_print(builder, F_LIT("\n"));
		}

		for (int j = 0; j < tab_level; j++) f_str_print(builder, F_LIT("    "));
		f_str_print(builder, F_LIT("}\n"));
	} break;

	case ffzNodeKind_IntLiteral: {
		f_str_print(builder, f_str_from_uint(F_AS_BYTES(node->IntLiteral.value), temp));
	} break;

	case ffzNodeKind_StringLiteral: {
		// TODO: print escaped strings
		f_str_print(builder, F_LIT("\""));
		f_str_print(builder, node->StringLiteral.zero_terminated_string);
		f_str_print(builder, F_LIT("\""));
	} break;

	//case ffzNodeKind_FloatLiteral: {
	//	str_print(builder, str_from_float(temp, AS_BYTES(node->Float.value)));
	//} break;

	case ffzNodeKind_If: {
		f_str_print(builder, F_LIT("if "));
		_print_ast(builder, node->If.condition, tab_level);
		f_str_print(builder, F_LIT(" "));
		F_ASSERT(node->If.true_scope);
		_print_ast(builder, node->If.true_scope, tab_level);

		if (node->If.else_scope) {
			for (int j = 0; j < tab_level; j++) f_str_print(builder, F_LIT("    "));
			f_str_print(builder, F_LIT("else \n"));
			_print_ast(builder, node->If.else_scope, tab_level);
		}

	} break;

	case ffzNodeKind_For: {
		f_str_print(builder, F_LIT("for "));
		for (int i = 0; i < 3; i++) {
			if (node->For.header_stmts[i]) {
				if (i > 0) f_str_print(builder, F_LIT(", "));
				_print_ast(builder, node->For.header_stmts[i], tab_level);
			}
		}

		f_str_print(builder, F_LIT(" "));
		_print_ast(builder, node->For.scope, tab_level);
	} break;

	case ffzNodeKind_Blank: { f_str_print(builder, F_LIT("_")); } break;
	case ffzNodeKind_Dot: { f_str_print(builder, F_LIT(".")); } break;

	case ffzNodeKind_PolyParamList: {
		f_str_print(builder, F_LIT("["));
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_str_print(builder, F_LIT(", "));
			_print_ast(builder, n, tab_level);
		}
		f_str_print(builder, F_LIT("]"));
	} break;

	default: {
		if (ffz_node_is_operator(node->kind)) {
			f_str_print(builder, F_LIT("("));
			_print_ast(builder, node->Op.left, tab_level);

			f_str_print(builder, F_LIT(" "));
			f_str_print(builder, ffzNodeKind_to_string[node->kind]);
			f_str_print(builder, F_LIT(" "));

			_print_ast(builder, node->Op.right, tab_level);
			f_str_print(builder, F_LIT(")"));
		}
		else F_BP;
	} break;

	}
	f_temp_pop();
}

fString ffz_print_ast(fAllocator* alc, ffzNode* node) {
	fArrayRaw builder = { .alc = alc };
	_print_ast(&builder, node, 0);
	return (fString){ builder.data, builder.len };
}

//static ffzOk parse_expression(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets);
//static ffzOk parse_value(ffzParser* p, ffzNode* parent, ffzNode** out);

#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\r')

typedef struct ParserState {
	ffzParser* parser;
	ffzNode* pending_tag;
	ffzLoc loc;
} ParserState;

typedef enum ParseFlags {
	ParseFlag_NewlineIsWhitespace = 1 << 0,
} ParseFlags;

static ffzOk parse_node(ParserState* state, ffzNode* parent, ffzNode** out);

// https://justine.lol/endian.html
#define READ32BE(p) (u32)(255 & p[0]) << 24 | (255 & p[1]) << 16 | (255 & p[2]) << 8 | (255 & p[3])

// returns an empty token when the end of file is reached.
static Token maybe_eat_next_token(ParserState* state, ParseFlags flags) {
	typedef enum CharType {
		CharType_Alphanumeric,
		CharType_Whitespace,
		CharType_Symbol,
	} CharType;

	CharType prev_type = CharType_Whitespace;
	s32 prev_r;

	ffzLoc tok_start = state->loc;
	//ffzLocRange token_range = ffz_loc_to_range(*pos);
	//bool inside_line_comment = false;

	for (;;) {
		uint next = state->loc.offset;
		rune r = f_str_next_rune(state->parser->source_code, &next);
		if (!r) break;

		CharType type = CharType_Symbol;
		if ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r > 128) {
			type = CharType_Alphanumeric;
		}
		else if (IS_WHITESPACE(r)) {
			type = CharType_Whitespace;
		}
		else if (r == '\n' && (flags & ParseFlag_NewlineIsWhitespace)) {
			type = CharType_Whitespace;
		}
		
		if (prev_type != CharType_Whitespace && type != prev_type) break;

		if (prev_type == CharType_Symbol) {
			// We need to manually check for some cases where symbols should be joined.
			// Or maybe this checking should be done outside of this function?
			bool join_symbol = false;
			if (prev_r == '|' && r == '|') join_symbol = true;
			if (prev_r == '&' && r == '&') join_symbol = true;
			if (prev_r == '=' && (r == '=' || r == '>')) join_symbol = true; // =>, ==
			if (prev_r == '<') join_symbol = true; // <<, <=
			if (prev_r == '>') join_symbol = true; // >>, >=
			if (prev_r == '!' && r == '=') join_symbol = true; // != should join, but e.g. !! and !~ shouldn't join
			if (prev_r == '*' && r == '/') join_symbol = true; // join comment block enders

			// We should skip the comments here and insert them to the tree

			if (!join_symbol) {
				break;
			}
		}

		if (r == '\n') {
			state->loc.line_num += 1;
			state->loc.column_num = 0;
		}

		state->loc.offset = (u32)next;
		state->loc.column_num += 1;

		if (type == CharType_Whitespace) tok_start = state->loc;

		prev_type = type;
		prev_r = r;
	}

	Token tok = { 0 };
	tok.range.start = tok_start;
	tok.range.end = state->loc;
	tok.str = f_str_slice(state->parser->source_code, tok.range.start.offset, tok.range.end.offset);
	memcpy(&tok.small, tok.str.data, F_MIN(tok.str.len, sizeof(tok.small)));
	return tok;
}

static ffzOk eat_next_token(ParserState* state, ParseFlags flags, const char* task_verb, Token* out) {
	*out = maybe_eat_next_token(state, flags);
	if (out->str.len == 0) {
		ERR(state, ffz_loc_to_range(state->loc), "File ended unexpectedly when %s.", task_verb);
	}
	return FFZ_OK;
}

static ffzOk eat_expected_token(ParserState* state, fString expected) {
	Token tok = maybe_eat_next_token(state, ParseFlag_NewlineIsWhitespace);
	if (!f_str_equals(tok.str, expected)) ERR(state, tok.range, "Expected \"%.*s\"; got \"%.*s\"", F_STRF(expected), F_STRF(tok.str));
	return FFZ_OK;
}

//static ffzOk parse_statement_separator(ffzParser* p, ffzLoc* pos) {
//	Token tok;
//	TRY(eat_next_token(p, pos, false, "parsing a statement separator", &tok));
//	
//	if (!f_str_equals(tok.str, F_LIT("\n")) && !f_str_equals(tok.str, F_LIT(","))) {
//		ERR(p, tok.range, "Expected a statement separator character (either a comma or a newline).", "");
//	}
//	return ffz_ok;
//}

//static ffzOk peek_next_token(ffzParser* p, ffzLoc pos, bool ignore_newlines, const char* task_verb, Token* out) {
//	return eat_next_token(p, &pos, ignore_newlines, task_verb, out);
//}
//
//static ffzOk maybe_peek_next_token(ffzParser* p, ffzLoc pos, bool ignore_newlines, Token* out) {
//	return maybe_eat_next_token(p, &pos, ignore_newlines, out);
//}

#define NEW_NODE(kind, state, parent, range) new_node((state), (parent), (range), ffzNodeKind_##kind)

static void* new_node(ParserState* state, ffzNode* parent, ffzLocRange range, ffzNodeKind kind) {
	ffzNode* node = f_mem_clone(ffzNode, (ffzNode){0}, state->parser->alc);
	//if (node == (void*)0x0000020000001a80) F_BP;
	//memset(node, 0, size);
	node->id.parser_id = state->parser->id;
	node->id.local_id = state->parser->next_local_id++;
	node->parent = parent;
	node->kind = kind;
	node->loc = range;
	//if (node->loc.start.offset == 4942) F_BP;
	return node;
}

static ffzOk parse_children(ParserState* state, ffzNode* parent, u8 bracket_close_char) {
	OPT(ffzNode*) prev = NULL;

	for (u32 i = 0;; i++) {
		ParserState new_state = *state;
		Token tok = maybe_eat_next_token(&new_state, ParseFlag_NewlineIsWhitespace);

		if (tok.small == bracket_close_char) {
			*state = new_state;
			//parent->loc.end = tok.end;
			break;
		}
		
		bool was_comma = false;
		if (i > 0) {
			Token tok = maybe_eat_next_token(state, (ParseFlags)0);
			was_comma = tok.small == ',';
			if (tok.small != '\n' && !was_comma) {
				ERR(state, tok.range, "Expected a node separator character (either a comma or a newline).", "");
			}
		}
		
		new_state = *state;
		tok = maybe_eat_next_token(&new_state, (ParseFlags)0);

		ffzNode* n;
		if ((tok.small == bracket_close_char && was_comma) || tok.small == ',') {
			// Node lists can have blank nodes, i.e.  {,1,,5,2,,1,}
			n = NEW_NODE(Blank, state, parent, tok.range);
		}
		else {
			TRY(parse_node(state, parent, &n));
		}

		if (prev) prev->next = n;
		else parent->first_child = n;
		prev = n;
	}
	return FFZ_OK;
}

static bool is_alnum_or_underscore(u8 c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c > 127;
}

/*static ffzOk parse_possible_tags(ffzParser* p, OPT(ffzNode*)* out_first_tag) {
	ffzNode* first = NULL;
	ffzNode* prev = NULL;
	for (;;) {
		Token tok;
		TRY(maybe_peek_next_token(p, p->pos, true, &tok));
		if (tok.str.len == 0 || !f_str_equals(tok.str, F_LIT("@"))) break;

		p->pos = tok.end;
			
		// NOTE: the parent is assigned later in assign_possible_tags_to_node
		ffzNode* tag;
		TRY(parse_value(p, NULL, &tag));
				
		if (!first) first = tag;
		if (prev) prev->next = tag;
		prev = tag;
	}
	*out_first_tag = first;
	return ffz_ok;
}*/

// Normally, we want to parse the tags before parsing and making the node they will be attached to.
// This procedure allows us to set the tags after the fact.
/*static void assign_possible_tags_to_node(ffzNode* node, OPT(ffzNode*) first_tag) {
	node->first_tag = first_tag;
	for (ffzNode* tag = first_tag; tag; tag = tag->next) {
		tag->parent = node;
	}
}*/

static ffzNodeOp* merge_operator_chain(fSlice(ffzNodeOp*) chain) {
	// Find the operator with the lowest precedence (pick the right-most
	// one if there are multiple operators with the same precedence)
	// and recursively call merge_operator_chain on both sides until no operators
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
	
	//    ^b * d > i + j
	//          / \
	//   (^b * d)
	//      /
	//   (^b)

	ffzNodeOp** data = chain.data;

	F_ASSERT(chain.len > 0);
	if (chain.len == 1) return data[0];

	uint lowest_prec_i = 0;
	uint lowest_prec = F_U64_MAX;
	for (uint i = chain.len - 1; i < chain.len; i--) {
		F_ASSERT(ffz_node_is_operator(data[i]->kind));
		uint prec = ffz_operator_get_precedence(data[i]->kind);
		if (prec < lowest_prec) {
			lowest_prec = prec;
			lowest_prec_i = i;
		}
	}

	ffzNodeOp* root = data[lowest_prec_i];
	if (lowest_prec_i > 0) {
		ffzNodeOp* left = merge_operator_chain(SLICE_BEFORE(ffzNodeOp*, chain, lowest_prec_i));
		if (root->Op.left) { // if this is an infix operator
			left->parent = (ffzNode*)root;
			root->Op.left = (ffzNode*)left;
		}
		else {
			// wrong asserts
			//F_ASSERT(left->right == (ffzNode*)root);
			//F_ASSERT(root->parent == (ffzNode*)left);
			return left;
		}
	}
	if (lowest_prec_i < chain.len - 1) {
		ffzNodeOp* right = merge_operator_chain(SLICE_AFTER(ffzNodeOp*, chain, lowest_prec_i + 1));
		if (root->Op.right) { // if this is an infix operator
			right->parent = (ffzNode*)root;
			root->Op.right = (ffzNode*)right;
		}
		else {
			// wrong asserts
			//F_ASSERT(right->left == (ffzNode*)root);
			//F_ASSERT(root->parent == (ffzNode*)right);
			return right;
		}
	}
	return root;
}

static ffzOk parse_node(ParserState* state, ffzNode* parent, ffzNode** out) {
	fArray(ffzNodeOp*) operator_chain = f_array_make_raw(state->parser->alc);

	// Start by parsing the operator chain

	bool check_infix_or_postfix = false;
	ffzNode* prev = NULL;
	for (;;) {
		ffzNode* node = NULL;
		
		ParserState state_before = *state;
		Token tok = maybe_eat_next_token(state, ParseFlag_NewlineIsWhitespace);
		if (!prev && tok.str.len == 0) {
			ERR(state, ffz_loc_to_range(state->loc), "File ended unexpectedly.", "");
		}
		
		if ((tok.small & 0xff) >= '0' && (tok.small & 0xff) <= '9') {
			u8 base = 10;
			if ((tok.small & 0xffff) == 'x0') { // :NoteAboutSeqLiterals
				base = 16;
				f_str_advance(&tok.str, 2);
			}
			else if ((tok.small & 0xffff) == 'b0') { // :NoteAboutSeqLiterals
				base = 2;
				f_str_advance(&tok.str, 2);
			}

			u64 numeric;
			if (!f_str_to_u64(tok.str, base, &numeric)) {
				ERR(state, tok.range, "Failed parsing numeric literal.", "");
			}

			node = NEW_NODE(IntLiteral, state, parent, tok.range);
			node->IntLiteral.value = numeric;
			node->IntLiteral.was_encoded_in_base = base;
		}

		if (tok.small == '(') { // parenthesized node
			TRY(parse_node(state, parent, &node));
			TRY(eat_expected_token(state, F_LIT(")")));
		}

		if (!node && (is_alnum_or_underscore((u8)tok.small) || tok.small == '#' || tok.small == '?')) {
			ffzKeyword* keyword = f_map64_get_raw(state->parser->keyword_from_string, f_hash64_str(tok.str));
			if (keyword) {
				node = NEW_NODE(Keyword, state, parent, tok.range);
				node->Keyword.keyword = *keyword;

				if (*keyword == ffzKeyword_import) {
					f_array_push(ffzNodeKeyword*, &state->parser->module_imports, node);
				}
			}
			else {
				// identifier!
				node = NEW_NODE(Identifier, state, parent, tok.range);
				if (tok.small == '#') {
					node->Identifier.is_constant = true;
					TRY(eat_next_token(state, true, "parsing an identifier", &tok));

					if (!is_alnum_or_underscore((u8)tok.small)) {
						ERR(state, tok.range, "Invalid character for constant identifier.", "");
					}
				}
				node->Identifier.name = tok.str;
			}
		}

		bool is_prefix_or_postfix = false;

		// Check to see if the next token is an operator.
		ffzNodeKind op_kind = 0;
		if (!node) {
			switch (tok.small) {
			case '^': {
				op_kind = check_infix_or_postfix ? ffzNodeKind_Dereference : ffzNodeKind_PointerTo;
				is_prefix_or_postfix = true;
			} break;
			case '-': {
				op_kind = check_infix_or_postfix ? ffzNodeKind_Sub : ffzNodeKind_UnaryMinus;
				is_prefix_or_postfix = !check_infix_or_postfix;
			} break;
			case '+': {
				op_kind = check_infix_or_postfix ? ffzNodeKind_Add : ffzNodeKind_UnaryPlus;
				is_prefix_or_postfix = !check_infix_or_postfix;
			} break;
			case '&': {
				if (!check_infix_or_postfix) {
					op_kind = ffzNodeKind_AddressOf; is_prefix_or_postfix = true;
				}
			} break;
			case '!': {
				if (!check_infix_or_postfix) {
					op_kind = ffzNodeKind_LogicalNOT; is_prefix_or_postfix = true;
				}
			} break;
			case '(': {
				if (check_infix_or_postfix) {
					op_kind = ffzNodeKind_PostRoundBrackets;
					is_prefix_or_postfix = true;
				}
			} break;
			case '[': {
				is_prefix_or_postfix = true;
				op_kind = check_infix_or_postfix ? ffzNodeKind_PostSquareBrackets : ffzNodeKind_PreSquareBrackets;
			} break;
			case ':': { op_kind = ffzNodeKind_Declare; } break;
			case '=': { op_kind = ffzNodeKind_Assign; } break;
			case '.': { op_kind = ffzNodeKind_MemberAccess; } break;
			case '&&': { op_kind = ffzNodeKind_LogicalAND; } break; // :NoteAboutSeqLiterals
			case '||': { op_kind = ffzNodeKind_LogicalOR; } break; // :NoteAboutSeqLiterals
			case '*': { op_kind = ffzNodeKind_Mul; } break;
			case '/': { op_kind = ffzNodeKind_Div; } break;
			case '%': { op_kind = ffzNodeKind_Modulo; } break;
			case '=<': { op_kind = ffzNodeKind_LessOrEqual; } break; // :NoteAboutSeqLiterals
			case '<': { op_kind = ffzNodeKind_Less; } break;
			case '=>': { op_kind = ffzNodeKind_GreaterOrEqual; } break; // :NoteAboutSeqLiterals
			case '>': { op_kind = ffzNodeKind_Greater; } break;
			case '==': { op_kind = ffzNodeKind_Equal; } break; // :NoteAboutSeqLiterals
			case '=!': { op_kind = ffzNodeKind_NotEqual; } break; // :NoteAboutSeqLiterals
			}

			if (op_kind) {
				node = new_node(state, parent, tok.range, op_kind);
				if (check_infix_or_postfix) node->Op.left = prev;
				f_array_push(ffzNodeOp*, &operator_chain, node);

				u8 bracket_op_close_char = ffz_get_bracket_op_close_char(op_kind);
				if (bracket_op_close_char) {
					TRY(parse_children(state, node, bracket_op_close_char));
				}
			}
		}
		
		if (!op_kind && check_infix_or_postfix) { // no more postfix / infix operator. Terminate the chain
			*state = state_before;
			break;
		}

		if (!node) {
			ERR(state, tok.range, "Failed parsing a value; unexpected token `%.*s`\n", F_STRF(tok.str));
		}

		if (!check_infix_or_postfix) {
			if (prev) {
				F_ASSERT(ffz_node_is_operator(prev->kind));
				prev->Op.right = node;
				node->parent = prev;
			}
		}

		if (!is_prefix_or_postfix) check_infix_or_postfix = !check_infix_or_postfix;
		prev = node;
	}
	
	ffzNode* node = prev;
	if (operator_chain.len > 0) {
		node = (ffzNode*)merge_operator_chain(operator_chain.slice);
	}

	*out = node;
	return FFZ_OK;
}

#if 0
static ffzOk parse_node(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets) {
	ffzNode* result = NULL;

	OPT(ffzNode*) first_tag;
	TRY(parse_possible_tags(p, &first_tag));
	ffzNodeFlags tag_flag = get_standalone_tag_flag(p);

	ffzLoc after_next = p->pos;
	Token tok;
	TRY(eat_next_token(p, &after_next, true, "parsing a statement", &tok));

	// check for ret / break / etc statements
	if (f_str_equals(tok.str, F_LIT("if"))) {
		p->pos = after_next;
		ffzNodeIf* if_stmt = NEW_NODE(If, p, parent, tok.range);
		TRY(parse_expression(p, (ffzNode*)if_stmt, &if_stmt->condition, true));
		TRY(parse_node(p, (ffzNode*)if_stmt, &if_stmt->true_scope, false));

		after_next = p->pos;
		TRY(maybe_eat_next_token(p, &after_next, true, &tok));
		if (f_str_equals(tok.str, F_LIT("else"))) {
			p->pos = after_next;
			TRY(parse_node(p, (ffzNode*)if_stmt, &if_stmt->else_scope, false));
		}
		if_stmt->loc.end = p->pos;
		result = (ffzNode*)if_stmt;
	}
	else if (f_str_equals(tok.str, F_LIT("for"))) {
		F_BP;//p->pos = after_next;
		//ffzNodeFor* for_loop = NEW_NODE(For, p, parent, tok.range);
		//for (int i = 0; i < 3; i++) {
		//	ffzLoc after_next = p->pos;
		//	Token next_tok;
		//	TRY(eat_next_token(p, &after_next, true, "parsing a for-loop header", &next_tok));
		//	if (f_str_equals(next_tok.str, F_LIT("{"))) break;
		//
		//	if (i > 0) {
		//		TRY(parse_statement_separator(p, &p->pos));
		//	}
		//
		//	after_next = p->pos;
		//	TRY(eat_next_token(p, &after_next, true, "parsing a for-loop header", &next_tok));
		//	if (f_str_equals(next_tok.str, F_LIT(","))) continue;
		//
		//	ffzNode* stmt;
		//	TRY(parse_node(p, (ffzNode*)for_loop, &stmt, true));
		//	for_loop->header_stmts[i] = stmt;
		//}
		//
		//TRY(parse_node(p, (ffzNode*)for_loop, &for_loop->scope, false));
		//for_loop->loc.end = p->pos;
		//result = (ffzNode*)for_loop;
	}
	else if (f_str_equals(tok.str, F_LIT("ret"))) {
		p->pos = after_next;
		ffzNodeReturn* ret = NEW_NODE(Return, p, parent, tok.range);

		TRY(maybe_eat_next_token(p, &after_next, false, &tok)); // With return statements, newlines do matter!
		if (f_str_equals(tok.str, F_LIT("\n"))) {
			p->pos = after_next;
		}
		else {
			TRY(parse_expression(p, (ffzNode*)ret, &ret->value, false));
		}
		ret->loc.end = p->pos;
		result = (ffzNode*)ret;
	}

	// first parse the expression on the left hand side
	if (!result) {
		TRY(parse_expression(p, parent, &result, stop_at_curly_brackets));

		ffzLoc after_next = p->pos;
		Token tok;
		TRY(maybe_eat_next_token(p, &after_next, false, &tok));

		if (tok.str.len == 1 && tok.str.data[0] == ':') {
			if (result->kind != ffzNodeKind_Identifier) {
				ERR(p, tok.range, "left-hand-side of a declaration must be an identifier.", "");
			}

			ffzNodeDeclaration* decl = NEW_NODE(Declaration, p, parent, result->loc);
			result->parent = (ffzNode*)decl;
			decl->name = AS(result,Identifier);
			
			p->pos = after_next;
			TRY(parse_expression(p, (ffzNode*)decl, &decl->rhs, stop_at_curly_brackets));
			decl->loc.end = decl->rhs->loc.end;
			result = (ffzNode*)decl;
		}
		else if (tok.str.len == 1 && tok.str.data[0] == '=') {
			ffzNodeAssignment* assignment = NEW_NODE(Assignment, p, parent, result->loc);
			result->parent = (ffzNode*)assignment;
			assignment->lhs = result;

			p->pos = after_next;
			TRY(parse_expression(p, (ffzNode*)assignment, &assignment->rhs, stop_at_curly_brackets));
			assignment->loc.end = assignment->rhs->loc.end;
			result = (ffzNode*)assignment;
		}
	}

	result->flags |= tag_flag;
	assign_possible_tags_to_node(result, first_tag);

	*out = result;
	return ffz_ok;
}
static ffzOk parse_enum(ffzParser* p, ffzNode* parent, ffzLocRange range, ffzNodeEnum** out) {
	ffzNodeEnum* node = NEW_NODE(Enum, p, parent, range);
	Token tok;
	TRY(eat_next_token(p, &p->pos, true, "parsing an enum", &tok));

	if (f_str_equals(tok.str, F_LIT(","))) {
		TRY(parse_expression(p, (ffzNode*)node, &node->internal_type, true));
		TRY(eat_next_token(p, &p->pos, true, "parsing an enum", &tok));
	}

	if (!f_str_equals(tok.str, F_LIT("{"))) ERR(p, tok.range, "Expected a `{`", "");
	TRY(parse_node_list(p, (ffzNode*)node, '}'));
	
	*out = node;
	return ffz_ok;
}

static ffzOk maybe_parse_polymorphic_parameter_list(ffzParser* p, ffzNode* parent, ffzNodePolyParamList** out) {
	Token tok;
	TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	if (f_str_equals(tok.str, F_LIT("["))) {
		p->pos = tok.end;
		ffzNodePolyParamList* node = NEW_NODE(PolyParamList, p, parent, tok.range);
		TRY(parse_node_list(p, (ffzNode*)node, ']'));
		*out = node;
	}
	return ffz_ok;
}

static ffzOk parse_struct(ffzParser* p, ffzNode* parent, ffzLocRange range, bool is_union, ffzNodeRecord** out) {
	ffzNodeRecord* node = NEW_NODE(Record, p, parent, range);
	TRY(maybe_parse_polymorphic_parameter_list(p, (ffzNode*)node, &node->polymorphic_parameters));

	Token tok;
	TRY(eat_next_token(p, &p->pos, true, "parsing a struct", &tok));
	if (!f_str_equals(tok.str, F_LIT("{"))) ERR(p, tok.range, "Expected a `{`", "");

	TRY(parse_node_list(p, (ffzNode*)node, '}'));

	node->is_union = is_union;
	*out = node;
	return ffz_ok;
}


static ffzOk parse_proc_type(ffzParser* p, ffzNode* parent, ffzLocRange range, ffzNodeProcType** out) {
	ffzNodeProcType* _proc = NEW_NODE(ProcType, p, parent, range);
	TRY(maybe_parse_polymorphic_parameter_list(p, (ffzNode*)_proc, &_proc->polymorphic_parameters));

	Token tok;
	TRY(peek_next_token(p, p->pos, true, "parsing a procedure", &tok));

	//if (str_equals(tok.str, F_LIT("["))) {
	//	BP;//p->pos = tok.end;
	//	//TRY(parse_node_list(p, (ffzNode*)proc, ']', &proc->ProcType.polymorphic_parameters));
	//	//TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	//}

	if (f_str_equals(tok.str, F_LIT("("))) {
		p->pos = tok.end;
		TRY(parse_node_list(p, (ffzNode*)_proc, ')'));
		TRY(maybe_peek_next_token(p, p->pos, true, &tok));
	}

	if (f_str_equals(tok.str, F_LIT("=>"))) {
		p->pos = tok.end;
		TRY(eat_expected_token(p, F_LIT("(")));
		TRY(parse_node(p, (ffzNode*)_proc, &_proc->out_parameter, false));
		TRY(eat_expected_token(p, F_LIT(")")));
	}
	_proc->loc.end = p->pos;
	*out = _proc;
	return ffz_ok;
}


static ffzOk parse_string_literal(ffzParser* p, fString* out) {
	fArrayRaw builder = {.alc = p->alc};

	ffzLoc start_pos = p->pos;

	for (;;) {
		uint next = p->pos.offset;
		rune r = f_str_next_rune(p->source_code, &next);
		if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.", "");
		if (r == '\n') {
			p->pos.line_num++;
			p->pos.column_num = 0;
		}

		if (r == '\\') {
			r = f_str_next_rune(p->source_code, &next);
			if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.", "");
			if (r == '\n') {
				p->pos.line_num++;
				p->pos.column_num = 0;
			}

			p->pos.offset = (u32)next;
			p->pos.column_num += 1;

			if (r == 'a')       f_str_print_rune(&builder, '\a');
			else if (r == 'b')  f_str_print_rune(&builder, '\b');
			else if (r == 'f')  f_str_print_rune(&builder, '\f');
			else if (r == 'f')  f_str_print_rune(&builder, '\f');
			else if (r == 'n')  f_str_print_rune(&builder, '\n');
			else if (r == 'r')  f_str_print_rune(&builder, '\r');
			else if (r == 't')  f_str_print_rune(&builder, '\t');
			else if (r == 'v')  f_str_print_rune(&builder, '\v');
			else if (r == '\\') f_str_print_rune(&builder, '\\');
			else if (r == '\'') f_str_print_rune(&builder, '\'');
			else if (r == '\"') f_str_print_rune(&builder, '\"');
			else if (r == '?')  f_str_print_rune(&builder, '\?');
			else if (r == '0')  f_str_print_rune(&builder, 0); // parsing octal characters is not supported like in C, with the exception of \0
			else if (r == 'x') {
				//if (p->pos.remaining.len < 2) PARSER_ERROR(p, p->pos, F_LIT("File ended unexpectedly when parsing a string literal."));
				F_ASSERT(p->pos.offset + 2 <= p->source_code.len);

				fString byte = f_str_slice(p->source_code, p->pos.offset, p->pos.offset + 2);
				p->pos.offset += 2;
				p->pos.column_num += 2;

				s64 byte_value;
				if (f_str_to_s64(byte, 16, &byte_value)) {
					f_str_print_rune(&builder, (u8)byte_value);
				}
				else ERR(p, ffz_loc_to_range(p->pos), "Failed parsing a hexadecimal byte.", "");
			}
			else ERR(p, ffz_loc_to_range(p->pos), "Invalid escape sequence.", "");
		}
		else {
			fString codepoint = f_str_slice(p->source_code, p->pos.offset, next);
			p->pos.offset = (u32)next;
			p->pos.column_num += 1;

			if (r == '\"') break;
			if (r == '\r') continue; // Ignore carriage returns

			f_str_print(&builder, codepoint);
		}
	}

	f_str_print_rune(&builder, '\0');
	*out = f_str_slice_before(*(fString*)&builder.slice, builder.slice.len - 1);
	return ffz_ok;
}

// TODO: return a boolean saying if there were multiple tags with the same identifier
//OPT(ffzNodeTag*) ffz_get_compiler_tag_by_name(ffzNode* node, fString tag) {
//	for (ffzNodeTag* n = node->first_tag; n; n = (ffzNodeTag*)n->next) {
//		if (n->kind == ffzNodeKind_CompilerTag && f_str_equals(n->tag, tag)) return n;
//	}
//	return NULL;
//}
//
//OPT(ffzNodeTag*) ffz_get_user_tag_by_name(ffzNode* node, fString tag) {
//	for (ffzNodeTag* n = node->first_tag; n; n = (ffzNodeTag*)n->next) {
//		if (n->kind == ffzNodeKind_UserTag && f_str_equals(n->tag, tag)) return n;
//	}
//	return NULL;
//}




static ffzOk parse_value_recursing_to_left(ffzParser* p, ffzNode* parent, ffzNode** out) {
	ffzNode* first_tag;
	TRY(parse_possible_tags(p, &first_tag));

	Token tok;
	TRY(eat_next_token(p, &p->pos, true, "parsing a value", &tok));

	ffzNode* result = NULL;

	u8 c = tok.str.data[0];
	
	if (c >= '0' && c <= '9') {
		u8 base = 10;
		if (f_str_starts_with(tok.str, F_LIT("0x"))) {
			base = 16;
			f_str_advance(&tok.str, 2);
		}
		else if (f_str_starts_with(tok.str, F_LIT("0b"))) {
			base = 16;
			f_str_advance(&tok.str, 2);
		}

		u64 numeric;
		if (!f_str_to_u64(tok.str, base, &numeric)) {
			ERR(p, tok.range, "Failed parsing numeric literal.", "");
		}

		ffzNodeIntLiteral* node = NEW_NODE(IntLiteral, p, parent, tok.range);
		node->value = numeric;
		node->was_encoded_in_base = base;
		*out = (ffzNode*)node;
		return ffz_ok;
	}

	if (c == '{') {
		result = NEW_NODE(Scope, p, parent, tok.range);
		TRY(parse_node_list(p, result, '}'));
	}
	else if (c == '(') {
		TRY(parse_expression(p, parent, &result, false));
		TRY(eat_expected_token(p, F_LIT(")")));
	}
	else if (c == '\"') {
		ffzNodeStringLiteral* lit = NEW_NODE(StringLiteral, p, parent, tok.range);
		TRY(parse_string_literal(p, &lit->zero_terminated_string));
		lit->loc.end = p->pos;
		result = (ffzNode*)lit;
	}
	else if (f_str_equals(tok.str, F_LIT("proc"))) {
		TRY(parse_proc_type(p, parent, tok.range, (ffzNodeProcType**)&result));
	}
	else if (f_str_equals(tok.str, F_LIT("enum"))) {
		TRY(parse_enum(p, parent, tok.range, (ffzNodeEnum**)&result));
	}
	else if (f_str_equals(tok.str, F_LIT("struct"))) {
		TRY(parse_struct(p, parent, tok.range, false, (ffzNodeRecord**)&result));
	}
	else if (f_str_equals(tok.str, F_LIT("union"))) {
		TRY(parse_struct(p, parent, tok.range, true, (ffzNodeRecord**)&result));
	}
	else if (is_alnum_or_underscore(c) || c == '#' || c == '?') {
		for (uint i = 0; i < F_LEN(ffz_keyword_to_string); i++) {
			if (f_str_equals(tok.str, ffz_keyword_to_string[i])) {
				result = NEW_NODE(Keyword, p, parent, tok.range);
				result->Keyword.keyword = (ffzKeyword)i;
				
				if (i == ffzKeyword_import) {
					f_array_push(ffzNodeKeyword*, &p->module_imports, AS(result, Keyword));
				}

				break;
			}
		}

		if (!result) {
			// identifier!
			result = NEW_NODE(Identifier, p, parent, tok.range);
			if (c == '#') {
				AS(result,Identifier)->is_constant = true;
				TRY(eat_next_token(p, &p->pos, true, "parsing an identifier", &tok));
				c = tok.str.data[0];

				if (!is_alnum_or_underscore(c)) {
					ERR(p, tok.range, "Invalid character for constant identifier.", "");
				}
			}
			AS(result,Identifier)->name = tok.str;
		}
	}
	else if (c == '.') {
		Token next;
		TRY(maybe_peek_next_token(p, p->pos, true, &next));
		if (next.str.len == 0 || !is_alnum_or_underscore(next.str.data[0])) { // otherwise it's an unary member access
			result = NEW_NODE(Dot, p, parent, tok.range);
		}
	}

	if (!result) {
		ffzNodeKind kind = ffzNodeKind_Invalid;
		if (c == '-') kind = ffzNodeKind_UnaryMinus;
		else if (c == '+') kind = ffzNodeKind_UnaryPlus;
		//else if (c == '.') kind = ffzNodeKind_UnaryMemberAccess;
		else if (c == '&') kind = ffzNodeKind_AddressOf;
		else if (c == '!') kind = ffzNodeKind_LogicalNOT;
		else if (c == '^') kind = ffzNodeKind_PointerTo;
		else if (c == '[') kind = ffzNodeKind_PreSquareBrackets;
		if (kind) {
			result = NEW_NODE(Operator, p, parent, tok.range);
			AS(result,Operator)->op_kind = kind;

			if (kind == ffzNodeKind_PreSquareBrackets) {
				TRY(parse_node_list(p, result, ']'));
			}

			bool recurse_to_left = /*c == '^' || */kind == ffzNodeKind_PreSquareBrackets;

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

	if (!result) ERR(p, tok.range, "Failed parsing a value; unexpected token `%s`\n", f_str_to_cstr(tok.str, p->alc));
	assign_possible_tags_to_node(result, first_tag);

	*out = result;
	return ffz_ok;
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

		ffzNodeKind op_kind = ffzNodeKind_Invalid;
		if (next.str.data[0] == '^') op_kind = ffzNodeKind_Dereference;
		if (next.str.data[0] == '.') op_kind = ffzNodeKind_MemberAccess;
		if (op_kind) {
			p->pos = after_next;
			
			ffzLocRange range = { result->loc.start, next.range.end };
			ffzNodeOp* op = NEW_NODE(Operator, p, parent, range);
			op->op_kind = op_kind;
			op->left = result;
			result->parent = (ffzNode*)op;

			if (op_kind == ffzNodeKind_MemberAccess) {
				TRY(parse_value_recursing_to_left(p, (ffzNode*)op, &op->right));
				op->loc.end = op->right->loc.end;
			}
			result = (ffzNode*)op;
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
			op_kind = ffzNodeKind_PostRoundBrackets;
			close_bracket_char = ')';
		}
		else if (next.str.data[0] == '[') {
			op_kind = ffzNodeKind_PostSquareBrackets;
			close_bracket_char = ']';
		}
		else if (!p->stop_at_curly_brackets && next.str.data[0] == '{') {
			op_kind = ffzNodeKind_PostCurlyBrackets;
			close_bracket_char = '}';
		}
		if (op_kind) {
			p->pos = after_next;

			ffzLocRange range = { result->loc.start, p->pos };
			ffzNodeOp* op = NEW_NODE(Operator, p, parent, range);
			op->op_kind = op_kind;
			op->left = result;
			result->parent = (ffzNode*)op;

			TRY(parse_node_list(p, (ffzNode*)op, close_bracket_char));
			result = (ffzNode*)op;
			continue;
		}

		break; // End of the chain
	}
	*out = result;
	return ffz_ok;
}

static ffzOk parse_expression(ffzParser* p, ffzNode* parent, ffzNode** out, bool stop_at_curly_brackets) {
	bool stop_bef = p->stop_at_curly_brackets;
	p->stop_at_curly_brackets = stop_at_curly_brackets;

	Array(ffzNodeOp*) operator_chain = { .alc = p->alc };

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
			if (tok.str.len == 0 || f_str_equals(tok.str, F_LIT(")"))) break;

			// this should be a hash table
			const ffzNodeKind TwoSidedOperators[] = {
				ffzNodeKind_Add,
				ffzNodeKind_Sub,
				ffzNodeKind_Mul,
				ffzNodeKind_Div,
				ffzNodeKind_Modulo,
				ffzNodeKind_Equal,
				ffzNodeKind_NotEqual,
				ffzNodeKind_Less,
				ffzNodeKind_LessOrEqual,
				ffzNodeKind_Greater,
				ffzNodeKind_GreaterOrEqual,
				ffzNodeKind_LogicalAND,
				ffzNodeKind_LogicalOR,
			};

			ffzNodeKind kind = ffzNodeKind_Invalid;
			for (int i = 0; i < F_LEN(TwoSidedOperators); i++) {
				ffzNodeKind test = TwoSidedOperators[i];
				if (f_str_equals(ffzNodeKind_String[test], tok.str)) {
					kind = test;
					break;
				}
			}
			if (kind == ffzNodeKind_Invalid) break;

			ffzLocRange range = { prev->loc.start, tok.end };
			node = NEW_NODE(Operator, p, parent, range);
			AS(node,Operator)->op_kind = kind;
			AS(node,Operator)->left = prev;
			prev->parent = node;

			f_array_push(ffzNodeOp*, &operator_chain, AS(node,Operator));
			p->pos = after_next;
		}

		expecting_value = !expecting_value;
		prev = node;
	}

	ffzNode* root = prev;
	if (operator_chain.len > 0) {
		root = (ffzNode*)find_root_operator(operator_chain.slice);
	}
	root->loc.end = p->pos;

	p->stop_at_curly_brackets = stop_bef;

	if (!root) ERR(p, (ffzLocRange){0}, "Empty expression.", "");
	*out = root;
	return ffz_ok;
}

#endif

ffzOk ffz_parse(ffzParser* p) {
	ParserState state = {0};
	state.parser = p;
	state.loc.line_num = 1;
	state.loc.column_num = 1;
	p->root = NEW_NODE(Scope, &state, NULL, (ffzLocRange){0});

	TRY(parse_children(&state, (ffzNode*)p->root, 0));
	//ffzNode* n;
	//ffzOk ok = parse_node(&state, (ffzNode*)p->root, &n);

	//p->root->first_child = n;
	
	return FFZ_OK;
}

OPT(ffzNode*) ffz_skip_standalone_tags(OPT(ffzNode*) node) {
	for (; node && node->flags & ffzNodeFlag_IsStandaloneTag; node = node->next) {}
	return node;
}

ffzNode* ffz_get_child(ffzNode* parent, u32 idx) {
	u32 i = 0;
	for FFZ_EACH_CHILD(n, parent) {
		if (i == idx) return n;
		i++;
	}
	F_ASSERT(false);
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
	F_ASSERT(false);
	return F_U32_MAX;
}

OPT(ffzNodeOpDeclare*) ffz_get_parent_decl(OPT(ffzNode*) node) {
	return (node && node->parent->kind == ffzNodeKind_Declare) ? (ffzNodeOpDeclare*)node->parent : NULL;
}

fString ffz_get_parent_decl_name(OPT(ffzNode*) node) {
	ffzNodeOpDeclare* decl = ffz_get_parent_decl(node);
	return decl ? decl->Op.left->Identifier.name : (fString) { 0 };
}

// :NoteAboutSeqLiterals
// when comparing agains a C character sequence literal, i.e. foo == 'abc', we need to 
// flip the byte order of the literal, because C represents them in big-endian format.