#define FOUNDATION_HELPER_MACROS
#include "foundation/foundation.h"

#include "ffz_ast.h"

#define TRY(x) { if ((x).ok == false) return (ffzOk){false}; }

#define OPT(ptr) ptr

#define ERR(p, at, fmt, ...) { \
	p->report_error(p, at, f_str_format(p->alc, fmt, __VA_ARGS__)); \
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

#define NODE_KIND_TO_STRING \
	X("", "invalid")\
	X("", "blank")\
	X("", "identifier")\
	X("", "polymorphic-parameter")\
	X("", "keyword")\
	X("", "this-value-dot")\
	X("", "proc-type")\
	X("", "struct")\
	X("", "enum")\
	X("", "return")\
	X("", "if")\
	X("", "for")\
	X("", "scope")\
	X("", "int-literal")\
	X("", "string-literal")\
	X("", "float-literal")\
	X(":", "declaration")\
	X("=", "assignment")\
	X("+", "addition")\
	X("-", "subtraction")\
	X("*", "multiplication")\
	X("/", "division")\
	X("%", "modulo")\
	X(".", "member-access")\
	X("==", "equal-to")\
	X("!=", "not-equal-to")\
	X("<", "less-than")\
	X("<=", "less-than-or-equal")\
	X(">", "greater-than")\
	X(">=", "greater-than-or-equal")\
	X("&&", "logical-AND")\
	X("||", "logical-OR")\
	X("", "pre-square-brackets")\
	X("-", "unary-minus")\
	X("+", "unary-plus")\
	X("&", "address-of")\
	X("^", "pointer-to")\
	X("!", "logical-NOT")\
	X("", "post-square-brackets")\
	X("", "post-round-brackets")\
	X("", "post-curly-brackets")\
	X("^", "dereference")

static const fString ffzNodeKind_to_name[] = {
#define X(op_string, name) F_LIT_COMP(name),
	NODE_KIND_TO_STRING
#undef X
};

static const fString ffzNodeKind_to_op_string[] = {
#define X(op_string, name) F_LIT_COMP(op_string),
	NODE_KIND_TO_STRING
#undef X
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
	F_LIT_COMP("f32"),
	F_LIT_COMP("f64"),
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
	F_LIT_COMP("extern"),
	F_LIT_COMP("using"),
	F_LIT_COMP("global"),
	F_LIT_COMP("module_defined_entry"),
};

F_STATIC_ASSERT(F_LEN(ffzNodeKind_to_name) == ffzNodeKind_COUNT);
F_STATIC_ASSERT(F_LEN(ffzKeyword_to_string) == ffzKeyword_COUNT);

fString ffz_node_kind_to_string(ffzNodeKind kind) { return ffzNodeKind_to_name[kind]; }
char* ffz_node_kind_to_cstring(ffzNodeKind kind) { return (char*)ffzNodeKind_to_name[kind].data; }

fString ffz_node_kind_to_op_string(ffzNodeKind kind) { return ffzNodeKind_to_op_string[kind]; }
char* ffz_node_kind_to_op_cstring(ffzNodeKind kind) { return ffzNodeKind_to_op_string[kind].data;}

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
	const fString tab_str = F_LIT("    ");

	if (false) {
		f_str_print(builder, F_LIT(" <"));
		f_str_print(builder, ffz_node_kind_to_string(node->kind));
		f_str_printf(builder, "|%d:%d-%d:%d", node->loc.start.line_num, node->loc.start.column_num, node->loc.end.line_num, node->loc.end.column_num);
			//str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		//str_print(builder, F_LIT(", line="));
		//str_print(builder, str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		f_str_print(builder, F_LIT(">"));
	}

	// TODO: this is incomplete!!
	// `@using a: b` is different from `(@using a): b`, but they both will currently be printed the same.
	for (ffzNode* tag = node->first_tag; tag; tag = tag->next) {
		f_str_print(builder, F_LIT("@"));
		_print_ast(builder, tag, tab_level);
		f_str_print(builder, F_LIT(" "));
	}

	if (node->flags & ffzNodeFlag_IsStandaloneTag) {
		f_str_print(builder, F_LIT("$"));
	}

	switch (node->kind) {

	case ffzNodeKind_Keyword: {
		if (ffz_keyword_is_extended(node->Keyword.keyword)) f_str_printf(builder, "*");
		f_str_print(builder, ffzKeyword_to_string[node->Keyword.keyword]);
	} break;

	case ffzNodeKind_PostRoundBrackets: // fallthrough
	case ffzNodeKind_PostSquareBrackets: // fallthrough
	case ffzNodeKind_PostCurlyBrackets: {
		//f_str_print_rune(builder, '(');
		_print_ast(builder, node->Op.left, tab_level);

		u8 open_char = ffz_get_bracket_op_open_char(node->kind);
		u8 close_char = ffz_get_bracket_op_close_char(node->kind);

		
		bool multi_line = node->kind == ffzNodeKind_PostCurlyBrackets; //ffz_get_child_count(node) >= 3 ||
		if (multi_line) {
			f_str_print_rune(builder, ' ');
			f_str_print_rune(builder, open_char);
			f_str_print_rune(builder, '\n');
			for (ffzNode* n = node->first_child; n; n = n->next) {
				f_str_print_repeat(builder, tab_str, tab_level + 1);
				_print_ast(builder, n, tab_level + 1);
				f_str_print(builder, F_LIT("\n"));
			}
			f_str_print_repeat(builder, tab_str, tab_level);
		}
		else {
			f_str_print_rune(builder, open_char);
			for (ffzNode* n = node->first_child; n; n = n->next) {
				if (n != node->first_child) f_str_print(builder, F_LIT(", "));
				_print_ast(builder, n, tab_level);
			}
		}
		f_str_print_rune(builder, close_char);
		//f_str_print_rune(builder, ')');
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
		//f_str_print_rune(builder,'(');
		f_str_print(builder, ffzNodeKind_to_op_string[node->kind]);
		_print_ast(builder, node->Op.right, tab_level);
		//f_str_print_rune(builder,')');
	} break;

	// postfix operator
	case ffzNodeKind_Dereference: {
		//f_str_print_rune(builder,'(');
		_print_ast(builder, node->Op.left, tab_level);
		f_str_print(builder, ffzNodeKind_to_op_string[node->kind]);
		//f_str_print_rune(builder,')');
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
			f_str_print_repeat(builder, tab_str, tab_level + 1);
			_print_ast(builder, n, tab_level + 1);
			f_str_print(builder, F_LIT("\n"));
		}

		f_str_print_repeat(builder, tab_str, tab_level);
		f_str_print(builder, F_LIT("}\n"));
	} break;

	case ffzNodeKind_IntLiteral: {
		f_str_print(builder, f_str_from_uint(F_AS_BYTES(node->IntLiteral.value), f_temp_alc()));
	} break;

	case ffzNodeKind_FloatLiteral: {
		f_str_printf(builder, "%f", node->FloatLiteral.value);
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
		//if (node->loc.start.line_num == 54) F_BP;
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
	case ffzNodeKind_ThisValueDot: { f_str_print(builder, F_LIT(".")); } break;

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
			bool print_parentheses = node->kind != ffzNodeKind_Assign && node->kind != ffzNodeKind_Declare;
			if (print_parentheses) f_str_print(builder, F_LIT("("));
			_print_ast(builder, node->Op.left, tab_level);

			f_str_print(builder, F_LIT(" "));
			f_str_print(builder, ffzNodeKind_to_op_string[node->kind]);
			f_str_print(builder, F_LIT(" "));

			_print_ast(builder, node->Op.right, tab_level);
			if (print_parentheses) f_str_print(builder, F_LIT(")"));
		}
		else F_BP;
	} break;

	}
}

fString ffz_print_ast(fAllocator* alc, ffzNode* node) {
	fArrayRaw builder = { .alc = alc };
	_print_ast(&builder, node, 0);
	return (fString){ builder.data, builder.len };
}

#define IS_WHITESPACE(c) ((c) == ' ' || (c) == '\t' || (c) == '\r')

typedef enum ParseFlags {
	ParseFlag_SkipNewlines = 1 << 0,
	
	// This is to resolve an ambiguity, i.e.
	// if Vector3{1, 2, 3}.x > 0 {...}   or   proc(a: int) => Vector3 {...}
	ParseFlag_NoPostCurlyBrackets = 1 << 1,
} ParseFlags;

static ffzOk parse_node(ffzParser* p, ffzLoc* loc, ffzNode* parent, ParseFlags flags, ffzNode** out);

// https://justine.lol/endian.html
#define READ32BE(p) (u32)(255 & p[0]) << 24 | (255 & p[1]) << 16 | (255 & p[2]) << 8 | (255 & p[3])

static bool is_identifier_char(rune r) {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '\\' || r > 127;
}

// returns an empty token when the end of file is reached.
static Token maybe_eat_next_token(ffzParser* p, ffzLoc* loc, ParseFlags flags) {
	typedef enum CharType {
		CharType_Alphanumeric,
		CharType_Whitespace,
		CharType_Symbol,
	} CharType;

	CharType prev_type = CharType_Whitespace;
	bool tok_starts_with_digit = false;

	s32 prev_r;

	ffzLoc tok_start = *loc;
	//ffzLocRange token_range = ffz_loc_to_range(*pos);
	//bool inside_line_comment = false;

	for (;;) {
		uint next = loc->offset;
		rune r = f_str_next_rune(p->source_code, &next);
		if (!r) break;

		CharType type = CharType_Symbol;
		if ((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r > 127) {
			type = CharType_Alphanumeric;
		}
		else if (r >= '0' && r <= '9') {
			type = CharType_Alphanumeric;
			if (prev_type == CharType_Whitespace) tok_starts_with_digit = true;
		}
		else if (IS_WHITESPACE(r)) {
			type = CharType_Whitespace;
		}
		else if (r == '\n' && (flags & ParseFlag_SkipNewlines)) {
			type = CharType_Whitespace;
		}
		else if (r == '.') {
			// For parsing floats, make '.' part of the token if the token starts with a digit,
			// or the character immediately after the '.' is a digit.
			uint peek_next = next;
			rune peek_next_r = f_str_next_rune(p->source_code, &peek_next);
			if (tok_starts_with_digit || (peek_next_r >= '0' && peek_next_r <= '9')) {
				type = CharType_Alphanumeric;
			}
		}

		//else if (r == '.' && tok_is_numeric) {
		//	// For parsing floats, classify '.' as alphanumeric if this token is a numeric literal.
		//	// Note that we disallow implicit zero in the front, i.e. `.12590`, because that would become tricky:
		//	// how would you tokenize `if x == ._123_456`? It could be an implicit enum value, or a float literal with an underscore.
		//	type = CharType_Alphanumeric;
		//}
		
		if (prev_type != CharType_Whitespace && type != prev_type) break;

		if (prev_type == CharType_Symbol) {
			// We need to manually check for some cases where symbols should be joined.
			// Or maybe this checking should be done outside of this function?
			bool join_symbol = false;
			if (prev_r == '|' && r == '|') join_symbol = true;
			else if (prev_r == '&' && r == '&') join_symbol = true;
			else if (prev_r == '=' && (r == '=' || r == '>')) join_symbol = true; // =>, ==
			else if (prev_r == '<') join_symbol = true; // <<, <=
			else if (prev_r == '>') join_symbol = true; // >>, >=
			else if (prev_r == '!' && r == '=') join_symbol = true; // != should join, but e.g. !! and !~ shouldn't join
			else if (prev_r == '*' && r == '/') join_symbol = true; // join comment block enders
			
			// Skip comments
			if (prev_r == '/' && r == '*') {
				loc->offset = (u32)next;
				loc->column_num += 1;
				for (;;) {
					Token _tok = maybe_eat_next_token(p, loc, ParseFlag_SkipNewlines);
					if (_tok.small == '/*' || !_tok.small) break; // :NoteAboutSeqLiterals
				}
				tok_start = *loc;
				prev_type = CharType_Whitespace;
				continue;
			}
			else if (prev_r == '/' && r == '/') {
				loc->offset = (u32)next;
				loc->column_num += 1;
				for (;;) {
					Token _tok = maybe_eat_next_token(p, loc, (ParseFlags)0);
					if (_tok.small == '\n' || !_tok.small) {
						// we don't want to skip the newline, because sometimes newlines are significant
						*loc = _tok.start;
						break;
					}
				}
				tok_start = *loc;
				prev_type = CharType_Whitespace;
				continue;
			}

			if (!join_symbol) {
				break;
			}
		}

		if (r == '\n') {
			loc->line_num += 1;
			loc->column_num = 0;
		}

		loc->offset = (u32)next;
		loc->column_num += 1;

		if (type == CharType_Whitespace) tok_start = *loc;

		prev_type = type;
		prev_r = r;
	}

	Token tok = { 0 };
	tok.range.start = tok_start;
	tok.range.end = *loc;
	tok.str = f_str_slice(p->source_code, tok.range.start.offset, tok.range.end.offset);
	memcpy(&tok.small, tok.str.data, F_MIN(tok.str.len, sizeof(tok.small)));
	return tok;
}

static ffzOk eat_next_token(ffzParser* p, ffzLoc* loc, ParseFlags flags, const char* task_verb, Token* out) {
	*out = maybe_eat_next_token(p, loc, flags);
	if (out->str.len == 0) {
		ERR(p, ffz_loc_to_range(*loc), "File ended unexpectedly when %s.", task_verb);
	}
	return FFZ_OK;
}

static ffzOk eat_expected_token(ffzParser* p, ffzLoc* loc, fString expected) {
	Token tok = maybe_eat_next_token(p, loc, ParseFlag_SkipNewlines);
	if (!f_str_equals(tok.str, expected)) ERR(p, tok.range, "Expected '%.*s'; got '%.*s'", F_STRF(expected), F_STRF(tok.str));
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

static void* new_node(ffzParser* p, ffzNode* parent, ffzLocRange range, ffzNodeKind kind) {
	ffzNode* node = f_mem_clone(ffzNode, (ffzNode){0}, p->alc);
	//if (node == (void*)0x0000020000001a80) F_BP;
	//memset(node, 0, size);
	node->id.parser_id = p->id;
	node->id.local_id = p->next_local_id++;
	node->parent = parent;
	node->kind = kind;
	node->loc = range;
	//if (node->loc.start.offset == 4942) F_BP;
	return node;
}

static ffzOk parse_children(ffzParser* p, ffzLoc* loc, ffzNode* parent, u8 bracket_close_char) {
	OPT(ffzNode*) prev = NULL;

	for (u32 i = 0;; i++) {
		ffzLoc new_loc = *loc;
		Token tok = maybe_eat_next_token(p, &new_loc, ParseFlag_SkipNewlines);
		
		if (tok.small == bracket_close_char) {
			*loc = new_loc;
			break;
		}
		
		bool was_comma = false;
		if (i > 0) {
			tok = maybe_eat_next_token(p, loc, (ParseFlags)0);
			was_comma = tok.small == ',';
			if (tok.small != '\n' && !was_comma) {
				ERR(p, prev->loc, "Expected a separator character (either a comma or a newline) after '%s', got '%.*s'",
					ffz_node_kind_to_cstring(prev->kind), F_STRF(tok.str));
			}
		}
		
		new_loc = *loc;
		tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0);

		ffzNode* n;
		if ((tok.small == bracket_close_char && was_comma) || tok.small == ',') {
			// Node lists can have blank nodes, i.e.  {,1,,5,2,,1,}
			n = new_node(p, parent, tok.range, ffzNodeKind_Blank);
		}
		else {
			TRY(parse_node(p, loc, parent, (ParseFlags)0, &n));
		}

		if (prev) prev->next = n;
		else parent->first_child = n;
		prev = n;
	}
	parent->loc.end = *loc;
	return FFZ_OK;
}

static ffzNodeOp* merge_operator_chain(fSlice(ffzNodeOp*) chain) {
	F_ASSERT(chain.len > 0);

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
		if (root->Op.left == NULL) { // if this is a prefix operator
			root = left;
		}
		else {
			root->Op.left = left;
		}
	}
	if (lowest_prec_i < chain.len - 1) {
		ffzNodeOp* right = merge_operator_chain(SLICE_AFTER(ffzNodeOp*, chain, lowest_prec_i + 1));
		if (root->Op.right == NULL) { // if this is a postfix operator
			root = right;
		}
		else {
			root->Op.right = right;
		}
	}

	// fixup parent references
	if (root->Op.left) {
		root->Op.left->parent = root;
		root->loc.start = root->Op.left->loc.start;
	}
	if (root->Op.right) {
		root->Op.right->parent = root;
		root->loc.end = root->Op.right->loc.end;
	}
	return root;
}

static ffzOk maybe_parse_polymorphic_parameter_list(ffzParser* p, ffzLoc* loc, ffzNode* parent, ffzNodePolyParamList** out) {
	ffzLoc new_loc = *loc;
	Token tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0);
	if (tok.small == '[') {
		*loc = new_loc;
		ffzNodePolyParamList* node = new_node(p, parent, tok.range, ffzNodeKind_PolyParamList);
		TRY(parse_children(p, loc, (ffzNode*)node, ']'));
		*out = node;
	}
	return FFZ_OK;
}

static ffzOk parse_proc_type(ffzParser* p, ffzLoc* loc, ffzNode* parent, ffzLocRange range, ffzNodeProcType** out) {
	ffzNodeProcType* node = new_node(p, parent, range, ffzNodeKind_ProcType);
	TRY(maybe_parse_polymorphic_parameter_list(p, loc, node, &node->ProcType.polymorphic_parameters));

	ffzLoc new_loc = *loc;
	Token tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0);

	if (tok.small == '(') {
		*loc = new_loc;
		TRY(parse_children(p, loc, node, ')'));
		new_loc = *loc;
		tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0);
	}

	if (tok.small == '>=') { // :NoteAboutSeqLiterals
		*loc = new_loc;
		TRY(parse_node(p, loc, node, ParseFlag_NoPostCurlyBrackets, &node->ProcType.out_parameter));
	}

	node->loc.end = *loc;
	*out = node;
	return FFZ_OK;
}

static void assign_possible_tags(ffzNode* node, OPT(ffzNode*) first_tag) {
	node->first_tag = first_tag;
	for (ffzNode* tag = first_tag; tag; tag = tag->next) {
		tag->parent = node;
	}
}

static ffzOk parse_possible_tags(ffzParser* p, ffzLoc* loc, OPT(ffzNode*)* out_first_tag) {
	ffzNode* first = NULL;
	ffzNode* prev = NULL;
	for (;;) {
		ffzLoc new_loc = *loc;
		Token tok = maybe_eat_next_token(p, &new_loc, ParseFlag_SkipNewlines);
		if (tok.small != '@') break;

		ffzNode* tag;
		*loc = new_loc;
		TRY(parse_node(p, loc, NULL, (ParseFlags)0, &tag)); // NOTE: the parent is assigned later in assign_possible_tag

		if (!first) first = tag;
		if (prev) prev->next = tag;
		prev = tag;
	}
	*out_first_tag = first;
	return FFZ_OK;
}

static ffzOk parse_string_literal(ffzParser* p, ffzLoc* loc, fString* out) {
	fArrayRaw builder = { .alc = p->alc };

	ffzLoc start_pos = *loc;
	for (;;) {
		uint next = loc->offset;
		rune r = f_str_next_rune(p->source_code, &next);
		if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.", "");
		if (r == '\n') {
			loc->line_num++;
			loc->column_num = 0;
		}

		if (r == '\\') {
			r = f_str_next_rune(p->source_code, &next);
			if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.", "");
			if (r == '\n') {
				loc->line_num++;
				loc->column_num = 0;
			}

			loc->offset = (u32)next;
			loc->column_num += 1;

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
				F_ASSERT(loc->offset + 2 <= p->source_code.len);

				fString byte = f_str_slice(p->source_code, loc->offset, loc->offset + 2);
				loc->offset += 2;
				loc->column_num += 2;

				s64 byte_value;
				if (f_str_to_s64(byte, 16, &byte_value)) {
					f_str_print_rune(&builder, (u8)byte_value);
				}
				else ERR(p, ffz_loc_to_range(*loc), "Failed parsing a hexadecimal byte.", "");
			}
			else ERR(p, ffz_loc_to_range(*loc), "Invalid escape sequence.", "");
		}
		else {
			fString codepoint = f_str_slice(p->source_code, loc->offset, next);
			loc->offset = (u32)next;
			loc->column_num += 1;

			if (r == '\"') break;
			if (r == '\r') continue; // Ignore carriage returns

			f_str_print(&builder, codepoint);
		}
	}

	f_str_print_rune(&builder, '\0');
	*out = f_str_slice_before(*(fString*)&builder.slice, builder.slice.len - 1);
	return FFZ_OK;
}

static ffzOk parse_enum(ffzParser* p, ffzLoc* loc, ffzNode* parent, ffzLocRange range, ffzNodeEnum** out) {
	ffzNodeEnum* node = new_node(p, parent, range, ffzNodeKind_Enum);
	Token tok = maybe_eat_next_token(p, loc, 0);

	if (tok.small == ',') {
		TRY(parse_node(p, loc, node, ParseFlag_NoPostCurlyBrackets, &node->Enum.internal_type));
		tok = maybe_eat_next_token(p, loc, 0);
	}

	if (tok.small != '{') ERR(p, tok.range, "Expected a `{`", "");
	TRY(parse_children(p, loc, node, '}'));

	*out = node;
	return FFZ_OK;
}

static ffzOk parse_struct(ffzParser* p, ffzLoc* loc, ffzNode* parent, ffzLocRange range, bool is_union, ffzNodeRecord** out) {
	ffzNodeRecord* node = new_node(p, parent, range, ffzNodeKind_Record);
	TRY(maybe_parse_polymorphic_parameter_list(p, loc, node, &node->Record.polymorphic_parameters));

	TRY(eat_expected_token(p, loc, F_LIT("{")));
	TRY(parse_children(p, loc, node, '}'));

	node->Record.is_union = is_union;
	*out = node;
	return FFZ_OK;
}

static ffzOk parse_node(ffzParser* p, ffzLoc* loc, ffzNode* parent, ParseFlags flags, ffzNode** out) {
	fArray(ffzNodeOp*) operator_chain = f_array_make_raw(p->alc);
	//F_HITS(_c, 4);
	
	//if (loc->line_num == 333) F_BP;

	// We want to first parse the tags for the entire node.
	// i.e. in `@using a: int`, the tag should be attached to the entire node, not to the left-hand-side.
	OPT(ffzNode*) first_tag;
	TRY(parse_possible_tags(p, loc, &first_tag));

	bool standalone_tag = false;
	{
		ffzLoc new_loc = *loc;
		Token tok = maybe_eat_next_token(p, &new_loc, ParseFlag_SkipNewlines);
		if (tok.small == '$') {
			*loc = new_loc;
			standalone_tag = true;
		}
	}

	// Start by parsing the operator chain

	bool check_infix_or_postfix = false;
	ffzNode* prev = NULL;
	for (;;) {
		ffzNode* node = NULL;
		ffzLoc loc_before = *loc;
		
		// TODO: improve parsing of tags. We should attach the tag to the biggest node after the tag.
		// i.e. in `foo: @hello proc() {}`, the tag should be attached to the post-curly-brackets, NOT
		// the procedure type!!!
		// 
		//OPT(ffzNode*) operand_first_tag;
		//TRY(parse_possible_tags(p, loc, &operand_first_tag));

		// skip newlines when NOT parsing for post/infix operators.
		// i.e. to make the following work (otherwise it'd be a dereference of aaa):
		// foo(aaa
		//     ^int(0))

		Token tok = maybe_eat_next_token(p, loc, check_infix_or_postfix ? 0 : ParseFlag_SkipNewlines);
		
		bool is_extended_keyword = !check_infix_or_postfix && tok.small == '*';
		if (is_extended_keyword) {
			tok = maybe_eat_next_token(p, loc, 0);
		}

		if (!prev && tok.str.len == 0) {
			ERR(p, parent->loc, "File ended unexpectedly when parsing child-list.", "");
		}

		bool is_prefix_or_postfix = false;

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
				else { // parenthesized expression - not an operator
					TRY(parse_node(p, loc, parent, (ParseFlags)0, &node));
					TRY(eat_expected_token(p, loc, F_LIT(")")));
				}
			} break;
			case '{': {
				if (check_infix_or_postfix) {
					if (!(flags & ParseFlag_NoPostCurlyBrackets)) {
						op_kind = ffzNodeKind_PostCurlyBrackets;
						is_prefix_or_postfix = true;
					}
				}
				else { // scope - not an operator
					node = new_node(p, parent, tok.range, ffzNodeKind_Scope);
					TRY(parse_children(p, loc, node, '}'));
				}
			} break;
			case '[': {
				is_prefix_or_postfix = true;
				op_kind = check_infix_or_postfix ? ffzNodeKind_PostSquareBrackets : ffzNodeKind_PreSquareBrackets;
			} break;
			case ':': { op_kind = ffzNodeKind_Declare; } break;
			case '=': { op_kind = ffzNodeKind_Assign; } break;
			case '.': {
				ffzLoc new_loc = *loc;
				Token next = maybe_eat_next_token(p, &new_loc, 0);
				if (next.str.len == 0 || !is_identifier_char(f_str_decode_rune(next.str))) {
					node = new_node(p, parent, tok.range, ffzNodeKind_ThisValueDot);
				}
				else {
					op_kind = ffzNodeKind_MemberAccess;
				}
			} break;
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
				node = new_node(p, parent, tok.range, op_kind);
				if (check_infix_or_postfix) {
					prev->parent = node;
					node->Op.left = prev;
					node->loc.start = prev->loc.start;
				}
				else if (!ffz_op_is_prefix(op_kind)) {
					ERR(p, tok.range, "Expected a value, but got an operator.", "");
				}
				
				f_array_push(ffzNodeOp*, &operator_chain, node);

				u8 bracket_op_close_char = ffz_get_bracket_op_close_char(op_kind);
				if (bracket_op_close_char) {
					TRY(parse_children(p, loc, node, bracket_op_close_char));
				}
			}
		}
		
		if (!op_kind && check_infix_or_postfix) { // no more postfix / infix operator. Terminate the chain
			*loc = loc_before;
			break;
		}
		
		//if (f_str_equals(tok.str, F_LIT(".55202"))) F_BP;

		if (!node) {
			if (f_str_equals(tok.str, F_LIT("if"))) {
				// TOOD: I think we should make if, for, etc keywords and call parse_if, parse_for, etc from the keyword codepath
				node = new_node(p, parent, tok.range, ffzNodeKind_If);
				TRY(parse_node(p, loc, node, ParseFlag_NoPostCurlyBrackets, &node->If.condition));
				TRY(parse_node(p, loc, node, 0, &node->If.true_scope));

				ffzLoc new_loc = *loc;
				tok = maybe_eat_next_token(p, &new_loc, ParseFlag_SkipNewlines);
				if (f_str_equals(tok.str, F_LIT("else"))) {
					*loc = new_loc;
					TRY(parse_node(p, loc, node, 0, &node->If.else_scope));
				}
			}
			else if (f_str_equals(tok.str, F_LIT("for"))) {
				node = new_node(p, parent, tok.range, ffzNodeKind_For);
				for (uint i = 0; i < 3; i++) {
					if (i > 0) {
						ffzLoc new_loc = *loc;
						tok = maybe_eat_next_token(p, &new_loc, 0);
						if (tok.small == '{') break;
						if (tok.small != ',') ERR(p, tok.range, "Invalid for-loop; expected ',' or '{'", "");
						*loc = new_loc;
					}

					ffzLoc new_loc = *loc;
					tok = maybe_eat_next_token(p, &new_loc, 0);
					if (tok.small == '{') break;
					if (tok.small == ',') continue;

					ffzNode* stmt;
					TRY(parse_node(p, loc, node, ParseFlag_NoPostCurlyBrackets, &stmt));
					node->For.header_stmts[i] = stmt;
				}

				TRY(parse_node(p, loc, node, 0, &node->For.scope));
			}
			else if (f_str_equals(tok.str, F_LIT("ret"))) {
				node = new_node(p, parent, tok.range, ffzNodeKind_Return);

				ffzLoc new_loc = *loc;
				tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0); // With return statements, newlines do matter!
				if (tok.small == '\n') {
					*loc = new_loc;
				}
				else {
					TRY(parse_node(p, loc, node, (ParseFlags)0, &node->Return.value));
				}
			}
			else if (f_str_equals(tok.str, F_LIT("proc"))) {
				TRY(parse_proc_type(p, loc, parent, tok.range, &node));
			}
			else if (f_str_equals(tok.str, F_LIT("enum"))) {
				TRY(parse_enum(p, loc, parent, tok.range, &node));
			}
			else if (f_str_equals(tok.str, F_LIT("struct"))) {
				TRY(parse_struct(p, loc, parent, tok.range, false, &node));
			}
			else if (f_str_equals(tok.str, F_LIT("union"))) {
				TRY(parse_struct(p, loc, parent, tok.range, true, &node));
			}
			else if (is_identifier_char(f_str_decode_rune(tok.str)) || tok.small == '#' || tok.small == '?' || is_extended_keyword) {
				ffzKeyword* keyword = f_map64_get_raw(p->keyword_from_string, f_hash64_str(tok.str));
				if (keyword) {
					if (ffz_keyword_is_extended(*keyword)) {
						if (!is_extended_keyword) keyword = NULL; // should be an identifier instead.
					}
					else {
						if (is_extended_keyword) ERR(p, tok.range, "Unrecognized extended keyword: \"%.*s\"", F_STRF(tok.str));
					}
				}
				if (keyword) {
					node = new_node(p, parent, tok.range, ffzNodeKind_Keyword);
					node->Keyword.keyword = *keyword;

					if (*keyword == ffzKeyword_import) {
						f_array_push(ffzNodeKeyword*, &p->module_imports, node);
					}
				}
				else {
					// identifier!
					node = new_node(p, parent, tok.range, ffzNodeKind_Identifier);
					if (tok.small == '#') {
						node->Identifier.is_constant = true;
						TRY(eat_next_token(p, loc, 0, "parsing an identifier", &tok));

						if (!is_identifier_char(f_str_decode_rune(tok.str))) {
							ERR(p, tok.range, "Invalid character for constant identifier.", "");
						}
					}
					node->Identifier.name = tok.str;
				}
			}
			else if (tok.small == '\'') {
				node = new_node(p, parent, tok.range, ffzNodeKind_IntLiteral);
				TRY(eat_next_token(p, loc, 0, "parsing a character literal", &tok));
				TRY(eat_expected_token(p, loc, F_LIT("'")));

				if (tok.small > 127) ERR(p, tok.range, "TODO: better support for character literals", "");
				node->IntLiteral.value = tok.small;
				node->loc.end = *loc;
			}
			else if (tok.small == '\"') {
				node = new_node(p, parent, tok.range, ffzNodeKind_StringLiteral);
				TRY(parse_string_literal(p, loc, &node->StringLiteral.zero_terminated_string));
				node->loc.end = *loc;
			}
		}

		if (!node) {
			if (f_str_contains(tok.str, F_LIT("."))) { // float
				f64 value;
				if (!f_str_to_f64(tok.str, &value)) {
					ERR(p, tok.range, "Invalid float literal.", "");
				}
				node = new_node(p, parent, tok.range, ffzNodeKind_FloatLiteral);
				node->FloatLiteral.value = value;
			}
			else if ((tok.small & 0xff) >= '0' && (tok.small & 0xff) <= '9') {
				u8 base = 10;
				const char* base_name = "numeric";
				if ((tok.small & 0xffff) == 'x0') { // :NoteAboutSeqLiterals
					base = 16;
					base_name = "hex";
					f_str_advance(&tok.str, 2);
				}
				else if ((tok.small & 0xffff) == 'b0') { // :NoteAboutSeqLiterals
					base = 2;
					base_name = "binary";
					f_str_advance(&tok.str, 2);
				}

				u64 value;
				if (!f_str_to_u64(tok.str, base, &value)) {
					ERR(p, tok.range, "Invalid %s literal.", base_name);
				}
				//f_str_to_f64

				node = new_node(p, parent, tok.range, ffzNodeKind_IntLiteral);
				node->IntLiteral.value = value;
				node->IntLiteral.was_encoded_in_base = base;
			}
		}

		if (!node) {
			ERR(p, tok.range, "Failed parsing a value; unexpected token `%.*s`", F_STRF(tok.str));
		}

		if (!check_infix_or_postfix) {
			if (prev) {
				F_ASSERT(ffz_node_is_operator(prev->kind));
				node->parent = prev;
				prev->Op.right = node;
				prev->loc.end = node->loc.end;
			}
		}

		//if (operand_first_tag) assign_possible_tags(node, operand_first_tag);
		if (!is_prefix_or_postfix) check_infix_or_postfix = !check_infix_or_postfix;
		prev = node;
	}

	
	ffzNode* node = prev;
	if (operator_chain.len > 0) {
		node = (ffzNode*)merge_operator_chain(operator_chain.slice);
	}

	if (standalone_tag) {
		node->flags |= ffzNodeFlag_IsStandaloneTag;
		if (parent->parent != NULL) {
			ERR(p, node->loc, "Standalone tags must be placed at top-level scope. This restriction might be removed in the future.", ""); // :StandaloneTagTopLevel
		}
	}

	if (first_tag) assign_possible_tags(node, first_tag);
	if (node->parent) node->parent->loc.end = node->loc.end;

	*out = node;
	return FFZ_OK;
}

ffzOk ffz_parse(ffzParser* p) {
	ffzLoc loc = {0};
	loc.line_num = 1;
	loc.column_num = 1;
	p->root = new_node(p, NULL, (ffzLocRange){0}, ffzNodeKind_Scope);

	TRY(parse_children(p, &loc, (ffzNode*)p->root, 0));
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