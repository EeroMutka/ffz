#define FOUNDATION_HELPER_MACROS
#include "foundation/foundation.h"

// TODO: convert the codebase to GCC-compitable C and hook it up with tracy?

// Future research:
// https://nothings.org/computer/lexing.html


#include "ffz_checker.h"
//#include "ffz_ast.h"

// Parser is responsible for parsing a single file / string of source code
typedef struct ffzParser {
	ffzSource* source;
	fAllocator* alc;

	fArray(ffzNode*) import_keywords;

	bool stop_at_curly_brackets;

	ffzError error;
} ffzParser;

#define TRY(x) { if ((x).ok == false) return (ffzOk){false}; }

#define OPT(ptr) ptr

inline fAllocator* parser_allocator(ffzParser* p) { return p->alc; }
ffzProject* project_from_parser(ffzParser* p) { return p->source->_module->project; }

#define ERR(p, at, fmt, ...) { \
	p->error = (ffzError){.source = p->source, .location = at, .message = f_aprint(parser_allocator(p), fmt, __VA_ARGS__)}; \
	return (ffzOk){false}; \
}

#define SLICE_BEFORE(T, slice, mid) (fSliceRaw){(T*)slice.data, (mid)}
#define SLICE_AFTER(T, slice, mid) (fSliceRaw){(T*)slice.data + (mid), (slice.len) - (mid)}
#define fSlice(T) fSliceRaw
#define Array(T) fArrayRaw

#define CHAR2(a, b) ((u32)a | (u32)b << 8)

const static ffzNode _ffz_node_default = {
	.is_instantiation_root_of_poly = FFZ_POLYMORPH_ID_NONE,
	.first_tag = NULL,
	.parent = NULL,
	.next = NULL,
	.first_child = NULL,
};

ffzNode ffz_node_default() { return _ffz_node_default; }

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
	X("", "poly-definition")\
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


fString ffz_keyword_to_string(ffzKeyword keyword) {
	switch (keyword) {
	case ffzKeyword_Eater:                return F_LIT("_");
	case ffzKeyword_QuestionMark:         return F_LIT("?");
	case ffzKeyword_Undefined:            return F_LIT("~~");
	case ffzKeyword_dbgbreak:             return F_LIT("dbgbreak");
	case ffzKeyword_size_of:              return F_LIT("size_of");
	case ffzKeyword_align_of:             return F_LIT("align_of");
	case ffzKeyword_import:               return F_LIT("import");
	case ffzKeyword_true:                 return F_LIT("true");
	case ffzKeyword_false:                return F_LIT("false");
	case ffzKeyword_u8:                   return F_LIT("u8");
	case ffzKeyword_u16:                  return F_LIT("u16");
	case ffzKeyword_u32:                  return F_LIT("u32");
	case ffzKeyword_u64:                  return F_LIT("u64");
	case ffzKeyword_s8:                   return F_LIT("s8");
	case ffzKeyword_s16:                  return F_LIT("s16");
	case ffzKeyword_s32:                  return F_LIT("s32");
	case ffzKeyword_s64:                  return F_LIT("s64");
	case ffzKeyword_f32:                  return F_LIT("f32");
	case ffzKeyword_f64:                  return F_LIT("f64");
	case ffzKeyword_int:                  return F_LIT("int");
	case ffzKeyword_uint:                 return F_LIT("uint");
	case ffzKeyword_bool:                 return F_LIT("bool");
	case ffzKeyword_raw:                  return F_LIT("raw");
	case ffzKeyword_string:               return F_LIT("string");
	case ffzKeyword_bit_and:              return F_LIT("bit_and");
	case ffzKeyword_bit_or:               return F_LIT("bit_or");
	case ffzKeyword_bit_xor:              return F_LIT("bit_xor");
	case ffzKeyword_bit_shl:              return F_LIT("bit_shl");
	case ffzKeyword_bit_shr:              return F_LIT("bit_shr");
	case ffzKeyword_bit_not:              return F_LIT("bit_not");
	case ffzKeyword_build_option:         return F_LIT("build_option");
	case ffzKeyword_extern:               return F_LIT("extern");
	case ffzKeyword_using:                return F_LIT("using");
	case ffzKeyword_global:               return F_LIT("global");
	case ffzKeyword_module_defined_entry: return F_LIT("module_defined_entry");
	default: f_trap();
	}
	return (fString){0};
}

char* ffz_keyword_to_cstring(ffzKeyword keyword) { return (char*)ffz_keyword_to_string(keyword).data; }

F_STATIC_ASSERT(F_LEN(ffzNodeKind_to_name) == ffzNodeKind_COUNT);

fString ffz_node_kind_to_string(ffzNodeKind kind) { return ffzNodeKind_to_name[kind]; }
char* ffz_node_kind_to_cstring(ffzNodeKind kind) { return (char*)ffzNodeKind_to_name[kind].data; }

fString ffz_node_kind_to_op_string(ffzNodeKind kind) { return ffzNodeKind_to_op_string[kind]; }
char* ffz_node_kind_to_op_cstring(ffzNodeKind kind) { return (char*)ffzNodeKind_to_op_string[kind].data;}


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
	default: f_assert(false);
	}
	return 0;
}

u8 ffz_get_bracket_op_open_char(ffzNodeKind kind) {
	switch (kind) {
	case ffzNodeKind_PreSquareBrackets: return '[';
	case ffzNodeKind_PostSquareBrackets: return '[';
	case ffzNodeKind_PostRoundBrackets: return '(';
	case ffzNodeKind_PostCurlyBrackets: return '{';
	default: return 0;
	}
}

u8 ffz_get_bracket_op_close_char(ffzNodeKind kind) {
	//ZoneScoped
	switch (kind) {
	case ffzNodeKind_PreSquareBrackets: return ']';
	case ffzNodeKind_PostSquareBrackets: return ']';
	case ffzNodeKind_PostRoundBrackets: return ')';
	case ffzNodeKind_PostCurlyBrackets: return '}';
	default: return 0;
	}
}

static void print_ast(fWriter* w, ffzNode* node, uint tab_level) {
	const fString tab_str = F_LIT("    ");

	if (false) {
		f_print(w, " <");
		f_prints(w, ffz_node_kind_to_string(node->kind));
		f_print(w, "|~u32:~u32-~u32:~u32", node->loc.start.line_num, node->loc.start.column_num, node->loc.end.line_num, node->loc.end.column_num);
			//str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		//str_print(builder, F_LIT(", line="));
		//str_print(builder, str_from_uint(AS_BYTES(node->start_pos.line_number), temp));
		f_print(w, ">");
	}

	// TODO: this is incomplete!!
	// `@using a: b` is different from `(@using a): b`, but they both will currently be printed the same.
	for (ffzNode* tag = node->first_tag; tag; tag = tag->next) {
		f_print(w, "@");
		print_ast(w, tag, tab_level);
		f_print(w, " ");
	}

	if (node->flags & ffzNodeFlag_IsStandaloneTag) {
		f_print(w, "$");
	}

	switch (node->kind) {

	case ffzNodeKind_Keyword: {
		if (ffz_keyword_is_extended(node->Keyword.keyword)) f_print(w, "*");
		f_prints(w, ffz_keyword_to_string(node->Keyword.keyword));
	} break;

	case ffzNodeKind_PostRoundBrackets: // fallthrough
	case ffzNodeKind_PostSquareBrackets: // fallthrough
	case ffzNodeKind_PostCurlyBrackets: {
		//f_str_print_rune(builder, '(');
		print_ast(w, node->Op.left, tab_level);

		u8 open_char = ffz_get_bracket_op_open_char(node->kind);
		u8 close_char = ffz_get_bracket_op_close_char(node->kind);
		
		bool multi_line = node->kind == ffzNodeKind_PostCurlyBrackets; //ffz_get_child_count(node) >= 3 ||
		if (multi_line) {
			f_printb(w, ' ');
			f_printb(w, open_char);
			f_printb(w, '\n');
			for (ffzNode* n = node->first_child; n; n = n->next) {
				f_prints_repeat(w, tab_str, tab_level + 1);
				print_ast(w, n, tab_level + 1);
				f_printb(w, '\n');
			}
			f_prints_repeat(w, tab_str, tab_level);
		}
		else {
			f_printb(w, open_char);
			for (ffzNode* n = node->first_child; n; n = n->next) {
				if (n != node->first_child) f_print(w, ", ");
				print_ast(w, n, tab_level);
			}
		}
		f_printb(w, close_char);
	} break;

	case ffzNodeKind_PreSquareBrackets: {
		f_printb(w, '[');
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_print(w, ", ");
			print_ast(w, n, tab_level);
		}
		f_printb(w, ']');
		print_ast(w, node->Op.right, tab_level);
	} break;

	case ffzNodeKind_UnaryMinus: // fallthrough
	case ffzNodeKind_UnaryPlus: // fallthrough
	case ffzNodeKind_AddressOf: // fallthrough
	case ffzNodeKind_PointerTo: // fallthrough
	case ffzNodeKind_LogicalNOT: {
		//f_str_print_rune(builder,'(');
		f_prints(w, ffzNodeKind_to_op_string[node->kind]);
		print_ast(w, node->Op.right, tab_level);
		//f_str_print_rune(builder,')');
	} break;

	// postfix operator
	case ffzNodeKind_Dereference: {
		//f_str_print_rune(builder,'(');
		print_ast(w, node->Op.left, tab_level);
		f_prints(w, ffzNodeKind_to_op_string[node->kind]);
		//f_str_print_rune(builder,')');
	} break;
	
	case ffzNodeKind_Identifier: {
		if (node->Identifier.is_constant) f_printb(w, '#');
		f_prints(w, node->Identifier.name);
	} break;

	case ffzNodeKind_Record: {
		f_print(w, node->Record.is_union ? "union" : "struct");

		//if (node->Record.polymorphic_parameters) {
		//	print_ast(w, node->Record.polymorphic_parameters, tab_level);
		//}
		f_printb(w, '{');
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_print(w, ", ");
			print_ast(w, n, tab_level);
		}
		f_printb(w, '}');
	} break;

	case ffzNodeKind_Enum: {
		f_print(w, "enum");
		if (node->Enum.internal_type) {
			f_print(w, ", ");
			print_ast(w, node->Enum.internal_type, tab_level);
		}
		f_print(w, " {");
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_print(w, ", ");
			print_ast(w, n, tab_level);
		}
		f_printb(w, '}');
	} break;

	case ffzNodeKind_ProcType: {
		f_print(w, "proc");
		
		//if (node->ProcType.polymorphic_parameters) {
		//	print_ast(w, node->ProcType.polymorphic_parameters, tab_level);
		//}

		if (node->first_child) {
			f_printb(w, '(');
			for (ffzNode* n = node->first_child; n; n = n->next) {
				if (n != node->first_child) f_print(w, ", ");
				print_ast(w, n, tab_level);
			}
			f_printb(w, ')');
		}

		ffzNode* out_param = node->ProcType.out_parameter;
		if (out_param) {
			f_print(w, " => ");
			print_ast(w, out_param, tab_level);
			//f_write(builder, F_LIT(""));
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
		f_print(w, "ret");

		if (node->Return.value) {
			f_printb(w, ' ');
			print_ast(w, node->Return.value, tab_level);
		}
	} break;

	case ffzNodeKind_Scope: {
		f_print(w, "{\n");

		for (ffzNode* n = node->first_child; n; n = n->next) {
			f_prints_repeat(w, tab_str, tab_level + 1);
			print_ast(w, n, tab_level + 1);
			f_printb(w, '\n');
		}

		f_prints_repeat(w, tab_str, tab_level);
		f_print(w, "}\n");
	} break;

	case ffzNodeKind_IntLiteral: {
		f_print(w, "~u64", node->IntLiteral.value);
	} break;

	case ffzNodeKind_FloatLiteral: {
		f_print(w, "~f64", node->FloatLiteral.value);
	} break;

	case ffzNodeKind_StringLiteral: {
		// TODO: print escaped strings
		f_printb(w, '\"');
		f_prints(w, node->StringLiteral.zero_terminated_string);
		f_printb(w, '\"');
	} break;

	//case ffzNodeKind_FloatLiteral: {
	//	str_print(builder, str_from_float(temp, AS_BYTES(node->Float.value)));
	//} break;

	case ffzNodeKind_If: {
		f_print(w, "if ");
		print_ast(w, node->If.condition, tab_level);
		f_print(w, " ");
		print_ast(w, node->If.true_scope, tab_level);

		fOpt(ffzNode*) false_scope = node->If.false_scope;
		if (false_scope) {
			for (int j = 0; j < tab_level; j++) f_print(w, "    ");
			f_print(w, "else \n");
			print_ast(w, false_scope, tab_level);
		}

	} break;

	case ffzNodeKind_For: {
		//if (node->loc.start.line_num == 54) f_trap();
		f_print(w, "for ");
		for (int i = 0; i < 3; i++) {
			fOpt(ffzNode*) stmt = node->For.header_stmts[i];
			if (stmt) {
				if (i > 0) f_print(w, ", ");
				print_ast(w, stmt, tab_level);
			}
		}

		f_print(w, " ");
		print_ast(w, node->For.scope, tab_level);
	} break;

	case ffzNodeKind_Blank: { f_print(w, "_"); } break;
	case ffzNodeKind_ThisDot: { f_print(w, "."); } break;

	case ffzNodeKind_PolyExpr: {
		f_print(w, "poly[");
		for (ffzNode* n = node->first_child; n; n = n->next) {
			if (n != node->first_child) f_print(w, ", ");
			print_ast(w, n, tab_level);
		}
		f_print(w, "] ");
		print_ast(w, node->PolyExpr.expr, tab_level);
	} break;

	default: {
		if (ffz_node_is_operator(node->kind)) {
			bool print_parentheses = node->kind != ffzNodeKind_Assign && node->kind != ffzNodeKind_Declare;
			if (print_parentheses) f_print(w, "(");
			print_ast(w, node->Op.left, tab_level);

			f_print(w, " ");
			f_prints(w, ffzNodeKind_to_op_string[node->kind]);
			f_print(w, " ");

			print_ast(w, node->Op.right, tab_level);
			if (print_parentheses) f_print(w, ")");
		}
		else f_trap();
	} break;

	}
}

void ffz_print_ast(fWriter* w, ffzNode* node) {
	print_ast(w, node, 0);
}

FFZ_CAPI fString ffz_node_to_string(ffzProject* p, ffzNode* node, bool try_to_use_source, fAllocator* alc) {
	if (node->loc_source && try_to_use_source) {
		fString source_code = node->loc_source->source_code;
		return f_str_slice(source_code, node->loc.start.offset, node->loc.end.offset);
	}
	else {
		fStringBuilder b;
		f_init_string_builder(&b, alc);
		ffz_print_ast(b.w, node);
		return b.str;
	}
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
		rune r = f_str_next_rune(p->source->source_code, &next);
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
			rune peek_next_r = f_str_next_rune(p->source->source_code, &peek_next);
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
			else if (prev_r == '~' && r == '~') join_symbol = true; // ~~
			else if (prev_r == '!' && r == '=') join_symbol = true; // != should join, but e.g. !! and !~ shouldn't join
			else if (prev_r == '*' && r == '/') join_symbol = true; // join comment block enders
			
			// Skip comments
			if (prev_r == '/' && r == '*') {
				loc->offset = (u32)next;
				loc->column_num += 1;
				for (;;) {
					Token _tok = maybe_eat_next_token(p, loc, ParseFlag_SkipNewlines);
					if (_tok.small == CHAR2('/', '*') || !_tok.small) break;
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
	tok.str = f_str_slice(p->source->source_code, tok.range.start.offset, tok.range.end.offset);
	memcpy(&tok.small, tok.str.data, F_MIN(tok.str.len, sizeof(tok.small)));
	return tok;
}

static ffzOk eat_next_token(ffzParser* p, ffzLoc* loc, ParseFlags flags, const char* task_verb, Token* out) {
	*out = maybe_eat_next_token(p, loc, flags);
	if (out->str.len == 0) {
		ERR(p, ffz_loc_to_range(*loc), "File ended unexpectedly when ~c.", task_verb);
	}
	return FFZ_OK;
}

static ffzOk eat_expected_token(ffzParser* p, ffzLoc* loc, fString expected) {
	Token tok = maybe_eat_next_token(p, loc, ParseFlag_SkipNewlines);
	if (!f_str_equals(tok.str, expected)) ERR(p, tok.range, "Expected '~s'; got '~s'", expected, tok.str);
	return FFZ_OK;
}


void ffz_replace_node(ffzCursor* at, ffzNode* with) {
	f_assert(with->parent == NULL && with->next == NULL);
	
	fOpt(ffzNode*) replaced = ffz_get_node_at_cursor(at);
	if (replaced) {
		with->next = replaced->next;
	}
	with->parent = at->parent;
	*at->pp_node = with;
}

//#ifdef _DEBUG
//static uint __nodes_memory_usage = 0;
//#endif

ffzNode* new_node(ffzParser* p, ffzNode* parent, ffzLocRange loc, ffzNodeKind kind) {
	ffzNode* node = f_mem_clone(_ffz_node_default, p->alc);
	node->_module = p->source->_module;
	node->kind = kind;
	node->loc_source = p->source;
	node->parent = parent;
	node->loc = loc;
	//__nodes_memory_usage += sizeof(ffzNode);
	return node;
}

ffzNode* ffz_new_node(ffzModule* m, ffzNodeKind kind) {
	ffzNode* node = f_mem_clone(_ffz_node_default, m->alc);
	node->_module = m;
	node->kind = kind;
	return node;
}

// This is a weird procedure, because you need to be careful with the children as we're not doing a deep copy.
// Idk if we should have it here
ffzNode* ffz_clone_node(ffzModule* m, ffzNode* node) {
	f_assert(!node->has_checked);

	ffzNode* new_node = f_mem_clone(*node, m->alc);
	new_node->_module = m;
	new_node->parent = NULL;
	new_node->next = NULL;
	return new_node;
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
				ERR(p, prev->loc, "Expected a separator character (either a comma or a newline) after '~s', got '~s'",
					ffz_node_kind_to_string(prev->kind), tok.str);
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
	f_assert(chain.len > 0);

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
		f_assert(ffz_node_is_operator(data[i]->kind));
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
	fOpt(ffzNode*) left = root->Op.left;
	fOpt(ffzNode*) right = root->Op.right;
	if (left) {
		left->parent = root;
		root->loc.start = left->loc.start;
	}
	if (right) {
		right->parent = root;
		root->loc.end = right->loc.end;
	}
	return root;
}

static ffzOk parse_proc_type(ffzParser* p, ffzLoc* loc, ffzNode* parent, ffzLocRange range, ffzNodeProcType** out) {
	ffzNodeProcType* node = new_node(p, parent, range, ffzNodeKind_ProcType);
	
	ffzLoc new_loc = *loc;
	Token tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0);

	if (tok.small == '(') {
		*loc = new_loc;
		TRY(parse_children(p, loc, node, ')'));
		new_loc = *loc;
		tok = maybe_eat_next_token(p, &new_loc, (ParseFlags)0);
	}

	if (tok.small == CHAR2('=', '>')) {
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
	fStringBuilder builder;
	f_init_string_builder(&builder, parser_allocator(p));

	ffzLoc start_pos = *loc;
	for (;;) {
		uint next = loc->offset;
		rune r = f_str_next_rune(p->source->source_code, &next);
		if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.", "");
		if (r == '\n') {
			loc->line_num++;
			loc->column_num = 0;
		}

		if (r == '\\') {
			r = f_str_next_rune(p->source->source_code, &next);
			if (!r) ERR(p, ffz_loc_to_range(start_pos), "File ended unexpectedly; no matching `\"` found for string literal.", "");
			if (r == '\n') {
				loc->line_num++;
				loc->column_num = 0;
			}

			loc->offset = (u32)next;
			loc->column_num += 1;

			if (r == 'a')       f_printb(builder.w, '\a');
			else if (r == 'b')  f_printb(builder.w, '\b');
			else if (r == 'f')  f_printb(builder.w, '\f');
			else if (r == 'f')  f_printb(builder.w, '\f');
			else if (r == 'n')  f_printb(builder.w, '\n');
			else if (r == 'r')  f_printb(builder.w, '\r');
			else if (r == 't')  f_printb(builder.w, '\t');
			else if (r == 'v')  f_printb(builder.w, '\v');
			else if (r == '\\') f_printb(builder.w, '\\');
			else if (r == '\'') f_printb(builder.w, '\'');
			else if (r == '\"') f_printb(builder.w, '\"');
			else if (r == '?')  f_printb(builder.w, '\?');
			else if (r == '0')  f_printb(builder.w, 0); // parsing octal characters is not supported like in C, with the exception of \0
			else if (r == 'x') {
				//if (p->pos.remaining.len < 2) PARSER_ERROR(p, p->pos, F_LIT("File ended unexpectedly when parsing a string literal."));
				f_assert(loc->offset + 2 <= p->source->source_code.len);

				fString byte = f_str_slice(p->source->source_code, loc->offset, loc->offset + 2);
				loc->offset += 2;
				loc->column_num += 2;

				s64 byte_value;
				if (f_str_to_s64(byte, 16, &byte_value)) {
					f_printb(builder.w, (u8)byte_value);
				}
				else ERR(p, ffz_loc_to_range(*loc), "Failed parsing a hexadecimal byte.", "");
			}
			else ERR(p, ffz_loc_to_range(*loc), "Invalid escape sequence.", "");
		}
		else {
			fString codepoint = f_str_slice(p->source->source_code, loc->offset, next);
			loc->offset = (u32)next;
			loc->column_num += 1;

			if (r == '\"') break;
			if (r == '\r') continue; // Ignore carriage returns

			f_prints(builder.w, codepoint);
		}
	}

	f_printb(builder.w, '\0');
	*out = f_str_slice_before(builder.str, builder.str.len - 1);
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

	TRY(eat_expected_token(p, loc, F_LIT("{")));
	TRY(parse_children(p, loc, node, '}'));

	node->Record.is_union = is_union;
	*out = node;
	return FFZ_OK;
}

static ffzOk parse_node(ffzParser* p, ffzLoc* loc, ffzNode* parent, ParseFlags flags, ffzNode** out) {
	fArray(ffzNodeOp*) operator_chain = f_array_make(parser_allocator(p));
	//F_HITS(_c, 4);
	
	//if (loc->line_num == 333) f_trap();

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
					node = new_node(p, parent, tok.range, ffzNodeKind_ThisDot);
				}
				else {
					op_kind = ffzNodeKind_MemberAccess;
				}
			} break;
			case CHAR2('~','~'): {
				node = new_node(p, parent, tok.range, ffzNodeKind_Keyword);
				node->Keyword.keyword = ffzKeyword_Undefined;
			} break;
			case CHAR2('&','&'): { op_kind = ffzNodeKind_LogicalAND; } break;
			case CHAR2('|','|'): { op_kind = ffzNodeKind_LogicalOR; } break;
			case '*':            { op_kind = ffzNodeKind_Mul; } break;
			case '/':            { op_kind = ffzNodeKind_Div; } break;
			case '%':            { op_kind = ffzNodeKind_Modulo; } break;
			case CHAR2('<','='): { op_kind = ffzNodeKind_LessOrEqual; } break;
			case '<':            { op_kind = ffzNodeKind_Less; } break;
			case CHAR2('>','='): { op_kind = ffzNodeKind_GreaterOrEqual; } break;
			case '>':            { op_kind = ffzNodeKind_Greater; } break;
			case CHAR2('=','='): { op_kind = ffzNodeKind_Equal; } break;
			case CHAR2('!','='): { op_kind = ffzNodeKind_NotEqual; } break;
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
				
				f_array_push(&operator_chain, node);

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
					TRY(parse_node(p, loc, node, 0, &node->If.false_scope));
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
			else if (f_str_equals(tok.str, F_LIT("poly"))) {
				node = new_node(p, parent, tok.range, ffzNodeKind_PolyExpr);

				tok = maybe_eat_next_token(p, loc, (ParseFlags)0); // With return statements, newlines do matter!
				if (tok.small != '[') {
					ERR(p, tok.range, "Expected `[`.", "");
				}
				
				TRY(parse_children(p, loc, node, ']'));
				TRY(parse_node(p, loc, node, (ParseFlags)0, &node->PolyExpr.expr));
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
			       // hmm... I don't think we even need the `f_str_decode_rune` here, we can just look at the first byte
			else if (is_identifier_char(f_str_decode_rune(tok.str)) || tok.small == '#' || tok.small == '?' || is_extended_keyword) {
				ffzProject* project = project_from_parser(p);
				ffzKeyword* keyword = f_map64_get_raw(&project->keyword_from_string, f_hash64_str(tok.str));
				if (keyword) {
					if (ffz_keyword_is_extended(*keyword)) {
						if (!is_extended_keyword) keyword = NULL; // should be an identifier instead.
					}
					else {
						if (is_extended_keyword) ERR(p, tok.range, "Unrecognized extended keyword: \"~s\"", tok.str);
					}
				}
				if (keyword) {
					node = new_node(p, parent, tok.range, ffzNodeKind_Keyword);
					node->Keyword.keyword = *keyword;

					if (*keyword == ffzKeyword_import) {
						f_array_push(&p->import_keywords, node);
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
				if ((tok.small & 0xffff) == CHAR2('0','x')) {
					base = 16;
					base_name = "hex";
					f_str_advance(&tok.str, 2);
				}
				else if ((tok.small & 0xffff) == CHAR2('0','b')) {
					base = 2;
					base_name = "binary";
					f_str_advance(&tok.str, 2);
				}

				u64 value;
				if (!f_str_to_u64(tok.str, base, &value)) {
					ERR(p, tok.range, "Invalid ~s literal.", base_name);
				}

				node = new_node(p, parent, tok.range, ffzNodeKind_IntLiteral);
				node->IntLiteral.value = value;
				node->IntLiteral.was_encoded_in_base = base;
			}
		}

		if (!node) {
			ERR(p, tok.range, "Failed parsing a value; unexpected token `~s`", tok.str);
		}

		if (!check_infix_or_postfix) {
			if (prev) {
				f_assert(ffz_node_is_operator(prev->kind));
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

ffzSource* ffz_new_source(ffzModule* m, fString code, fString filepath) {
	ffzSource* source = f_mem_clone((ffzSource){0}, m->alc);
	source->self_id = (ffzSourceID)f_array_push(&m->project->sources, source); // TODO: mutex
	source->_module = m;
	source->source_code = code;
	source->source_code_filepath = filepath;
	return source;
}

ffzParseResult ffz_parse_node(ffzModule* m, fString file_contents, fString file_path) {
	ffzParser parser = {0};
	parser.source = ffz_new_source(m, file_contents, file_path);
	parser.alc = m->alc;
	parser.import_keywords = f_array_make(parser.alc);

	ffzLoc loc = { .line_num = 1, .column_num = 1 };
	
	ffzNode* node;
	ffzOk ok = parse_node(&parser, &loc, NULL, (ParseFlags)0, &node);
	return (ffzParseResult){
		.node = ok.ok ? node : NULL,
		.import_keywords = parser.import_keywords.slice,
		.error = parser.error
	};
}

ffzParseResult ffz_parse_scope(ffzModule* m, fString file_contents, fString file_path) {
	ffzParser parser = {0};
	parser.source = ffz_new_source(m, file_contents, file_path);
	parser.alc = m->alc;
	parser.import_keywords = f_array_make(parser.alc);

	ffzLoc loc = { .line_num = 1, .column_num = 1 };
	ffzNode* root = new_node(&parser, NULL, (ffzLocRange){0}, ffzNodeKind_Scope);

	ffzOk ok = parse_children(&parser, &loc, root, 0);
	return (ffzParseResult){
		.node = ok.ok ? root : NULL,
		.import_keywords = parser.import_keywords.slice,
		.error = parser.error
	};
}

void ffz_skip_standalone_tags(OPT(ffzNode*)* node) {
	while (*node && (*node)->flags & ffzNodeFlag_IsStandaloneTag) {
		*node = (*node)->next;
	}
}

ffzNode* ffz_get_child(ffzNode* parent, u32 idx) {
	u32 i = 0;
	for FFZ_EACH_CHILD(n, parent) {
		if (i == idx) return n;
		i++;
	}
	f_assert(false);
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
	f_assert(false);
	return F_U32_MAX;
}

OPT(ffzNodeOpDeclare*) ffz_get_parent_decl(OPT(ffzNode*) node) {
	return (node && node->parent->kind == ffzNodeKind_Declare) ? (ffzNodeOpDeclare*)node->parent : NULL;
}

fString ffz_get_parent_decl_name(OPT(ffzNode*) node) {
	ffzNodeOpDeclare* decl = ffz_get_parent_decl(node);
	return decl ? decl->Op.left->Identifier.name : (fString) { 0 };
}

fString ffz_get_pretty_name(ffzNodeIdentifier* n) { return n->Identifier.pretty_name.len ? n->Identifier.pretty_name : n->Identifier.name; }

fString ffz_get_parent_decl_pretty_name(OPT(ffzNode*) node) {
	ffzNodeOpDeclare* decl = ffz_get_parent_decl(node);
	return decl ? ffz_get_pretty_name(decl->Op.left) : (fString){0};
}
