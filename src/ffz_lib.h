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

typedef struct { u32 idx; } ffzPolymorphIdx; // 0 is invalid index

typedef u32 ffzParserIndex;
typedef u32 ffzCheckerIndex;

typedef struct ffzChecker ffzChecker;
typedef struct ffzParser ffzParser;

typedef struct ffzLoc {
	u32 line_num; // As in text files, starts at 1
	u32 column_num;
	u32 offset;
} ffzLoc;

typedef struct ffzLocRange {
	ffzLoc start;
	ffzLoc end;
} ffzLocRange;

typedef struct ffzProject {
	fAllocator* persistent_allocator;
	fString module_name;
	fMap64(ffzChecker*) checked_module_from_directory; // key: str_hash_meow64(absolute_path_of_directory)

	fArray(fString) linker_inputs;
	
	fArray(ffzChecker*) checker_from_poly_idx; // key: ffzPolymorphIdx
	//fArray(ffzNode*) node_from_idx;

	fArray(ffzChecker*) checkers; // key: ffzCheckerIndex
	fArray(ffzParser*) parsers_dependency_sorted; // key: ffzParserIndex // dependency sorted from leaf modules towards higher-level modules
} ffzProject;

//ffzToken token_from_node(ffzProject* project, ffzNode* node);

void ffz_log_pretty_error(ffzParser* parser, fString error_kind, ffzLocRange loc, fString error, bool extra_newline);

bool ffz_parse_and_check_directory(ffzProject* project, fString directory);

bool ffz_build_directory(fString directory);
