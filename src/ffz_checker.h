//
// ffz_checker is a submodule within ffz whose purpose is to check if a given ffz program is valid or not.
// This includes figuring out the types of expressions and checking if they match, substituting polymorphic types and making them concrete,
// amongst other things. While doing so, the checker caches information about the program, such as type information, that can be useful in later stages.
// The checker takes in an abstract syntax tree form of a program as input, so it is dependend on "ffz_ast.h".
// 

struct ffzChecker;

typedef enum ffzTypeTag {
	ffzTypeTag_Invalid,

	ffzTypeTag_Raw,
	ffzTypeTag_Type,
	ffzTypeTag_PolyProc, // this is the type of an entire polymorphic procedure including a body
	ffzTypeTag_PolyRecord, // nothing should ever actually have the type of this - but a polymorphic struct type definition will type type to this
	ffzTypeTag_Module,

	ffzTypeTag_Bool,
	ffzTypeTag_Pointer,

	// :TypeIsInteger
	ffzTypeTag_SizedInt, // maybe SizedInt/SizedUint could be a flag if we would have flags in types?
	ffzTypeTag_SizedUint,
	ffzTypeTag_Int,
	ffzTypeTag_Uint,

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


typedef u64 ffzHash; // TODO: increase this to 128 bits.
typedef ffzHash ffzNodeInstHash;
typedef ffzHash ffzPolymorphHash; // PolyInstHash should be consistent across modules across identical code!
typedef ffzHash ffzTypeHash; // Should be consistent across modules across identical code!
typedef ffzHash ffzConstantHash; // Should be consistent across modules across identical code!

// Hmm. We could store a compressed version of NodeInst in our data structures (down to 8 bytes from 16)
// typedef struct ffzNodeInstSlim { ffzNodeIdx node; ffzPolyInstIdx poly_inst; } ffzNodeInstSlim;

#define FFZ_DECLARE_NODE_INST_TYPE(T)\
	struct T##Inst {\
		T* /*opt*/ node;\
		ffzPolymorphIdx poly_idx;\
	}

FFZ_DECLARE_NODE_INST_TYPE(ffzNode);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeDeclaration);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeAssignment);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeTag);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeTagDecl);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeIdentifier);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeDot);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodePolyParamList);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeKeyword);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeOperator);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeIf);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeFor);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeProcType);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeRecord);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeEnum);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeScope);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeReturn);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeIntLiteral);
FFZ_DECLARE_NODE_INST_TYPE(ffzNodeStringLiteral);

struct ffzType;

/*typedef struct ffzCheckerStackFrame ffzCheckerStackFrame;
struct ffzCheckerStackFrame {
	ffzParser* parser;
	ffzNodeInst scope;
	//Slice<AstNode*> poly_path; // this is only for error reporting

	// TODO: cleanup
	OPT(ffzNodeInst) current_proc;
	OPT(ffzType*) current_proc_type;
};*/

typedef struct ffzCheckerScope {
	ffzNode* node;
	ffzCheckerScope* parent;
} ffzCheckerScope;

typedef struct ffzTypeRecordField {
	fString name;
	ffzType* type;
	u32 offset;
	ffzNodeDeclaration* /*opt*/ decl;
} ffzTypeRecordField;

typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;
struct ffzTypeRecordFieldUse {
	ffzType* type;
	u32 offset;
};

typedef struct ffzTypeProcParameter {
	ffzNodeIdentifier* name;
	ffzType* type;
} ffzTypeProcParameter;

typedef struct ffzTypeEnumField {
	fString name;
	u64 value;
} ffzTypeEnumField;

typedef struct ffzType {
	ffzTypeTag tag;
	u32 size;
	u32 align;
	
	union {
		// unique_node is available for struct, union, enum, and proc types.
		ffzNodeInst unique_node;
		struct {
			void* _;
			ffzPolymorphIdx poly_idx; // poly_idx is available for all types. FIXME: currently it's not!!
		};
	};

	fSlice(ffzTypeRecordField) record_fields; // available for struct, union, slice types and the string type.

	union {
		struct {
			//ffzNodeProcTypeInst type_node;
			fSlice(ffzTypeProcParameter) in_params;
			ffzTypeProcParameter* /*opt*/ out_param;
		} Proc, PolyProc;
		
		struct {
			//ffzNodeRecordInst /*opt*/ node;
			bool is_union; // otherwise struct
		} Record, PolyRecord;

		struct {
			//ffzNodeEnumInst node;
			ffzType* internal_type;
			fSlice(ffzTypeEnumField) fields;
		} Enum;
		
		struct {
			ffzType* elem_type;
		} fSlice;

		struct {
			ffzType* elem_type;
			s32 length; // -1 means length is inferred by [?]
		} FixedArray;

		struct {
			ffzType* /*opt*/ pointer_to;
		} Pointer;
	};
} ffzType;

typedef struct ffzConstant {
	union {
		s64 s8_;
		s64 s16_;
		s64 s32_;
		s64 s64_;
		u64 u8_;
		u64 u16_;
		u64 u32_;
		u64 u64_;
		u16 f16_;
		f32 f32_;
		f64 f64_;
		bool bool_;
		ffzConstant* /*opt*/ ptr;

		ffzType* type;
		ffzChecker* module;
		fString string_zero_terminated; // length doesn't contain the zero termination.

		// tightly-packed array of ffzConstant. i.e. if this is an array of u8,
		// the n-th element would be ((ffzConstant*)((u8*)array_elems + n))->_u8.
		// You can use ffz_constant_fixed_array_get() to get an element from it.
		void* fixed_array_elems; // or NULL for zero-initialized
		
		// ProcType if @extern proc, otherwise Operator.
		// Currently, procedure definitions are actually categorized as "operators" in the AST,
		// because they have the form of `procedure_type{}`, which might seem a bit strange at first.
		ffzNodeInst proc_node;
		
		fSlice(ffzConstant) record_fields; // or empty for zero-initialized
	};
} ffzConstant;

typedef struct ffzCheckedExpr {
	ffzType* /*opt*/ type;
	ffzConstant* /*opt*/ const_val;
} ffzCheckedExpr;

typedef struct ffzPolymorph {
	ffzNode* node;
	fSlice(ffzCheckedExpr) parameters;
} ffzPolyInst;

typedef u64 ffzMemberHash;
typedef u64 ffzEnumValueHash;

// Checker is responsible for checking some chunk of code (currently must be a single module) and caching information about it.
struct ffzChecker {
	ffzProject* project; // should we make this void*?
	ffzCheckerIndex self_idx;
	fAllocator* alc;
	u32 pointer_size;

#ifdef _DEBUG
	fString _dbg_module_import_name;
#endif

	ffzType builtin_types[ffzKeyword_string+1 - ffzKeyword_u8];

	// implicit state for the current checker invocation
	//OPT(ffzNodeInst) parent_proc;
	//OPT(ffzType*) parent_proc_type;
	ffzCheckerScope* current_scope;
	fMap64Raw checked_identifiers; // key: ffz_hash_poly_inst. This is to detect cycles. We could reduce the memory footprint here by removing things as we go...

	// "declaration" is when it has a `:` token, e.g.  foo: 20  is a declaration.
	// "definition" is also a declaration, but it's not parsed into the AST as that form. e.g. in  struct[T]{...}  the polymorphic argument T is a definition.
	
	fMap64(ffzNodeIdentifier*) definition_map; // key: ffz_hash_declaration_path.
	//Map64<ffzNodeIdentifier*> definition_from_node; // key: ffzNode*

	fMap64(ffzType*) type_from_hash; // key: TypeHash
	fMap64(ffzCheckedExpr) cache; // key: ffz_hash_node_inst. Statements have NULL entries.
	
	ffzPolymorphIdx base_poly_idx;
	fMap64(ffzPolymorph) poly_from_idx; // key: (u64)ffzPolyInstIdx // maybe this should be moved into Project and turned into an array
	fMap64(ffzPolymorphIdx) poly_idx_from_hash; // key: ffz_hash_poly_inst
	fMap64(ffzPolymorphIdx) poly_instantiation_sites; // key: ffz_has_node_inst

	fMap64(ffzTypeRecordFieldUse*) record_field_from_name; // key: MemberKey

	// Only required during checking.
	fMap64(u64) enum_value_from_name; // key: MemberKey.
	fMap64(ffzNode*) enum_value_is_taken; // key: EnumValuekey

	fMap64(ffzChecker*) imported_modules; // key: *AstNode. Maybe this should be moved into ffzProject since it doesn't change often (thinking about threading)

	void(*report_error)(ffzChecker* c, fSlice(ffzNode*) poly_path, ffzNode* at, fString error);
	//void* report_error_userptr;
};

#define FFZ_INST_AS(node,kind) (*(ffzNode##kind##Inst*)&(node))
#define FFZ_INST_BASE(node) (*(ffzNodeInst*)&(node))

#define FFZ_EACH_CHILD_INST(n, parent) (\
	ffzNodeInst n = {(parent.node) ? FFZ_BASE((parent).node)->children.first : NULL, (parent).poly_idx};\
	n.node = ffz_skip_tag_decls(n.node);\
	n.node = n.node->next)

#define FFZ_INST_CHILD(T, parent, child_access) T { (parent).node->child_access, (parent).poly_inst }

//#define FFZ_NODE_INST(p, n) ffzNodeInst{ (n), (p).poly_inst }

// -- Checker utilities  --------------------------------------------------------------

inline bool ffz_type_is_integer(ffzTypeTag tag) { return tag >= ffzTypeTag_SizedInt && tag <= ffzTypeTag_Uint; }
inline bool ffz_type_is_signed_integer(ffzTypeTag tag) { return tag == ffzTypeTag_SizedInt || tag == ffzTypeTag_Int; }

inline bool ffz_type_is_pointer_ish(ffzTypeTag tag) { return tag == ffzTypeTag_Pointer || tag == ffzTypeTag_Proc; }
inline bool ffz_type_is_integer_ish(ffzTypeTag tag) {
	return ffz_type_is_integer(tag) || tag == ffzTypeTag_Enum || tag == ffzTypeTag_Bool || tag == ffzTypeTag_Pointer || tag == ffzTypeTag_Proc;
}

u32 ffz_get_encoded_constant_size(ffzType* type);
ffzConstant ffz_constant_fixed_array_get(ffzType* array_type, ffzConstant* array, u32 index);

ffzNodeInst ffz_get_child_inst(ffzNodeInst parent, u32 idx);

ffzType* ffz_ground_type(ffzCheckedExpr checked); // TODO: get rid of this?
bool ffz_type_is_grounded(ffzType* type); // a type is grounded when a runtime variable may have that type.
bool ffz_type_is_comparable(ffzType* type);

fString ffz_type_to_string(ffzProject* p, ffzType* type);
const char* ffz_type_to_cstring(ffzProject* p, ffzType* type);

fString ffz_constant_to_string(ffzProject* p, ffzCheckedExpr constant);
const char* ffz_constant_to_cstring(ffzProject* p, ffzCheckedExpr constant);

//ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value);
ffzNodeInstHash ffz_hash_node_inst(ffzNodeInst inst);
//u64 ffz_hash_declaration_path(ffzDefinitionPath path);
//ffzMemberHash ffz_hash_member(ffzType* type, fString member_name);
ffzConstantHash ffz_hash_constant(ffzCheckedExpr constant);

inline ffzNodeInst ffz_get_toplevel_inst(ffzChecker* c, ffzNode* node) { return ffzNodeInst{node, c->base_poly_idx}; }
//ffzTypeHash ffz_hash_type(ffzType* type);
//ffzPolyInstHash ffz_hash_poly_inst(ffzPolyInst inst);

ffzType* /*opt*/ ffz_builtin_type(ffzChecker* c, ffzKeyword keyword);

// -- Checker operations --------------------------------------------------------------

ffzOk ffz_check_toplevel_statement(ffzChecker* c, ffzNode* node);
ffzOk ffz_instanceless_check(ffzChecker* c, ffzNode* node, bool recursive);

ffzChecker* ffz_checker_init(ffzProject* p, fAllocator* allocator);

// -- Accessing cached data -----------------------------------------------------------

inline ffzChecker* ffz_checker_from_poly_idx(ffzProject* p, ffzPolymorphIdx poly_idx) {
	F_ASSERT(poly_idx.idx != 0);
	return p->checker_from_poly_idx[poly_idx.idx];
}
inline ffzChecker* ffz_checker_from_inst(ffzProject* p, ffzNodeInst inst) { return ffz_checker_from_poly_idx(p, inst.poly_idx); }


// Currently may return NULL for some basic types! this might be changed though.
inline ffzChecker* ffz_checker_from_type(ffzProject* p, ffzType* type) { return p->checker_from_poly_idx[type->poly_idx.idx]; }

ffzPolymorph ffz_poly_from_idx(ffzProject* p, ffzPolymorphIdx idx);
inline ffzPolymorph ffz_poly_from_inst(ffzProject* p, ffzNodeInst inst) { return ffz_poly_from_idx(p, inst.poly_idx); }

inline bool ffz_is_polymorphic(ffzProject* p, ffzNodeInst inst) { return inst.poly_idx.idx != ffz_checker_from_inst(p, inst)->base_poly_idx.idx; }


bool ffz_find_top_level_declaration(ffzChecker* c, fString name, ffzNodeDeclarationInst* out_decl);

ffzNodeInst ffz_get_instantiated_expression(ffzProject* p, ffzNodeInst node); // do we need this?

bool ffz_type_find_record_field_use(ffzProject* p, ffzType* type, fString name, ffzTypeRecordFieldUse* out);
//fSlice(ffzTypeRecordField) ffz_type_get_record_fields(ffzChecker* c, ffzType* type);

ffzCheckedExpr ffz_expr_get_checked(ffzProject* p, ffzNodeInst node);
inline ffzType* ffz_expr_get_type(ffzProject* p, ffzNodeInst node) { return ffz_expr_get_checked(p, node).type; }
inline ffzConstant* ffz_expr_get_evaluated_constant(ffzProject* p, ffzNodeInst node) { return ffz_expr_get_checked(p, node).const_val; }

ffzCheckedExpr ffz_decl_get_checked(ffzProject* p, ffzNodeDeclarationInst decl);
inline ffzType* ffz_decl_get_type(ffzProject* p, ffzNodeDeclarationInst node) { return ffz_decl_get_checked(p, node).type; }
inline ffzConstant* ffz_decl_get_evaluated_constant(ffzProject* p, ffzNodeDeclarationInst node) { return ffz_decl_get_checked(p, node).const_val; }

// "definition" is the identifier of a value that defines the name of the value.
// e.g. in  foo: int  the "foo" identifier would be a definition.
ffzNodeIdentifier* ffz_get_definition(ffzProject* p, ffzNodeIdentifier* ident);

bool ffz_get_decl_if_definition(ffzNodeIdentifierInst node, ffzNodeDeclarationInst* out_decl); // hmm... this is a bit weird.
//bool ffz_definition_is_constant(ffzNodeIdentifier* definition);

//bool ffz_decl_is_constant(ffzNodeDeclaration* decl);
bool ffz_decl_is_runtime_value(ffzNodeDeclaration* decl);

bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee);
