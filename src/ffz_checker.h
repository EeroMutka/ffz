//
// ffz_checker is a submodule within ffz whose purpose is to check if a given ffz program is valid or not.
// This includes figuring out the types of expressions and checking if they match, substituting polymorphic types and making them concrete,
// amongst other things. While doing so, the checker caches information about the program, such as type information, that can be useful in later stages.
// The checker takes in an abstract syntax tree form of a program as input, so it is dependend on "ffz_ast.h".
// 

struct ffzChecker;

typedef enum ffzTypeTag {
	ffzTypeTag_Invalid,

	ffzTypeTag_Type,
	ffzTypeTag_PolyProc, // this is the type of an entire polymorphic procedure including a body
	ffzTypeTag_PolyRecord, // nothing should ever actually have the type of this - but a polymorphic struct type definition will type type to this
	ffzTypeTag_Module,

	ffzTypeTag_Bool,
	ffzTypeTag_Pointer,
	ffzTypeTag_Void, // void is the type of an _ expression

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
	OPT(ffzNode*) parent_scope; // NULL for top-level scope
	String name;
};

typedef u64 ffzHash; // TODO: make this 128-bit.
typedef ffzHash ffzNodeInstHash;
typedef ffzHash ffzPolyInstHash; // PolyInstHash should be consistent across modules across identical code!
typedef ffzHash ffzTypeHash; // Should be consistent across modules across identical code!
typedef ffzHash ffzConstantHash; // Should be consistent across modules across identical code!

#define FFZ_DECLARE_NODE_INST_TYPE(T)\
	struct T##Inst {\
		OPT(T*) node;\
		ffzPolyInstHash poly_inst;\
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
	String name;
	ffzType* type;
	u32 offset;
	OPT(ffzNodeDeclaration*) decl;
} ffzTypeRecordField;

typedef struct ffzTypeRecordFieldUse ffzTypeRecordFieldUse;

struct ffzTypeRecordFieldUse {
	OPT(ffzTypeRecordFieldUse*) parent;
	ffzType* type;
	u32 offset_from_root;
	u32 local_index;
};

typedef struct ffzTypeProcParameter {
	ffzNodeIdentifier* name;
	ffzType* type;
} ffzTypeProcParameter;

typedef struct ffzTypeEnumField {
	String name;
	u64 value;
} ffzTypeEnumField;

typedef struct ffzType {
	ffzTypeTag tag;
	u32 size;
	u32 alignment;
	ffzChecker* module; // NULL for built-in types. TODO: lets just make it always valid
	
	union {
		struct {
			ffzNodeProcTypeInst type_node;
			//ffzNodeOperatorInst body_node; // should we have this?
			Slice<ffzTypeProcParameter> in_params;
			OPT(ffzTypeProcParameter*) out_param;
		} Proc, PolyProc;
		
		struct {
			Slice<ffzTypeRecordField> fields;
			OPT(ffzNodeRecordInst) node;
			bool is_union; // otherwise struct
		} Record, PolyRecord;

		struct {
			ffzNodeEnumInst node;
			ffzType* internal_type;
			Slice<ffzTypeEnumField> fields;
		} Enum;
		
		struct {
			ffzType* elem_type;
		} Slice;

		struct {
			ffzType* elem_type;
			s32 length; // -1 means length is inferred by [?]
		} FixedArray;

		struct {
			OPT(ffzType*) pointer_to;
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
		OPT(ffzConstant*) ptr; // can be NULL

		ffzType* type;
		ffzChecker* module;
		String string_zero_terminated;

		// tightly-packed array of ffzConstant. i.e. if this is an array of u8,
		// the n-th element would be ((ffzConstant*)((u8*)array_elems + n))->_u8.
		// You can use ffz_constant_fixed_array_get() to get an element from it.
		void* fixed_array_elems; // or NULL for zero-initialized
		
		// ProcType if @extern proc, otherwise Operator.
		// Currently, procedure definitions are actually categorized as "operators" in the AST,
		// because they have the form of `procedure_type{}`, which might seem a bit strange at first.
		ffzNodeInst proc_node;
		
		Slice<ffzConstant> record_fields; // or empty for zero-initialized
	};
} ffzConstant;

typedef struct ffzCheckedExpr {
	OPT(ffzType*) type;
	OPT(ffzConstant*) const_val;
} ffzCheckedExpr;

typedef struct ffzPolyInst {
	ffzNode* node;
	Slice<ffzCheckedExpr> parameters;
} ffzPolyInst;

typedef u64 ffzMemberHash;
typedef u64 ffzEnumValueHash;

// Checker is responsible for checking some chunk of code (currently must be a single module) and caching information about it.
struct ffzChecker {
	ffzProject* project;
	ffzCheckerIndex self_idx;
	Allocator* alc;

	u32 pointer_size;

#ifdef _DEBUG
	String _dbg_module_import_name;
#endif

	ffzType builtin_types[ffzKeyword_string+1 - ffzKeyword_u8];

	// implicit state for the current checker invocation
	//OPT(ffzNodeInst) parent_proc;
	//OPT(ffzType*) parent_proc_type;
	ffzCheckerScope* current_scope;
	
	// "declaration" is when it has a `:` token, e.g.  foo: 20  is a declaration.
	// "definition" is also a declaration, but it's not parsed into the AST as that form. e.g. in  struct[T]{...}  the polymorphic argument T is a definition.

	Map64<ffzNodeIdentifier*> definition_map; // key: ffz_hash_declaration_path.
	//Map64<ffzNodeIdentifier*> definition_from_node; // key: ffzNode*

	Map64<ffzType*> type_from_hash; // key: TypeHash
	Map64<ffzCheckedExpr> cache; // key: ffz_hash_node_inst. Statements have NULL entries.
	Map64<ffzPolyInst> poly_instantiations; // key: ffz_hash_poly_inst
	Map64<ffzPolyInstHash> poly_instantiation_sites; // key: ffz_has_node_inst
	Map64<ffzTypeRecordFieldUse*> record_field_from_name; // key: MemberKey
	Map64<u64> enum_value_from_name; // key: MemberKey. TODO: remove this and use the constant eval instead!
	Map64<ffzNode*> enum_value_is_taken; // key: EnumValuekey

	Map64<ffzChecker*> imported_modules; // key: *AstNode. Maybe this should be moved into ffzProject since it doesn't change often (thinking about threading)

	void(*report_error)(ffzChecker* c, Slice<ffzNode*> poly_path, ffzNode* at, String error);
	//void* report_error_userptr;
};

#define FFZ_INST_AS(node,kind) (*(ffzNode##kind##Inst*)&(node))
#define FFZ_INST_BASE(node) (*(ffzNodeInst*)&(node))

#define FFZ_EACH_CHILD_INST(n, parent) (\
	ffzNodeInst n = {(parent.node) ? FFZ_BASE((parent).node)->children.first : NULL, (parent).poly_inst};\
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

String ffz_type_to_string(ffzChecker* c, ffzType* type);
const char* ffz_type_to_cstring(ffzChecker* c, ffzType* type);

String ffz_constant_to_string(ffzChecker* c, ffzCheckedExpr constant);
const char* ffz_constant_to_cstring(ffzChecker* c, ffzCheckedExpr constant);

ffzEnumValueHash ffz_hash_enum_value(ffzType* enum_type, u64 value);
ffzNodeInstHash ffz_hash_node_inst(ffzNodeInst inst);
u64 ffz_hash_declaration_path(ffzDefinitionPath path);
ffzMemberHash ffz_hash_member(ffzType* type, String member_name);
ffzConstantHash ffz_hash_constant(ffzCheckedExpr constant); // do we need this? if we can map constants to node instances, why don't we use node inst hash?
ffzTypeHash ffz_hash_type(ffzType* type);
ffzPolyInstHash ffz_hash_poly_inst(ffzPolyInst inst);

OPT(ffzType*) ffz_builtin_type(ffzChecker* c, ffzKeyword keyword);

// -- Checker operations --------------------------------------------------------------

ffzOk ffz_check_toplevel_statement(ffzChecker* c, ffzNodeInst node); // TODO: cleanup
ffzOk ffz_instanceless_check(ffzChecker* c, ffzNode* node, bool recursive);

// -- Accessing cached data -----------------------------------------------------------

bool ffz_find_top_level_declaration(ffzChecker* c, String name, ffzNodeDeclarationInst* out_decl);

ffzNodeInst ffz_get_instantiated_expression(ffzChecker* c, ffzNodeInst node); // do we need this?

bool ffz_type_find_record_field_use(ffzChecker* c, ffzType* type, String name, ffzTypeRecordFieldUse* out);
Slice<ffzTypeRecordField> ffz_type_get_record_fields(ffzChecker* c, ffzType* type); // available for struct, union, slice types and the string type.

ffzCheckedExpr ffz_expr_get_checked(ffzChecker* c, ffzNodeInst node);
inline ffzType* ffz_expr_get_type(ffzChecker* c, ffzNodeInst node) { return ffz_expr_get_checked(c, node).type; }
inline ffzConstant* ffz_expr_get_evaluated_constant(ffzChecker* c, ffzNodeInst node) { return ffz_expr_get_checked(c, node).const_val; }

ffzCheckedExpr ffz_decl_get_checked(ffzChecker* c, ffzNodeDeclarationInst decl);
inline ffzType* ffz_decl_get_type(ffzChecker* c, ffzNodeDeclarationInst node) { return ffz_decl_get_checked(c, node).type; }
inline ffzConstant* ffz_decl_get_evaluated_constant(ffzChecker* c, ffzNodeDeclarationInst node) { return ffz_decl_get_checked(c, node).const_val; }

// "definition" is the identifier of a value that defines the name of the value.
// e.g. in  foo: int  the "foo" identifier would be a definition.
ffzNodeIdentifier* ffz_get_definition(ffzProject* project, ffzNodeIdentifier* ident);

bool ffz_get_decl_if_definition(ffzNodeIdentifierInst node, ffzNodeDeclarationInst* out_decl); // hmm... this is a bit weird.
bool ffz_definition_is_constant(ffzNodeIdentifier* definition);

bool ffz_decl_is_constant(ffzNodeDeclaration* decl);

bool ffz_dot_get_assignee(ffzNodeDotInst dot, ffzNodeInst* out_assignee);

ffzType* make_type(ffzChecker* c, ffzType type); // TODO: this shouldn't be exposed