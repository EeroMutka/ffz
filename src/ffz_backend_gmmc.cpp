#if 0
#include "foundation/foundation.hpp"

#include "GMMC/gmmc.h"

#include "ffz_ast.h"
#include "ffz_checker.h"
#include "ffz_backend_gmmc.h"
#include "ffz_lib.h"

#define SHA256_DECL extern "C"
#include "sha256.h"

// Helper macros

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

#define IAS(node, kind) FFZ_INST_AS(node, kind)
#define IBASE(node) FFZ_INST_BASE(node) 
#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).poly_inst }

struct GenExprDesc { bool get_address_of; bool must_be_constant; };

static gmmcValue* gen_expression(ffzBackend* gen, ffzNodeInst node, const GenExprDesc& desc);
static gmmcValue* gen_procedure(ffzBackend* gen, ffzNodeInst node);

static void set_gmmc_dbginfo_loc(ffzBackend* g, gmmcOp* op, ffzNodePosition pos) {
	if (!g->curr_proc->disable_setting_dbginfo_pos) {
		gmmc_di_op_set_line(op, pos.line_number);
	}
}

static OPT(gmmcValue*) gen_get_definition_value(ffzBackend* gen, ffzNodeIdentifierInst definition) {
	ffzNodeInstHash decl_hash = ffz_hash_node_inst(FFZ_INST_BASE(definition));
	if (gmmcValue** existing = map64_get(&gen->gmmc_definition_value, decl_hash)) return *existing;
	
	ffzNodeDeclarationInst decl;
	ASSERT(ffz_get_decl_if_definition(definition, &decl));

	OPT(gmmcValue*) gmmc_value = NULL;
	if (ffz_definition_is_constant(definition)) {
		gmmc_value = gen_expression(gen, ICHILD(decl,rhs), GenExprDesc{ false, true });
	}
	else {
		ffzType* type = ffz_expr_get_type(gen->checker, IBASE(definition));
		ASSERT(ffz_type_is_grounded(type));
		
		if (decl.node->base.parent->kind == ffzNodeKind_ProcType) { // parameter?
			gmmc_value = gmmc_val_param(gen->curr_proc->gmmc_proc, type->size, ffz_get_child_index(BASE(decl.node)));
		}
		else {
			gmmc_value = gmmc_val_local(gen->curr_proc->gmmc_proc, type->size);
		}
	}
	map64_insert(&gen->gmmc_definition_value, decl_hash, gmmc_value);
	return gmmc_value;
}

static void add_op(ffzBackend* g, gmmcOp* op, ffzNodePosition dbginfo_pos) {
	ASSERT(op);
	set_gmmc_dbginfo_loc(g, op, dbginfo_pos);
	array_push(&g->curr_proc->gmmc_ops, op);
}

static String fill_empty_name_with_id(ffzBackend* gen, String name) {
	if (name.len == 0) {
		name = str_format(gen->allocator, "#%u", gen->dummy_name_counter);
		gen->dummy_name_counter++;
	}
	return name;
}

static String make_export_name(ffzBackend* gen, ffzNodeInst inst) {
	Array<u8> name = make_array<u8>(gen->allocator);
	str_print(&name, ffz_get_parent_decl_name(inst.node));
	if (inst.poly_inst != 0) {
		str_print(&name, F_LIT("["));

		ffzPolyInst* poly_inst = map64_get(&gen->checker->poly_instantiations, inst.poly_inst);
		for (uint i = 0; i < poly_inst->parameters.len; i++) {
			if (i > 0) str_print(&name, F_LIT(", "));

			ASSERT(poly_inst->parameters[i]->tag == ffzTypeTag_Type);
			str_print(&name, ffz_type_to_string(gen->checker, poly_inst->parameters[i]->type.t));
		}

		str_print(&name, F_LIT("]"));
	}

	if (gen->checker->_dbg_module_import_name.len > 0) {
		// We don't want to export symbols from imported modules.
		// Currently, we're giving these symbols unique ids and exporting them anyway, because
		// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!

		BP;//export_name = str_join_il(gen->allocator, { gen->checker->imported_from_module_name, F_LIT("."), export_name });
	}
	return fill_empty_name_with_id(gen, name.slice);
}

static gmmcDITypeIdx to_gmmc_type(ffzBackend* gen, ffzType* type) {
	gmmcDITypeIdx* cached = map64_get(&gen->to_gmmc_type_idx, (u64)type);
	if (cached) return *cached;

	gmmcDIType gmmc_type = {};

	switch (type->tag) {
	case ffzTypeTag_Type: { ASSERT(false); } break;
	case ffzTypeTag_Bool: {
		gmmc_type.tag = gmmcDITypeTag_Int;
		gmmc_type.size = 1;
	} break;
	case ffzTypeTag_Pointer: {
		gmmc_type.tag = gmmcDITypeTag_Pointer;
		gmmc_type.size = 8;
		gmmc_type.Pointer.type_idx = to_gmmc_type(gen, type->Pointer.pointer_to);
	} break;
	case ffzTypeTag_Enum: {
		BP;//Slice<gmmcDIEnumField> fields = make_slice_garbage<gmmcDIEnumField>(type->Enum.fields.len, gen->allocator);
		//for (uint i = 0; i < fields.len; i++) {
		//	fields[i].name = BITCAST(gmmcString, type->Enum.fields[i].name->name);
		//	fields[i].value = (u32)type->Enum.fields[i].value; // NOTE: GMMC debug information enums don't support values > 2^32
		//}
		//
		//String name = make_export_name(gen, IBASE(type->Enum.node));
		//
		//gmmc_type.tag = gmmcDITypeTag_Enum;
		//gmmc_type.size = type->size;
		//gmmc_type.Enum.name = BITCAST(gmmcString, name);
		//gmmc_type.Enum.fields = fields.data;
		//gmmc_type.Enum.fields_count = (u32)fields.len;
	} break;
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_SizedInt: {
		gmmc_type.tag = gmmcDITypeTag_Int;
		gmmc_type.size = type->size;
	} break;
	case ffzTypeTag_UInt: // fallthrough
	case ffzTypeTag_SizedUInt: {
		gmmc_type.tag = gmmcDITypeTag_UnsignedInt;
		gmmc_type.size = type->size;
	} break;
	case ffzTypeTag_Float: {BP; } break;
	case ffzTypeTag_Proc: {
		gmmc_type.tag = gmmcDITypeTag_Int;
		gmmc_type.size = 8;
	} break;
	case ffzTypeTag_Record: {
		BP;//Slice<gmmcDIStructField> gmmc_members = make_slice_garbage<gmmcDIStructField>(type->Struct.fields.len, gen->allocator);
		//for (uint i = 0; i < type->Struct.fields.len; i++) {
		//	ffzTypeRecordField& m = type->Struct.fields[i];
		//	gmmc_members[i] = gmmcDIStructField{ BITCAST(gmmcString, m.name->name), to_gmmc_type(gen, m.type), m.offset };
		//}
		//
		//String name = make_export_name(gen, IBASE(type->Struct.node));
		////ffz_get_parent_decl_name(BASE(type->Struct.node.node)));
		//
		//gmmc_type.tag = gmmcDITypeTag_Struct;
		//gmmc_type.size = type->size;
		//gmmc_type.Struct.name = BITCAST(gmmcString, name);
		//gmmc_type.Struct.fields = gmmc_members.data;
		//gmmc_type.Struct.fields_count = (u32)gmmc_members.len;
	} break;
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Slice: {
		// TODO
		gmmc_type.tag = gmmcDITypeTag_Int;
		gmmc_type.size = 8;
	} break;
	case ffzTypeTag_FixedArray: {
		// This is a horrendous hack, but it works!

		Array<gmmcDIStructField> gmmc_members = make_array_cap<gmmcDIStructField>(8, gen->allocator);

		gmmcDITypeIdx elem_type_idx = to_gmmc_type(gen, type->FixedArray.elem_type);
		u32 elem_type_size = type->FixedArray.elem_type->size;

		u32 num_elements = type->size / elem_type_size;
		for (u32 i = 0; i < num_elements; i++) {
			gmmcDIStructField gmmc_member = {};
			gmmc_member.name = BITCAST(gmmcString, str_format(gen->allocator, "[%u]", i));
			gmmc_member.type_idx = elem_type_idx;
			gmmc_member.offset_of_member = i * elem_type_size;
			array_push(&gmmc_members, gmmc_member);
		}

		String name = fill_empty_name_with_id(gen, String{});
		gmmc_type.tag = gmmcDITypeTag_Struct;
		gmmc_type.size = type->size;
		gmmc_type.Struct.name = BITCAST(gmmcString, name);
		gmmc_type.Struct.fields = gmmc_members.data;
		gmmc_type.Struct.fields_count = (u32)gmmc_members.len;
	} break;
	}

	ASSERT(gmmc_type.tag != gmmcDITypeTag_Invalid);

	gmmcDITypeIdx idx = (gmmcDITypeIdx)gen->to_gmmc_type_idx.alive_count;
	array_push(&gen->gmmc_types, gmmc_type);
	map64_insert(&gen->to_gmmc_type_idx, (u64)type, idx);
	return idx;
}

static void add_dbginfo_local(ffzBackend* gen, ffzNodeIdentifierInst definition, String prefix = {}) {
	gmmcValue* value = gen_get_definition_value(gen, definition);
	ASSERT(value != NULL);

	ffzType* type = ffz_ground_type(ffz_expr_get_type(gen->checker, IBASE(definition)));
	
	String name = definition.node->name;
	if (prefix.len > 0) name = str_join_il(gen->allocator, { prefix, name });

	array_push(&gen->curr_proc->dbginfo_locals, gmmcDILocal{
		BITCAST(gmmcString, name),
		value,
		to_gmmc_type(gen, type),
		});
}

static void gen_return(ffzBackend* gen, OPT(gmmcValue*) return_value, ffzNodePosition pos) {
	ffzBackendProc* g = gen->curr_proc;
	if (g->proc_type->Proc.out_param && !return_value) {
		ffzNodeInst out_param_node = ICHILD(g->proc_type->Proc.type_node, out_parameter);

		if (AS(g->inst.node,Operator)->left->kind == ffzNodeKind_ProcType && out_param_node.node->kind == ffzNodeKind_Declaration) {
			return_value = gen_get_definition_value(gen, ICHILD(IAS(out_param_node,Declaration),name));
		}
		else {
			// To simplify checking, let's not make returning a value manually mandatory.
			return_value = gen_expression(gen, out_param_node, GenExprDesc{ false, true });
		}
	}
	add_op(gen, gmmc_op_return(g->gmmc_proc, return_value), pos);
}

static gmmcProcSignature* gen_get_proc_signature(ffzBackend* gen, ffzType* proc_type) {
	auto proc_sig = map64_insert(&gen->gmmc_proc_signature_from_type, (u64)proc_type, (gmmcProcSignature*)0, MapInsert_DoNotOverride);
	if (proc_sig.added) {
		Slice<u32> param_sizes = make_slice_garbage<u32>(proc_type->Proc.in_params.len, gen->allocator);
		for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
			ASSERT(proc_type->Proc.in_params[i].type->size > 0);
			param_sizes[i] = proc_type->Proc.in_params[i].type->size;
		}

		u32 return_size = proc_type->Proc.out_param ? proc_type->Proc.out_param->type->size : 0;
		*proc_sig._unstable_ptr = gmmc_make_proc_signature(gen->gmmc, return_size, param_sizes.data, (int)param_sizes.len);
	}
	return *proc_sig._unstable_ptr;
}

static gmmcValue* gen_call(ffzBackend* gen, ffzNodeOperatorInst node) {
	ASSERT(node.node->base.kind == ffzNodeKind_Operator);
	ffzNodeInst left = ICHILD(node, left);

	Array<gmmcValue*> arguments = make_array_cap<gmmcValue*>(8, gen->allocator);

	for FFZ_EACH_CHILD_INST(n, node) {
		gmmcValue* arg_val = gen_expression(gen, n, GenExprDesc{});
		array_push(&arguments, arg_val);
	}
	gmmcValue* proc_address = gen_expression(gen, left, GenExprDesc{});

	ffzType* proc_type = ffz_ground_type(ffz_expr_get_type(gen->checker, left));
	gmmcProcSignature* proc_signature = gen_get_proc_signature(gen, proc_type);

	gmmcValue* return_value = NULL;
	if (proc_type->Proc.out_param) {
		return_value = gmmc_val_local(gen->curr_proc->gmmc_proc, proc_type->Proc.out_param->type->size);
	}

	add_op(gen,
		gmmc_op_call(gen->curr_proc->gmmc_proc, proc_signature, proc_address, arguments.data, (int)arguments.len, return_value),
		node.node->base.start_pos);

	return return_value;
}

static void gen_code_statement(ffzBackend* gen, ffzNodeInst inst) {
	//HITS(_c, 8);
	switch (inst.node->kind) {
	
	case ffzNodeKind_Declaration: {
		ffzNodeDeclarationInst decl = IAS(inst,Declaration);
		ffzNodeIdentifierInst definition = ICHILD(decl,name);
		if (ffz_definition_is_constant(definition)) {
			// need to generate procs even if they're not used
			if (ffz_decl_get_type(gen->checker, decl)->tag == ffzTypeTag_Proc) {
				gmmcValue* _ = gen_get_definition_value(gen, definition);
			}
		}
		else {
			ffzNodeInst rhs = ICHILD(decl, rhs);

			// Generate store

			gmmcValue* src_value = gen_expression(gen, rhs, GenExprDesc{});
			if (ffz_expr_get_type(gen->checker, rhs)->tag == ffzTypeTag_Void) BP;
			
			gmmcValue* dst_address = gen_expression(gen, IBASE(definition), GenExprDesc{ true, false });
			add_op(gen, gmmc_op_store(gen->curr_proc->gmmc_proc, dst_address, src_value), definition.node->base.start_pos);

			add_dbginfo_local(gen, definition);
		}
	} break;

	case ffzNodeKind_Assignment: {
		ffzNodeAssignmentInst assign = IAS(inst,Assignment);
		ffzNodeInst rhs = ICHILD(assign, rhs);
		ffzNodeInst lhs = ICHILD(assign, lhs);
		
		// Generate store

		gmmcValue* src_value = gen_expression(gen, rhs, GenExprDesc{});
		if (ffz_expr_get_type(gen->checker, lhs)->tag != ffzTypeTag_Void) {
			gmmcValue* dst_address = gen_expression(gen, lhs, GenExprDesc{ true, false });
			add_op(gen, gmmc_op_store(gen->curr_proc->gmmc_proc, dst_address, src_value), lhs.node->start_pos);
		}
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_code_statement(gen, n);
		}
	} break;

	case ffzNodeKind_If: {
		ffzBackendProc* g = gen->curr_proc;
		ffzNodeIfInst if_stmt = IAS(inst,If);
		
		gmmcValue* condition = gen_expression(gen, ICHILD(if_stmt,condition), GenExprDesc{});

		int jump_over_else_idx;

		int jump_over_true_idx = (int)g->gmmc_ops.len;
		array_push(&g->gmmc_ops, (gmmcOp*)NULL);

		{ // if true
			gen_code_statement(gen, ICHILD(if_stmt,true_scope));

			if (if_stmt.node->else_scope) {
				jump_over_else_idx = (int)g->gmmc_ops.len;
				array_push(&g->gmmc_ops, (gmmcOp*)NULL);
			}
		}

		// if the condition is false, jump over here

		gmmcOp* jump_over_true = gmmc_op_jump_if(g->gmmc_proc, condition, true, (int)g->gmmc_ops.len);
		set_gmmc_dbginfo_loc(gen, jump_over_true, inst.node->start_pos);
		g->gmmc_ops[jump_over_true_idx] = jump_over_true;

		if (if_stmt.node->else_scope) { // if false
			gen_code_statement(gen, ICHILD(if_stmt,else_scope));
			// if the condition is true, jump over here

			gmmcOp* jump_over_else = gmmc_op_jump(g->gmmc_proc, (int)g->gmmc_ops.len);
			set_gmmc_dbginfo_loc(gen, jump_over_else, inst.node->start_pos);
			g->gmmc_ops[jump_over_else_idx] = jump_over_else;
		}
	} break;

	case ffzNodeKind_For: {
		ffzBackendProc* g = gen->curr_proc;
		ffzNodeForInst for_loop = IAS(inst, For);

		ffzNodeInst init_stmt = ICHILD(for_loop,header_stmts[0]);
		ffzNodeInst condition = ICHILD(for_loop,header_stmts[1]);
		ffzNodeInst post_stmt = ICHILD(for_loop,header_stmts[2]);
		ffzNodeInst body = ICHILD(for_loop,scope);

		ffzType* second_stmt_type = ffz_expr_get_type(gen->checker, condition);
		ASSERT(second_stmt_type->tag == ffzTypeTag_Bool);

		// e.g.
		// ...                 ; code before the loop
		// jmp condition       ; initial jump
		// body:
		// ...
		// condition:
		// cmp (...), 0
		// jne body
		// ...                 ; code after the loop

		if (init_stmt.node) {
			// :ForLoopNoinitialDebugPos
			// We do not call `SetGMMCOpDebugInfoPos` for the initial instructions of the for loop
			// (which includes the first header statement, and the initial jump instruction), because that would make the
			// line -> instruction mapping point to the initial instructions for the for loop's header line.
			// That'd make the debugger step over the header line after each loop iteration. We want the debugger
			// to step back to the condition every time.

			bool disable_setting_dbginfo_pos__before = g->disable_setting_dbginfo_pos;
			g->disable_setting_dbginfo_pos = true;

			//node->For.header_stmts[0]->start_pos.line_number = 1;
			gen_code_statement(gen, init_stmt);

			g->disable_setting_dbginfo_pos = disable_setting_dbginfo_pos__before;
		}

		int initial_jump_idx = (int)g->gmmc_ops.len;
		array_push(&g->gmmc_ops, (gmmcOp*)NULL);

		int body_idx = (int)g->gmmc_ops.len;
		gen_code_statement(gen, body);

		if (post_stmt.node) {
			gen_code_statement(gen, post_stmt);
		}

		int condition_idx = (int)g->gmmc_ops.len;
		gmmcValue* condition_val = gen_expression(gen, condition, GenExprDesc{});

		add_op(gen, gmmc_op_jump_if(g->gmmc_proc, condition_val, false, body_idx), inst.node->start_pos);

		// Note: no debug position is set for the jump op (:ForLoopNoinitialDebugPos)
		gmmcOp* initial_jump_op = gmmc_op_jump(g->gmmc_proc, condition_idx);
		g->gmmc_ops[initial_jump_idx] = initial_jump_op;
	} break;

	case ffzNodeKind_Keyword: {
		add_op(gen, gmmc_op_debugbreak(gen->curr_proc->gmmc_proc), inst.node->start_pos);
	} break;

	case ffzNodeKind_Return: {
		ffzNodeReturnInst ret = IAS(inst,Return);
		OPT(gmmcValue*) return_value = NULL;
		if (ret.node->value) {
			return_value = gen_expression(gen, ICHILD(ret,value), GenExprDesc{});
		}
		gen_return(gen, return_value, inst.node->start_pos);
	} break;

	case ffzNodeKind_Operator: {
		if (AS(inst.node,Operator)->kind == ffzOperatorKind_PostRoundBrackets) {
			gen_call(gen, IAS(inst,Operator));
		}
	} break;
	
	default: BP;
	}
}



static gmmcValue* gen_procedure(ffzBackend* gen, ffzNodeOperatorInst inst) {
	ffzNodeInst left = ICHILD(inst,left);

	ffzType* proc_type = ffz_expr_get_type(gen->checker, IBASE(inst));
	ASSERT(proc_type->tag == ffzTypeTag_Proc);

	if (ffz_get_child_count(BASE(proc_type->Proc.type_node.node->polymorphic_parameters)) > 0) {
		if (inst.poly_inst == 0 || map64_get(&gen->checker->poly_instantiations, inst.poly_inst)->node != BASE(inst.node)) {
			return NULL;
		}
	}

	auto proc_gen_cached = map64_insert(&gen->proc_gen, ffz_hash_node_inst(IBASE(inst)), ffzBackendProcGenerated{}, MapInsert_DoNotOverride);
	if (!proc_gen_cached.added) {
		return proc_gen_cached._unstable_ptr->gmmc_proc_value;
	}

	gmmcProcSignature* sig = gen_get_proc_signature(gen, proc_type);
	
	String export_name = make_export_name(gen, IBASE(inst));
	
	gmmcProcedure* _proc = gmmc_make_proc(gen->gmmc, sig, BITCAST(gmmcString, export_name));
	gmmcValue* proc_address = gmmc_val_proc_address(_proc);
	proc_gen_cached._unstable_ptr->gmmc_proc = _proc;
	proc_gen_cached._unstable_ptr->gmmc_proc_value = proc_address;

	ASSERT(_proc);

	ffzBackendProc* proc_bef = gen->curr_proc;
	ffzBackendProc proc_gen_ctx = {};
	proc_gen_ctx.proc_type = proc_type;
	proc_gen_ctx.gmmc_proc = _proc;
	proc_gen_ctx.inst = inst;
	proc_gen_ctx.gmmc_ops = make_array_cap<gmmcOp*>(32, gen->allocator);
	proc_gen_ctx.dbginfo_locals = make_array_cap<gmmcDILocal>(8, gen->allocator);
	gen->curr_proc = &proc_gen_ctx;

	for FFZ_EACH_CHILD_INST(n, proc_type->Proc.type_node) {
		String prefix = left.node->kind == ffzNodeKind_ProcType ? String{} : F_LIT("in.");
		add_dbginfo_local(gen, ICHILD(IAS(n,Declaration),name), prefix);
	}

	if (left.node->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		gen_code_statement(gen, ICHILD(IAS(left,ProcType),out_parameter));
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_code_statement(gen, n);
	}

	gen_return(gen, NULL, inst.node->base.end_pos); // Always return at the end of the procedure

	gmmc_proc_set_ops(_proc, proc_gen_ctx.gmmc_ops.data, (int)proc_gen_ctx.gmmc_ops.len);

	//if (dbginfo_name.len == 0) dbginfo_name = F_LIT("?");

	gmmcDIProcedure* proc_dbginfo = mem_clone(gmmcDIProcedure{}, gen->allocator);
	//proc_dbginfo->name = transmute(GMMC_String)dbginfo_name;
	proc_dbginfo->root_block.start_op_idx = 0;
	proc_dbginfo->root_block.end_op_idx = (int)proc_gen_ctx.gmmc_ops.len;
	proc_dbginfo->root_block.locals = proc_gen_ctx.dbginfo_locals.data;
	proc_dbginfo->root_block.locals_count = (int)proc_gen_ctx.dbginfo_locals.len;
	proc_dbginfo->file_index = inst.node->base.parser_idx;
	proc_dbginfo->entry_line_number = inst.node->base.start_pos.line_number;
	gmmc_di_proc_set_info(_proc, proc_dbginfo);

	gen->curr_proc = proc_bef;
	return proc_address;
}

//static void gen_slice_literal(Codegen* gen, GMMC_Value* result, GMMC_Constant* slice_data, u32 slice_length, AstNodePosition pos) {
//	GMMC_Constant* gmmc_ptr = GMMC_MakeValue_AddressOf(gen->gmmc, slice_data, 0);
//	GMMC_Constant* gmmc_len = GMMC_MakeValue_Constant(gen->gmmc, 8, mem_clone(s64{ slice_length }, gen->allocator));
//
//	GMMC_Value* ptr_field = GMMC_MakeValue_Subview(gen->gmmc, result, 0, 8);
//	GMMC_Value* len_field = GMMC_MakeValue_Subview(gen->gmmc, result, 8, 8);
//
//	add_op(gen, GMMC_MakeOp_CopyValue(gen->curr_proc->gmmc_proc, gmmc_ptr, ptr_field), pos);
//	add_op(gen, GMMC_MakeOp_CopyValue(gen->curr_proc->gmmc_proc, gmmc_len, len_field), pos);
//}

static gmmcValue* gen_constant_slice_literal(ffzBackend* gen, gmmcGlobal* slice_data, u32 slice_length) {
	gmmcValue* fields[2];
	fields[0] = gmmc_val_address_of(gen->gmmc, slice_data, 0);
	fields[1] = gmmc_val_constant(gen->gmmc, 8, mem_clone((s64)slice_length, gen->allocator));
	return gmmc_val_constant_composite(gen->gmmc, fields, 2);
}

static gmmcValue* gen_op_post_round_brackets(ffzBackend* gen, ffzNodeOperatorInst inst, const GenExprDesc& desc) {
	ffzNodeInst left = ICHILD(inst,left);
	gmmcValue* result = NULL;
	
	if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(AS(left.node,Keyword)->kind)) {
		ffzKeyword keyword = AS(left.node, Keyword)->kind;

		ASSERT(!desc.must_be_constant);
		ASSERT(!desc.get_address_of);

		ffzType* type = ffz_expr_get_type(gen->checker, IBASE(inst));
		result = gmmc_val_local(gen->curr_proc->gmmc_proc, type->size);

		gmmcOp* op = NULL;
		
		gmmcValue* first_value = gen_expression(gen, ffz_get_child_inst(IBASE(inst), 0), GenExprDesc{});

		if (keyword == ffzKeyword_bit_not) {
			op = gmmc_op_not(gen->curr_proc->gmmc_proc, first_value, result);
		}
		else {
			gmmcValue* second_value = gen_expression(gen, ffz_get_child_inst(IBASE(inst), 1), GenExprDesc{});

			if (keyword == ffzKeyword_bit_and)      op = gmmc_op_and(gen->curr_proc->gmmc_proc, first_value, second_value, result);
			else if (keyword == ffzKeyword_bit_or)  op = gmmc_op_or(gen->curr_proc->gmmc_proc, first_value, second_value, result);
			else if (keyword == ffzKeyword_bit_xor) op = gmmc_op_xor(gen->curr_proc->gmmc_proc, first_value, second_value, result);
			else BP;
		}

		add_op(gen, op, inst.node->base.start_pos);
	}
	else if (left.node->kind == ffzNodeKind_Keyword && AS(left.node,Keyword)->kind == ffzKeyword_size_of) {
		ffzNodeInst arg = ffz_get_child_inst(IBASE(inst), 0);
		ffzType* arg_type = ffz_expr_get_type(gen->checker, arg)->type.t;
		u64* size = mem_clone(u64(arg_type->size), gen->allocator);
		result = gmmc_val_constant(gen->gmmc, 8, size);
	}
	else {
		ffzType* left_type = ffz_expr_get_type(gen->checker, left);
		if (left_type->tag == ffzTypeTag_Type) {
			// :TypeCast    e.g. u32(501002)
			ffzType* type = left_type->type.t;
			ASSERT(ffz_type_is_integer(type->tag) || type->tag == ffzTypeTag_Pointer);

			ffzNodeInst arg = ffz_get_child_inst(IBASE(inst), 0);
			ffzType* arg_type = ffz_expr_get_type(gen->checker, arg);

			gmmcValue* val = gen_expression(gen, arg, desc);
			if (type->size <= arg_type->size) {
				result = gmmc_val_subview(gen->gmmc, val, 0, type->size);
			}
			else {
				result = gmmc_val_local(gen->curr_proc->gmmc_proc, type->size);
				add_op(gen, gmmc_op_extend_int(gen->curr_proc->gmmc_proc, ffz_type_is_signed_integer(arg_type->tag), val, result), inst.node->base.start_pos);
			}
		}
		else {
			ASSERT(!desc.must_be_constant);
			// procedure call
			result = gen_call(gen, inst);
		}
	}
	return result;
}

static gmmcValue* gen_dereference(ffzBackend* gen, ffzNodeInst left, const GenExprDesc& desc) {
	ffzType* left_type = ffz_expr_get_type(gen->checker, left);
	ASSERT(left_type->tag == ffzTypeTag_Pointer);
	gmmcValue* address = gen_expression(gen, left, GenExprDesc{});

	gmmcValue* result;
	if (desc.get_address_of) {
		result = address;
	}
	else {
		result = gmmc_val_local(gen->curr_proc->gmmc_proc, left_type->Pointer.pointer_to->size);
		add_op(gen, gmmc_op_load(gen->curr_proc->gmmc_proc, address, result), left.node->start_pos);
	}
	return result;
}

static gmmcValue* gen_operator(ffzBackend* gen, ffzNodeOperatorInst inst, const GenExprDesc& desc) {
	ffzNodeInst left = ICHILD(inst, left);
	ffzNodeInst right = ICHILD(inst, right);
	ffzOperatorKind kind = inst.node->kind;

	ffzType* type = ffz_expr_get_type(gen->checker, IBASE(inst));
	OPT(gmmcProcedure*) gmmc_proc = gen->curr_proc ? gen->curr_proc->gmmc_proc : NULL;
	gmmcValue* result = NULL;
	switch (kind) {

	case ffzOperatorKind_MemberAccess: { // :CheckMemberAccess
		ASSERT(!desc.must_be_constant);
		String member_name = AS(right.node, Identifier)->name;

		if (left.node->kind == ffzNodeKind_Identifier && AS(left.node, Identifier)->name == F_LIT("in")) {
			for (u32 i = 0; i < gen->curr_proc->proc_type->Proc.in_params.len; i++) {
				ffzTypeProcParameter& param = gen->curr_proc->proc_type->Proc.in_params[i];
				if (param.name->name == member_name) {
					result = gmmc_val_param(gen->curr_proc->gmmc_proc, param.type->size, i);
				}
			}
		}
		else {
			ffzType* left_type = ffz_expr_get_type(gen->checker, left);

			if (left_type->tag == ffzTypeTag_Module) {
				ffzChecker* checker_before = gen->checker;
				gen->checker = left_type->Module.module_checker;

				ffzNodeDeclarationInst decl;
				ASSERT(ffz_find_top_level_declaration(gen->checker, member_name, &decl));
				result = gen_expression(gen, ICHILD(decl,rhs), desc);
				
				gen->checker = checker_before;
			}
			else if (left_type->tag == ffzTypeTag_Type && left_type->type.t->tag == ffzTypeTag_Enum) {
				ffzMemberHash member_key = ffz_hash_member(left_type->type.t, member_name);
				u64* enum_value = map64_get(&gen->checker->enum_value_from_name, member_key);
				result = gmmc_val_constant(gen->gmmc, left_type->type.t->size, enum_value);
			}
			else {
				ffzType* dereferenced_type = left_type->tag == ffzTypeTag_Pointer ? left_type->Pointer.pointer_to : left_type;
				BP; // ffzTypeRecordField member;
				//ASSERT(ffz_find_record_field(gen->project->checkers[dereferenced_type->module], dereferenced_type, member_name, &member));
				
				// first get the address of the struct
				gmmcValue* left_value = gen_expression(gen, left, GenExprDesc{ left_type->tag != ffzTypeTag_Pointer });
				BP; // u64* offset = mem_clone(u64(member.offset), gen->allocator);
				gmmcValue* address = gmmc_val_local(gmmc_proc, 8);
				
				BP;//add_op(gen,
				//	gmmc_op_add(gmmc_proc, left_value, gmmc_val_constant(gen->gmmc, 8, offset), address),
				//	inst.node->base.start_pos);
				//
				//if (desc.get_address_of) {
				//	result = address;
				//}
				//else {
				//	result = gmmc_val_local(gmmc_proc, member.type->size);
				//	add_op(gen, gmmc_op_load(gmmc_proc, address, result), inst.node->base.start_pos);
				//}
			}
		}
	} break;

	case ffzOperatorKind_PostSquareBrackets: {
		ASSERT(!desc.must_be_constant);
		// Array subscript

		ffzNodeInst index_node = ffz_get_child_inst(IBASE(inst), 0);
		gmmcValue* left_value = gen_expression(gen, left, GenExprDesc{});
		ffzType* left_type = ffz_expr_get_type(gen->checker, left);

		gmmcValue* base_address;
		ffzType* elem_type;
		if (left_type->tag == ffzTypeTag_Slice) {
			base_address = gmmc_val_subview(gen->gmmc, left_value, 0, 8);
			elem_type = left_type->Slice.elem_type;
		}
		else if (left_type->tag == ffzTypeTag_FixedArray) {
			base_address = gmmc_val_address_of(gen->gmmc, left_value, 0);
			elem_type = left_type->FixedArray.elem_type;
		}
		else BP;

		gmmcValue* elem_address = gmmc_val_local(gmmc_proc, 8);

		gmmcValue* scale = gmmc_val_constant(gen->gmmc, 8, mem_clone(u64(elem_type->size), gen->allocator));
		gmmcValue* index = gen_expression(gen, index_node, GenExprDesc{});
		if (ffz_expr_get_type(gen->checker, index_node)->size < 8) BP;

		add_op(gen, gmmc_op_mul(gmmc_proc, false, index, scale, elem_address), inst.node->base.start_pos);
		add_op(gen, gmmc_op_add(gmmc_proc, base_address, elem_address, elem_address), inst.node->base.start_pos);

		if (desc.get_address_of) {
			result = elem_address;
		}
		else {
			result = gmmc_val_local(gmmc_proc, type->size);
			add_op(gen, gmmc_op_load(gmmc_proc, elem_address, result), inst.node->base.start_pos);
		}
	} break;

	case ffzOperatorKind_Add: case ffzOperatorKind_Sub: case ffzOperatorKind_Mul: case ffzOperatorKind_Div: case ffzOperatorKind_Modulo:
	{
		ASSERT(!desc.must_be_constant);
		ASSERT(!desc.get_address_of); // @check

		gmmcValue* left_value = gen_expression(gen, left, GenExprDesc{});
		gmmcValue* right_value = gen_expression(gen, right, GenExprDesc{});

		result = gmmc_val_local(gmmc_proc, type->size);
		bool is_signed = ffz_type_is_signed_integer(type->tag);

		gmmcOp* op = NULL;
		if (kind == ffzOperatorKind_Add) op = gmmc_op_add(gmmc_proc, left_value, right_value, result);
		else if (kind == ffzOperatorKind_Sub) op = gmmc_op_sub(gmmc_proc, left_value, right_value, result);
		else if (kind == ffzOperatorKind_Mul) op = gmmc_op_mul(gmmc_proc, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_Div) op = gmmc_op_div(gmmc_proc, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_Modulo) op = gmmc_op_mod(gmmc_proc, is_signed, left_value, right_value, result);
		else ASSERT(false);

		if (!ffz_type_is_integer(type->tag)) BP;

		add_op(gen, op, inst.node->base.start_pos);
	} break;

	case ffzOperatorKind_Equal: case ffzOperatorKind_NotEqual: case ffzOperatorKind_Less:
	case ffzOperatorKind_LessOrEqual: case ffzOperatorKind_Greater: case ffzOperatorKind_GreaterOrEqual:
	{
		ASSERT(!desc.must_be_constant);
		ASSERT(!desc.get_address_of);
		ffzType* left_type = ffz_expr_get_type(gen->checker, left);
		ffzType* right_type = ffz_expr_get_type(gen->checker, right);
		ASSERT(ffz_type_is_integer(left_type->tag) && ffz_type_is_integer(right_type->tag));

		gmmcValue* left_value = gen_expression(gen, left, GenExprDesc{});
		gmmcValue* right_value = gen_expression(gen, right, GenExprDesc{});

		result = gmmc_val_local(gmmc_proc, 1);
		bool is_signed = ffz_type_is_signed_integer(left_type->tag) || ffz_type_is_signed_integer(right_type->tag); // uint implicitly casts to int

		gmmcOp* op = NULL;
		if (kind == ffzOperatorKind_Greater)             op = gmmc_op_compare(gmmc_proc, gmmcCompare_GreaterThan, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_GreaterOrEqual) op = gmmc_op_compare(gmmc_proc, gmmcCompare_GreaterThanOrEqual, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_Less)           op = gmmc_op_compare(gmmc_proc, gmmcCompare_LessThan, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_LessOrEqual)    op = gmmc_op_compare(gmmc_proc, gmmcCompare_LessThanOrEqual, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_Equal)          op = gmmc_op_compare(gmmc_proc, gmmcCompare_Equal, is_signed, left_value, right_value, result);
		else if (kind == ffzOperatorKind_NotEqual)       op = gmmc_op_compare(gmmc_proc, gmmcCompare_NotEqual, is_signed, left_value, right_value, result);
		else ASSERT(false);

		add_op(gen, op, inst.node->base.start_pos);
	} break;

	case ffzOperatorKind_LogicalAND: case ffzOperatorKind_LogicalOR: {
		ASSERT(!desc.must_be_constant);
		ASSERT(!desc.get_address_of);
		ASSERT(ffz_expr_get_type(gen->checker, left)->tag == ffzTypeTag_Bool && ffz_expr_get_type(gen->checker, right)->tag == ffzTypeTag_Bool);
		gmmcValue* left_value = gen_expression(gen, left, GenExprDesc{});

		result = gmmc_val_local(gmmc_proc, 1);
		add_op(gen, gmmc_op_copy(gmmc_proc, left_value, result), inst.node->base.start_pos);

		uint jump_op_idx = array_push(&gen->curr_proc->gmmc_ops, {});

		gmmcValue* right_value = gen_expression(gen, right, GenExprDesc{});

		bool jump_if_zero;
		if (kind == ffzOperatorKind_LogicalAND) {
			add_op(gen, gmmc_op_and(gmmc_proc, result, right_value, result), inst.node->base.start_pos);
			jump_if_zero = true;
		}
		else {
			add_op(gen, gmmc_op_or(gmmc_proc, result, right_value, result), inst.node->base.start_pos);
			jump_if_zero = false;
		}

		gen->curr_proc->gmmc_ops[jump_op_idx] = gmmc_op_jump_if(gen->curr_proc->gmmc_proc,
			left_value, jump_if_zero, (u32)gen->curr_proc->gmmc_ops.len);
	} break;

	case ffzOperatorKind_UnaryMinus: case ffzOperatorKind_UnaryPlus: case ffzOperatorKind_UnaryMemberAccess:
	case ffzOperatorKind_AddressOf: case ffzOperatorKind_PointerTo: case ffzOperatorKind_LogicalNOT:
	{
		ASSERT(!desc.must_be_constant);
		ASSERT(!desc.get_address_of);
		if (kind == ffzOperatorKind_LogicalNOT) {
			ASSERT(ffz_expr_get_type(gen->checker, right)->tag == ffzTypeTag_Bool);
			gmmcValue* right_value = gen_expression(gen, right, GenExprDesc{});

			// Logical NOT can be implemented by comparing against zero.
			// An alternative way would be to do ~x & 1
			result = gmmc_val_local(gmmc_proc, 1);
			add_op(gen, gmmc_op_compare(gmmc_proc, gmmcCompare_Equal, false, right_value, gen->gmmc_false, result), inst.node->base.start_pos);
		}
		else if (kind == ffzOperatorKind_AddressOf) {
			result = gen_expression(gen, right, GenExprDesc{ true, false });
		}
		else if (kind == ffzOperatorKind_UnaryMinus || kind == ffzOperatorKind_UnaryPlus) {
			ffzType* right_type = ffz_expr_get_type(gen->checker, right);
			gmmcValue* right_value = gen_expression(gen, right, GenExprDesc{});
			if (kind == ffzOperatorKind_UnaryMinus) {
				result = gmmc_val_local(gmmc_proc, right_type->size);

				gmmcValue* zero = gmmc_val_constant(gen->gmmc, right_type->size, NULL);
				add_op(gen, gmmc_op_sub(gmmc_proc, zero, right_value, result), inst.node->base.start_pos);
			}
			else {
				result = right_value;
			}
		}
		else if (kind == ffzOperatorKind_PointerTo) {}
		else BP;
	} break;

	case ffzOperatorKind_Dereference: {
		ASSERT(!desc.must_be_constant);
		result = gen_dereference(gen, left, desc);
	} break;

	case ffzOperatorKind_PostRoundBrackets: {
		result = gen_op_post_round_brackets(gen, inst, desc);
	} break;

	case ffzOperatorKind_PostCurlyBrackets: {
		ASSERT(!desc.get_address_of);
		ffzType* left_type = ffz_expr_get_type(gen->checker, left);
		ASSERT(left_type->tag == ffzTypeTag_Type);

		ffzType* left_is_a_type = left_type->type.t;

		u32 num_arguments = ffz_get_child_count(BASE(inst.node));
		if (left_is_a_type->tag == ffzTypeTag_Record) {
			result = gmmc_val_local(gmmc_proc, left_is_a_type->size);
			ASSERT(!desc.must_be_constant);
			uint i = 0;
			for FFZ_EACH_CHILD_INST(n, inst) {
				BP;//ffzTypeRecordField& m = left_is_a_type->Struct.fields[i];
				//gmmcValue* src = gen_expression(gen, n, GenExprDesc{});
				//gmmcValue* dst = gmmc_val_subview(gen->gmmc, result, m.offset, m.type->size);
				//add_op(gen, gmmc_op_copy(gmmc_proc, src, dst), inst.node->base.start_pos);
				//i++;
			}
		}
		else if (left_is_a_type->tag == ffzTypeTag_Slice) {
			ASSERT(left_is_a_type->size == 16);
			// Slice literal

			Slice<gmmcValue*> elements = make_slice_garbage< gmmcValue*>(num_arguments, gen->allocator);
			uint i = 0;
			for FFZ_EACH_CHILD_INST(n, inst) {
				elements[i] = gen_expression(gen, n, GenExprDesc{ false, true });
				i++;
			}

			gmmcValue* slice_data = gmmc_val_constant_composite(gen->gmmc, elements.data, (u32)elements.len);
			result = gen_constant_slice_literal(gen, slice_data, (u32)elements.len);
		}
		else if (left_is_a_type->tag == ffzTypeTag_FixedArray) {
			ASSERT(!desc.must_be_constant);
			
			result = gmmc_val_local(gmmc_proc, left_is_a_type->size);

			u32 elem_size = left_is_a_type->FixedArray.elem_type->size;
			u32 i = 0;
			for FFZ_EACH_CHILD_INST(n, inst) {
				gmmcValue* src = gen_expression(gen, n, GenExprDesc{});
				gmmcValue* dst = gmmc_val_subview(gen->gmmc, result, i * elem_size, elem_size);
				add_op(gen, gmmc_op_copy(gmmc_proc, src, dst), inst.node->base.start_pos);
				i++;
			}
		}
		else if (left_is_a_type->tag == ffzTypeTag_Proc) {
			result = gen_procedure(gen, inst);
		}
		else BP;
	} break;
	default: BP;
	}
	return result;
}

static OPT(gmmcValue*) gen_expression(ffzBackend* gen, ffzNodeInst inst, const GenExprDesc& desc) {
	if (desc.must_be_constant) ASSERT(!desc.get_address_of);

	OPT(gmmcProcedure*) gmmc_proc = gen->curr_proc ? gen->curr_proc->gmmc_proc : NULL;

	inst = ffz_get_instantiated_expression(gen->checker, inst);
	gmmcValue* result = NULL;

	ffzType* type = ffz_expr_get_type(gen->checker, inst);
	if (type->tag == ffzTypeTag_Type) {
		ASSERT(!desc.get_address_of);

		// if this expression is a type, return the default value for this type.

		// default (zero) value for the type
		result = gmmc_val_constant(gen->gmmc, type->type.t->size, NULL);

		//result = GenConstant(gen, node);
		ASSERT(result);
		return result;
	}

	switch (inst.node->kind) {
	case ffzNodeKind_Identifier: {
		ffzNodeIdentifierInst def = ffz_get_definition(gen->checker, IAS(inst,Identifier));
		if (desc.must_be_constant) ASSERT(ffz_definition_is_constant(def));
		result = gen_get_definition_value(gen, def);
		
		if (desc.get_address_of) {
			result = gmmc_val_address_of(gen->gmmc, result, 0);
		}
	} break;

	case ffzNodeKind_Keyword: {
		if (AS(inst.node,Keyword)->kind == ffzKeyword_true) return gen->gmmc_true;
		if (AS(inst.node,Keyword)->kind == ffzKeyword_false) return gen->gmmc_false;
	} break;

	case ffzNodeKind_Dot: {
		BP;//AstNodePolyInst decl = get_decl_inst(gen->checker, node);
		//if (desc.must_be_constant) ASSERT(stmt_is_constant_decl(decl.node));
		//result = gen_get_decl_value(gen, decl);
		//if (desc.get_address_of) {
		//	result = GMMC_MakeValue_AddressOf(gen->gmmc, result, 0);
		//}
	} break;

	case ffzNodeKind_Operator: {
		result = gen_operator(gen, IAS(inst,Operator), desc);
	} break;

	case ffzNodeKind_IntLiteral: {
		ASSERT(type != NULL);

		String data = { (u8*)&AS(inst.node,IntLiteral)->value, type->size };
		result = gmmc_val_constant(gen->gmmc, (u32)data.len, data.data);
	} break;

	case ffzNodeKind_Record: {
		ASSERT(!desc.get_address_of);
		ffzType* struct_type = ffz_ground_type(type);
		result = gmmc_val_constant(gen->gmmc, struct_type->size, NULL);
	} break;

	case ffzNodeKind_ProcType: {
		if (ffz_node_get_compiler_tag(inst.node, F_LIT("extern"))) {
			String name = ffz_get_parent_decl_name(inst.node);
			result = gmmc_val_extern_sym_address(gen->gmmc, 8, BITCAST(gmmcString, name));
		}
		else BP;
		//ASSERT(!desc.get_address_of); // tocheck
		//result = gen_procedure(gen, node, desc.export_name);
	} break;

	case ffzNodeKind_StringLiteral: {
		// TODO: make sure this is not duplicated (like any other constants) for different poly instances

		// hmm yeah maybe it's a bit dumb to have "import" be a compiler tag.
		if (ffz_node_get_compiler_tag(inst.node, F_LIT("import"))) return NULL;

		String str = AS(inst.node,StringLiteral)->zero_terminated_string;
		ASSERT(str.len > 0 && str.len + 1 < U32_MAX);
		gmmcValue* string_constant = gmmc_val_constant(gen->gmmc, (u32)str.len + 1, str.data);
		result = gen_constant_slice_literal(gen, string_constant, (u32)str.len);
		
		if (desc.get_address_of) {
			result = gmmc_val_address_of(gen->gmmc, result, 0);
		}
	} break;

	default: BP;
	}

	ASSERT(result);
	return result;
}

void ffz_gmmc_generate(ffzProject* project, ffzBackend* gen, String objname) {
	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		gen->checker = project->checkers[parser->checker_idx];
		//ProjectFile pair = project->project_files_dependency_sorted[i];
		//gen->curr_parser = project->parsers_dependency_sorted[i];

		//gen->source_code_file_index = i;
		for FFZ_EACH_CHILD(n, parser->root) {
			gen_code_statement(gen, ffzNodeInst{ n, 0 });
		}
	}

	Slice<gmmcDISourceFile> files = make_slice_garbage<gmmcDISourceFile>(project->parsers_dependency_sorted.len, gen->allocator);

	gmmcDIInfo dbg_info = {};
	dbg_info.objname = BITCAST(gmmcString, objname);
	dbg_info.files = files.data;
	dbg_info.files_count = (u32)files.len;
	dbg_info.types = gen->gmmc_types.data;
	dbg_info.types_count = (int)gen->gmmc_types.len;

	for (uint i = 0; i < files.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];

		SHA256_CTX ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, parser->source_code.data, parser->source_code.len);

		gmmcHashSHA256 result = {};
		sha256_final(&ctx, result.bytes);
		files[i].filepath = BITCAST(gmmcString, parser->source_code_filepath);
		files[i].hash = result;
	}

	gmmc_build(gen->gmmc);

	gmmc_create_windows_obj(gen->gmmc, &dbg_info, [](gmmcString data, void* userptr) {
		String path = *(String*)userptr;
		bool ok = os_file_write_whole(path, { data.data, data.len });
		ASSERT(ok);
		}, &objname);
}
#endif