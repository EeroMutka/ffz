#ifdef FFZ_BACKEND_TB

#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

#include "ffz_backend_tb.h"

#pragma warning(disable:4200)
#include "Cuik/tb/include/tb.h"

// hack, to get TB to compile
extern "C" uint64_t cuik_time_in_nanos(void) { return 0; }
extern "C" void cuikperf_region_start(uint64_t now, const char* fmt, const char* extra) {}
extern "C" void cuikperf_region_end(void) {}

static fAllocator* tb_allocator = NULL;
//static Arena* tb_arena = {};
#define todo F_BP

extern "C" {
	void* tb_platform_heap_alloc(size_t size) {
		// TODO: mutex lock
		return f_mem_alloc(size, 16, tb_allocator);
		//void* result = arena_push_size(tb_arena, size, 16).data;
		//memset(result, 0, size);
		//return result;
	}
	void* tb_platform_heap_realloc(void* ptr, size_t size) {
		//HITS(_c, 3);
		// hmm.. can't mem_resize() because that requires the size. We could allocate a prefix for it
		void* out = f_mem_alloc(size, 16, tb_allocator);
		if (ptr) memcpy(out, ptr, size);
		//return mem_resize(ptr, 
		//void* out = arena_push_size(tb_arena, size, 16).data;
		return out;
	}
	void tb_platform_heap_free(void* ptr) {}
}

union Constant {
	TB_Symbol* symbol;
};

/*struct Local {
	TB_Reg reg;
	bool is_big_parameter;
};*/

struct Gen {
	ffzProject* project;
	fAllocator* alc;
	ffzChecker* checker;

	TB_Module* tb;
	TB_Function* fn;
	TB_Reg func_big_return;

	uint dummy_name_counter;
	
	fMap64(TB_Function*) func_from_hash;
	fMap64(TB_Reg) tb_local_addr_from_definition;
	fArray(TB_FileID) tb_file_from_parser_idx;
};

// Helper macros for ffz

#define AS(node,kind) FFZ_AS(node, kind)
#define BASE(node) FFZ_BASE(node)

#define IAS(node, kind) FFZ_INST_AS(node, kind)
#define IBASE(node) FFZ_INST_BASE(node) 
#define ICHILD(parent, child_access) { (parent).node->child_access, (parent).polymorph }

// holds either a value, or a pointer to the value if the size of the type > 8 bytes
struct SmallOrPtr {
	TB_Reg small;
	TB_Reg ptr;
	bool ptr_can_be_stolen; // if false, the caller must make a local copy of the value if they need it. Otherwise, they can just take it and pretend its their own copy.
};

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc = true);
static SmallOrPtr gen_expr(Gen* g, ffzNodeInst inst, bool address_of = false);

//static const char* make_type_name(Gen* g, ffzType* type) {
//}

static const char* make_name(Gen* g, ffzNodeInst inst = {}, bool pretty = true) {
	fArray(u8) name = f_array_make<u8>(g->alc);

	if (inst.node) {
		f_str_print(&name, ffz_get_parent_decl_name(inst.node));
		
		if (inst.polymorph) {
			/*if (pretty) {
				f_str_print(&name, F_LIT("["));

				for (uint i = 0; i < inst.polymorph->parameters.len; i++) {
					if (i > 0) f_str_print(&name, F_LIT(", "));

					f_str_print(&name, ffz_constant_to_string(g->project, inst.polymorph->parameters[i]));
				}

				f_str_print(&name, F_LIT("]"));
			}*/
			//else {
			//	// hmm.. deterministic index for polymorph, how?
			//	//F_BP; // f_str_printf(&name, "$%u", inst.poly_idx.idx);
			//}
			f_str_printf(&name, "$%xll", inst.polymorph->hash);
		}
		
		if (g->checker->_dbg_module_import_name.len > 0) {
			// We don't want to export symbols from imported modules.
			// Currently, we're giving these symbols unique ids and exporting them anyway, because
			// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!

			if (!ffz_node_get_compiler_tag(inst.node, F_LIT("extern"))) {
				f_str_print(&name, F_LIT("$$"));
				f_str_print(&name, g->checker->_dbg_module_import_name);
			}
		}
	}
	else {
		f_str_printf(&name, "_ffz_%llu", g->dummy_name_counter);
		g->dummy_name_counter++;
	}

	f_str_print(&name, F_LIT("\0"));
	return (const char*)name.data;
}

struct TypeWithDebug {
	TB_DataType dt;
	TB_DebugType* dbg_type;
};


TB_DataType get_tb_basic_type(Gen* g, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Bool: return TB_TYPE_BOOL;
	
	case ffzTypeTag_Proc: // fallthrough
	case ffzTypeTag_Pointer: return TB_TYPE_PTR;

	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: {
		if (type->size == 1) return TB_TYPE_I8;
		else if (type->size == 2) return TB_TYPE_I16;
		else if (type->size == 4) return TB_TYPE_I32;
		else if (type->size == 8) return TB_TYPE_I64;
		else F_BP;
	} break;

	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: {
		if (type->size == 1) return TB_TYPE_I8;
		else if (type->size == 2) return TB_TYPE_I16;
		else if (type->size == 4) return TB_TYPE_I32;
		else if (type->size == 8) return TB_TYPE_I64;
		else F_BP;
	} break;

	case ffzTypeTag_Record: {
		F_ASSERT(type->size <= 8);
		return TB_TYPE_I64; // maybe we should get the smallest type that the struct fits in instead
	} break;
		//case ffzTypeTag_Enum: {} break;
		//case ffzTypeTag_FixedArray: {} break;
	}
	F_BP;
	return {};
}

//TB_DataType get_tb_basic_type_or_ptr(Gen* g, ffzType* type) {
//	if (type->size > 8) return TB_TYPE_PTR; // return pointer if the size is > 8
//	return get_tb_basic_type(g, type);
//}

TB_DebugType* get_tb_debug_type(Gen* g, ffzType* type) {
	switch (type->tag) {
	case ffzTypeTag_Bool: return tb_debug_get_bool(g->tb);

	case ffzTypeTag_Raw: return tb_debug_get_void(g->tb);
	case ffzTypeTag_Proc: return tb_debug_create_ptr(g->tb, tb_debug_get_void(g->tb));
	case ffzTypeTag_Pointer: return tb_debug_create_ptr(g->tb, get_tb_debug_type(g, type->Pointer.pointer_to));

	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: return tb_debug_get_integer(g->tb, true, type->size * 8);

	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: return tb_debug_get_integer(g->tb, false, type->size * 8);
		//case ffzTypeTag_Float: {} break;
		//case ffzTypeTag_Proc: {} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Record: {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) F_BP;

		fArray(TB_DebugType*) tb_fields = f_array_make<TB_DebugType*>(g->alc);

		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzTypeRecordField& field = type->record_fields[i];
			TB_DebugType* t = tb_debug_create_field(g->tb, get_tb_debug_type(g, field.type), f_str_to_cstr(field.name, g->alc), field.offset);
			f_array_push(&tb_fields, t);
		}

		const char* name = type->tag == ffzTypeTag_String ? "string" :
			type->tag == ffzTypeTag_Slice ? make_name(g) : // TODO
			make_name(g, IBASE(type->unique_node));

		TB_DebugType* out = tb_debug_create_struct(g->tb, name);
		tb_debug_complete_record(out, tb_fields.data, tb_fields.len, type->size, type->align);
		return out;
	} break;

		//case ffzTypeTag_Enum: {} break;
	case ffzTypeTag_FixedArray: {
		// TODO: message negate / try to fix array debug info
		
		fArray(TB_DebugType*) tb_fields = f_array_make<TB_DebugType*>(g->alc);
		TB_DebugType* elem_type_tb = get_tb_debug_type(g, type->FixedArray.elem_type);

		for (u32 i = 0; i < (u32)type->FixedArray.length; i++) {
			const char* name = f_str_to_cstr(f_str_format(g->alc, "[%u]", i), g->alc);
			TB_DebugType* t = tb_debug_create_field(g->tb, elem_type_tb, name, i * type->FixedArray.elem_type->size);
			f_array_push(&tb_fields, t);
		}

		TB_DebugType* out = tb_debug_create_struct(g->tb, make_name(g));
		tb_debug_complete_record(out, tb_fields.data, tb_fields.len, type->size, type->align);
		return out;
	} break;

	default: F_BP;
	}
	return NULL;
}

// should we separate this into DebugType and DataType?
//TypeWithDebug type_to_tb(Gen* g, ffzType* type) {
//	TypeWithDebug out = {};
//	
//
//	return out;
//}

//TB_DataType get_proc_return_type(Gen* g, ffzType* proc_type) {
//	return proc_type->Proc.out_param ? get_tb_basic_type(g, proc_type->Proc.out_param->type) : TB_TYPE_VOID;
//}

#define FIX_TB_BIG_RETURN_HACK 1

static TB_Function* gen_procedure(Gen* g, ffzNodeOperatorInst inst) {
	auto insertion = f_map64_insert(&g->func_from_hash, ffz_hash_node_inst(IBASE(inst)), (TB_Function*)0, fMapInsert_DoNotOverride);
	if (!insertion.added) return *insertion._unstable_ptr;

	ffzType* proc_type = ffz_expr_get_type(g->project, IBASE(inst));
	F_ASSERT(proc_type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = proc_type->Proc.out_param ? proc_type->Proc.out_param->type : NULL;
	
	bool big_return = ret_type && ret_type->size > 8;
	TB_DataType ret_type_tb = big_return ? TB_TYPE_PTR :
		ret_type ? get_tb_basic_type(g, ret_type) : TB_TYPE_VOID;

	// TODO: deduplicate prototypes?
	TB_FunctionPrototype* proto = tb_prototype_create(g->tb, TB_CDECL, ret_type_tb, NULL, (int)proc_type->Proc.in_params.len + (int)big_return, false); // TODO: debug type?
	
	if (big_return) {
		// if big return, pass the pointer to the return value as the first argument the same way C does. :BigReturn
		//tb_prototype_add_param(proto, TB_TYPE_PTR);
		tb_prototype_add_param_named(g->tb, proto, TB_TYPE_PTR, "[return value address]", tb_debug_get_integer(g->tb, false, 64));
	}

	for (uint i = 0; i < proc_type->Proc.in_params.len; i++) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];
		
		TB_DebugType* param_debug_type = get_tb_debug_type(g, param->type);
		TB_DataType param_type = param->type->size > 8 ? TB_TYPE_PTR : get_tb_basic_type(g, param->type);
		
		if (param->type->size > 8) {
			param_debug_type = tb_debug_create_ptr(g->tb, param_debug_type); // TB doesn't allow parameters > 8 bytes
		}
		
		tb_prototype_add_param_named(g->tb, proto, param_type, f_str_to_cstr(param->name->name, g->alc), param_debug_type);
	}

	const char* name = make_name(g, IBASE(inst));
	TB_Function* func = tb_function_create(g->tb, name, TB_LINKAGE_PUBLIC);
	tb_function_set_prototype(func, proto);
	*insertion._unstable_ptr = func;

	// Set function start location
	tb_inst_loc(func, g->tb_file_from_parser_idx[inst.node->id.parser_id], inst.node->loc.start.line_num);
	
	ffzNodeInst left = ICHILD(inst,left);
	if (left.node->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		F_BP;//gen_statement(g, ICHILD(IAS(left, ProcType), out_parameter));
	}

	TB_Function* func_before = g->fn;
	TB_Reg func_big_return_before = g->func_big_return;
	g->fn = func;
	
	g->func_big_return = TB_NULL_REG;
	if (big_return) {
		// There's some weird things going on in TB debug info if we don't call tb_inst_param_addr on every parameter. So let's just call it.
		TB_Reg _param_addr = tb_inst_param_addr(func, 0);

#if FIX_TB_BIG_RETURN_HACK
		g->func_big_return = tb_inst_local(func, 8, 8);
		tb_inst_store(func, TB_TYPE_PTR, g->func_big_return, tb_inst_param(func, 0), 8);
#else
		g->func_big_return = tb_inst_param(func, 0);
#endif
	}

	ffzNodeProcTypeInst proc_type_inst = IAS(proc_type->unique_node,ProcType);

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, proc_type_inst) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];

		F_ASSERT(n.node->kind == ffzNodeKind_Declaration);
		ffzNodeIdentifierInst param_definition = ICHILD(IAS(n, Declaration), name);
		ffzNodeInstHash hash = ffz_hash_node_inst(IBASE(param_definition));
		
		TB_Reg param_addr = tb_inst_param_addr(func, i + (u32)big_return); // TB parameter inspection doesn't work if we never call this

		// if it's a big parameter, then let's dereference the pointer pointer
		if (param->type->size > 8) {
			param_addr = tb_inst_param(func, i + (u32)big_return); // NOTE: this works with the new TB X64 backend, but has a bug with the old backend.
			//param_addr = tb_inst_load(g->tb_func, TB_TYPE_PTR, param_addr, 8); // so let's use this to make sure it works.
		}
		f_map64_insert(&g->tb_local_addr_from_definition, hash, param_addr);
		i++;
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_statement(g, n);
	}
	
	if (!proc_type->Proc.out_param) { // automatically generate a return statement if the proc doesn't return a value
		tb_inst_loc(func, g->tb_file_from_parser_idx[inst.node->id.parser_id], inst.node->loc.end.line_num);
		tb_inst_ret(func, TB_NULL_REG);
	}

	g->fn = func_before;
	g->func_big_return = func_big_return_before;

	//printf("\n");
	//tb_function_print(func, tb_default_print_callback, stdout, false);
	//printf("\n");

	bool ok = tb_module_compile_function(g->tb, func, TB_ISEL_FAST);
	F_ASSERT(ok);

	return func;
}

static SmallOrPtr gen_call(Gen* g, ffzNodeOperatorInst inst) {
	ffzNodeInst left = ICHILD(inst,left);
	ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
	F_ASSERT(left_chk.type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = left_chk.type->Proc.out_param ? left_chk.type->Proc.out_param->type : NULL;
	bool big_return = ret_type && ret_type->size > 8; // :BigReturn
	
	TB_DataType ret_type_tb = big_return ? TB_TYPE_PTR :
		ret_type ? get_tb_basic_type(g, ret_type) : TB_TYPE_VOID;

	fArray(TB_Reg) args = f_array_make<TB_Reg>(g->alc);

	SmallOrPtr out = {};
	if (big_return) {
		out.ptr = tb_inst_local(g->fn, ret_type->size, ret_type->align);
		out.ptr_can_be_stolen = true;
		f_array_push(&args, out.ptr);
	}

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, inst) {
		ffzType* param_type = left_chk.type->Proc.in_params[i].type;
		SmallOrPtr arg = gen_expr(g, n);
		
		if (param_type->size > 8) {
			// make a copy on the stack for the parameter
			TB_Reg local_copy_addr = tb_inst_local(g->fn, param_type->size, param_type->align);
			tb_inst_memcpy(g->fn, local_copy_addr, arg.ptr, tb_inst_uint(g->fn, TB_TYPE_I32, param_type->size), param_type->align);
			f_array_push(&args, local_copy_addr);
		}
		else {
			F_ASSERT(arg.small != TB_NULL_REG);
			f_array_push(&args, arg.small);
		}
		i++;
	}

	// TODO: non-vcall for constant procedures

	TB_Reg target = gen_expr(g, left, false).small;
	F_ASSERT(target != TB_NULL_REG);

	TB_Reg return_val = tb_inst_vcall(g->fn, ret_type_tb, target, args.len, args.data);
	if (!big_return) out.small = return_val;

	return out;
}

struct Initializer { TB_Initializer* init; u8* mem; };

Initializer make_initializer(Gen* g, u32 size, u32 alignment) {
	TB_Initializer* init = tb_initializer_create(g->tb, size, alignment, 32); // ... why do we need to provide a capacity???
	void* mem = tb_initializer_add_region(g->tb, init, 0, size);
	return { init, (u8*)mem };
}

static TB_Symbol* get_proc_symbol(Gen* g, ffzNodeInst proc_node) {
	if (proc_node.node->kind == ffzNodeKind_ProcType) { // @extern proc
		const char* name = make_name(g, proc_node);
		TB_External* external = tb_extern_create(g->tb, name, TB_EXTERNAL_SO_EXPORT);
		return (TB_Symbol*)external;
	}
	else {
		TB_Function* func = gen_procedure(g, IAS(proc_node, Operator));
		return (TB_Symbol*)func;
	}
}

static void gen_initializer_constant(Gen* g, Initializer init, u32 offset, ffzType* type, ffzConstant* constant) {
	switch (type->tag) {
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_SizedInt: // fallthrough
	case ffzTypeTag_Int: // fallthrough
	case ffzTypeTag_SizedUint: // fallthrough
	case ffzTypeTag_Uint: {
		memcpy(init.mem + offset, constant, type->size);
	} break;

	case ffzTypeTag_Proc: {
		memset(init.mem + offset, 0, 8);
		if (constant->proc_node.node) {
			TB_Symbol* proc_sym = get_proc_symbol(g, constant->proc_node);
			tb_initializer_add_symbol_reloc(g->tb, init.init, offset, proc_sym);
		}
	} break;

	case ffzTypeTag_Pointer: {
		if (constant->ptr) todo;
		memset(init.mem + offset, 0, 8);
	} break;

	case ffzTypeTag_String: {
		fString s = constant->string_zero_terminated;
		Initializer str_data_init = make_initializer(g, s.len + 1, 8);
		memcpy(str_data_init.mem, s.data, s.len + 1);

		// we need to make a global out of the string...
		TB_Global* str_data_global = tb_global_create(g->tb, make_name(g), TB_STORAGE_DATA, NULL, TB_LINKAGE_PRIVATE);
		tb_global_set_initializer(g->tb, str_data_global, str_data_init.init);
		
		memset(init.mem + offset, 0, 8);
		tb_initializer_add_symbol_reloc(g->tb, init.init, offset, (TB_Symbol*)str_data_global);

		u64 len = s.len;
		memcpy(init.mem + offset + 8, &len, 8);
	} break;

	case ffzTypeTag_Slice: {
		memset(init.mem + offset, 0, 16);
	} break;

	case ffzTypeTag_Record: {
		memset(init.mem + offset, 0, type->size);
		ffzConstant empty_constant = {};
		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzTypeRecordField* field = &type->record_fields[i];
			
			gen_initializer_constant(g, init, offset + field->offset, field->type,
				constant->record_fields.len == 0 ? &empty_constant : &constant->record_fields[i]);
		}
	} break;
	case ffzTypeTag_FixedArray: {
		uint elem_size = type->FixedArray.elem_type->size;
		for (u32 i = 0; i < (u32)type->FixedArray.length; i++) {
			ffzConstant c = ffz_constant_fixed_array_get(type, constant, i);
			gen_initializer_constant(g, init, offset + i*elem_size, type->FixedArray.elem_type, &c);
		}
	} break;
	default: F_BP;
	}
}

static void _gen_store(Gen* g, TB_Reg addr, SmallOrPtr value, ffzType* type) {
	if (type->size > 8) {
		tb_inst_memcpy(g->fn, addr, value.ptr, tb_inst_uint(g->fn, TB_TYPE_I64, type->size), type->align);
	}
	else {
		tb_inst_store(g->fn, get_tb_basic_type(g, type), addr, value.small, type->align);
	}
}

static void gen_store(Gen* g, TB_Reg lhs_address, ffzNodeInst rhs) {
	SmallOrPtr rhs_value = gen_expr(g, rhs);
	ffzType* type = ffz_expr_get_type(g->project, rhs);
	_gen_store(g, lhs_address, rhs_value, type);
}

static SmallOrPtr gen_expr(Gen* g, ffzNodeInst inst, bool address_of) {
	SmallOrPtr out = {};

	ffzCheckedExpr checked = ffz_expr_get_checked(g->project, inst);
	F_ASSERT(ffz_type_is_grounded(checked.type));

	if (checked.const_val) {
		switch (checked.type->tag) {
		case ffzTypeTag_Bool: {
			F_ASSERT(!address_of);
#if 0
			// TODO: message NeGate about this:
			// e.g.   foo: false   won't work
			out.small = tb_inst_bool(g->fn, checked.const_val->bool_);
#else
			out.small = tb_inst_cmp_ne(g->fn, tb_inst_uint(g->fn, TB_TYPE_I32, 0),
				tb_inst_uint(g->fn, TB_TYPE_I32, checked.const_val->bool_));
#endif
		} break;
		case ffzTypeTag_SizedInt: // fallthrough
		case ffzTypeTag_Int: {
			F_ASSERT(!address_of);
			if (checked.type->size == 1)      out.small = tb_inst_sint(g->fn, TB_TYPE_I8,  checked.const_val->u8_);
			else if (checked.type->size == 2) out.small = tb_inst_sint(g->fn, TB_TYPE_I16, checked.const_val->u16_);
			else if (checked.type->size == 4) out.small = tb_inst_sint(g->fn, TB_TYPE_I32, checked.const_val->u32_);
			else if (checked.type->size == 8) out.small = tb_inst_sint(g->fn, TB_TYPE_I64, checked.const_val->u64_);
			else F_BP;
		} break;

		case ffzTypeTag_SizedUint: // fallthrough
		case ffzTypeTag_Uint: {
			F_ASSERT(!address_of);
			if (checked.type->size == 1)      out.small = tb_inst_uint(g->fn, TB_TYPE_I8,  checked.const_val->u8_);
			else if (checked.type->size == 2) out.small = tb_inst_uint(g->fn, TB_TYPE_I16, checked.const_val->u16_);
			else if (checked.type->size == 4) out.small = tb_inst_uint(g->fn, TB_TYPE_I32, checked.const_val->u32_);
			else if (checked.type->size == 8) out.small = tb_inst_uint(g->fn, TB_TYPE_I64, checked.const_val->u64_);
			else F_BP;
		} break;
		//case ffzTypeTag_Int: { BP; } break;
		case ffzTypeTag_Proc: {
			F_ASSERT(!address_of);
			
			TB_Symbol* proc_sym = get_proc_symbol(g, checked.const_val->proc_node);
			out.small = tb_inst_get_symbol_address(g->fn, proc_sym);
		} break;

		case ffzTypeTag_Slice: // fallthrough
		case ffzTypeTag_String: // fallthrough
		case ffzTypeTag_FixedArray: // fallthrough
		case ffzTypeTag_Record: {
			Initializer init = make_initializer(g, checked.type->size, checked.type->align);
			
			gen_initializer_constant(g, init, 0, checked.type, checked.const_val);
			
			TB_Global* global = tb_global_create(g->tb, make_name(g), TB_STORAGE_DATA, NULL, TB_LINKAGE_PRIVATE);
			tb_global_set_initializer(g->tb, global, init.init);
			
			TB_Reg global_addr = tb_inst_get_symbol_address(g->fn, (TB_Symbol*)global);
			if (checked.type->size > 8) {
				if (address_of) out.small = global_addr;
				else out.ptr = global_addr;
			}
			else F_BP;
		} break;

		default: F_BP;
		}

		return out;
	}

	bool should_dereference = false;
	bool should_take_address = false;

	switch (inst.node->kind) {
	case ffzNodeKind_Identifier: {
		ffzNodeIdentifierInst def = ffz_get_definition(g->project, IAS(inst,Identifier));
		if (def.node->is_constant) F_BP;
		//if (ffz_definition_is_constant(def.node)) BP;

		ffzNodeInstHash hash = ffz_hash_node_inst(IBASE(def));
		out.small = *f_map64_get(&g->tb_local_addr_from_definition, hash);

		//TypeWithDebug type_tb = type_to_tb(g, checked.type);
		should_dereference = !address_of;
		//checked.type
	} break;
	case ffzNodeKind_Operator: {
//		F_HITS(__c, 12);
		ffzNodeOperatorInst derived = IAS(inst,Operator);
		ffzNodeInst left = ICHILD(derived,left);
		ffzNodeInst right = ICHILD(derived,right);

		switch (derived.node->op_kind) {

		case ffzOperatorKind_Add: case ffzOperatorKind_Sub:
		case ffzOperatorKind_Mul: case ffzOperatorKind_Div:
		case ffzOperatorKind_Modulo: case ffzOperatorKind_Equal:
		case ffzOperatorKind_NotEqual: case ffzOperatorKind_Less:
		case ffzOperatorKind_LessOrEqual: case ffzOperatorKind_Greater:
		case ffzOperatorKind_GreaterOrEqual:
		{
			F_ASSERT(!address_of);
			//F_HITS(___c, 6);
			TB_Reg a = gen_expr(g, left).small;
			TB_Reg b = gen_expr(g, right).small;
			
			bool is_signed = ffz_type_is_signed_integer(checked.type->tag);

			switch (derived.node->op_kind) {
			case ffzOperatorKind_Add: { out.small = tb_inst_add(g->fn, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzOperatorKind_Sub: { out.small = tb_inst_sub(g->fn, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzOperatorKind_Mul: { out.small = tb_inst_mul(g->fn, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzOperatorKind_Div: { out.small = tb_inst_div(g->fn, a, b, is_signed); } break;
			case ffzOperatorKind_Modulo: { out.small = tb_inst_mod(g->fn, a, b, is_signed); } break;

			case ffzOperatorKind_Equal: { out.small = tb_inst_cmp_eq(g->fn, a, b); } break;
			case ffzOperatorKind_NotEqual: { out.small = tb_inst_cmp_ne(g->fn, a, b); } break;
			case ffzOperatorKind_Less: { out.small = tb_inst_cmp_ilt(g->fn, a, b, is_signed); } break;
			case ffzOperatorKind_LessOrEqual: { out.small = tb_inst_cmp_ile(g->fn, a, b, is_signed); } break;
			case ffzOperatorKind_Greater: { out.small = tb_inst_cmp_igt(g->fn, a, b, is_signed); } break;
			case ffzOperatorKind_GreaterOrEqual: { out.small = tb_inst_cmp_ige(g->fn, a, b, is_signed); } break;

			default: F_BP;
			}
		} break;

		case ffzOperatorKind_UnaryMinus: {
			F_ASSERT(!address_of);
			out.small = tb_inst_neg(g->fn, gen_expr(g, right).small);
		} break;

		case ffzOperatorKind_LogicalNOT: {
			F_ASSERT(!address_of);
			// (!x) is equivalent to (x == false)
			out.small = tb_inst_cmp_eq(g->fn, gen_expr(g, right).small, tb_inst_bool(g->fn, false));
		} break;

		case ffzOperatorKind_PostRoundBrackets: {
			// sometimes we need to take the address of a temporary.
			// e.g.  copy_string("hello").ptr
			should_take_address = address_of;

			if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(AS(left.node, Keyword)->keyword)) {
				ffzKeyword keyword = AS(left.node,Keyword)->keyword;
				
				TB_Reg first = gen_expr(g, ffz_get_child_inst(IBASE(inst), 0)).small;
				if (keyword == ffzKeyword_bit_not) {
					out.small = tb_inst_not(g->fn, first);
				}
				else {
					TB_Reg second = gen_expr(g, ffz_get_child_inst(IBASE(inst), 1)).small;
					switch (keyword) {		
					case ffzKeyword_bit_and: { out.small = tb_inst_and(g->fn, first, second); } break;
					case ffzKeyword_bit_or: { out.small = tb_inst_or(g->fn, first, second); } break;
					case ffzKeyword_bit_xor: { out.small = tb_inst_xor(g->fn, first, second); } break;
					case ffzKeyword_bit_shl: { out.small = tb_inst_shl(g->fn, first, second, (TB_ArithmaticBehavior)0); } break;
					case ffzKeyword_bit_shr: { out.small = tb_inst_shr(g->fn, first, second); } break;
					default: F_BP;
					}
				}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				if (left_chk.type->tag == ffzTypeTag_Type) {
					ffzType* dst_type = left_chk.const_val->type;
					// type cast, e.g. u32(5293900)

					ffzNodeInst arg = ffz_get_child_inst(IBASE(inst), 0);
					ffzType* arg_type = ffz_expr_get_type(g->project, arg);

					out = gen_expr(g, arg);
					if (ffz_type_is_pointer_ish(dst_type->tag)) { // cast to pointer
						if (arg_type->tag == ffzTypeTag_Pointer) {}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							out.small = tb_inst_int2ptr(g->fn, out.small);
						}
					}
					else if (ffz_type_is_integer_ish(dst_type->tag)) { // cast to integer
						TB_DataType dt = get_tb_basic_type(g, dst_type);
						if (arg_type->tag == ffzTypeTag_Pointer) {
							out.small = tb_inst_ptr2int(g->fn, out.small, dt);
						}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							// integer -> integer cast

							if (dst_type->size > arg_type->size) {
								if (ffz_type_is_signed_integer(dst_type->tag)) {
									out.small = tb_inst_sxt(g->fn, out.small, dt);  // sign extend
								}
								else {
									out.small = tb_inst_zxt(g->fn, out.small, dt);  // zero extend
								}
							}
							else if (dst_type->size < arg_type->size) {
								out.small = tb_inst_trunc(g->fn, out.small, dt);  // truncate
							}
						}
						else { todo; }
					}
					else todo;
				}
				else {
					out = gen_call(g, derived);
				}
			}
		} break;
		
		case ffzOperatorKind_AddressOf: {
			F_ASSERT(!address_of);
			out = gen_expr(g, right, true);
		} break;

		case ffzOperatorKind_Dereference: {
			if (address_of) {
				out = gen_expr(g, left);
			}
			else {
				out = gen_expr(g, left, true);
				should_dereference = true;
			}
		} break;

		case ffzOperatorKind_MemberAccess: {
			fString member_name = AS(right.node, Identifier)->name;

			if (left.node->kind == ffzNodeKind_Identifier && AS(left.node, Identifier)->name == F_LIT("in")) {
				F_ASSERT(!address_of); // TODO
				F_BP;//for (u32 i = 0; i < g->curr_proc->proc_type->Proc.in_params.len; i++) {
				//	ffzTypeProcParameter& param = g->curr_proc->proc_type->Proc.in_params[i];
				//	if (param.name->name == member_name) {
				//		result = gmmc_val_param(g->curr_proc->gmmc_proc, param.type->size, i);
				//	}
				//}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				ffzType* struct_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;

				ffzTypeRecordFieldUse field;
				F_ASSERT(ffz_type_find_record_field_use(g->project, struct_type, member_name, &field));

				TB_Reg addr_of_struct = gen_expr(g, left, left_chk.type->tag != ffzTypeTag_Pointer).small;
				F_ASSERT(addr_of_struct != TB_NULL_REG);
				
				out.small = tb_inst_member_access(g->fn, addr_of_struct, field.offset);
				should_dereference = !address_of;
			}
		} break;

		case ffzOperatorKind_PostCurlyBrackets: {
			// dynamic initializer
			out.ptr = tb_inst_local(g->fn, checked.type->size, checked.type->align);
			out.ptr_can_be_stolen = true;
			F_ASSERT(checked.type->size > 8);

			if (checked.type->tag == ffzTypeTag_Record) {
				u32 i = 0;
				for FFZ_EACH_CHILD_INST(n, inst) {
					ffzTypeRecordField& field = checked.type->record_fields[i];
					
					SmallOrPtr src = gen_expr(g, n);
					TB_Reg dst_ptr = tb_inst_member_access(g->fn, out.ptr, field.offset);
					_gen_store(g, dst_ptr, src, field.type);
					i++;
				}
			}
			else if (checked.type->tag == ffzTypeTag_FixedArray) {
				u32 i = 0;
				ffzType* elem_type = checked.type->FixedArray.elem_type;
				for FFZ_EACH_CHILD_INST(n, inst) {
					SmallOrPtr src = gen_expr(g, n, false);
					TB_Reg dst_ptr = tb_inst_member_access(g->fn, out.ptr, i * elem_type->size);
					_gen_store(g, dst_ptr, src, elem_type);
					i++;
				}
			}
			else F_BP;
		} break;

		case ffzOperatorKind_PostSquareBrackets: {
			ffzType* left_type = ffz_expr_get_type(g->project, left);
			F_ASSERT(left_type->tag == ffzTypeTag_FixedArray || left_type->tag == ffzTypeTag_Slice);

			ffzType* elem_type = left_type->tag == ffzTypeTag_Slice ? left_type->fSlice.elem_type : left_type->FixedArray.elem_type;
			
			TB_Reg left_value = gen_expr(g, left, true).small;
			TB_Reg array_data = left_value;

			if (left_type->tag == ffzTypeTag_Slice) {
				F_BP;// array_data = c0_push_load(g->c0_proc, c0_agg_type_basic(g->c0, C0Basic_ptr), array_data);
			}

			if (ffz_get_child_count(BASE(inst.node)) == 2) { // slicing
				ffzNodeInst lo_inst = ffz_get_child_inst(IBASE(inst), 0);
				ffzNodeInst hi_inst = ffz_get_child_inst(IBASE(inst), 1);

				TB_Reg lo = lo_inst.node->kind == ffzNodeKind_Blank ?
					tb_inst_uint(g->fn, TB_TYPE_I64, 0) : gen_expr(g, lo_inst).small;
				TB_Reg hi;
				if (hi_inst.node->kind == ffzNodeKind_Blank) {
					if (left_type->tag == ffzTypeTag_FixedArray) {
						hi = tb_inst_uint(g->fn, TB_TYPE_I64, left_type->FixedArray.length);
					} else {
						// load the 'len' field of a slice
						hi = tb_inst_load(g->fn, TB_TYPE_I64, tb_inst_member_access(g->fn, left_value, 8), 8);
					}
				} else {
					hi = gen_expr(g, hi_inst).small;
				}

				out.ptr = tb_inst_local(g->fn, 16, 8);
				lo = tb_inst_zxt(g->fn, lo, TB_TYPE_I64);
				hi = tb_inst_zxt(g->fn, hi, TB_TYPE_I64);
				TB_Reg lo_offset = tb_inst_mul(g->fn, lo, tb_inst_uint(g->fn, TB_TYPE_I64, elem_type->size), (TB_ArithmaticBehavior)0);
				TB_Reg ptr = tb_inst_add(g->fn, tb_inst_ptr2int(g->fn, array_data, TB_TYPE_I64), lo_offset, (TB_ArithmaticBehavior)0);
				TB_Reg len = tb_inst_sub(g->fn, hi, lo, (TB_ArithmaticBehavior)0);

				tb_inst_store(g->fn, TB_TYPE_I64, out.ptr, ptr, 8);
				tb_inst_store(g->fn, TB_TYPE_I64, tb_inst_member_access(g->fn, out.ptr, 8), len, 8);
			}
			else { // taking an index
				ffzNodeInst index_node = ffz_get_child_inst(IBASE(inst), 0);
				TB_Reg index = tb_inst_zxt(g->fn, gen_expr(g, index_node).small, TB_TYPE_I64);
				
				TB_Reg index_offset = tb_inst_mul(g->fn, index,
					tb_inst_uint(g->fn, TB_TYPE_I64, elem_type->size), (TB_ArithmaticBehavior)0);
				
				out.small = tb_inst_add(g->fn, tb_inst_ptr2int(g->fn, array_data, TB_TYPE_I64),
					index_offset, (TB_ArithmaticBehavior)0);

				should_dereference = !address_of;
			}
		} break;

		default: F_BP;
		}

	} break;

	case ffzNodeKind_Dot: {
		ffzNodeInst assignee;
		F_ASSERT(ffz_dot_get_assignee(IAS(inst, Dot), &assignee));
		out = gen_expr(g, assignee, address_of); 
	} break;

	default: F_BP;
	}
	
	if (should_dereference) {
		F_ASSERT(!should_take_address);
		if (checked.type->size > 8) {
			out.ptr = out.small;
			out.small = {};
			F_ASSERT(!out.ptr_can_be_stolen); //out.ptr_can_be_stolen = false;
		}
		else {
			out.small = tb_inst_load(g->fn, get_tb_basic_type(g, checked.type), out.small, checked.type->align);
		}
	}
	
	if (should_take_address) {
		F_ASSERT(!should_dereference);
		if (checked.type->size > 8) {
			out.small = out.ptr;
			out.ptr = {};
		}
		else {
			TB_Reg temporary = tb_inst_local(g->fn, checked.type->size, checked.type->align);
			tb_inst_store(g->fn, get_tb_basic_type(g, checked.type), temporary, out.small, checked.type->align);
			out.small = temporary;
		}
	}
	
	F_ASSERT(out.small || out.ptr);
	F_ASSERT((out.small == NULL) ^ (out.ptr == NULL));
	// a ^^ b
	return out;
}

static void inst_loc(Gen* g, ffzNode* node, u32 line_num) {
	tb_inst_loc(g->fn, g->tb_file_from_parser_idx[node->id.parser_id], line_num);
}

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc) {
	if (set_loc) {
		if (inst.node->kind == ffzNodeKind_Declaration && !ffz_decl_is_runtime_value(AS(inst.node, Declaration))) {}
		else {
			inst_loc(g, inst.node, inst.node->loc.start.line_num);
		}
	}
	
	switch (inst.node->kind) {
		
	case ffzNodeKind_Declaration: {
		ffzNodeDeclarationInst decl = IAS(inst, Declaration);
		ffzNodeIdentifierInst definition = ICHILD(decl, name);
		ffzType* type = ffz_decl_get_type(g->project, decl);

		if (ffz_decl_is_runtime_value(decl.node)) {
			TB_Reg local_addr = tb_inst_local(g->fn, type->size, type->align);
			f_map64_insert(&g->tb_local_addr_from_definition, ffz_hash_node_inst(IBASE(definition)), local_addr);
			
			tb_function_attrib_variable(g->fn, local_addr, f_str_to_cstr(definition.node->name, g->alc), get_tb_debug_type(g, type));

			gen_store(g, local_addr, ICHILD(decl, rhs));
		}
		else {
			// need to still generate exported procs
			if (type->tag == ffzTypeTag_Proc) {
				ffzNodeInst rhs = ICHILD(decl,rhs);
				if (rhs.node->kind == ffzNodeKind_Operator) { // @extern procs also have the type ffzTypeTag_Proc
					gen_procedure(g, IAS(rhs, Operator));
				}
			}
		}
	} break;

	case ffzNodeKind_Assignment: {
		ffzNodeAssignmentInst assign = IAS(inst, Assignment);
		ffzNodeInst lhs = ICHILD(assign, lhs);
		TB_Reg addr_of_lhs = gen_expr(g, lhs, true).small;
		gen_store(g, addr_of_lhs, ICHILD(assign, rhs));
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		ffzNodeIfInst if_stmt = IAS(inst, If);
		TB_Reg cond = gen_expr(g, ICHILD(if_stmt, condition)).small;
		
		//if (inst.node->loc.start.line_num == 108) F_BP;

		TB_Label true_bb = tb_basic_block_create(g->fn);
		TB_Label else_bb;
		if (if_stmt.node->else_scope) {
			else_bb = tb_basic_block_create(g->fn);
		}

		TB_Label after_bb = tb_basic_block_create(g->fn);
		tb_inst_if(g->fn, cond, true_bb, if_stmt.node->else_scope ? else_bb : after_bb);
		
		tb_inst_set_label(g->fn, true_bb);
		gen_statement(g, ICHILD(if_stmt,true_scope));
		true_bb = tb_inst_get_label(g->fn); // continue the block where the recursion left off
		
		if (!tb_basic_block_is_complete(g->fn, true_bb)) { // TB will otherwise complain
			inst_loc(g, inst.node, if_stmt.node->true_scope->loc.end.line_num);
			tb_inst_goto(g->fn, after_bb);
		}

		if (if_stmt.node->else_scope) {
			tb_inst_set_label(g->fn, else_bb);
			gen_statement(g, ICHILD(if_stmt,else_scope));
			else_bb = tb_inst_get_label(g->fn); // continue the block where the recursion left off
			
			if (!tb_basic_block_is_complete(g->fn, else_bb)) { // TB will otherwise complain
				inst_loc(g, inst.node, if_stmt.node->else_scope->loc.end.line_num);
				tb_inst_goto(g->fn, after_bb);
			}
		}

		tb_inst_set_label(g->fn, after_bb);
	} break;

	case ffzNodeKind_For: {
		ffzNodeForInst for_loop = IAS(inst,For);
		ffzNodeInst pre = ICHILD(for_loop, header_stmts[0]);
		ffzNodeInst condition = ICHILD(for_loop, header_stmts[1]);
		ffzNodeInst post = ICHILD(for_loop, header_stmts[2]);
		ffzNodeInst body = ICHILD(for_loop, scope);
		
		if (pre.node) gen_statement(g, pre);
		
		TB_Label cond_bb = tb_basic_block_create(g->fn);
		TB_Label body_bb = tb_basic_block_create(g->fn);
		TB_Label after_bb = tb_basic_block_create(g->fn);
		tb_inst_goto(g->fn, cond_bb);

		if (!condition.node) F_BP; // TODO
		
		{
			tb_inst_set_label(g->fn, cond_bb);
			TB_Reg cond = gen_expr(g, condition).small;
			tb_inst_if(g->fn, cond, body_bb, after_bb);
		}

		{
			tb_inst_set_label(g->fn, body_bb);
			gen_statement(g, body);
			
			inst_loc(g, inst.node, body.node->loc.end.line_num);
			if (post.node) gen_statement(g, post, false); // don't set loc, let's override the loc to be at the end of the body scope

			tb_inst_goto(g->fn, cond_bb);
		}

		tb_inst_set_label(g->fn, after_bb);
	} break;

	case ffzNodeKind_Keyword: {
		tb_inst_debugbreak(g->fn);
	} break;

	case ffzNodeKind_Return: {
		ffzNodeReturnInst ret = IAS(inst, Return);
		TB_Reg val = TB_NULL_REG;
		
		if (ret.node->value) {
			SmallOrPtr return_value = gen_expr(g, ICHILD(ret, value));
			if (return_value.ptr) {
				ffzType* ret_type = ffz_expr_get_type(g->project, ICHILD(ret, value));

#if FIX_TB_BIG_RETURN_HACK
				val = tb_inst_load(g->fn, TB_TYPE_PTR, g->func_big_return, 8);
#else
				val = g->func_big_return;
#endif
				//tb_inst_param(g->tb_func, 0); // :BigReturn
				tb_inst_memcpy(g->fn, val, return_value.ptr, tb_inst_uint(g->fn, TB_TYPE_I64, ret_type->size), ret_type->align);
			}
			else {
				val = return_value.small;
			}
		}

		tb_inst_ret(g->fn, val);
	} break;

	case ffzNodeKind_Operator: {
		F_ASSERT(AS(inst.node, Operator)->op_kind == ffzOperatorKind_PostRoundBrackets);
		gen_call(g, IAS(inst, Operator));
	} break;

	default: F_BP;
	}
}

void ffz_tb_generate(ffzProject* project, fString objname) {
	fAllocator* temp = f_temp_push(); F_DEFER(f_temp_pop()); // temp_push_volatile?

	//ASSERT(!tb_arena);
	//tb_arena = arena_make_virtual_reserve_fixed(GiB(1), NULL);
	F_ASSERT(!tb_allocator);
	tb_allocator = temp;

	TB_FeatureSet features = { 0 };
	TB_Module* tb_module = tb_module_create_for_host(&features, true);

	Gen g = {};
	g.tb = tb_module;
	g.alc = temp;
	g.project = project;
	g.tb_file_from_parser_idx = f_array_make<TB_FileID>(g.alc);
	g.tb_local_addr_from_definition = f_map64_make<TB_Reg>(g.alc);
	g.func_from_hash = f_map64_make<TB_Function*>(g.alc);

	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		
		TB_FileID file = tb_file_create(tb_module, f_str_to_cstr(parser->source_code_filepath, temp));
		f_array_push(&g.tb_file_from_parser_idx, file);
	}

	for (u32 i = 0; i < project->parsers_dependency_sorted.len; i++) {
		ffzParser* parser = project->parsers_dependency_sorted[i];
		g.checker = parser->checker;

		for FFZ_EACH_CHILD(n, parser->root) {
			gen_statement(&g, ffz_get_toplevel_inst(g.checker, n));
		}
	}

	//foo_os_file_picker_dialog(..
	TB_Exports exports = tb_exporter_write_output(tb_module, TB_FLAVOR_OBJECT, TB_DEBUGFMT_CODEVIEW);
	f_files_write_whole(objname, fString{ exports.files[0].data, exports.files[0].length });
	tb_exporter_free(exports);
	
	tb_module_destroy(tb_module);
}

#if 0
static void tb_test() {
	TB_FeatureSet features = { 0 };
	TB_Module* m = tb_module_create_for_host(&features, true);
	
	TB_FunctionPrototype* proto = tb_prototype_create(m, TB_CDECL, TB_TYPE_I32, NULL, 1, false);
	tb_prototype_add_param(proto, TB_TYPE_PTR);
	
	TB_Function* func = tb_function_create(m, "entry", TB_LINKAGE_PUBLIC);
	tb_function_set_prototype(func, proto);

	TB_FileID my_file = tb_file_create(m, "test.txt");
	tb_inst_loc(func, my_file, 2);
	
	TB_Reg result = tb_inst_sint(func, TB_TYPE_I32, 999);
	tb_function_attrib_variable(func, result, "RESULT", tb_debug_get_integer(m, true, 32));
	tb_inst_ret(func, result);

	tb_function_print(func, tb_default_print_callback, stdout, false);

	bool ok = tb_module_compile_function(m, func, TB_ISEL_FAST);

	TB_Exports exports = tb_exporter_write_output(m, TB_FLAVOR_OBJECT, TB_DEBUGFMT_CODEVIEW);
	os_file_write_whole(F_LIT("DUMMY.obj"), String{ exports.files[0].data, exports.files[0].length });
	tb_exporter_free(exports);

	tb_module_destroy(m);
}
#endif

#endif // FFZ_BACKEND_TB