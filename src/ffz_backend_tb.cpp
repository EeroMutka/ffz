#ifdef FFZ_BUILD_INCLUDE_TB

#include "foundation/foundation.hpp"

#include "ffz_ast.h"
#include "ffz_checker.h"

//#include "ffz_backend_tb.h"
#include "microsoft_craziness.h"
#undef small // Windows.h, wtf?

//#pragma warning(disable:4200)
//#include "Cuik/tb/include/tb.h"
#include "tb.h"

// hack, to get TB to compile
extern "C" uint64_t cuik_time_in_nanos(void) { return 0; }
extern "C" void cuikperf_region_start(uint64_t now, const char* fmt, const char* extra) {}
extern "C" void cuikperf_region_end(void) {}

//static fAllocator* tb_allocator = NULL;
//static Arena* tb_arena = {};
#define todo f_trap()

const bool VOLATILE_OPS = false;
/*extern "C" {
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
}*/

struct Value {
	TB_Symbol* symbol;
	TB_Node* local_addr; // local_addr should be valid if symbol is NULL
};

union Constant {
	TB_Symbol* symbol;
};

/*struct Local {
	TB_Node* reg;
	bool is_big_parameter;
};*/

struct Gen {
	ffzProject* project;
	fAllocator* alc;
	ffzChecker* checker;

	TB_Module* tb;
	TB_Function* fn;
	ffzType* proc_type;
	TB_Node* func_big_return;

	uint dummy_name_counter;
	
	fMap64(TB_Function*) func_from_hash;
	fMap64(Value) value_from_definition;
	fArray(TB_FileID) tb_file_from_parser_idx;
};

#define CHILD(parent, child_access) ffzNodeInst{ (parent).node->child_access, (parent).polymorph }

// holds either a value, or a pointer to the value if the size of the type > 8 bytes
struct SmallOrPtr {
	TB_Node* small;
	TB_Node* ptr;
	bool ptr_can_be_stolen; // if false, the caller must make a local copy of the value if they need it. Otherwise, they can just take it and pretend its their own copy.
};

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc = true);
static SmallOrPtr gen_expr(Gen* g, ffzNodeInst inst, bool address_of = false);

//static const char* make_type_name(Gen* g, ffzType* type) {
//}

static const char* make_name(Gen* g, ffzNodeInst inst = {}, bool pretty = true) {
	fArray(u8) name = f_array_make<u8>(g->alc);

	if (inst.node) {
		ffzNodeInst parent = ffz_parent_inst(g->project, inst);
		f_str_print(&name, ffz_get_parent_decl_name(inst.node));
		
		if (inst.polymorph) {
			if (pretty) {
				f_str_print(&name, F_LIT("["));

				for (uint i = 0; i < inst.polymorph->parameters.len; i++) {
					if (i > 0) f_str_print(&name, F_LIT(", "));

					f_str_print(&name, ffz_constant_to_string(g->project, inst.polymorph->parameters[i]));
				}

				f_str_print(&name, F_LIT("]"));
			}
			//else {
			//	// hmm.. deterministic index for polymorph, how?
			//	//f_trap(); // f_str_printf(&name, "$%u", inst.poly_idx.idx);
			//}
			//f_str_printf(&name, "$%xll", inst.polymorph->hash);
		}
		
		if (g->checker->_dbg_module_import_name.len > 0) {
			// We don't want to export symbols from imported modules.
			// Currently, we're giving these symbols unique ids and exporting them anyway, because
			// if we're using debug-info, an export name is required. TODO: don't export these procedures in non-debug builds!!
			
			bool is_extern = ffz_get_tag(g->project, parent, ffzKeyword_extern);
			bool is_module_defined_entry = ffz_get_tag(g->project, parent, ffzKeyword_module_defined_entry);
			if (!is_extern && !is_module_defined_entry) {
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

	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_DefaultSint: {
		if (type->size == 1) return TB_TYPE_I8;
		else if (type->size == 2) return TB_TYPE_I16;
		else if (type->size == 4) return TB_TYPE_I32;
		else if (type->size == 8) return TB_TYPE_I64;
		else f_trap();
	} break;

	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultUint: {
		if (type->size == 1) return TB_TYPE_I8;
		else if (type->size == 2) return TB_TYPE_I16;
		else if (type->size == 4) return TB_TYPE_I32;
		else if (type->size == 8) return TB_TYPE_I64;
		else f_trap();
	} break;

	case ffzTypeTag_Record: {
		f_assert(type->size <= 8);
		return TB_TYPE_I64; // maybe we should get the smallest type that the struct fits in instead
	} break;
		//case ffzTypeTag_Enum: {} break;
		//case ffzTypeTag_FixedArray: {} break;
	}
	f_trap();
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

	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Sint: return tb_debug_get_integer(g->tb, true, type->size * 8);

	case ffzTypeTag_DefaultUint: // fallthrough
	case ffzTypeTag_Uint: return tb_debug_get_integer(g->tb, false, type->size * 8);
		//case ffzTypeTag_Float: {} break;
		//case ffzTypeTag_Proc: {} break;

	case ffzTypeTag_Slice: // fallthrough
	case ffzTypeTag_String: // fallthrough
	case ffzTypeTag_Record: {
		if (type->tag == ffzTypeTag_Record && type->Record.is_union) f_trap();

		fArray(TB_DebugType*) tb_fields = f_array_make<TB_DebugType*>(g->alc);

		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzTypeRecordField& field = type->record_fields[i];
			TB_DebugType* t = tb_debug_create_field(g->tb, get_tb_debug_type(g, field.type), f_str_to_cstr(field.name, g->alc), field.offset);
			f_array_push(&tb_fields, t);
		}

		const char* name = type->tag == ffzTypeTag_String ? "string" :
			type->tag == ffzTypeTag_Slice ? make_name(g) : // TODO
			make_name(g, type->unique_node);

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

	default: f_trap();
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

static TB_Function* gen_procedure(Gen* g, ffzNodeOpInst inst) {
	auto insertion = f_map64_insert(&g->func_from_hash, ffz_hash_node_inst(inst), (TB_Function*)0, fMapInsert_DoNotOverride);
	if (!insertion.added) return *insertion._unstable_ptr;

	ffzType* proc_type = ffz_expr_get_type(g->project, inst);
	f_assert(proc_type->tag == ffzTypeTag_Proc);

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
		
		tb_prototype_add_param_named(g->tb, proto, param_type, f_str_to_cstr(param->name->Identifier.name, g->alc), param_debug_type);
	}

	const char* name = make_name(g, inst);
	TB_Function* func = tb_function_create(g->tb, name, TB_LINKAGE_PUBLIC);
	tb_function_set_prototype(func, proto);
	*insertion._unstable_ptr = func;

	// Set function start location
	tb_inst_loc(func, g->tb_file_from_parser_idx[inst.node->id.source_id], inst.node->loc.start.line_num);
	
	ffzNodeInst left = CHILD(inst,Op.left);
	if (left.node->kind == ffzNodeKind_ProcType && proc_type->Proc.out_param && proc_type->Proc.out_param->name) {
		// Default initialize the output value
		f_trap();//gen_statement(g, CHILD(IAS(left, ProcType), out_parameter));
	}

	TB_Function* func_before = g->fn;
	TB_Node* func_big_return_before = g->func_big_return;
	ffzType* proc_type_before = g->proc_type;
	g->fn = func;
	g->proc_type = proc_type;

	g->func_big_return = TB_NULL_REG;
	if (big_return) {
		// There's some weird things going on in TB debug info if we don't call tb_inst_param_addr on every parameter. So let's just call it.
		TB_Node* _param_addr = tb_inst_param_addr(func, 0);

#if FIX_TB_BIG_RETURN_HACK
		g->func_big_return = tb_inst_local(func, 8, 8);
		tb_inst_store(func, TB_TYPE_PTR, g->func_big_return, tb_inst_param(func, 0), 8, VOLATILE_OPS);
#else
		g->func_big_return = tb_inst_param(func, 0);
#endif
	}

	u32 i = 0;
	for FFZ_EACH_CHILD_INST(n, proc_type->unique_node) {
		ffzTypeProcParameter* param = &proc_type->Proc.in_params[i];

		f_assert(n.node->kind == ffzNodeKind_Declare);
		ffzNodeIdentifierInst param_definition = CHILD(n, Op.left);
		param_definition.polymorph = inst.polymorph; // hmmm...
		ffzNodeInstHash hash = ffz_hash_node_inst(param_definition);
		
		Value val = {};
		val.local_addr = tb_inst_param_addr(func, i + (u32)big_return); // TB parameter inspection doesn't work if we never call this

		// if it's a big parameter, then let's dereference the pointer pointer
		if (param->type->size > 8) {
			val.local_addr = tb_inst_param(func, i + (u32)big_return); // NOTE: this works with the new TB X64 backend, but has a bug with the old backend.
			//param_addr = tb_inst_load(g->tb_func, TB_TYPE_PTR, param_addr, 8); // so let's use this to make sure it works.
		}
		f_map64_insert(&g->value_from_definition, hash, val);
		i++;
	}

	for FFZ_EACH_CHILD_INST(n, inst) {
		gen_statement(g, n);
	}
	
	if (!proc_type->Proc.out_param) { // automatically generate a return statement if the proc doesn't return a value
		tb_inst_loc(func, g->tb_file_from_parser_idx[inst.node->id.source_id], inst.node->loc.end.line_num);
		tb_inst_ret(func, TB_NULL_REG);
	}

	g->proc_type = proc_type_before;
	g->fn = func_before;
	g->func_big_return = func_big_return_before;
	
	printf("\n");
	tb_function_print(func, tb_default_print_callback, stdout, false);
	printf("\n");

	bool ok = tb_module_compile_function(g->tb, func, TB_ISEL_FAST);
	f_assert(ok);

	return func;
}

static SmallOrPtr gen_call(Gen* g, ffzNodeOpInst inst) {
	ffzNodeInst left = CHILD(inst,Op.left);
	ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
	f_assert(left_chk.type->tag == ffzTypeTag_Proc);

	ffzType* ret_type = left_chk.type->Proc.out_param ? left_chk.type->Proc.out_param->type : NULL;
	bool big_return = ret_type && ret_type->size > 8; // :BigReturn
	
	TB_DataType ret_type_tb = big_return ? TB_TYPE_PTR :
		ret_type ? get_tb_basic_type(g, ret_type) : TB_TYPE_VOID;

	fArray(TB_Node*) args = f_array_make<TB_Node*>(g->alc);

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
			TB_Node* local_copy_addr = tb_inst_local(g->fn, param_type->size, param_type->align);
			tb_inst_memcpy(g->fn, local_copy_addr, arg.ptr, tb_inst_uint(g->fn, TB_TYPE_I32, param_type->size), param_type->align, VOLATILE_OPS);
			f_array_push(&args, local_copy_addr);
		}
		else {
			f_assert(arg.small != TB_NULL_REG);
			f_array_push(&args, arg.small);
		}
		i++;
	}

	TB_Node* target = gen_expr(g, left, false).small;
	f_assert(target != TB_NULL_REG);

	TB_Node* return_val = tb_inst_call(g->fn, ret_type_tb, target, args.len, args.data);
	if (!big_return) out.small = return_val;

	return out;
}

//struct Initializer { TB_Initializer* init; u8* mem; };

//Initializer make_initializer(Gen* g, u32 size, u32 alignment) {
//	TB_Initializer* init = tb_initializer_create(g->tb, size, alignment, 32); // ... why do we need to provide a capacity???
//	void* mem = tb_initializer_add_region(g->tb, init, 0, size);
//	return { init, (u8*)mem };
//}

static TB_Symbol* get_proc_symbol(Gen* g, ffzNodeInst proc_node) {
	if (proc_node.node->kind == ffzNodeKind_ProcType) { // @extern proc
		const char* name = make_name(g, proc_node);
		TB_External* external = tb_extern_create(g->tb, name, TB_EXTERNAL_SO_EXPORT);
		return (TB_Symbol*)external;
	}
	else {
		TB_Function* func = gen_procedure(g, proc_node);
		return (TB_Symbol*)func;
	}
}

static TB_Global* global_create(TB_Module* m, const char* name, TB_DebugType* dbg_type, size_t size, size_t align,
	TB_ModuleSection* section, TB_Linkage linkage, void** out_data)
{
	TB_Global* global = tb_global_create(m, name, dbg_type, linkage); // TODO: debug type?
	tb_global_set_storage(m, section, global, size, align, 32);
	*out_data = tb_global_add_region(m, global, 0, size);
	return global;
}

static void gen_global_constant(Gen* g, TB_Global* global, u8* base, u32 offset, ffzType* type, ffzConstantData* constant) {
	switch (type->tag) {
	case ffzTypeTag_Bool: // fallthrough
	case ffzTypeTag_Sint: // fallthrough
	case ffzTypeTag_DefaultSint: // fallthrough
	case ffzTypeTag_Uint: // fallthrough
	case ffzTypeTag_DefaultUint: {
		memcpy(base + offset, constant, type->size);
	} break;

	case ffzTypeTag_Proc: {
		memset(base + offset, 0, 8);
		if (constant->proc_node.node) {
			TB_Symbol* proc_sym = get_proc_symbol(g, constant->proc_node);
			tb_global_add_symbol_reloc(g->tb, global, offset, proc_sym);
		}
	} break;

	case ffzTypeTag_Pointer: {
		if (constant->ptr) todo;
		memset(base + offset, 0, 8);
	} break;

	case ffzTypeTag_String: {
		fString s = constant->string_zero_terminated;

		void* str_data;
		
		TB_Global* str_data_global = global_create(g->tb, make_name(g), NULL, (u32)s.len + 1, 1, tb_module_get_rdata(g->tb),
			TB_LINKAGE_PRIVATE, &str_data);
		memcpy(str_data, s.data, s.len);
		((u8*)str_data)[s.len] = 0; // zero-termination

		memset(base + offset, 0, 8);
		tb_global_add_symbol_reloc(g->tb, global, offset, (TB_Symbol*)str_data_global);

		u64 len = s.len;
		memcpy(base + offset + 8, &len, 8);
	} break;

	case ffzTypeTag_Slice: {
		memset(base + offset, 0, 16);
	} break;

	case ffzTypeTag_Record: {
		memset(base + offset, 0, type->size);
		ffzConstantData empty_constant = {};
		for (uint i = 0; i < type->record_fields.len; i++) {
			ffzTypeRecordField* field = &type->record_fields[i];
			
			gen_global_constant(g, global, base, offset + field->offset, field->type,
				constant->record_fields.len == 0 ? &empty_constant : &constant->record_fields[i]);
		}
	} break;
	case ffzTypeTag_FixedArray: {
		u32 elem_size = type->FixedArray.elem_type->size;
		for (u32 i = 0; i < (u32)type->FixedArray.length; i++) {
			ffzConstantData c = ffz_constant_fixed_array_get(type, constant, i);
			gen_global_constant(g, global, base, offset + i * elem_size, type->FixedArray.elem_type, &c);
		}
	} break;
	default: f_trap();
	}
}

static void _gen_store(Gen* g, TB_Node* addr, SmallOrPtr value, ffzType* type) {
	if (type->size > 8) {
		tb_inst_memcpy(g->fn, addr, value.ptr, tb_inst_uint(g->fn, TB_TYPE_I64, type->size), type->align, VOLATILE_OPS);
	}
	else {
		tb_inst_store(g->fn, get_tb_basic_type(g, type), addr, value.small, type->align, VOLATILE_OPS);
	}
}

//static void gen_store(Gen* g, TB_Node* lhs_address, ffzNodeInst rhs) {
//	SmallOrPtr rhs_value = gen_expr(g, rhs);
//	ffzType* type = ffz_expr_get_type(g->project, rhs);
//	_gen_store(g, lhs_address, rhs_value, type);
//}

static TB_Node* load_small(Gen* g, TB_Node* ptr, uint size) {
	if (size == 1) return tb_inst_load(g->fn, TB_TYPE_I8, ptr, 1, VOLATILE_OPS);
	else if (size == 2) return tb_inst_load(g->fn, TB_TYPE_I16, ptr, 2, VOLATILE_OPS);
	else if (size == 4) return tb_inst_load(g->fn, TB_TYPE_I32, ptr, 4, VOLATILE_OPS);
	else if (size == 8) return tb_inst_load(g->fn, TB_TYPE_I64, ptr, 8, VOLATILE_OPS);
	else f_trap(); // TODO!! i.e. a type could be of size 3, when [3]u8
	return 0;
}

static SmallOrPtr gen_expr(Gen* g, ffzNodeInst inst, bool address_of) {
	SmallOrPtr out = {};

	ffzCheckedExpr checked = ffz_expr_get_checked(g->project, inst);
	f_assert(ffz_type_is_grounded(checked.type));

	if (checked.const_val) {
		switch (checked.type->tag) {
		case ffzTypeTag_Bool: {
			f_assert(!address_of);
#if 0
			// TODO: message NeGate about this:
			// e.g.   foo: false   won't work
			out.small = tb_inst_bool(g->fn, checked.const_val->bool_);
#else
			out.small = tb_inst_cmp_ne(g->fn, tb_inst_uint(g->fn, TB_TYPE_I32, 0),
				tb_inst_uint(g->fn, TB_TYPE_I32, checked.const_val->bool_));
#endif
		} break;
		case ffzTypeTag_Sint: // fallthrough
		case ffzTypeTag_DefaultSint: {
			f_assert(!address_of);
			if (checked.type->size == 1)      out.small = tb_inst_sint(g->fn, TB_TYPE_I8,  checked.const_val->u8_);
			else if (checked.type->size == 2) out.small = tb_inst_sint(g->fn, TB_TYPE_I16, checked.const_val->u16_);
			else if (checked.type->size == 4) out.small = tb_inst_sint(g->fn, TB_TYPE_I32, checked.const_val->u32_);
			else if (checked.type->size == 8) out.small = tb_inst_sint(g->fn, TB_TYPE_I64, checked.const_val->u64_);
			else f_trap();
		} break;

		case ffzTypeTag_Uint: // fallthrough
		case ffzTypeTag_DefaultUint: {
			f_assert(!address_of);
			if (checked.type->size == 1)      out.small = tb_inst_uint(g->fn, TB_TYPE_I8,  checked.const_val->u8_);
			else if (checked.type->size == 2) out.small = tb_inst_uint(g->fn, TB_TYPE_I16, checked.const_val->u16_);
			else if (checked.type->size == 4) out.small = tb_inst_uint(g->fn, TB_TYPE_I32, checked.const_val->u32_);
			else if (checked.type->size == 8) out.small = tb_inst_uint(g->fn, TB_TYPE_I64, checked.const_val->u64_);
			else f_trap();
		} break;
		//case ffzTypeTag_Int: { BP; } break;
		case ffzTypeTag_Proc: {
			f_assert(!address_of);
			
			TB_Symbol* proc_sym = get_proc_symbol(g, checked.const_val->proc_node);
			out.small = tb_inst_get_symbol_address(g->fn, proc_sym);
		} break;

		case ffzTypeTag_Slice: // fallthrough
		case ffzTypeTag_String: // fallthrough
		case ffzTypeTag_FixedArray: // fallthrough
		case ffzTypeTag_Record: {
			void* base;
			TB_Global* global = global_create(g->tb, make_name(g), NULL, checked.type->size, checked.type->align,
				tb_module_get_rdata(g->tb), TB_LINKAGE_PRIVATE, &base); // TODO: debug type?

			gen_global_constant(g, global, (u8*)base, 0, checked.type, checked.const_val);
			
			TB_Node* global_addr = tb_inst_get_symbol_address(g->fn, (TB_Symbol*)global);
			if (address_of) out.small = global_addr;
			else {
				if (checked.type->size > 8) out.ptr = global_addr;
				else out.small = load_small(g, global_addr, checked.type->size);
			}
		} break;

		default: f_trap();
		}

		return out;
	}

	bool should_dereference = false;
	bool should_take_address = false;

	if (ffz_node_is_operator(inst.node->kind)) {
		ffzNodeInst left = CHILD(inst, Op.left);
		ffzNodeInst right = CHILD(inst, Op.right);
		switch (inst.node->kind) {

		case ffzNodeKind_Add: case ffzNodeKind_Sub:
		case ffzNodeKind_Mul: case ffzNodeKind_Div:
		case ffzNodeKind_Modulo: case ffzNodeKind_Equal:
		case ffzNodeKind_NotEqual: case ffzNodeKind_Less:
		case ffzNodeKind_LessOrEqual: case ffzNodeKind_Greater:
		case ffzNodeKind_GreaterOrEqual:
		{
			ffzType* input_type = ffz_expr_get_type(g->project, left);
			bool is_signed = ffz_type_is_signed_integer(input_type->tag);

			// TODO: more operator defines. I guess we should do this together with the fix for vector math
			f_assert(input_type->size <= 8);

			f_assert(!address_of);
			TB_Node* a = gen_expr(g, left).small;
			TB_Node* b = gen_expr(g, right).small;

			switch (inst.node->kind) {
			case ffzNodeKind_Add: { out.small = tb_inst_add(g->fn, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzNodeKind_Sub: { out.small = tb_inst_sub(g->fn, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzNodeKind_Mul: { out.small = tb_inst_mul(g->fn, a, b, (TB_ArithmaticBehavior)0); } break;
			case ffzNodeKind_Div: { out.small = tb_inst_div(g->fn, a, b, is_signed); } break;
			case ffzNodeKind_Modulo: { out.small = tb_inst_mod(g->fn, a, b, is_signed); } break;

			case ffzNodeKind_Equal: { out.small = tb_inst_cmp_eq(g->fn, a, b); } break;
			case ffzNodeKind_NotEqual: { out.small = tb_inst_cmp_ne(g->fn, a, b); } break;
			case ffzNodeKind_Less: { out.small = tb_inst_cmp_ilt(g->fn, a, b, is_signed); } break;
			case ffzNodeKind_LessOrEqual: { out.small = tb_inst_cmp_ile(g->fn, a, b, is_signed); } break;
			case ffzNodeKind_Greater: { out.small = tb_inst_cmp_igt(g->fn, a, b, is_signed); } break;
			case ffzNodeKind_GreaterOrEqual: { out.small = tb_inst_cmp_ige(g->fn, a, b, is_signed); } break;

			default: f_trap();
			}
		} break;

		case ffzNodeKind_UnaryMinus: {
			f_assert(!address_of);
			out.small = tb_inst_neg(g->fn, gen_expr(g, right).small);
		} break;

		case ffzNodeKind_LogicalNOT: {
			f_assert(!address_of);
			// (!x) is equivalent to (x == false)
			out.small = tb_inst_cmp_eq(g->fn, gen_expr(g, right).small, tb_inst_bool(g->fn, false));
		} break;

		case ffzNodeKind_PostRoundBrackets: {
			// sometimes we need to take the address of a temporary.
			// e.g.  copy_string("hello").ptr
			should_take_address = address_of;

			if (left.node->kind == ffzNodeKind_Keyword && ffz_keyword_is_bitwise_op(left.node->Keyword.keyword)) {
				ffzKeyword keyword = left.node->Keyword.keyword;

				TB_Node* first = gen_expr(g, ffz_get_child_inst(inst, 0)).small;
				if (keyword == ffzKeyword_bit_not) {
					out.small = tb_inst_not(g->fn, first);
				}
				else {
					TB_Node* second = gen_expr(g, ffz_get_child_inst(inst, 1)).small;
					switch (keyword) {
					case ffzKeyword_bit_and: { out.small = tb_inst_and(g->fn, first, second); } break;
					case ffzKeyword_bit_or: { out.small = tb_inst_or(g->fn, first, second); } break;
					case ffzKeyword_bit_xor: { out.small = tb_inst_xor(g->fn, first, second); } break;
					case ffzKeyword_bit_shl: { out.small = tb_inst_shl(g->fn, first, second, (TB_ArithmaticBehavior)0); } break;
					case ffzKeyword_bit_shr: { out.small = tb_inst_shr(g->fn, first, second); } break;
					default: f_trap();
					}
				}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				if (left_chk.type->tag == ffzTypeTag_Type) {
					ffzType* dst_type = left_chk.const_val->type;
					// type cast, e.g. u32(5293900)

					ffzNodeInst arg = ffz_get_child_inst(inst, 0);
					ffzType* arg_type = ffz_expr_get_type(g->project, arg);

					out = gen_expr(g, arg);
					if (ffz_type_is_pointer_ish(dst_type->tag)) { // cast to pointer
						if (ffz_type_is_pointer_ish(arg_type->tag)) {}
						else if (ffz_type_is_integer_ish(arg_type->tag)) {
							out.small = tb_inst_int2ptr(g->fn, out.small);
						}
					}
					else if (ffz_type_is_integer_ish(dst_type->tag)) { // cast to integer
						TB_DataType dt = get_tb_basic_type(g, dst_type);
						if (ffz_type_is_pointer_ish(arg_type->tag)) {
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
					out = gen_call(g, inst);
				}
			}
		} break;

		case ffzNodeKind_AddressOf: {
			f_assert(!address_of);
			out = gen_expr(g, right, true);
		} break;

		case ffzNodeKind_Dereference: {
			out = gen_expr(g, left);
			should_dereference = !address_of;
		} break;

		case ffzNodeKind_MemberAccess: {
			fString member_name = right.node->Identifier.name;

			if (left.node->kind == ffzNodeKind_Identifier && left.node->Identifier.name == F_LIT("in")) {
				f_assert(!address_of); // TODO
				for (int i = 0; i < g->proc_type->Proc.in_params.len; i++) {
					ffzTypeProcParameter& param = g->proc_type->Proc.in_params[i];
					if (param.name->Identifier.name == member_name) {
						out.small = tb_inst_param(g->fn, i);
						f_assert(param.type->size <= 8);
					}
				}
			}
			else {
				ffzCheckedExpr left_chk = ffz_expr_get_checked(g->project, left);
				ffzType* struct_type = left_chk.type->tag == ffzTypeTag_Pointer ? left_chk.type->Pointer.pointer_to : left_chk.type;

				ffzTypeRecordFieldUse field;
				f_assert(ffz_type_find_record_field_use(g->project, struct_type, member_name, &field));

				TB_Node* addr_of_struct = gen_expr(g, left, left_chk.type->tag != ffzTypeTag_Pointer).small;
				f_assert(addr_of_struct != TB_NULL_REG);

				out.small = tb_inst_member_access(g->fn, addr_of_struct, field.offset);
				should_dereference = !address_of;
			}
		} break;

		case ffzNodeKind_PostCurlyBrackets: {
			// dynamic initializer
			out.ptr = tb_inst_local(g->fn, checked.type->size, checked.type->align);
			out.ptr_can_be_stolen = true;
			f_assert(checked.type->size > 8);

			if (checked.type->tag == ffzTypeTag_Record) {
				u32 i = 0;
				for FFZ_EACH_CHILD_INST(n, inst) {
					ffzTypeRecordField& field = checked.type->record_fields[i];

					SmallOrPtr src = gen_expr(g, n);
					TB_Node* dst_ptr = tb_inst_member_access(g->fn, out.ptr, field.offset);
					_gen_store(g, dst_ptr, src, field.type);
					i++;
				}
			}
			else if (checked.type->tag == ffzTypeTag_FixedArray) {
				u32 i = 0;
				ffzType* elem_type = checked.type->FixedArray.elem_type;
				for FFZ_EACH_CHILD_INST(n, inst) {
					SmallOrPtr src = gen_expr(g, n, false);
					TB_Node* dst_ptr = tb_inst_member_access(g->fn, out.ptr, i * elem_type->size);
					_gen_store(g, dst_ptr, src, elem_type);
					i++;
				}
			}
			else f_trap();
		} break;

		case ffzNodeKind_PostSquareBrackets: {
			ffzType* left_type = ffz_expr_get_type(g->project, left);
			f_assert(left_type->tag == ffzTypeTag_FixedArray || left_type->tag == ffzTypeTag_Slice);

			ffzType* elem_type = left_type->tag == ffzTypeTag_Slice ? left_type->Slice.elem_type : left_type->FixedArray.elem_type;

			TB_Node* left_value = gen_expr(g, left, true).small;
			TB_Node* array_data = left_value;

			if (left_type->tag == ffzTypeTag_Slice) {
				f_trap();// array_data = c0_push_load(g->c0_proc, c0_agg_type_basic(g->c0, C0Basic_ptr), array_data);
			}

			if (ffz_get_child_count(inst.node) == 2) { // slicing
				ffzNodeInst lo_inst = ffz_get_child_inst(inst, 0);
				ffzNodeInst hi_inst = ffz_get_child_inst(inst, 1);

				TB_Node* lo = lo_inst.node->kind == ffzNodeKind_Blank ?
					tb_inst_uint(g->fn, TB_TYPE_I64, 0) : gen_expr(g, lo_inst).small;
				TB_Node* hi;
				if (hi_inst.node->kind == ffzNodeKind_Blank) {
					if (left_type->tag == ffzTypeTag_FixedArray) {
						hi = tb_inst_uint(g->fn, TB_TYPE_I64, left_type->FixedArray.length);
					}
					else {
						// load the 'len' field of a slice
						hi = tb_inst_load(g->fn, TB_TYPE_I64, tb_inst_member_access(g->fn, left_value, 8), 8, VOLATILE_OPS);
					}
				}
				else {
					hi = gen_expr(g, hi_inst).small;
				}

				out.ptr = tb_inst_local(g->fn, 16, 8);
				lo = tb_inst_zxt(g->fn, lo, TB_TYPE_I64);
				hi = tb_inst_zxt(g->fn, hi, TB_TYPE_I64);
				TB_Node* lo_offset = tb_inst_mul(g->fn, lo, tb_inst_uint(g->fn, TB_TYPE_I64, elem_type->size), (TB_ArithmaticBehavior)0);
				TB_Node* ptr = tb_inst_add(g->fn, tb_inst_ptr2int(g->fn, array_data, TB_TYPE_I64), lo_offset, (TB_ArithmaticBehavior)0);
				TB_Node* len = tb_inst_sub(g->fn, hi, lo, (TB_ArithmaticBehavior)0);

				tb_inst_store(g->fn, TB_TYPE_I64, out.ptr, ptr, 8, VOLATILE_OPS);
				tb_inst_store(g->fn, TB_TYPE_I64, tb_inst_member_access(g->fn, out.ptr, 8), len, 8, VOLATILE_OPS);
			}
			else { // taking an index
				ffzNodeInst index_node = ffz_get_child_inst(inst, 0);
				TB_Node* index = tb_inst_zxt(g->fn, gen_expr(g, index_node).small, TB_TYPE_I64);

				TB_Node* index_offset = tb_inst_mul(g->fn, index,
					tb_inst_uint(g->fn, TB_TYPE_I64, elem_type->size), (TB_ArithmaticBehavior)0);

				out.small = tb_inst_add(g->fn, tb_inst_ptr2int(g->fn, array_data, TB_TYPE_I64),
					index_offset, (TB_ArithmaticBehavior)0);

				should_dereference = !address_of;
			}
		} break;

		case ffzNodeKind_LogicalOR: // fallthrough
		case ffzNodeKind_LogicalAND: {
			TB_Node* left_cond = gen_expr(g, left).small;

			// implement short-circuiting

			TB_Label true_bb = tb_basic_block_create(g->fn);
			TB_Label right_bb = tb_basic_block_create(g->fn);
			TB_Label after_bb = tb_basic_block_create(g->fn);
			TB_Label false_bb = tb_basic_block_create(g->fn);

			if (inst.node->kind == ffzNodeKind_LogicalAND) {
				tb_inst_if(g->fn, left_cond, right_bb, false_bb);
			}
			else {
				tb_inst_if(g->fn, left_cond, true_bb, right_bb);
			}

			tb_inst_set_label(g->fn, right_bb);
			tb_inst_if(g->fn, gen_expr(g, right).small, true_bb, false_bb);

			tb_inst_set_label(g->fn, false_bb);
			TB_Node* false_val = tb_inst_bool(g->fn, false);
			tb_inst_goto(g->fn, after_bb);

			tb_inst_set_label(g->fn, true_bb);
			TB_Node* true_val = tb_inst_bool(g->fn, true);
			tb_inst_goto(g->fn, after_bb);

			tb_inst_set_label(g->fn, after_bb);
			out.small = tb_inst_phi2(g->fn, false_bb, false_val, true_bb, true_val);

			// TODO: message negate, this doesn't always work!  i.e. with  foo() || bar()   where foo returns true
			/*TB_Label left_false = tb_basic_block_create(g->fn);
			TB_Label left_true = tb_basic_block_create(g->fn);
			TB_Label after = tb_basic_block_create(g->fn);
			tb_inst_if(g->fn, left_cond, left_true, left_false);

			tb_inst_set_label(g->fn, left_false);
			TB_Node* left_false_val = AND ? tb_inst_bool(g->fn, false) : gen_expr(g, right).small;

			tb_inst_goto(g->fn, after);

			tb_inst_set_label(g->fn, left_true);
			TB_Node* left_true_val = AND ? gen_expr(g, right).small : tb_inst_bool(g->fn, true);
			tb_inst_goto(g->fn, after);

			tb_inst_set_label(g->fn, after);
			out.small = tb_inst_phi2(g->fn, left_false, left_false_val, left_true, left_true_val);*/
		} break;

		default: f_trap();
		}
	}
	else {
		switch (inst.node->kind) {
		case ffzNodeKind_Identifier: {
			ffzNodeIdentifierInst def = ffz_get_definition(g->project, inst);
			if (def.node->Identifier.is_constant) f_trap();

			Value* val = f_map64_get(&g->value_from_definition, ffz_hash_node_inst(def));
			f_assert(val);
			out.small = val->symbol ? tb_inst_get_symbol_address(g->fn, val->symbol) : val->local_addr;
			
			should_dereference = !address_of;
		} break;
		case ffzNodeKind_ThisValueDot: {
			ffzNodeInst assignee;
			f_assert(ffz_dot_get_assignee(inst, &assignee));
			out = gen_expr(g, assignee, address_of);
		} break;

		default: f_trap();
		}
	}

	if (should_dereference) {
		f_assert(!should_take_address);
		if (checked.type->size > 8) {
			out.ptr = out.small;
			out.small = {};
			f_assert(!out.ptr_can_be_stolen); //out.ptr_can_be_stolen = false;
		}
		else {
			// TODO: load small
			out.small = tb_inst_load(g->fn, get_tb_basic_type(g, checked.type), out.small, checked.type->align, VOLATILE_OPS);
		}
	}
	
	if (should_take_address) {
		f_assert(!should_dereference);
		if (checked.type->size > 8) {
			out.small = out.ptr;
			out.ptr = {};
		}
		else {
			TB_Node* tmp = tb_inst_local(g->fn, checked.type->size, checked.type->align);
			tb_inst_store(g->fn, get_tb_basic_type(g, checked.type), tmp, out.small, checked.type->align, VOLATILE_OPS);
			out.small = tmp;
		}
	}
	
	f_assert(out.small || out.ptr);
	f_assert((out.small == NULL) ^ (out.ptr == NULL));
	// a ^^ b
	return out;
}

static void inst_loc(Gen* g, ffzNode* node, u32 line_num) {
	tb_inst_loc(g->fn, g->tb_file_from_parser_idx[node->id.source_id], line_num);
}

static void gen_statement(Gen* g, ffzNodeInst inst, bool set_loc) {
	if (set_loc) {
		if (inst.node->kind == ffzNodeKind_Declare && !ffz_decl_is_runtime_value(inst.node)) {}
		else {
			inst_loc(g, inst.node, inst.node->loc.start.line_num);
		}
	}
	
	switch (inst.node->kind) {
		
	case ffzNodeKind_Declare: {
		ffzNodeIdentifierInst definition = CHILD(inst, Op.left);
		ffzCheckedExpr checked = ffz_decl_get_checked(g->project, inst);

		if (ffz_decl_is_runtime_value(inst.node)) {
			ffzNodeInst rhs = CHILD(inst, Op.right);
			Value val = {};
			if (ffz_get_tag(g->project, inst, ffzKeyword_global)) {
				ffzCheckedExpr rhs_checked = ffz_decl_get_checked(g->project, rhs); // get the initial value

				void* global_data;
				TB_Global* global = global_create(g->tb, make_name(g), NULL, rhs_checked.type->size, rhs_checked.type->align,
					tb_module_get_data(g->tb), TB_LINKAGE_PRIVATE, &global_data);

				gen_global_constant(g, global, (u8*)global_data, 0, rhs_checked.type, rhs_checked.const_val);
				val.symbol = (TB_Symbol*)global;
			}
			else {
				SmallOrPtr rhs_value = gen_expr(g, rhs);
				val.local_addr = tb_inst_local(g->fn, checked.type->size, checked.type->align);

				tb_function_attrib_variable(g->fn, val.local_addr, f_str_to_cstr(definition.node->Identifier.name, g->alc),
					get_tb_debug_type(g, checked.type));

				_gen_store(g, val.local_addr, rhs_value, checked.type);
			}
			f_map64_insert(&g->value_from_definition, ffz_hash_node_inst(definition), val);
		}
		else {
			// need to still generate exported procs
			if (checked.type->tag == ffzTypeTag_Proc) {
				ffzNodeInst rhs = CHILD(inst,Op.right);
				if (rhs.node->kind == ffzNodeKind_PostCurlyBrackets) { // @extern procs also have the type ffzTypeTag_Proc so we need to ignore those
					gen_procedure(g, rhs);
				}
			}
		}
	} break;

	case ffzNodeKind_Assign: {
		ffzNodeInst lhs = CHILD(inst, Op.left);
		ffzNodeInst rhs = CHILD(inst, Op.right);
		TB_Node* addr_of_lhs = gen_expr(g, lhs, true).small;
		
		SmallOrPtr rhs_value = gen_expr(g, rhs);
		_gen_store(g, addr_of_lhs, rhs_value, ffz_expr_get_type(g->project, rhs));
	} break;

	case ffzNodeKind_Scope: {
		for FFZ_EACH_CHILD_INST(n, inst) {
			gen_statement(g, n);
		}
	} break;

	case ffzNodeKind_If: {
		TB_Node* cond = gen_expr(g, CHILD(inst, If.condition)).small;
		
		//if (inst.node->loc.start.line_num == 108) f_trap();

		TB_Label true_bb = tb_basic_block_create(g->fn);
		TB_Label else_bb;
		if (inst.node->If.else_scope) {
			else_bb = tb_basic_block_create(g->fn);
		}

		TB_Label after_bb = tb_basic_block_create(g->fn);
		tb_inst_if(g->fn, cond, true_bb, inst.node->If.else_scope ? else_bb : after_bb);
		
		tb_inst_set_label(g->fn, true_bb);
		gen_statement(g, CHILD(inst,If.true_scope));
		true_bb = tb_inst_get_label(g->fn); // continue the block where the recursion left off
		
		if (!tb_basic_block_is_complete(g->fn, true_bb)) { // TB will otherwise complain
			inst_loc(g, inst.node, inst.node->If.true_scope->loc.end.line_num);
			tb_inst_goto(g->fn, after_bb);
		}

		if (inst.node->If.else_scope) {
			tb_inst_set_label(g->fn, else_bb);
			gen_statement(g, CHILD(inst, If.else_scope));
			else_bb = tb_inst_get_label(g->fn); // continue the block where the recursion left off
			
			if (!tb_basic_block_is_complete(g->fn, else_bb)) { // TB will otherwise complain
				inst_loc(g, inst.node, inst.node->If.else_scope->loc.end.line_num);
				tb_inst_goto(g->fn, after_bb);
			}
		}

		tb_inst_set_label(g->fn, after_bb);
	} break;

	case ffzNodeKind_For: {
		ffzNodeInst pre = CHILD(inst, For.header_stmts[0]);
		ffzNodeInst condition = CHILD(inst, For.header_stmts[1]);
		ffzNodeInst post = CHILD(inst, For.header_stmts[2]);
		ffzNodeInst body = CHILD(inst, For.scope);
		
		if (pre.node) gen_statement(g, pre);
		
		TB_Label cond_bb = tb_basic_block_create(g->fn);
		TB_Label body_bb = tb_basic_block_create(g->fn);
		TB_Label after_bb = tb_basic_block_create(g->fn);
		tb_inst_goto(g->fn, cond_bb);

		if (!condition.node) f_trap(); // TODO
		
		{
			tb_inst_set_label(g->fn, cond_bb);
			TB_Node* cond = gen_expr(g, condition).small;
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
		TB_Node* val = TB_NULL_REG;
		
		if (inst.node->Return.value) {
			SmallOrPtr return_value = gen_expr(g, CHILD(inst, Return.value));
			if (return_value.ptr) {
				ffzType* ret_type = ffz_expr_get_type(g->project, CHILD(inst, Return.value)); // hmm.. I think we should return the type with gen_expr

#if FIX_TB_BIG_RETURN_HACK
				val = tb_inst_load(g->fn, TB_TYPE_PTR, g->func_big_return, 8, VOLATILE_OPS);
#else
				val = g->func_big_return;
#endif
				//tb_inst_param(g->tb_func, 0); // :BigReturn
				tb_inst_memcpy(g->fn, val, return_value.ptr, tb_inst_uint(g->fn, TB_TYPE_I64, ret_type->size), ret_type->align, VOLATILE_OPS);
			}
			else {
				val = return_value.small;
			}
		}

		tb_inst_ret(g->fn, val);
	} break;

	case ffzNodeKind_PostRoundBrackets: {
		gen_call(g, inst);
	} break;

	default: f_trap();
	}
}

bool ffz_backend_gen_executable_tb(ffzProject* project) {
	//ASSERT(!tb_arena);
	//tb_arena = arena_make_virtual_reserve_fixed(GiB(1), NULL);
	//f_assert(!tb_allocator);
	//tb_allocator = f_temp_alc();

	TB_FeatureSet features = { 0 };
	TB_Module* tb_module = tb_module_create_for_host(&features, true);

	Gen g = {};
	g.tb = tb_module;
	g.alc = f_temp_alc();
	g.project = project;
	g.tb_file_from_parser_idx = f_array_make<TB_FileID>(g.alc);
	g.value_from_definition = f_map64_make<Value>(g.alc);
	g.func_from_hash = f_map64_make<TB_Function*>(g.alc);

	for (u32 i = 0; i < project->parsers.len; i++) {
		ffzParser* parser = project->parsers[i];
		
		TB_FileID file = tb_file_create(tb_module, f_str_to_cstr(parser->source_code_filepath, g.alc));
		f_array_push(&g.tb_file_from_parser_idx, file);
	}

	for (u32 i = 0; i < project->parsers.len; i++) {
		ffzParser* parser = project->parsers[i];
		g.checker = parser->checker;

		for FFZ_EACH_CHILD(n, parser->root) {
			gen_statement(&g, ffz_get_toplevel_inst(g.checker, n));
		}
	}

	f_trap(); // TODO: f_files_make_directory on build dir
	fString obj_path = F_STR_T_JOIN(project->directory, F_LIT("\\.build\\"), project->name, F_LIT(".obj"));
	fString exe_path = F_STR_T_JOIN(project->directory, F_LIT("\\.build\\"), project->name, F_LIT(".exe"));

	TB_Exports exports = tb_module_object_export(tb_module, TB_DEBUGFMT_CODEVIEW);
	f_files_write_whole(obj_path, fString{ exports.files[0].data, exports.files[0].length });
	tb_exporter_free(exports);
	
	tb_module_destroy(tb_module);

	{ // link
		WinSDK_Find_Result windows_sdk = WinSDK_find_visual_studio_and_windows_sdk();
		fString msvc_directory = f_str_from_utf16(windows_sdk.vs_exe_path, g.alc); // contains cl.exe, link.exe
		fString windows_sdk_include_base_path = f_str_from_utf16(windows_sdk.windows_sdk_include_base, g.alc); // contains <string.h>, etc
		fString windows_sdk_um_library_path = f_str_from_utf16(windows_sdk.windows_sdk_um_library_path, g.alc); // contains kernel32.lib, etc
		fString windows_sdk_ucrt_library_path = f_str_from_utf16(windows_sdk.windows_sdk_ucrt_library_path, g.alc); // contains libucrt.lib, etc
		fString vs_library_path = f_str_from_utf16(windows_sdk.vs_library_path, g.alc); // contains MSVCRT.lib etc
		fString vs_include_path = f_str_from_utf16(windows_sdk.vs_include_path, g.alc); // contains vcruntime.h

		fArray(fString) linker_args = f_array_make<fString>(g.alc);
		f_array_push(&linker_args, F_STR_T_JOIN(msvc_directory, F_LIT("\\link.exe")));

		// Note that we should not put quotation marks around the path. It's because of some weird rules with how command line arguments are combined into one string on windows.
		f_array_push(&linker_args, F_STR_T_JOIN(F_LIT("/LIBPATH:"), windows_sdk_um_library_path));
		f_array_push(&linker_args, F_STR_T_JOIN(F_LIT("/LIBPATH:"), windows_sdk_ucrt_library_path));
		f_array_push(&linker_args, F_STR_T_JOIN(F_LIT("/LIBPATH:"), vs_library_path));
		f_array_push(&linker_args, F_LIT("/INCREMENTAL:NO"));     // incremental linking would break things with the way we're generating OBJ files
		f_array_push(&linker_args, F_LIT("/DEBUG"));

		bool console_app = true;
		f_array_push(&linker_args, console_app ? F_LIT("/SUBSYSTEM:CONSOLE") : F_LIT("/SUBSYSTEM:WINDOWS"));
		
		f_array_push(&linker_args, F_LIT("/NODEFAULTLIB")); // avoid linking to CRT
		f_array_push(&linker_args, F_LIT("/ENTRY:ffz_entry"));

		f_array_push(&linker_args, F_STR_T_JOIN(F_LIT("/OUT:"), exe_path));
		f_array_push(&linker_args, obj_path);

		for (uint i = 0; i < project->link_libraries.len; i++) {
			f_array_push(&linker_args, project->link_libraries[i]);
		}
		for (uint i = 0; i < project->link_system_libraries.len; i++) {
			f_array_push(&linker_args, project->link_system_libraries[i]);
		}

		printf("Running microsoft linker: \n");
		for (uint i = 0; i < linker_args.len; i++) {
			printf("\"%s\" ", f_str_to_cstr(linker_args[i], f_temp_alc()));
		}
		printf("\n\n");

		u32 exit_code;
		if (!f_os_run_command(linker_args.slice, {}, &exit_code)) {
			printf("Could find the microsoft linker!\n");
			return false; // @leak: WinSDK_free_resources
		}
		if (exit_code != 0) {
			printf("Linker failed!\n");
			return false; // @leak: WinSDK_free_resources
		}
	}
	return true;
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
	
	TB_Node* result = tb_inst_sint(func, TB_TYPE_I32, 999);
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

#endif // FFZ_BUILD_INCLUDE_TB