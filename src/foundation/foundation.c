// required libraries
#pragma comment(lib, "gdi32.lib") // required by glfw3
#pragma comment(lib, "shell32.lib") // required by glfw3
#pragma comment(lib, "user32.lib") // required by glfw3

#pragma comment(lib, "Dbghelp.lib") // os_get_stack_trace

#define FOUNDATION_HELPER_MACROS
#include "foundation.h"

#define OPT(ptr) ptr

#define Array(T) fArrayRaw
#define fSlice(T) fSliceRaw
#define fMap64(T) fMap64Raw

#include <stdio.h> // would be nice to get rid of this
#include <stdarg.h> // for va_list
#include <string.h> // for memcmp
#include <stdlib.h> // for strtod

//#include "vendor/meow_hash/meow_hash_x64_aesni.h"
//#include "vendor/meow_hash/meow_hash_x64_aesni.h"
#define XXH_STATIC_LINKING_ONLY
#define XXH_NO_STDLIB
#define XXH_IMPLEMENTATION
#include "vendor/xxhash.h"

// -- All global state held by the foundation -------------------------------
//Arena temp_allocator_arena;
u64 global_rand = 0;

static u8 SLOT_ARENA_FREELIST_END = 0;

//THREAD_LOCAL void* _foundation_pass; // TODO: get rid of this!

F_THREAD_LOCAL fArena* _f_temp_arena;
F_THREAD_LOCAL uint _f_temp_arena_scope_counter = 0;
F_THREAD_LOCAL bool _f_temp_arena_keep_alive = false;
F_THREAD_LOCAL fLeakTracker _f_leak_tracker;

// --------------------------------------------------------------------------


#define ARRAY_IDX(T, arr, idx) ((T*)arr.data)[i]

#define SEPARATOR_CHARS F_LIT("/\\")

typedef struct {
	u8 bytes[32];
} ASCII_Set;

// @noutf
ASCII_Set ascii_set_make(fString chars) {
	//ZoneScoped;
	ASCII_Set set = {0};
	for (uint i = 0; i < chars.len; i++) {
		u8 c = chars.data[i];
		set.bytes[c / 8] |= 1 << (c % 8);
	}
	return set;
}

bool ascii_set_contains(ASCII_Set set, u8 c) {
	//ZoneScoped;
	return (set.bytes[c / 8] & 1 << (c % 8)) != 0;
}


// @noutf
bool f_str_last_index_of_any_char(fString str, fString chars, uint* out_index) {
	//ZoneScoped;
	ASCII_Set char_set = ascii_set_make(chars);

	for (uint i = str.len - 1; i < str.len; i--) {
		if (ascii_set_contains(char_set, str.data[i])) {
			*out_index = i;
			return true;
		}
	}
	return false;
}

bool f_str_equals(fString a, fString b) {
	return a.len == b.len && memcmp(a.data, b.data, a.len) == 0;
}

bool f_str_equals_nocase(fString a, fString b) {
	if (a.len != b.len) return false;
	for (uint i = 0; i < a.len; i++) {
		if (f_str_rune_to_lower(a.data[i]) != f_str_rune_to_lower(b.data[i])) {
			return false;
		}
	}
	return true;
}

fString f_str_slice(fString str, uint lo, uint hi) {
	F_ASSERT(hi >= lo && hi <= str.len);
	return (fString){str.data + lo, hi - lo};
}

fString f_str_slice_after(fString str, uint mid) {
	F_ASSERT(mid <= str.len);
	return (fString){str.data + mid, str.len - mid};
}

fString f_str_slice_before(fString str, uint mid) {
	F_ASSERT(mid <= str.len);
	return (fString){str.data, mid};
}

bool f_str_find_substring(fString str, fString substr, uint* out_index) {
	// ZoneScoped;
	for (uint i = 0; i < str.len; i++) {
		if (f_str_equals(f_str_slice(str, i, i + substr.len), substr)) {
			*out_index = i;
			return true;
		}
	}
	return false;
};

bool f_str_contains(fString str, fString substr) {
	uint _idx;
	return f_str_find_substring(str, substr, &_idx);
}

fString f_str_path_extension(fString path) {
	//ZoneScoped;
	s64 idx;
	if (f_str_last_index_of_any_char(path, F_LIT("."), &idx)) {
		return f_str_slice_after(path, idx + 1);
	}
	return (fString){0};
}

fString f_str_path_dir(fString path) {
	uint last_sep;
	if (f_str_last_index_of_any_char(path, SEPARATOR_CHARS, &last_sep)) {
		return f_str_slice_before(path, last_sep);
	}
	return path;
}

fString str_format_va_list(fAllocator* a, const char* fmt, va_list args) {
	va_list _args = args;

	uint needed_bytes = vsnprintf(0, 0, fmt, args) + 1;
	fString result = f_str_make(needed_bytes, a);

	result.len -= 1;
	result.data[result.len] = 0;

	vsnprintf((char*)result.data, needed_bytes, fmt, _args);
	return result;
}

void f_str_print(Array(u8)* buffer, fString str) {
	f_array_push_slice_raw(buffer, F_BITCAST(fSliceRaw, str), 1, 1);
}

void f_str_print_rune(Array(u8)* buffer, rune r) {
	F_ASSERT(r < 128); // TODO
	f_array_push_raw(buffer, &r, 1, 1);
}

//SliceRaw array_get_slice_raw(ArrayRaw* array) { return *(SliceRaw*)array; }

void f_str_print_repeat(Array(u8)* buffer, fString str, uint count) {
	for (uint i = 0; i < count; i++) f_str_print(buffer, str);
}

fString f_str_format(fAllocator* a, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	fString result = str_format_va_list(a, fmt, args);
	va_end(args);
	return result;
}

void f_str_printf(Array(u8)* buffer, const char* fmt, ...) {
	fAllocator* temp = f_temp_push();
	
	va_list args;
	va_start(args, fmt);
	fString str = str_format_va_list(temp, fmt, args);
	va_end(args);
	
	f_str_print(buffer, str);
	f_temp_pop();
}



void f_mem_copy(void* dst, const void* src, uint size) { memcpy(dst, src, size); }

fString f_str_path_tail(fString path) {
	uint last_sep;
	if (f_str_last_index_of_any_char(path, SEPARATOR_CHARS, &last_sep)) {
		path = f_str_slice_after(path, last_sep + 1);
	}
	return path;
}

fString f_str_path_stem(fString path) {
	//ZoneScoped;
	//if (path.len == 0 || str_contains(SEPARATOR_CHARS, STR_FROM_CHAR(path[path.len - 1]))) {
	//	return {};
	//}

	uint last_sep;
	if (f_str_last_index_of_any_char(path, SEPARATOR_CHARS, &last_sep)) {
		path = f_str_slice_after(path, last_sep + 1);
	}

	uint last_dot;
	if (f_str_last_index_of_any_char(path, F_LIT("."), &last_dot)) {
		path = f_str_slice_before(path, last_dot);
	}

	return path;
}

//const char* temp_cstr(fString str) {
//	fSlice(u8) mem = mem_alloc(str.len + 1, TEMP_ALLOCATOR);
//	memcpy(mem.data, str.data, str.len);
//	mem.data[str.len] = '\0';
//
//	return (char*)mem.data;
//}


//void slot_array_test() {
//	Slot_Array<int> arr = {};
//
//	Slot_Array_Handle<int> first_handle = slot_array_add(arr, 123);
//	Slot_Array_Handle<int> bah = slot_array_add(arr, 521);
//
//	assert(*arr[first_handle] == 123);
//	assert(*arr[bah] == 521);
//
//	*arr[first_handle] = 1293;
//	assert(*arr[first_handle] == 1293);
//
//}

//u32 hash_fnv32(fSlice(u8) data, u32 seed) {
//	for (i64 i = 0; i < data.len; i++) {
//		seed = (seed * 0x01000193) ^ data[i];
//	}
//	return seed;
//}


// idea for a bucketed slice
// 
// template<typename T>
// struct BucketedIndex {
//   void* bucket_base;
//   u32 elem_offset;
// 
//   // Bucket array metadata
//   u8 bucket_start_offset; // at offset 0, we store a pointer to the previous bucket. Maybe this field is not needed.
//   u24 bucket_end_offset; // at this offset, we store a pointer to the next bucket.
// }
// 
//template<typename T>
//struct BucketedSlice {
//  BucketedIndex lo;
//  BucketedIndex hi;
//};

//void ArrayReserveRaw(RawArray* arr, uint elem_size, uint capacity) {
//	ZoneScoped;

//}

fString f_str_clone(fString str, fAllocator* a) {
	fString copied = f_str_make(str.len, a);
	f_str_copy(copied, str);
	return copied;
}

//fString f_str_clone(const char* cstr, fAllocator* a) {
//	ZoneScoped;
//	return f_str_clone(fString{ (u8*)cstr, (isize)strlen(cstr) }, allocator);
//}

//fString _str_join(fSlice(fString) strings, fAllocator* a) {
//	ZoneScoped;
//	i64 total_size = 0;
//	for (i64 i = 0; i < strings.len; i++)
//		total_size += strings.data[i].len;
//
//	fString result = MakeSlice(u8, total_size, allocator);
//
//	u8* ptr = result.data;
//	for (i64 i = 0; i < strings.len; i++) {
//		memcpy(ptr, (const void*)strings.data[i].data, strings.data[i].len);
//		ptr += strings.data[i].len;
//	}
//
//	return result;
//}

/*void str_split(fString str, u8 character, fAllocator* a, Slice(fString)* out) {
	uint required_len = 1;
	for (uint i = 0; i < str.len; i++) {
		if (str.data[i] == character) required_len++;
	}

	Array(fString) substrings = make_array_cap_raw(sizeof(fString), required_len, a);
	
	uint prev = 0;
	for (uint i = 0; i < str.len; i++) {
		if (str.data[i] == character) {
			fString s = str_slice(str, prev, i);
			array_push_raw(&substrings, &s, sizeof(fString));
			prev = i + 1;
		}
	}
	
	fString s = str_slice_after(str, prev);
	array_push_raw(&substrings, &s, sizeof(fString));
	*out = BITCAST(Slice(fString), substrings);
}*/

bool f_str_ends_with(fString str, fString end) {
	return str.len >= end.len && f_str_equals(end, f_str_slice_after(str, str.len - end.len));
}

bool f_str_starts_with(fString str, fString start) {
	return str.len >= start.len && f_str_equals(start, f_str_slice_before(str, start.len));
}

fString f_str_cut_end(fString str, fString end) {
	if (f_str_ends_with(str, end)) {
		str.len -= end.len;
	}
	return str;
}

fString f_str_cut_start(fString str, fString start) {
	if (f_str_starts_with(str, start)) {
		str = f_str_slice_after(str, start.len);
	}
	return str;
}

void f_str_split_i(fString str, u8 character, fAllocator* a, fSlice(fRangeUint)* out) {
	uint required_len = 1;
	for (uint i = 0; i < str.len; i++) {
		if (str.data[i] == character) required_len++;
	}

	Array(fRangeUint) splits = f_array_make_cap_raw(sizeof(fRangeUint), required_len, a);

	uint prev = 0;
	for (uint i = 0; i < str.len; i++) {
		if (str.data[i] == character) {
			fRangeUint range = { prev, i };
			f_array_push(fRangeUint, &splits, range);
			prev = i + 1;
		}
	}

	fRangeUint range = { prev, str.len };
	f_array_push(fRangeUint, &splits, range);
	*out = F_BITCAST(fSlice(fRangeUint), splits);
}

//void* slot_array_subscript_raw(SlotArrayRaw* arr, SlotArrayHandle handle, usize elem_size) {
//	ZoneScoped;
//	if (handle.id == 0) return NULL;
//
//	handle.id -= 1;
//	u32 bucket_index = handle.id / arr->num_items_per_bucket; // if we made `num_items_per_bucket` a power of 2, we could get rid of this divide
//	u32 item_index = handle.id % arr->num_items_per_bucket;
//
//	const usize item_size = sizeof(SlotArrayElemHeader) + elem_size;
//	SlotArrayElemHeader* item = (SlotArrayElemHeader*)((u8*)arr->buckets.data[bucket_index] + item_index * item_size);
//	if (item->gen != handle.gen) return NULL;
//
//	return item + 1;
//}

//SlotArrayHandle slot_array_add_raw(SlotArrayRaw* arr, usize size, const void* value) {
//	ZoneScoped;
//	ASSERT(arr->num_items_per_bucket != 0); // Did you call slot_array_init?
//
//	const isize item_size = sizeof(SlotArrayElemHeader) + size;
//
//	arr->num_alive += 1;
//	if (arr->first_removed) {
//		// take a previously freed handle
//
//		u32 id = arr->first_removed;
//		u32 bucket_index = (id - 1) / arr->num_items_per_bucket;
//		u32 item_index = (id - 1) % arr->num_items_per_bucket;
//
//		SlotArrayElemHeader* item = (SlotArrayElemHeader*)((u8*)arr->buckets.data[bucket_index] + item_size * item_index);
//		arr->first_removed = item->next_free_item;
//
//		item->next_free_item = 0;
//		memcpy(item + 1, value, size);
//
//		return { id, item->gen };
//	}
//
//	if (arr->last_bucket_cursor >= arr->num_items_per_bucket) {
//		arr->last_bucket_cursor = 0;
//		arr->last_bucket++;
//	}
//	if (arr->last_bucket >= arr->buckets.len) {
//		//if (!arr->allocator.proc)
//		//	slot_array_init(arr);
//
//		fSlice(u8) bucket_allocation = MemAllocSlice(u8, arr->num_items_per_bucket * item_size, arr->allocator);
//		array_append(&arr->buckets, (void*)bucket_allocation.data);
//	}
//
//	// allocate a new handle
//
//	u32 id = arr->last_bucket * arr->num_items_per_bucket + arr->last_bucket_cursor + 1;
//	SlotArrayElemHeader* item = (SlotArrayElemHeader*)((u8*)arr->buckets.data[arr->last_bucket] + item_size * arr->last_bucket_cursor);
//	item->gen = 0;
//	item->next_free_item = 0;
//	memcpy(item + 1, value, size);
//	arr->last_bucket_cursor++;
//
//	return { id, item->gen };
//}

//inline u64 leak_tracker_next_allocation(LeakTracker* t) {
//	u64 new_idx = t->next_allocation_idx;
//	t->next_allocation_idx++;
//	return new_idx;
//}

#if 0
fSlice(u8) tracker_alloc(fAllocator* a, i64 size, i64 alignment) {
	LeakTracker* tracker = (LeakTracker*)allocator;
	fSlice(u8) allocation = tracker->passthrough_allocator->alloc(tracker->passthrough_allocator, size, alignment);
	
	// Even with zero sized allocations, we still want a unique allocated address at least for memory debugging purposes.
	ASSERT(allocation.data != NULL);

	LeakTracker_Entry entry;
	entry.allocation_idx = leak_tracker_next_allocation(tracker);
	entry.size = size;
	entry.alignment = alignment;
	array_init(&entry.callstack, 8, &tracker->internal_arena.allocator);

	{
		struct Pass {
			int i;
			LeakTracker* tracker;
			LeakTracker_Entry* entry;
		} pass = {0, tracker, &entry};
		_foundation_pass = &pass;

		os_get_stack_trace([](fString function, fString file, u32 line) {
			Pass* pass = (Pass*)_foundation_pass;
			if (pass->i > 0) {
				fString* filepath_cached = pass->tracker->file_names_cache[file];
				if (!filepath_cached) {
					fString cloned = f_str_clone(file, &pass->tracker->internal_arena.allocator);
					filepath_cached = map_insert(&pass->tracker->file_names_cache, cloned, cloned).ptr;
				}

				array_append(&pass->entry->callstack, { *filepath_cached, line });
			}
			pass->i++;
		});
	}

	map_insert(&tracker->active_allocations, (void*)allocation.data, entry);
	return allocation;
	BP;
	return {};
}
#endif

#if 0
void tracker_free(fAllocator* a, fSlice(u8) allocation) {
	BP;
	LeakTracker* tracker = (LeakTracker*)allocator;
	if (allocation.data) {
		LeakTracker_Entry* entry = tracker->active_allocations[(void*)allocation.data];
		if (entry && entry->size == allocation.len) {
			map_remove(&tracker->active_allocations, (void*)allocation.data);
			tracker->passthrough_allocator->free(tracker->passthrough_allocator, allocation);
		}
		else {
			ASSERT(false); // not sure if we should have bad_free_array or assert
			LeakTracker_BadFree bad_free = { (void*)allocation.data };
			array_append(&tracker->bad_free_array, bad_free);
		}
	}
}
#endif

#if 0
void tracker_resize(fAllocator* a, fSlice(u8)* allocation, i64 new_size, i64 alignment) {
	LeakTracker* tracker = (LeakTracker*)allocator;
	u8* old_address = allocation->data;
	ASSERT(old_address);

	tracker->passthrough_allocator->resize(tracker->passthrough_allocator, allocation, new_size, alignment);
	
	LeakTracker_Entry entry = {};

	if (old_address) {
		entry = *tracker->active_allocations[(void*)old_address];
		
		if (old_address != allocation->data) {
			ASSERT(map_remove(&tracker->active_allocations, (void*)old_address));
		}
	}

	//entry.location = loc;
	//entry.memory = (void*)allocation->data;
	entry.size = new_size;
	entry.alignment = alignment;
	map_insert(&tracker->active_allocations, (void*)allocation->data, entry, MapInsertMode_Overwrite);
	BP;
}
#endif

//void tracker_begin(fAllocator* a, void* address) {
//	LeakTracker* tracker = (LeakTracker*)allocator;
//	map_insert(&tracker->active_allocations, address, (LeakTracker_Entry) { leak_tracker_next_allocation(tracker) });
//}
//
//void tracker_end(fAllocator* a, void* address) {
//	LeakTracker* tracker = (LeakTracker*)allocator;
//	if (address) {
//		LeakTracker_Entry* entry = tracker->active_allocations[address];
//		if (entry) {
//			map_remove(&tracker->active_allocations, address);
//		}
//		else {
//			LeakTracker_BadFree bad_free = { address };
//			array_append(&tracker->bad_free_array, bad_free);
//		}
//	}
//}

void f_leak_tracker_init() {
	//ZoneScoped;
	F_ASSERT(!_f_leak_tracker.active);
	
	_f_leak_tracker.internal_arena = f_arena_make_virtual_reserve_fixed(F_GIB(1), NULL);
	_f_leak_tracker.active_allocations = f_map64_make_raw(sizeof(fLeakTracker_Entry), &_f_leak_tracker.internal_arena->alc);
	_f_leak_tracker.file_names_cache = f_map64_make_raw(sizeof(fString), &_f_leak_tracker.internal_arena->alc);
	_f_leak_tracker.active = true;
}

void f_leak_tracker_deinit() {
	F_ASSERT(_f_leak_tracker.active);
	_f_leak_tracker.active = false;
	//ZoneScoped;
	
	fAllocator* temp = f_temp_push();
	fLeakTracker_Entry* entry;
	for f_map64_each_raw(&_f_leak_tracker.active_allocations, key, &entry) {
		printf("Leak tracker still has an active entry! Original callstack:\n");
		for (uint i = 0; i < entry->callstack.len; i++) {
			fLeakTrackerCallstackEntry stackframe = ARRAY_IDX(fLeakTrackerCallstackEntry, entry->callstack, i);
			printf("   - file: %s, line: %u\n", f_str_to_cstr(stackframe.file, temp), stackframe.line);
		}
	}

	f_temp_pop();
	//BP;
	//for (uint i = 0; i < .alive_count; i++) {
	//	BP;
	//}

	//if (_leak_tracker.active_allocations.alive_count > 0) {
	//}
	//ASSERT(_leak_tracker.active_allocations.alive_count == 0); // TODO: print a summary

	f_arena_free(_f_leak_tracker.internal_arena);
}

typedef struct {
	fLeakTracker_Entry* entry;
	uint skip_stackframes_count;
	uint i;
} LeakTrackerBeginEntryPass;

//u64 hash64_ex(u64 value, u64 seed) {
//	return XXH64(&value, 8, seed);
//}

u64 f_hash64_str_ex(fString data, u64 seed) {
	return XXH64(data.data, data.len, seed);
	//u64 h = 0xcbf29ce484222325;
	//for (u64 i =0; i < data.len; i++) {
	//	h = (h * 0x100000001b3) ^ data.data[i];
	//}
	//return h;
}

static void leak_tracker_begin_entry_stacktrace_visitor(fString function, fString file, u32 line, void* user_ptr) {
	LeakTrackerBeginEntryPass* pass = user_ptr;
	if (pass->i > pass->skip_stackframes_count) {
		u64 filepath_hash = f_hash64_str_ex(file, 0);
		
		fMapInsertResult map_entry = f_map64_insert_raw(&_f_leak_tracker.file_names_cache, filepath_hash, NULL, fMapInsert_DoNotOverride);		
		fString* filepath_cached = (fString*)map_entry._unstable_ptr;
		if (map_entry.added) {
			*filepath_cached = f_str_clone(file, &_f_leak_tracker.internal_arena->alc);
		}

		fLeakTrackerCallstackEntry entry = { *filepath_cached, line };
		f_array_push(fLeakTrackerCallstackEntry, &pass->entry->callstack, entry);
	}
	pass->i++;
}

void f_leak_tracker_begin_entry(void* address, uint skip_stackframes_count) {
	if (!_f_leak_tracker.active) return;
	_f_leak_tracker.active = false; // disable leak tracker for the duration of this function
	
	fLeakTracker_Entry entry = {0};
	entry.callstack = f_array_make_cap_raw(sizeof(fLeakTracker_Entry), 8, &_f_leak_tracker.internal_arena->alc);
	
	// We could even store the function name and use the file_names_cache. Maybe rename it to just "string_table"
	f_get_stack_trace(leak_tracker_begin_entry_stacktrace_visitor, &(LeakTrackerBeginEntryPass) { &entry, skip_stackframes_count, 0});
	
	f_map64_insert_raw(&_f_leak_tracker.active_allocations, (u64)address, &entry, fMapInsert_AssertUnique);
	_f_leak_tracker.active = true;
}

fArrayRaw f_array_make_raw(fAllocator* a) { return (fArrayRaw) { .alc = a }; }

fArrayRaw f_array_make_len_raw(u32 elem_size, uint len, const void* initial_value, fAllocator* a) {
	fArrayRaw array = f_array_make_len_garbage_raw(elem_size, len, a);
	for (uint i = 0; i < len; i++) {
		memcpy((u8*)array.data + elem_size*i, initial_value, elem_size);
	}
	return array;
}

fArrayRaw f_array_make_len_garbage_raw(u32 elem_size, uint len, fAllocator* a) {
	return (fArrayRaw) {
		.data = f_mem_alloc_n(u8, len * elem_size, a), // TODO: go with the next power of 2
		.len = len,
		.capacity = len,
		.alc = a,
	};
}

fArrayRaw f_array_make_cap_raw(u32 elem_size, uint capacity, fAllocator* a) {
	return (fArrayRaw) {
		.data = f_mem_alloc_n(u8, capacity * elem_size, a), // TODO: go with the next power of 2
		.len = 0,
		.capacity = capacity,
		.alc = a,
	};
}

void f_array_reserve_raw(fArrayRaw* array, uint capacity, u32 elem_size) {
	if (capacity > array->capacity) {
		F_ASSERT(array->alc); // Did you call f_array_make?
		array->data = f_mem_resize_n(u8, array->data, array->capacity * elem_size, capacity * elem_size, array->alc);
		array->capacity = capacity;
	}
}

void f_array_free_raw(fArrayRaw* array, u32 elem_size) {
	f_mem_free_n(u8, array->data, elem_size * array->capacity, array->alc);
	_DEBUG_FILL_GARBAGE(array, sizeof(*array));
}

#ifdef _DEBUG
void _DEBUG_FILL_GARBAGE(void* ptr, uint len) { memset(ptr, 0xCC, len); }
#endif

void slice_copy_raw(fSliceRaw dst, fSliceRaw src) {
}

void f_array_push_slice_raw(fArrayRaw* array, fSliceRaw elems, u32 elem_size, u32 elem_align) {
	f_array_reserve_raw(array, array->len + elems.len, elem_size);
	for (uint i = 0; i < elems.len; i++) {
		f_array_push_raw(array, (const void*)((u8*)elems.data + elem_size * i), elem_size, elem_align);
	}
}

void f_array_resize_raw(fArrayRaw* array, uint len, const void* value, u32 elem_size) {
	f_array_reserve_raw(array, len, elem_size);
	for (uint i = array->len; i < len; i++) {
		memcpy((u8*)array->data + i * elem_size, value, elem_size);
	}
	array->len = len;
}

uint f_array_push_raw(fArrayRaw* array, const void* elem, u32 elem_size, u32 elem_align) {
	if (array->len >= array->capacity) {
		// grow the array
		uint new_capacity = F_MAX(8, array->capacity * 2);
		
		array->data = f_mem_resize(array->data, elem_size * array->capacity, elem_size * new_capacity, elem_align, array->alc);
		array->capacity = new_capacity;
	}
	memcpy((u8*)array->data + array->len * elem_size, elem, elem_size);
	return array->len++;
}

void f_array_pop_raw(fArrayRaw* array, OPT(void*) out_elem, u32 elem_size) {
	F_ASSERT(array->len >= 1);
	array->len--;
	if (out_elem) {
		memcpy(out_elem, (u8*)array->data + array->len * elem_size, elem_size);
	}
}

void f_leak_tracker_assert_is_alive(void* address) {
	if (!_f_leak_tracker.active) return;
	F_ASSERT(f_map64_get_raw(&_f_leak_tracker.active_allocations, (u64)address));
}

void f_leak_tracker_end_entry(void* address) {
	if (!_f_leak_tracker.active) return;
	_f_leak_tracker.active = false; // disable leak tracker for the duration of this function
	bool ok = f_map64_remove_raw(&_f_leak_tracker.active_allocations, (u64)address);
	F_ASSERT(ok);

	_f_leak_tracker.active = true;
}

u32 f_random_u32() {
	//ZoneScoped;
	F_BP;
	//ASSERT(false);
	//return rand();
	return 0;
	//if (global_rand == 0) {
	//	global_rand = read_cycle_counter();
	//}
	//
	//return (u32)rand() + (u32)global_rand;
}

u64 f_random_u64() {
	F_BP;
	//return (((u64)rand_u32()) << 32) | (u64)rand_u32();
	return 0;
}


float f_random_float_in_range(float minimum, float maximum) {
	F_BP;
	//ZoneScoped;
	//return minimum + (maximum - minimum) * (((float)rand()) / (float)RAND_MAX);
	return 0;
}



//void _custom_print_f(void(*append_fn)(fString), fString fmt, std::initializer_list<fString> args) {
//	fSlice(fString) args_slice = { (fString*)args.begin(), args.size() };
//
//	uint reserve_len = fmt.len;
//	for (int i = 0; i < args.size(); i++) reserve_len += args_slice[i].len;
//
//	for (uint offset = 0, offset_next = 0; rune r = str_next_rune(fmt, &offset_next); offset = offset_next) {
//		if (r == '%') {
//			offset = offset_next;
//			r = str_next_rune(fmt, &offset_next);
//
//			if (r == '%') { // escape %
//				append_fn(F_LIT("%"));
//				continue;
//			}
//
//			ASSERT(r >= '0' && r <= '9');
//			append_fn(args_slice[r - '0']);
//			continue;
//		}
//
//		append_fn(slice(fmt, offset, offset_next));
//	}
//}

//fString __aprint(fAllocator* a, const char* fmt, ...) {
//	//ZoneScoped;
//	va_list args;
//	va_start(args, fmt);
//	fString result = __aprint_va_list(allocator, fmt, args);
//	va_end(args);
//	return result;
//	//__crt_va_start(args, fmt); defer(__crt_va_end(args));
//}


//void _print_fmt(fString fmt, std::initializer_list<fString> args) {
//	_custom_print_f([](fString str) {
//		os_write_to_console(str);
//	}, fmt, args);
//}

//fString _aprint_fmt(fAllocator* a, fString fmt, std::initializer_list<fString> args) {
//	fSlice(fString) args_slice = { (fString*)args.begin(), args.size() };
//
//	uint size = 0;
//	_foundation_pass = &size;
//	_custom_print_f([](fString str) { *(uint*)_foundation_pass += 1; }, fmt, args);
//	
//	fString result = MakeSlice(u8, size, allocator);
//	
//	_foundation_pass = result.data;
//	_custom_print_f([](fString str) {
//		memcpy(_foundation_pass, str.data, str.len);
//		_foundation_pass = (u8*)_foundation_pass + str.len;
//	}, fmt, args);
//
//	return result;
//}

//void _bprint_fmt(fArray(u8)* buffer, fString fmt, std::initializer_list<fString> args) {
//	_foundation_pass = buffer;
//	_custom_print_f([](fString str) {
//		array_push_slice((fArray(u8)*)_foundation_pass, str);
//		}, fmt, args);
//}
//
//void _Print(std::initializer_list<fString> args) {
//	for (fString arg : args) {
//		os_write_to_console(arg);
//	}
//}

//void _PrintB(fArray(u8)* buffer, std::initializer_list<fString> args) {
//	for (fString arg : args) {
//		array_push_slice(buffer, arg);
//	}
//}

//fString _PrintA(fAllocator* a, std::initializer_list<fString> args) {
//	uint size = 0;
//	for (fString arg : args) size += arg.len;
//
//	fArray(u8) buf;
//	InitArrayCap(&buf, size, allocator);
//	for (fString arg : args) array_push_slice(&buf, arg);
//	return buf.slice;
//}

fString f_str_from_uint(fString bytes, fAllocator* a) {
	F_ASSERT(bytes.len == 1 || bytes.len == 2 || bytes.len == 4 || bytes.len == 8);
	return bytes.len == 1 ?
			f_str_format(a, "%hhu", *(u8*)bytes.data) : bytes.len == 2 ?
			f_str_format(a, "%hu", *(u16*)bytes.data) : bytes.len == 4 ?
			f_str_format(a, "%u", *(u32*)bytes.data) :
			f_str_format(a, "%llu", *(u64*)bytes.data);
}

fString f_str_from_int(fString bytes, fAllocator* a) {
	F_ASSERT(bytes.len == 1 || bytes.len == 2 || bytes.len == 4 || bytes.len == 8);
	return bytes.len == 1 ?
			f_str_format(a, "%hhd", *(s8*)bytes.data) : bytes.len == 2 ?
			f_str_format(a, "%hd", *(s16*)bytes.data) : bytes.len == 4 ?
			f_str_format(a, "%d", *(s32*)bytes.data) :
			f_str_format(a, "%lld", *(s64*)bytes.data);
}

fString f_str_from_float_ex(fString bytes, int num_decimals, fAllocator* a) {
	//ZoneScoped;
	F_ASSERT(bytes.len == 4 || bytes.len == 8);
	char fmt_string[5];
	fmt_string[0] = '%';
	fmt_string[1] = '.';
	fmt_string[2] = '0' + (char)F_MIN(num_decimals, 9);
	fmt_string[3] = 'f';
	fmt_string[4] = 0;
	return f_str_format(a, fmt_string, bytes.len == 4 ? *(f32*)bytes.data : *(f64*)bytes.data);
}

fString f_str_from_float(fString bytes, fAllocator* a) {
	F_ASSERT(bytes.len == 4 || bytes.len == 8);
	return f_str_format(a, "%f", bytes.len == 4 ? *(f32*)bytes.data : *(f64*)bytes.data);
}


//fSlice(u8) global_allocator_alloc(fAllocator* a, uint size, uint alignment) {
//	fSlice(u8) allocation;
//	allocation.data = (u8*)malloc(size);
//	allocation.len = size;
//
//#ifdef _DEBUG
//	memset(allocation.data, 0xCC, allocation.len);
//#endif
//
//	// About capacity:
//	// As we're providing the user with the size of the allocation, we could potentially supply more than the requested size there.
//	// The only problem is that some places, such as `new_clone` will not end up using that memory / storing the allocated size anywhere
//	// and will instead provide the requested size back to free.
//	// Maybe we could have additional `AllocatorMode_Alloc_Flexible` and `AllocatorMode_Resize_Flexible` modes
//
//	return allocation;
//}

//void global_allocator_free(fAllocator* a, fSlice(u8) allocation) {
//#ifdef _DEBUG
//	memset(allocation.data, 0xCC, allocation.len); // debug; trigger data-breakpoints and make use-after-free bugs evident.
//#endif
//	free(allocation.data);
//}

//void global_allocator_resize(fAllocator* a, fSlice(u8)* allocation, uint new_size, uint alignment) {
//	if (new_size <= allocation->len) return;
//
//	ASSERT(allocation->data != NULL);
//
//#ifdef _DEBUG
//	u8* new_data = (u8*)malloc(new_size);
//	memcpy(new_data, allocation->data, allocation->len);
//	memset(new_data + allocation->len, 0xCC, new_size - allocation->len);
//
//	memset(allocation->data, 0xCC, allocation->len); // debug; trigger data-breakpoints and make use-after-free bugs evident.
//	free(allocation->data);
//
//	allocation->data = new_data;
//	allocation->len = new_size;
//#else
//	allocation->data = (u8*)realloc(allocation->data, new_size);
//	allocation->len = new_size;
//#endif
//}

void f_str_copy(fString dst, fString src) {
	F_ASSERT(dst.len >= src.len);
	memcpy(dst.data, src.data, src.len);
}

u8* f_arena_push_str(fArena* arena, fString data, uint_pow2 alignment) {
	fString result = f_arena_push(arena, data.len, alignment);
	f_str_copy(result, data);
	return result.data;
}

static void error_out_of_memory() {
	f_os_error_popup(F_LIT("Error!"), F_LIT("Program ran out of available memory.\nThis is likely the fault of the program itself."));
	exit(1);
}

fString f_arena_push(fArena* arena, uint size, uint_pow2 alignment) {
	F_ASSERT(F_IS_POWER_OF_2(alignment));
	//ZoneScoped;
	u8* allocation_pos = NULL;

	F_HITS(_c, 0);
	// TODO: get rid of this switch for the allocator vtable

	switch (arena->desc.mode) {
	case fArenaMode_VirtualReserveFixed: {
		//uint allocation_pos = ALIGN_UP_POW2(arena->pos.offset, alignment);
		//arena->pos.offset = allocation_pos + size;
		allocation_pos = (u8*)F_ALIGN_UP_POW2((uint)arena->pos.head, alignment);
		arena->pos.head = allocation_pos + size;

		if ((uint)arena->pos.head > (uint)arena->committed_end) {
			f_mem_commit(arena->committed_end, (uint)arena->pos.head - (uint)arena->committed_end);
			arena->committed_end = (u8*)F_ALIGN_UP_POW2((uint)arena->pos.head, F_KIB(4));
		}
		
		if ((uint)arena->pos.head > (uint)arena->internal_base + arena->desc.VirtualReserveFixed.reserve_size) {
			error_out_of_memory();
		}

#ifdef _DEBUG
		memset(allocation_pos, 0xCC, size);
#endif
	} break;
	
	case fArenaMode_UsingBufferFixed: {
		allocation_pos = (u8*)F_ALIGN_UP_POW2((uint)arena->pos.head, alignment);
		arena->pos.head = allocation_pos + size;

		F_ASSERT(arena->internal_base);
		if ((uint)arena->pos.head > (uint)arena->internal_base + arena->desc.UsingBufferFixed.size) {
			error_out_of_memory();
		}
	} break;
	
	case fArenaMode_UsingAllocatorGrowing: {
		// form a linked list of allocation blocks

		allocation_pos = (u8*)F_ALIGN_UP_POW2((uint)arena->pos.head, alignment);

		fArenaBlock* curr_block = arena->pos.current_block;
		if (!curr_block || ((uint)allocation_pos + size > (uint)curr_block + curr_block->size_including_header)) {
			//HITS(_cccc, 31);
			// The allocation doesn't fit in this block.

			OPT(fArenaBlock*) next_block = curr_block ? curr_block->next : NULL;
			
			uint block_size = F_MAX(arena->desc.UsingAllocatorGrowing.min_block_size, sizeof(fArenaBlock) + size);

			// If the allocation overflows the block size, let's free at least as much memory from above the head as we allocate.
			// This is to make sure that the arena's memory usage never grows past the maximum of what the user has asked for.
			//ArenaBlockHeader* b = next_block;
			for (uint amount_of_memory_released = 0;
				next_block && block_size > next_block->size_including_header && amount_of_memory_released < block_size;)
			{
				fArenaBlock* after = next_block->next;
				amount_of_memory_released += next_block->size_including_header;
				f_mem_free(next_block, next_block->size_including_header, arena->desc.UsingAllocatorGrowing.a);
				next_block = after;
				curr_block->next = next_block;
			}

			if (next_block && block_size <= next_block->size_including_header) {
				curr_block = next_block;
			}
			else {
				// allocate a new block
				F_ASSERT(alignment <= 16); // Let's align each block to 16 bytes.
				fArenaBlock* new_block = f_mem_alloc(block_size, 16, arena->desc.UsingAllocatorGrowing.a);
				new_block->size_including_header = block_size;
				new_block->next = next_block;

				//printf("_c is %llu\n", _c);

				if (curr_block) curr_block->next = new_block;
				else arena->first_block = new_block;
				curr_block = new_block;
			}

			arena->pos.current_block = curr_block;
			allocation_pos = (u8*)(curr_block + 1);
		}

		arena->pos.head = allocation_pos + size;
		F_ASSERT((uint)arena->pos.head <= (uint)arena->pos.current_block + arena->pos.current_block->size_including_header);
	} break;
	
	default: F_BP;
	}

	return (fString){ allocation_pos, size };
}


fMap64Raw f_map64_make_raw(u32 value_size, fAllocator* a) { return f_make_map64_cap_raw(value_size, 0, a); }

static u32 hashmap64_get_slot_index(u64 key, u32 slot_count_log2) {
	const u64 golden_ratio_64 = 0x9E3779B97F4A7D69;

	u32 slot_index = (u32)((key * golden_ratio_64) >> (64 - slot_count_log2)); // fibonacci hash
	return slot_index;
}

OPT(void*) f_map64_get_raw(fMap64Raw* map, u64 key) {
	F_ASSERT(key <= F_MAP64_LAST_VALID_KEY);
	if (!map->slots) return NULL;

	//HITS(_c, 628);
	u32 slot_index = hashmap64_get_slot_index(key, map->slot_count_log2);
	u32 slot_size = map->value_size + 8;
	u8* slots = (u8*)map->slots;

	u32 wrapping_mask = (1u << map->slot_count_log2) - 1;
	for (;;) {
		F_ASSERT(slot_index < (1u << map->slot_count_log2));
		u64* key_ptr = (u64*)(slots + slot_index * slot_size);
		if (*key_ptr == key) {
			return key_ptr + 1;
		}

		if (*key_ptr == F_MAP64_EMPTY_KEY) return NULL;
		
		slot_index = (slot_index + 1) & wrapping_mask;
	}
}

void f_map64_resize_raw(fMap64Raw* map, u32 slot_count_log2) {
	slot_count_log2 = F_MAX(slot_count_log2, 2); // always have at minimum 4 slots
	u32 slot_size = map->value_size + 8;
	
	OPT(u8*) slots_before = map->slots;
	u32 slot_count_before = (1 << map->slot_count_log2);

	map->alive_count = 0;
	map->slot_count = (1 << slot_count_log2);
	map->slot_count_log2 = slot_count_log2;
	
	//((uint) & ((T*)0)->f)
	//uint test = ((struct _dummy { char c; Arena member; }*)0)->member;

	int test = F_ALIGN_OF(int);

	F_HITS(_c, 0);
	map->slots = f_mem_alloc_n(u8, slot_size * map->slot_count, map->alc);
	//if (map->slots == (void*)0x0000020000004440) BP;
	memset(map->slots, 0xFFFFFFFF, map->slot_count * slot_size); // fill all keys with HASHMAP64_EMPTY_KEY

	if (slots_before) {
		for (uint i = 0; i < slot_count_before; i++) {
			u64* key_ptr = (u64*)(slots_before + i * slot_size);
			void* value_ptr = key_ptr + 1;
			if (*key_ptr <= F_MAP64_LAST_VALID_KEY) {
				f_map64_insert_raw(map, *key_ptr, value_ptr, fMapInsert_AssertUnique);
			}
		}

		f_mem_free_n(u8, slots_before, slot_size * slot_count_before, map->alc);
	}
}

uint_pow2 f_next_pow_of_2(uint v) {
	// todo: use the following formula from Tilde Backend
	// x == 1 ? 1 : 1 << (64 - _lzcnt_u64(x - 1));

	// https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;
	v++;
	return v;
}

uint log2(uint_pow2 value) {
	F_ASSERT(F_IS_POWER_OF_2(value));
	uint result = 0;
	for (; value > 1;) {
		value >>= 1;
		result++;
	}
	return result;
}

#define slice_get(T, slice, index) ((T*)slice.data)[index]

fString f_str_join(fAllocator* a, fSliceRaw args) {
	uint offset = 0;
	for (uint i = 0; i < args.len; i++) {
		offset += slice_get(fString, args, i).len;
	}

	fString result = { f_mem_alloc_n(u8, offset, a), offset };

	offset = 0;
	for (uint i = 0; i < args.len; i++) {
		fString arg = slice_get(fString, args, i);
		f_str_copy(f_str_slice(result, offset, offset + arg.len), arg);
		offset += arg.len;
	}
	return result;
}

fMap64Raw f_make_map64_cap_raw(u32 value_size, uint_pow2 capacity, fAllocator* a) {
	fMap64Raw map = (fMap64Raw){
		.alc = a,
		.value_size = F_ALIGN_UP_POW2(value_size, 8),
	};
	uint slot_count_log2 = log2(capacity);
	f_map64_resize_raw(&map, F_CAST(u32, slot_count_log2));
	return map;
}

fMapInsertResult f_map64_insert_raw(fMap64Raw* map, u64 key, OPT(const void*) value, fMapInsert mode) {
	F_ASSERT(key <= F_MAP64_LAST_VALID_KEY);
	F_HITS(_c, 0);

	//     filled / allocated >= 70/100
	// <=> filled * 100 >= allocated * 70

	// Note that `slot_count_before` will be 1 even when it's actually zero, becase we can't represent 0 in the _log2 form.
	// However this is fine, because the map will expand in that case too.
	u32 slot_count_before = 1u << map->slot_count_log2;
	if ((map->alive_count + 1) * 100 >= slot_count_before * 70) {
		// expand the map
		f_map64_resize_raw(map, map->slot_count_log2 + 1);
	}

	u32 slot_index = hashmap64_get_slot_index(key, map->slot_count_log2);
	u32 slot_size = map->value_size + 8;
	u8* slots = (u8*)map->slots;
	u32 wrapping_mask = (1u << map->slot_count_log2) - 1;

	void* first_dead_value = NULL;
	
	for (;;) {
		u64* key_ptr = (u64*)(slots + slot_index * slot_size);
		void* value_ptr = key_ptr + 1;

		if (*key_ptr > F_MAP64_LAST_VALID_KEY) {
			// We can't stop yet, because the key might still exist after this.
			if (!first_dead_value) first_dead_value = value_ptr;
			if (*key_ptr == F_MAP64_EMPTY_KEY) break; // Don't have to continue further, we know that this key does not exist in the map.
		}
		else if (*key_ptr == key) {
			if (mode == fMapInsert_Override) {
				memcpy(value_ptr, value, map->value_size);
				return (fMapInsertResult) { value_ptr, .added = false };
			}
			else if (mode == fMapInsert_DoNotOverride) {
				return (fMapInsertResult) { value_ptr, .added = false };
			}
			else { // Element already exists, and the behaviour of the map is set to AssertUnique!
				F_ASSERT(false);
			}
		}
		slot_index = (slot_index + 1) & wrapping_mask;
	}

	map->alive_count++;
	*((u64*)first_dead_value - 1) = key;
	if (value) memcpy(first_dead_value, value, map->value_size);
	return (fMapInsertResult) { first_dead_value, .added = true };
}

bool f_map64_remove_raw(fMap64Raw* map, u64 key) {
	if (map->alive_count == 0 || !map->slots) return false;

	u32 slot_index = hashmap64_get_slot_index(key, map->slot_count_log2);
	u32 slot_size = map->value_size + 8;
	u8* slots = (u8*)map->slots;
	u32 wrapping_mask = (1u << map->slot_count_log2) - 1;

	for (;;) {
		u64* key_ptr = (u64*)(slots + slot_index * slot_size);
		if (*key_ptr == F_MAP64_EMPTY_KEY) {
			return false; // key does not exist in the table!
		}

		u32 next_slot_index = (slot_index + 1) & wrapping_mask;

		if (*key_ptr == key) {
			void* value_ptr = key_ptr + 1;
#ifdef _DEBUG
			memset(value_ptr, 0xCC, map->value_size); // debug; trigger data-breakpoints
#endif
			u64* next_key_ptr = (u64*)(slots + next_slot_index * slot_size);
			if (*next_key_ptr == F_MAP64_EMPTY_KEY) {
				// If the next slot is empty and not required for the chain, this slot is not required for the chain either.
				*key_ptr = F_MAP64_EMPTY_KEY;
				// TODO: We could release the entries before this from the chain duty as well
			}
			else {
				*key_ptr = F_MAP64_DEAD_BUT_REQUIRED_FOR_CHAIN_KEY;
			}

			map->alive_count--;
			return true;
		}

		slot_index = next_slot_index;
	}
}

void f_map64_free_raw(fMap64Raw* map) {
	u32 slot_size = map->value_size + 8;
	if (map->slots) {
		f_mem_free_n(u8, map->slots, slot_size * map->slot_count, map->alc);
	}
	_DEBUG_FILL_GARBAGE(map, sizeof(*map));
}

//SlotArenaRaw* make_slot_arena_contiguous_raw(u32 elem_size, ArenaDesc arena_desc) {
//	SlotArenaRaw _slot_arena = {
//		.first_free = &SLOT_ARENA_FREELIST_END,
//		.is_using_arena = true,
//		.using_arena = make_arena(arena_desc),
//		.elem_size = elem_size,
//	};
//	return f_mem_clone(_slot_arena, &_slot_arena.arena->alc);
//}

//SlotArenaRaw* make_slot_arena_raw(u32 elem_size, u32 num_elems_per_bucket, fAllocator* a) {
//	SlotArenaRaw _slot_arena = {
//		.first_free = &SLOT_ARENA_FREELIST_END,
//		.a = a,
//		.num_elems_per_bucket = num_elems_per_bucket,
//		.elem_size = elem_size,
//	};
//	return f_mem_clone(_slot_arena, a);
//}

/*

void slot_arena_clear_raw(RawSlotArena* arena) {
	arena_clear(arena->arena);
	arena->num_active = 0;
	arena->num_freed = 0;
	arena->first_free = &SLOT_ARENA_FREELIST_END;
}

void* slot_arena_add_garbage_raw(RawSlotArena* arena) {
	//ZoneScoped;
	ASSERT(arena->arena->reserved != 0); // have you called slot_arena_create?
	arena->num_active++;
	
	// should the freelist items point to the actual content or the freelist pointer?
	// I think I should switch it to point to the content, because it's less steps in the iterator.

	if (arena->first_free != &SLOT_ARENA_FREELIST_END) {
		void* ptr = arena->first_free;
		void** next_free = (void**)((u8*)ptr - sizeof(uint));
		arena->first_free = *next_free;
		*next_free = NULL;
		return ptr;
	}
	
	// TODO: 8 byte alignment?
	// For that we'd have to update SLOT_ARENA_EACH
	uint* next_free = (uint*)arena_push_size(arena->arena, sizeof(uint) + arena->elem_size, 1).data;
	*next_free = 0;
	return next_free + 1;
}

bool slot_arena_remove_raw(RawSlotArena* arena, void* ptr) {
	//ZoneScoped;
	BP;//ASSERT(ptr > arena->arena->mem && ptr < arena->arena->mem + arena->arena->pos);

	void** next_free = (void**)((u8*)ptr - sizeof(uint));
	ASSERT(*next_free == NULL); // If this fails, it means you tried to remove an element that was already removed.

	void* first_removed = arena->first_free;
	arena->first_free = ptr;
	*next_free = first_removed;
	arena->num_active--;
	return true;
}

void delete_slot_arena_raw(RawSlotArena* arena) {
	//ZoneScoped;
	delete_arena(arena->arena);
	_DEBUG_FILL_GARBAGE(arena, sizeof(RawSlotArena));
}

u64 slot_arena_get_index_raw(const RawSlotArena* arena, void* ptr) {
	//ZoneScoped;
	//ASSERT(ptr >= arena->arena->mem && ptr < arena->arena->mem + arena->arena->pos);
	//uint offset = (uint)ptr - (uint)arena->arena->mem;
	//return offset / (arena->elem_size + 8);
	BP;
	return 0;
}
*/

u8* f_arena_get_contiguous_base(fArena* arena) {
	F_ASSERT(arena->desc.mode == fArenaMode_UsingBufferFixed || arena->desc.mode == fArenaMode_VirtualReserveFixed);
	return arena->internal_base + sizeof(fArena); }

uint f_arena_get_contiguous_cursor(fArena* arena) {
	F_ASSERT(arena->desc.mode == fArenaMode_UsingBufferFixed || arena->desc.mode == fArenaMode_VirtualReserveFixed);
	return arena->pos.head - (arena->internal_base + sizeof(fArena));
}

fArenaPosition f_arena_get_pos(fArena* arena) { return arena->pos; }

void f_arena_pop_to(fArena* arena, fArenaPosition pos) {
	//ZoneScoped;
#ifdef _DEBUG
	if (arena->desc.mode == fArenaMode_UsingAllocatorGrowing) {
		fArenaBlock* last = arena->pos.current_block;
		for (fArenaBlock* block = pos.current_block->next; block && block != last->next; block = block->next) {
			_DEBUG_FILL_GARBAGE(block + 1, block->size_including_header - sizeof(fArenaBlock));
		}
		F_ASSERT(pos.head >= (u8*)(pos.current_block + 1));
		_DEBUG_FILL_GARBAGE(pos.head, ((u8*)pos.current_block + pos.current_block->size_including_header) - pos.head);
	}
	else {
		F_ASSERT(pos.head <= arena->pos.head);
		_DEBUG_FILL_GARBAGE(pos.head, arena->pos.head - pos.head); // debug; trigger data-breakpoints and garbage-fill the memory
	}
#endif

	// maybe we should also decommit memory. WARNING: if we do this, remember to update delete_arena()!!!
	arena->pos = pos;
}

void f_arena_clear(fArena* arena) {
	//ZoneScoped;
	if (arena->desc.mode == fArenaMode_UsingAllocatorGrowing) {
		f_arena_pop_to(arena, (fArenaPosition) {
			.head = (u8*)(arena->first_block + 1) + sizeof(fArena),
			.current_block = arena->first_block
		});
	} else {
		f_arena_pop_to(arena, (fArenaPosition) { .head = arena->internal_base + sizeof(fArena) });
	}
}

static void* arena_allocator_proc(fAllocator* a, OPT(u8*) old_ptr, uint old_size, uint new_size, uint new_alignment) {
	//ZoneScoped;

	//F_HITS(_c, 0);
	fArena* arena = (fArena*)a;

	//fArenaBlock* headers[2048] = { 0 };
	//uint _i = 0;
	//for (fArenaBlock* h = arena->first_block; h; h = h->next) {
	//	headers[_i] = h;
	//	_i++;
	//}

	if (new_size > old_size) {
		F_ASSERT(new_alignment > 0);
		F_ASSERT(F_IS_POWER_OF_2(new_alignment));

		fString new_allocation = f_arena_push(arena, new_size, new_alignment);

		// TODO: Reuse the end of the arena if possible?
		//if (old_ptr + old_size == arena->internal_base + arena->internal_pos &&
		//	HAS_ALIGNMENT_POW2((uint)old_ptr, new_alignment))
		//{
		//	uint difference = new_size - old_size;
		//	arena_push_size(arena, difference, 1);
		//	
		//	_DEBUG_FILL_GARBAGE(old_ptr + old_size, difference);
		//	return old_ptr;
		//}

		if (old_ptr) {
			memcpy(new_allocation.data, old_ptr, old_size); // first do the copy, then fill old with garbage
			_DEBUG_FILL_GARBAGE(old_ptr, old_size);
			_DEBUG_FILL_GARBAGE(new_allocation.data + old_size, new_size - old_size);
		}

		return new_allocation.data;
	}
	else {
		_DEBUG_FILL_GARBAGE(old_ptr + new_size, old_size - new_size); // erase the top
		int a = 11111;
	}

	return old_ptr;
}

uint round_up_pow_of_2(uint x) {
	// https://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
	x--;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x |= x >> 32;
	return x + 1;
}

void* heap_allocator_proc(fAllocator* a, OPT(u8*) old_ptr, uint old_size, uint new_size, uint new_alignment) {
	// 0b0010110
	//
	//uint arena_index = log2(round_up_pow_of_2(new_size)); // there's probably a better way to calculate this
	// the last arena is for 4k blocks
	F_BP;
	return NULL;
}

//Heap* make_heap(fArenaDesc backing_arena_desc) {
//	Heap _heap = { .alc = { heap_allocator_proc } };
//	_heap.backing_arena = f_arena_make_ex(backing_arena_desc);
//	Heap* heap = (Heap*)arena_push(_heap.backing_arena, AS_BYTES(_heap), 1);
//	return heap;
//}

fArena* f_arena_make(u32 min_block_size, fAllocator* a) {
	return f_arena_make_ex((fArenaDesc) {
		.mode = fArenaMode_UsingAllocatorGrowing,
		.UsingAllocatorGrowing = { .min_block_size = min_block_size, .a = a },
	});
}

fArena* f_arena_make_virtual_reserve_fixed(uint reserve_size, OPT(void*) reserve_base) {
	return f_arena_make_ex((fArenaDesc) {
		.mode = fArenaMode_VirtualReserveFixed,
		.VirtualReserveFixed = { .reserve_size = reserve_size, .reserve_base = reserve_base },
	});
}

fArena* f_arena_make_buffer_fixed(void* base, uint size) {
	return f_arena_make_ex((fArenaDesc) {
		.mode = fArenaMode_UsingBufferFixed,
		.UsingBufferFixed = {.base = base, .size = size },
	});
}

fArena* f_arena_make_ex(fArenaDesc desc) {	
	//HITS(_c, 3);
	fArena _arena = {
		.alc = (fAllocator){ ._proc = arena_allocator_proc },
		.desc = desc,
	};
	
	switch (desc.mode) {
	case fArenaMode_VirtualReserveFixed: {
		_arena.internal_base = f_mem_reserve(desc.VirtualReserveFixed.reserve_size, desc.VirtualReserveFixed.reserve_base);
		if (!_arena.internal_base) error_out_of_memory();
		_arena.pos.head = _arena.internal_base;
		_arena.committed_end = _arena.internal_base;
	} break;
	case fArenaMode_UsingBufferFixed: {
		_arena.internal_base = desc.UsingBufferFixed.base;
		_arena.pos.head = _arena.internal_base;
	} break;
	case fArenaMode_UsingAllocatorGrowing: {} break;
	default: F_BP;
	}

	fArena* arena = (fArena*)f_arena_push(&_arena, sizeof(fArena), 1).data;
	*arena = _arena;
	
	f_leak_tracker_begin_entry(arena, 1);
	return arena;
}

//Arena* make_arena_supplied_contiguous(void* base, uint size) {
//	return make_arena((ArenaDesc) {
//		.mode = ArenaMode_UsingBufferFixed,
//		.SuppliedContiguous = {
//			.base = base,
//			.size = size,
//		},
//	});
//}

//Arena* make_arena_virtual_contiguous(uint reserve_size) {
//	return make_arena_virtual_contiguous_ex(reserve_size, NULL);
//}

//Arena* make_arena_virtual_contiguous_ex(uint reserve_size, void* custom_base) {
//	return make_arena((ArenaDesc) {
//		.mode = ArenaMode_VirtualReserveFixed,
//		.VirtualContiguous = {
//			.reserve_size = reserve_size,
//			.reserve_base = custom_base,
//		},
//	});
//}

void f_arena_free(fArena* arena) {
	//ZoneScoped;
	f_leak_tracker_end_entry(arena);
	f_arena_clear(arena); // this will fill the arena memory with garbage in debug builds
	if (arena->desc.mode == fArenaMode_UsingBufferFixed) {
		_DEBUG_FILL_GARBAGE(arena, sizeof(fArena));
	}
	else if (arena->desc.mode == fArenaMode_VirtualReserveFixed) {
		f_mem_release(arena->internal_base);
	}
	else if (arena->desc.mode == fArenaMode_UsingAllocatorGrowing) {
		fAllocator* a = arena->desc.UsingAllocatorGrowing.a;
		fArenaBlock* block = arena->first_block;
		for (; block;) {
			fArenaBlock* next = block->next;
			f_mem_free(block, block->size_including_header, a);
			block = next;
		}
	}
	else F_BP;
}

s64 f_round_to_s64(float x) {
	//ZoneScoped;
	return f_floor_to_s64(x + 0.5f);
}

s64 f_floor_to_s64(float x) {
	//ZoneScoped;
	F_ASSERT(x > (float)F_I64_MIN && x < (float)F_I64_MAX);

	s64 x_i64 = (s64)x;
	if (x < 0) {
		float fraction = (float)x_i64 - x;
		if (fraction != 0) x_i64 -= 1;
	}
	return x_i64;
}

static const u32 offsetsFromUTF8[6] = {
	0x00000000UL, 0x00003080UL, 0x000E2080UL,
	0x03C82080UL, 0xFA082080UL, 0x82082080UL
};

// Taken and altered from https://www.cprogramming.com/tutorial/utf8.c
uint f_str_encode_rune(u8* output, rune r) {
	//ZoneScoped;
	u32 ch;

	ch = r;
	if (ch < 0x80) {
		*output++ = (char)ch;
		return 1;
	}
	else if (ch < 0x800) {
		*output++ = (ch >> 6) | 0xC0;
		*output++ = (ch & 0x3F) | 0x80;
		return 2;
	}
	else if (ch < 0x10000) {
		*output++ = (ch >> 12) | 0xE0;
		*output++ = ((ch >> 6) & 0x3F) | 0x80;
		*output++ = (ch & 0x3F) | 0x80;
		return 3;
	}
	else if (ch < 0x110000) {
		*output++ = (ch >> 18) | 0xF0;
		*output++ = ((ch >> 12) & 0x3F) | 0x80;
		*output++ = ((ch >> 6) & 0x3F) | 0x80;
		*output++ = (ch & 0x3F) | 0x80;
		return 4;
	}
	F_ASSERT(false);
	return 0;
}

// Taken and altered from https://www.cprogramming.com/tutorial/unicode.html
rune f_str_next_rune(fString str, uint* byteoffset) {
	//ZoneScoped;
	if (*byteoffset >= str.len) return 0;
	F_ASSERT(*byteoffset >= 0);

	u32 ch = 0;
	int sz = 0;

	do {
		ch <<= 6;
		ch += str.data[(*byteoffset)++];
		sz++;
	} while (*byteoffset < str.len && !f_str_is_utf8_first_byte(str.data[*byteoffset]));
	ch -= offsetsFromUTF8[sz - 1];

	return (rune)ch;
}

rune f_str_prev_rune(fString str, uint* byteoffset) {
	//ZoneScoped;
	if (*byteoffset <= 0) return 0;

	(void)(f_str_is_utf8_first_byte(str.data[--(*byteoffset)]) ||
		f_str_is_utf8_first_byte(str.data[--(*byteoffset)]) ||
		f_str_is_utf8_first_byte(str.data[--(*byteoffset)]) || --(*byteoffset));

	uint b = *byteoffset;
	return f_str_next_rune(str, &b);
}

uint f_str_rune_count(fString str) {
	//ZoneScoped;
	uint i = 0;
	for f_str_each(str, r, offset) i++;
	return i;
}


bool f_str_to_u64(fString s, uint base, u64* out_value) {
	F_ASSERT(2 <= base && base <= 16);

	uint value = 0;
	for (uint i = 0; i < s.len; i++) {
		uint c = s.data[i];
		if (c == '_') continue;

		if (c >= 'A' && c <= 'Z') c += 32; // ASCII convert to lowercase

		uint digit;
		if (c >= '0' && c <= '9') {
			digit = c - '0';
		}
		else if (c >= 'a' && c <= 'f') {
			digit = 10 + c - 'a';
		}
		else return false;

		if (digit > base) return false;

		if (f_does_mul_overflow(value, base)) return false;
		value *= base;
		if (f_does_add_overflow(value, digit)) return false;
		value += digit;
	}
	*out_value = value;
	return true;
}

bool f_str_to_s64(fString s, uint base, s64* out_value) {
	F_ASSERT(2 <= base && base <= 16);

	s64 sign = 1;
	if (s.len > 0) {
		if (s.data[0] == '+') f_str_advance(&s, 1);
		else if (s.data[0] == '-') {
			f_str_advance(&s, 1);
			sign = -1;
		}
	}

	s64 val;
	if (!f_str_to_u64(s, base, (u64*)&val) || val < 0) return false;
	*out_value = val * sign;
	return true;
}

char* f_str_to_cstr(fString s, fAllocator* a) {
	char* bytes = f_mem_alloc(s.len + 1, 1, a);
	memcpy(bytes, s.data, s.len);
	bytes[s.len] = 0;
	return bytes;
}

bool f_str_to_f64(fString s, f64* out) {
	//ZoneScoped;
	fAllocator* temp = f_temp_push();
	char* cstr = f_str_to_cstr(s, temp);
	char* end;
	*out = strtod(cstr, &end);
	f_temp_pop();
	return s.len > 0 && end == cstr + s.len;
}

// supports UTF8
fString f_str_replace(fString str, fString search_for, fString replace_with, fAllocator* a) {
	if (search_for.len > str.len) return str;

	Array(u8) result = f_array_make_cap_raw(1, str.len * 2, a);
	uint last = str.len - search_for.len;
	
	for (uint i = 0; i <= last;) {
		if (memcmp(str.data + i, search_for.data, search_for.len) == 0) {
			f_array_push_slice_raw(&result, F_BITCAST(fSliceRaw, replace_with), 1, 1);
			i += search_for.len;
		}
		else {
			f_array_push_raw(&result, &str.data[i], 1, 1);
			i++;
		}
	}
	return F_BITCAST(fString, result);
}

fString f_str_replace_multi(fString str, fSlice(fString) search_for, fSlice(fString) replace_with, fAllocator* a) {
	F_ASSERT(search_for.len == replace_with.len);
	uint n = search_for.len;

	Array(u8) result = f_array_make_cap_raw(1, str.len * 2, a);
	
	for (uint i = 0; i < str.len;) {
		for (uint j = 0; j < n; j++) {
			fString search_for_j = ((fString*)search_for.data)[j];
			if (i + search_for_j.len > str.len) continue;
			
			if (memcmp(str.data + i, search_for_j.data, search_for_j.len) == 0) {
				fString replace_with_j = ((fString*)replace_with.data)[j];
				f_array_push_slice_raw(&result, F_BITCAST(fSliceRaw, replace_with_j), 1, 1);
				i += search_for_j.len;
				goto continue_outer;
			}
		}
		
		f_array_push_raw(&result, &str.data[i], 1, 1);
		i++;
	continue_outer:;
	}
	return F_BITCAST(fString, result);
}

fString f_str_from_cstr(const char* s) { return (fString){(u8*)s, strlen(s)}; }

// Detect which OS we're compiling on
#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
	#define OS_WINDOWS
#else
	#error "Sorry, only windows is supported for now!"
#endif

#ifdef OS_WINDOWS
	#define NOMINMAX
	#include <Windows.h>
	#include <DbgHelp.h>

	#pragma comment(lib, "Comdlg32.lib") // for GetOpenFileName

	void f_os_print(fString str) {
		fAllocator* temp = f_temp_push();

		uint str_utf16_len;
		wchar_t* str_utf16 = f_str_to_utf16(str, 1, temp, &str_utf16_len);
		F_ASSERT((u32)str_utf16_len == str_utf16_len);

		DWORD num_chars_written;
		BOOL ok = WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), str_utf16, (u32)str_utf16_len, &num_chars_written, NULL);
		f_temp_pop();
	}

	// colored write to console
	// WriteConsoleOutputAttribute
	void f_os_print_color(fString str, fConsoleAttributeFlags attributes_mask) {
		if (str.len == 0) return;
		//ASSERT(str.len < U32_MAX);
		fAllocator* temp = f_temp_push();
		HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);

		CONSOLE_SCREEN_BUFFER_INFO console_info;
		if (!GetConsoleScreenBufferInfo(stdout_handle, &console_info)) return;
		
		str = f_str_replace(str, F_LIT("\t"), F_LIT("    "), temp);

		uint str_utf16_len;
		wchar_t* str_utf16 = f_str_to_utf16(str, 1, temp, &str_utf16_len);

		DWORD num_chars_written;
		if (!WriteConsoleW(stdout_handle, str_utf16, F_CAST(u32, str_utf16_len), &num_chars_written, NULL)) return;
		
		WORD* attributes = f_mem_alloc_n(WORD, str.len, temp);
		for (u32 i = 0; i < str.len; i++) {
			attributes[i] = (u16)attributes_mask;
		}

		DWORD num_attributes_written;
		BOOL ok = WriteConsoleOutputAttribute(stdout_handle, attributes, F_CAST(u32, str.len), console_info.dwCursorPosition, &num_attributes_written);
		f_temp_pop();
	}

	u64 f_read_cycle_counter() {
		//ZoneScoped;
		u64 counter = 0;
		BOOL res = QueryPerformanceCounter((LARGE_INTEGER*)&counter);
		F_ASSERT(res == TRUE);
		return counter;
	}

	u64 f_files_get_modtime(fString filepath) {
		//ZoneScoped;
		fAllocator* temp = f_temp_push();

		HANDLE h = CreateFileA(f_str_to_cstr(filepath, temp), 0, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY | FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (h == INVALID_HANDLE_VALUE) return 0;

		FILETIME write_time;
		GetFileTime(h, NULL, NULL, &write_time);

		//LARGE_INTEGER file_size;
		//GetFileSizeEx(h, &file_size);

		CloseHandle(h);
		f_temp_pop();
		return F_BITCAST(u64, write_time);
	}

	bool f_files_clone(fString src_filepath, fString dst_filepath) {
		//ZoneScoped;
		fAllocator* temp = f_temp_push();

		BOOL ok = CopyFileA(f_str_to_cstr(src_filepath, temp), f_str_to_cstr(dst_filepath, temp), 0) == TRUE;
		f_temp_pop();
		return ok;
	}

	bool f_files_delete(fString filepath) {
		fAllocator* temp = f_temp_push();

		bool ok = DeleteFileA(f_str_to_cstr(filepath, temp)) == TRUE;
		f_temp_pop();
		return ok;
	}

	void f_sleep_milliseconds(s64 ms) {
		//ZoneScoped;
		F_ASSERT(ms < F_U32_MAX);
		Sleep((DWORD)ms);
	}

	fDynamicLibrary f_dynamic_library_load(fString filepath) {
		//ZoneScoped;
		fAllocator* temp = f_temp_push();
		HANDLE handle = LoadLibraryA(f_str_to_cstr(filepath, temp));
		f_leak_tracker_begin_entry(handle, 1);
		f_temp_pop();
		return (fDynamicLibrary){ .handle = handle };
	}

	bool f_dynamic_library_unload(fDynamicLibrary dll) {
		//ZoneScoped;
		f_leak_tracker_end_entry(dll.handle);
		return FreeLibrary((HMODULE)dll.handle) == TRUE;
	}

	void* f_dynamic_library_sym_address(fDynamicLibrary dll, fString symbol) {
		//ZoneScoped;
		fAllocator* temp = f_temp_push();
		void* addr = GetProcAddress((HMODULE)dll.handle, f_str_to_cstr(symbol, temp));
		f_temp_pop();
		return addr;
	}

	fString f_files_pick_file_dialog(fAllocator* a) {
		fAllocator* temp = f_temp_push();

		//ZoneScoped;
		fString buffer = f_str_make(4096, temp);
		buffer.data[0] = '\0';

		OPENFILENAMEA ofn = (OPENFILENAMEA){
			.lStructSize = sizeof(OPENFILENAMEA),
			.hwndOwner = NULL,
			.lpstrFile = (char*)buffer.data,
			.nMaxFile = F_CAST(u32, buffer.len) - 1,
			.lpstrFilter = "All\0*.*\0Text\0*.TXT\0",
			.nFilterIndex = 1,
			.lpstrFileTitle = NULL,
			.nMaxFileTitle = 0,
			.lpstrInitialDir = NULL,
			.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR,
		};

		GetOpenFileNameA(&ofn);
		f_temp_pop();
		return f_str_clone(f_str_from_cstr(buffer.data), a);
	}

	
	//fSlice(fString) os_file_picker_multi() {
	//	ZoneScoped;
	//	ASSERT(false); // cancelling does not work!!!!
	//	return {};

		//fSlice(u8) buffer = mem_alloc(16*KB, TEMP_ALLOCATOR);
		//buffer[0] = '\0';
		//
		//OPENFILENAMEA ofn = {};
		//ofn.lStructSize = sizeof(ofn);
		//ofn.hwndOwner = NULL;
		//ofn.lpstrFile = (char*)buffer.data;
		//ofn.nMaxFile = (u32)buffer.len - 1;
		//ofn.lpstrFilter = "All\0*.*\0Text\0*.TXT\0";
		//ofn.nFilterIndex = 1;
		//ofn.lpstrFileTitle = NULL;
		//ofn.nMaxFileTitle = 0;
		//ofn.lpstrInitialDir = NULL;
		//ofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER | OFN_NOCHANGEDIR;
		//GetOpenFileNameA(&ofn);
		//
		//fArray(fString) items = {};
		//items.allocator = TEMP_ALLOCATOR;
		//
		//fString directory = fString{ buffer.data, (isize)strlen((char*)buffer.data) };
		//u8* ptr = buffer.data + directory.len + 1;
		//
		//if (*ptr == NULL) {
		//	if (directory.len == 0) return {};
		//	
		//	array_append(items, directory);
		//	return items.slice;
		//}
		//
		//i64 i = 0;
		//while (*ptr) {
		//	fString filename = fString{ ptr, (isize)strlen((char*)ptr) };
		//
		//	fString fullpath = str_join(slice({ directory, F_LIT("\\"), filename }), TEMP_ALLOCATOR);
		//	assert(fullpath.len < 270);
		//	array_append(items, fullpath);
		//
		//	ptr += filename.len + 1;
		//	i++;
		//	assert(i < 1000);
		//}
		//
		//return items.slice;
	//}

	wchar_t* f_str_to_utf16(fString str, uint num_null_terminations, fAllocator* a, uint* out_len) {
		if (str.len == 0) {
			*out_len = 0;
			return NULL;
		}
		F_ASSERT(str.len < F_I32_MAX);
		
		wchar_t* w_text = NULL;
		
		int w_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char*)str.data, (int)str.len, NULL, 0);
		w_text = f_mem_alloc_n(wchar_t, 2 * (w_len + num_null_terminations), a);
		
		int w_len1 = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, (const char*)str.data, (int)str.len, (wchar_t*)w_text, w_len);
		
		F_ASSERT(w_len != 0 && w_len1 == w_len);
		
		memset(&w_text[w_len], 0, num_null_terminations * sizeof(wchar_t));

		*out_len = w_len;
		return w_text;
	}

	fString f_str_from_utf16(wchar_t* str_utf16, fAllocator* a) {
		if (*str_utf16 == 0) return (fString){0};
		
		int length = WideCharToMultiByte(CP_UTF8, 0, str_utf16, -1, NULL, 0, NULL, NULL);
		if (length <= 0) return (fString) { 0 };

		fString result = f_str_make(length, a); // length includes the null-termination.
		int length2 = WideCharToMultiByte(CP_UTF8, 0, str_utf16, -1, result.data, (int)result.len, NULL, NULL);
		if (length2 <= 0) return (fString) { 0 };
		
		result.len--;
		return result;
	}

	//void os_allocator_proc(fSlice(u8)* allocation, AllocatorMode mode, i64 size, i64 alignment, void* allocator_data, Code_Location loc) {
	//	switch (mode) {
	//	case AllocatorMode_VirtualReserve:
	//		assert(allocation->data == NULL);
	//		allocation->len = size; // we could give more space to this!
	//		allocation->data = (u8*)VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_READWRITE);
	//		return;
	//
	//	case AllocatorMode_VirtualRelease:
	//		return;
	//	case AllocatorMode_Alloc:
	//		return;
	//	case AllocatorMode_Free:
	//		return;
	//	}
	//	assert(false);
	//}

	void f_os_error_popup(fString title, fString message) {
		u8 buf[4096]; // we can't use temp_push/f_temp_pop here, because we might be reporting an error about running over the temporary arena
		fArena* stack_arena = f_arena_make_buffer_fixed(buf, sizeof(buf));
		uint _;
		wchar_t* title_utf16 = f_str_to_utf16(title, 1, &stack_arena->alc, &_);
		wchar_t* message_utf16 = f_str_to_utf16(message, 1, &stack_arena->alc, &_);

		MessageBoxW(0, message_utf16, title_utf16, MB_OK);
		f_arena_free(stack_arena);
	}

	OPT(u8*) f_mem_reserve(u64 size, OPT(void*) address) {
		OPT(u8*) ptr = (u8*)VirtualAlloc(address, size, MEM_RESERVE, PAGE_READWRITE);
		return ptr;
	}
	
	void f_mem_commit(u8* ptr, u64 size) {
		VirtualAlloc(ptr, size, MEM_COMMIT, PAGE_READWRITE);
	}

	void f_mem_decommit(u8* ptr, u64 size) {
		VirtualFree(ptr, size, MEM_DECOMMIT);
	}

	void f_mem_release(u8* ptr) {
		VirtualFree(ptr, 0, MEM_RELEASE);
	}

	bool f_os_set_working_dir(fString dir) {
		fAllocator* temp = f_temp_push();
		uint _;
		BOOL ok = SetCurrentDirectoryW(f_str_to_utf16(dir, 1, temp, &_));
		f_temp_pop();
		return ok;
	}

	fString f_os_get_working_dir(fAllocator* a) {
		wchar_t buf[MAX_PATH];
		buf[0] = 0;
		GetCurrentDirectoryW(MAX_PATH, buf);
		return f_str_from_utf16(buf, a);
	}

	fString f_os_clipboard_get_text(fAllocator* a) {
		fString text = (fString){0};
		if (OpenClipboard(NULL)) {
			HANDLE hData = GetClipboardData(CF_UNICODETEXT);
			
			u8* buffer = (u8*)GlobalLock(hData);
			
			int length = WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)hData, -1, NULL, 0, NULL, NULL);
			if (length > 0) {
				text = f_str_make((uint)length, a);
				WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)hData, -1, (char*)text.data, length, NULL, NULL);
				text.len -= 1;
				F_ASSERT(text.data[text.len] == 0);
			}

			GlobalUnlock(hData);
			CloseClipboard();
		}
		return text;
	}

	void f_os_clipboard_set_text(fString text) {
		//ZoneScoped;
		if (!OpenClipboard(NULL)) return;

		fAllocator* temp = f_temp_push();
		{
			EmptyClipboard();

			//int h = 0;
			//int length = MultiByteToWideChar(CP_UTF8, 0, (const char*)text.data, (int)text.len, NULL, 0);
			//
			//u8* utf16 = MakeSlice(u8, (uint)length * 2 + 2, temp);
			//
			//ASSERT(MultiByteToWideChar(CP_UTF8, 0, (const char*)text.data, (int)text.len, (wchar_t*)utf16.data, length) == length);
			//((u16*)utf16.data)[length] = 0;
			uint utf16_len;
			wchar_t* utf16 = f_str_to_utf16(text, 1, temp, &utf16_len);


			HANDLE clipbuffer = GlobalAlloc(0, utf16_len * 2 + 2);
			u8* buffer = (u8*)GlobalLock(clipbuffer);
			memcpy(buffer, utf16, utf16_len * 2 + 2);
		
			GlobalUnlock(clipbuffer);
			SetClipboardData(CF_UNICODETEXT, clipbuffer);

			CloseClipboard();
		}
		f_temp_pop();
	}

	bool f_files_directory_exists(fString path) {
		fAllocator* temp = f_temp_push();
		
		uint path_utf16_len;
		wchar_t* path_utf16 = f_str_to_utf16(path, 1, temp, &path_utf16_len);
		DWORD dwAttrib = GetFileAttributesW(path_utf16);

		f_temp_pop();
		return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
	}

	bool f_files_path_is_absolute(fString path) {
		return path.len > 2 && path.data[1] == ':';
	}

	fString f_files_path_to_absolute(fString working_dir, fString path, fAllocator* a) {
		fAllocator* temp = f_temp_push();
		
		fString working_dir_before;
		if (working_dir.len > 0) {
			working_dir_before = f_os_get_working_dir(temp);
			f_os_set_working_dir(working_dir);
		}

		uint path_utf16_len;
		wchar_t* path_utf16 = f_str_to_utf16(path, 1, temp, &path_utf16_len);
		
		wchar_t buf[MAX_PATH + 1];
		DWORD length = GetFullPathNameW(path_utf16, MAX_PATH, buf, NULL);
		
		fString result = {0};
		if (length > 0 && length <= MAX_PATH) {
			result = f_str_from_utf16(buf, a);
		}
		
		if (working_dir.len > 0) {
			f_os_set_working_dir(working_dir_before);
		}

		f_temp_pop();
		return result;
	}

	bool f_files_visit_directory(fString path, fVisitDirectoryVisitor visitor, void* visitor_userptr) {
		fAllocator* temp = f_temp_push();

		fString match_str = f_str_make(path.len + 2, temp);
		f_mem_copy(match_str.data, path.data, path.len);
		match_str.data[path.len] = '\\';
		match_str.data[path.len+1] = '*';

		uint match_str_utf16_len;
		wchar_t* match_str_utf16 = f_str_to_utf16(match_str, 1, temp, &match_str_utf16_len);

		WIN32_FIND_DATAW find_info;
		HANDLE handle = FindFirstFileW(match_str_utf16, &find_info);
		if (handle == INVALID_HANDLE_VALUE) return false;

		for (; FindNextFileW(handle, &find_info);) {
			fVisitDirectoryInfo info = {
				.name = f_str_from_utf16(find_info.cFileName, temp),
				.is_directory = find_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY,
			};
			
			if (f_str_equals(info.name, F_LIT(".."))) continue;
			
			fVisitDirectoryResult result = visitor(&info, visitor_userptr);
		}

		bool ok = GetLastError() == ERROR_NO_MORE_FILES;
		FindClose(handle);
		
		f_temp_pop();
		return ok;
	}

	bool f_files_delete_directory(fString path) {
		if (!f_files_directory_exists(path)) return true;

		fAllocator* temp = f_temp_push();
		uint path_utf16_len;

		// NOTE: path must be double null-terminated!
		wchar_t* path_utf16 = f_str_to_utf16(path, 2, temp, &path_utf16_len);
		
		SHFILEOPSTRUCTW file_op = {
			.hwnd = NULL,
			.wFunc = FO_DELETE,
			.pFrom = path_utf16,
			.pTo = NULL,
			.fFlags = FOF_NO_UI,
			.fAnyOperationsAborted = false,
			.hNameMappings = 0,
			.lpszProgressTitle = NULL,
		};

		int result = SHFileOperationW(&file_op);

		f_temp_pop();
		return result == 0;
	}

	bool f_files_make_directory(fString path) {
		fAllocator* temp = f_temp_push();
		
		uint path_utf16_len;
		wchar_t* path_utf16 = f_str_to_utf16(path, 1, temp, &path_utf16_len);

		BOOL ok = CreateDirectoryW(path_utf16, NULL);
		f_temp_pop();
		
		if (ok) return true;

		DWORD err = GetLastError();
		if (err == ERROR_ALREADY_EXISTS) return true;

		return false;
	}

	bool f_files_read_whole(fString filepath, fAllocator* a, fString* out_str) {
		//ZoneScoped;
		fFile file = f_files_open(filepath, fFileOpenMode_Read);
		if (!f_files_exists(file)) return false;

		uint size = f_files_size(file);
		
		fString result = f_str_make(size, a);

		F_ASSERT(f_files_read(file, result.data, size) == size);

		f_files_close(file);
		*out_str = result;
		return true;
	}

	bool f_files_exists(fFile file) { return file._handle != 0; }
	
	fFile f_files_open(fString filepath, fFileOpenMode mode) {
		HANDLE handle;

		fAllocator* temp = f_temp_push();
		uint filepath_utf16_len;
		wchar_t* filepath_utf16 = f_str_to_utf16(filepath, 1, temp, &filepath_utf16_len);

		if (mode == fFileOpenMode_Read) {
			handle = CreateFileW(filepath_utf16, FILE_GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		}
		else {
			u32 creation = mode == fFileOpenMode_Append ? OPEN_ALWAYS : CREATE_ALWAYS;
			handle = CreateFileW(filepath_utf16, FILE_GENERIC_READ|FILE_GENERIC_WRITE, FILE_SHARE_READ, NULL, creation, 0, NULL);
		}

		if (handle == INVALID_HANDLE_VALUE) handle = 0;
		else f_leak_tracker_begin_entry(handle, 1);

		f_temp_pop();
		return (fFile){ handle };
	}

	uint f_files_read(fFile file, void* dst, uint size) {
		if (dst == NULL) return 0;
		if (size <= 0) return 0;

		for (uint read_so_far = 0; read_so_far < size;) {
			uint remaining = size - read_so_far;
			u32 to_read = remaining >= F_U32_MAX ? F_U32_MAX : (u32)remaining;

			DWORD bytes_read;
			BOOL ok = ReadFile(file._handle, (u8*)dst + read_so_far, to_read, &bytes_read, NULL);
			read_so_far += bytes_read;
			
			if (ok != TRUE || bytes_read < to_read) {
				return read_so_far;
			}
		}
		return size;
	}

	uint f_files_size(fFile file) {
		LARGE_INTEGER size;
		if (GetFileSizeEx(file._handle, &size) != TRUE) return -1;
		return size.QuadPart;
	}
	
	bool f_files_write(fFile file, fString data) {
		if (data.len >= F_U32_MAX) return false; // TODO: writing files greater than 4 GB
		
		DWORD bytes_written;
		return WriteFile(file._handle, data.data, (DWORD)data.len, &bytes_written, NULL) == TRUE && bytes_written == data.len;
	}

	uint f_files_get_position(fFile file) {
		LARGE_INTEGER offset;
		if (SetFilePointerEx(file._handle, (LARGE_INTEGER){0}, &offset, FILE_CURRENT) != TRUE) return -1;
		return offset.QuadPart;
	}

	bool f_files_set_position(fFile file, uint position) {
		LARGE_INTEGER offset;
		offset.QuadPart = position;
		return SetFilePointerEx(file._handle, offset, NULL, FILE_BEGIN) == TRUE;
	}

	bool f_files_close(fFile file) {
		bool ok = CloseHandle(file._handle) == TRUE;
		f_leak_tracker_end_entry(file._handle);
		return ok;
	}

	void f_get_stack_trace(void(*visitor)(fString function, fString file, u32 line, void* user_ptr), void* user_ptr) {
		HANDLE process = GetCurrentProcess();
		
		// This is a bit sloppy and technically incorrect...
		static bool has_called_sym_initialize = false;
		if (!has_called_sym_initialize) {
			SymInitialize(process, NULL, true);
		}

		CONTEXT ctx;
		RtlCaptureContext(&ctx);

		STACKFRAME64 stack_frame = (STACKFRAME64){
			.AddrPC.Offset = ctx.Rip,
			.AddrPC.Mode = AddrModeFlat,
			.AddrFrame.Offset = ctx.Rsp,
			.AddrFrame.Mode = AddrModeFlat,
			.AddrStack.Offset = ctx.Rsp,
			.AddrStack.Mode = AddrModeFlat,
		};

		for (uint i = 0; i < 64; i++) {
			if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, GetCurrentThread(), &stack_frame, &ctx,
				NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
				// Maybe it failed, maybe we have finished walking the stack.
				break;
			}

			if (stack_frame.AddrPC.Offset == 0) break;
			if (i == 0) continue; // ignore this function

			struct {
				IMAGEHLP_SYMBOL64 s;
				u8 name_buf[64];
			} sym;
			
			sym.s.SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
			sym.s.MaxNameLength = 64;

			if (SymGetSymFromAddr(process, stack_frame.AddrPC.Offset, NULL, &sym.s) != TRUE) break;

			fString function_name = f_str_from_cstr(sym.s.Name);
			
			IMAGEHLP_LINE64 Line64;
			Line64.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
			DWORD dwDisplacement;
			if (SymGetLineFromAddr64(process, ctx.Rip, &dwDisplacement, &Line64) != TRUE) break;
			
			visitor(function_name, f_str_from_cstr(Line64.FileName), Line64.LineNumber, user_ptr);
			
			if (f_str_equals(function_name, F_LIT("main"))) break; // Don't care about anything beyond main
		}
	}

	bool f_os_run_command(fSliceRaw args, fString working_dir, u32* out_exit_code) {
		bool ok = false;

		fAllocator* temp = f_temp_push();
		fString working_dir_before;
		if (working_dir.len > 0) {
			working_dir_before = f_os_get_working_dir(temp);
			f_os_set_working_dir(working_dir);
		}
		
		// Windows expects a single space-separated string that encodes a list of the passed command-line arguments.
		// In order to support spaces within an argument, we must enclose it with quotation marks (").
		// This escaping method is the absolute dumbest thing that has ever existed.
		// https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments?redirectedfrom=MSDN&view=msvc-170
		// https://stackoverflow.com/questions/1291291/how-to-accept-command-line-args-ending-in-backslash
		// https://daviddeley.com/autohotkey/parameters/parameters.htm#WINCRULESDOC
		
		fString* arg_strings = args.data;
		fArrayRaw cmd_string = f_array_make_raw(temp);

		for (uint i = 0; i < args.len; i++) {
			fString arg = arg_strings[i];
			
			u8 quotation = '\"', backslash = '\\';
			f_array_push_raw(&cmd_string, &quotation, 1, 1);
			
			for (uint j = 0; j < arg.len; j++) {
				if (arg.data[j] == quotation) {
					f_array_push_raw(&cmd_string, &backslash, 1, 1); // escape quotation marks with a backslash
				}
				else if (arg.data[j] == backslash) {
					if (j + 1 == arg.len) {
						// if we have a backslash and it's the last character in the string,
						// we must push \\"
						f_array_push_raw(&cmd_string, &backslash, 1, 1);
						f_array_push_raw(&cmd_string, &backslash, 1, 1);
						break;
					}
					else if (arg.data[j + 1] == quotation) {
						// if we have a backslash and the next character is a quotation mark,
						// we must push \\\"
						f_array_push_raw(&cmd_string, &backslash, 1, 1);
						f_array_push_raw(&cmd_string, &backslash, 1, 1);
						f_array_push_raw(&cmd_string, &backslash, 1, 1);
						f_array_push_raw(&cmd_string, &quotation, 1, 1);
						j++; // also skip the next "
						continue;
					}
				}
				
				f_array_push_raw(&cmd_string, &arg.data[j], 1, 1);
			}
			
			f_array_push_raw(&cmd_string, &quotation, 1, 1);
			
			if (i < args.len - 1) f_array_push_raw(&cmd_string, &(u8){' '}, 1, 1); // Separate each argument with a space
		}

		uint cmd_string_utf16_len;
		wchar_t* cmd_string_utf16 = f_str_to_utf16((fString) { cmd_string.data, cmd_string.len }, 1, temp, &cmd_string_utf16_len);

		PROCESS_INFORMATION process_info = { 0 };

		STARTUPINFOW startup_info = { 0 };
		startup_info.cb = sizeof(STARTUPINFOW);

		HANDLE IN_Rd = NULL;
		HANDLE IN_Wr = NULL;
		HANDLE OUT_Rd = NULL;
		HANDLE OUT_Wr = NULL;

		// Initialize pipes
		SECURITY_ATTRIBUTES security_attrs = {
			.nLength = sizeof(SECURITY_ATTRIBUTES),
			.bInheritHandle = TRUE,
			.lpSecurityDescriptor = NULL,
		};

		if (!CreatePipe(&OUT_Rd, &OUT_Wr, &security_attrs, 0)) goto end;
		if (!SetHandleInformation(OUT_Rd, HANDLE_FLAG_INHERIT, 0)) goto end;
			
		if (!CreatePipe(&IN_Rd, &IN_Wr, &security_attrs, 0)) goto end;
		if (!SetHandleInformation(IN_Rd, HANDLE_FLAG_INHERIT, 0)) goto end;

		// TODO: capture output
		//startup_info.hStdError = OUT_Wr;
		//startup_info.hStdOutput = OUT_Wr;
		//startup_info.hStdInput = IN_Rd;
		//startup_info.dwFlags |= STARTF_USESTDHANDLES;

		//char* cmd_line[] = { "C:\\Program Files\\Notepad++\\notepad++.exe" };
		//wchar_t cmd_line[] = TEXT("C:\\Program Files\\Notepad++\\notepad++.exe");
		//wchar_t* cmd_line = TEXT("libtrans.exe");

		if (!CreateProcessW(NULL,
			cmd_string_utf16, // command line
			NULL,             // process security attributes 
			NULL,             // primary thread security attributes 
			TRUE,             // handles are inherited 
			0,                // creation flags 
			NULL,             // use parent's environment 
			NULL,             // use parent's current directory 
			&startup_info,    // STARTUPINFO pointer 
			&process_info     // receives PROCESS_INFORMATION 
		)) goto end;
		
		// wait for the process to finish
		WaitForSingleObject(process_info.hProcess, INFINITE);
		
		if (!GetExitCodeProcess(process_info.hProcess, (DWORD*)out_exit_code)) goto end;
		
		CloseHandle(process_info.hProcess);
		CloseHandle(process_info.hThread);
		
		// Close the handles to the pipe ends that are in the child processes hands - we don't need them.
		CloseHandle(OUT_Wr);
		CloseHandle(IN_Rd);

		// Close our own handles
		CloseHandle(IN_Wr);
		CloseHandle(OUT_Rd);
		ok = true;
	end:;
		if (working_dir.len > 0) {
			f_os_set_working_dir(working_dir_before);
		}

		f_temp_pop();
		return ok;
	}


#endif // OS_WINDOWS

fString f_str_advance(fString* str, uint len) {
	fString result = f_str_slice_before(*str, len);
	*str = f_str_slice_after(*str, len);
	return result;
}

bool f_files_write_whole(fString filepath, fString data) {
	//ZoneScoped;

	fFile file = f_files_open(filepath, fFileOpenMode_Write);
	if (!f_files_exists(file)) return false;
	if (!f_files_write(file, data)) return false;

	f_files_close(file);
	return true;
}

void f_temp_init() {
	F_ASSERT(_f_temp_arena_keep_alive == false); // temp_init can only be called once!
	_f_temp_arena_keep_alive = true;
}

void f_temp_deinit() {
	F_ASSERT(_f_temp_arena_scope_counter == 0);
	F_ASSERT(_f_temp_arena_keep_alive);
	
	_f_temp_arena_keep_alive = false;
	if (_f_temp_arena) {
		f_arena_free(_f_temp_arena);
		_f_temp_arena = NULL;
	}
}

fAllocator* f_temp_push() {
	if (_f_temp_arena == NULL) {
		F_ASSERT(_f_temp_arena_scope_counter == 0);
		// Allocate temp arena at a deterministic memory address
		_f_temp_arena = f_arena_make_virtual_reserve_fixed(F_GIB(1), (void*)F_TIB(2));
	}
	
	_f_temp_arena_scope_counter += 1;
	return &_f_temp_arena->alc;
}

void f_temp_pop() {
	//ASSERT(_temp_arena_scope_counter == temp.scope_counter);
	_f_temp_arena_scope_counter -= 1;
	if (_f_temp_arena_scope_counter == 0) {
		if (_f_temp_arena_keep_alive) {
			f_arena_clear(_f_temp_arena);
		}
		else {
			f_arena_free(_f_temp_arena);
			_f_temp_arena = NULL;
		}
	}
}

rune f_str_rune_to_lower(rune r) { // TODO: utf8
	return r >= 'A' && r <= 'Z' ? r + 32 : r;
}

fString f_str_to_lower(fString str, fAllocator* a) {
	fString out = f_str_clone(str, a);
	for (uint i = 0; i < out.len; i++) {
		out.data[i] = f_str_rune_to_lower(out.data[i]);
	}
	return out;
}
