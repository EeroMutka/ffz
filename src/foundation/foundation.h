﻿
// 
// The foundation is a minimal set of functions and utilities
// that I've found come in handy everywhere, and which the C/C++
// language doesn't provide you in a good way.
// 
// WARNING: THIS IS ALL CURRENTLY A WORK-IN-PROGRESS CODEBASE!! Some things aren't complete or fully tested,
// such as UTF8 support and some things might be implemented in a dumb way.

// Build options:
//  F_DEF_DEBUG - enable various debugging helpers, i.e. allocations are filled to 0xCC
//  F_DEF_MINIMAL_INCLUDE - include only essential type definitions, such as fArray, fString and fMap64
//  F_DEF_INCLUDE_OS - include OS procedures
//  F_DEF_TRAP_TITLE
//  F_DEF_TRAP_MESSAGE

#ifndef _FOUNDATION_H
#define _FOUNDATION_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct fSliceRaw {
	void* data;
	size_t len;
} fSliceRaw;


// TODO: we should make fArena into an interface that can be overridden with static defines

typedef struct fArena fArena;

typedef struct fArrayRaw {
	union {
		struct {
			void* data;
			size_t len;
		};
		fSliceRaw slice;
	};
	size_t capacity;
	fArena* arena;
} fArrayRaw;

// A writer is a simple interface to simply write bytes to some buffer.
// If you're writing a library that needs to build some buffer / write some bytes and you use a Writer, the user of the library
// can intercept that and say "write to a file instead" or "print to stdout instead" or "write to this arena".
typedef struct fWriter {
	void(*proc)(struct fWriter* writer, const void* data, size_t size);
	void* userdata;
} fWriter;

//typedef struct fFormatter {
//	void(*printer)(fFormatter* formatter, fWriter* w);
//	void* userdata;
//} fFormatter;

typedef struct fBufferedWriter {
	fWriter writer;
	void* buffer;
	uint32_t buffer_size;
	uint32_t current_pos;
} fBufferedWriter;

typedef struct fMap64Raw {
	fArena* arena;
	uint32_t value_size; // ...should we even have this?

	uint32_t alive_count;

	uint32_t slot_count;
	/*opt*/ void* slots;
} fMap64Raw;

#ifndef fArray
#define fArray(T) fArrayRaw
#endif

#ifndef fSlice
#define fSlice(T) fSliceRaw
#endif

#ifndef fMap64
#define fMap64(T) fMap64Raw
#endif

#ifndef fString
typedef struct {
	uint8_t* data;
	size_t len;
} fString;
#define fString fString
#endif

typedef struct fStringBuilder {
	fWriter* w;
	fWriter writer;
	union {
		fArray(uint8_t) buffer;
		fString str;
	};
} fStringBuilder;

// Used to mark nullable pointers
#define fOpt(ptr) ptr

#ifndef F_DEF_MINIMAL_INCLUDE

// Common type aliases. These are the only things without the 'f' prefix
typedef uint8_t   u8;
typedef int8_t    s8;
typedef uint16_t  u16;
typedef int16_t   s16;
typedef uint32_t  u32;
typedef int32_t   s32;
typedef uint64_t  u64;
typedef int64_t   s64;
typedef float     f32;
typedef double    f64;
typedef size_t    uint;
typedef intptr_t  sint;
typedef s32       rune;
typedef uint      uint_pow2; // must be a positive power-of-2. (zero is not allowed)

// https://www.wambold.com/Martin/writings/alignof.html
#ifdef __cplusplus
template<typename T> struct alignment_trick { char c; T member; };
#define F_ALIGN_OF(type) F_OFFSET_OF(alignment_trick<type>, member)
#else
#define F_ALIGN_OF(type) (F_OFFSET_OF(struct F_CONCAT(_dummy, __COUNTER__) { char c; type member; }, member))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define F_THREAD_LOCAL __declspec(thread)

#ifdef __cplusplus
#define F_STRUCT_INIT(T) T
#define F_STRUCT_INIT_COMP(T) T
#else
#define F_STRUCT_INIT(T) (T)
#define F_STRUCT_INIT_COMP(T)
#endif

#define F_LIT(x) F_STRUCT_INIT(fString){ (u8*)x, sizeof(x)-1 }
#define F_LIT_COMP(x) F_STRUCT_INIT_COMP(fString){ (u8*)x, sizeof(x)-1 }

// If you want to pass an fString into printf, you can do:  printf("%.*s", F_STRF(my_string))
//#define F_STRF(s) (u32)s.len, s.data

#define F_LEN(x) (sizeof(x) / sizeof(x[0]))
#define F_OFFSET_OF(T, f) ((uint)&((T*)0)->f)

#define F_I8_MIN   (-127i8 - 1)
#define F_I16_MIN  (-32767i16 - 1)
#define F_I32_MIN  (-2147483647i32 - 1)
#define F_I64_MIN  (-9223372036854775807i64 - 1)
#define F_I8_MAX   127i8
#define F_I16_MAX  32767i16
#define F_I32_MAX  2147483647i32
#define F_I64_MAX  9223372036854775807i64
#define F_U8_MAX   0xffui8
#define F_U16_MAX  0xffffui16
#define F_U32_MAX  0xffffffffui32
#define F_U64_MAX  0xffffffffffffffffui64


#define F_PAD(x) char _pad_##__COUNTER__[x]
#define F_STRINGIFY(s) #s

#define F_CONCAT___(x, y) x ## y
#define F_CONCAT(x, y) F_CONCAT___(x, y)

#define F_STATIC_ASSERT(x) enum { F_CONCAT(_static_assert_, __LINE__) = 1 / ((int)!!(x)) }

// Useful for surpressing compiler warnings
// https://stackoverflow.com/questions/12198449/cross-platform-macro-for-silencing-unused-variables-warning/12199209#12199209
#define F_UNUSED(x) (void)(x)

bool f_os_is_debugger_present();
void f_os_error_popup(fString title, fString message);
void f_os_exit_program(u32 exit_code);

#ifndef F_DEF_TRAP_TITLE
#define F_DEF_TRAP_TITLE "Debug-trap!"
#endif
#ifndef F_DEF_TRAP_MESSAGE
#define F_DEF_TRAP_MESSAGE "The program reached an invalid state."
#endif

#define f_trap() do { \
	if (f_os_is_debugger_present()) { __debugbreak(); } \
	else { f_os_error_popup(F_LIT(F_DEF_TRAP_TITLE), F_LIT(F_DEF_TRAP_MESSAGE)); f_os_exit_program(1); } \
} while(0)

#define f_assert(x) { if (!(x)) f_trap(); }

// Breakpoint that executes only when ran inside the debugger
#define f_bp() do { if (f_os_is_debugger_present()) __debugbreak(); } while(0)


// Cast with range checking
//#define F_CAST(T, x) ((T)(x) == (x) ? (T)(x) : (f_trap(), (T)0))
#define F_CAST(T, x) (T)x

// Debugging helper that counts the number of hits and allows for breaking at a certain index
#define F_HITS(name, break_if_equals) \
static uint F_CONCAT(name, _c) = 1; \
F_CONCAT(name, _c)++; \
uint name = F_CONCAT(name, _c); \
if (name == (break_if_equals)) { __debugbreak(); }

// https://stackoverflow.com/questions/6235847/how-to-generate-nan-infinity-and-infinity-in-ansi-c
inline f32 _get_f32_pos_infinity() { u32 x = 0x7F800000; return *(f32*)&x; }
inline f32 _get_f32_neg_infinity() { u32 x = 0xFF800000; return *(f32*)&x; }
#define F_F32_MAX _get_f32_pos_infinity()
#define F_F32_MIN _get_f32_neg_infinity()

#define F_KIB(x) ((uint)(x) << 10)
#define F_MIB(x) ((uint)(x) << 20)
#define F_GIB(x) ((uint)(x) << 30)
#define F_TIB(x) ((u64)(x) << 40)

#define F_MIN(a, b) ((a) < (b) ? (a) : (b))
#define F_MAX(a, b) ((a) > (b) ? (a) : (b))
#define F_CLAMP(x, minimum, maximum) ((x) < (minimum) ? (minimum) : (x) > (maximum) ? (maximum) : (x))

// e.g. 0b0010101000
// =>   0b0010100000
#define F_FLIP_RIGHTMOST_ONE_BIT(x) ((x) & ((x) - 1))

// e.g. 0b0010101111
// =>   0b0010111111
#define F_FLIP_RIGHTMOST_ZERO_BIT(x) ((x) | ((x) + 1))

// e.g. 0b0010101000
// =>   0b0010101111
#define F_FLIP_RIGHMOST_ZEROES(x) (((x) - 1) | (x))

// When x is a power of 2, it must only contain a single 1-bit
// x == 0 will output 1.
#define F_IS_POWER_OF_2(x) (F_FLIP_RIGHTMOST_ONE_BIT(x) == 0)

// `p` must be a power of 2.
// `x` is allowed to be negative as well.
#define F_ALIGN_UP_POW2(x, p) (((x) + (p) - 1) & ~((p) - 1)) // e.g. (x=30, p=16) -> 32
#define F_ALIGN_DOWN_POW2(x, p) ((x) & ~((p) - 1)) // e.g. (x=30, p=16) -> 16

#define F_HAS_ALIGNMENT_POW2(x, p) ((x) % (p) == 0) // p must be a power of 2

#define F_LERP(a, b, alpha) ((alpha)*(b) + (1.f - (alpha))*(a))

#define F_PEEK(x) (x)[(x).len - 1]

#define F_AS_BYTES(x) F_STRUCT_INIT(fString){ (u8*)&x, sizeof(x) }
#define F_SLICE_AS_BYTES(x) F_STRUCT_INIT(fString){ (u8*)(x).data, (x).len * sizeof((x).data[0]) }

// https://graphitemaster.github.io/aau/#unsigned-multiplication-can-overflow
inline bool f_does_mul_overflow(uint x, uint y) { return y && x > ((uint)-1) / y; }
inline bool f_does_add_overflow(uint x, uint y) { return x + y < x; }
inline bool f_does_sub_underflow(uint x, uint y) { return x - y > x; }

typedef enum fArenaMode {
	fArenaMode_VirtualReserveFixed,
	//ArenaMode_VirtualGrowing, // do we really need this since we have UsingAllocatorGrowing?
	fArenaMode_UsingBufferFixed,
	//fArenaMode_UsingAllocatorGrowing,
} fArenaMode;

typedef struct fArenaDesc {
	fArenaMode mode;
	struct {
		fOpt(u8*) reserve_base;
		uint reserve_size;
	} VirtualReserveFixed;
	struct {
		u8* base;
		uint size;
	} UsingBufferFixed;
	//struct {
	//	u32 min_block_size;
	//	fArena a;
	//} UsingAllocatorGrowing;
} fArenaDesc;

typedef struct fArenaBlock {
	uint size_including_header;
	struct fArenaBlock* next;
	// the block memory comes right after the header
} fArenaBlock;

typedef struct fArenaMark {
	u8* head;
	fArenaBlock* current_block; // used only with ArenaMode_UsingAllocatorGrowing
} fArenaMark;

// hmm. I believe I could personally make a large program without ever manually freeing an array;
// it's tempting to say "manual free is not even allowed!"
// I think all my problems can be solved with either heap scopes or heap arenas.

// but we do need allocation-groups, where individual allocations are fully freed and reused with doubly-linked list.
// And at the leaves, allocator-backed bucket arenas.
// We need a name for both of these:
// 1. control allocation group / heap scope / heap control group.
// 2. leaf allocation group    / heap arena
// The difference is that with a heap arena, it's not possible to free/realloc children, but with heap scope it is
// heap scope is heap -> child heap, while heap arena is heap -> child arena

typedef struct fArena {
	fArenaDesc desc;

	struct { // should be union
		u8* internal_base;
		fArenaBlock* first_block; // used only with ArenaMode_UsingAllocatorGrowing
	};

	u8* committed_end; // only used with ArenaMode_VirtualReserveFixed

	fArenaMark pos;
} fArena;

#define f_make_slice_one(elem, arena) {MemClone((elem), (arena)), 1}

inline u8 f_get_alignment(uint size) {
	const static u8 small_aligns[] = { 1, 1, 2, 4, 4, 8, 8, 8, 8 };
	if (size <= 8) return small_aligns[size];
	return 16;
}

// Warning: these return uninitialized memory.
//#define f_mem_resize(ptr, old_size, new_size, arena) (void*)(arena)->_proc((arena), (ptr), (old_size), (new_size))
//#define f_mem_free(ptr, size, arena) (arena)->_proc((arena), (ptr), (size), 0)

#define f_mem_alloc(size, arena) f_alloc_undef(arena, size)
#define f_mem_alloc_n(T, count, arena) (T*)f_alloc_undef(arena, ((uint)count) * sizeof(T))
#define f_mem_clone(value, arena) f_mem_clone_size(sizeof(value), &value, arena)

#define f_mem_resize_n(T, ptr, old_count, new_count, arena) (T*)f_realloc_undef(arena, ptr, (old_count) * sizeof(T), (new_count) * sizeof(T), F_ALIGN_OF(T))
//#define f_mem_free_n(T, ptr, count, arena) (arena)->_proc((arena), (ptr), (count) * sizeof(T), 0)

#ifdef F_DEF_DEBUG
#define f_debug_fill_garbage(ptr, len) memset(ptr, 0xCC, len);
#else
#define f_debug_fill_garbage(ptr, len)
#endif


inline bool _f_array_each_condition(void* array, uint* i, void* elem, uint elem_size) {
	fSliceRaw slice = *(fSliceRaw*)array;
	if (*i < slice.len) {
		memcpy(elem, (u8*)slice.data + (*i) * elem_size, elem_size);
		return true;
	}
	return false;
}

inline bool _f_array_each_ptr_condition(void* array, uint* i, void** elem, uint elem_size) {
	fSliceRaw slice = *(fSliceRaw*)array;
	if (*i < slice.len) {
		*elem = (u8*)slice.data + (*i) * elem_size;
		return true;
	}
	return false;
}

/*
 Magical array iteration macro - works both on fArray and fSlice types.
 e.g.
    fArray(float) foo;
    f_for_array(float, foo, it) {
       printf("foo at index %d has the value of %f\n", it.i, it.elem);
    }
*/
#define f_for_array(T, array, it_name) \
	struct F_CONCAT(f_, __LINE__) {uint i; T elem;}; \
	for (struct F_CONCAT(f_, __LINE__) it_name = {0}; _f_array_each_condition(&(array), &it_name.i, &it_name.elem, sizeof(T)); it_name.i++)

//#define f_for_array_ptr(T, array, it_name) (struct f_##__LINE__{uint i; T* elem;} it_name = {0}; \
//	_f_array_each_ptr_condition(&(array), &it_name.i, &it_name.elem, sizeof(T)); it_name.i++)


#define F_MAP64_EMPTY_KEY (0xFFFFFFFFFFFFFFFF)
#define F_MAP64_DEAD_BUT_REQUIRED_FOR_CHAIN_KEY (0xFFFFFFFFFFFFFFFE)
#define F_MAP64_LAST_VALID_KEY (0xFFFFFFFFFFFFFFFD)

inline bool _f_for_map64_condition(void* _map, uint* i, u64* key, void* elem) {
	fMap64Raw* map = (fMap64Raw*)_map;
	if (!map->slots) return false;

	u32 slot_size = map->value_size + 8;
	for (;;) {
		if (*i >= map->slot_count) return false;

		u64* key_ptr = (u64*)((u8*)map->slots + (*i) * slot_size);

		if (*key_ptr <= F_MAP64_LAST_VALID_KEY) {
			*key = *key_ptr;
			memcpy(elem, key_ptr + 1, map->value_size);
			return true;
		}
		(*i)++;
	}
}

#define f_for_map64(T, map, it_name) \
	struct F_CONCAT(f_, __LINE__) {uint i; u64 key; T elem;}; \
	for (struct F_CONCAT(f_, __LINE__) it_name = {0}; _f_for_map64_condition(&(map), &it_name.i, &it_name.key, &it_name.elem); it_name.i++)


// c helper macros
#ifndef __cplusplus
#define f_array_push(array, elem) f_array_push_raw((array), &(elem), sizeof(elem))

// 
// f_array_get/f_array_get_ptr/f_array_set work on fArrays as well as fSlices
#define f_array_get(T, array_or_slice, i) ((T*)array_or_slice.data)[i]
#define f_array_get_ptr(T, array_or_slice, i) (&((T*)array_or_slice.data)[i])
#define f_array_set(T, array_or_slice, i, value) ((T*)array_or_slice.data)[i] = value

#define f_map64_insert(map, key, value, mode) f_map64_insert_raw((map), (key), &(value), (mode))

#define f_make_slice_undef(T, len, alc) (fSliceRaw){f_mem_alloc_n(T, len, alc), len}
#define f_make_slice(T, len, initial_elem_value, alc) f_make_slice_raw(len, &initial_elem_value, alc, sizeof(T))

#define f_to_slice(ptr, len) (fSliceRaw){ptr, len}
#define f_clone_to_slice(ptr, len, alc) f_clone_slice_raw(f_to_slice(ptr, len), alc, sizeof(*ptr))
#define f_clone_slice(T, slice, alc) f_clone_slice_raw(slice, alc, sizeof(T))

#define f_slice_lit(T, ...) (fSliceRaw){(T[]){__VA_ARGS__}, sizeof((T[]){__VA_ARGS__}) / sizeof((T[]){__VA_ARGS__}[0])}
#endif

typedef struct fTick { s64 nsec; } fTick;

//#define NANOSECOND 1
//#define MICROSECOND 1000 // 1000 * NANOSECOND
//#define MILLISECOND 1000000 // 1000 * MICROSECOND
//#define SECOND 1000000000 // 1000 * MILLISECOND
//#define MINUTE 60000000000 // 60 * SECOND
//#define HOUR 3600000000000 // 60 * MINUTE

typedef struct fDynamicLibrary { void* handle; } fDynamicLibrary;

typedef enum fFileOpenMode {
	fFileOpenMode_Read,
	fFileOpenMode_Write,
	fFileOpenMode_Append,
} fFileOpenMode;

#ifndef F_FILE_WRITER_BUFFER_SIZE
#define F_FILE_WRITER_BUFFER_SIZE 4096
#endif

typedef struct fFile {
	fFileOpenMode mode;
	void* os_handle;

	fWriter backing_writer;
	fBufferedWriter buffered_writer;
	uint8_t buffer[F_FILE_WRITER_BUFFER_SIZE];
} fFile;

typedef struct fLeakTrackerCallstackEntry {
	fString file;
	u32 line;
} fLeakTrackerCallstackEntry;

typedef struct fLeakTracker_Entry {
	fArray(fLeakTrackerCallstackEntry) callstack;

	/*u64 allocation_idx;

	i64 size;
	i64 alignment;
	// this could be a BucketArray
	fArray(CallstackEntry) callstack;
	*/
} fLeakTracker_Entry;

typedef struct fLeakTracker {
	// Note: LeakTracker never frees any of its internals until deinit_leak_tracker() is called
	bool active;
	fArena* internal_arena;

	fMap64(fLeakTracker_Entry) active_allocations; // key is the address of the allocation

	/*fArena* arena; // Must be the first field for outwards-casting!

	fArena passthrough_allocator;
	Arena internal_arena;

	u64 next_allocation_idx;

	fArray(LeakTracker_BadFree) bad_free_array;
	*/
	// This is here so that we won't have to create a dozen of duplicate strings
	fMap64(fString) file_names_cache; // key is the string hashed
} fLeakTracker;

// Relies on PDB symbol info
//void f_get_stack_trace(void(*visitor)(fString function, fString file, u32 line, void* user_ptr), void* user_ptr);

//
// Leak tracker can be used to track anything that can be keyed using a 64-bit identifier.
// For example, this can be an address for a memory allocation, or an OS handle.
// All of the OS and memory allocation related functions inside the foundation call to
// leak_tracker_begin_entry and leak_tracker_end_entry whenever they're dealing with state
// that needs to be manually released. As a consequence, if you for example call OS_FileOpen()
// but forget to call OS_FileClose() at the end, the leak tracker will report that as a leak
// and will give you the callstack of where the leak was created.
// 
// If you want to detect the leaks, just call init_leak_tracker() in your application entry point
// and deinit_leak_tracker() when your application has finished running. deinit_leak_tracker()
// will assert on any leaks and print information about them.
//
//void f_leak_tracker_init();
//void f_leak_tracker_deinit();

// These functions are ignored if leak tracker is not present
//void f_leak_tracker_begin_entry(void* address, uint skip_stackframes_count);
//void f_leak_tracker_assert_is_alive(void* address);
//void f_leak_tracker_end_entry(void* address);

/*
typedef struct {
	u32 elem_size;

	u32 num_elems_per_bucket;
	fArena a;
	//bool is_using_arena;
	//union {
	//	struct {
	//	} using_alc;
	//	Arena* using_arena;
	//};

	uint num_active;
	uint num_freed;

	void* first_free;
} SlotArenaRaw;
*/

//#define SLOT_ARENA_EACH(ar, T, ptr) (T* ptr = (T*)((ar).arena.mem + 8); \
//	SlotArenaIteratorCondition((RawSlotArena*)&(ar), (void**)&ptr); ptr = (T*)((u8*)ptr + 8 + (ar).elem_size))
//
//inline bool SlotArenaIteratorCondition(const RawSlotArena* arena, void** ptr) {
//	// `ptr` is a pointer on the element itself.
//	for (; *ptr < arena->arena->internal_base + arena->arena->internal_pos;) {
//		if (*((void**)*ptr - 1) == 0) return true;
//
//		// Element is destroyed; it has a freelist pointer other than null.
//		// Skip to the next element.
//		*ptr = (u8*)*ptr + arena->elem_size + 8;
//	}
//	return false;
//}

// These can be combined as a mask
typedef enum fConsoleAttribute {
	fConsoleAttribute_Blue = 0x0001,
	fConsoleAttribute_Green = 0x0002,
	fConsoleAttribute_Red = 0x0004,
	fConsoleAttribute_Intensify = 0x0008,
} fConsoleAttribute;
typedef int fConsoleAttributeFlags;

// TODO: get rid of this enum and make it into proc variants
typedef enum fMapInsert {
	fMapInsert_AssertUnique,
	fMapInsert_DoNotOverride,
	fMapInsert_Override,
} fMapInsert;

// Temporary allocation scope
typedef struct fTempScope {
	fArena* arena;
} fTempScope;

typedef struct fMapInsertResult { void* _unstable_ptr; bool added; } fMapInsertResult; // todo: get rid of this?

typedef struct fVisitDirectoryInfo {
	fString name;
	bool is_directory;
} fVisitDirectoryInfo;

typedef enum fVisitDirectoryResult {
	// TODO: OS_VisitDirectoryResult_Recurse,
	fVisitDirectoryResult_Continue,
} fVisitDirectoryResult;

typedef fVisitDirectoryResult(*fVisitDirectoryVisitor)(const fVisitDirectoryInfo* info, void* userptr);

typedef struct fRangeUint { uint lo, hi; } fRangeUint;

F_THREAD_LOCAL extern fArena* _f_temp_arena_;
//F_THREAD_LOCAL extern fLeakTracker _f_leak_tracker;

void f_init();
void f_deinit();

//fArena f_arena_make(u32 min_block_size, fArena a);

// fArena* f_arena_make_heap_group(fArena* parent)
// fArena* f_arena_make_heap_backed(fArena* parent)
// void f_heap_scope_free(fHeap* heap, fArena* arena)
fArena* f_arena_make_virtual_reserve_fixed(uint reserve_size, fOpt(void*) reserve_base);
fArena* f_arena_make_buffer_fixed(void* base, uint size);
fArena* f_arena_make_ex(fArenaDesc desc);
void f_arena_free(fArena* arena);

/*
 Arenas can be used in two ways:
 1. As a way to give a lifetime to a group of allocations.
 2. To build a contiguous string.
 But not all arenas have the requirement to be contiguous. The following operations work only on linear arenas.
 hmm, maybe we should have a special thing like fLinearArena
*/
u8* f_linear_arena_get_base(fArena* arena);
uint f_linear_arena_get_cursor(fArena* arena);
void* f_linear_arena_push_undef(fArena* arena, uint size, uint align);
void f_linear_arena_push_str(fArena* arena, fString str, uint align);

void* f_alloc_zero(fArena* arena, uint size, uint align);
void* f_alloc_undef_ex(fArena* arena, uint size, uint align);
inline void* f_alloc_undef(fArena* arena, uint size) { return f_alloc_undef_ex(arena, size, f_get_alignment(size)); }

// NOTE: these are mainly for allocation groups, to forward the realloc/free to the backing allocation.
// With ordinary arenas, f_realloc_undef does not free the original allocation.
// 
//void* f_hint_realloc_undef(fArena* arena, void* ptr, uint old_size, uint new_size, uint align);
//inline void* f_hint_free(fArena* arena, void* ptr, uint old_size) {}

inline void* f_mem_clone_size(uint size, const void* value, fArena* arena) {
	void* ptr = f_alloc_undef(arena, size);
	memcpy(ptr, value, size);
	return ptr;
}

inline fSliceRaw f_clone_slice_raw(fSliceRaw slice, fArena* arena, uint elem_size) {
	fSliceRaw result = { f_mem_alloc(slice.len * elem_size, arena), slice.len };
	memcpy(result.data, slice.data, slice.len * elem_size);
	return result;
}

inline fSliceRaw f_make_slice_raw(uint len, const void* initial_elem_value, fArena* arena, uint elem_size) {
	fSliceRaw result = { f_mem_alloc(len * elem_size, arena), len };
	for (uint i = 0; i < len; i++) {
		memcpy((u8*)result.data + i * elem_size, initial_elem_value, elem_size);
	}
	return result;
}

inline fArenaMark f_arena_get_mark(fArena* arena) { return arena->pos; }
void f_arena_set_mark(fArena* arena, fArenaMark mark);
// TODO: void arena_shrink_memory(uint base_size) // the memory will not be reduced past base_size
void f_arena_clear(fArena* arena);

inline fTempScope f_temp_push() { fTempScope x = { _f_temp_arena_}; return x; }
inline void f_temp_pop(fTempScope scope) {}
// inline void f_temp_pop_force(fTempScope scope) {}  // when you're sure that nothing was leaked to the outside

uint_pow2 f_round_up_power_of_2(uint v); // todo: move this into the macros section as an inline function?


// WARNING: The largest 2 key values (see HASHMAP64_LAST_VALID_KEY)
// are reserved internally for marking empty/destroyed slots by the hashmap, so you cannot use them as valid keys.
// An assertion will fail if you try to insert a value with a reserved key.
// This is done for performance, but maybe we should have an option to default to a safe implementation.

// I think we should provide serialization and deserialization functions for map.

fMap64Raw f_map64_make_raw(u32 value_size, fArena* arena);
fMap64Raw f_make_map64_cap_raw(u32 value_size, u32 capacity_pow2, fArena* arena);
//void f_map64_free_raw(fMap64Raw* map);
void f_map64_resize_raw_(fMap64Raw* map, u32 slot_count_pow2);
fMapInsertResult f_map64_insert_raw(fMap64Raw* map, u64 key, fOpt(const void*) value, fMapInsert mode);
bool f_map64_remove_raw(fMap64Raw* map, u64 key);
fOpt(void*) f_map64_get_raw(fMap64Raw* map, u64 key);

void f_mem_copy(void* dst, const void* src, uint size); // TODO: make this an inline call?

fArrayRaw f_array_make(fArena* arena);
fArrayRaw f_array_make_len_raw(u32 elem_size, uint len, const void* initial_value, fArena* arena);
fArrayRaw f_array_make_len_garbage_raw(u32 elem_size, uint len, fArena* arena);
fArrayRaw f_array_make_cap_raw(u32 elem_size, uint capacity, fArena* arena);
size_t f_array_push_raw(fArrayRaw* array, const void* elem, u32 elem_size);
size_t f_array_push_n_raw(fArrayRaw* array, const void* elems, size_t n, u32 elem_size);
void f_array_pop_raw(fArrayRaw* array, fOpt(void*) out_elem, u32 elem_size);
void f_array_reserve_raw(fArrayRaw* array, uint capacity, u32 elem_size);
void f_array_resize_raw(fArrayRaw* array, uint len, fOpt(const void*) value, u32 elem_size); // set value to NULL to not initialize the memory
//void f_array_free_raw(fArrayRaw* array, u32 elem_size);
//SliceRaw array_get_slice_raw(ArrayRaw* array);

//SlotArenaRaw* make_slot_arena_contiguous_raw(u32 elem_size, ArenaDesc arena_desc);
//SlotArenaRaw* make_slot_arena_raw(ArenaDesc arena_desc);
//void* slot_arena_add_garbage_raw(SlotArenaRaw* arena);
//void slot_arena_clear_raw(SlotArenaRaw* arena);
//bool slot_arena_remove_raw(SlotArenaRaw* arena, void* ptr);
//void delete_slot_arena_raw(SlotArenaRaw* arena);
//uint slot_arena_get_index_raw(const SlotArenaRaw* arena, void* ptr);

fOpt(u8*) f_mem_reserve(u64 size, fOpt(void*) address);
void f_mem_commit(u8* ptr, u64 size);
void f_mem_decommit(u8* ptr, u64 size);
void f_mem_release(u8* ptr);

s64 f_round_to_s64(float x);
s64 f_floor_to_s64(float x);

// -- Hash --------------------------------------------------------------------

// Interesting resources related to hashing:
// https://papa.bretmulvey.com/post/124027987928/hash-functions
// https://nullprogram.com/blog/2018/07/31/
// https://www.reddit.com/r/RNG/comments/jqnq20/the_wang_and_jenkins_integer_hash_functions_just/
// https://marc-b-reynolds.github.io/math/2019/08/10/Avalanche.html
// https://github.com/jonmaiga/mx3/blob/master/mx3.h
inline uint64_t f_mix64(uint64_t x) {
	// https://github.com/jonmaiga/mx3/blob/master/mx3.h
	static const uint64_t C = 0xbea225f9eb34556d;
	x ^= x >> 32;
	x *= C;
	x ^= x >> 29;
	x *= C;
	x ^= x >> 32;
	x *= C;
	x ^= x >> 29;
	return x;
}

inline uint64_t f_mix64_stream(uint64_t h, uint64_t x) {
	// https://github.com/jonmaiga/mx3/blob/master/mx3.h
	static const uint64_t C = 0xbea225f9eb34556d;
	x *= C;
	x ^= (x >> 57) ^ (x >> 43);
	x *= C;
	h += x;
	h *= C;
	return h;
}

// TODO: replace xxhash with mx3 hash / benchmark it!
u64 f_hash64_str_ex(fString s, u64 seed);
#define f_hash64_str(s) f_hash64_str_ex(s, 0)

typedef struct fHasher { uint64_t state; } fHasher;
inline fHasher f_hasher_begin() { fHasher h = { 0 }; return h; }
inline void f_hasher_add(fHasher* h, uint64_t data) { h->state = f_mix64_stream(h->state, data); }
inline uint64_t f_hasher_end(fHasher* h) { return f_mix64(h->state); }

// -- fString ------------------------------------------------------------------

#define f_str_is_utf8_first_byte(c) (((c) & 0xC0) != 0x80) /* is c the start of a utf8 sequence? */
#define f_str_each(str, r, i) (uint i=0, r = 0, i##_next=0; (r=f_str_next_rune(str, &i##_next)); i=i##_next)
#define f_str_each_reverse(str, r, i) (uint i=str.len; rune r=f_str_prev_rune(str, &i);)

#define f_str_make(len, arena) F_STRUCT_INIT(fString){ f_mem_alloc(len, arena), len }

// Formatting rules:
// ~s                       - fString
// ~c                       - c-style string
// ~~                       - escape for ~
// TODO: ~r                 - rune
// ~u8, ~u16, ~u32, ~u64    - unsigned integers
// ~i8, ~i16, ~i32, ~i64    - signed integers
// ~x8, ~x16, ~x32, ~x64    - hexadecimal integers
// ~f                       - double
void f_print(fWriter* w, const char* fmt, ...);
void f_print_va(fWriter* w, const char* fmt, va_list args);

void f_prints(fWriter* w, fString str); // write string
void f_prints_repeat(fWriter* writer, fString str, uint count);
void f_printc(fWriter* w, const char* str);
void f_printb(fWriter* w, uint8_t b); // print ASCII-byte. hmm.. maybe we should just have writer
// void f_printr(fWriter* writer, rune r); // write rune, TODO

fString f_aprint(fArena* arena, const char* fmt, ...); // arena-print

void f_cprint(const char* fmt, ...);         // console-print

fString f_str_advance(fString* str, uint len);
fString f_str_clone(fString str, fArena* arena);

void f_str_copy(fString dst, fString src);

fString f_str_path_stem(fString path); // Returns the name of a file without extension, e.g. "matty/boo/billy.txt" => "billy"
fString f_str_path_extension(fString path); // returns the file extension, e.g. "matty/boo/billy.txt" => "txt"
fString f_str_path_tail(fString path); // Returns the last part of a path, e.g. "matty/boo/billy.txt" => "billy.txt"
fString f_str_path_dir(fString path); // returns the directory, e.g. "matty/boo/billy.txt" => "matty/boo"

bool f_str_last_index_of_any_char(fString str, fString chars, uint* out_index);
bool f_str_contains(fString str, fString substr);
bool f_str_find_substring(fString str, fString substr, uint* out_index);

fString f_str_replace(fString str, fString search_for, fString replace_with, fArena* arena);
fString f_str_replace_multi(fString str, fSlice(fString) search_for, fSlice(fString) replace_with, fArena* arena);
fString f_str_to_lower(fString str, fArena* arena);
rune f_str_rune_to_lower(rune r);

bool f_str_ends_with(fString str, fString end);
bool f_str_starts_with(fString str, fString start);
bool f_str_cut_end(fString* str, fString end);
bool f_str_cut_start(fString* str, fString start);

void f_str_split_i(fString str, u8 character, fArena* arena, fSlice(fRangeUint)* out);

fString f_str_join_n(fSlice(fString) args, fArena* arena);

#ifndef __cplusplus
#define f_str_join(arena, ...) f_str_join_n(f_slice_lit(fString, __VA_ARGS__), arena)
#endif

bool f_str_equals(fString a, fString b);
bool f_str_equals_nocase(fString a, fString b); // case-insensitive version of str_equals

fString f_str_slice(fString str, uint lo, uint hi);
fString f_str_slice_before(fString str, uint mid);
fString f_str_slice_after(fString str, uint mid);

// - Works with any base up to 16 (i.e. binary, base-10, hex)
// - Underscores are allowed and skipped
bool f_str_to_u64(fString s, uint base, u64* out_value);

// - A single minus or plus is accepted preceding the digits
// - Works with any base up to 16 (i.e. binary, base-10, hex)
// - Underscores are allowed and skipped
bool f_str_to_s64(fString s, uint base, s64* out_value);
bool f_str_to_f64(fString s, f64* out);

void f_print_uint(fWriter* w, uint64_t value, size_t base);
fString f_str_from_uint(uint64_t value, size_t base, fArena* arena);

void f_print_int(fWriter* w, int64_t value, size_t base);
fString f_str_from_int(int64_t value, size_t base, fArena* arena);

void f_print_float(fWriter* w, double value);
fString f_str_from_float(double value, fArena* arena);

//void f_print_float_ex(fWriter* w, fString bytes);
//fString f_str_from_float_ex(f64 value, int num_decimals, fArena alc);

char* f_str_to_cstr(fString s, fArena* arena);
fString f_str_from_cstr(const char* s);

// Do we need this function...? It's very windows-specific.
wchar_t* f_str_to_utf16(fString str, uint num_null_terminations, fArena* arena, uint* out_len);
fString f_str_from_utf16(wchar_t* str_utf16, fArena* arena); // returns an empty string if fails

uint f_str_encode_rune(u8* output, rune r); // returns the number of bytes written

// Returns the character on `byteoffset`, then increments it.
// Will returns 0 if byteoffset >= str.len
rune f_str_next_rune(fString str, uint* byteoffset);
rune f_str_decode_rune(fString str);

// Decrements `bytecounter`, then returns the character on it.
// Will returns 0 if byteoffset < 0
rune f_str_prev_rune(fString str, uint* byteoffset);

uint f_str_rune_count(fString str);

#ifdef F_DEF_INCLUDE_OS
// -- OS general ---------------------------------------------------------------

u64 f_read_cycle_counter();
void f_sleep_milliseconds(s64 ms);

void f_os_print(fString str);
void f_os_print_color(fString str, fConsoleAttributeFlags attributes_mask);

// If `working_dir` is an empty string, the current working directory will be used.
// `args[0]` should be the path of the executable, where `\' and `/` are both accepted path separators.
// TODO: options to capture stdout and stderr
bool f_os_run_command(fSlice(fString) args, fString working_dir, u32* out_exit_code);
//bool os_run_command_no_wait(Slice(fString) args, fString working_dir);

// Find the path of an executable given its name, or return an empty string if it's not found.
// NOTE: `name` must include the file extension!
fString f_os_find_executable(fString name, fArena* arena);

bool f_os_set_working_dir(fString dir);
fString f_os_get_working_dir(fArena* arena);

fString f_os_get_executable_path(fArena* arena);

// these strings do not currently convert slashes - they will be windows specific `\`
//fSlice(fString) os_file_picker_multi(); // allocated with temp_allocator

void f_os_error_popup(fString title, fString message);

// -- Clipboard ----------------------------------------------------------------

fString f_os_clipboard_get_text(fArena* arena);
void f_os_clipboard_set_text(fString str);

// -- DynamicLibrary -----------------------------------------------------------

fDynamicLibrary f_dynamic_library_load(fString filepath);
bool f_dynamic_library_unload(fDynamicLibrary dll);
void* f_dynamic_library_sym_address(fDynamicLibrary dll, fString symbol);

// -- Files --------------------------------------------------------------------


// The path separator in the returned string will depend on the OS. On windows, it will be a backslash.
// If the provided path is invalid, an empty string will be returned.
// TODO: maybe it'd be better if these weren't os-specific functions, and instead could take an argument for specifying
//       windows-style paths / unix-style paths
bool f_files_path_is_absolute(fString path);

// If `working_dir` is an empty string, the current working directory will be used.
bool f_files_path_to_canonical(fString working_dir, fString path, fArena* arena, fString* out_canonical);

bool f_files_visit_directory(fString path, fVisitDirectoryVisitor visitor, void* visitor_userptr);
bool f_files_directory_exists(fString path);
bool f_files_delete_directory(fString path); // If the directory doesn't already exist, it's treated as a success.
bool f_files_make_directory(fString path); // If the directory already exists, it's treated as a success.

bool f_files_read_whole(fString filepath, fArena* arena, fString* out_str);
bool f_files_write_whole(fString filepath, fString data);

bool f_files_open(fString filepath, fFileOpenMode mode, fFile* out_file);
bool f_files_close(fFile* file);
uint f_files_size(fFile* file);
uint f_files_read(fFile* file, void* dst, uint size);
bool f_files_write_unbuffered(fFile* file, fString data);
uint f_files_get_cursor(fFile* file);
bool f_files_set_cursor(fFile* file, uint position);

void f_files_flush(fFile* file);
inline fWriter* f_files_get_writer(fFile* file) { return (fWriter*)&file->buffered_writer; }

u64 f_files_get_modtime(fString filepath); // it'd be nice if this used apollo time
bool f_files_clone(fString src_filepath, fString dst_filepath);
bool f_files_delete(fString filepath);

fString f_files_pick_file_dialog(fArena* arena);

// TODO: writer. Should be buffered by default
//inline fBufferedWriter f_files_writer(fFile* file) {
//
//}

// -- Time --------------------------------------------------------------------

//fTick f_get_tick();

#endif

// -- Random ------------------------------------------------------------------

u32 f_random_u32();
u64 f_random_u64();
float f_random_float_in_range(float minimum, float maximum);

// -- Writer --------------------------

void f_writer_stdout_proc(fWriter* writer, const void* data, size_t size);
void f_string_builder_writer_proc(fWriter* writer, const void* data, size_t size);
void f_buffered_writer_proc(fWriter* writer, const void* data, size_t size);

void f_flush_buffered_writer(fBufferedWriter* writer);

// IMPORTANT: You must call `f_flush_buffered_writer` after you've finished printing!
inline fWriter* f_open_buffered_writer(fWriter* backing, u8* buffer, uint32_t buffer_size, fBufferedWriter* out_writer) {
	out_writer->writer.proc = f_buffered_writer_proc;
	out_writer->writer.userdata = backing;
	out_writer->buffer = buffer;
	out_writer->buffer_size = buffer_size;
	out_writer->current_pos = 0;
	return (fWriter*)out_writer;
}

inline fWriter* f_get_stdout() {
	const static fWriter w = { f_writer_stdout_proc, NULL };
	return (fWriter*)&w;
}

inline void f_init_string_builder(fStringBuilder* builder, fArena* arena) {
	fArrayRaw buffer = f_array_make(arena);
	memcpy(&builder->buffer, &buffer, sizeof(fArrayRaw)); // memcpy because of C++ semantics and templated fArray
	builder->writer.proc = f_string_builder_writer_proc;
	builder->writer.userdata = &builder->buffer;
	builder->w = &builder->writer;
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif

#endif // _FOUNDATION_H