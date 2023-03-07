// 
// The foundation is a minimal set of functions and utilities
// that I've found come in handy everywhere, and which the C/C++
// language doesn't provide you in a good way.
// 
// WARNING: THIS IS ALL CURRENTLY A WORK-IN-PROGRESS CODEBASE!! Some things aren't complete or fully tested,
// such as UTF8 support and some things might be implemented in a dumb way.

#ifdef FOUNDATION_INCLUDED
#error
#endif
#define FOUNDATION_INCLUDED

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS // should be defined before including initializer_list
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h> // for memset

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

// Used to mark nullable pointers
#define fOpt(ptr) ptr

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
#define F_STRF(s) (u32)s.len, s.data

#define F_LEN(x) (sizeof(x) / sizeof(x[0]))
#define F_OFFSET_OF(T, f) ((uint)&((T*)0)->f)

#define F_I8_MIN -128
#define F_I8_MAX 127
#define F_U8_MAX 255
#define F_I16_MIN -32768
#define F_I16_MAX 32767
#define F_U16_MAX 0xffff
#define F_I32_MIN 0x80000000
#define F_I32_MAX 0x7fffffff
#define F_U32_MAX 0xffffffffu
#define F_I64_MIN 0x8000000000000000ll
#define F_I64_MAX 0x7fffffffffffffffll
#define F_U64_MAX 0xffffffffffffffffllu

#define F_PAD(x) char _pad_##__COUNTER__[x]
#define F_STRINGIFY(s) #s

#define F_CONCAT___(x, y) x ## y
#define F_CONCAT(x, y) F_CONCAT___(x, y)

#define F_STATIC_ASSERT(x) enum { F_CONCAT(_static_assert_, __LINE__) = 1 / ((int)!!(x)) }

// https://www.wambold.com/Martin/writings/alignof.html
#ifdef __cplusplus
template<typename T> struct alignment_trick { char c; T member; };
#define F_ALIGN_OF(type) F_OFFSET_OF(alignment_trick<type>, member)
#else
#define F_ALIGN_OF(type) (F_OFFSET_OF(struct F_CONCAT(_dummy, __COUNTER__) { char c; type member; }, member))
#endif

// Useful for surpressing compiler warnings
#define F_UNUSED(name) ((void)(0 ? ((name) = (name)) : (name)))

#ifdef _DEBUG
#define F_ASSERT(x) { if (!(x)) __debugbreak(); }
#else
#define F_ASSERT(x) { if (x) {} }
#endif

inline static void _cast_check_fail() { F_ASSERT(false); }
// Cast with range checking
#define F_CAST(T, x) ((T)(x) == (x) ? (T)(x) : (_cast_check_fail(), (T)0))

#define F_BP __debugbreak();

// Debugging helper that counts the number of hits and allows for breaking at a certain index
#define F_HITS(name, break_if_equals) \
static uint F_CONCAT(name, _c) = 1; \
F_CONCAT(name, _c)++; \
uint name = F_CONCAT(name, _c); \
if (name == (break_if_equals)) { F_BP; }

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

// TODO: fix this to not be UB
#define F_BITCAST(T, x) (*(T*)&x)

#define F_AS_BYTES(x) F_STRUCT_INIT(fString){ (u8*)&x, sizeof(x) }
#define F_SLICE_AS_BYTES(x) F_STRUCT_INIT(fString){ (u8*)(x).data, (x).len * sizeof((x).data[0]) }

// https://graphitemaster.github.io/aau/#unsigned-multiplication-can-overflow
inline bool f_does_mul_overflow(uint x, uint y) { return y && x > ((uint)-1) / y; }
inline bool f_does_add_overflow(uint x, uint y) { return x + y < x; }
inline bool f_does_sub_underflow(uint x, uint y) { return x - y > x; }

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
	u8* data;
	uint len;
} fString;
#define fString fString
#endif

// c container macros
#ifndef __cplusplus
#define f_array_push(T, array, elem) f_array_push_raw((array), &(elem), sizeof(elem), F_ALIGN_OF(T))
#define f_map64_insert(map, key, value, mode) f_map64_insert_raw((map), (key), &(value), (mode))
#endif

// TODO: make it possible for an arena to grow.
// It should be an enum parameter for the make_arena function.
// In some cases, you might want the arena to have a max size instead of growing,
// because it could be a useful assumption to know that the addresses will be all in one contiguous block of memory.
// It should also be possible to allocate a growing child-arena out from an existing arena / slot arena

typedef struct fAllocator fAllocator;
struct fAllocator {
	// TODO: get rid of caller-managed alignment for convenience?
	// `old_ptr` can be NULL
	void* (*_proc)(fAllocator* allocator, void* old_ptr, uint old_size, uint new_size, uint_pow2 new_alignment);
};

typedef enum {
	fArenaMode_VirtualReserveFixed,
	//ArenaMode_VirtualGrowing, // do we really need this since we have UsingAllocatorGrowing?
	fArenaMode_UsingBufferFixed,
	fArenaMode_UsingAllocatorGrowing,
} fArenaMode;

typedef struct {
	fArenaMode mode;
	struct {
		fOpt(u8*) reserve_base;
		uint reserve_size;
	} VirtualReserveFixed;
	struct {
		u8* base;
		uint size;
	} UsingBufferFixed;
	struct {
		u32 min_block_size;
		fAllocator* a;
	} UsingAllocatorGrowing;
} fArenaDesc;

typedef struct fArenaBlock fArenaBlock;
struct fArenaBlock {
	uint size_including_header;
	fArenaBlock* next;
	// the block memory comes right after the header
};

typedef struct fArenaPosition {
	u8* head;
	fArenaBlock* current_block; // used only with ArenaMode_UsingAllocatorGrowing
} fArenaPosition;

typedef struct fArena {
	fAllocator alc; // Must be the first field for outwards-casting!
	fArenaDesc desc;

	struct { // should be union
		u8* internal_base;
		fArenaBlock* first_block; // used only with ArenaMode_UsingAllocatorGrowing
	};

	u8* committed_end; // only used with ArenaMode_VirtualReserveFixed

	fArenaPosition pos;
} fArena;

#define f_make_slice_one(elem, allocator) {MemClone((elem), (allocator)), 1}

// Warning: these return uninitialized memory.
#define f_mem_alloc(size, alignment, allocator) (void*)(allocator)->_proc((allocator), NULL, 0, (size), (alignment))
#define f_mem_resize(ptr, old_size, new_size, new_alignment, allocator) (void*)(allocator)->_proc((allocator), (ptr), (old_size), (new_size), (new_alignment))
#define f_mem_free(ptr, size, allocator) (allocator)->_proc((allocator), (ptr), (size), 0, 1)

#define f_mem_alloc_n(T, count, allocator) (T*)(allocator)->_proc((allocator), NULL, 0, (count) * sizeof(T), F_ALIGN_OF(T))
#define f_mem_resize_n(T, ptr, old_count, new_count, allocator) (T*)(allocator)->_proc((allocator), ptr, (old_count) * sizeof(T), (new_count) * sizeof(T), F_ALIGN_OF(T))
#define f_mem_free_n(T, ptr, count, allocator) (allocator)->_proc((allocator), (ptr), (count) * sizeof(T), 0, F_ALIGN_OF(T))

#define f_mem_zero(ptr) memset(ptr, 0, sizeof(*ptr))
#define f_mem_zero_slice(slice) memset((f_slice).data, 0, (slice).size_bytes())

#define f_mem_clone(T, value, allocator) f_mem_clone_size(sizeof(T), F_ALIGN_OF(T), &value, allocator)

inline void* f_mem_clone_size(uint size, uint align, const void* value, fAllocator* a) {
	void* result = f_mem_alloc(size, 1, a);
	memcpy(result, value, size);
	return result;
}

// Slice, Array and fString have the same binary layout, so they can be bitcasted between each other

typedef struct {
	void* data;
	uint len;
} fSliceRaw;

typedef struct {
	union {
		struct {
			void* data;
			uint len;
		};
		fSliceRaw slice;
	};
	uint capacity;
	fAllocator* alc;
} fArrayRaw;

//#define HASH_STRING(x) MeowU64From(MeowHash(MeowDefaultSeed, x.len, x.data), 0)

// @speed: for release builds we could use #define HASH HASH_U64(__COUNTER__) instead, if that'd compile to better machine code.
// But for debug, we want everything to be 100% consistent between builds.
// Actually, for now, lets just use the counter.
//#define HASH_LOC HASH_U64(__COUNTER__+1)
//#define HASH_LOC (((u64)__FILE__) ^ HASH_U64((u64)__LINE__))

#ifdef _DEBUG
void _DEBUG_FILL_GARBAGE(void* ptr, uint len);
#else
#define _DEBUG_FILL_GARBAGE(ptr, len)
#endif

typedef struct { s64 nsec; } fTick;

#define NANOSECOND 1
#define MICROSECOND 1000 // 1000 * NANOSECOND
#define MILLISECOND 1000000 // 1000 * MICROSECOND
#define SECOND 1000000000 // 1000 * MILLISECOND
#define MINUTE 60000000000 // 60 * SECOND
#define HOUR 3600000000000 // 60 * MINUTE

typedef struct { void* handle; } fDynamicLibrary;

typedef enum {
	fFileOpenMode_Read,
	fFileOpenMode_Write,
	fFileOpenMode_Append,
} fFileOpenMode;

typedef struct { void* _handle; } fFile;

// #define STRING_FROM_CSTR(x) fString{ (u8*)x, strlen(x) } // this shouldn't be a macro

// ALLOCA_C_STRING probably shouldn't be used in actual programs. Use to_cstring() instead.
//inline const char* _temp_cstr(fString string, void* out) { ZoneScoped; memcpy(out, string.data, string.len); ((char*)out)[string.len] = '\0'; return (const char*)out; }
//#define ALLOCA_C_STRING(str) _temp_cstr(str, alloca(str.len + 1))

//#define __ACTIVATE_MANUAL_STRUCT_PADDING \
//_Pragma("warning(3:4820)") \
//_Pragma("warning(3:4121)")
//#define __RESTORE_MANUAL_STRUCT_PADDING \
//_Pragma("warning(4:4820)") \
//_Pragma("warning(4:4121)")

//typedef struct {
//	union {
//		u32 id; // 1 is the first valid index, 0 is invalid
//		bool initialized;
//	};
//	u32 gen;
//} SlotArrayHandle;

//struct SlotArrayElemHeader {
//	u32 gen;
//	u32 next_free_item; // 0 means this slot is currently occupied
//	// the value comes after the header
//};

typedef struct {
	fAllocator* alc;
	u32 value_size; // ...should we even have this?

	u32 alive_count;

	u32 slot_count;
	u32 slot_count_log2; // if there are zero slots, this will be zero and the `slots` pointer will be null.
	fOpt(void*) slots;
} fMap64Raw;

typedef struct {
	fString file;
	u32 line;
} fLeakTrackerCallstackEntry;

typedef struct {
	fArray(fLeakTrackerCallstackEntry) callstack;

	/*u64 allocation_idx;

	i64 size;
	i64 alignment;
	// this could be a BucketArray
	fArray(CallstackEntry) callstack;
	*/
} fLeakTracker_Entry;

typedef struct {
	// Note: LeakTracker never frees any of its internals until deinit_leak_tracker() is called
	bool active;
	fArena* internal_arena;

	fMap64(fLeakTracker_Entry) active_allocations; // key is the address of the allocation

	/*fAllocator allocator; // Must be the first field for outwards-casting!

	fAllocator* passthrough_allocator;
	Arena internal_arena;

	u64 next_allocation_idx;

	fArray(LeakTracker_BadFree) bad_free_array;
	*/
	// This is here so that we won't have to create a dozen of duplicate strings
	fMap64(fString) file_names_cache; // key is the string hashed
} fLeakTracker;

//extern fAllocator _global_allocator; // do we need this?
//F_THREAD_LOCAL extern void* _foundation_pass;
F_THREAD_LOCAL extern fArena* _f_temp_arena;
F_THREAD_LOCAL extern uint _f_temp_arena_scope_counter;
F_THREAD_LOCAL extern fLeakTracker _f_leak_tracker;

// Relies on PDB symbol info
void f_get_stack_trace(void(*visitor)(fString function, fString file, u32 line, void* user_ptr), void* user_ptr);

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
void f_leak_tracker_init();
void f_leak_tracker_deinit();

// These functions are ignored if leak tracker is not present
void f_leak_tracker_begin_entry(void* address, uint skip_stackframes_count);
void f_leak_tracker_assert_is_alive(void* address);
void f_leak_tracker_end_entry(void* address);

/*
typedef struct {
	u32 elem_size;

	u32 num_elems_per_bucket;
	fAllocator* a;
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
typedef enum {
	fConsoleAttribute_Blue = 0x0001,
	fConsoleAttribute_Green = 0x0002,
	fConsoleAttribute_Red = 0x0004,
	fConsoleAttribute_Intensify = 0x0008,
} fConsoleAttribute;
typedef int fConsoleAttributeFlags;

// TODO: get rid of this enum and make it into proc variants
typedef enum {
	fMapInsert_AssertUnique,
	fMapInsert_DoNotOverride,
	fMapInsert_Override,
} fMapInsert;

// todo: get rid of this?
typedef struct { void* _unstable_ptr; bool added; } fMapInsertResult;

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

//
// `temp_push`/`f_temp_pop` sets a convention for easily getting temporary memory
// in a thread-safe way for a duration of some scope. Internally, foundation.cpp
// declares a thread-local Arena.
// 
// If you have nested push/pop pairs, PopTemp doesn't actually pop the stack until
// the final pop is called (when the scope counter reaches zero).
// This is done to make sure you can safely pass the temp allocator to procedures that
// return allocated memory back to the outer scope. e.g:
// 
// foo:
//    fAllocator* temp = temp_push();
//    MyArray<int> a = f_array_make(temp);
//    bar(&a);
//    f_temp_pop();
// 
// bar:
//    fAllocator* temp = temp_push();
//    Baz* baz = some_procedure_that_allocates_memory(temp);
//    f_array_push(&a, baz->some_field)  // Potentially grow the array and require an allocation from the temp arena
//    f_temp_pop();                  // Whoops, we might have just corrupted the entire array!
// 
// ... If the temp arena was popped at the end of `bar` to where it was when entering the procedure,
// there would be a subtle bug. `f_array_push` would first use the temporary allocator to insert some value, requiring
// a potential allocation by the array. Then `f_temp_pop` would be called, and the memory in use by the array
// would marked available for subsequent temporary allocations, corrupting the entire array.
// 

#ifdef __cplusplus
extern "C" {
#endif

fAllocator* f_temp_push();
void f_temp_pop();

// temp_init and temp_deinit are not necessary and they only exist for performance.
// They keep the temp arena alive even after a final (scope counter reaching zero) call to f_temp_pop.
// You probably want to call temp_init/deinit in main, if your program has multiple independent temp_push/pop scopes.
// If you don't call temp_init, then each final call to f_temp_pop will release the arena back to the OS,
// and temp_push will in turn need to allocate a new arena from the OS.
void f_temp_init();
void f_temp_deinit();

fArena* f_arena_make(u32 min_block_size, fAllocator* a);
fArena* f_arena_make_virtual_reserve_fixed(uint reserve_size, fOpt(void*) reserve_base);
fArena* f_arena_make_buffer_fixed(void* base, uint size);
fArena* f_arena_make_ex(fArenaDesc desc);
void f_arena_free(fArena* arena);

//Heap* make_heap(fArenaDesc backing_arena_desc);

fString f_arena_push(fArena* arena, uint size, uint_pow2 alignment);
u8* f_arena_push_str(fArena* arena, fString data, uint_pow2 alignment);


// should we instead just ask for a string?
// f_arena_get_as_string()
u8* f_arena_get_contiguous_base(fArena* arena);
uint f_arena_get_contiguous_cursor(fArena* arena);

fArenaPosition f_arena_get_pos(fArena* arena);
void f_arena_pop_to(fArena* arena, fArenaPosition pos);
// TODO: void arena_shrink_memory(uint base_size) // the memory will not be reduced past base_size
void f_arena_clear(fArena* arena);

uint_pow2 f_round_up_power_of_2(uint v); // todo: move this into the macros section as an inline function?

#define F_MAP64_EMPTY_KEY (0xFFFFFFFFFFFFFFFF)
#define F_MAP64_DEAD_BUT_REQUIRED_FOR_CHAIN_KEY (0xFFFFFFFFFFFFFFFE)
#define F_MAP64_LAST_VALID_KEY (0xFFFFFFFFFFFFFFFD)

inline bool f_map64_iterate(fMap64Raw* map, uint* i, uint* key, void** value_ptr) {
	if (!map->slots) return false;
	u32 slot_size = map->value_size + 8;

	for (;;) {
		if (*i >= map->slot_count) return false;

		u64* key_ptr = (u64*)((u8*)map->slots + (*i) * slot_size);
		(*i)++;

		if (*key_ptr <= F_MAP64_LAST_VALID_KEY) {
			*key = *key_ptr;
			*value_ptr = key_ptr + 1;
			return true;
		}
	}
}

#define f_map64_each_raw(map, key, value_ptr) (uint _i=0, key=0; f_map64_iterate(map, &_i, &key, value_ptr); )

// WARNING: The largest 2 key values (see HASHMAP64_LAST_VALID_KEY)
// are reserved internally for marking empty/destroyed slots by the hashmap, so you cannot use them as valid keys.
// An assertion will fail if you try to insert a value with a reserved key.
// This is done for performance, but maybe we should have an option to default to a safe implementation.
fMap64Raw f_map64_make_raw(u32 value_size, fAllocator* a);
fMap64Raw f_make_map64_cap_raw(u32 value_size, uint_pow2 capacity, fAllocator* a);
void f_map64_free_raw(fMap64Raw* map);
void f_map64_resize_raw(fMap64Raw* map, u32 slot_count_log2);
fMapInsertResult f_map64_insert_raw(fMap64Raw* map, u64 key, fOpt(const void*) value, fMapInsert mode);
bool f_map64_remove_raw(fMap64Raw* map, u64 key);
fOpt(void*) f_map64_get_raw(fMap64Raw* map, u64 key);

void f_mem_copy(void* dst, const void* src, uint size); // TODO: make this an inline call?

fArrayRaw f_array_make_raw(fAllocator* a);
fArrayRaw f_array_make_len_raw(u32 elem_size, uint len, const void* initial_value, fAllocator* a);
fArrayRaw f_array_make_len_garbage_raw(u32 elem_size, uint len, fAllocator* a);
fArrayRaw f_array_make_cap_raw(u32 elem_size, uint capacity, fAllocator* a);
void f_array_free_raw(fArrayRaw* array, u32 elem_size);
uint f_array_push_raw(fArrayRaw* array, const void* elem, u32 elem_size, u32 elem_align);
void f_array_push_slice_raw(fArrayRaw* array, fSliceRaw elems, u32 elem_size, u32 elem_align);
void f_array_pop_raw(fArrayRaw* array, fOpt(void*) out_elem, u32 elem_size);
void f_array_reserve_raw(fArrayRaw* array, uint capacity, u32 elem_size);
void f_array_resize_raw(fArrayRaw* array, uint len, fOpt(const void*) value, u32 elem_size); // set value to NULL to not initialize the memory
//SliceRaw array_get_slice_raw(ArrayRaw* array);

//SlotArenaRaw* make_slot_arena_contiguous_raw(u32 elem_size, ArenaDesc arena_desc);
//SlotArenaRaw* make_slot_arena_raw(ArenaDesc arena_desc);
//void* slot_arena_add_garbage_raw(SlotArenaRaw* arena);
//void slot_arena_clear_raw(SlotArenaRaw* arena);
//bool slot_arena_remove_raw(SlotArenaRaw* arena, void* ptr);
//void delete_slot_arena_raw(SlotArenaRaw* arena);
//uint slot_arena_get_index_raw(const SlotArenaRaw* arena, void* ptr);

u64 f_read_cycle_counter();
void f_sleep_milliseconds(s64 ms);

void f_os_print(fString str);
void f_os_print_color(fString str, fConsoleAttributeFlags attributes_mask);

// If `working_dir` is an empty string, the current working directory will be used.
// `args[0]` should be the path of the executable, where `\' and `/` are both accepted path separators.
// TODO: options to capture stdout and stderr
bool f_os_run_command(fSlice(fString) args, fString working_dir, u32* out_exit_code);
//bool os_run_command_no_wait(Slice(fString) args, fString working_dir);

bool f_os_set_working_dir(fString dir);
fString f_os_get_working_dir(fAllocator* allocator);

fString f_os_get_executable_path(fAllocator* allocator);

// these strings do not currently convert slashes - they will be windows specific `\`
//fSlice(fString) os_file_picker_multi(); // allocated with temp_allocator

void f_os_error_popup(fString title, fString message);

fOpt(u8*) f_mem_reserve(u64 size, fOpt(void*) address);
void f_mem_commit(u8* ptr, u64 size);
void f_mem_decommit(u8* ptr, u64 size);
void f_mem_release(u8* ptr);

s64 f_round_to_s64(float x);
s64 f_floor_to_s64(float x);

// -- Hash --------------------------------------------------------------------

#define f_hash64(value) ((value) * 0x9E3779B97F4A7D69LLU) // Multiply by golden ratio (0.61803398874989486662 * 2^64)
#define f_hash64_ex(value, seed) (f_hash64(value) ^ (u64)(seed)) // fvn64-style hash
#define f_hash64_push(hash, value) *(u64*)(hash) = f_hash64_ex(value, *(u64*)hash)

u64 f_hash64_str_ex(fString s, u64 seed);
#define f_hash64_str(s) f_hash64_str_ex(s, 0) 

// -- fString ------------------------------------------------------------------

#define f_str_is_utf8_first_byte(c) (((c) & 0xC0) != 0x80) /* is c the start of a utf8 sequence? */
#define f_str_each(str, r, i) (uint i=0, r = 0, i##_next=0; r=f_str_next_rune(str, &i##_next); i=i##_next)
#define f_str_each_reverse(str, r, i) (uint i=str.len; rune r=f_str_prev_rune(str, &i);)

#define f_str_make(len, allocator) F_STRUCT_INIT(fString){ f_mem_alloc(len, 1, allocator), len }

fString f_str_format(fAllocator* a, const char* fmt, ...);
void f_str_print(fArray(u8)* buffer, fString str);
void f_str_print_rune(fArray(u8)* buffer, rune r);
void f_str_print_repeat(fArray(u8)* buffer, fString str, uint count);
void f_str_printf(fArray(u8)* buffer, const char* fmt, ...);

fString f_str_advance(fString* str, uint len);
fString f_str_clone(fString str, fAllocator* allocator);

void f_str_copy(fString dst, fString src);

fString f_str_path_stem(fString path); // Returns the name of a file without extension, e.g. "matty/boo/billy.txt" => "billy"
fString f_str_path_extension(fString path); // returns the file extension, e.g. "matty/boo/billy.txt" => "txt"
fString f_str_path_tail(fString path); // Returns the last part of a path, e.g. "matty/boo/billy.txt" => "billy.txt"
fString f_str_path_dir(fString path); // returns the directory, e.g. "matty/boo/billy.txt" => "matty/boo"

bool f_str_last_index_of_any_char(fString str, fString chars, uint* out_index);
bool f_str_contains(fString str, fString substr);
bool f_str_find_substring(fString str, fString substr, uint* out_index);

fString f_str_replace(fString str, fString search_for, fString replace_with, fAllocator* a);
fString f_str_replace_multi(fString str, fSlice(fString) search_for, fSlice(fString) replace_with, fAllocator* a);
fString f_str_to_lower(fString str, fAllocator* a);
rune f_str_rune_to_lower(rune r);

bool f_str_ends_with(fString str, fString end);
bool f_str_starts_with(fString str, fString start);
fString f_str_cut_end(fString str, fString end);
fString f_str_cut_start(fString str, fString start);

//void str_split(fString str, u8 character, fAllocator* a, Slice(fString)* out);
void f_str_split_i(fString str, u8 character, fAllocator* a, fSlice(fRangeUint)* out);

fString f_str_join(fAllocator* a, fSlice(fString) args);

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

fString f_str_from_uint(fString bytes, fAllocator* a);
fString f_str_from_int(fString bytes, fAllocator* a);
fString f_str_from_float(f64 value, fAllocator* a);
fString f_str_from_float_ex(f64 value, int num_decimals, fAllocator* a);

char* f_str_to_cstr(fString s, fAllocator* a);
fString f_str_from_cstr(const char* s);

// Do we need this function...? It's very windows-specific.
wchar_t* f_str_to_utf16(fString str, uint num_null_terminations, fAllocator* a, uint* out_len);
fString f_str_from_utf16(wchar_t* str_utf16, fAllocator* a);

uint f_str_encode_rune(u8* output, rune r); // returns the number of bytes written

// Returns the character on `byteoffset`, then increments it.
// Will returns 0 if byteoffset >= str.len
rune f_str_next_rune(fString str, uint* byteoffset);
rune f_str_decode_rune(fString str);

// Decrements `bytecounter`, then returns the character on it.
// Will returns 0 if byteoffset < 0
rune f_str_prev_rune(fString str, uint* byteoffset);

uint f_str_rune_count(fString str);

// -- Clipboard ----------------------------------------------------------------

fString f_os_clipboard_get_text(fAllocator* allocator);
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
fString f_files_path_to_absolute(fString working_dir, fString path, fAllocator* a);
bool f_files_visit_directory(fString path, fVisitDirectoryVisitor visitor, void* visitor_userptr);
bool f_files_directory_exists(fString path);
bool f_files_delete_directory(fString path); // If the directory doesn't already exist, it's treated as a success.
bool f_files_make_directory(fString path); // If the directory already exists, it's treated as a success.

bool f_files_read_whole(fString filepath, fAllocator* allocator, fString* out_str);
bool f_files_write_whole(fString filepath, fString data);

fFile f_files_open(fString filepath, fFileOpenMode mode);
bool f_files_exists(fFile file);
bool f_files_close(fFile file);
uint f_files_size(fFile file);
uint f_files_read(fFile file, void* dst, uint size);
bool f_files_write(fFile file, fString data);
uint f_files_get_position(fFile file);
bool f_files_set_position(fFile file, uint position);

u64 f_files_get_modtime(fString filepath); // it'd be nice if this used apollo time
bool f_files_clone(fString src_filepath, fString dst_filepath);
bool f_files_delete(fString filepath);

fString f_files_pick_file_dialog(fAllocator* allocator);

// -- Time --------------------------------------------------------------------

//fTick f_get_tick();

// -- Random ------------------------------------------------------------------

u32 f_random_u32();
u64 f_random_u64();
float f_random_float_in_range(float minimum, float maximum);

#ifdef __cplusplus
} // extern "C"
#endif
