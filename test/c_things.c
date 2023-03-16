//#include <stdio.h>
//int entry();

void hello(int x) {
	int k = x + 5;
	__debugbreak();
	__debugbreak();
	__debugbreak();
	//printf("%llu\n", x);
}

//typedef struct { void* ptr; unsigned long long len; } string;
//void print_string(string x) {
//	printf("%.*s\n", x.len, x.ptr);
//}

//typedef struct { int64_t x; int64_t y; int64_t z; } V3;

//void receive_v3(V3 aa) {
//	int64_t x = aa.x;
//}
//
//V3 get_v3() {
//	return (V3){999, 888, 777};
//}
//
//V1 get_v1() {
//	return (V1){999};
//}
//
//int main() {
//	//int test = entry();
//	//int b = test + 1;
//	return 0;
//}