#include <stdint.h>
//int entry();

typedef struct { int64_t x; } V1;
typedef struct { int64_t x; int64_t y; int64_t z; } V3;

void receive_v3(V3 aa) {
	int64_t x = aa.x;
}

V3 get_v3() {
	return (V3){999, 888, 777};
}

V1 get_v1() {
	return (V1){999};
}

int main() {
	//int test = entry();
	//int b = test + 1;
	return 0;
}