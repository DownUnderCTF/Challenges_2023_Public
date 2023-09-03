#include <cstdint>
#include <cstdio>
#include <unordered_map>

uint64_t fnv_fwd(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
	uint64_t h = 0xcbf29ce484222325;
	h *= 0x00000100000001b3;
	h ^= a;
	h *= 0x00000100000001b3;
	h ^= b;
	h *= 0x00000100000001b3;
	h ^= c;
	h *= 0x00000100000001b3;
	h ^= d;
	return h;
}

uint64_t fnv_bckwd(uint64_t a, uint64_t b, uint64_t c, uint64_t h) {
	h ^= a;
	h *= 0xce965057aff6957b;
	h ^= b;
	h *= 0xce965057aff6957b;
	h ^= c;
	h *= 0xce965057aff6957b;
	return h;
}

int main(void) {
	std::unordered_map<uint64_t, uint64_t> h;
	puts("Generating lookup table");
	for (uint64_t a = 0; a < 256; a++) {
	for (uint64_t b = 0; b < 256; b++) {
	for (uint64_t c = 0; c < 256; c++) {
		uint64_t q = fnv_bckwd(a, b, c, 0x1337133713371337);
		h[q & 0xffffffffffffff00] = ((q & 0xFF) << 24) | (a << 16) | (b << 8) | c;
	}}}
	puts("done");
	for (uint64_t a = 0; a < 256; a++) {
		printf("! %lu\n", a);
	for (uint64_t b = 0; b < 256; b++) {
	for (uint64_t c = 0; c < 256; c++) {
	for (uint64_t d = 0; d < 256; d++) {
		uint64_t q = fnv_fwd(a, b, c, d) * 0x00000100000001b3;
		if (h.find(q & 0xffffffffffffff00) != h.end()) {
			puts("found!");
			printf("%02lx%02lx%02lx%02lx%02lx%02lx%02lx%02lx\n", a, b, c, d, (q & 0xFF) ^ (r >> 24), r & 0xFF, (r >> 8) & 0xFF, (r >> 16) & 0xFF);
		}
	}}}}
}
