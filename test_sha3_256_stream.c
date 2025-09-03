#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "sha3.h"


int main(void) {
	uint64_t read_size = 0;
	SHA3_NEW(ctx1);

	sha3_init(&ctx1, SHA3_256_TYPE, 0);

	char buf[1 << 17];
	while ((read_size = fread(buf, 1, sizeof(buf), stdin)) > 0) {
		sha3_process(&ctx1, (uint8_t *)buf, read_size);
	}

	sha3_finish(&ctx1);
	for (int32_t i = 0; i < SHA3_256_LEN; i++)
		printf("%02x", SHA3_STATE(&ctx1, i));
	printf("\n");

	return 0;
}
