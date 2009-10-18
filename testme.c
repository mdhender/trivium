#include "trivium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char source[] = "A very good day to you, Mr. Doogles.";

int
main(int argc, char *argv[])
{
	int idx;

	/* encrypt and decrypt several buffers */
	unsigned char *src = malloc(sizeof(source) + 1);
	unsigned char *dst = malloc(sizeof(source) + 1);

	TriviumKeyHash tkh;
	TriviumBuffer  tb;
	TriviumState  *ts;

	tkh.keyHash[0] = ' ';
	tkh.keyHash[1] = ' ';
	tkh.keyHash[2] = ' ';
	tkh.keyHash[3] = ' ';
	tkh.keyHash[4] = ' ';
	tkh.keyHash[5] = ' ';
	tkh.keyHash[6] = ' ';
	tkh.keyHash[7] = ' ';
	tkh.keyHash[8] = ' ';
	tkh.keyHash[9] = ' ';

	tb.srcLength = sizeof(source);
	tb.src       = src;
	tb.dst       = dst;

	ts = Trivium_Init(0, &tkh);
	memcpy(src, source, tb.srcLength);
	Trivium_TwiddleBuffer(ts, &tb);
	printf("%4d %d\n", __LINE__, memcmp(source, tb.src, tb.srcLength));
	printf("%4d %d\n", __LINE__, memcmp(source, tb.dst, tb.srcLength));

	ts = Trivium_Init(0, &tkh);
	memcpy(src, dst, tb.srcLength);
	Trivium_TwiddleBuffer(ts, &tb);
	printf("%4d %d\n", __LINE__, memcmp(source, tb.src, tb.srcLength));
	printf("%4d %d\n", __LINE__, memcmp(source, tb.dst, tb.srcLength));

	ts = Trivium_Init(0, &tkh);
	tb.dst = src;
	memcpy(src, source, tb.srcLength);
	memcpy(dst, source, tb.srcLength);
	for (idx = 0; idx < 1024 * 128; ++idx) {
		Trivium_TwiddleBuffer(ts, &tb);
	}
	printf("\t%d\n", memcmp(source, tb.src, tb.srcLength));
	ts = Trivium_Init(0, &tkh);
	for (idx = 0; idx < 1024 * 128; ++idx) {
		Trivium_TwiddleBuffer(ts, &tb);
	}
	printf("\t%d\n", memcmp(source, tb.src, tb.srcLength));
	printf("%4d %d\n", __LINE__, memcmp(source, tb.dst, tb.srcLength));

	return 0;
}
