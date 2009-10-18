#include "trivium.h"

#include <stdlib.h> /* for malloc */
#include <string.h> /* for memset, memcpy */

/* if you really implement this, you should change the init vector
 * to something less silly. or maybe even make it a parameter.
 */
TriviumState *
Trivium_Init(TriviumState *state, TriviumKeyHash *tkh)
{
	/* only allocate buffer if we have an invalid structure */
	if (tkh && state == 0) {
		state = malloc(sizeof(TriviumState));
	}

	/* only initialize if we have valid structures */
	if (tkh && state) {
		int idx;
		unsigned char *k     /* 80 bit hashed key */
			= tkh->keyHash;
		unsigned char iv[10] /* 80 bit init vector */
			= { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA
			  , 0xFE, 0xF0, 0x0D, 0xBA, 0xAD };
		unsigned char ib[36]; /* 288 bit init buffer */

		/* unitialized bits will be set to zero */
		memset(state, 0, sizeof(TriviumState));

		/* (s0,...,s92) <- (k0,...,k79,0,...,0) */
		memcpy(state->s, k, sizeof(k));

		/* (s93,...,s176) <- (iv0,...,iv79,0,...,0) */
		memcpy(state->s+93, iv, sizeof(iv));

		/* (s177,...,s287) <- (0,...,0,1,1,1) */
		state->s[285] = state->s[286] = state->s[287] = 1;

		/* rotate over four full cycles.
		 * this is equivalent to 4 * 288 bits.
		 * conveniently, our init buffer is 288 bits.
		 */
		for (idx = 0; idx < 4; ++idx) {
			TriviumBuffer tb;
			tb.srcLength = sizeof(ib);
			tb.src       = ib;
			tb.dst       = 0;

			Trivium_TwiddleBuffer(state, &tb);
		}
	}

	return tkh ? state : 0;
}
