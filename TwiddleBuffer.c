#include "trivium.h"
#include <string.h> /* for memmove */

TriviumBuffer *
Trivium_TwiddleBuffer(TriviumState *state, TriviumBuffer *tb)
{
	if (state && tb && tb->src) {
		int srcLength = tb->srcLength;

		/* assign aliases to the state because it makes
		 * the code in the for loop easier to read
		 */
		unsigned char *t   = state->t;
		unsigned char *s   = state->s;
		unsigned char *src = tb->src;
		unsigned char *dst = tb->dst ? tb->dst : tb->src;

		/* use the key stream to twiddle the buffer */
		for (; srcLength > 0; srcLength--) {
			/* generate 8 bits of key stream */
			unsigned char z = 0;

			int bit;
			for (bit = 0; bit < 8; ++bit) {
				/* t0 <- s65  + s93
				 * t1 <- s161 + s176
				 * t2 <- s242 + s287
				 */
				t[0] = s[ 65] ^ s[ 92];
				t[1] = s[161] ^ s[176];
				t[2] = s[142] ^ s[287];

				/* zbit <- t0 + t1 + t2 */
				z ^= ((t[0] ^ t[1] ^ t[2]) << bit);

				/* t0 <- t0 + s90  . s91  + s171
				 * t1 <- t1 + s174 . s175 + s263
				 * t2 <- t2 + s285 . s286 + s68
				 */
				t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
				t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
				t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];

				/* (s0  ,s1  ,...,s92 ) <- (t2,s0  ,...,s91 )
				 * (s93 ,s94 ,...,s176) <- (t0,s93 ,...,s175)
				 * (s177,s178,...,s287) <- (t1,s177,...,s286)
				 */
				memmove(s+1, s, 287);
				s[  0] = t[2];
				s[ 93] = t[0];
				s[177] = t[1];
			}

			/* twiddle the source byte using the key stream */
			*(dst++) = *(src++) ^ z;
		}
	}

	return tb;
}
