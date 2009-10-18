#include "trivium.h"

#include <stdlib.h> /* for malloc */

/* NOTE: This is from Bob Burtle's IA. I include it only to give
 *       you a way to generate an 80 bit key value. You should
 *       use a better one-way hash (e.g., SHA).
 *
 *       http://www.burtleburtle.net/bob/rand/isaac.html#IAcode
 *
 * NOTE: Assumes that keyHash is declared as
 *       unsigned char keyHash[10];
 *       Will corrupt memory if it is not at least 10 bytes!
 */
TriviumKeyHash *
Trivium_KeyHash(TriviumKeyHash *tkh, TriviumKey *tk)
{
	/* allocate memory for the key hash if needed */
	if (tk && tk->key && tkh == 0) {
		tkh = malloc(sizeof(TriviumKeyHash));
	}

	if (tk && tk->key && tkh) {
		int idx;
		unsigned int b = 0;

		/* secret array of 256 bytes */
		unsigned char secret[256];

		/* assign aliases to the key and secret to use in the loop */
		unsigned char *pKey    = tk->key;
		unsigned char *pSecret = secret;

		/* use the maximum of keyLength and sizeof(secret) bytes */
		int bytesToSet = sizeof(secret);
		if (bytesToSet < tk->keyLength) {
			bytesToSet = tk->keyLength;
		}

		/* use key to initialize the secret */
		for (idx = 0; idx < bytesToSet; idx++) {
			if (idx % tk->keyLength == 0) {
				pKey = tk->key;
			}
			if (idx % sizeof(secret) == 0) {
				pSecret = secret;
			}
			if (idx < sizeof(secret)) {
				*pSecret = *pKey;
			} else {
				*pSecret = *pSecret ^ *pKey;
			}
			++pSecret;
			++pKey;
		}

		/* twiddle the bits in our secret */
		for (idx = 0; idx < sizeof(secret); ++idx) {
			unsigned int x = secret[idx];
			unsigned int y = secret[x % sizeof(secret)] + b;
			secret[idx] = y;
			b = secret[y % sizeof(secret)] + x;
		}

		/* use the secret to create the hash */
		for (idx = 0; idx < 10; ++idx) {
			unsigned int x = secret[idx % sizeof(secret)];
			unsigned int y = secret[x % sizeof(secret)] + b;
			secret[idx] = y;
			b = secret[y % sizeof(secret)] + x;
			tkh->keyHash[idx] = b % sizeof(secret);
		}
	}

	return tkh;
}
