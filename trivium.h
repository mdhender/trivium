#ifndef    TMdh_Trivium_H
#define    TMdh_Trivium_H

/*------------------------------------------------------------------------
 * you will need to create a key hash in order to initialize the state.
 * once you have done that, you may use Twiddle to encrypt/decrypt data.
 */
struct TMdh_Trivium_State {
	unsigned char t[  3]; /* t0 .. t2   */
	unsigned char s[288]; /* s0 .. s287 */
};
typedef struct TMdh_Trivium_State TriviumState;

/*------------------------------------------------------------------------
 * you only need to create a key if you are going to use the supplied
 * key hash function.
 */
struct TMdh_Trivium_Key {
	int            keyLength;
	unsigned char *key;
};
typedef struct TMdh_Trivium_Key TriviumKey;

/*------------------------------------------------------------------------
 * you will need to populate the key hash with 80 bits of data before you
 * can create a state.
 */
struct TMdh_Trivium_KeyHash {
	unsigned char  keyHash[10];
};
typedef struct TMdh_Trivium_KeyHash TriviumKeyHash;

/*------------------------------------------------------------------------
 * note that if the buffer destination is zero, then the source will be
 * updated directly.
 */
struct TMdh_Trivium_Buffer {
	int            srcLength;
	unsigned char *src;
	unsigned char *dst;
};
typedef struct TMdh_Trivium_Buffer TriviumBuffer;

/*------------------------------------------------------------------------
 * Usage:
 *    Populate a Key.
 *    Use the Key to create an 80 bit KeyHash.
 *    Use the KeyHash to create a State.
 *    Use the State and a Buffer to encrypt/decrypt data.
 */
TriviumKeyHash *Trivium_KeyHash(TriviumKeyHash *tkh, TriviumKey *tk);
TriviumState   *Trivium_Init(TriviumState *ts, TriviumKeyHash *tkh);
TriviumBuffer  *Trivium_TwiddleBuffer(TriviumState *ts, TriviumBuffer *tb);
unsigned char   Trivium_TwiddleByte(TriviumState *ts, unsigned char b);

#endif  /* TMdh_Trivium_H */
