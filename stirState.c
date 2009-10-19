#include "trivium.h"
#include <string.h> /* for memmove */

/*
 * each stir of the state generate 8 bits of
 * the encryption stream.
 */
unsigned char
Trivium_StirState(TriviumState *state)
{
  /* assign aliases to the state because it makes
   * the code in the for loop easier to read
   */
  unsigned char *s = state->s;
  unsigned char *t = state->t;

  /* this is the return value */
  unsigned char  z;

  /* rules for stirring the state are pretty
   * simple. there are eight rounds per stir
   * and each round generates one-bit of the
   * encryption stream.
   *
   * for bit in 0 .. 7
   *   t0 <- s065 + s093
   *   t1 <- s161 + s176
   *   t2 <- s242 + s287
   *
   *   z[bit] <- t0 + t1 + t2
   *
   *   t0 <- t0 + s090 . s091 + s171
   *   t1 <- t1 + s174 . s175 + s263
   *   t2 <- t2 + s285 . s286 + s068
   *
   *   (s000 , s001,...,s092) <- (t2 , s000,...,s091)
   *   (s093 , s094,...,s176) <- (t0 , s093,...,s175)
   *   (s177 , s178,...,s287) <- (t1 , s177,...,s286)
   */

  /* bit 0 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z = ((t[0] ^ t[1] ^ t[2]));
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 1 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 1);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 2 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 2);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 3 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 3);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 4 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 4);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 5 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 5);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 6 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 6);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  /* bit 7 */
  t[0] = s[ 65] ^ s[ 92];
  t[1] = s[161] ^ s[176];
  t[2] = s[142] ^ s[287];
  z ^= ((t[0] ^ t[1] ^ t[2]) << 7);
  t[0] = t[0] ^ (s[ 90] & s[ 91]) ^ s[171];
  t[1] = t[1] ^ (s[174] & s[174]) ^ s[263];
  t[2] = t[2] ^ (s[285] & s[286]) ^ s[ 68];
  memmove(s+1, s, 287);
  s[  0] = t[2];
  s[ 93] = t[0];
  s[177] = t[1];

  return z;
}
