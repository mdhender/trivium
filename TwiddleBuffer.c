#include "trivium.h"

void
Trivium_TwiddleBuffer(TriviumState *state, TriviumBuffer *tb)
{
  int srcLength = tb->srcLength;

  unsigned char *src = tb->src;
  unsigned char *dst = tb->dst ? tb->dst : tb->src;

  /* use the key stream to twiddle the buffer */
  for (; srcLength > 0; srcLength--) {
    /*
     * twiddle the source byte using the PRNG stream
     */
    *(dst++) = *(src++) ^ Trivium_StirState(state);
  }
}
