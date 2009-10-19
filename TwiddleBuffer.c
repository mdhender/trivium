#include "trivium.h"

TriviumBuffer *
Trivium_TwiddleBuffer(TriviumState *state, TriviumBuffer *tb)
{
  if (state && tb && tb->src) {
    int srcLength = tb->srcLength;

    unsigned char *src = tb->src;
    unsigned char *dst = tb->dst ? tb->dst : tb->src;

    /* use the key stream to twiddle the buffer */
    for (; srcLength > 0; srcLength--) {

      /* twiddle the source byte using the key stream */
      *(dst++) = *(src++) ^ Trivium_StirState(state);
    }
  }

  return tb;
}
