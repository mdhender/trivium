#include "trivium.h"
#include <string.h> /* for memmove */

unsigned char
Trivium_TwiddleByte(TriviumState *state, unsigned char byte)
{
	/* twiddle the byte */
	TriviumBuffer tb;
	tb.srcLength = 1;
	tb.src       = &byte;
	tb.dst       = &byte;
	Trivium_TwiddleBuffer(state, &tb);

	return byte;
}
