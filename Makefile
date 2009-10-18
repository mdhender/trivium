testme: testme.o Init.o KeyHash.o TwiddleBuffer.o TwiddleByte.o
	gcc -o testme testme.o Init.o KeyHash.o TwiddleBuffer.o TwiddleByte.o

Init.o: Init.c trivium.h

KeyHash.o: KeyHash.c trivium.h

testme.o: testme.c trivium.h

TwiddleBuffer.o: TwiddleBuffer.c trivium.h

TwiddleByte.o: TwiddleByte.c trivium.h

clean:
	rm -f testme
	rm -f Init.o KeyHash.o testme.o TwiddleBuffer.o TwiddleByte.o

