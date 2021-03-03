CFLAGS = -Wall -Wextra -pedantic -std=c99
LIBS = -lcrypto

madness: madness.o
	$(CC) $^ -o $@ $(LIBS)

madness.o: madness.c
	$(CC) $(CFLAGS) -c $^ -o $@

debug: madness.c
	$(CC) $(CFLAGS) -g madness.c -o madness -lcrypto

clean:
	$(RM) *.o madness
