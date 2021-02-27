all: madness.c
	$(CC) madness.c -o madness -lcrypto

debug: madness.c
	$(CC) -g madness.c -o madness -lcrypto

clean:
	$(RM) madness
