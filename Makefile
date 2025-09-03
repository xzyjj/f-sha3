CC = gcc
CFLAGS = -O1 -g -std=c99 -Wall -Wextra -Wpedantic -Wshadow \
	-Wno-format-pedantic -Wno-trigraphs -fno-builtin \
	-fno-inline-functions -finline-hint-functions
RM = rm

PROGRAMS = test_sha3_stream test_sha3_256_stream test_sha3_512_stream
C_SOURCES = sha3_fast.c
C_OBJECTS = $(C_SOURCES:.c=.o)

.PHONY: all
all: $(PROGRAMS)

test_sha3_stream: $(C_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ test_sha3_stream.c

test_sha3_256_stream: $(C_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ test_sha3_256_stream.c

test_sha3_512_stream: $(C_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^ test_sha3_512_stream.c

.PHONY: clean
clean:
	$(RM) -f $(C_OBJECTS) $(PROGRAMS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^
