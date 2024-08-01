CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lssl -lcrypto -lcheck

all: main test

main: main.o
	$(CC) -o main main.o $(LIBS)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

test: main test_main.o
	$(CC) -o test_main test_main.o main.o $(LIBS)

test_main.o: test_main.c
	$(CC) $(CFLAGS) -c test_main.c

clean:
	rm -f *.o main test_main

