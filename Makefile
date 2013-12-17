.PHONY: all clean

OBJS=des.o \
my_test.o

CC=gcc
CFLAGS=-O0 -g -I.

TARGET=des_test

des.o: des.c
	$(CC) $(CFLAGS) -c -o $@ $<

my_test.o: my_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): $(OBJS) 
	$(CC) -o $@ $(OBJS)

all: $(TARGET)

clean:
	rm -rf *.o $(TARGET)

