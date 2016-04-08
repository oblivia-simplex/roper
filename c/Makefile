CC = gcc
CFLAGS = -fPIC -Wall -O0 
LDFLAGS = -shared
STACKFLAGS = -zexecstack -fno-stack-protector

AS = as
LD = ld

ASFLAGS =
BINLDFLAGS = -Ttext 200000 --oformat binary

ELFCODE = example.elf
FLATBIN = example.bin
EXAMPLE = example.s
EXAMPLE_HEADER = example.h

DUMP = xxd
DUMPFLAGS = -i


LIB = libhatchery.so
SOURCES = hatchery.c 
HEADERS = hatchery.h includes.h
TEST = test
TESTSRC = main.c example.h
OBJECTS = $(SOURCES:.c=.o)
SERVER = hatchsock


.PHONY: dump clean dotest all

all: $(LIB) $(TEST) $(FLATBIN) $(EXAMPLE_HEADER) $(SERVER)

clean:
	rm -f $(OBJECTS) $(LIB) $(TEST) $(FLATBIN) $(ELFCODE) $(EXAMPLE_HEADER)

$(LIB): $(OBJECTS)
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`"
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS) $(STACKFLAGS)


$(ELFCODE): $(EXAMPLE)
	$(AS) $(ASFLAGS) $(EXAMPLE) -o $(ELFCODE)

$(FLATBIN): $(ELFCODE)
	$(LD) $(BINLDFLAGS) $(ELFCODE) -o $(FLATBIN)

$(EXAMPLE_HEADER): $(FLATBIN)
	  $(DUMP) $(DUMPFLAGS) $(FLATBIN) | tee $(EXAMPLE_HEADER)


$(TEST): $(LIB) $(TESTSRC) $(EXAMPLE_HEADER)
	$(CC) -L `pwd` -lhatchery main.c -o test $(STACKFLAGS)

$(SERVER): $(LIB) $(SOURCES) $(HEADERS) hatchsock.c
	$(CC) -L `pwd` -lhatchery hatchsock.c -o $(SERVER) $(STACKFLAGS)

dotest:
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH:`pwd`" ./test



