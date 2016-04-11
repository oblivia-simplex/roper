
CC = gcc
CFLAGS = -fPIC -Wall -O0 
LDFLAGS = -shared
STACKFLAGS = -zexecstack -fno-stack-protector

AS = as
LD = ld

ASFLAGS =
#BINLDFLAGS = -Ttext 200000 --oformat binary

BUILD_DIR = ../build/

ARCH=$(shell uname -m)
ifeq ($(ARCH),armv6l)
EXAMPLE = example.arm.s
else
EXAMPLE = example.x86.s
endif


ELFCODE = example.elf
FLATBIN = example.bin
EXAMPLE_HEADER = example.h

DUMP = xxd
DUMPFLAGS = -i


LIB = $(BUILD_DIR)libhatchery.so
SOURCES = hatchery.c 
HEADERS = hatchery.h includes.h
TEST = $(BUILD_DIR)test
TESTSRC = main.c example.h
SERVER = $(BUILD_DIR)hatchsock



.PHONY: dump clean dotest make_build_dir all debug

all: $(LIB) $(TEST) $(FLATBIN) $(EXAMPLE_HEADER) $(SERVER)




clean:
	rm *.elf *.bin
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)


$(LIB): hatchery.o
	$(CC) $(CFLAGS) $(SOURCES) -o $@ $(LDFLAGS) $(STACKFLAGS)
#	rm hatchery.o

$(ELFCODE): $(EXAMPLE)
	$(AS) $(ASFLAGS) $(EXAMPLE) -o $(ELFCODE)

$(FLATBIN): $(ELFCODE) 
	objcopy -O binary example.elf example.bin

$(EXAMPLE_HEADER): $(FLATBIN)
	  $(DUMP) $(DUMPFLAGS) $(FLATBIN) | tee $(EXAMPLE_HEADER)


$(TEST): $(LIB) $(TESTSRC) $(EXAMPLE_HEADER)
	$(CC) -L $(BUILD_DIR) -lhatchery main.c -o $(TEST) $(STACKFLAGS)


$(SERVER): $(LIB) $(SOURCES) $(HEADERS) hatchsock.c
	$(CC) -L $(BUILD_DIR) -lhatchery hatchsock.c -o $(SERVER) $(STACKFLAGS)


dotest:
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH:." $(TEST)



