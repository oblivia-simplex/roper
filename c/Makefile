
CC = gcc
CFLAGS = -fPIC -Wall -O0 -g

LDFLAGS += $(shell pkg-config --libs glib-2.0) -lpthread -lm -lunicorn
STACKFLAGS = -zexecstack -fno-stack-protector

AS = as
LD = ld

ASFLAGS =
#BINLDFLAGS = -Ttext 200000 --oformat binary

X86_AS=$(AS)

BUILD_DIR = ../build/

#ARCH=$(shell uname -m)
#ifeq ($(ARCH),armv6l)
ARM_EXAMPLE = example.arm.s
#else
X86_EXAMPLE = example.x86.s
#endif

ARM_PREFIX=arm-none-eabi-
ARM_AS=$(ARM_PREFIX)$(AS)



X86_ELFCODE = example.x86.elf
X86_FLATBIN = example.x86.bin

ARM_ELFCODE=example.arm.elf
ARM_FLATBIN=example.arm.bin


EXAMPLE_HEADER = example.h

DUMP = xxd
DUMPFLAGS = -i


LIB1 = $(BUILD_DIR)libhatchery.so
LIB2 = $(BUILD_DIR)libemhatchery.so
SOURCES = hatchery.c 
HEADERS = hatchery.h includes.h
TEST = $(BUILD_DIR)test
TESTSRC = main.c example.h
SERVER = $(BUILD_DIR)hatchsock



.PHONY: dump clean dotest make_build_dir all debug

all: $(LIB1) $(LIB2) $(TEST) $(X86_FLATBIN) $(ARM_FLATBIN) $(EXAMPLE_HEADER) $(SERVER)
	bash -c	"source ../aliases.rc"

clean:
	rm *.elf *.bin
	rm -rf $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)


$(LIB1): hatchery.o
	$(CC) $(CFLAGS) hatchery.c -o $@ -shared $(LDFLAGS) $(STACKFLAGS)

$(LIB2): emhatchery.o
	$(CC) $(CFLAGS) emhatchery.c -o $@ -shared $(LDFLAGS) 
#	rm hatchery.o

$(X86_ELFCODE): $(X86_EXAMPLE)
	$(X86_AS) $(X86_ASFLAGS) $(X86_EXAMPLE) -o $(X86_ELFCODE)

$(X86_FLATBIN): $(X86_ELFCODE) 
	objcopy -O binary $(X86_ELFCODE) $(X86_FLATBIN)

$(ARM_ELFCODE): $(ARM_EXAMPLE)
	$(ARM_AS) $(ARM_ASFLAGS) $(ARM_EXAMPLE) -o $(ARM_ELFCODE)

$(ARM_FLATBIN): $(ARM_ELFCODE)
	$(ARM_PREFIX)objcopy -O binary $(ARM_ELFCODE) $(ARM_FLATBIN)

$(EXAMPLE_HEADER): $(X86_FLATBIN)
	  $(DUMP) $(DUMPFLAGS) $(X86_FLATBIN) | tee $(EXAMPLE_HEADER)


$(TEST): $(LIB1) $(LIB2) $(TESTSRC) $(EXAMPLE_HEADER)
	$(CC) -L $(BUILD_DIR) -lemhatchery -lhatchery main.c -o $(TEST) $(STACKFLAGS)


$(SERVER): $(LIB1) $(LIB2) $(SOURCES) $(HEADERS) hatchsock.c
	$(CC) -L $(BUILD_DIR) -lemhatchery -lhatchery hatchsock.c -o $(SERVER) $(STACKFLAGS) $(LDFLAGS)


dotest:
	LD_LIBRARY_PATH="$LD_LIBRARY_PATH:." $(TEST)



