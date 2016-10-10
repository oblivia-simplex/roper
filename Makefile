C_DIR = src/c/


.PHONY: all clean


all:	$(C_DIR)*.[ch]
	cd $(C_DIR) && make

clean:
	cd $(C_DIR) && make clean
