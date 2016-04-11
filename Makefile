C_DIR = c/


.PHONY: all clean


all:	c/*.[ch]
	cd $(C_DIR) && make

clean:
	cd $(C_DIR) && make clean
