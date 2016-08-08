#include "includes.h"
#include "listener.h"
#include "arm_unicorn_data.h"
#include <unicorn/unicorn.h>
#define DEBUG 1

#define TTL 1024
/* Server. Listens for messages containing machine-code, executes */
/* them, and returns the resulting registers state. */

#define PORT 9999
#define TRANSMISSION_SIZE 0x1000 // how big can this be?

#define RET(x) (x == 0xC3)
#define READY(x) (x < 0)

#define DUMP 1

#define SEXP_LENGTH 256

#define YESORNO(x) (x? "yes":"no")

#define R4K(x) (x & ~(0xFFF)) // floor to nearest 4K

#define NOTE(x) if (DEBUG) fputs(x,stderr)
#define NOTEVAL(x,y) if (DEBUG) fprintf(stderr, x, y)
#define UNICORNMUST(com, str) if ((err = (com))) { uc_perror(str,err); exit(EXIT_FAILURE); }
#define UNICORNSHOULD(com,str) if ((err = (com))) { uc_perror(str,err);}

#define IMAGINARY_STACK_ADDR 0x1000 // a virgin address, ideally.
#define IMAGINARY_STACK_SIZE 0x1000 // why not?

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// IO-Related stuff
// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

/**
 * A bit of cut-and-pasta from Hacking: The Art of Exploitation
 **/
void fatal(char *message){
  char error_message[100];
  strcpy(error_message, "[!!] Fatal Error ");
  strncat(error_message, message, 83);
  perror(error_message);
  exit(EXIT_FAILURE);
}

// Dumps raw memory in hex byte and printable split format
// should put this somewhere else with other handy, general tools. 
void fdump(FILE *fp, const u8 *data_buffer, const u32 length){
  unsigned char byte;
  unsigned int i, j;

  char *shade = "";
  for (i=0; i < length; i++) {
    byte = data_buffer[i];
    fprintf(fp, "%02x ", data_buffer[i]); // Display byte in hex
    if (((i%16) == 15) || (i == length-1)){
      for (j=0; j <= 15-(i%16); j++) 
        fprintf(fp,"   ");
      fprintf(fp,"| ");
      for(j=(i-(i%16)); j <= i; j++) {
        
        // display printable bytes from line
        byte = data_buffer[j];
        if ((byte > 31) && (byte < 127)){
          fprintf(fp,"%c", byte);
        } else  
          fprintf(fp,".");
      }
      fprintf(fp,"\n"); // end of dump line (each line is 16 bytes)
    }// end if
  } // end for
}         

void uc_perror(const char *func, uc_err err) {
  if (DEBUG)
    fprintf(stderr, "Error in %s(): %s\n", func, uc_strerror(err));  
}

/**
 * Encodes the data provided as a lisp vector
 **/
u32 lisp_encode(u8 *vector, char *sexp){
  u32 vptr=0, length=0;
  // maximum length for sexp is 1 + 2 + (16+2)*7 + 7
  // #, parens, seven 64bit hex numbers, prefixed by #x, spaces
  // grand total of 135, plus a null character, so 137
  // vector is SYSREG_BYTES long. Bump it up to 256. More than we need
  memset(sexp, 0, SEXP_LENGTH);
  length += sprintf(sexp+length, "#(");
  // we should do something about this magic #. parameterize.
  // it's the # of registers we're tracking, btw. 
  for (vptr = 0; vptr < WORDSIZE * REGISTER_COUNT; vptr += WORDSIZE) {
    length += sprintf(sexp+length, "#x%x ",
                      bytes_to_integer(vector + vptr));
  }
  length --;
  length += sprintf(sexp+length, ")\n\0");
  NOTEVAL("SEXP: %s\n", sexp);
  return length;
}

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
// Unicorn initialization functions
// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

#define SIZE_OF_UC_ENGINE 0x1000 // faking it. probably a disaster. o
uc_engine *init_unicorn(uc_arch arch, uc_mode mode){
  uc_err err;
  uc_engine *uc;
  if(!(uc = malloc(SIZE_OF_UC_ENGINE))){
    fprintf(stderr, "Error allocating unicorn engine. Terminating.\n");
    exit(EXIT_FAILURE);
  }
  if ((err = uc_open(arch, mode, &uc))) {
    uc_perror("uc_open", err);
    return NULL;
  }
  return uc;
}

int kill_unicorn(uc_engine *uc){
  free(uc);
  return 0;
}

#define PERM_EXEC(x) (0x01 & x)
#define PERM_WRIT(x) (0x02 & x)
int map_memory(uc_engine *uc, u8 *bytes, size_t bytelength,
               u8 perms, u32 startat){
  uc_err err;
  u32 rounded_length = roundup(bytelength, 12); // must be 4k aligned
  // TODO: incorporate more restrictive permissions, by processing perms parameter

  UNICORNMUST(uc_mem_map(uc, R4K(startat), rounded_length, UC_PROT_ALL),
              "uc_mem_map in map_memory");
  NOTEVAL("Memory successfully mapped, starting at 0x%x.\n",
          R4K(startat));

  /* consider separating mapping and writing into two functions */
  UNICORNMUST(uc_mem_write(uc, startat, (void *) bytes, bytelength-1),
              "uc_mem_write in map_memory");
  NOTEVAL("Memory successfully written, from 0x%x ",
          startat);
  NOTEVAL("to 0x%x\n", startat+bytelength);
  return 0;
}


int init_stack(uc_engine *uc, uc_arch arch, uc_mode mode){
  uc_err err;
  int sp_val = IMAGINARY_STACK_ADDR;
  UNICORNMUST(uc_mem_map(uc, 0, 2*IMAGINARY_STACK_SIZE, UC_PROT_ALL),
              "uc_mem_map in init_stack");
  NOTEVAL("Mapped unicorn stack, from 0x%x\n",R4K(sp_val));
  return 0;
}

int set_stack(uc_engine *uc, uc_arch arch, uc_mode mode,
                      u8 *stack_bytes, u32 stack_bytes_len){
  int sp;
  uc_err err;
  int sp_val = IMAGINARY_STACK_ADDR;
  u64 *ptr;
  ptr = malloc(sizeof(u64));
  *ptr = sp_val;
  u8 *to_load;
  to_load = calloc(IMAGINARY_STACK_SIZE, sizeof(u8));
  memcpy(to_load, stack_bytes, stack_bytes_len);
  
  switch (arch) {
  case UC_ARCH_ARM :
    sp = UC_ARM_REG_R13;
    break;
  case UC_ARCH_X86 :
    sp = UC_X86_REG_RSP;
    break;
  default:
    fprintf(stderr,"Architecture unknown in reset_unicorn_stack()\n");
    exit(EXIT_FAILURE);
  }

  UNICORNMUST(uc_reg_write(uc, sp, (void *) ptr),
          "uc_reg_write in reset_unicorn_stack");
  NOTEVAL("Set stack pointer to %d.\n", *((u32 *)ptr));    
  UNICORNMUST(uc_mem_write(uc, sp_val, (void *) to_load, IMAGINARY_STACK_SIZE),
          "uc_mem_write in reset_unicorn_stack");

  if (DEBUG){
    fprintf(stderr, "Wrote data to stack, from 0x%x to 0x%x\n",
            R4K(sp_val), (R4K(sp_val) + IMAGINARY_STACK_SIZE));
    fdump(stderr, stack_bytes, stack_bytes_len);
  }

  free(ptr);
  if (DEBUG) display_stack(uc, 8);
  return 0;
}

/* #define MAKE_REG_PTRS(union_name, reg_vec_len, ptrs) \ */
/*   union union_name { \ */
/*     u32 words[reg_vec_len]; \ */
/*     u8 bytes[reg_vec_len * WORDSIZE]; \ */
/*   } union_name;  \ */
/*   void *ptrs[reg_vec_len];      \ */
/*   int ijkl___; \ */
/*   for (ijkl___ = 0; ijkl___ < reg_vec_len; ijkl___++) { \ */
/*     ptrs[ijkl___] = &(union_name.words[ijkl___]); \ */
/*   }  */


void hook_step(uc_engine *uc, void *user_data) {
  uc_err err;
  u32 *reg_vec, reg_vec_len;
  reg_vec = arm_32_reg_vec;
  reg_vec_len = arm_32_reg_vec_len;
  int pc;
  u32 inst;

  union regun {      
    u32 words[reg_vec_len]; 
    u8 bytes[reg_vec_len * WORDSIZE]; 
  } regun;

  void *ptrs[reg_vec_len];      
  int j; 
  for (j = 0; j < reg_vec_len; j++) { 
    ptrs[j] = &(regun.words[j]);      
  } 
  
  /* get pc */
  UNICORNSHOULD(uc_reg_read(uc, UC_ARM_REG_PC, &pc),
                "uc_reg_read in hook_step");

  /* now get the instruction at mem[pc] */
  
  UNICORNSHOULD(uc_mem_read(uc, pc, (void *) &inst, 4),
                "uc_mem_read in hook_step");

  UNICORNSHOULD(uc_reg_read_batch(uc, reg_vec, ptrs, reg_vec_len),
                "uc_reg_read_batch in hook_step");
  
  NOTEVAL("[ PC: %x ] ", pc);
  if (!err)
    NOTEVAL(": %8.8x\n", inst);
  else
    NOTE(" CANNOT READ\n");
  NOTE("R: #(");
  int i;
  for (i = 0; i < reg_vec_len; i++) {
    if (i != 0) NOTE(" ");
    NOTEVAL("%x", regun.words[i]);
  }
  NOTE(")\n");

  return;
}

/**
 * Pops the first address of the stack, and begins execution there. 
 * Subsequent POP {PC} instructions will fetch the remaining addresses from
 * the stack. 0 will *typically* send execution to address 0, which contains 0. 
 * This will lead to a NOP-loop that will run until the TTL is exhausted. 
 * This is an inelegant solution to programme termination, maybe, but it works. 
 * Address 0 should be made unwriteable, though. 
 **/
int hatch_stack(uc_engine *uc, u8 *result){
  if (!uc) {fprintf(stderr, "ENGINE NULL! ABORTING!\n"); exit(EXIT_FAILURE);}

  uc_err err;
  uc_hook _hook_step;
  /* seed the registers */

  u32 *reg_vec = arm_32_reg_vec;
  u32 reg_vec_len = arm_32_reg_vec_len;
  union seedvals {
    u32 words[reg_vec_len]; // wrinkle here: the word size should be dynamic
    u8 bytes[reg_vec_len * sizeof(word)];
  } seedvals;
  memcpy(&(seedvals.bytes), result, sizeof(seedvals));
  /* A bit of an abstraction: we use a specially-located stack for this. */
  seedvals.words[13] = IMAGINARY_STACK_ADDR;
  
  void *ptrs[reg_vec_len]; // -2 to avoid overwriting SP, LR?      
  int i;
  for (i = 0; i < reg_vec_len; i++) {
    ptrs[i] = &(seedvals.words[i]);
  }
  
  UNICORNMUST(uc_reg_write_batch(uc, reg_vec, ptrs, reg_vec_len),
          "uc_reg_write in hatch_stack");
  /* finished seeding registers */

  u64 *sp; // we'll only use half of this
  sp = calloc(1,sizeof(u64));

  UNICORNMUST(uc_reg_read(uc, UC_ARM_REG_SP, (void *) sp),
          "uc_reg_read in hatch_stack");
  
  u64 *start;
  start = malloc(sizeof(u64));
  UNICORNMUST(uc_mem_read(uc, *sp, start, 4),
          "uc_mem_read in hatch_stack");
  *sp += 4; // arch sensitive. word size. 
  UNICORNMUST(uc_reg_write(uc, UC_ARM_REG_SP, (void *) sp),
          "uc_reg_write in hatch_stack");
  
  /* Add a single-stepping hook if debugging */
  if (DEBUG){
    UNICORNMUST(uc_hook_add(uc, &_hook_step, UC_HOOK_CODE, hook_step, NULL, 1, 0, 0),
                "uc_hook_add single-step hook in hatch_stack");
  }

  NOTEVAL("START = %8.8x\n", *start);
  
  if ((err = (uc_emu_start(uc, *start, 0, 0, TTL)))){
    uc_perror("uc_emu_start in hatch_stack", err);
  }

  /* retrieve the register state */
  uc_reg_read_batch(uc, reg_vec, ptrs, reg_vec_len);
  
  /** for testing  **/
  if (DEBUG) {
    printf("REGISTERS: #(");
    for (i = 0; i < reg_vec_len; i++) {
      if (i != 0) printf(" ");
      printf("%8.8x", seedvals.words[i]);
    }
    printf(")\n");
  }
  /******************/
  memcpy(result, seedvals.bytes,
         (reg_vec_len * sizeof(u32)));
  
  if (DEBUG) display_stack(uc,8);

  return 0;
}
                       

/**
 * For debugging purposes: shows the current state of the stack, 
 * with two degrees of dereference.
 **/
int display_stack(uc_engine *uc, int depth){
  uc_err err;
  u64 *sp; // we'll only use half of this
  sp = calloc(1,sizeof(u64));
  
  UNICORNSHOULD(uc_reg_read(uc, UC_ARM_REG_SP, (void *) sp),
                "uc_reg_read in display_stack");
  u8 peek[4];
  u8 peek2[4];
  u32 i = 0;
  fprintf(stderr,"--------------------\n");
  for (i = 0; i < depth; i ++){
    UNICORNSHOULD(uc_mem_read(uc, (*sp)+(i*4), (void *) peek, 4),
                  "uc_mem_read in display_stack");
    
    fprintf(stderr,"%8.8x => %8.8x",
            (*sp)+(i*4), *((u32*)peek));
    err = uc_mem_read(uc, *((u32*)peek), (void *) peek2, 4);
    if (!err)
      fprintf(stderr, " ==> %8.8x\n", *((u32*)peek2));
    else
      fprintf(stderr, "\n");
  }
  return 0;
}


/**
 * Round up to the next nth power of two.
 **/
int roundup(int num, int shiftby){
  int i;
  for (i=1; i < num; i <<= shiftby);
  return i;
}

/**
 * Copy from one buffer to another. Update the number of bytes written so far.
 **/
u32 datacopy(u8 *databuffer, u8 *recvbuffer, u32 stackheight, u32 recvlength){
  u32 i;
  for (i = 0; i < recvlength; i++){
    databuffer[stackheight++] = recvbuffer[i];
  }
  return stackheight;
}


/************************************************************
  Header parsing macros
************************************************************/

#define BIT(n,x) (((u8) (1 << n) & (u8) *x) >> n)

#define SET_DATA(x) BIT(0,x)  //((0x01 & x[0]))
#define RESET_REG(x)  BIT(1,x) //((0x02 & x[0]) >> 1)
#define RESET_DATA(x) BIT(1,x) // we can overload this bit; contexts differ
#define FEEDBACK_SEXP(x) BIT(2,x) //((0x04 & x[0]) >> 2) // overloadable
#define ARCHFLAG(x) BIT(3,x) // ((0x08 & x[0]) >> 3)
#define RESERVED1(x) BIT(4,x) //((0x10 & x[0]) >> 4) // room for more arches
#define MODEFLAG(x) BIT(5,x) //(0x20 & x[0])  // 0 for arm/x86_64, 1 for thumb/i386
// we can overload MODEFLAG for architectures that only have one mode. 
#define EXECUTABLE(x) BIT(6,x) //(0x40 & x[0])
#define WRITEABLE(x) BIT(7,x) //(0x80 & x[0])
#define EXPECT(x) ((0xFF & x[1]) | ((0xFF & x[2]) << 8) | ((0xFF & x[3]) << 16))
#define STARTAT(x)  ((0xFF & x[4]) |  ((0xFF & x[5]) << 8) |            \
                     ((0xFF & x[6]) << 16) | ((0xFF & x[7]) << 24)) 
#define HEADERLENGTH 8 // bytes

/**
 * Initialize the socket that the listener is going to use.
 **/
u32 init_socket(u16 port, struct sockaddr_in *srv_addr){

  u32 sockfd, yes_reuse_the_socket=1;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    fatal("in socket");

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes_reuse_the_socket,
                 sizeof(u32)) == -1)
    fatal("setting socket option SO_REUSEADDR");

  srv_addr->sin_family = AF_INET;   // host byte order
  srv_addr->sin_port = htons(port); // short, network byte order
  srv_addr->sin_addr.s_addr = 0;    // automatically fill with my ip address

  memset(&(srv_addr->sin_zero), '\0', 8); // zero out the rest of the struct

  if (bind(sockfd, (struct sockaddr *)srv_addr, sizeof(struct sockaddr)) == -1)
    fatal("binding to socket");

  if (listen(sockfd, 5) == -1)
    fatal("listening on socket");

  return sockfd;
}


/**
 * The main workhorse of the ontoserver. Listen for incoming packets, 
 * decode the header, populate memory space, and kick off execution from
 * incoming stacks. 
 **/
u32 hatch_listener(u16 port, char *allowed_ip){

  u32 sockfd, new_sockfd, recvlength=1;
  socklen_t sin_size;
  uc_engine *engine = NULL;
  u8 *buffer = malloc(TRANSMISSION_SIZE);
  u8 *databuffer = NULL;
  u32 datalength = 0;
  u8 *result;
  char *sexp;
  u32 stackheight, actual_sexp_length;
  int unauth_count = 0;
  int max_unauth = 100;
  int result_buffer_size = (REGISTER_COUNT + 1) * sizeof(u32); // make flexible
  int any_ip = !strncmp(allowed_ip, "any", 3); // boolean flag
  
  /*** Data to extract from the header ***/
  /* Consider putting this into a struct, if it ever needs to be
   * passed around from func to func (when refactoring...)
   */
  u8 initflag = 1, reset_data, set_data, reset_reg, feedback_sexp,
    archflag, modeflag, executable, writeable;
  u32 expect, startat;
  uc_arch arch;
  uc_mode mode;
  
  result = calloc(1,result_buffer_size);
  sexp = malloc(SEXP_LENGTH);
  sin_size = sizeof(struct sockaddr_in);

  /* initialize the socket */
  struct sockaddr_in srv_addr, cli_addr;
  sockfd = init_socket(port, &srv_addr);  
  while (1) {
  restart:
    if ((new_sockfd = accept(sockfd, (struct sockaddr *) &cli_addr,
                             &sin_size)) < 0){
      fatal("accepting connection");
    }
    char *client_ip = inet_ntoa(cli_addr.sin_addr);
    if (DEBUG) printf("SERVER: ACCEPTED CONNECTION "
                      "FROM %s, PORT %d\n",
                      client_ip, ntohs(cli_addr.sin_port));
    if (!any_ip && strncmp(client_ip, allowed_ip, 0xF)){
      fprintf(stderr, "UNAUTHORIZED CONNECTION ATTEMPTED. %d SO FAR.",
              ++unauth_count);
      if (unauth_count > max_unauth){
        fprintf(stderr, " TERMINATING!\n");
        exit(EXIT_FAILURE);
      } else {
        fprintf(stderr," %d CHANCES LEFT\nAND THEN I TURN YOU INTO A GOON.\n",
                max_unauth - unauth_count);
        close(new_sockfd);
        goto restart;
      }  
    } // end of saftey check

    /** Get the first packet **/
    NOTE("Awaiting connection...\n");
    recvlength = recv(new_sockfd, buffer, TRANSMISSION_SIZE, 0);
    stackheight = 0;
    while (recvlength > 0) {
      NOTEVAL("RECVLENGTH = %d\n", recvlength);
      NOTEVAL("INITFLAG = %d\n", initflag);
      if (initflag && recvlength >= HEADERLENGTH){
        /* If the stack hasn't been built yet, then we must be at the beginning
         * of the packet. So read the header, and parse it. 
         */
        if (DEBUG) {
          printf("HEADER: %d bytes\n", HEADERLENGTH);
          fdump(stderr, buffer, HEADERLENGTH);
        }

        /******************************
         * Extract header information *
         ******************************/
        set_data = SET_DATA(buffer);
        // note: RESET_DATA and RESET_REG overload the same bit
        reset_data = set_data? RESET_DATA(buffer):0;
        reset_reg = set_data? 0:RESET_REG(buffer);
        // so that's why I have the ternary conditional ops there
        feedback_sexp = FEEDBACK_SEXP(buffer);
        archflag = ARCHFLAG(buffer);
        modeflag = MODEFLAG(buffer);
        executable = EXECUTABLE(buffer);
        writeable = WRITEABLE(buffer);
        expect = EXPECT(buffer);
        startat = STARTAT(buffer);

        if (DEBUG){
          fprintf(stderr,
                  "RECVLENGTH = %d\n" "EXPECT = %d\n" "SET_DATA = %s\n"
                  "RESET_DATA = %s\n" "RESET_REG = %s\n" "FEEDBACK_SEXP = %s\n"
                  "ARCHFLAG = %d\n" "MODEFLAG = %d\n" "EXECUTABLE = %s\n"
                  "STARTAT = 0x%x\n",
                  recvlength, expect, YESORNO(set_data), YESORNO(reset_data),
                  YESORNO(reset_reg), YESORNO(feedback_sexp), archflag,
                  modeflag, YESORNO(executable), startat);
        }

        /* Time to allocate the databuffer. */
        /* This is an attack vector, since we're trusting the user
         * to accruately report the size of the data in the expect field.
         * so a safeguard should be implemented.
         */
        databuffer = calloc(sizeof(u8), expect);

        switch (archflag) {
        case 0:
          arch = UC_ARCH_X86;
          mode = UC_MODE_64;
          break;
        case 1:
          arch = UC_ARCH_ARM;
          mode = UC_MODE_ARM;
          break;
        default:
          fprintf(stderr, "UNRECOGNIZED ARCH IN HEADER.\n");
          exit(EXIT_FAILURE);
        }

        if (reset_data){
          if (engine){
            NOTE("Freeing old engine.");
            free(engine);
          }
          engine = init_unicorn(arch, mode);
          init_stack(engine, arch, mode);
        }
        
        /* Reset the result/seed register array. */
        if (reset_reg){
          memset(result, 0, result_buffer_size);
        }
        initflag = 0;
        recvlength -= HEADERLENGTH;
      } // End of header section. 
      NOTEVAL("INITFLAG = %d\n", initflag);
      NOTEVAL("AFTER HEADER, RECVLENGTH = %d\n", recvlength);

      /* If RESET_DATA is 0, then we assume you're loading the stack. */
      /* If RESET_DATA is 1, then incoming bytes are loaded into the */
      /* other areas of memory. */

      if (set_data){ /* Load the rest of memory, destined for the unicorn*/
        NOTE("Loading data into transient buffer...\n");
        if (recvlength + datalength <= expect){ // safeguard
          datalength = datacopy(databuffer, buffer + HEADERLENGTH,
                                datalength, recvlength);
        }
      } else { /* Load the stack. */ // if not set_data
        NOTE("Loading the stack...\n");
        if (recvlength + stackheight <= expect){
          stackheight = datacopy(databuffer, buffer + HEADERLENGTH,
                                 stackheight, recvlength);
        }
      }
      
      if (set_data){
        NOTEVAL("DATA SIZE: %d\n", datalength);
        //if (DEBUG) fdump(stderr, databuffer, datalength);
      } else {
        NOTEVAL("STACK HEIGHT: %d\n",stackheight);
        if (DEBUG) fdump(stderr, databuffer, stackheight);
      }
                
      /* There are two modes: load memory (rodata, text, etc.), or load stack */
      /* They are differentiated by the reset flag */
      /* We can use the same databuffer to transiently hold the data. */
      /* expect has different meanings, somewhat, depending on the context */
      
      /*************************************************************
       * When the stack is ready, we commence execution. But we know this
       * won't happen until after the memory space is loaded, if it's being
       * loaded, because so long as reset_data is lit, stackheight remains at 0. 
       */
      
      NOTEVAL("DATALENGTH: %d", datalength);
      NOTEVAL(" / EXPECT: %d\n", expect);

      /* If we are setting data, and have collected all the expected bytes
       */
      if (set_data && (datalength >= expect)) {
        if (DEBUG){
          fprintf(stderr, "FINISHED RECEIVING DATA:\n");
          //fdump(stderr, databuffer, datalength);
        }
        u8 perms = executable | (writeable << 1) | (1 << 2);
        if (DEBUG) fprintf(stderr, "About to map memory...\n");
        map_memory(engine, databuffer, datalength, perms, startat);
        send(new_sockfd, "Ready", 5, 0);
        free(databuffer);
        recvlength = 0;
        datalength = 0;
        expect = 0;
        initflag = 1;
        break;
      }/*=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
      /* Or, if we are collecting the stack, and have received all 
       * expected bytes.
       *-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=*/
      else if (stackheight >= expect) {
        if (DEBUG){
          fprintf(stderr, "FINISHED RECEIVING STACK:\n");
          fdump(stderr, databuffer, stackheight);
        }
        /* First, check to make sure uc isn't NULL. If it is, init it. */
        if (!engine){ 
          NOTE("Unicorn engine not yet initialized. Doing so now.\n");
          engine = init_unicorn(arch, mode);
        }
        /* Here, we copy the stack over into unicorn memory */
        set_stack(engine, arch, mode, databuffer, stackheight);
        /***** THE EXECUTION ROUTINE IS CALLED FROM HERE ******/
        hatch_stack(engine, result);
        /* if symbolic expression feedback requested */
        if (feedback_sexp){ 
          actual_sexp_length = lisp_encode(result,sexp);
          send(new_sockfd, sexp, actual_sexp_length, 0);
        } else {
          send(new_sockfd, "Ok", 2, 0);
        }
        free(databuffer);
        recvlength = 0;
        datalength = 0;
        expect = 0;
        initflag = 1;
        break;
      }
        
      // the else is implicit...
        
      /* If neither the data or the stack is ready to be loaded into
       * its respective data structure, just keep on receiving bytes
       */

      // a buffer overflow is happening  here!
      recvlength = recv(new_sockfd, buffer, TRANSMISSION_SIZE, 0);
      if (recvlength < 0){
        fprintf(stderr,"Error in socket %d. Reporting recvlength of %d.\n",
                new_sockfd, recvlength);
        exit(EXIT_FAILURE);
      }
      NOTE("===================================================================\n");

    }  // end while (recvlength > 0)
    close(new_sockfd);
  }
  printf("~ The end. ~\n");
  free(databuffer);
  free(result);
  free(sexp);
  kill_unicorn(engine);
}


int main(int argc, char **argv){
  /*
   * TODO: parse command line options to select architecture
   * and virtualization vs baremetal options
   */
  char opt;
  u32 port = 9999;
  char allowed_ip[0x10] = "any";
  if (argc < 2)
    goto noopts;
  while ((opt = getopt(argc, argv, "p:v:i:")) != -1){
    switch (opt) {
    case 'v':
      printf("verification not yet implemented.\n");
      break;
    case 'p':
      sscanf(optarg, "%d",&port);
      break;
    case 'i':
      printf("Setting allowed ip to %s\n", optarg);
      strncpy(allowed_ip, optarg, 0xF);
      break;
    case 'h':
    default:
      fprintf(stderr,"TODO: write help documentation.\n");
    }
  }
 noopts:
            
  
  printf("************************************************************\n"
         "*                     READY TO SERVE...                    *\n"
         "* Send machine code to be executed to port %4d.           *\n"
         "* This is not a secure service. Run this on an insecure    *\n"
         "* network, and you *will* be pwned.                        *\n"
         "************************************************************\n", port);
  hatch_listener(port, allowed_ip);
  
  return 0;
}



/**
 * Todo: 
 * - place hooks in hatch_stack, to see what's going on in exec
 * - double check register setting. seems corrupt. 
 * - complete and polish stack based execution. 
 * - once that's ready, the adjustments needed on the phylo end should be trivial
 * - write defcon paper!
 */


/* Current bug: mapping, say, rodata or bss after text erases text, and vice versa. 
 */

/**
 * Todo:
 * tweak header protocol. first packet should be to set initial requirements
 * -- how much space do you need? from where to where?
 * -- then do all mapping at once. 
 * -- dissociate mapping from writing. 
 * -- there will be a header marking for "this is an init packet"
 * -- there will be a lisp function that does nothing but send an init packet. 
 * -- then will come data packets for rodata, text, etc. 
 * -- then, once all that is done, will come the onslaught of stack packets. 
 */
 
