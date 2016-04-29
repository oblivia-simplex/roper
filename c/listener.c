#include "includes.h"
#include <unicorn/unicorn.h>
#define DEBUG 1

/* Server. Listens for messages containing machine-code, executes */
/* them, and returns the resulting registers state. */

#define PORT 9999
#define TRANSMISSION_SIZE 0x10000 // how big can this be?

#define RET(x) (x == 0xC3)
#define READY(x) (x < 0)

#define DUMP 1
//#define MAX_CODE_SIZE 0x10000
#define SEXP_LENGTH 256

#define YESORNO(x) (x? "yes":"no")


/************************************************************
  Header parsing macros
 ************************************************************/

#define BIT(n,x) (((u8) (1 << n) & (u8) x) >> n)

#define RESET_DATA(x) BIT(0,x)  //((0x01 & x[0]))
#define RESET_REG(x)  BIT(1,x) //((0x02 & x[0]) >> 1)
#define FEEDBACK_SEXP(x) BIT(2,x) //((0x04 & x[0]) >> 2)
#define ARCHFLAG(x) BIT(3,x) // ((0x08 & x[0]) >> 3) //? UC_ARCH_ARM : UC_ARCH_X86) // just return boolean
#define RESERVED1(x) BIT(4,x) //((0x10 & x[0]) >> 4) // room for more arches
#define MODEFLAG(x) BIT(5,x) //(0x20 & x[0])  // 0 for arm/x86_64, 1 for thumb/i386
#define EXECUTABLE(x) BIT(6,x) //(0x40 & x[0])
#define WRITEABLE(x) BIT(7,x) //(0x80 & x[0])
#define EXPECT(x) ((0xFF & x[1]) | ((0xFF & x[2]) << 8) | ((0xFF & x[3]) << 16))
#define STARTAT(x)  ((0xFF & x[4]) |  ((0xFF & x[5]) << 8) |            \
                     ((0xFF & x[6]) << 16) | ((0xFF & x[7]) << 24)) 
#define HEADERLENGTH 8 // bytes

// init engine
// map memory by request
// can we do some sort of cow? or track changes so that we can quickly undo?
// build up to that, perhaps. for now, just mark large tainted sections.
// no need to refresh rodata, e.g.


/**
 * A bit of cut-and-pasta from Hacking: The Art of Exploitation
 **/
void fatal(char *message){
  char error_message[100];
  strcpy(error_message, "[!!] Fatal Error ");
  strncat(error_message, message, 83);
  perror(error_message);
  exit(-1);
}


//Dumps raw memory in hex byte and printable split format
// should put this somewhere else with other handy, general tools. 
void fdump(FILE *fp, const unsigned char *data_buffer, const unsigned int length){
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


void uc_perror(const char *func, uc_err err)
{
  if (DEBUG)
    fprintf(stderr, "Error in %s(): %s\n", func, uc_strerror(err));  
}

// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=


u32 lisp_encode(unsigned char *vector, char *sexp){
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

  if (DEBUG) printf("SEXP: %s\n", sexp);
  
  return length;
}

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

#define R4K(x) (x & ~(0xFFF))

#define IMAGINARY_STACK_ADDR 0x1000 // a virgin address, ideally.
#define IMAGINARY_STACK_SIZE 0x1000 // why not?
int reset_unicorn_stack(uc_engine *uc, uc_arch arch, uc_mode mode,
                        u8 *stack_bytes, u32 stack_bytes_len){
  int sp;
  uc_err err;
  int sp_val = IMAGINARY_STACK_ADDR;
  void *ptr = (void *) &sp_val;
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
  if ((err = uc_reg_write(uc, sp, ptr))){
    uc_perror("uc_reg_write",err);
    fprintf(stderr,"Error setting stack pointer.\n");
    exit(EXIT_FAILURE);
  }
  if (DEBUG)
    fprintf(stderr, "Set stack pointer to %d.\n", *((u32 *)ptr));

  if ((err = uc_mem_map(uc, R4K(sp_val), IMAGINARY_STACK_SIZE, UC_PROT_ALL))){
    uc_perror("uc_mem_map", err);
    exit(EXIT_FAILURE);
  }
  
  if ((err = uc_mem_write(uc, sp_val, (void *) stack_bytes, stack_bytes_len))){
    uc_perror("uc_mem_write",err);
    fprintf(stderr,"Error writing to stack.\n");
    exit(EXIT_FAILURE);
  }
  if (DEBUG){
    fprintf(stderr, "Wrote data to stack:\n");
    fdump(stderr, stack_bytes, stack_bytes_len);
  }
  return 0;
}

int roundup(int num, int shiftby){
  int i;
  for (i=1; i < num; i <<= shiftby);
  return i;
}


#define PERM_EXEC(x) (0x01 & x)
#define PERM_WRIT(x) (0x02 & x)
int map_memory(uc_engine *uc, u8 *bytes, size_t bytelength,
               u8 perms, u32 startat){
  uc_err err;
  u32 rounded_length = roundup(bytelength, 0x1000); // must be 4k aligned
  // TODO: incorporate more restrictive permissions, by processing perms parameter
  if ((err = uc_mem_map(uc, R4K(startat), rounded_length, UC_PROT_ALL))){
    uc_perror("uc_mem_map", err);
    return -1;
  }
  if (DEBUG)
    fprintf(stderr, "Memory successfully mapped.\n");
  if ((err = uc_mem_write(uc, startat, (void *) bytes, bytelength-1))){
    uc_perror("uc_mem_write", err);
    return -2;
  }
  if (DEBUG)
    fprintf(stderr, "Memory successfully written.\n");
  return 0;
}


u32 datacopy(u8 *databuffer, u8 *recvbuffer, u32 stackheight, u32 recvlength){
  u32 i;
  for (i = 0; i < recvlength; i++){
    databuffer[stackheight++] = recvbuffer[i];
  }
  return stackheight;
}


u32 stack_listener(u32 port, char *allowed_ip){

  u8 any_ip; // boolean flag

  if (!strncmp(allowed_ip, "any", 3)){
    printf("Accepting connections from any ip.\n");
    any_ip = 1;
  }
  u32 sockfd, new_sockfd, yes=1, recvlength=1;
  // move to other header vars


  socklen_t sin_size;
  u8 *buffer = malloc(TRANSMISSION_SIZE);
  struct sockaddr_in srv_addr, cli_addr;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    fatal("in socket");

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(u32)) == -1)
    fatal("setting socket option SO_REUSEADDR");

  srv_addr.sin_family = AF_INET;   // host byte order
  srv_addr.sin_port = htons(port); // short, network byte order
  srv_addr.sin_addr.s_addr = 0;    // automatically fill with my ip address

  memset(&(srv_addr.sin_zero), '\0', 8); // zero out the rest of the struct

  if (bind(sockfd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr)) == -1)
    fatal("binding to socket");

  if (listen(sockfd, 5) == -1)
    fatal("listening on socket");

  /**
   * Main loop
   **/

  u8 *databuffer = NULL;
  u32 datalength = 0;
  u8 *result;
  char *sexp;
  u32 stackheight, actual_sexp_length;
  int unauth_count = 0;
  int max_unauth = 100;
  int result_buffer_size = (REGISTER_COUNT + 1) * sizeof(u32); // make flexible

  u8 initflag = 1;

  /*** Data to extract from the header ***/
  u8 reset_data;
  u8 reset_reg;
  u8 feedback_sexp;
  u8 archflag;
  u8 modeflag;
  u8 executable;
  u8 writeable;
  u32 expect;
  u32 startat;
  uc_arch arch;
  uc_mode mode;
  

  result = malloc(result_buffer_size);
  sexp = malloc(SEXP_LENGTH);
  sin_size = sizeof(struct sockaddr_in);

  uc_engine *engine = NULL;
  
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
    if (strncmp(client_ip, allowed_ip, 0xF)){
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

    recvlength = recv(new_sockfd, buffer, TRANSMISSION_SIZE, 0);

    /* Clean the buffers.
     */
    //    memset(databuffer, 0, IMAGINARY_STACK_SIZE);
    // memset(sexp, 0, SEXP_LENGTH);
    stackheight = 0;
    
    u8 baremetal = 0;
    // initialize header variables

    //    exit(EXIT_SUCCESS);
    while (recvlength > 0) {
      printf("*** RECVLENGTH = %d\n", recvlength);
      if (initflag){
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

        reset_data = RESET_DATA(buffer);
        reset_reg = RESET_REG(buffer);
        feedback_sexp = FEEDBACK_SEXP(buffer);
        archflag = ARCHFLAG(buffer);
        modeflag = MODEFLAG(buffer);
        executable = EXECUTABLE(buffer);
        writeable = WRITEABLE(buffer);
        expect = EXPECT(buffer);
        startat = STARTAT(buffer);

        if (DEBUG){
          fprintf(stderr,
                  "RECVLENGTH = %d\n"
                  "RESET_DATA = %s\n"
                  "RESET_REG = %s\n"
                  "FEEDBACK_SEXP = %s\n"
                  "ARCHFLAG = %d\n"
                  "MODEFLAG = %d\n"
                  "EXECUTABLE = %s\n"
                  "STARTAT = 0x%x\n",
                  recvlength,
                  YESORNO(reset_data),
                  YESORNO(reset_reg),
                  YESORNO(feedback_sexp),
                  archflag,
                  modeflag,
                  YESORNO(executable),
                  startat);
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
            fprintf(stderr, "Freeing old engine.\n");
            free(engine);
          }
          engine = init_unicorn(arch, mode);
        }
        

        if (reset_reg){

        }

        initflag = 0;
        recvlength -= HEADERLENGTH;
      } // End of header section. 

      printf("*** *** RECVLENGTH = %d\n", recvlength);

      /* If RESET_DATA is 0, then we assume you're loading the stack. */
      /* If RESET_DATA is 1, then incoming bytes are loaded into the */
      /* other areas of memory. */

      if (reset_data){ /* Load the rest of memory, destined for the unicorn*/
        if (DEBUG){
          fprintf(stderr, "Mapping memory...\n");
        }
        if (recvlength + datalength < expect){ // safeguard
          datalength = datacopy(databuffer, buffer + HEADERLENGTH,
                                datalength, recvlength);
        }
      } else { /* Load the stack. */
        if (DEBUG)
          fprintf(stderr, "Loading the stack...\n");
        if (recvlength + stackheight < expect){
          stackheight = datacopy(databuffer, buffer + HEADERLENGTH,
                                 stackheight, recvlength);
        }
      }
      
      if (DEBUG){
        fprintf(stderr, "STACK HEIGHT: %d\n",stackheight);
        fdump(stderr, databuffer, stackheight);
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
      if (datalength >= expect) {

        
        
        initflag = 1;
        free(databuffer);
      } else if (stackheight >= expect) {
        if (DEBUG){
          fprintf(stderr, "FINISHED RECEIVING STACK:\n");
          fdump(stderr, databuffer, stackheight);
        }

        /* Here, we copy the stack over into unicorn memory */
        reset_unicorn_stack(engine, arch, mode, databuffer, stackheight);
        
        
        if (DEBUG){
          fprintf(stderr, "REGISTERS GOING IN:\n");
          lisp_encode(result, sexp);
        }


        /***** THE EXECUTION ROUTINE IS CALLED FROM HERE ******/

        // what the execution function needs to do:
        // * start the unicorn emulation at the address presented
        //   at the top of the unicorn stack. report a failure,
        //   gracefully, if this causes a "segfault".
        // * ideally, the return (pop-style return) instruction will
        //   just transfer control to the code at the next address on
        //   the stack. but we should insert plenty of code hooks to
        //   monitor just what's happening. 

        
        if (feedback_sexp){
          actual_sexp_length = lisp_encode(result,sexp);
          send(new_sockfd, sexp, actual_sexp_length, 0);
        } else {
          send(new_sockfd, "Ok", 2, 0);
        }
        break;
        free(databuffer);
        initflag = 1;
      } else {
        
        /* If neither the data or the stack is ready to be loaded into
         * its respective data structure, just keep on receiving bytes
         */        
        recvlength = recv(new_sockfd, &buffer, TRANSMISSION_SIZE, 0);

      }
      
    }
    close(new_sockfd);
  }
  printf("~ The end. ~\n");
  free(databuffer);
  free(result);
  free(sexp);
  kill_unicorn(engine);
}

  

u32 main(u32 argc, char **argv){
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
  stack_listener(port, allowed_ip);
  
  return 0;
}


