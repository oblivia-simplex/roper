#include "includes.h"
#define SOCKDEBUG 1

/**
 * Server. Listens for messages containing machine-code, executes them, and
 * returns the resulting registers state.
 **/

#define PORT 9999
#define TRANSMISSION_SIZE 512

#define RET(x) (x == 0xC3)
#define READY(x) (x < 0)

#define DUMP 1
#define MAX_CODE_SIZE 0x10000
#define SEXP_LENGTH 137

#define BREAKPOINT_OPCODE 0xCC

#define ARM_WORD_LEN 4
#define X86_NOP 0x90

#define ARM_NOP "\x00\x00\x00\x00"


#define BAREMETAL 0

// marks end of code transmission

u8 *armrets[] = {
  "\x0e\xf0\xa0\xe1", // mov  pc, lr
};

int armrets_len = 1;


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

/************************************************************/

int validate(char *header){

  return 1;
}


int arm_return_p(u8 *word){
  int i;
  int yes_or_no = 0;
  for (i = 0; i < armrets_len; i++){
    if (!memcmp(word, armrets[i], ARM_WORD_LEN)){
      yes_or_no = 1;
      break;
    }
  }
  return yes_or_no;

}

/**
 * Returns next free position in codebuffer, or -1 * that position
 * if a return instruction has been received.
 **/
int codecopy(unsigned char *codebuffer, unsigned char *recvbuffer,
             int codelength, int recvlength, uc_arch arch){
  int i;
  /* Insert a breakpoint at the beginning of the code */
  /* it's more efficient to do this here, than in hatch_code */
  /*
    if (!codelength){
    codebuffer[0] = 0xCC;
    codebuffer[1] = 0x03;
    codelength = 2;
    if (SOCKDEBUG) printf("Added breakpoint at head.\n");
    }
  */
  
  if (arch == UC_ARCH_X86) { // check to see this is default for bare metal mode
    for (i = 0; i < recvlength; i ++){
      codebuffer[codelength++] =
        (RET(recvbuffer[i]))? 0x90 : recvbuffer[i];
      if (RET(recvbuffer[i])){
        codelength = -(codelength);
        break;
      }
    }
  } else if (arch == UC_ARCH_ARM) {
    u8 lastword[4] = {0,0,0,0};
    
    for (i = 0; i < recvlength; i ++){
      lastword[i%4] = recvbuffer[i];
      arm_return_p(lastword);
      codebuffer[codelength++] = recvbuffer[i];
      if (arm_return_p(lastword)){
        memcpy(codebuffer+(codelength-4), ARM_NOP, ARM_WORD_LEN); 
        codelength = -(codelength);
        break;
      }
    }
  }  
  return codelength;
}
    

  

int lisp_encode(unsigned char *vector, char *sexp){
  int vptr=0, sptr, length=0;
  // maximum length for sexp is 1 + 2 + (16+2)*7 + 7
  // #, parens, seven 64bit hex numbers, prefixed by #x, spaces
  // grand total of 135, plus a null character, so 137
  // vector is SYSREG_BYTES long.
  memset(sexp, 0, SEXP_LENGTH);
    
  length += sprintf(sexp+length, "#(");
  
  for (vptr = 0; vptr < SYSREG_BYTES; vptr += sizeof(long int)) {
    length += sprintf(sexp+length, "#x%llx ",
                      bytes_to_integer(vector + vptr));
  }
  length --;
  length += sprintf(sexp+length, ")\n\0");

  if (SOCKDEBUG) printf("SEXP: %s\n", sexp);
  
  return length;
}

#define SET_BY_CLIENT -1
int listen_for_code(int baremetal, uc_arch arch){

  int sockfd, new_sockfd, port=PORT, yes=1, recvlength=1;
  socklen_t sin_size;
  char buffer[TRANSMISSION_SIZE];
  struct sockaddr_in srv_addr, cli_addr;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    fatal("in socket");

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
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

  unsigned char *codebuffer;
  unsigned char *result;
  char *sexp;
  int codelength, actual_sexp_length;
  
  codebuffer = malloc(MAX_CODE_SIZE);
  result = malloc(SYSREG_BYTES);
  sexp = malloc(SEXP_LENGTH);
  
  while (1) {
    sin_size = sizeof(struct sockaddr_in);
    
    if ((new_sockfd =
         accept(sockfd, (struct sockaddr *) &cli_addr, &sin_size))
        == -1)
      fatal("accepting connection");

    if (SOCKDEBUG) printf("SERVER: ACCEPTED CONNECTION FROM %s PORT %d\n",
                          inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

    recvlength = recv(new_sockfd, &buffer, TRANSMISSION_SIZE, 0);
    
    /** 
     * Clean the buffers
     **/
    memset(codebuffer, 0, MAX_CODE_SIZE);
    memset(result, 0, SYSREG_BYTES);
    memset(sexp, 0, SEXP_LENGTH);
    
    codelength = 0;
    int offset = 0;
    baremetal = SET_BY_CLIENT;
    while (recvlength > 0) {
      if (SOCKDEBUG){
        printf("RECV: %d bytes\n", recvlength);
        fdump(stdout, buffer, recvlength);
      }

      if (!codelength && baremetal < 0){
        /* The lower nibble of the first byte sets the bare metal
         * vs virtual option (1 for bare metal, 0 for virtual).
         * The upper nibble sets the architecture, when virtual. 
         * Currently: 1 for ARM, 0 for X86;
         */         
        baremetal = buffer[0] & 0x0F;
        arch = (0xF0 & buffer[0])? UC_ARCH_ARM : UC_ARCH_X86;
        if (SOCKDEBUG)
          printf("setting baremetal option to %d\n", baremetal);
        recvlength --;
        offset = 1;
      }
      codelength = codecopy(codebuffer, buffer + offset,
      codelength, recvlength, arch);

      if (SOCKDEBUG)
        printf("code length = %d\n", -(codelength));

      if (READY(codelength)){
        /*
         * todo: load the register seed from a file. 
         * this file will be written in the code analysis stage
         * probably from the lispy side of things
         */
        codelength *= -1;
        if (SOCKDEBUG)
          fdump(stdout, codebuffer, codelength);
        
        /*************************************************/
        /* This is where the code actually gets launched */
        /*************************************************/
        if (baremetal) {
          if (SOCKDEBUG)
            printf("Running on bare metal.\n");
          hatch_code(codebuffer, codelength, NULL, result);
        } else {
          if (SOCKDEBUG)
            printf("Running in virtual environment.\n");
          em_code(codebuffer, codelength, result, arch);
        }
        /*************************************************
         em_code takes seed and result as same pointer.
         hatch_code should be updated to do this too. 
        *************************************************/
        actual_sexp_length = lisp_encode(result, sexp);
        send(new_sockfd, sexp, actual_sexp_length, 0);
        break;
      } else {      
        recvlength = recv(new_sockfd, &buffer, TRANSMISSION_SIZE, 0);
      }
    }

    close(new_sockfd);
  }
  free(codebuffer);
  free(result);
  free(sexp);
}

int main(int argc, char **argv){
  /*
   * TODO: parse command line options to select architecture
   * and virtualization vs baremetal options
   */
  int baremetal = SET_BY_CLIENT;
  char opt;
  uc_arch arch = UC_ARCH_X86;
  if (argc < 2)
    goto noopts;  
  while ((opt = getopt(argc, argv, "m")) != -1){
    switch (opt) {
    case 'm':
      if (!strncmp("bare",optarg,4)){
        baremetal = 1;
      } else if (!strncmp("x86",optarg,3)){
        baremetal = 0;
        arch = UC_ARCH_X86;
      } else if (!strncmp("arm",optarg,3)){
        baremetal = 0;
        arch = UC_ARCH_ARM;
      } else {
        fprintf(stderr, "Unrecognized architecture.\n");
        exit(EXIT_FAILURE);
      }
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
         "************************************************************\n", PORT);
  listen_for_code(baremetal, arch);
  return 0;
}

