#include "includes.h"

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

// marks end of code transmission


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


/**
 * Returns next free position in codebuffer, or -1 * that position
 * if a return instruction has been received.
 **/
int codecopy(unsigned char *codebuffer, unsigned char *recvbuffer,
             int codelength, int recvlength){
  int i;
  for (i = 0; i < recvlength; i ++){
    codebuffer[codelength++] = recvbuffer[i];
    if (RET(recvbuffer[i])){
      codelength = -(codelength);
      break;
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

  printf("SEXP: %s\n", sexp);
  
  return length;
}


int listen_for_code(void){

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
         accept(sockfd, (struct sockaddr *) &cli_addr, &sin_size)) == -1)
      fatal("accepting connection");

    printf("SERVER: ACCEPTED CONNECTION FROM %s PORT %d\n",
           inet_ntoa(cli_addr.sin_addr), ntohs(cli_addr.sin_port));

    //send(new_sockfd, "Hello, world!\n\r", 13, 0); // just for testing

    recvlength = recv(new_sockfd, &buffer, TRANSMISSION_SIZE, 0);
    
    /** 
     * Clean the buffers
     **/
    memset(codebuffer, 0, MAX_CODE_SIZE);
    memset(result, 0, SYSREG_BYTES);
    memset(sexp, 0, SEXP_LENGTH);
    
    codelength = 0;
    
    while (recvlength > 0) {
      printf("RECV: %d bytes\n", recvlength);
      if (DUMP) fdump(stdout, buffer, recvlength);

      //      memcpy(codebuffer+codelength, buffer, recvlength);
      codelength = codecopy(codebuffer, buffer,
                            codelength, recvlength);
      //      codelength += recvlength;

      printf("code length = %d\n", codelength);

      if (READY(codelength)){
        hatch_code(codebuffer, NULL, result);
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
  listen_for_code();
  return 0;
}
