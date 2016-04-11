#include "includes.h"

/**
 * Server. Listens for messages containing machine-code, executes them, and
 * returns the resulting registers state.
 **/

#define PORT 9999
#define TRANSMISSION_SIZE 1024

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


int listen_for_code(void){

  int sockfd, new_sockfd, port=PORT, yes=1;
  struct sockaddr_in srv_addr, cli_addr;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    fatal("in socket");

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    fatal("setting socket option SO_REUSEADDR");

  host_addr.sin_family = AF_INET;   // host byte order
  host_addr.sin_port = htons(port); // short, network byte order
  host_addr.sin_addr.s_addr = 0;    // automatically fill with my ip address

  memset(&(host_addr.sin_zero), '\0', 8); // zero out the rest of the struct

  if (bin(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1)
    fatal("binding to socket");

  if (listen(sockfd, 5) == -1)
    fatal("listening on socket");

  /**
   * Main loop
   **/

  while (1) {
    sin_size = sizeof(struct sockaddr_in);
    
    if ((new_sockfd =
         accept(sockfd, (struct sockaddr *) &client_addr, &sin_size)) == -1)
      fatal("accepting connection");

    printf("SERVER: ACCEPTED CONNECTION FROM %s PORT %d\n"
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    send(new_sockfd, "Hello, world!\n\r", 13, 0); // just for testing

    recv_length = recv(new_sockfd, &buffer, TRANSMISSION_SIZE, 0);

    while (recv_length > 0) {
      printf("RECV: %d bytes\n", recv_length);
      fdump(stdout, buffer, recv_length);
      recv_length = recv(new_sockfd, &buffer, TRANSMISSION_SIZE, 0);
    }

    close(new_sockfd);
    
  }
}
