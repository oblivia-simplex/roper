#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#ifdef __x86_64__
#include <sys/reg.h>
#endif


#include "hatchery.h"
#include "example.h"


unsigned char *sc = "\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c\x58\x0f\x05";


void print_registers(unsigned char *bytes){
  #ifdef __x86_64__
  SYSCALL_REG_VEC srv;
  memcpy(srv.bvec, bytes, sizeof(SYSCALL_REG_VEC));
  printf("RAX: "WORDFMT"\n"
         "RDI: "WORDFMT"\n"
         "RSI: "WORDFMT"\n"
         "RDX: "WORDFMT"\n"
         "R10: "WORDFMT"\n"
         "R8:  "WORDFMT"\n"
         "R9:  "WORDFMT"\n"
         ,srv.rvec[rax]
         ,srv.rvec[rdi]
         ,srv.rvec[rsi]
         ,srv.rvec[rdx]
         ,srv.rvec[r10]
         ,srv.rvec[r8]
         ,srv.rvec[r9]);
#endif //__x86_64__
  #ifdef __arm__
  REGISTERS regs;
  memcpy(&regs,bytes,sizeof(REGISTERS));
  int i;
  for (i = 0; i < 18; i++){
    printf("R%d: "WORDFMT"\n", i, regs.vector[i]);
  }
#endif // __arm__
}


int test_code(){
  void (*proc)() = (void(*)())example_x86_bin;
  proc();
  return 1;
}


/* main() is just for testing purposes. */
int main(int argc, char **argv){
  int i=0;
  int result;
  test_code();

  unsigned char somebytes[] = {255,255,255,255,
                               255,255,255,255};
  word number = bytes_to_integer(somebytes);
  printf("number = 0x"WORDFMT"\n", number);

  /* unsigned char fakeseedbytes[sizeof(REGISTERS)] */
  /*   = {1,2,3,4,5,6,7,8}; */

  /* seed_registers(0,fakeseedbytes); */
  
  
  //  scanf("%s", input);
  //REGISTERS *registers;
  //printf("size of registers struct: %d bytes\n", size_of_registers());
  //  registers = calloc(1,sizeof(REGISTERS));
  unsigned char *res;
  res = calloc(sizeof(SYSCALL_REG_VEC),1);
  fprintf(stderr,"--- REGISTERS BEFORE ---\n");
  print_registers(res);
  result = hatch_code(example_x86_bin,example_x86_bin_len,NULL,res);
  fprintf(stderr,"You're back. Result code: "WORDFMT"\n\n", result);
  fprintf(stderr,"--- REGISTERS AFTER ---\n");
  print_registers(res);
  return 0;
}

