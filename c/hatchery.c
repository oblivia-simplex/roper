#include "includes.h"
#define TTL 128

#ifndef DEBUG
#define DEBUG 1
#endif

// do debug flag as a command line opt.

// todo: intercept syscalls, intercept segfaults

int size_of_registers(){
  return sizeof(REGISTERS);
}

int size_of_sysreg_union(){
  return SYSREG_BYTES;
}

long long int bytes_to_integer(unsigned char *bytes){
  int i;
  long int number;
  for (i = sizeof(long int); i >= 0; i--){
    number <<= 8;
    number |= bytes[i];
  }
  return number;
}

void print_word(long long int word){
  int i;
  for (i = 0; i < sizeof(long long int); i++){
    printf("%2.2hhx ", (u8) (word >> (8 * i)) & 0xFF);
  }
  puts("");
  return;
}

/****
 * Out of service
 */
REGISTERS * seed_registers(pid_t pid, REGISTERS *regs,
                                 unsigned char *register_seed){

  ptrace(PTRACE_GETREGS, pid, NULL, regs);
  long long rip = regs->structure.rip; 
  
  if (register_seed){
    printf("*** SEEDING REG ***\n");
    memcpy(regs,register_seed,sizeof(REGISTERS));
  } else {
    printf("zeroing registers\n");
    regs->structure.rax =
      regs->structure.rbx =
      regs->structure.rcx =
      regs->structure.rdx =
      regs->structure.rdi =
      regs->structure.rsi =
      regs->structure.r8 =
      regs->structure.r9 =
      regs->structure.r10 = 1; // just for testing    
  }
  //regs->structure.rip = rip; // restore instruction pointer
  
  ptrace(PTRACE_SETREGS, pid, NULL, regs);
  return regs; // remember to free afterwards
}
  
 



#define INT80 0x80cd
#define SYSCALL 0x050f
#define SHORTMASK 0x000000000000FFFF
int syscallp (long int peeked){
  u16 op = (u16) (peeked & SHORTMASK);
  return ((op == INT80 || op == SYSCALL));  
}

#define RET 0xC3
#define BYTEMASK 0x000000000000000FF
int retp (long int peeked){
  u8 op = (u8) (peeked & BYTEMASK);

  return (op == RET);
}

int hatch_code (unsigned char *code, unsigned char *seed,
                unsigned char *res){
  /* cast the byte array as a function */
  long (*proc)() = (long(*)())code;
  SYSCALL_REG_VEC syscall_reg_vec;
  /* This struct will be loaded by the tracer with a representation
   * of all the registers at the end of the code's execution. 
   */
    
  pid_t pid;
  /* fork a new process in which to run the shellcode */
  pid = fork();
  if (pid == 0){ // if in child process (tracee)
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    //kill(getpid(), SIGSTOP); // to let the tracer catch up
    proc(); // if you want to pass any params to the code, do it here
    exit(1); // we're done with this child, now
  } else {
    /* We're in the tracer process. It will observe the child and
     * report back to the head office.
     */
    REGISTERS *regs;
    regs = calloc(1,sizeof(REGISTERS));
    
    int status;
    wait(&status);
    printf("-- TRAPPED CHILD %d WITH STATUS %d --\n", pid,
           WSTOPSIG(status));
    //    seed_registers(pid, regs, seed);

    // To prevent escape
    //ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL);
    long long int inst = 0;
    int in_code = 0;
    int steps = 0;

    while(in_code || !WIFEXITED(status)){
      long opcode = 0;
      int ptrace_errno;
      //      if (!in_code) printf ("not yet in code\n");
      if ((ptrace_errno = ptrace(PTRACE_GETREGS, pid, NULL, regs))
          == -1){
        fprintf(stderr, "-- ERROR GETTING REGISTERS: %d --\n",
                ptrace_errno);
        //      exit(EXIT_FAILURE);
      }

      opcode = ptrace(PTRACE_PEEKTEXT, pid, regs->structure.rip,
                      NULL);
      if (DEBUG){
        printf("PEEKING AT OPCODES: ");
        print_word(opcode);
      }
      if (in_code && syscallp(opcode)){
        fprintf(stderr, "**** WARNING: SYSCALL AT RIP %llx\n",
                regs->structure.rip);
        fprintf(stderr, "**** YOUR SYSTEM MAY BE UNDER ATTACK! \n");
        regs->structure.rip += 2; // size of int 80 and syscall
        ptrace(PTRACE_SETREGS, pid, NULL, regs);
        fprintf(stderr, "**** INCREMENTING RIP TO SKIP SYSCALL\n");
      }
      
      //    print_registers(regs);
      if (WTERMSIG(status) == SIGSEGV){
        fprintf(stderr, "-- SEGFAULT --\n");  // not detecting ?
      }

      inst = regs->structure.rip;
      printf("AT LINE %llx\n", inst);
      if (!in_code && inst < THE_SHELLCODE_LIES_BELOW){
        printf("ENTERING CODE\n");
        in_code = 1;
      }
      if (in_code) steps ++;
      if (retp(opcode) ||
          (in_code && inst > THE_SHELLCODE_LIES_BELOW)
          || (steps > TTL))
        break;
      
      if (in_code){
        if (DEBUG) {
          printf("AT INSTRUCTION %llx\n", inst);
          printf("IN RAX: %llx\n" 
                 "IN RDI: %llx\n"
                 "IN RSI: %llx\n"
                 "IN RDX: %llx\n"
                 "IN R10: %llx\n"
                 "IN R8:  %llx\n"
                 "IN R9:  %llx\n\n",
                 regs->structure.rax,
                 regs->structure.rdi,
                 regs->structure.rsi,
                 regs->structure.rdx,
                 regs->structure.r10,
                 regs->structure.r8,
                 regs->structure.r9);
        }
        
        /**
         * Serialize the register information
         **/
        #ifdef __x86_64__
        syscall_reg_vec.rvec[rax] = regs->structure.rax;
        syscall_reg_vec.rvec[rdi] = regs->structure.rdi;
        syscall_reg_vec.rvec[rsi] = regs->structure.rsi;
        syscall_reg_vec.rvec[rdx] = regs->structure.rdx;
        syscall_reg_vec.rvec[r10] = regs->structure.r10;
        syscall_reg_vec.rvec[r8] = regs->structure.r8;
        syscall_reg_vec.rvec[r9] = regs->structure.r9;
        #endif

        #ifdef __arm__

        // put ARM syscall reg vec assignments here

        #endif 
      }
            
      ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

      waitpid(pid, &status, 0);
                 
    }
    printf("-- EXITING WITH STATUS %d --\n", WSTOPSIG(status));
    /* int j; */
    /* for (j=0; j<26; j++){ */
    /*   printf("Register number %d: %llx\n", */
    /*          j, regs->vector[j]); */
    /* } */

    memcpy(res, syscall_reg_vec.bvec, SYSREG_BYTES);
    free(regs);
  }
  
  return syscall_reg_vec.rvec[rax];
}

/**
   ideas:
   screen out jump instructions from gadgets, for now. 
   end each gadget with a null/dummy syscall, to hand
   control to the monitor
*/

