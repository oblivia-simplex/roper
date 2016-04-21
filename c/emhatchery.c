#include "includes.h"
#define DEBUG 1
#define TTL 256

/*********************************************************************
 *********************************************************************
                        Virtual Land Begins Here
 *********************************************************************
 ********************************************************************/

#define EM_ADDR 0x1000 // arbitrary?
uc_arch global_arch; // for lack of a better place
/*
 * unicorn-powered
 */
int x86_64_syscall_abi[] = {
  UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
  UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9
};
int x86_64_syscall_abi_len = 7;

/* In arm mode, the syscall # is passed in R7, and the params 
 * are passed in R0-R5. In thumb mode, the # is passed in R0, and
 * the params are passed in R1-R6. The simplest solution here seems
 * to be to just keep track of R0-R7 at all times, and search for
 * hyperplanes in that register space as needed.
 */
int arm_32_syscall_abi[] = {
  UC_ARM_REG_R0,
  UC_ARM_REG_R1,
  UC_ARM_REG_R2,
  UC_ARM_REG_R3,
  UC_ARM_REG_R4,
  UC_ARM_REG_R5,
  UC_ARM_REG_R6,
  UC_ARM_REG_R7
}; 

int arm_32_syscall_abi_len = 8; // need to look this up


void uc_perror(const char *func, uc_err err)
{
  if (DEBUG)
    fprintf(stderr, "Error in %s(): %s\n", func, uc_strerror(err));  
}


int roundup(int num){
  int i;
  for (i=1; i < num; i <<= 1);
  return i;
}



void hook_step(uc_engine *uc, void *user_data) {

  int *sys_abi_vec, sys_abi_len;
  //  uc_arch arch = UC_ARCH_ARM;  // just a stopgap
  int pc;

  switch (global_arch) {
  case UC_ARCH_X86 :
    sys_abi_vec = x86_64_syscall_abi; // careful
    sys_abi_len = x86_64_syscall_abi_len;
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
    break;
  case UC_ARCH_ARM :
    sys_abi_vec = arm_32_syscall_abi;
    sys_abi_len = arm_32_syscall_abi_len;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    break;
  }
  // bad code rep for now, but refactor later
  // this is mostly just for debugging, anyways
  union seedvals {
    word words[sys_abi_len];
    u8 bytes[sys_abi_len * sizeof(word)];
  } seedvals;
  void *ptrs[sys_abi_len];      
  int i;
  for (i = 0; i < sys_abi_len; i++) {
    ptrs[i] = &(seedvals.words[i]);
  }
  
  uc_reg_read_batch(uc, sys_abi_vec, ptrs, sys_abi_len);
  
  /** for testing  **/
  if (DEBUG) {
    printf("[ PC: %x ] syscall vec: {", pc);
    for (i = 0; i < sys_abi_len; i++) {
      if (i != 0) printf(", ");
      printf("%x", seedvals.words[i]);
    }
    printf("}\n");
  }
  /******************/
  return;
}


void ret_msg(uc_engine *uc, int err, uc_arch arch){
  // check to see if you've reached the end of the code, by
  // accessing the instruction pointer in uc
  u32 pc;
  if (arch == UC_ARCH_X86) {
    uc_reg_read(uc, UC_X86_REG_RIP, &pc);
  } else if (arch == UC_ARCH_ARM) {
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  }
  printf("Attempted to branch to %x\n",pc);
  return;
}



/**
 * This is the part that launches the code in the Unicorn emulator.
 **/
int em_code(u8 *code, u32 bytelength, u32 startat,
            u8 *seed_res, uc_arch arch){

  // bit of lazy coding here: update a global arch var, so that
  // we can easily read the arch from the single step hook.
  // neither elegant nor dangerous. 
  if (global_arch != arch)
    global_arch = arch;

  /* The start address must be aligned to 4KB, or uc_mem_map will
   * throw a UC_ERR_ARG error. 
   */
  u32 round_start = startat & (u32) (~0xFFF);
  u32 offset = startat - round_start;
  int errcode = 0;
  int roundlength = roundup(bytelength);
  uc_engine *uc;
  uc_err err;
  uc_hook hook1;
  int sys_abi_len;
  uc_mode mode;
  
  int ret_inst;
  int *sys_abi_vec;

  /* if (DEBUG){ */
  /*   printf("IN EMULATOR\n"); */
  /*   fdump(stdout, code, bytelength); */
  /* } */
  
  switch (arch) {
  case UC_ARCH_X86 :
    sys_abi_vec = x86_64_syscall_abi; // careful
    sys_abi_len = x86_64_syscall_abi_len;
    mode = UC_MODE_64;
    ret_inst = UC_X86_INS_RET; 
    break;
  case UC_ARCH_ARM :
    if (DEBUG) printf("Emulating ARM architecture...\n");
    sys_abi_vec = arm_32_syscall_abi;
    sys_abi_len = arm_32_syscall_abi_len;
    mode = UC_MODE_ARM;
    break;
  default :
    fprintf(stderr,"Unknown architecture requested of em_code.\nExiting.\n");
    exit(EXIT_FAILURE);
  }
    
  union seedvals {
    word words[sys_abi_len];
    u8 bytes[sys_abi_len * sizeof(word)];
  } seedvals;

  /* fprintf(stderr, "bytelength = %d\nroundlength = %d\nsizeof(seedvals.bytes) = %d\nsizeof(seed_res) = %d\nsizeof(word) * sys_abi_len = %d\n",bytelength, roundlength, sizeof(seedvals.bytes), sizeof(seed_res), (sys_abi_len * sizeof(word))); */
  
  if (!memcpy(seedvals.bytes, seed_res,
              (sys_abi_len * sizeof(word)))){
    fprintf(stderr, "Error in memcpy, in em_code.\n");
  }
  
  /**
   * from the unicorn src: "This part of the API is less... clean...
   * because Unicorn supports arbitrary register types. So the least
   * intrusive solution is passing individual pointers. On the plus
   * side, you only need to make this pointer array once."
   */
  void *ptrs[sys_abi_len];
  int i;
  for (i = 0; i < sys_abi_len; i++) {
    ptrs[i] = &(seedvals.words[i]);
  }
  
  if ((err = uc_open(arch, mode, &uc))) {
    uc_perror("uc_open", err);
    return -1;
  }

  // seed the registers
  if ((err = uc_reg_write_batch(uc, sys_abi_vec, ptrs, sys_abi_len))){
    uc_perror("uc_reg_write_batch", err);
    return -1;
  }

  /* Add a single-stepping hook if debugging */
  if (DEBUG){
    if ((err = uc_hook_add(uc, &hook1, UC_HOOK_CODE, hook_step, NULL, 1, 0, 0))) {
      uc_perror("uc_hook_add", err);
      return 1;
    }
  }

  // don't leave 0x1000 a magic number
  if ((err = uc_mem_map(uc, round_start, 0x1000, UC_PROT_ALL))) {
    // does PROT_ALL mean 777? might want to set to XN for ROP...
    uc_perror("uc_mem_map", err);
    return -1;
  }

  if ((err = uc_mem_write(uc, startat, (void *) code,
                          bytelength-1))) {
    uc_perror("uc_mem_write", err);
    return -1;
  }
  // why does the unicorn example suggest sizeof(CODE) -1
  // where I have bytelength (sizeof(CODE))? probably because
  // it's implemented as a string, so it ends with a null byte
  if ((err = uc_emu_start(uc, startat,
                          startat + bytelength -1, 0, TTL))){
    if (DEBUG){
      uc_perror("uc_emu_start", err);
      if (err == UC_ERR_FETCH_UNMAPPED)
        ret_msg(uc, err, arch);
    }
    errcode = -2;
  }
  
  uc_reg_read_batch(uc, sys_abi_vec, ptrs, sys_abi_len);

  /** for testing  **/
  if (DEBUG) {
    printf("syscall vec: {");
    for (i = 0; i < sys_abi_len; i++) {
      if (i != 0) printf(", ");
      printf(WORDFMT, seedvals.words[i]);
    }
    printf("}\n");
  }
  /******************/
  memcpy(seed_res, seedvals.bytes,
         (sys_abi_len * sizeof(word)));  
  uc_close(uc);
  return errcode;
}






// write a return hook. i think that some of the errors are due
// to the return instruction being executed, and this is why the
// code benefits from the -1 length
/**********************************************************************
 * Check for memory leaks! The thing devours memory right now. Are you
 *  freeing all your mallocs? probably missed at least one
 */








