
#ifndef hatchery_h__
#define hatchery_h__

#ifdef __x86_64__

/************************************************************
 * Constants
 ************************************************************/

#define SYSREG_COUNT 7
#define SYSREG_BYTES 7*8
#define THE_SHELLCODE_LIES_BELOW 0x700000000000 // kludge

/************************************************************
 * Function prototypes
 ************************************************************/

long long int bytes_to_integer(unsigned char *bytes);
int hatch_code (unsigned char *code, unsigned char *seed,
                unsigned char *reg);

int size_of_registers(void);

int size_of_sysreg_union(void);

/************************************************************
 * Some useful types
 ************************************************************/

typedef union {
  struct user_regs_struct structure;
  long long int vector[sizeof(struct user_regs_struct)];
} REGISTERS;

typedef union syscall_reg_vec {
  unsigned long int rvec[SYSREG_COUNT]; // rax, rdi, rsi, rdx, r10, r8, r9
  unsigned char bvec[SYSREG_BYTES];
} SYSCALL_REG_VEC;

enum sysreg_t {rax, rdi, rsi, rdx, r10, r8, r9};

/************************************************************/

#endif // __x86_64__

#ifdef __arm__

#define REGISTERS struct user_regs

#endif // __arm__

#endif // hatchery_h__


