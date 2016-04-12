
#ifndef hatchery_h__
#define hatchery_h__


/************************************************************
 * Machine independent types
 ************************************************************/
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;


#ifdef __x86_64__

/************************************************************
 * Constants
 ************************************************************/

#define SYSREG_COUNT 7
#define SYSREG_BYTES 7*8
#define THE_SHELLCODE_LIES_BELOW 0x700000000000 // kludge

/************************************************************
 * Some useful types
 ************************************************************/
typedef u64 word;

typedef union {
  struct user_regs_struct structure;
  u64 vector[sizeof(struct user_regs_struct)];
} REGISTERS;

typedef union syscall_reg_vec {
  word rvec[SYSREG_COUNT]; // rax, rdi, rsi, rdx, r10, r8, r9
  u8 bvec[SYSREG_BYTES];
} SYSCALL_REG_VEC;

enum sysreg_t {rax, rdi, rsi, rdx, r10, r8, r9};

#define PC structure.rip

#define SYSCALL_INST_SIZE 2

#define WORDFMT "%llx"



/************************************************************/

#endif // __x86_64__

#ifdef __arm__

typedef u32 word;
#define WORDFMT "%lx"

#define SYSCALL_INST_SIZE 4

#define SYSREG_COUNT 1
#define SYSREG_BYTES 4 // temporary, false

#define PC vector[15]

typedef union {
  struct user_regs structure;
  word vector[18];
} REGISTERS;

typedef union syscall_reg_vec {
  word rvec[SYSREG_COUNT]; // rax, rdi, rsi, rdx, r10, r8, r9
  u8 bvec[SYSREG_BYTES];
} SYSCALL_REG_VEC;



#endif // __arm__


/************************************************************
 * Function prototypes
 ************************************************************/

word bytes_to_integer(u8 *bytes);
int hatch_code (u8 *code, int bytelength,
                u8 *seed, u8 *reg);

int size_of_registers(void);

int size_of_sysreg_union(void);

/************************************************************
 * Unicorn-related stuff, etc.
 ************************************************************/

enum{ARCH_X86_64, ARCH_ARM_32} arch_t;

#endif // hatchery_h__


