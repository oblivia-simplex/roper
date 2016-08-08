u32 arm_32_reg_vec[] = {
  UC_ARM_REG_R0,
  UC_ARM_REG_R1,
  UC_ARM_REG_R2,
  UC_ARM_REG_R3,
  UC_ARM_REG_R4,
  UC_ARM_REG_R5,
  UC_ARM_REG_R6,
  UC_ARM_REG_R7,
  UC_ARM_REG_R8,
  UC_ARM_REG_R9,
  UC_ARM_REG_R10,
  UC_ARM_REG_R11,
  UC_ARM_REG_R12,
  UC_ARM_REG_R13,
  UC_ARM_REG_R14,  
}; 
int arm_32_reg_vec_len = 15;

#define ARM_POP_PC {0xE9, 0xBD, (1 << 7), 0x00} // POP  R15
#define WORDSIZE 4
