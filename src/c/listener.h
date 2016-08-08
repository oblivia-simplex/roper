/** 
 * Signatures for listener.c
 **/

void fatal (char *message);
void fdump(FILE *fp, const u8 *buf, const u32 length);
void uc_perror(const char *func, uc_err err);
u32 lisp_encode(u8 *vector, char *sexp);
uc_engine * init_unicorn(uc_arch arch, uc_mode mode);
int kill_unicorn(uc_engine *uc);
int map_memory(uc_engine *uc, u8 *bytes, size_t bytelength,
               u8 perms, u32 startat);
int init_stack(uc_engine *uc, uc_arch arch, uc_mode mode);
int set_stack(uc_engine *uc, uc_arch arch, uc_mode mode,
              u8 *stack_bytes, u32 stack_bytes_len);
void hook_step(uc_engine *uc, void *user_data);
int hatch_stack(uc_engine *uc, u8 *result);
int display_stack(uc_engine *uc, int depth);
int roundup(int num, int shiftby);
u32 datacopy(u8 *databuffer, u8 *recvbuffer, u32 stackheight, u32 recvlength);
u32 init_socket(u16 port, struct sockaddr_in *srv_addr);
u32 hatch_listener(u16 port, char *allowed_ip_string);
