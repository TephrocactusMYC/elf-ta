#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdint.h>

int load_elf(uint8_t *exec_buf, uint8_t *interp_buf, size_t stack_size, char *argv[], char *envp[]);

#endif //ELF_LOADER_H
