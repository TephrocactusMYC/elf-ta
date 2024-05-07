#ifndef ELF_LOADER_API_H
#define ELF_LOADER_API_H

#include <stdint.h>
#include <stddef.h>

#define BIT32(nr)                   (UINT32_C(1) << (nr))
#define LDELF_MAP_FLAG_SHAREABLE    BIT32(0)
#define LDELF_MAP_FLAG_WRITEABLE    BIT32(1)
#define LDELF_MAP_FLAG_EXECUTABLE   BIT32(2)
#define LDELF_MAP_FLAG_BTI          BIT32(3)

void *elf_loader_map(void *addr, size_t size, uint32_t prot);

int elf_loader_unmap(void *addr, size_t size);

int elf_loader_prot(void *addr, size_t size, uint32_t prot);

void elf_loader_fill_random(void *addr, size_t size);

void *elf_loader_internal_alloc(size_t size);

void elf_loader_internal_free(void *addr);

#endif //ELF_LOADER_API_H
