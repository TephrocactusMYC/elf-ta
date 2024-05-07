#include <stdio.h>
#include <tee_internal_api.h>
#include <elf_common.h>
#include <utee_syscalls.h>
#include "elf_loader_api.h"

static unsigned long translate_prot(uint32_t prot) {
    unsigned long ret = 0;
    if (prot & PF_X) {
        ret |= LDELF_MAP_FLAG_EXECUTABLE;
    }
    if (prot & PF_W) {
        ret |= LDELF_MAP_FLAG_WRITEABLE;
    }
    return ret;
}

void *elf_loader_map(void *addr, size_t size, uint32_t prot) {
    TEE_Result res;
    vaddr_t vaddr = (vaddr_t) addr;
    res = _utee_ldelf_map_zi(&vaddr, size, 0, 0, 0);
    if (res != TEE_SUCCESS) {
        printf("_utee_ldelf_map_zi failed with 0x%x\n", res);
        return NULL;
    }
    if (prot == (PF_R | PF_W)) {
        return (void *) vaddr;
    }
    res = _utee_ldelf_set_prot(vaddr, size, translate_prot(prot));
    if (res != TEE_SUCCESS) {
        printf("_utee_ldelf_set_prot failed with 0x%x\n", res);
        return NULL;
    }
    return (void *) vaddr;
}

int elf_loader_unmap(void *addr, size_t size) {
    TEE_Result res = _utee_ldelf_unmap((vaddr_t) addr, size);
    if (res != TEE_SUCCESS) {
        return -1;
    }
    return 0;
}

int elf_loader_prot(void *addr, size_t size, uint32_t prot) {
    TEE_Result res;
    vaddr_t vaddr = (vaddr_t) addr;
    res = _utee_ldelf_set_prot(vaddr, size, translate_prot(prot));
    if (res != TEE_SUCCESS) {
        return -1;
    }
    return 0;
}

void elf_loader_fill_random(void *addr, size_t size) {
    TEE_GenerateRandom(addr, size);
}

void *elf_loader_internal_alloc(size_t size) {
    return TEE_Malloc(size, 0);
}

void elf_loader_internal_free(void *addr) {
    TEE_Free(addr);
}
