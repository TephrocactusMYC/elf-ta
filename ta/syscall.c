#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <utee_syscalls.h>
#include "elf_util.h"
#include "elf_loader_api.h"
#include "syscall_number.h"
#include "syscall.h"

struct iovec {
    void *iov_base;
    size_t iov_len;
};

static ssize_t sys_writev(int fd, const struct iovec *iov, int iovcnt) {
    // only support stdout & stderr now
    if (fd != 1 && fd != 2) {
        return -1;
    }

    ssize_t ret = 0;
    for (int i = 0; i < iovcnt; i++) {
        for (size_t j = 0; j < iov[i].iov_len; j++) {
            putchar(((char *) iov[i].iov_base)[j]);
        }
        ret += iov[i].iov_len;
    }
    return ret;
}

__noreturn
static void sys_exit_group(int status) {
    _utee_return(status);
}

static void *make_brk_space(size_t size) {
    vaddr_t ptr = 0;
    TEE_Result res = _utee_ldelf_map_zi(&ptr, size, 0, 0, 0);
    if (res != TEE_SUCCESS) {
        return NULL;
    }
    return (void *) ptr;
}

static void * sys_brk(void * brk) {
    const size_t brk_size = 2 * 0x1000;
    static void *brk_start = NULL;
    static void *curr_ptr = NULL;
    if (brk_start == NULL) {
        brk_start = make_brk_space(brk_size);
        curr_ptr = brk_start;
    }

    if (brk != 0) {
        curr_ptr = min((uint8_t *) brk, (uint8_t *) brk_start + brk_size);
    }
    return curr_ptr;
}

#define PROT_READ    0x1        /* Page can be read.  */
#define PROT_WRITE   0x2        /* Page can be written.  */
#define PROT_EXEC    0x4        /* Page can be executed.  */

static unsigned long translate_prot(int flags) {
    unsigned long prot = 0;
    if (flags & PROT_WRITE) {
        prot |= LDELF_MAP_FLAG_WRITEABLE;
    }
    if (flags & PROT_EXEC) {
        prot |= LDELF_MAP_FLAG_EXECUTABLE;
    }
    return prot;
}

static void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    vaddr_t vaddr = (vaddr_t) addr;
    TEE_Result res;
    res = _utee_ldelf_map_zi(&vaddr, len, 0, 0, 0);
    if (res != TEE_SUCCESS) {
        return (void *) -1;
    }
    unsigned long tee_prot = translate_prot(prot);
    if (tee_prot == LDELF_MAP_FLAG_WRITEABLE) {
        return (void *) vaddr;
    }

    res = _utee_ldelf_set_prot(vaddr, len, tee_prot);
    if (res != TEE_SUCCESS) {
        return (void *) -1;
    }
    return (void *) vaddr;
}

static int sys_mprotect(void *addr, size_t len, int prot) {
    unsigned long tee_prot = translate_prot(prot);
    TEE_Result res = _utee_ldelf_set_prot((vaddr_t) addr, len, tee_prot);
    if (res != TEE_SUCCESS) {
        return -EINVAL;
    }
    return 0;
}

long syscall_hook_impl(long n, long a, long b, long c, long d, long e, long f) {
    long ret = 0;
    printf("syscall_hook_impl(%ld, %ld, %ld, %ld, %ld, %ld, %ld)\n", n, a, b, c, d, e, f);
    switch (n) {
        case SYS_set_tid_address:
        case SYS_ioctl:
            ret = -1;
            break;
        case SYS_writev:
            ret = (long) sys_writev((int) a, (const struct iovec *) b, (int) c);
            break;
        case SYS_exit_group:
            sys_exit_group((int) a);
        case SYS_brk:
            ret = (long) sys_brk((void *) a);
            break;
        case SYS_mmap:
            ret = (long) sys_mmap((void *) a, (size_t) b, (int) c, (int) d, (int) e, (long) f);
            break;
        case SYS_mprotect:
            ret = sys_mprotect((void *) a, (size_t) b, (int) c);
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}


