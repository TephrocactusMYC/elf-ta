#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <utee_syscalls.h>
#include <tee_internal_api.h>
#include <pta_elf_ta_loader.h>
#include "elf_util.h"
#include "elf_loader_api.h"
#include "syscall_number.h"
#include "syscall.h"

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

static void *sys_brk(void *brk) {
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

static int  sys_munmap(void *start, size_t len) {
    vaddr_t vaddr = (vaddr_t) start;
    TEE_Result res;
    res = _utee_ldelf_unmap(vaddr, len);
    if (res != TEE_SUCCESS) {
        DMSG("sys_munmap(%p, %d) = %ld\n", vaddr, len, res);
        return -1;
    }

    return TEE_SUCCESS;
}

static int sys_mprotect(void *addr, size_t len, int prot) {
    unsigned long tee_prot = translate_prot(prot);
    TEE_Result res = _utee_ldelf_set_prot((vaddr_t) addr, len, tee_prot);
    if (res != TEE_SUCCESS) {
        return -EINVAL;
    }
    return 0;
}

static int sys_openat(int dirfd, const char *pathname, int flags) {
    sys_openat_args_t args = {
            .dirfd = dirfd,
            .pathname = pathname,
            .pathname_len = strlen(pathname) + 1,
            .flags = flags,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_openat, &args, sizeof(args), &ret);
//    DMSG("sys_openat(%d, %s, %d) = %ld\n", dirfd, pathname, flags, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (int) ret;
}

static int sys_close(int fd) {
    sys_close_args_t args = {
            .fd = fd,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_close, &args, sizeof(args), &ret);
    DMSG("sys_close(%d) = %ld\n", fd, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (int) ret;
}

static ssize_t sys_read(int fd, void *buf, size_t count){
    sys_read_args_t args = {
            .fd = fd,
            .buf=buf,
            .count=count,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_read, &args, sizeof(args), &ret);
//    DMSG("sys_read(%d) = %ld\n", fd, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (ssize_t) ret;
}

static ssize_t sys_readv(int fd, const struct iovec *iov, int count){
    sys_readv_args_t args = {
            .fd = fd,
            .iov=iov,
            .count=count,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_readv, &args, sizeof(args), &ret);
    DMSG("sys_readv(%d) = %ld\n", fd, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (ssize_t) ret;
}

static ssize_t sys_write(int fd, void *buf, size_t count){
    sys_write_args_t args = {
            .fd = fd,
            .buf=buf,
            .count=count,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_write, &args, sizeof(args), &ret);
//    DMSG("sys_write(%d) = %ld\n", fd, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (ssize_t) ret;
}

static ssize_t sys_pread(int fd, void *buf, size_t count,long ofs){
    sys_pread_args_t args = {
            .fd = fd,
            .buf=buf,
            .count=count,
            .ofs=ofs,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_pread64, &args, sizeof(args), &ret);
//    DMSG("sys_pread(%d) = %ld\n", fd, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (ssize_t) ret;
}

static ssize_t sys_pwrite(int fd, void *buf, size_t count,long ofs){
    sys_pwrite_args_t args = {
            .fd = fd,
            .buf=buf,
            .count=count,
            .ofs=ofs,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_pwrite64, &args, sizeof(args), &ret);
//    DMSG("sys_pwrite(%d) = %ld\n", fd, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (ssize_t) ret;
}

static int sys_access(const char *filename, int amode) {
    sys_access_args_t args = {
            .filename = filename,
            .amode = amode,
            .pathname_len = strlen(filename) + 1,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_faccessat, &args, sizeof(args), &ret);
//    DMSG("access(%d, %s, %d) = %ld\n", amode, filename, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (int) ret;
}

static int sys_lseek(int fd, long offset, int whence) {
    sys_lseek_args_t args = {
            .fd=fd,
            .offset=offset,
            .whence=whence,
    };
    long ret = 0;
    TEE_Result res = TEE_forward_syscall(SYS_lseek, &args, sizeof(args), &ret);
    DMSG("lseek(%d, %ld, %d, %d) = %ld\n", fd, offset,whence, ret);

    if (res != TEE_SUCCESS) {
        return -1;
    }
    return (int) ret;
}

long syscall_hook_impl(long n, long a, long b, long c, long d, long e, long f) {
    long ret = 0;
    DMSG("syscall_hook_impl(%ld, %ld, %ld, %ld, %ld, %ld, %ld)\n", n, a, b, c, d, e, f);
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
        case SYS_munmap:
            ret = (long) sys_munmap((void *) a, (size_t) b);
            break;
        case SYS_mprotect:
            ret = sys_mprotect((void *) a, (size_t) b, (int) c);
            break;
        case SYS_openat:
            ret = sys_openat((int) a, (const char *) b, (int) c);
            break;
        case SYS_close:
            ret = sys_close((int) a);
            break;
        case SYS_read:
            ret = sys_read((int) a,(void *)b,(size_t) c);
            break;
        case SYS_write:
            ret = sys_write((int) a,(void *)b,(size_t) c);
            break;
        case SYS_pread64:
            ret = sys_pread((int) a,(void *)b,(size_t) c,(long) d);
            break;
        case SYS_pwrite64:
            ret = sys_pwrite((int) a,(void *)b,(size_t) c,(long) d);
            break;
        case SYS_faccessat:
            ret = sys_access( (const char *) a, (int) b);
            break;
        case SYS_lseek:
            ret = sys_lseek( (int) a, (long) b, (int) c);
            break;
        case SYS_readv:
            ret = sys_readv( (int) a,(void *)b,(size_t) c);
            break;
        default:
            ret = -1;
            break;
    }

    return ret;
}


