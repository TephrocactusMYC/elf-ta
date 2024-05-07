#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <elf_common.h>
#include <elf.h>
#include <auxv.h>
#include <memory.h>
#include "elf_util.h"
#include "syscall_hook.h"
#include "elf_loader_api.h"
#include "elf_loader.h"

#define PAGE_SIZE 0x1000
#define MAX_AUXV 10
#define ADD_AUXV(auxv, t, v)      \
    do {                          \
        (auxv)->a_type = (t);     \
        (auxv)->a_un.a_val = (v); \
        (auxv)++;                 \
    } while (0)

typedef struct {
    const char *name;
    void *hook_addr;
} hook_entry_t;

static void *get_entry(uint8_t *buf, void *image_base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
    return (void *) ((intptr_t) image_base + ehdr->e_entry);
}

static Elf64_Shdr *get_section_header(uint8_t *buf, int type) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
    Elf64_Shdr *shdr = (Elf64_Shdr *) (buf + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == type && !(shdr[i].sh_flags & SHF_ALLOC)) {
            return &shdr[i];
        }
    }

    return NULL;
}

static int hook_libc_export_syscall(uint8_t *buf, void *image_base) {
    hook_entry_t hooks[] = {
            {"__syscall_stub0", syscall_hook0},
            {"__syscall_stub1", syscall_hook1},
            {"__syscall_stub2", syscall_hook2},
            {"__syscall_stub3", syscall_hook3},
            {"__syscall_stub4", syscall_hook4},
            {"__syscall_stub5", syscall_hook5},
            {"__syscall_stub6", syscall_hook6},
    };
    // parse .symtab section
    Elf64_Shdr *symtab_shdr = get_section_header(buf, SHT_SYMTAB);
    if (symtab_shdr == NULL) {
        return -EINVAL;
    }

    Elf64_Shdr *strtab_shdr = get_section_header(buf, SHT_STRTAB);
    if (strtab_shdr == NULL) {
        return -EINVAL;
    }

    int hook_count = 0;

    Elf64_Sym *symtab = (Elf64_Sym *) (buf + symtab_shdr->sh_offset);
    char *strtab = (char *) (buf + strtab_shdr->sh_offset);

    for (int i = 0; i < symtab_shdr->sh_size / sizeof(Elf64_Sym); i++) {
        if (ELF64_ST_TYPE(symtab[i].st_info) != STT_OBJECT) {
            continue;
        }

        const char *name = strtab + symtab[i].st_name;
        for (int j = 0; j < sizeof(hooks) / sizeof(hook_entry_t); j++) {
            if (strcmp(name, hooks[j].name) == 0) {
                *(void **) ((intptr_t) image_base + symtab[i].st_value) = hooks[j].hook_addr;
                printf("hook %s at %p\n", name, (void *) ((intptr_t) image_base + symtab[i].st_value));
                hook_count++;
                break;
            }
        }
    }

    return hook_count == sizeof(hooks) / sizeof(hook_entry_t) ? 0 : -EINVAL;
}

static char *get_interp_path(uint8_t *buf) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
    Elf64_Phdr *phdr = (Elf64_Phdr *) (buf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_INTERP) {
            continue;
        }
        return (char *) (buf + phdr[i].p_offset);
    }
    return NULL;
}

static int check_elf_format(uint8_t *buf) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return -EINVAL;
    }
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return -EINVAL;
    }
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return -EINVAL;
    }
    if (ehdr->e_ident[EI_VERSION] != EV_CURRENT) {
        return -EINVAL;
    }
    if (ehdr->e_type != ET_DYN) {
        return -EINVAL;
    }
    if (ehdr->e_machine != EM_AARCH64) {
        return -EINVAL;
    }
    if (ehdr->e_version != EV_CURRENT) {
        return -EINVAL;
    }
    if (ehdr->e_phoff == 0) {
        return -EINVAL;
    }
    if (ehdr->e_shoff == 0) {
        return -EINVAL;
    }
    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        return -EINVAL;
    }
    if (ehdr->e_shentsize != sizeof(Elf64_Shdr)) {
        return -EINVAL;
    }
    char *interp_path = get_interp_path(buf);
    if (interp_path && strcmp(interp_path, "/lib/ld-musl-aarch64.so.1") != 0) {
        return -EINVAL;
    }
    return 0;
}

static void get_map_range(uint8_t *buf, intptr_t *p_begin, intptr_t *p_end) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
    Elf64_Phdr *phdr = (Elf64_Phdr *) (buf + ehdr->e_phoff);
    uintptr_t begin = UINTPTR_MAX;
    uintptr_t end = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }
        begin = min(begin, round_down(phdr[i].p_vaddr, PAGE_SIZE));
        end = max(end, round_up(phdr[i].p_vaddr + phdr[i].p_memsz, PAGE_SIZE));
    }
    *p_begin = begin;
    *p_end = end;
}

static int map_elf(uint8_t *buf, void **p_image_base) {
    int ret;
    if ((ret = check_elf_format(buf)) != 0) {
        return ret;
    }
    intptr_t map_begin;
    intptr_t map_end;
    get_map_range(buf, &map_begin, &map_end);
    size_t map_size = map_end - map_begin;

    void *image_base = elf_loader_map(NULL, map_size, PF_R | PF_W);
    if (image_base == NULL) {
        return -ENOMEM;
    }
    elf_loader_unmap(image_base, map_size);
    *p_image_base = image_base;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) buf;
    Elf64_Phdr *phdr = (Elf64_Phdr *) (buf + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            continue;
        }

        intptr_t seg_begin = (intptr_t)image_base + round_down(phdr[i].p_vaddr, PAGE_SIZE);
        intptr_t seg_end = (intptr_t)image_base + round_up(phdr[i].p_vaddr + phdr[i].p_memsz, PAGE_SIZE);
        size_t seg_size = seg_end - seg_begin;
        if (elf_loader_map((void *) seg_begin, seg_size, PF_R | PF_W) == NULL) {
            return ret;
        }

        // copy data from file to memory
        if (phdr[i].p_filesz > 0) {
            memcpy((void *) ((intptr_t)image_base + phdr[i].p_vaddr), buf + phdr[i].p_offset, phdr[i].p_filesz);
        }

        // zero out the rest of the memory
        if (phdr[i].p_memsz > phdr[i].p_filesz) {
            memset((void *) ((intptr_t)image_base + phdr[i].p_vaddr + phdr[i].p_filesz), 0, phdr[i].p_memsz - phdr[i].p_filesz);
        }

        // change protection
        if ((ret = elf_loader_prot((void *) seg_begin, seg_size, phdr[i].p_flags)) != 0) {
            return ret;
        }
    }
    return 0;
}

static char **fill_args_str(intptr_t *p_stack, char *args[], int *p_count) {
    int count = 0;
    for (int i = 0; args[i] != NULL; i++) {
        count++;
    }
    *p_count = count;

    char **buf = elf_loader_internal_alloc(sizeof(char *) * count);
    if (buf == NULL) {
        return NULL;
    }

    for (int i = 0; i < count; i++) {
        size_t len = strlen(args[i]) + 1;
        *p_stack -= len;
        buf[i] = (char *) *p_stack;
        memcpy(buf[i], args[i], len);
    }

    return buf;
}

static void
fill_stack_ptr(intptr_t *p_stack, char **argv, int argv_count, char **envp, int envp_count, Elf64_auxv_t *auxv,
               int auxv_count) {
    *p_stack -= (auxv_count + 1) * sizeof(Elf64_auxv_t);
    Elf64_auxv_t *auxv_stack = (Elf64_auxv_t *) *p_stack;
    for (int i = 0; i < auxv_count; i++) {
        auxv_stack[i] = auxv[i];
    }
    auxv_stack[auxv_count].a_type = AT_NULL;
    auxv_stack[auxv_count].a_un.a_val = 0;
    elf_loader_internal_free(auxv);

    *p_stack -= sizeof(char *) * (envp_count + 1);
    char **envp_stack = (char **) *p_stack;
    for (int i = 0; i < envp_count; i++) {
        envp_stack[i] = envp[i];
    }
    envp_stack[envp_count] = NULL;
    elf_loader_internal_free(envp);

    *p_stack -= sizeof(char *) * (argv_count + 1);
    char **argv_stack = (char **) *p_stack;
    for (int i = 0; i < argv_count; i++) {
        argv_stack[i] = argv[i];
    }
    argv_stack[argv_count] = NULL;
    elf_loader_internal_free(argv);

    *p_stack -= sizeof(intptr_t);
    *(intptr_t *) *p_stack = argv_count;
}

static Elf64_auxv_t *
get_auxv(intptr_t *p_stack, uint8_t *exec_buf, void *exec_image_base, void *interp_image_base, int *p_count) {
    Elf64_auxv_t *auxv_base = elf_loader_internal_alloc(sizeof(Elf64_auxv_t) * MAX_AUXV);
    if (auxv_base == NULL) {
        return NULL;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *) exec_buf;

    size_t random_size = 16;
    *p_stack -= random_size;
    elf_loader_fill_random((void *) *p_stack, random_size);

    Elf64_auxv_t *auxv = auxv_base;
    ADD_AUXV(auxv, AT_PHDR, (intptr_t) exec_image_base + ehdr->e_phoff);
    ADD_AUXV(auxv, AT_PHENT, sizeof(Elf64_Phdr));
    ADD_AUXV(auxv, AT_PHNUM, ehdr->e_phnum);
    ADD_AUXV(auxv, AT_PAGESZ, PAGE_SIZE);
    ADD_AUXV(auxv, AT_ENTRY, (intptr_t) exec_image_base + ehdr->e_entry);
    ADD_AUXV(auxv, AT_BASE, (intptr_t) interp_image_base);
    ADD_AUXV(auxv, AT_RANDOM, *p_stack);

    *p_count = auxv - auxv_base;
    return auxv_base;
}

static int
build_stack(uint8_t *buf, void *exec_image_base, void *interp_image_base, size_t stack_size, intptr_t *p_stack,
            char *argv[], char *envp[]) {
    void *stack_base = elf_loader_map(NULL, stack_size, PF_R | PF_W);
    if (stack_base == NULL) {
        return -ENOMEM;
    }

    intptr_t stack = (intptr_t) stack_base + stack_size;

    int argv_count;
    char **argv_dup = fill_args_str(&stack, argv, &argv_count);
    if (argv_dup == NULL) {
        return -ENOMEM;
    }

    int envp_count;
    char **envp_dup = fill_args_str(&stack, envp, &envp_count);
    if (envp_dup == NULL) {
        elf_loader_internal_free(argv_dup);
        return -ENOMEM;
    }

    // align stack
    stack = stack & ~0x7;

    int auxv_count;
    Elf64_auxv_t *auxv = get_auxv(&stack, buf, exec_image_base, interp_image_base, &auxv_count);
    if (auxv == NULL) {
        elf_loader_internal_free(argv_dup);
        elf_loader_internal_free(envp_dup);
        return -ENOMEM;
    }

    fill_stack_ptr(&stack, argv_dup, argv_count, envp_dup, envp_count, auxv, auxv_count);
    *p_stack = stack;
    return 0;
}

__attribute__((noreturn))
static void jump_to_entry(void *entry, intptr_t stack) {
    asm volatile(
            "mov x0, %0\n"
            "mov sp, %1\n"
            "blr x0\n"
            :
            : "r"(entry), "r"(stack)
            : "x0", "sp"
            );
    __builtin_unreachable();
}

int load_elf(uint8_t *exec_buf, uint8_t *interp_buf, size_t stack_size, char *argv[], char *envp[]) {
    int ret;
    void *exec_image_base;
    if ((ret = map_elf(exec_buf, &exec_image_base)) != 0) {
        return ret;
    }
    printf("exec_image_base = %p\n", exec_image_base);
    void *interp_image_base;
    if ((ret = map_elf(interp_buf, &interp_image_base)) != 0) {
        return ret;
    }
    printf("interp_image_base = %p\n", interp_image_base);
    if ((ret = hook_libc_export_syscall(interp_buf, interp_image_base)) != 0) {
        return ret;
    }

    intptr_t stack;
    if ((ret = build_stack(exec_buf, exec_image_base, interp_image_base, stack_size, &stack, argv, envp)) != 0) {
        return ret;
    }
    void *entry = get_entry(interp_buf, interp_image_base);

    jump_to_entry(entry, stack);
}
