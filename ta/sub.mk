global-incdirs-y += include
srcs-y += elf_ta_loader.c
srcs-y += elf_loader.c
srcs-y += elf_loader_api.c
srcs-y += syscall.c
srcs-y += syscall_hook.c

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
