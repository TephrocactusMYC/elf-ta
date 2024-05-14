#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_client_api.h>
#include <elf_ta_loader.h>

static int read_file(const char *filename, uint8_t **p_buf, size_t *p_len) {
    FILE *f;
    uint8_t *buf;
    size_t len;
    size_t read;

    f = fopen(filename, "rb");
    if (!f) {
        return -ENOENT;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = malloc(len);
    if (!buf) {
        fclose(f);
        return -ENOMEM;
    }

    read = fread(buf, 1, len, f);
    if (read != len) {
        fclose(f);
        free(buf);
        return -EIO;
    }

    fclose(f);

    *p_buf = buf;
    *p_len = len;
    return 0;
}

static int make_args_buf(char *args[], char **p_buf, size_t *p_len) {
    size_t size = 0;
    for (int i = 0; args[i] != NULL; i++) {
        size += strlen(args[i]) + 1;
    }
    size += 1;

    char *buf = malloc(size);
    if (!buf) {
        return -ENOMEM;
    }

    char *p = buf;
    for (int i = 0; args[i] != NULL; i++) {
        size_t len = strlen(args[i]);
        memcpy(p, args[i], len);
        p += len;
        *p++ = '\0';
    }
    *p = '\0';

    *p_buf = buf;
    *p_len = size;
    return 0;
}

int main(int argc, char *argv[], char *envp[]) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = ELF_TA_LOADER_UUID;
    uint32_t err_origin;
    int ret;
    char *exec_name;
    uint8_t *exec_buf;
    size_t exec_size;
    char *interp_name;
    uint8_t *interp_buf;
    size_t interp_size;
    char *argv_buf;
    size_t argv_size;
    char *envp_buf;
    size_t envp_size;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("TEE init failed with code 0x%x\n", res);
        return 1;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEE open session failed with code 0x%x origin 0x%x\n", res, err_origin);
        return 1;
    }

    if (argc != 2 || strcmp(argv[1], "--help") == 0) {
        printf("Usage: %s <file_name>\n", argv[0]);
        return 1;
    }
    exec_name = argv[1];
    if ((ret = read_file(exec_name, &exec_buf, &exec_size)) != 0) {
        printf("Failed to read file %s: %s\n", exec_name, strerror(-ret));
        return 1;
    }
    interp_name = "libc.so";
    if ((ret = read_file(interp_name, &interp_buf, &interp_size)) != 0) {
        printf("Failed to read file %s: %s\n", interp_name, strerror(-ret));
        return 1;
    }

    // argv + 1 to skip the loader program name
    if ((ret = make_args_buf(argv + 1, &argv_buf, &argv_size)) != 0) {
        printf("Failed to make argv buffer: %s\n", strerror(-ret));
        return 1;
    }

    if ((ret = make_args_buf(envp, &envp_buf, &envp_size)) != 0) {
        printf("Failed to make envp buffer: %s\n", strerror(-ret));
        return 1;
    }

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
    op.params[0].tmpref.buffer = exec_buf;
    op.params[0].tmpref.size = exec_size;
    op.params[1].tmpref.buffer = interp_buf;
    op.params[1].tmpref.size = interp_size;
    op.params[2].tmpref.buffer = argv_buf;
    op.params[2].tmpref.size = argv_size;
    op.params[3].tmpref.buffer = envp_buf;
    op.params[3].tmpref.size = envp_size;

    printf("Invoking TA to load ELF file %s\n", exec_name);
    res = TEEC_InvokeCommand(&sess, TA_LOADER_CMD_LOAD, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TA invocation failed with code 0x%x origin 0x%x\n", res, err_origin);
        return 1;
    }
    // printf("TA invocation succeeded, TA returned code 0x%x\n", err_origin);
    printf("TA invocation succeede.\n");

    free(envp_buf);
    free(argv_buf);
    free(interp_buf);
    free(exec_buf);

    TEEC_CloseSession(&sess);

    TEEC_FinalizeContext(&ctx);

    return 0;
}
