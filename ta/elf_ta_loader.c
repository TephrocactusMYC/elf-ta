#include <string.h>
#include <tee_internal_api.h>
#include "elf_loader.h"
#include "elf_ta_loader.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void) {
    // DMSG("has been called");

    return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void) {
    // DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param __maybe_unused params[4],
                                    void __maybe_unused **sess_ctx) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE,
                                               TEE_PARAM_TYPE_NONE);

    // DMSG("has been called");

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Unused parameters */
    (void) &params;
    (void) &sess_ctx;


    /* If return value != TEE_SUCCESS the session will not be created. */
    return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx) {
    (void) &sess_ctx; /* Unused parameter */
    // IMSG("Goodbye!\n");
}

static char **rebuild_args(char *args_buf) {
    size_t count = 0;
    char *curr;
    size_t curr_size;

    curr = args_buf;
    while ((curr_size = strlen(curr)) != 0) {
        count++;
        curr += curr_size + 1;
    }

    char **args = TEE_Malloc(sizeof(char *) * (count + 1), 0);
    if (args == NULL) {
        return NULL;
    }

    curr = args_buf;
    for (size_t i = 0; i < count; i++) {
        curr_size = strlen(curr);
        args[i] = curr;
        curr += curr_size + 1;
    }
    args[count] = NULL;

    return args;
}

static TEE_Result handle_load(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INPUT,
                                               TEE_PARAM_TYPE_MEMREF_INPUT);

    // DMSG("has been called");

    if (param_types != exp_param_types) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t *exec_buf = params[0].memref.buffer;
    size_t exec_size = params[0].memref.size;
    uint8_t *interp_buf = params[1].memref.buffer;
    size_t interp_size = params[1].memref.size;
    char *argv_buf = params[2].memref.buffer;
    size_t argv_size = params[2].memref.size;
    char *envp_buf = params[3].memref.buffer;
    size_t envp_size = params[3].memref.size;

    char **argv_rebuild = rebuild_args(argv_buf);
    if (argv_rebuild == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    char **envp_rebuild = rebuild_args(envp_buf);
    if (envp_rebuild == NULL) {
        TEE_Free(argv_rebuild);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    DMSG("argv_rebuild: %p", argv_rebuild);
    DMSG("envp_rebuild: %p", envp_rebuild);

    int result = load_elf(exec_buf, interp_buf, 0x4000, argv_rebuild, envp_rebuild);

    TEE_Free(envp_rebuild);
    TEE_Free(argv_rebuild);

    if (result != 0) {
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                      uint32_t cmd_id,
                                      uint32_t param_types,
                                      TEE_Param params[4]) {
    (void) &sess_ctx; /* Unused parameter */

    switch (cmd_id) {
        case TA_LOADER_CMD_LOAD:
            return handle_load(param_types, params);
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }
}
