/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/sdf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "sdfprov_ctx.h"

#ifdef _WIN32
# include <windows.h>
#else
# include <dlfcn.h>
#endif

/* BYCSM_LoadModule: vendor-specific module initialization (password parameter) */
typedef int (*FN_BYCSM_LoadModule)(const char *);

/*
 * Load the SDF vendor DLL and call BYCSM_LoadModule to initialize the module.
 * This must be called before any standard SDF operations.
 * The DLL loaded here is the same instance that DSO will use later,
 * so the module state is shared.
 */
static int sdfprov_load_module(const char *password)
{
#ifdef _WIN32
    HMODULE hDll;
    FN_BYCSM_LoadModule pLoad;

    hDll = LoadLibraryA("sdf.dll");
    if (hDll == NULL)
        return 0;

    pLoad = (FN_BYCSM_LoadModule)GetProcAddress(hDll, "BYCSM_LoadModule");
    if (pLoad == NULL) {
        FreeLibrary(hDll);
        return 0;
    }

    if (pLoad(password) != 0) {
        FreeLibrary(hDll);
        return 0;
    }

    /* Don't free the DLL - DSO will also reference it */
    return 1;
#else
    void *hDll;
    FN_BYCSM_LoadModule pLoad;

    hDll = dlopen("libsdf.so", RTLD_NOW);
    if (hDll == NULL)
        return 0;

    pLoad = (FN_BYCSM_LoadModule)dlsym(hDll, "BYCSM_LoadModule");
    if (pLoad == NULL) {
        dlclose(hDll);
        return 0;
    }

    if (pLoad(password) != 0) {
        dlclose(hDll);
        return 0;
    }

    return 1;
#endif
}

SDFPROV_CTX *sdfprov_ctx_new(OSSL_LIB_CTX *libctx,
                             const OSSL_CORE_HANDLE *handle)
{
    SDFPROV_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx == NULL)
        return NULL;

    ctx->libctx = libctx;
    ctx->handle = handle;
    ctx->lock = CRYPTO_THREAD_lock_new();
    if (ctx->lock == NULL) {
        OPENSSL_free(ctx);
        return NULL;
    }

    return ctx;
}

void sdfprov_ctx_free(SDFPROV_CTX *ctx)
{
    if (ctx == NULL)
        return;

    sdfprov_ctx_teardown_device(ctx);
    OPENSSL_free(ctx->sdf_lib_path);
    OPENSSL_free(ctx->device_name);
    OPENSSL_free(ctx->password);
    CRYPTO_THREAD_lock_free(ctx->lock);
    OPENSSL_free(ctx);
}

int sdfprov_ctx_init_device(SDFPROV_CTX *ctx)
{
    int ret;

    if (ctx == NULL)
        return 0;

    if (ctx->initialized)
        return 1;

    /* Step 1: Load the vendor module with password */
    if (!ctx->module_loaded) {
        const char *pwd = ctx->password ? ctx->password : "88888888";
        if (!sdfprov_load_module(pwd)) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                           "SDF module load failed (BYCSM_LoadModule)");
            return 0;
        }
        ctx->module_loaded = 1;
    }

    /* Step 2: Open device */
    ret = TSAPI_SDF_OpenDevice(&ctx->hDevice);
    if (ret != OSSL_SDR_OK) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                       "SDF_OpenDevice failed: 0x%08x", ret);
        return 0;
    }

    /* Step 3: Open session */
    ret = TSAPI_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    if (ret != OSSL_SDR_OK) {
        TSAPI_SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = NULL;
        return 0;
    }

    ctx->initialized = 1;
    return 1;
}

void sdfprov_ctx_teardown_device(SDFPROV_CTX *ctx)
{
    if (ctx == NULL || !ctx->initialized)
        return;

    TSAPI_SDF_CloseSession(ctx->hSession);
    TSAPI_SDF_CloseDevice(ctx->hDevice);
    ctx->hSession = NULL;
    ctx->hDevice = NULL;
    ctx->initialized = 0;
}
