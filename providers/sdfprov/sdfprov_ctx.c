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
#include "internal/tlog.h"
#include "sdfprov_ctx.h"

#ifdef _WIN32
# include <windows.h>
#else
# include <dlfcn.h>
#endif

/*
 * Load the SDF vendor DLL and optionally call BYCSM_LoadModule to initialize the module.
 * lib_path: 厂商库路径，为 NULL 时使用默认名称
 *   Windows 默认: "sdf.dll"
 *   Linux 默认: "libsdf.so"
 * password: BYCSM_LoadModule 的密码参数
 *
 * 注意：BYCSM_LoadModule 是特定厂商（如博雅）的模块初始化接口，
 * 不是标准 SDF API 的一部分。通过 sdf_use_loadmodule 配置参数控制是否调用。
 *
 * 这里必须直接用 GetProcAddress/dlsym 从已加载的 DLL 获取函数指针，
 * 不能走 SDF 框架层（DSO_load 加载的是 "sdf" 库，不是用户配置的厂商库）。
 */
typedef int (*FN_BYCSM_LoadModule)(const char *);

static int sdfprov_load_module(SDFPROV_CTX *ctx, const char *password)
{
    const char *default_lib =
#ifdef _WIN32
        "sdf.dll";
#else
        "libsdf.so";
#endif
    const char *load_lib = (ctx->sdf_lib_path != NULL && ctx->sdf_lib_path[0] != '\0')
                           ? ctx->sdf_lib_path : default_lib;

    TLOG_DEBUG("sdfprov_load_module: lib=%s, use_load_module=%d", load_lib, ctx->use_load_module);

    if (ctx->hModule != NULL)
        return 1; /* 已经加载 */

#ifdef _WIN32
    TLOG_DEBUG("Loading library: %s", load_lib);
    ctx->hModule = LoadLibraryA(load_lib);
    if (ctx->hModule == NULL) {
        DWORD error = GetLastError();
        TLOG_DEBUG("LoadLibraryA failed for: %s, error=%lu", load_lib, error);
        return 0;
    }
    TLOG_DEBUG("LoadLibraryA succeeded");

    /* 如果配置启用 BYCSM_LoadModule，直接从已加载的 DLL 获取函数指针 */
    if (ctx->use_load_module) {
        FN_BYCSM_LoadModule pLoad = (FN_BYCSM_LoadModule)GetProcAddress(ctx->hModule,
                                                                         "BYCSM_LoadModule");
        if (pLoad != NULL) {
            int ret = pLoad(password);
            if (ret != 0) {
                FreeLibrary(ctx->hModule);
                ctx->hModule = NULL;
                return 0;
            }
        }
    }

    return 1;
#else
    ctx->hModule = dlopen(load_lib, RTLD_NOW);
    if (ctx->hModule == NULL)
        return 0;

    /* 如果配置启用 BYCSM_LoadModule，直接从已加载的 DLL 获取函数指针 */
    if (ctx->use_load_module) {
        FN_BYCSM_LoadModule pLoad = (FN_BYCSM_LoadModule)dlsym(ctx->hModule,
                                                                 "BYCSM_LoadModule");
        if (pLoad != NULL) {
            if (pLoad(password) != 0) {
                TLOG_DEBUG("BYCSM_LoadModule failed");
                dlclose(ctx->hModule);
                ctx->hModule = NULL;
                return 0;
            }
            TLOG_DEBUG("BYCSM_LoadModule succeeded");
        } else {
            TLOG_DEBUG("BYCSM_LoadModule not found in DLL, skipping");
        }
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
#ifdef _WIN32
    if (ctx->hModule != NULL)
        FreeLibrary(ctx->hModule);
#else
    if (ctx->hModule != NULL)
        dlclose(ctx->hModule);
#endif
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

    /* 加锁保护，防止多线程并发初始化 */
    if (CRYPTO_THREAD_write_lock(ctx->lock) == 0)
        return 0;

    /* Double-check after acquiring lock */
    if (ctx->initialized) {
        CRYPTO_THREAD_unlock(ctx->lock);
        return 1;
    }

    /* Step 1: Load the vendor module with password */
    if (!ctx->module_loaded) {
        const char *pwd = ctx->password ? ctx->password : "88888888";
        if (!sdfprov_load_module(ctx, pwd)) {
            CRYPTO_THREAD_unlock(ctx->lock);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                           "SDF module load failed (BYCSM_LoadModule)");
            return 0;
        }
        ctx->module_loaded = 1;
    }

    /* Step 2: Open device */
    ret = TSAPI_SDF_OpenDevice(&ctx->hDevice);
    if (ret != 0) {
        CRYPTO_THREAD_unlock(ctx->lock);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                       "SDF_OpenDevice failed: 0x%08x", ret);
        return 0;
    }

    /* Step 3: Open session */
    ret = TSAPI_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    if (ret != 0) {
        TSAPI_SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = NULL;
        CRYPTO_THREAD_unlock(ctx->lock);
        return 0;
    }

    ctx->initialized = 1;
    CRYPTO_THREAD_unlock(ctx->lock);
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
    ctx->module_loaded = 0;
}

void *sdfprov_ctx_get_session(SDFPROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    if (!ctx->initialized && !sdfprov_ctx_init_device(ctx))
        return NULL;

    return ctx->hSession;
}
