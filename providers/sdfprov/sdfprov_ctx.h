/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROVIDERS_SDFPROV_CTX_H
# define OSSL_PROVIDERS_SDFPROV_CTX_H

# include <openssl/core.h>
# include <openssl/types.h>
# include "internal/cryptlib.h"

typedef struct sdfprov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;

    /* SDF 设备/会话 */
    void *hDevice;
    void *hSession;
    int initialized;
    int module_loaded;
#ifdef _WIN32
    HMODULE hModule;            /* 厂商 DLL 句柄 (LoadLibrary) */
#else
    void *hModule;              /* 厂商 DLL 句柄 (dlopen) */
#endif

    /* 配置参数 */
    char *sdf_lib_path;
    char *device_name;
    char *password;          /* 模块加载口令 (BYCSM_LoadModule) */
    int use_load_module;     /* 是否调用 BYCSM_LoadModule 接口 (0=不调用, 1=调用) */
    unsigned int sign_key_index;
    unsigned int enc_key_index;

    /* 线程安全 */
    CRYPTO_RWLOCK *lock;
} SDFPROV_CTX;

SDFPROV_CTX *sdfprov_ctx_new(OSSL_LIB_CTX *libctx,
                             const OSSL_CORE_HANDLE *handle);
void sdfprov_ctx_free(SDFPROV_CTX *ctx);
int sdfprov_ctx_init_device(SDFPROV_CTX *ctx);
void sdfprov_ctx_teardown_device(SDFPROV_CTX *ctx);

/* 获取全局 SDF 上下文 (定义在 sdfprov.c) */
SDFPROV_CTX *sdfprov_get_global_ctx(void);

#endif
