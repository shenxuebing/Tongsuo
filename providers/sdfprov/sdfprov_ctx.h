/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * SDF Provider 上下文结构定义
 *
 * SDFPROV_CTX 是 Provider 的全局上下文，管理：
 *   - SDF 设备/会话生命周期
 *   - 厂商库配置参数（路径、密码、模块加载方式）
 *   - SDF 函数指针表（sdfList，复用 TSAPI 层的 ts_sdf_meth）
 *
 * 所有 provider 操作文件（KEYMGMT / SIGNATURE / ASYM_CIPHER / KEYEXCH）
 * 通过 sdfprov_get_global_ctx() 获取此上下文，
 * 再通过 ctx->sdfList->xxx 调用厂商 SDF 接口。
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
# include "sdf_types.h"

typedef struct sdfprov_ctx_st {
    const OSSL_CORE_HANDLE *handle;   /* OpenSSL core 句柄 */
    OSSL_LIB_CTX *libctx;             /* 库上下文 */

    /* SDF 设备/会话 */
    void *hDevice;                    /* SDF 设备句柄 (SDF_OpenDevice 返回) */
    void *hSession;                   /* SDF 会话句柄 (SDF_OpenSession 返回) */
    int initialized;                  /* 设备是否已初始化 (0=未初始化, 1=已初始化) */
    int module_loaded;                /* 厂商库是否已加载 (0=未加载, 1=已加载) */

    /* 配置参数（从 openssl.cnf [sdfprov_sect] 读取） */
    char *sdf_lib_path;               /* 厂商库路径 (如 byzk0018.dll) */
    char *device_name;                /* 设备名称（可选） */
    char *password;                   /* 模块加载口令 (BYCSM_LoadModule 的密码参数) */
    int use_load_module;              /* 是否调用 BYCSM_LoadModule (0=不调用, 1=调用，博雅等厂商需要) */
    unsigned int sign_key_index;      /* 默认签名密钥索引 */
    unsigned int enc_key_index;       /* 默认加密密钥索引 */

    /*
     * SDF 函数指针表（复用 TSAPI 层的 SDF_METHOD）。
     *
     * init_device 时赋值为 &ts_sdf_meth（由 sdf_lib.c 通过 DSO 机制
     * 从厂商库动态绑定所有 SDF API 函数指针）。
     *
     * 所有 provider 文件统一通过 sdfctx->sdfList->xxx 调用，
     * 例如：
     *   sdfctx->sdfList->InternalSign_ECC(...)
     *   sdfctx->sdfList->ExportSignPublicKey_RSA(...)
     *   sdfctx->sdfList->GenerateKeyWithECCEx(...)
     *
     * 未来新增/修改 SDF 接口，只需改 sdf_lib.c 一处（ts_sdf_meth 绑定）。
     */
    const SDF_METHOD *sdfList;

    CRYPTO_RWLOCK *lock;              /* 线程安全锁（保护 init_device 并发） */
} SDFPROV_CTX;

SDFPROV_CTX *sdfprov_ctx_new(OSSL_LIB_CTX *libctx,
                             const OSSL_CORE_HANDLE *handle);
void sdfprov_ctx_free(SDFPROV_CTX *ctx);
int sdfprov_ctx_init_device(SDFPROV_CTX *ctx);
void sdfprov_ctx_teardown_device(SDFPROV_CTX *ctx);
void *sdfprov_ctx_get_session(SDFPROV_CTX *ctx);
/* 获取全局 SDF 上下文 (定义在 sdfprov.c) */
SDFPROV_CTX *sdfprov_get_global_ctx(void);

#endif
