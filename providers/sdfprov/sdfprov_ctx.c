/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * SDF Provider 上下文管理
 *
 * 职责：
 *   - 管理 SDF 设备/会话的生命周期（OpenDevice / OpenSession / Close）
 *   - 通过 TSAPI 层（sdf_lib.c）加载厂商库（byzk0018.dll 等），只加载一次
 *   - 将 TSAPI 层的 SDF_METHOD 函数指针表（ts_sdf_meth）暴露给所有 provider 文件
 *   - 所有 provider 文件统一通过 sdfctx->sdfList->xxx 调用厂商 SDF 接口
 *
 * 调用层次：
 *   Provider 文件 → sdfctx->sdfList->xxx → ts_sdf_meth.xxx → DSO_bind_func → 厂商 DLL
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
#include "internal/sdf.h"
#include "internal/tlog.h"
#include "sdfprov_ctx.h"

/* 创建 SDF Provider 上下文 */
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

/* 释放 SDF Provider 上下文（含设备/会话关闭） */
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

/*
 * 初始化 SDF 设备（懒加载：首次使用密钥时才触发）
 *
 * 流程：
 *   1. ossl_sdf_lib_preload() — 通过 TSAPI 层 DSO 机制加载厂商库
 *      （LoadLibrary/dlopen + 可选 BYCSM_LoadModule），只执行一次
 *   2. SDF_OpenDevice() — 打开 SDF 设备
 *   3. SDF_OpenSession() — 打开会话
 *   4. ctx->sdfList = &ts_sdf_meth — 绑定 TSAPI 层的函数指针表
 *
 * 线程安全：通过 ctx->lock 写锁保护，防止并发初始化
 */
int sdfprov_ctx_init_device(SDFPROV_CTX *ctx)
{
    int ret;

    if (ctx == NULL)
        return 0;

    /* 已初始化则直接返回 */
    if (ctx->initialized)
        return 1;

    if (CRYPTO_THREAD_write_lock(ctx->lock) == 0)
        return 0;

    /* 双重检查：防止并发竞争 */
    if (ctx->initialized) {
        CRYPTO_THREAD_unlock(ctx->lock);
        return 1;
    }

    /*
     * 步骤1：加载厂商库（只加载一次）
     * ossl_sdf_lib_preload 内部通过 DSO 机制加载厂商 DLL（byzk0018.dll），
     * 绑定所有 SDF API 函数指针到全局 ts_sdf_meth 表中。
     * 如果 use_load_module=1，还会调用厂商的 BYCSM_LoadModule 进行模块初始化。
     */
    if (!ctx->module_loaded) {
        const char *pwd = ctx->password != NULL ? ctx->password : "88888888";

        if (!ossl_sdf_lib_preload(ctx->sdf_lib_path, pwd,
                                  ctx->use_load_module)) {
            CRYPTO_THREAD_unlock(ctx->lock);
            ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                           "SDF module preload failed");
            return 0;
        }

        ctx->module_loaded = 1;
    }

    /* 步骤2：打开 SDF 设备 */
    ret = TSAPI_SDF_OpenDevice(&ctx->hDevice);
    if (ret != 0) {
        CRYPTO_THREAD_unlock(ctx->lock);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER,
                       "SDF_OpenDevice failed: 0x%08x", ret);
        return 0;
    }

    /* 步骤3：打开会话 */
    ret = TSAPI_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    if (ret != 0) {
        TSAPI_SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = NULL;
        CRYPTO_THREAD_unlock(ctx->lock);
        return 0;
    }

    /*
     * 步骤4：绑定 TSAPI 层的 SDF_METHOD 函数指针表
     * ts_sdf_meth 已在 ossl_sdf_lib_preload 中完成所有 SDF API 函数指针的绑定，
     * 所有 provider 文件通过 sdfctx->sdfList->xxx 统一调用。
     */
    ctx->initialized = 1;
    ctx->sdfList = &ts_sdf_meth;
    CRYPTO_THREAD_unlock(ctx->lock);
    return 1;
}

/* 关闭 SDF 设备/会话（释放资源） */
void sdfprov_ctx_teardown_device(SDFPROV_CTX *ctx)
{
    if (ctx == NULL || !ctx->initialized)
        return;

    TSAPI_SDF_CloseSession(ctx->hSession);
    TSAPI_SDF_CloseDevice(ctx->hDevice);
    ctx->hSession = NULL;
    ctx->hDevice = NULL;
    ctx->sdfList = NULL;
    ctx->initialized = 0;
}

/*
 * 获取 SDF 会话句柄（懒加载：首次调用时自动初始化设备）
 * 返回值：SDF 会话句柄，NULL 表示初始化失败
 */
void *sdfprov_ctx_get_session(SDFPROV_CTX *ctx)
{
    if (ctx == NULL)
        return NULL;

    /* 首次使用时自动初始化设备 */
    if (!ctx->initialized && !sdfprov_ctx_init_device(ctx))
        return NULL;

    return ctx->hSession;
}
