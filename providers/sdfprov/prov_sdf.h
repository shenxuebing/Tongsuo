/*
 * SDF Provider for Tongsuo
 *
 * 基于 GM/T 0018 SDF 接口的 Tongsuo Provider 实现
 * 将密码卡硬件能力通过 OpenSSL 3.x Provider 机制暴露
 *
 * 私钥永不离卡原则：
 * - 所有私钥操作必须调用密码卡 SDF 接口
 * - Provider keydata 中禁止存储私钥字节
 * - 仅用密钥索引 (key_index) 引用设备上的密钥
 *
 * 动态加载：
 * - 参照 e_sdf.c 的 setFunctionList 方式，从密码卡厂商 DLL 动态加载
 *   完整的 SD_FUNCTION_LIST 接口
 * - 不依赖 Tongsuo 自带的 sdf_lib.c（接口不全）
 */

#ifndef PROV_SDF_H
#define PROV_SDF_H

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>

/* Provider 名称和版本 */
#define SDF_PROVIDER_NAME "SDF Provider"
#define SDF_PROVIDER_VERSION "1.0.0"
#define SDF_PROVIDER_BUILDINFO "SDF Provider for Tongsuo based on GM/T 0018"

/*
 * SDF Provider type definitions (GM/T 0018-2012)
 *
 * Use standalone sdf_types.h for SDF types.
 * Built-in providers are compiled into libcrypto and cannot depend on
 * engine-specific headers.
 */

#include "sdf_types.h"

/* Provider 代码中使用的类型别名 */
#define OSSL_ECCref_MAX_BITS  ECCref_MAX_BITS
#define OSSL_ECCref_MAX_LEN   ECCref_MAX_LEN
#define SGD_NULL               ((SGD_HANDLE)NULL)

/* Provider 上下文 */
typedef struct sdf_prov_ctx_st {
    const OSSL_CORE_HANDLE *core;
    OSSL_LIB_CTX *libctx;  /* Library context (后续调用 OpenSSL API 需要) */

    /* 密码卡 DLL 句柄 */
#ifdef _WIN32
    HMODULE dll_handle;
#else
    void *dll_handle;
#endif

    /* 厂商 DLL 路径和配置 */
    char *module_path;
    int module_type;
    char *password;
    char *start_password;
    int debug;

    /* 设备和会话句柄 */
    SGD_HANDLE hDevice;
    SGD_HANDLE hSession;

    /* 设备信息 */
    DEVICEINFO device_info;

    /* SDF 函数指针表 (从厂商 DLL 动态加载) */
    SD_FUNCTION_LIST sdfList;

    /* 状态 */
    int initialized;
    int card_available;
} SDF_PROV_CTX;

/* 密钥对象 */
typedef struct sdf_prov_key_st {
    SDF_PROV_CTX *ctx;          /* Provider 上下文 */

    /* 密钥标识 */
    int key_index;              /* 密钥索引 (设备上的) */
    int key_usage;              /* 1=签名, 2=加密, 3=密钥协商 */
    int algorithm_id;           /* 算法 ID: NID_sm2 等 */

    /* 公钥信息 (可导出) */
    EC_KEY *ec_key;             /* SM2 EC_KEY */

    /* 密钥属性 */
    unsigned char *pubkey_buf;  /* 公钥原始数据 (未压缩格式) */
    int pubkey_len;

    int refcnt;                 /* 引用计数 */
} SDF_PROV_KEY;

/* 函数声明 */

/* Provider 入口 */
OSSL_provider_init_fn ossl_sdf_provider_init;

/* Provider 上下文管理 */
SDF_PROV_CTX *SDF_PROV_CTX_new(void);
void SDF_PROV_CTX_free(void *provctx);
int SDF_PROV_CTX_init(SDF_PROV_CTX *ctx, const char *config_file);
void SDF_PROV_CTX_close_device(SDF_PROV_CTX *ctx);

/* DLL 加载和函数指针绑定 */
int SDF_PROV_load_library(SDF_PROV_CTX *ctx);
void SDF_PROV_set_function_list(SDF_PROV_CTX *ctx);

/* 错误处理 */
#define SDF_PROVerr(f, r) \
    ERR_raise(ERR_LIB_PROV, (r))

/*
 * 通过 SDF 函数指针调用的快捷宏
 * 所有模块通过 ctx->provctx->sdfList.SDF_* 调用密码卡接口
 */
#define SDF_CALL(ctx, func, ...) ((ctx)->sdfList.func(__VA_ARGS__))

#endif /* PROV_SDF_H */
