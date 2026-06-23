/*
 * SDF Provider for Tongsuo - Provider 入口
 *
 * 实现基于 GM/T 0018 SDF 接口的 Tongsuo Provider
 * 私钥永不离卡，所有私钥操作在密码卡上完成
 *
 * 密码卡 DLL 加载参照 e_sdf.c 的 setFunctionList 方式
 */

#include "prov_sdf.h"
#include "prov_sdf_keys.h"
#include "prov_sdf_sig.h"
#include "prov_sdf_enc.h"
#include "prov_sdf_digest.h"
#include "prov_sdf_cipher.h"
#include "prov_sdf_mac.h"
#include "prov_sdf_rand.h"

#ifdef _WIN32
#include <windows.h>
#define SDF_DLOPEN(filename) LoadLibraryA(filename)
#define SDF_DLSYM(handle, symbol) GetProcAddress((HMODULE)(handle), symbol)
#define SDF_DLCLOSE(handle) FreeLibrary((HMODULE)(handle))
#else
#include <dlfcn.h>
#define SDF_DLOPEN(filename) dlopen(filename, RTLD_LAZY)
#define SDF_DLSYM(handle, symbol) dlsym(handle, symbol)
#define SDF_DLCLOSE(handle) dlclose(handle)
#endif

/*============================================================================
 * DLL 加载和函数指针绑定
 *===========================================================================*/

static void sdf_set_function_list(SDF_PROV_CTX *ctx)
{
    void *h = ctx->dll_handle;
    SD_FUNCTION_LIST *pList = &ctx->sdfList;

    /* 设备管理 */
    pList->SDF_OpenDevice = (_CP_SDF_OpenDevice*)SDF_DLSYM(h, "SDF_OpenDevice");
    pList->SDF_CloseDevice = (_CP_SDF_CloseDevice*)SDF_DLSYM(h, "SDF_CloseDevice");
    pList->SDF_OpenSession = (_CP_SDF_OpenSession*)SDF_DLSYM(h, "SDF_OpenSession");
    pList->SDF_CloseSession = (_CP_SDF_CloseSession*)SDF_DLSYM(h, "SDF_CloseSession");
    pList->SDF_GetDeviceInfo = (_CP_SDF_GetDeviceInfo*)SDF_DLSYM(h, "SDF_GetDeviceInfo");
    pList->SDF_GenerateRandom = (_CP_SDF_GenerateRandom*)SDF_DLSYM(h, "SDF_GenerateRandom");
    pList->SDF_GetPrivateKeyAccessRight =
        (_CP_SDF_GetPrivateKeyAccessRight*)SDF_DLSYM(h, "SDF_GetPrivateKeyAccessRight");
    pList->SDF_ReleasePrivateKeyAccessRight =
        (_CP_SDF_ReleasePrivateKeyAccessRight*)SDF_DLSYM(h, "SDF_ReleasePrivateKeyAccessRight");

    /* 对称密钥管理 */
    pList->SDF_ImportKey = (_CP_SDF_ImportKey*)SDF_DLSYM(h, "SDF_ImportKey");
    pList->SDF_DestroyKey = (_CP_SDF_DestroyKey*)SDF_DLSYM(h, "SDF_DestroyKey");
    pList->SDF_GetSymmKeyHandle =
        (_CP_SDF_GetSymmKeyHandle*)SDF_DLSYM(h, "SDF_GetSymmKeyHandle");
    pList->SDF_GenerateKeyWithKEK =
        (_CP_SDF_GenerateKeyWithKEK*)SDF_DLSYM(h, "SDF_GenerateKeyWithKEK");
    pList->SDF_ImportKeyWithKEK =
        (_CP_SDF_ImportKeyWithKEK*)SDF_DLSYM(h, "SDF_ImportKeyWithKEK");

    /* ECC 密钥管理 */
    pList->SDF_GenerateKeyPair_ECC =
        (_CP_SDF_GenerateKeyPair_ECC*)SDF_DLSYM(h, "SDF_GenerateKeyPair_ECC");
    pList->SDF_ExportSignPublicKey_ECC =
        (_CP_SDF_ExportSignPublicKey_ECC*)SDF_DLSYM(h, "SDF_ExportSignPublicKey_ECC");
    pList->SDF_ExportEncPublicKey_ECC =
        (_CP_SDF_ExportEncPublicKey_ECC*)SDF_DLSYM(h, "SDF_ExportEncPublicKey_ECC");
    pList->SDF_ImportKeyWithISK_ECC =
        (_CP_SDF_ImportKeyWithISK_ECC*)SDF_DLSYM(h, "SDF_ImportKeyWithISK_ECC");
    pList->SDF_ImportKeyPair_ECC =
        (_CP_SDF_ImportKeyPair_ECC*)SDF_DLSYM(h, "SDF_ImportKeyPair_ECC");

    /* ECC 协商 */
    pList->SDF_GenerateAgreementDataWithECC =
        (_CP_SDF_GenerateAgreementDataWithECC*)SDF_DLSYM(h, "SDF_GenerateAgreementDataWithECC");
    pList->SDF_GenerateKeyWithECC =
        (_CP_SDF_GenerateKeyWithECC*)SDF_DLSYM(h, "SDF_GenerateKeyWithECC");
    pList->SDF_GenerateAgreementDataAndKeyWithECC =
        (_CP_SDF_GenerateAgreementDataAndKeyWithECC*)SDF_DLSYM(h, "SDF_GenerateAgreementDataAndKeyWithECC");
    pList->SDF_GenerateAgreementDataWithECCEx =
        (_CP_SDF_GenerateAgreementDataWithECCEx*)SDF_DLSYM(h, "SDF_GenerateAgreementDataWithECCEx");
    pList->SDF_GenerateKeyWithECCEx =
        (_CP_SDF_GenerateKeyWithECCEx*)SDF_DLSYM(h, "SDF_GenerateKeyWithECCEx");
    pList->SDF_GenerateAgreementDataAndKeyWithECCEx =
        (_CP_SDF_GenerateAgreementDataAndKeyWithECCEx*)SDF_DLSYM(h, "SDF_GenerateAgreementDataAndKeyWithECCEx");

    /* 非对称运算 */
    pList->SDF_InternalSign_ECC =
        (_CP_SDF_InternalSign_ECC*)SDF_DLSYM(h, "SDF_InternalSign_ECC");
    pList->SDF_InternalVerify_ECC =
        (_CP_SDF_InternalVerify_ECC*)SDF_DLSYM(h, "SDF_InternalVerify_ECC");
    pList->SDF_InternalEncrypt_ECC =
        (_CP_SDF_InternalEncrypt_ECC*)SDF_DLSYM(h, "SDF_InternalEncrypt_ECC");
    pList->SDF_InternalDecrypt_ECC =
        (_CP_SDF_InternalDecrypt_ECC*)SDF_DLSYM(h, "SDF_InternalDecrypt_ECC");
    pList->SDF_ExternalSign_ECC =
        (_CP_SDF_ExternalSign_ECC*)SDF_DLSYM(h, "SDF_ExternalSign_ECC");
    pList->SDF_ExternalVerify_ECC =
        (_CP_SDF_ExternalVerify_ECC*)SDF_DLSYM(h, "SDF_ExternalVerify_ECC");
    pList->SDF_ExternalEncrypt_ECC =
        (_CP_SDF_ExternalEncrypt_ECC*)SDF_DLSYM(h, "SDF_ExternalEncrypt_ECC");
    pList->SDF_ExternalDecrypt_ECC =
        (_CP_SDF_ExternalDecrypt_ECC*)SDF_DLSYM(h, "SDF_ExternalDecrypt_ECC");

    /* 对称运算 */
    pList->SDF_Encrypt = (_CP_SDF_Encrypt*)SDF_DLSYM(h, "SDF_Encrypt");
    pList->SDF_Decrypt = (_CP_SDF_Decrypt*)SDF_DLSYM(h, "SDF_Decrypt");
    pList->SDF_CalculateMAC = (_CP_SDF_CalculateMAC*)SDF_DLSYM(h, "SDF_CalculateMAC");

    /* 杂凑运算 */
    pList->SDF_HashInit = (_CP_SDF_HashInit*)SDF_DLSYM(h, "SDF_HashInit");
    pList->SDF_HashUpdate = (_CP_SDF_HashUpdate*)SDF_DLSYM(h, "SDF_HashUpdate");
    pList->SDF_HashFinal = (_CP_SDF_HashFinal*)SDF_DLSYM(h, "SDF_HashFinal");

    /* 文件操作 */
    pList->SDF_CreateFile = (_CP_SDF_CreateFile*)SDF_DLSYM(h, "SDF_CreateFile");
    pList->SDF_ReadFile = (_CP_SDF_ReadFile*)SDF_DLSYM(h, "SDF_ReadFile");
    pList->SDF_WriteFile = (_CP_SDF_WriteFile*)SDF_DLSYM(h, "SDF_WriteFile");
    pList->SDF_DeleteFile = (_CP_SDF_DeleteFile*)SDF_DLSYM(h, "SDF_DeleteFile");

    /* 扩展接口 */
    pList->SDF_GetErrMsg = (_CP_SDF_GetErrMsg*)SDF_DLSYM(h, "SDF_GetErrMsg");
    pList->SDF_GetKekAccessRight =
        (_CP_SDF_GetKekAccessRight*)SDF_DLSYM(h, "SDF_GetKekAccessRight");
    pList->SDF_ReleaseKekAccessRight =
        (_CP_SDF_ReleaseKekAccessRight*)SDF_DLSYM(h, "SDF_ReleaseKekAccessRight");
    pList->BYCSM_LoadModule =
        (_CP_BYCSM_LoadModule*)SDF_DLSYM(h, "BYCSM_LoadModule");
    pList->BYCSM_UninstallModule =
        (_CP_BYCSM_UninstallModule*)SDF_DLSYM(h, "BYCSM_UninstallModule");
}

static int sdf_load_library(SDF_PROV_CTX *ctx)
{
    if (ctx == NULL || ctx->module_path == NULL) {
        return 0;
    }

    if (ctx->dll_handle != NULL)
        return 1; /* 已加载 */

    ctx->dll_handle = SDF_DLOPEN(ctx->module_path);
    if (ctx->dll_handle == NULL) {
        return 0;
    }

    /* 绑定所有 SDF 函数指针 */
    sdf_set_function_list(ctx);

    /* 检查必要函数 */
    if (ctx->sdfList.SDF_OpenDevice == NULL
        || ctx->sdfList.SDF_CloseDevice == NULL
        || ctx->sdfList.SDF_OpenSession == NULL
        || ctx->sdfList.SDF_CloseSession == NULL) {
        SDF_DLCLOSE(ctx->dll_handle);
        ctx->dll_handle = NULL;
        return 0;
    }

    return 1;
}

/*============================================================================
 * Provider 上下文管理
 *===========================================================================*/

SDF_PROV_CTX *SDF_PROV_CTX_new(void)
{
    SDF_PROV_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    return ctx;
}

void SDF_PROV_CTX_free(void *provctx)
{
    SDF_PROV_CTX *ctx = (SDF_PROV_CTX *)provctx;

    if (ctx == NULL)
        return;

    /* 关闭会话和设备 */
    if (ctx->initialized) {
        if (ctx->hSession != SGD_NULL)
            ctx->sdfList.SDF_CloseSession(ctx->hSession);
        if (ctx->hDevice != SGD_NULL)
            ctx->sdfList.SDF_CloseDevice(ctx->hDevice);
    }

    /* 卸载 DLL */
    if (ctx->dll_handle != NULL)
        SDF_DLCLOSE(ctx->dll_handle);

    OPENSSL_free(ctx->module_path);
    OPENSSL_free(ctx->password);
    OPENSSL_free(ctx->start_password);
    OPENSSL_free(ctx);
}

int SDF_PROV_CTX_init(SDF_PROV_CTX *ctx, const char *config_file)
{
    int ret;

    if (ctx == NULL)
        return 0;

    if (ctx->initialized)
        return 1;

    /* 加载 DLL */
    if (!sdf_load_library(ctx))
        return 0;

    /* 加载模块 (部分厂商需要) */
    if (ctx->sdfList.BYCSM_LoadModule != NULL && ctx->start_password != NULL) {
        ret = ctx->sdfList.BYCSM_LoadModule(ctx->start_password);
        if (ret != SDR_OK)
            return 0;
    }

    /* 打开设备 */
    ret = ctx->sdfList.SDF_OpenDevice(&ctx->hDevice);
    if (ret != SDR_OK) {
        return 0;
    }

    /* 打开会话 */
    ret = ctx->sdfList.SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    if (ret != SDR_OK) {
        ctx->sdfList.SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = SGD_NULL;
        return 0;
    }

    /* 获取设备信息 */
    if (ctx->sdfList.SDF_GetDeviceInfo != NULL) {
        ret = ctx->sdfList.SDF_GetDeviceInfo(ctx->hSession, &ctx->device_info);
        if (ret != SDR_OK)
            ; /* 获取失败不影响使用 */
    }

    ctx->initialized = 1;
    ctx->card_available = 1;

    return 1;
}

void SDF_PROV_CTX_close_device(SDF_PROV_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->hSession != SGD_NULL) {
        ctx->sdfList.SDF_CloseSession(ctx->hSession);
        ctx->hSession = SGD_NULL;
    }

    if (ctx->hDevice != SGD_NULL) {
        ctx->sdfList.SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = SGD_NULL;
    }

    ctx->card_available = 0;
    ctx->initialized = 0;
}

/*============================================================================
 * Provider 全局参数
 *===========================================================================*/

static const OSSL_PARAM sdf_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_DEFN("card_available", OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sdf_prov_gettable_params(void *provctx)
{
    return sdf_param_types;
}

static int sdf_prov_get_params(void *provctx, OSSL_PARAM params[])
{
    SDF_PROV_CTX *ctx = (SDF_PROV_CTX *)provctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "SDF Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SDF_PROVIDER_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, SDF_PROVIDER_BUILDINFO))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->card_available ? 1 : 0))
        return 0;

    p = OSSL_PARAM_locate(params, "card_available");
    if (p != NULL && !OSSL_PARAM_set_int(p, ctx->card_available ? 1 : 0))
        return 0;

    return 1;
}

/*============================================================================
 * 算法查询
 *===========================================================================*/

static const OSSL_ALGORITHM *sdf_prov_query(void *provctx,
                                              int operation_id,
                                              int *no_cache)
{
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return sdf_keymgmt_sm2;
    case OSSL_OP_SIGNATURE:
        return sdf_signature_sm2;
    case OSSL_OP_ASYM_CIPHER:
        return sdf_asym_cipher_sm2;
    case OSSL_OP_DIGEST:
        return sdf_digest_sm3;
    case OSSL_OP_CIPHER:
        return sdf_cipher_sm4;
    case OSSL_OP_MAC:
        return sdf_mac_cmac_sm4;
    case OSSL_OP_RAND:
        return sdf_rand;
    default:
        return NULL;
    }
}

/*============================================================================
 * Provider 分发表和入口
 *===========================================================================*/

static const OSSL_DISPATCH sdf_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))sdf_prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))sdf_prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sdf_prov_query },
    { OSSL_FUNC_PROVIDER_TEARDOWN,        (void (*)(void))SDF_PROV_CTX_free },
    { 0, NULL }
};

OSSL_provider_init_fn ossl_sdf_provider_init;
# define OSSL_provider_init_int ossl_sdf_provider_init

int ossl_sdf_provider_init(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            void **provctx)
{
    SDF_PROV_CTX *ctx;
    OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    OSSL_PARAM params[5];
    /* 使用指针接收 core 传递的配置值 (core_get_params 用 set_utf8_ptr) */
    const char *module_path_ptr = NULL;
    const char *password_ptr = NULL;
    const char *start_password_ptr = NULL;
    int debug = 0;

    /* 解析 core dispatch 表，获取核心函数指针 */
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        }
    }

    ctx = SDF_PROV_CTX_new();
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->core = handle;
    ctx->initialized = 0;
    ctx->card_available = 0;

    /* 保存 libctx (后续调用 OpenSSL API 需要) */
    if (c_get_libctx != NULL)
        ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

    /*
     * 从 openssl.cnf 的 [sdfprov] 段读取配置参数。
     *
     * 工作原理：
     * 1. provider_conf.c 解析 [sdfprov] 段，将键值对存入 prov->parameters
     * 2. core_get_params() 遍历 prov->parameters，用 OSSL_PARAM_set_utf8_ptr
     *    将值指针设置到我们提供的 OSSL_PARAM 中
     * 3. 因此必须使用 OSSL_PARAM_construct_utf8_ptr 接收指针
     */
    if (c_get_params != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_ptr("module_path",
                                                   (char **)&module_path_ptr,
                                                   0);
        params[1] = OSSL_PARAM_construct_utf8_ptr("password",
                                                   (char **)&password_ptr,
                                                   0);
        params[2] = OSSL_PARAM_construct_utf8_ptr("start_password",
                                                   (char **)&start_password_ptr,
                                                   0);
        params[3] = OSSL_PARAM_construct_int("debug", &debug);
        params[4] = OSSL_PARAM_construct_end();

        if (c_get_params(handle, params)) {
            ctx->debug = debug;

            /* 复制字符串到 ctx (core 的指针生命周期由 core 管理) */
            if (module_path_ptr != NULL) {
                ctx->module_path = OPENSSL_strdup(module_path_ptr);
                if (ctx->module_path == NULL) {
                    SDF_PROV_CTX_free(ctx);
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
            }
            if (password_ptr != NULL) {
                ctx->password = OPENSSL_strdup(password_ptr);
                if (ctx->password == NULL) {
                    SDF_PROV_CTX_free(ctx);
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
            }
            if (start_password_ptr != NULL) {
                ctx->start_password = OPENSSL_strdup(start_password_ptr);
                if (ctx->start_password == NULL) {
                    SDF_PROV_CTX_free(ctx);
                    ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
            }
        }
    }

    /*
     * 尝试初始化密码卡
     * 如果 module_path 未配置或 DLL 加载失败或设备打开失败，
     * Provider 会正常加载但 card_available = 0
     */
    if (ctx->module_path != NULL) {
        if (SDF_PROV_CTX_init(ctx, NULL) == 1) {
            ctx->card_available = 1;
        } else {
            ctx->card_available = 0;
        }
    }

    *out = sdf_dispatch_table;
    *provctx = ctx;

    return 1;
}
