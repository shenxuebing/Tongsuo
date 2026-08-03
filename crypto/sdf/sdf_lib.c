/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/sdf.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
# include <windows.h>
#endif
#include "internal/thread_once.h"
#include "internal/dso.h"
#include "internal/sdf.h"
#include "sdf_local.h"

#define SDF_SM2DH_EX_SECRET_LEN 48

#ifdef SDF_LIB
# ifdef SDF_LIB_SHARED
static DSO *sdf_dso = NULL;
# else
extern int SDF_OpenDevice(void **phDeviceHandle) __attribute__((weak));
extern int SDF_CloseDevice(void *hDeviceHandle) __attribute__((weak));
extern int SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle) __attribute__((weak));
extern int SDF_CloseSession(void *hSessionHandle) __attribute__((weak));

extern int SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
    unsigned char *pucRandom) __attribute__((weak));

extern int SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucPassword,
    unsigned int uiPwdLength);

extern int SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
    unsigned int uiKeyIndex);

extern int SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucKey,
    void **phKeyHandle) __attribute__((weak));

extern int SDF_ImportKeyWithKEK(void *hSessionHandle,
    unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle) __attribute__((weak));

extern int SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey)
    __attribute__((weak));

extern int SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey)
    __attribute__((weak));

extern int SDF_ExportSignPublicKey_RSA(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey)
    __attribute__((weak));

extern int SDF_ExportSignPublicKey_RSAEx(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKeyEx *pucPublicKey)
    __attribute__((weak));

extern int SDF_ExportEncPublicKey_RSA(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey)
    __attribute__((weak));

extern int SDF_ExportEncPublicKey_RSAEx(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKeyEx *pucPublicKey)
    __attribute__((weak));

extern int SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
    __attribute__((weak));

extern int SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle,
    OSSL_RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));

extern int SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle,
    OSSL_RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));

extern int SDF_InternalPublicKeyOperation_RSA_Ex(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiKeyUsage,
    unsigned char *pucDataInput, unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalPublicKeyOperation_RSAEx(void *hSessionHandle,
    OSSL_RSArefPublicKeyEx *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalPublicKeyOperation_RSA_Ex(void *hSessionHandle,
    OSSL_RSArefPublicKeyEx *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));

extern int SDF_InternalPrivateKeyOperation_RSA_Ex(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiKeyUsage,
    unsigned char *pucDataInput, unsigned int uiInputLength,
    unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalPrivateKeyOperation_RSAEx(void *hSessionHandle,
    OSSL_RSArefPrivateKeyEx *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));
extern int SDF_ExternalPrivateKeyOperation_RSA_Ex(void *hSessionHandle,
    OSSL_RSArefPrivateKeyEx *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength) __attribute__((weak));

extern int SDF_InternalEncrypt_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiAlgID, unsigned char *pucData,
    unsigned int uiDataLength, OSSL_ECCCipher * pucEncData);

extern int SDF_InternalDecrypt_ECC(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiAlgID, OSSL_ECCCipher *pucEncData,
    unsigned char *pucData, unsigned int *puiDataLength);

extern int SDF_InternalSign_ECC(void * hSessionHandle, unsigned int uiISKIndex,
    unsigned char * pucData, unsigned int uiDataLength,
    OSSL_ECCSignature * pucSignature);

extern int SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength) __attribute__((weak));

extern int SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength) __attribute__((weak));

extern int SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength) __attribute__((weak));

extern int SDFE_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
    uint32_t len, void **pkey_handle) __attribute__((weak));

extern int SDF_GenerateAgreementDataWithECCEx(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle) __attribute__((weak));

extern int SDF_GenerateKeyWithECCEx(void *hSessionHandle,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle) __attribute__((weak));

extern int SDF_GenerateAgreementDataAndKeyWithECCEx(
    void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle) __attribute__((weak));
# endif

/*
 * SDF 框架层全局状态
 *
 * sdf_dso: 厂商库 DSO 句柄（DSO_load 加载），整个进程只加载一次
 * sdfm: SDF_METHOD 函数指针表，所有 TSAPI_SDF_* 接口通过它转发到厂商库
 * sdf_preload_*: 由 ossl_sdf_lib_preload() 设置的预加载参数，
 *                在 RUN_ONCE 初始化时使用
 */
static CRYPTO_ONCE sdf_lib_once = CRYPTO_ONCE_STATIC_INIT;
static SDF_METHOD sdfm;
static char *sdf_preload_path = NULL;
static char *sdf_preload_password = NULL;
static int sdf_preload_use_load_module = 0;

#if defined(SDF_LIB) && defined(SDF_LIB_SHARED)
static DSO_FUNC_TYPE bind_first_available(DSO *dso, const char *name1,
                                          const char *name2,
                                          const char *name3)
{
    DSO_FUNC_TYPE f = NULL;

    if (name1 != NULL)
        f = DSO_bind_func(dso, name1);
    if (f == NULL && name2 != NULL)
        f = DSO_bind_func(dso, name2);
    if (f == NULL && name3 != NULL)
        f = DSO_bind_func(dso, name3);

    return f;
}
#endif

#ifdef _WIN32
/*
 * 切换当前工作目录到厂商 DLL 所在目录（Windows 专用）
 *
 * 某些厂商 DLL（如 byzk0018.dll）在加载时会依赖同目录下的配置文件
 * （如 softModule.ini、yj.db），DSO_load 用相对路径加载时需要先
 * 切换到 DLL 所在目录，加载完成后再恢复原目录。
 *
 * 参数：
 *   dll_path  - 厂商库路径（如 "E:\\...\\byzk0018.dll"）
 *   saved_cwd - 输出：切换前的原始目录（调用方负责 OPENSSL_free）
 * 返回：1=成功，0=失败
 */
static int ossl_sdf_push_dll_dir(const char *dll_path, char **saved_cwd)
{
    DWORD cwd_len;
    char *cwd = NULL;
    char *dir = NULL;
    char *sep;

    if (saved_cwd == NULL || dll_path == NULL)
        return 0;

    cwd_len = GetCurrentDirectoryA(0, NULL);
    if (cwd_len == 0)
        return 0;

    cwd = OPENSSL_malloc(cwd_len);
    if (cwd == NULL)
        return 0;

    if (GetCurrentDirectoryA(cwd_len, cwd) == 0) {
        OPENSSL_free(cwd);
        return 0;
    }

    dir = OPENSSL_strdup(dll_path);
    if (dir == NULL) {
        OPENSSL_free(cwd);
        return 0;
    }

    sep = strrchr(dir, '\\');
    if (sep == NULL)
        sep = strrchr(dir, '/');
    if (sep == NULL) {
        OPENSSL_free(dir);
        OPENSSL_free(cwd);
        return 0;
    }
    *sep = '\0';

    if (!SetCurrentDirectoryA(dir)) {
        OPENSSL_free(dir);
        OPENSSL_free(cwd);
        return 0;
    }

    OPENSSL_free(dir);
    *saved_cwd = cwd;
    return 1;
}

/* 恢复原工作目录（配合 ossl_sdf_push_dll_dir 使用） */
static void ossl_sdf_pop_dll_dir(char *saved_cwd)
{
    if (saved_cwd != NULL) {
        SetCurrentDirectoryA(saved_cwd);
        OPENSSL_free(saved_cwd);
    }
}
#endif

/*
 * SDF 框架层一次性初始化（通过 RUN_ONCE 保证线程安全，整个进程只执行一次）
 *
 * 流程：
 *   1. DSO_load() 加载厂商库（如 byzk0018.dll）
 *   2. DSO_bind_func() 绑定所有标准 SDF API 函数指针到 sdfm
 *   3. 绑定扩展 API（GenerateKey、GenerateAgreementData 等，可能不存在）
 *   4. 绑定厂商特定接口 BYCSM_LoadModule（博雅等厂商需要，可能不存在）
 *   5. 如果 use_load_module=1 且 LoadModule 可用，调用 BYCSM_LoadModule(password)
 *
 * 静态链接时（非 SDF_LIB_SHARED），直接用编译时链接的 SDF_* 符号。
 */
DEFINE_RUN_ONCE_STATIC(ossl_sdf_lib_init)
{
# ifdef SDF_LIB_SHARED
#  ifndef LIBSDF
#   define LIBSDF "sdf"
#  endif
#  ifdef _WIN32
    char *saved_cwd = NULL;
#  endif

    /*
     * 若 ossl_sdf_lib_preload 未设置路径（TSAPI/sdf 命令等非 provider 路径），
     * 从环境变量 SDF_LIB_PATH / SDF_MODULE_PASSWORD / SDF_USE_LOADMODULE 回退，
     * 保持与 sdfprov provider（sdfprov_ctx_init_device）一致的配置来源。
     * 这样 openssl sdf 等命令无需手动 preload 即可自动加载厂商库。
     */
    if (sdf_preload_path == NULL) {
        const char *env_path = getenv("SDF_LIB_PATH");
        if (env_path != NULL && env_path[0] != '\0') {
            sdf_preload_path = OPENSSL_strdup(env_path);
            if (sdf_preload_path == NULL)
                return 0;
        }
    }
    if (sdf_preload_password == NULL) {
        const char *env_pwd = getenv("SDF_MODULE_PASSWORD");
        if (env_pwd != NULL)
            sdf_preload_password = OPENSSL_strdup(env_pwd);
    }
    if (!sdf_preload_use_load_module) {
        const char *env_ulm = getenv("SDF_USE_LOADMODULE");
        sdf_preload_use_load_module =
            (env_ulm == NULL || env_ulm[0] != '0') ? 1 : 0;
    }

#  ifdef _WIN32
    if (sdf_preload_path != NULL)
        (void)ossl_sdf_push_dll_dir(sdf_preload_path, &saved_cwd);
#  endif

    sdf_dso = DSO_load(NULL,
                       sdf_preload_path != NULL ? sdf_preload_path : LIBSDF,
                       NULL,
                       (sdf_preload_path != NULL
                        ? DSO_FLAG_NO_NAME_TRANSLATION : 0)
#  ifndef _WIN32
                       | DSO_FLAG_NO_UNLOAD_ON_FREE
#  endif
                       );
    if (sdf_dso != NULL) {
        sdfm.OpenDevice = (SDF_OpenDevice_fn)DSO_bind_func(sdf_dso, "SDF_OpenDevice");
        sdfm.CloseDevice = (SDF_CloseDevice_fn)DSO_bind_func(sdf_dso, "SDF_CloseDevice");
        sdfm.OpenSession = (SDF_OpenSession_fn)DSO_bind_func(sdf_dso, "SDF_OpenSession");
        sdfm.CloseSession = (SDF_CloseSession_fn)DSO_bind_func(sdf_dso, "SDF_CloseSession");
        sdfm.GenerateRandom = (SDF_GenerateRandom_fn)DSO_bind_func(sdf_dso, "SDF_GenerateRandom");
        sdfm.GetPrivateKeyAccessRight = (SDF_GetPrivateKeyAccessRight_fn)DSO_bind_func(sdf_dso, "SDF_GetPrivateKeyAccessRight");
        sdfm.ReleasePrivateKeyAccessRight = (SDF_ReleasePrivateKeyAccessRight_fn)DSO_bind_func(sdf_dso, "SDF_ReleasePrivateKeyAccessRight");
        sdfm.ImportKeyWithISK_ECC = (SDF_ImportKeyWithISK_ECC_fn)DSO_bind_func(sdf_dso, "SDF_ImportKeyWithISK_ECC");
        sdfm.ImportKeyWithKEK = (SDF_ImportKeyWithKEK_fn)DSO_bind_func(sdf_dso, "SDF_ImportKeyWithKEK");
        sdfm.ExportSignPublicKey_ECC = (SDF_ExportSignPublicKey_ECC_fn)DSO_bind_func(sdf_dso, "SDF_ExportSignPublicKey_ECC");
        sdfm.ExportEncPublicKey_ECC = (SDF_ExportEncPublicKey_ECC_fn)DSO_bind_func(sdf_dso, "SDF_ExportEncPublicKey_ECC");
        sdfm.ExportSignPublicKey_RSA = (SDF_ExportSignPublicKey_RSA_fn)DSO_bind_func(sdf_dso, "SDF_ExportSignPublicKey_RSA");
        sdfm.ExportSignPublicKey_RSAEx = (SDF_ExportSignPublicKey_RSAEx_fn)DSO_bind_func(sdf_dso, "SDF_ExportSignPublicKey_RSAEx");
        sdfm.ExportEncPublicKey_RSA = (SDF_ExportEncPublicKey_RSA_fn)DSO_bind_func(sdf_dso, "SDF_ExportEncPublicKey_RSA");
        sdfm.ExportEncPublicKey_RSAEx = (SDF_ExportEncPublicKey_RSAEx_fn)DSO_bind_func(sdf_dso, "SDF_ExportEncPublicKey_RSAEx");
        sdfm.DestroyKey = (SDF_DestroyKey_fn)DSO_bind_func(sdf_dso, "SDF_DestroyKey");
        sdfm.ExternalPublicKeyOperation_RSA = (SDF_ExternalPublicKeyOperation_RSA_fn)DSO_bind_func(sdf_dso, "SDF_ExternalPublicKeyOperation_RSA");
        sdfm.ExternalPublicKeyOperation_RSAEx = (SDF_ExternalPublicKeyOperation_RSAEx_fn)DSO_bind_func(sdf_dso, "SDF_ExternalPublicKeyOperation_RSAEx");
        if (sdfm.ExternalPublicKeyOperation_RSAEx == NULL)
            sdfm.ExternalPublicKeyOperation_RSAEx = (SDF_ExternalPublicKeyOperation_RSAEx_fn)DSO_bind_func(sdf_dso, "SDF_ExternalPublicKeyOperation_RSA_Ex");
        sdfm.InternalPublicKeyOperation_RSA = (SDF_InternalPublicKeyOperation_RSA_fn)DSO_bind_func(sdf_dso, "SDF_InternalPublicKeyOperation_RSA");
        sdfm.ExternalPrivateKeyOperation_RSA = (SDF_ExternalPrivateKeyOperation_RSA_fn)DSO_bind_func(sdf_dso, "SDF_ExternalPrivateKeyOperation_RSA");
        sdfm.ExternalPrivateKeyOperation_RSAEx = (SDF_ExternalPrivateKeyOperation_RSAEx_fn)DSO_bind_func(sdf_dso, "SDF_ExternalPrivateKeyOperation_RSAEx");
        if (sdfm.ExternalPrivateKeyOperation_RSAEx == NULL)
            sdfm.ExternalPrivateKeyOperation_RSAEx = (SDF_ExternalPrivateKeyOperation_RSAEx_fn)DSO_bind_func(sdf_dso, "SDF_ExternalPrivateKeyOperation_RSA_Ex");
        sdfm.InternalPrivateKeyOperation_RSA = (SDF_InternalPrivateKeyOperation_RSA_fn)DSO_bind_func(sdf_dso, "SDF_InternalPrivateKeyOperation_RSA");
        sdfm.InternalPublicKeyOperation_RSA_Ex = (SDF_InternalPublicKeyOperation_RSA_Ex_fn)DSO_bind_func(sdf_dso, "SDF_InternalPublicKeyOperation_RSA_Ex");
        sdfm.InternalPrivateKeyOperation_RSA_Ex = (SDF_InternalPrivateKeyOperation_RSA_Ex_fn)DSO_bind_func(sdf_dso, "SDF_InternalPrivateKeyOperation_RSA_Ex");
        sdfm.InternalEncrypt_ECC = (SDF_InternalEncrypt_ECC_fn)DSO_bind_func(sdf_dso, "SDF_InternalEncrypt_ECC");
        sdfm.InternalDecrypt_ECC = (SDF_InternalDecrypt_ECC_fn)DSO_bind_func(sdf_dso, "SDF_InternalDecrypt_ECC");
        sdfm.InternalSign_ECC = (SDF_InternalSign_ECC_fn)DSO_bind_func(sdf_dso, "SDF_InternalSign_ECC");
        sdfm.Encrypt = (SDF_Encrypt_fn)DSO_bind_func(sdf_dso, "SDF_Encrypt");
        sdfm.Decrypt = (SDF_Decrypt_fn)DSO_bind_func(sdf_dso, "SDF_Decrypt");
        sdfm.CalculateMAC = (SDF_CalculateMAC_fn)DSO_bind_func(sdf_dso, "SDF_CalculateMAC");

        /* SDFE_GenerateKey 是扩展函数，部分厂商 DLL 不提供，绑定失败不影响基本功能 */
        ERR_set_mark();
        sdfm.GenerateKey = (SDF_GenerateKey_fn)DSO_bind_func(sdf_dso, "SDFE_GenerateKey");
        sdfm.GenerateAgreementDataWithECCEx = (SDF_GenerateAgreementDataWithECCEx_fn)DSO_bind_func(sdf_dso, "SDF_GenerateAgreementDataWithECCEx");
        sdfm.GenerateKeyWithECCEx = (SDF_GenerateKeyWithECCEx_fn)DSO_bind_func(sdf_dso, "SDF_GenerateKeyWithECCEx");
        sdfm.GenerateAgreementDataAndKeyWithECCEx = (SDF_GenerateAgreementDataAndKeyWithECCEx_fn)DSO_bind_func(sdf_dso, "SDF_GenerateAgreementDataAndKeyWithECCEx");
        sdfm.GenerateAgreementDataWithECC_Ex_SW =
            (SDF_GenerateAgreementDataWithECC_Ex_SW_fn)DSO_bind_func(
                sdf_dso, "SDF_GenerateAgreementDataWithECC_Ex");
        sdfm.GenerateKeyWithECC_Ex_SW =
            (SDF_GenerateKeyWithECC_Ex_SW_fn)DSO_bind_func(
                sdf_dso, "SDF_GenerateKeyWithECC_Ex");
        sdfm.GenerateAgreementDataAndKeyWithECC_Ex_SW =
            (SDF_GenerateAgreementDataAndKeyWithECC_Ex_SW_fn)DSO_bind_func(
                sdf_dso, "SDF_GenerateAgreementDataAndKeyWithECC_Ex");
        /* BYCSM_LoadModule 是厂商特定接口，部分厂商 DLL 不提供，绑定失败不影响基本功能 */
        sdfm.LoadModule = (SDFE_LoadModule_fn)DSO_bind_func(sdf_dso, "BYCSM_LoadModule");
        /* BYCSM_UninstallModule 与 LoadModule 配对，用于卸载模块并释放厂商库内加载的 OpenSSL Provider，
         * 避免进程退出阶段 destructor 里 OSSL_PROVIDER_unload 因状态不可靠而泄漏。
         * 同样为厂商特定接口，绑定失败不影响基本功能。 */
        sdfm.UninstallModule = (SDFE_UninstallModule_fn)DSO_bind_func(sdf_dso, "BYCSM_UninstallModule");
        /*
         * SWCSM_* 密钥管理接口（三未 swsds 与 byzk0018 均导出此前缀）。
         * 绑定失败（部分厂商库不提供）保持 NULL，SDFE_* stub 会返回 NOTSUPPORT。
         */
        sdfm.GenECCKey = (SDFE_GenECCKey_fn)bind_first_available(sdf_dso,
            "SWCSM_GenerateECCKeyPair", "BYCSM_GenerateECCKeyPair", NULL);
        sdfm.DelECCKey = (SDFE_DelECCKey_fn)bind_first_available(sdf_dso,
            "SWCSM_DestroyECCKeyPair", "BYCSM_DestroyECCKeyPair", NULL);
        sdfm.ImportECCKey = (SDFE_ImportECCKey_fn)bind_first_available(sdf_dso,
            "SWCSM_ImportECCKeyPair", "BYCSM_ImportECCKeyPair",
            "SDF_ImportKeyPair_ECC");
        sdfm.InputRSAKey = (SDFE_InputRSAKey_fn)bind_first_available(sdf_dso,
            "SWCSM_InputRSAKeyPair", "BYCSM_InputRSAKeyPair",
            "SDF_InputRSAKeyPair");
        sdfm.InputRSAKeyEx = (SDFE_InputRSAKeyEx_fn)bind_first_available(sdf_dso,
            "SWCSM_InputRSAKeyPair_Ex", "BYCSM_InputRSAKeyPairEx",
            "SDF_InputRSAKeyPairEx");
        ERR_pop_to_mark();

        if (sdf_preload_use_load_module && sdfm.LoadModule != NULL
                && sdf_preload_password != NULL
                && sdfm.LoadModule(sdf_preload_password) != 0) {
#  ifdef _WIN32
            ossl_sdf_pop_dll_dir(saved_cwd);
#  endif
            DSO_free(sdf_dso);
            sdf_dso = NULL;
            memset(&sdfm, 0, sizeof(sdfm));
            return 0;
        }
    }
#  ifdef _WIN32
    ossl_sdf_pop_dll_dir(saved_cwd);
#  endif
# else
    sdfm.OpenDevice = SDF_OpenDevice;
    sdfm.CloseDevice = SDF_CloseDevice;
    sdfm.OpenSession = SDF_OpenSession;
    sdfm.CloseSession = SDF_CloseSession;
    sdfm.GenerateRandom = SDF_GenerateRandom;
    sdfm.GetPrivateKeyAccessRight = SDF_GetPrivateKeyAccessRight;
    sdfm.ReleasePrivateKeyAccessRight = SDF_ReleasePrivateKeyAccessRight;
    sdfm.ImportKeyWithISK_ECC = SDF_ImportKeyWithISK_ECC;
    sdfm.ImportKeyWithKEK = SDF_ImportKeyWithKEK;
    sdfm.ExportSignPublicKey_ECC = SDF_ExportSignPublicKey_ECC;
    sdfm.ExportEncPublicKey_ECC = SDF_ExportEncPublicKey_ECC;
    sdfm.ExportSignPublicKey_RSA = SDF_ExportSignPublicKey_RSA;
    sdfm.ExportSignPublicKey_RSAEx = SDF_ExportSignPublicKey_RSAEx;
    sdfm.ExportEncPublicKey_RSA = SDF_ExportEncPublicKey_RSA;
    sdfm.ExportEncPublicKey_RSAEx = SDF_ExportEncPublicKey_RSAEx;
    sdfm.DestroyKey = SDF_DestroyKey;
    sdfm.ExternalPublicKeyOperation_RSA = SDF_ExternalPublicKeyOperation_RSA;
    sdfm.ExternalPublicKeyOperation_RSAEx = SDF_ExternalPublicKeyOperation_RSAEx;
    if (sdfm.ExternalPublicKeyOperation_RSAEx == NULL)
        sdfm.ExternalPublicKeyOperation_RSAEx = SDF_ExternalPublicKeyOperation_RSA_Ex;
    sdfm.InternalPublicKeyOperation_RSA = SDF_InternalPublicKeyOperation_RSA;
    sdfm.ExternalPrivateKeyOperation_RSA = SDF_ExternalPrivateKeyOperation_RSA;
    sdfm.ExternalPrivateKeyOperation_RSAEx = SDF_ExternalPrivateKeyOperation_RSAEx;
    if (sdfm.ExternalPrivateKeyOperation_RSAEx == NULL)
        sdfm.ExternalPrivateKeyOperation_RSAEx = SDF_ExternalPrivateKeyOperation_RSA_Ex;
    sdfm.InternalPrivateKeyOperation_RSA = SDF_InternalPrivateKeyOperation_RSA;
    sdfm.InternalPublicKeyOperation_RSA_Ex = SDF_InternalPublicKeyOperation_RSA_Ex;
    sdfm.InternalPrivateKeyOperation_RSA_Ex = SDF_InternalPrivateKeyOperation_RSA_Ex;
    sdfm.InternalEncrypt_ECC = SDF_InternalEncrypt_ECC;
    sdfm.InternalDecrypt_ECC = SDF_InternalDecrypt_ECC;
    sdfm.InternalSign_ECC = SDF_InternalSign_ECC;
    sdfm.Encrypt = SDF_Encrypt;
    sdfm.Decrypt = SDF_Decrypt;
    sdfm.CalculateMAC = SDF_CalculateMAC;
    sdfm.GenerateKey = SDFE_GenerateKey;
    sdfm.GenerateAgreementDataWithECCEx = SDF_GenerateAgreementDataWithECCEx;
    sdfm.GenerateKeyWithECCEx = SDF_GenerateKeyWithECCEx;
    sdfm.GenerateAgreementDataAndKeyWithECCEx = SDF_GenerateAgreementDataAndKeyWithECCEx;
    /* 静态链接时，BYCSM_LoadModule/BYCSM_UninstallModule 可能为 NULL，由调用方检查 */
    sdfm.LoadModule = NULL;
    sdfm.UninstallModule = NULL;
    /* SWCSM_* 密钥管理接口静态链接时不绑定，由调用方检查 NULL */
    sdfm.GenECCKey = NULL;
    sdfm.DelECCKey = NULL;
    sdfm.ImportECCKey = NULL;
    sdfm.InputRSAKey = NULL;
    sdfm.InputRSAKeyEx = NULL;
    sdfm.GenerateAgreementDataWithECC_Ex_SW = NULL;
    sdfm.GenerateKeyWithECC_Ex_SW = NULL;
    sdfm.GenerateAgreementDataAndKeyWithECC_Ex_SW = NULL;
# endif
    return 1;
}
#endif

/* 释放 SDF 框架层资源（DSO 句柄、预加载参数） */
void ossl_sdf_lib_cleanup(void)
{
#ifdef SDF_LIB_SHARED
    /* 先卸载厂商模块（释放厂商库内部加载的 OpenSSL Provider），
     * 必须在 DSO_free(dlclose) 之前调用：
     * dlclose 后厂商库代码段被卸载，sdfm.UninstallModule 指针变悬挂。
     * 此处在 OPENSSL_cleanup(atexit) 中调用，OpenSSL 状态仍完整，
     * 可靠释放 provider，避免 destructor 阶段状态不可靠导致泄漏。
     * 调用条件与 BYCSM_LoadModule 对称：仅在 use_load_module=1 时调用，
     * 因为只有 LoadModule 被调用过才需要配对卸载。
     * 用 mark/pop 吞掉厂商接口可能压入的 ERR，保持 ERR 栈干净。 */
    if (sdf_dso != NULL && sdf_preload_use_load_module
            && sdfm.UninstallModule != NULL) {
        ERR_set_mark();
        sdfm.UninstallModule(sdf_preload_password);
        ERR_pop_to_mark();
    }
    DSO_free(sdf_dso);
    sdf_dso = NULL;
#endif
#ifdef SDF_LIB
    /*
     * sdf_preload_path / sdf_preload_password 仅在 SDF_LIB 启用时定义（见上方
     * #ifdef SDF_LIB 块）。未启用 sdf-lib 时这些变量不存在，必须用 SDF_LIB 包裹，
     * 否则在不带 enable-sdf-lib(-dynamic) 的配置下编译会报 undeclared。
     */
    OPENSSL_free(sdf_preload_path);
    sdf_preload_path = NULL;
    OPENSSL_free(sdf_preload_password);
    sdf_preload_password = NULL;
#endif
}

/*
 * 预加载厂商库（由 SDF Provider 的 init_device 调用）
 *
 * 设置厂商库路径、密码、是否调用 BYCSM_LoadModule，
 * 然后触发 RUN_ONCE 执行实际加载。
 *
 * 参数：
 *   path            - 厂商库路径（如 "byzk0018.dll"），为 NULL 时用默认名
 *   password        - BYCSM_LoadModule 的模块密码（如 "88888888"）
 *   use_load_module - 是否调用 BYCSM_LoadModule（1=调用，博雅等厂商需要）
 * 返回：1=成功，0=失败
 */
int ossl_sdf_lib_preload(const char *path, const char *password,
                         int use_load_module)
{
#ifdef SDF_LIB
# ifdef SDF_LIB_SHARED
    if (sdf_dso != NULL)
        return 1;

    if (path != NULL && sdf_preload_path == NULL) {
        sdf_preload_path = OPENSSL_strdup(path);
        if (sdf_preload_path == NULL)
            return 0;
    }

    if (password != NULL && sdf_preload_password == NULL) {
        sdf_preload_password = OPENSSL_strdup(password);
        if (sdf_preload_password == NULL)
            return 0;
    }

    sdf_preload_use_load_module = use_load_module;

    if (!RUN_ONCE(&sdf_lib_once, ossl_sdf_lib_init))
        return 0;
# else
    (void)path;
    (void)password;
    (void)use_load_module;
# endif
#else
    (void)path;
    (void)password;
    (void)use_load_module;
#endif
    return 1;
}

/* 获取 SDF_METHOD 函数指针表（所有 TSAPI_SDF_* 接口通过它转发） */
static const SDF_METHOD *sdf_get_method(void)
{
    const SDF_METHOD *meth = &ts_sdf_meth;

#ifdef SDF_LIB
    if (RUN_ONCE(&sdf_lib_once, ossl_sdf_lib_init))
        meth = &sdfm;
#endif

    return meth;
}

/*
 * 导出版本：供 SDFE_* stub（crypto/tsapi/）跨翻译单元获取 DSO 绑定的函数指针表。
 * 仅在厂商库已成功加载（RUN_ONCE 成功）时返回 &sdfm，否则返回 NULL。
 * 注意：返回值可能为 NULL（厂商库未加载或静态链接），调用方必须判空。
 */
const SDF_METHOD *ossl_sdf_get_method(void)
{
#ifdef SDF_LIB
    if (sdf_dso != NULL && RUN_ONCE(&sdf_lib_once, ossl_sdf_lib_init))
        return &sdfm;
#endif
    return NULL;
}

/*
 * 以下 TSAPI_SDF_* 函数是标准 SDF API 的统一转发层。
 * 每个函数通过 sdf_get_method() 获取函数指针表（ts_sdf_meth），
 * 再通过函数指针调用厂商库中的真实实现。
 * 如果函数指针为 NULL（厂商库不支持该接口），返回 OSSL_SDR_NOTSUPPORT。
 */
int TSAPI_SDF_OpenDevice(void **phDeviceHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->OpenDevice == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->OpenDevice(phDeviceHandle);
}

int TSAPI_SDF_CloseDevice(void *hDeviceHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (hDeviceHandle == NULL)
        return OSSL_SDR_OK;

    if (meth == NULL || meth->CloseDevice == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->CloseDevice(hDeviceHandle);
}

int TSAPI_SDF_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->OpenSession == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->OpenSession(hDeviceHandle, phSessionHandle);
}

int TSAPI_SDF_CloseSession(void *hSessionHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (hSessionHandle == NULL)
        return OSSL_SDR_OK;

    if (meth == NULL || meth->CloseSession == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->CloseSession(hSessionHandle);
}

int TSAPI_SDF_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                             unsigned char *pucRandom)
{
#define MAX_RANDOM_LEN (2048)
    int ret;
    unsigned int len;
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->GenerateRandom == NULL)
        return OSSL_SDR_NOTSUPPORT;

    do {
        if (uiLength > MAX_RANDOM_LEN)
            len = MAX_RANDOM_LEN;
        else
            len = uiLength;

        if ((ret = meth->GenerateRandom(hSessionHandle, len, pucRandom)) != 0)
            return ret;

        uiLength -= len;
        pucRandom += len;
    } while (uiLength > 0);

    return OSSL_SDR_OK;
}

int TSAPI_SDF_GetPrivateKeyAccessRight(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      unsigned char *pucPassword,
                                      unsigned int uiPwdLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->GetPrivateKeyAccessRight == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->GetPrivateKeyAccessRight(hSessionHandle, uiKeyIndex,
                                         pucPassword, uiPwdLength);
}

int TSAPI_SDF_ReleasePrivateKeyAccessRight(void *hSessionHandle,
                                           unsigned int uiKeyIndex)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ReleasePrivateKeyAccessRight == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ReleasePrivateKeyAccessRight(hSessionHandle, uiKeyIndex);
}

int TSAPI_SDF_LoadModule(const char *password)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->LoadModule == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->LoadModule(password);
}

int TSAPI_SDF_ImportKeyWithISK_ECC(void *hSessionHandle,
                                   unsigned int uiISKIndex,
                                   OSSL_ECCCipher *pucKey,
                                   void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ImportKeyWithISK_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ImportKeyWithISK_ECC(hSessionHandle, uiISKIndex, pucKey,
                                      phKeyHandle);
}

int TSAPI_SDF_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                               unsigned int uiKEKIndex, unsigned char *pucKey,
                               unsigned int puiKeyLength, void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ImportKeyWithKEK == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ImportKeyWithKEK(hSessionHandle, uiAlgID, uiKEKIndex, pucKey,
                                   puiKeyLength, phKeyHandle);
}

int TSAPI_SDF_Encrypt(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucIV,
                      unsigned char *pucData, unsigned int uiDataLength,
                      unsigned char *pucEncData, unsigned int *puiEncDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->Encrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData,
                         uiDataLength, pucEncData, puiEncDataLength);
}

int TSAPI_SDF_Decrypt(void *hSessionHandle, void *hKeyHandle,
                      unsigned int uiAlgID, unsigned char *pucIV,
                      unsigned char *pucEncData, unsigned int uiEncDataLength,
                      unsigned char *pucData, unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->Decrypt == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->Decrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                         pucEncData, uiEncDataLength, pucData, puiDataLength);
}

int TSAPI_SDF_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
                           unsigned int uiAlgID, unsigned char *pucIV,
                           unsigned char *pucData, unsigned int uiDataLength,
                           unsigned char *pucMac, unsigned int *puiMACLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->CalculateMAC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->CalculateMAC(hSessionHandle, hKeyHandle, uiAlgID, pucIV,
                              pucData, uiDataLength, pucMac, puiMACLength);
}

int TSAPI_SDF_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
                          uint32_t len, void **pkey_handle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->GenerateKey == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->GenerateKey(hSessionHandle, type, no_kek, len, pkey_handle);
}

int TSAPI_SDF_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->DestroyKey == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->DestroyKey(hSessionHandle, hKeyHandle);
}

int TSAPI_SDF_ExportSignPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportSignPublicKey_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportSignPublicKey_ECC(hSessionHandle, uiKeyIndex, pucPublicKey);
}

int TSAPI_SDF_ExportEncPublicKey_ECC(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_ECCrefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportEncPublicKey_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportEncPublicKey_ECC(hSessionHandle, uiKeyIndex, pucPublicKey);
}

int TSAPI_SDF_ExportSignPublicKey_RSA(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_RSArefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportSignPublicKey_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportSignPublicKey_RSA(hSessionHandle, uiKeyIndex,
                                         pucPublicKey);
}

int TSAPI_SDF_ExportSignPublicKey_RSAEx(void *hSessionHandle,
                                        unsigned int uiKeyIndex,
                                        OSSL_RSArefPublicKeyEx *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportSignPublicKey_RSAEx == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportSignPublicKey_RSAEx(hSessionHandle, uiKeyIndex,
                                           pucPublicKey);
}

int TSAPI_SDF_ExportEncPublicKey_RSA(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_RSArefPublicKey *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportEncPublicKey_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportEncPublicKey_RSA(hSessionHandle, uiKeyIndex,
                                        pucPublicKey);
}

int TSAPI_SDF_ExportEncPublicKey_RSAEx(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       OSSL_RSArefPublicKeyEx *pucPublicKey)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExportEncPublicKey_RSAEx == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExportEncPublicKey_RSAEx(hSessionHandle, uiKeyIndex,
                                          pucPublicKey);
}

int TSAPI_SDF_InternalPublicKeyOperation_RSA(void *hSessionHandle,
                                             unsigned int uiKeyIndex,
                                             unsigned char *pucDataInput,
                                             unsigned int uiInputLength,
                                             unsigned char *pucDataOutput,
                                             unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalPublicKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalPublicKeyOperation_RSA(hSessionHandle, uiKeyIndex,
                                                pucDataInput, uiInputLength,
                                                pucDataOutput,
                                                puiOutputLength);
}

int TSAPI_SDF_ExternalPublicKeyOperation_RSA(void *hSessionHandle,
                                             OSSL_RSArefPublicKey *pucPublicKey,
                                             unsigned char *pucDataInput,
                                             unsigned int uiInputLength,
                                             unsigned char *pucDataOutput,
                                             unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExternalPublicKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExternalPublicKeyOperation_RSA(hSessionHandle, pucPublicKey,
                                                pucDataInput, uiInputLength,
                                                pucDataOutput,
                                                puiOutputLength);
}

int TSAPI_SDF_InternalPrivateKeyOperation_RSA(void *hSessionHandle,
                                              unsigned int uiKeyIndex,
                                              unsigned char *pucDataInput,
                                              unsigned int uiInputLength,
                                              unsigned char *pucDataOutput,
                                              unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalPrivateKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalPrivateKeyOperation_RSA(hSessionHandle, uiKeyIndex,
                                                 pucDataInput, uiInputLength,
                                                 pucDataOutput,
                                                 puiOutputLength);
}

int TSAPI_SDF_ExternalPrivateKeyOperation_RSA(void *hSessionHandle,
                                              OSSL_RSArefPrivateKey *pucPrivateKey,
                                              unsigned char *pucDataInput,
                                              unsigned int uiInputLength,
                                              unsigned char *pucDataOutput,
                                              unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExternalPrivateKeyOperation_RSA == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExternalPrivateKeyOperation_RSA(hSessionHandle, pucPrivateKey,
                                                 pucDataInput, uiInputLength,
                                                 pucDataOutput,
                                                 puiOutputLength);
}

int TSAPI_SDF_InternalPublicKeyOperation_RSA_Ex(void *hSessionHandle,
                                                unsigned int uiKeyIndex,
                                                unsigned int uiKeyUsage,
                                                unsigned char *pucDataInput,
                                                unsigned int uiInputLength,
                                                unsigned char *pucDataOutput,
                                                unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalPublicKeyOperation_RSA_Ex == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalPublicKeyOperation_RSA_Ex(hSessionHandle, uiKeyIndex,
                                                   uiKeyUsage, pucDataInput,
                                                   uiInputLength,
                                                   pucDataOutput,
                                                   puiOutputLength);
}

int TSAPI_SDF_ExternalPublicKeyOperation_RSAEx(void *hSessionHandle,
                                               OSSL_RSArefPublicKeyEx *pucPublicKey,
                                               unsigned char *pucDataInput,
                                               unsigned int uiInputLength,
                                               unsigned char *pucDataOutput,
                                               unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExternalPublicKeyOperation_RSAEx == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExternalPublicKeyOperation_RSAEx(hSessionHandle, pucPublicKey,
                                                  pucDataInput, uiInputLength,
                                                  pucDataOutput,
                                                  puiOutputLength);
}

int TSAPI_SDF_InternalPrivateKeyOperation_RSA_Ex(void *hSessionHandle,
                                                 unsigned int uiKeyIndex,
                                                 unsigned int uiKeyUsage,
                                                 unsigned char *pucDataInput,
                                                 unsigned int uiInputLength,
                                                 unsigned char *pucDataOutput,
                                                 unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalPrivateKeyOperation_RSA_Ex == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalPrivateKeyOperation_RSA_Ex(hSessionHandle, uiKeyIndex,
                                                    uiKeyUsage, pucDataInput,
                                                    uiInputLength,
                                                    pucDataOutput,
                                                    puiOutputLength);
}

int TSAPI_SDF_ExternalPrivateKeyOperation_RSAEx(void *hSessionHandle,
                                                OSSL_RSArefPrivateKeyEx *pucPrivateKey,
                                                unsigned char *pucDataInput,
                                                unsigned int uiInputLength,
                                                unsigned char *pucDataOutput,
                                                unsigned int *puiOutputLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->ExternalPrivateKeyOperation_RSAEx == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->ExternalPrivateKeyOperation_RSAEx(hSessionHandle,
                                                   pucPrivateKey,
                                                   pucDataInput, uiInputLength,
                                                   pucDataOutput,
                                                   puiOutputLength);
}

int TSAPI_SDF_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned int uiAlgID,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalEncrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalEncrypt_ECC(hSessionHandle, uiISKIndex, uiAlgID,
                                     pucData, uiDataLength, pucEncData);
}

int TSAPI_SDF_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned int uiAlgID,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalDecrypt_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalDecrypt_ECC(hSessionHandle, uiISKIndex, uiAlgID,
                                     pucEncData, pucData, puiDataLength);
}

int TSAPI_SDF_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                               unsigned char *pucData,
                               unsigned int uiDataLength,
                               OSSL_ECCSignature *pucSignature)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL || meth->InternalSign_ECC == NULL)
        return OSSL_SDR_NOTSUPPORT;

    return meth->InternalSign_ECC(hSessionHandle, uiISKIndex, pucData,
                                  uiDataLength, pucSignature);
}

int TSAPI_SDF_GenerateAgreementDataWithECCEx(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL)
        return OSSL_SDR_NOTSUPPORT;

    if (meth->GenerateAgreementDataWithECCEx != NULL)
        return meth->GenerateAgreementDataWithECCEx(
            hSessionHandle, uiISKIndex, uiKeyBits, pucSponsorID,
            uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,
            phAgreementHandle);

    if (meth->GenerateAgreementDataWithECC_Ex_SW != NULL)
        return meth->GenerateAgreementDataWithECC_Ex_SW(
            hSessionHandle, uiISKIndex, uiKeyBits, pucSponsorID,
            uiSponsorIDLength, pucSponsorPublicKey, pucSponsorTmpPublicKey,
            phAgreementHandle);

    return OSSL_SDR_NOTSUPPORT;
}

int TSAPI_SDF_GenerateKeyWithECCEx(void *hSessionHandle,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL)
        return OSSL_SDR_NOTSUPPORT;

    if (meth->GenerateKeyWithECCEx != NULL)
        return meth->GenerateKeyWithECCEx(
            hSessionHandle, pucResponseID, uiResponseIDLength,
            pucResponsePublicKey, pucResponseTmpPublicKey, hAgreementHandle,
            pucSharedSecret, puiSecretLength, phKeyHandle);

    if (meth->GenerateKeyWithECC_Ex_SW != NULL) {
        if (puiSecretLength != NULL
                && *puiSecretLength < SDF_SM2DH_EX_SECRET_LEN)
            return OSSL_SDR_INARGERR;

        if (phKeyHandle != NULL)
            *phKeyHandle = NULL;

        {
            int ret = meth->GenerateKeyWithECC_Ex_SW(
                hSessionHandle, pucResponseID, uiResponseIDLength,
                pucResponsePublicKey, pucResponseTmpPublicKey, hAgreementHandle,
                pucSharedSecret);
            if (ret == OSSL_SDR_OK && puiSecretLength != NULL)
                *puiSecretLength = SDF_SM2DH_EX_SECRET_LEN;
            return ret;
        }
    }

    return OSSL_SDR_NOTSUPPORT;
}

int TSAPI_SDF_GenerateAgreementDataAndKeyWithECCEx(
    void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle)
{
    const SDF_METHOD *meth = sdf_get_method();

    if (meth == NULL)
        return OSSL_SDR_NOTSUPPORT;

    if (meth->GenerateAgreementDataAndKeyWithECCEx != NULL)
        return meth->GenerateAgreementDataAndKeyWithECCEx(
            hSessionHandle, uiISKIndex, uiKeyBits, pucResponseID,
            uiResponseIDLength, pucSponsorID, uiSponsorIDLength,
            pucSponsorPublicKey, pucSponsorTmpPublicKey,
            pucResponsePublicKey, pucResponseTmpPublicKey,
            pucSharedSecret, puiSecretLength, phKeyHandle);

    if (meth->GenerateAgreementDataAndKeyWithECC_Ex_SW != NULL) {
        if (uiKeyBits / 8 < SDF_SM2DH_EX_SECRET_LEN)
            return OSSL_SDR_INARGERR;

        if (phKeyHandle != NULL)
            *phKeyHandle = NULL;

        {
            int ret = meth->GenerateAgreementDataAndKeyWithECC_Ex_SW(
                hSessionHandle, uiISKIndex, uiKeyBits, pucResponseID,
                uiResponseIDLength, pucSponsorID, uiSponsorIDLength,
                pucSponsorPublicKey, pucSponsorTmpPublicKey,
                pucResponsePublicKey, pucResponseTmpPublicKey,
                pucSharedSecret);
            if (ret == OSSL_SDR_OK && puiSecretLength != NULL)
                *puiSecretLength = SDF_SM2DH_EX_SECRET_LEN;
            return ret;
        }
    }

    return OSSL_SDR_NOTSUPPORT;
}
