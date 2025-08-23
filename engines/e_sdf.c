/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * SDF Engine Implementation for GMT 0018-2023
 * 支持 RSA 和 ECC/SM2 算法，签名、验证、加密、解密操作，随机数生成
 * 支持 SSL 相关功能，支持 openssl.cnf 加载和代码加载
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL 头文件 */
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/obj_mac.h>
#include <openssl/kdf.h>

/* 定义缺失的宏 */
#ifndef NID_sm_scheme  
#define NID_sm_scheme 1142
#endif

#ifndef NID_secg_scheme
#define NID_secg_scheme 1143
#endif

#ifndef EVP_PKEY_CTRL_EC_SCHEME
#define EVP_PKEY_CTRL_EC_SCHEME (EVP_PKEY_ALG_CTRL + 20)
#endif

#ifndef EVP_PKEY_CTRL_SIGNER_ID
#define EVP_PKEY_CTRL_SIGNER_ID (EVP_PKEY_ALG_CTRL + 21)
#endif

#ifndef EVP_PKEY_CTRL_GET_SIGNER_ID
#define EVP_PKEY_CTRL_GET_SIGNER_ID (EVP_PKEY_ALG_CTRL + 22)
#endif

#ifndef EVP_PKEY_CTRL_GET_SIGNER_ZID
#define EVP_PKEY_CTRL_GET_SIGNER_ZID (EVP_PKEY_ALG_CTRL + 23)
#endif

#ifndef EVP_PKEY_CTRL_EC_ENCRYPT_PARAM
#define EVP_PKEY_CTRL_EC_ENCRYPT_PARAM (EVP_PKEY_ALG_CTRL + 24)
#endif

/* 兼容性宏定义 */
#define EVP_PKEY_CTX_set_ec_scheme(ctx, scheme) \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_SCHEME, scheme, NULL)

#define EVP_PKEY_CTX_set_signer_id(ctx, id) \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_SIGNER_ID, 0, (void *)id)

#define EVP_PKEY_CTX_set_ec_encrypt_param(ctx, param) \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, param, NULL)

#ifdef _WIN32
# include <windows.h>

/* Windows 字符串转换函数 */
static HMODULE sdf_load_library_win32(const char *filename)
{
    HMODULE handle = NULL;
    WCHAR *wfilename = NULL;
    int wlen;
    
    if (!filename) return NULL;
    
    /* 首先尝试直接加载（ANSI 版本） */
    handle = LoadLibraryA(filename);
    if (handle) return handle;
    
    /* 如果失败，尝试 UTF-8 到 UTF-16 转换 */
    wlen = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
    if (wlen > 0) {
        wfilename = (WCHAR *)OPENSSL_malloc(wlen * sizeof(WCHAR));
        if (wfilename) {
            if (MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, wlen) > 0) {
                handle = LoadLibraryW(wfilename);
            }
            OPENSSL_free(wfilename);
        }
    }
    
    /* 如果还是失败，尝试当前代码页转换 */
    if (!handle) {
        wlen = MultiByteToWideChar(CP_ACP, 0, filename, -1, NULL, 0);
        if (wlen > 0) {
            wfilename = (WCHAR *)OPENSSL_malloc(wlen * sizeof(WCHAR));
            if (wfilename) {
                if (MultiByteToWideChar(CP_ACP, 0, filename, -1, wfilename, wlen) > 0) {
                    handle = LoadLibraryW(wfilename);
                }
                OPENSSL_free(wfilename);
            }
        }
    }
    
    return handle;
}

# define DLOPEN(filename) sdf_load_library_win32(filename)
# define DLSYM(handle, symbol) GetProcAddress(handle, symbol)
# define DLCLOSE(handle) FreeLibrary(handle)
# define DLERROR() "Windows DLL error"
#else
# include <dlfcn.h>
# include <pthread.h>
# define DLOPEN(filename) dlopen(filename, RTLD_LAZY)
# define DLSYM(handle, symbol) dlsym(handle, symbol)
# define DLCLOSE(handle) dlclose(handle)
# define DLERROR() dlerror()
#endif

/* 标准 SDF 错误码 */
#define SDR_OK                  0x0
#define SDR_BASE                0x01000000
#define SDR_UNKNOWNERR          (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT          (SDR_BASE + 0x00000002)
#define SDR_COMMFAIL            (SDR_BASE + 0x00000003)
#define SDR_HARDFAIL            (SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE          (SDR_BASE + 0x00000005)
#define SDR_OPENSESSION         (SDR_BASE + 0x00000006)
#define SDR_PARDENY             (SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST         (SDR_BASE + 0x00000008)
#define SDR_ALGNOTSUPPORT       (SDR_BASE + 0x00000009)
#define SDR_ALGMODNOTSUPPORT    (SDR_BASE + 0x0000000A)
#define SDR_PKOPERR             (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR             (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR             (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR           (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR            (SDR_BASE + 0x0000000F)
#define SDR_STEPERR             (SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR         (SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST         (SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR          (SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR          (SDR_BASE + 0x00000014)
#define SDR_KEYERR              (SDR_BASE + 0x00000015)

/* 标准 SDF 算法标识 */
#define SGD_SM1_ECB             0x00000101
#define SGD_SM1_CBC             0x00000102
#define SGD_SM1_CFB             0x00000104
#define SGD_SM1_OFB             0x00000108
#define SGD_SM1_MAC             0x00000110
#define SGD_SMS4_ECB            0x00000401
#define SGD_SMS4_CBC            0x00000402
#define SGD_SMS4_CFB            0x00000404
#define SGD_SMS4_OFB            0x00000408
#define SGD_SMS4_MAC            0x00000410
#define SGD_RSA                 0x00010000
#define SGD_SM2_1               0x00020100
#define SGD_SM2_2               0x00020200
#define SGD_SM2_3               0x00020400
#define SGD_SM3                 0x00000001
#define SGD_SHA1                0x00000002
#define SGD_SHA256              0x00000004

/* 标准 SDF 数据结构 */
#define RSAref_MAX_BITS         2048
#define RSAref_MAX_LEN          ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS        ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN         ((RSAref_MAX_PBITS + 7) / 8)

#define ECCref_MAX_BITS         256
#define ECCref_MAX_LEN          ((ECCref_MAX_BITS + 7) / 8)

typedef struct DeviceInfo_st {
    unsigned char IssuerName[40];
    unsigned char DeviceName[16];
    unsigned char DeviceSerial[16];
    unsigned int DeviceVersion;
    unsigned int StandardVersion;
    unsigned int AsymAlgAbility[2];
    unsigned int SymAlgAbility;
    unsigned int HashAlgAbility;
    unsigned int BufferSize;
} DEVICEINFO;

typedef struct RSArefPublicKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPrivateKey_st {
    unsigned int bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

typedef struct ECCrefPublicKey_st {
    unsigned int bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int L;
    unsigned char C[1];
} ECCCipher;

/* SDF 函数指针类型定义 */
typedef int (*SDF_OpenDevice_FuncPtr)(void **phDeviceHandle);
typedef int (*SDF_CloseDevice_FuncPtr)(void *hDeviceHandle);
typedef int (*SDF_OpenSession_FuncPtr)(void *hDeviceHandle, void **phSessionHandle);
typedef int (*SDF_CloseSession_FuncPtr)(void *hSessionHandle);
typedef int (*SDF_GetDeviceInfo_FuncPtr)(void *hSessionHandle, DEVICEINFO *pstDeviceInfo);
typedef int (*SDF_GenerateRandom_FuncPtr)(void *hSessionHandle, unsigned int uiLength, unsigned char *pucRandom);
typedef int (*SDF_GetPrivateKeyAccessRight_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucPassword, unsigned int uiPwdLength);
typedef int (*SDF_ReleasePrivateKeyAccessRight_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex);

/* RSA 相关函数 */
typedef int (*SDF_ExportSignPublicKey_RSA_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
typedef int (*SDF_ExportEncPublicKey_RSA_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, RSArefPublicKey *pucPublicKey);
typedef int (*SDF_InternalPublicKeyOperation_RSA_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
typedef int (*SDF_InternalPrivateKeyOperation_RSA_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
typedef int (*SDF_ExternalPublicKeyOperation_RSA_FuncPtr)(void *hSessionHandle, RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);
typedef int (*SDF_ExternalPrivateKeyOperation_RSA_FuncPtr)(void *hSessionHandle, RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput, unsigned int uiInputLength, unsigned char *pucDataOutput, unsigned int *puiOutputLength);

/* ECC 相关函数 */
typedef int (*SDF_ExportSignPublicKey_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
typedef int (*SDF_ExportEncPublicKey_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiKeyIndex, ECCrefPublicKey *pucPublicKey);
typedef int (*SDF_InternalSign_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
typedef int (*SDF_InternalVerify_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
typedef int (*SDF_ExternalSign_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, unsigned char *pucData, unsigned int uiDataLength, ECCSignature *pucSignature);
typedef int (*SDF_ExternalVerify_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucDataInput, unsigned int uiInputLength, ECCSignature *pucSignature);
typedef int (*SDF_ExternalEncrypt_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucData, unsigned int uiDataLength, ECCCipher *pucEncData);
typedef int (*SDF_ExternalDecrypt_ECC_FuncPtr)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPrivateKey *pucPrivateKey, ECCCipher *pucEncData, unsigned char *pucData, unsigned int *puiDataLength);

/* 对称密码运算函数 */
typedef int (*SDF_Encrypt_FuncPtr)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData, unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength);
typedef int (*SDF_Decrypt_FuncPtr)(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData, unsigned int *puiDataLength);

/* 杂凑运算函数 */
typedef int (*SDF_HashInit_FuncPtr)(void *hSessionHandle, unsigned int uiAlgID, ECCrefPublicKey *pucPublicKey, unsigned char *pucID, unsigned int uiIDLength);
typedef int (*SDF_HashUpdate_FuncPtr)(void *hSessionHandle, unsigned char *pucData, unsigned int uiDataLength);
typedef int (*SDF_HashFinal_FuncPtr)(void *hSessionHandle, unsigned char *pucHash, unsigned int *puiHashLength);


/* 其他函数 */
typedef int (*BYCSM_LoadModule_FuncPtr)(const char* pwd);
typedef int (*BYCSM_UninstallModule_FuncPtr)(const char* pwd);

/* 厂商配置结构 */ 
typedef struct vendor_config {
	const char* name;
	const char* library_path;
	const char* display_name;
	int priority;  // 优先级，数字越小优先级越高
} vendor_config_t;

/* 预定义的厂商配置；1）可以检测待加载的库是否在列表中；2）可以根据优先级自动加载库，完成密码运算 */ 
static vendor_config_t vendor_configs[] = {
	{"westone", "westone_sdf.dll", "卫士通SDF", 1},
	{"huada", "huada_sdf.dll", "华大SDF", 2},
	{"sansec", "sansec_sdf.dll", "三未信安SDF", 3},
	{"koal", "koal_sdf.dll", "科蓝SDF", 4},
	{"tass", "tass_sdf.dll", "天威诚信SDF", 5},
	{"generic", "sdf.dll", "通用SDF", 99},
	{NULL, NULL, NULL, 0}
};
// 全局当前使用的厂商
//static sdf_vendor_ops_t* current_vendor = NULL;
//static sdf_vendor_ops_t* available_vendors[MAX_VENDORS];
static int vendor_count = 6;
/* ENGINE 控制命令 */
#define SDF_CMD_MODULE_PATH     ENGINE_CMD_BASE
#define SDF_CMD_DEVICE_NAME     (ENGINE_CMD_BASE + 1)
#define SDF_CMD_KEY_INDEX       (ENGINE_CMD_BASE + 2)
#define SDF_CMD_PASSWORD        (ENGINE_CMD_BASE + 3)
#define SDF_CMD_START_PASSWORD  (ENGINE_CMD_BASE + 4)
#define SDF_CMD_LIST_VENDORS     (ENGINE_CMD_BASE + 5)
#define SDF_CMD_SWITCH_VENDOR    (ENGINE_CMD_BASE + 6)
#define SDF_CMD_GET_CURRENT      (ENGINE_CMD_BASE + 7)
#define SDF_CMD_AUTO_SELECT      (ENGINE_CMD_BASE + 8)

/* ENGINE 控制命令定义 */
static const ENGINE_CMD_DEFN sdf_cmd_defns[] = {
    {SDF_CMD_MODULE_PATH, "MODULE_PATH", "SDF library path", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_DEVICE_NAME, "DEVICE_NAME", "Device name", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_KEY_INDEX, "KEY_INDEX", "Key index", ENGINE_CMD_FLAG_NUMERIC},
    {SDF_CMD_PASSWORD, "PASSWORD", "Password", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_START_PASSWORD, "START_PASSWORD", "Start Password", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_LIST_VENDORS, "LIST_VENDORS", "List all vendors", ENGINE_CMD_FLAG_NO_INPUT},
	{SDF_CMD_SWITCH_VENDOR, "SWITCH_VENDOR", "Switch vendor", ENGINE_CMD_FLAG_STRING},
	{SDF_CMD_GET_CURRENT, "GET_CURRENT", "Get current vendor", ENGINE_CMD_FLAG_NO_INPUT},
	{SDF_CMD_AUTO_SELECT, "AUTO_SELECT", "Auto select vendor", ENGINE_CMD_FLAG_NO_INPUT},
    {0, NULL, NULL, 0}
};

/* SDF 引擎上下文 */
typedef struct {
    void *dll_handle;
    char *module_path;
    char *device_name;
    char *password;
    char* start_password;
    unsigned int key_index;
    int initialized;
    
    /* 设备和会话句柄 */
    void *hDevice;
    void *hSession;
    
    /* 设备信息 */
    DEVICEINFO device_info;
    
    /* SDF 函数指针 */
    SDF_OpenDevice_FuncPtr p_SDF_OpenDevice;
    SDF_CloseDevice_FuncPtr p_SDF_CloseDevice;
    SDF_OpenSession_FuncPtr p_SDF_OpenSession;
    SDF_CloseSession_FuncPtr p_SDF_CloseSession;
    SDF_GetDeviceInfo_FuncPtr p_SDF_GetDeviceInfo;
    SDF_GenerateRandom_FuncPtr p_SDF_GenerateRandom;
    SDF_GetPrivateKeyAccessRight_FuncPtr p_SDF_GetPrivateKeyAccessRight;
    SDF_ReleasePrivateKeyAccessRight_FuncPtr p_SDF_ReleasePrivateKeyAccessRight;
    
    /* RSA 函数指针 */
    SDF_ExportSignPublicKey_RSA_FuncPtr p_SDF_ExportSignPublicKey_RSA;
    SDF_ExportEncPublicKey_RSA_FuncPtr p_SDF_ExportEncPublicKey_RSA;
    SDF_InternalPublicKeyOperation_RSA_FuncPtr p_SDF_InternalPublicKeyOperation_RSA;
    SDF_InternalPrivateKeyOperation_RSA_FuncPtr p_SDF_InternalPrivateKeyOperation_RSA;
    SDF_ExternalPublicKeyOperation_RSA_FuncPtr p_SDF_ExternalPublicKeyOperation_RSA;
    SDF_ExternalPrivateKeyOperation_RSA_FuncPtr p_SDF_ExternalPrivateKeyOperation_RSA;
    
    /* ECC 函数指针 */
    SDF_ExportSignPublicKey_ECC_FuncPtr p_SDF_ExportSignPublicKey_ECC;
    SDF_ExportEncPublicKey_ECC_FuncPtr p_SDF_ExportEncPublicKey_ECC;
    SDF_InternalSign_ECC_FuncPtr p_SDF_InternalSign_ECC;
    SDF_InternalVerify_ECC_FuncPtr p_SDF_InternalVerify_ECC;
    SDF_ExternalSign_ECC_FuncPtr p_SDF_ExternalSign_ECC;
    SDF_ExternalVerify_ECC_FuncPtr p_SDF_ExternalVerify_ECC;
    SDF_ExternalEncrypt_ECC_FuncPtr p_SDF_ExternalEncrypt_ECC;
    SDF_ExternalDecrypt_ECC_FuncPtr p_SDF_ExternalDecrypt_ECC;
    
    /* 杂凑函数指针 */
    SDF_HashInit_FuncPtr p_SDF_HashInit;
    SDF_HashUpdate_FuncPtr p_SDF_HashUpdate;
    SDF_HashFinal_FuncPtr p_SDF_HashFinal;
    
    /* 对称加密函数指针 */
    SDF_Encrypt_FuncPtr p_SDF_Encrypt;
    SDF_Decrypt_FuncPtr p_SDF_Decrypt;

    /* 其他函数指针 */
    BYCSM_LoadModule_FuncPtr p_BYCSM_LoadModule;
	BYCSM_UninstallModule_FuncPtr p_BYCSM_UninstallModule;
    
#ifdef _WIN32
    CRITICAL_SECTION lock;
#else
    pthread_mutex_t lock;
#endif
} SDF_CTX;

/* 密钥上下文 */
typedef struct {
    SDF_CTX *sdf_ctx;
    unsigned int key_index;
    int key_type;  /* 0: RSA, 1: ECC/SM2 */
    int is_sign_key;
    EVP_PKEY *pkey;
} SDF_KEY_CTX;

/* 全局 SDF 上下文 */
static SDF_CTX *global_sdf_ctx = NULL;

/* 错误处理 */
static ERR_STRING_DATA sdf_str_functs[] = {
    {ERR_PACK(0, 0, 0), "sdf engine"},
    {0, NULL}
};

static ERR_STRING_DATA sdf_str_reasons[] = {
    {1, "sdf library not found"},
    {2, "sdf function not found"},
    {3, "sdf operation failed"},
    {4, "invalid parameter"},
    {5, "device not found"},
    {6, "session open failed"},
    {7, "authentication failed"},
    {8, "key not found"},
    {9, "soft moudle not load "},
    {0, NULL}
};

#define SDFerr(f, r) ERR_PUT_error(0, (f), (r), __FILE__, __LINE__)

/* 引擎 ID 和名称 */
static const char *engine_sdf_id = "sdf";
static const char *engine_sdf_name = "SDF engine for GMT 0018-2023";

/* 函数声明 */
static int sdf_init(ENGINE *e);
static int sdf_finish(ENGINE *e);
static int sdf_destroy(ENGINE *e);
static int sdf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));
static EVP_PKEY *sdf_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data);
static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data);
static int sdf_load_ssl_client_cert(ENGINE *e, SSL *ssl, STACK_OF(X509_NAME) *ca_dn, X509 **pcert, EVP_PKEY **pkey, STACK_OF(X509) **pother, UI_METHOD *ui_method, void *callback_data);

/* 辅助函数 */
static void sdf_lock(SDF_CTX *ctx)
{
    if (!ctx) return;
#ifdef _WIN32
    EnterCriticalSection(&ctx->lock);
#else
    pthread_mutex_lock(&ctx->lock);
#endif
}

static void sdf_unlock(SDF_CTX *ctx)
{
    if (!ctx) return;
#ifdef _WIN32
    LeaveCriticalSection(&ctx->lock);
#else
    pthread_mutex_unlock(&ctx->lock);
#endif
}

static SDF_CTX *sdf_ctx_new(void)
{
    SDF_CTX *ctx = OPENSSL_zalloc(sizeof(SDF_CTX));
    if (!ctx) return NULL;
    
    ctx->key_index = 1;  /* 默认密钥索引 */
    
#ifdef _WIN32
    InitializeCriticalSection(&ctx->lock);
#else
    pthread_mutex_init(&ctx->lock, NULL);
#endif
    
    return ctx;
}

static void sdf_ctx_free(SDF_CTX *ctx)
{
    if (!ctx) return;
    
    /* 释放私钥访问权限 */
    if (ctx->hSession && ctx->p_SDF_ReleasePrivateKeyAccessRight) {
        ctx->p_SDF_ReleasePrivateKeyAccessRight(ctx->hSession, ctx->key_index);
    }
    
    /* 关闭会话和设备 */
    if (ctx->hSession && ctx->p_SDF_CloseSession) {
        ctx->p_SDF_CloseSession(ctx->hSession);
    }
    if (ctx->hDevice && ctx->p_SDF_CloseDevice) {
        ctx->p_SDF_CloseDevice(ctx->hDevice);
    }

    /* 卸载模块 */
    if (ctx->p_BYCSM_UninstallModule)
    {
        if (ctx->start_password)
        {
            ctx->p_BYCSM_UninstallModule(ctx->start_password);
        }   
    }

    /* 卸载动态库 */
    if (ctx->dll_handle) {
        DLCLOSE(ctx->dll_handle);
    }
    
    /* 释放字符串 */
    OPENSSL_free(ctx->module_path);
    OPENSSL_free(ctx->device_name);
    OPENSSL_free(ctx->password);
    OPENSSL_free(ctx->start_password);
    
#ifdef _WIN32
    DeleteCriticalSection(&ctx->lock);
#else
    pthread_mutex_destroy(&ctx->lock);
#endif
    
    OPENSSL_free(ctx);
}

/*static int sdf_switch_to_vendor(const char* vendor_name) {
	// 如果已经是当前厂商，直接返回
	if (current_vendor && strcmp(current_vendor->vendor_name, vendor_name) == 0) {
		return 0;
	}

	// 清理当前厂商
	if (current_vendor && current_vendor->is_initialized) {
		if (current_vendor->session_handle) {
			current_vendor->SDF_CloseSession(current_vendor->session_handle);
			current_vendor->session_handle = NULL;
		}
		if (current_vendor->device_handle) {
			current_vendor->SDF_CloseDevice(current_vendor->device_handle);
			current_vendor->device_handle = NULL;
		}
		current_vendor->is_initialized = 0;
	}

	// 查找目标厂商
	sdf_vendor_ops_t* target_vendor = NULL;
	for (int i = 0; i < vendor_count; i++) {
		if (strcmp(available_vendors[i]->vendor_name, vendor_name) == 0) {
			target_vendor = available_vendors[i];
			break;
		}
	}

	if (!target_vendor) {
		printf("Vendor %s not found\n", vendor_name);
		return -1;
	}

	// 初始化新厂商
	if (sdf_init_vendor(target_vendor) == 0) {
		current_vendor = target_vendor;
		printf("Switched to SDF vendor: %s\n", vendor_name);
		return 0;
	}

	return -1;
}*/



/* 加载 SDF 动态库 */
static int sdf_load_library(SDF_CTX *ctx)
{
    if (!ctx || !ctx->module_path) {
        SDFerr(0, 1);
        return 0;
    }
    
    if (ctx->dll_handle) {
        return 1;  /* 已经加载 */
    }
    
    ctx->dll_handle = DLOPEN(ctx->module_path);
    if (!ctx->dll_handle) {
        SDFerr(0, 1);
        return 0;
    }
    
    /* 加载基础函数 */
    ctx->p_SDF_OpenDevice = (SDF_OpenDevice_FuncPtr)DLSYM(ctx->dll_handle, "SDF_OpenDevice");
    ctx->p_SDF_CloseDevice = (SDF_CloseDevice_FuncPtr)DLSYM(ctx->dll_handle, "SDF_CloseDevice");
    ctx->p_SDF_OpenSession = (SDF_OpenSession_FuncPtr)DLSYM(ctx->dll_handle, "SDF_OpenSession");
    ctx->p_SDF_CloseSession = (SDF_CloseSession_FuncPtr)DLSYM(ctx->dll_handle, "SDF_CloseSession");
    ctx->p_SDF_GetDeviceInfo = (SDF_GetDeviceInfo_FuncPtr)DLSYM(ctx->dll_handle, "SDF_GetDeviceInfo");
    ctx->p_SDF_GenerateRandom = (SDF_GenerateRandom_FuncPtr)DLSYM(ctx->dll_handle, "SDF_GenerateRandom");
    ctx->p_SDF_GetPrivateKeyAccessRight = (SDF_GetPrivateKeyAccessRight_FuncPtr)DLSYM(ctx->dll_handle, "SDF_GetPrivateKeyAccessRight");
    ctx->p_SDF_ReleasePrivateKeyAccessRight = (SDF_ReleasePrivateKeyAccessRight_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ReleasePrivateKeyAccessRight");
    
    /* 加载 RSA 函数 */
    ctx->p_SDF_ExportSignPublicKey_RSA = (SDF_ExportSignPublicKey_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExportSignPublicKey_RSA");
    ctx->p_SDF_ExportEncPublicKey_RSA = (SDF_ExportEncPublicKey_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExportEncPublicKey_RSA");
    ctx->p_SDF_InternalPublicKeyOperation_RSA = (SDF_InternalPublicKeyOperation_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_InternalPublicKeyOperation_RSA");
    ctx->p_SDF_InternalPrivateKeyOperation_RSA = (SDF_InternalPrivateKeyOperation_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_InternalPrivateKeyOperation_RSA");
    ctx->p_SDF_ExternalPublicKeyOperation_RSA = (SDF_ExternalPublicKeyOperation_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExternalPublicKeyOperation_RSA");
    ctx->p_SDF_ExternalPrivateKeyOperation_RSA = (SDF_ExternalPrivateKeyOperation_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExternalPrivateKeyOperation_RSA");
    
    /* 加载 ECC 函数 */
    ctx->p_SDF_ExportSignPublicKey_ECC = (SDF_ExportSignPublicKey_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExportSignPublicKey_ECC");
    ctx->p_SDF_ExportEncPublicKey_ECC = (SDF_ExportEncPublicKey_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExportEncPublicKey_ECC");
    ctx->p_SDF_InternalSign_ECC = (SDF_InternalSign_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_InternalSign_ECC");
    ctx->p_SDF_InternalVerify_ECC = (SDF_InternalVerify_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_InternalVerify_ECC");
    ctx->p_SDF_ExternalSign_ECC = (SDF_ExternalSign_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExternalSign_ECC");
    ctx->p_SDF_ExternalVerify_ECC = (SDF_ExternalVerify_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExternalVerify_ECC");
    ctx->p_SDF_ExternalEncrypt_ECC = (SDF_ExternalEncrypt_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExternalEncrypt_ECC");
    ctx->p_SDF_ExternalDecrypt_ECC = (SDF_ExternalDecrypt_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_ExternalDecrypt_ECC");
    
    /* 加载杂凑函数 */
    ctx->p_SDF_HashInit = (SDF_HashInit_FuncPtr)DLSYM(ctx->dll_handle, "SDF_HashInit");
    ctx->p_SDF_HashUpdate = (SDF_HashUpdate_FuncPtr)DLSYM(ctx->dll_handle, "SDF_HashUpdate");
    ctx->p_SDF_HashFinal = (SDF_HashFinal_FuncPtr)DLSYM(ctx->dll_handle, "SDF_HashFinal");
    
    /* 加载对称加密函数 */
    ctx->p_SDF_Encrypt = (SDF_Encrypt_FuncPtr)DLSYM(ctx->dll_handle, "SDF_Encrypt");
    ctx->p_SDF_Decrypt = (SDF_Decrypt_FuncPtr)DLSYM(ctx->dll_handle, "SDF_Decrypt");
    
    /* 其他函数 */
    ctx->p_BYCSM_LoadModule = (BYCSM_LoadModule_FuncPtr)DLSYM(ctx->dll_handle, "BYCSM_LoadModule");
    ctx->p_BYCSM_UninstallModule = (BYCSM_UninstallModule_FuncPtr)DLSYM(ctx->dll_handle, "BYCSM_UninstallModule");

    //ctx->p_SDF_GenerateKeyPair_ECC = (SDF_GenerateKeyPair_ECC_FuncPtr)DLSYM(ctx->dll_handle, "SDF_GenerateKeyPair_ECC");
    //ctx->p_SDF_GenerateKeyPair_RSA = (SDF_GenerateKeyPair_RSA_FuncPtr)DLSYM(ctx->dll_handle, "SDF_GenerateKeyPair_RSA");
    

    /* 检查必要函数是否加载成功 */
    if (!ctx->p_SDF_OpenDevice || !ctx->p_SDF_CloseDevice ||
        !ctx->p_SDF_OpenSession || !ctx->p_SDF_CloseSession) {
        SDFerr(0, 2);
        DLCLOSE(ctx->dll_handle);
        ctx->dll_handle = NULL;
        return 0;
    }
    
    return 1;
}

/* 初始化设备和会话 */
static int sdf_init_device(SDF_CTX *ctx)
{
    int ret;
    
    if (!ctx || ctx->initialized) {
        return ctx ? ctx->initialized : 0;
    }
    
    if (!sdf_load_library(ctx)) {
        return 0;
    }

    /* 加载模块 */
    if (ctx->p_BYCSM_LoadModule)
    {
       if (ctx->start_password)
       {
		   ret = ctx->p_BYCSM_LoadModule(ctx->start_password);
		   if (ret != SDR_OK) {
			   SDFerr(0, 9);
			   return 0;
		   }
       }       
    }
    /* 打开设备 */
    ret = ctx->p_SDF_OpenDevice(&ctx->hDevice);
    if (ret != SDR_OK) {
        SDFerr(0, 5);
        return 0;
    }
    
    /* 打开会话 */
    ret = ctx->p_SDF_OpenSession(ctx->hDevice, &ctx->hSession);
    if (ret != SDR_OK) {
        SDFerr(0, 6);
        ctx->p_SDF_CloseDevice(ctx->hDevice);
        ctx->hDevice = NULL;
        return 0;
    }
    
    /* 获取设备信息 */
    if (ctx->p_SDF_GetDeviceInfo) {
        ret = ctx->p_SDF_GetDeviceInfo(ctx->hSession, &ctx->device_info);
        if (ret != SDR_OK) {
            /* 获取设备信息失败不影响继续使用 */
        }
    }
    
    /* 获取密钥访问权限 */
    if (ctx->password && ctx->p_SDF_GetPrivateKeyAccessRight) {
        ret = ctx->p_SDF_GetPrivateKeyAccessRight(ctx->hSession, ctx->key_index,
                                                  (unsigned char *)ctx->password,
                                                  strlen(ctx->password));
        if (ret != SDR_OK) {
            SDFerr(0, 7);
            /* 继续执行，某些操作可能不需要认证 */
        }
    }
    
    ctx->initialized = 1;
    return 1;
}

/* ENGINE 控制函数 */
static int sdf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    SDF_CTX *ctx = global_sdf_ctx;
    
    if (!ctx) {
        ctx = sdf_ctx_new();
        if (!ctx) return 0;
        global_sdf_ctx = ctx;
    }
    
    switch (cmd) {
    case SDF_CMD_MODULE_PATH:
        if (!p) return 0;
        OPENSSL_free(ctx->module_path);
        ctx->module_path = OPENSSL_strdup((char *)p);
        return ctx->module_path ? 1 : 0;
        
    case SDF_CMD_DEVICE_NAME:
        if (!p) return 0;
        OPENSSL_free(ctx->device_name);
        ctx->device_name = OPENSSL_strdup((char *)p);
        return ctx->device_name ? 1 : 0;
        
    case SDF_CMD_KEY_INDEX:
        ctx->key_index = (unsigned int)i;
        return 1;
        
    case SDF_CMD_PASSWORD:
        if (!p) return 0;
        OPENSSL_free(ctx->password);
        ctx->password = OPENSSL_strdup((char *)p);
        return ctx->password ? 1 : 0;
	case SDF_CMD_START_PASSWORD:
		if (!p) return 0;
		OPENSSL_free(ctx->start_password);
		ctx->start_password = OPENSSL_strdup((char*)p);
		return ctx->start_password ? 1 : 0;
	case SDF_CMD_LIST_VENDORS:  
    {
		// 列出所有可用厂商
        if (!p) return 0;
		char* buffer = (char*)p;
		int offset = 0;

		for (int j = 0; j < vendor_count; j++) {
			offset += snprintf(buffer + offset, 1024 - offset,
				"name:%s,library_path:%s,display_name:%s,priority:%d\n",
                vendor_configs[j].name,
                vendor_configs[j].library_path,
                vendor_configs[j].display_name,
                vendor_configs[j].priority);
		}
		return 1;
    }
	case SDF_CMD_SWITCH_VENDOR:
    {
        // 切换到指定厂商
        if (!p) return 0;
		//return switch_to_vendor((char*)p);
        char* buffer = (char*)p;
        snprintf(buffer,"%s", "not support");
        return 1;
    }
	case SDF_CMD_GET_CURRENT: 
    {
        // 获取当前厂商名称
        if (!p) return 0;
        if (ctx->module_path)
        {
            strncpy((char*)p, ctx->module_path, strlen(ctx->module_path));
			return 1;
        }
		return 0;		
    }
	case SDF_CMD_AUTO_SELECT:
    {
		//return auto_select_vendor();
		if (!p) return 0;
		//return switch_to_vendor((char*)p);
		char* buffer = (char*)p;
		snprintf(buffer, "%s", "not support");
		return 1;
    }
    default:
        return 0;
    }
}

/* RSA 签名函数 */
static int sdf_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                        unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    SDF_CTX *ctx = global_sdf_ctx;
    SDF_KEY_CTX *key_ctx;
    unsigned char padded[RSAref_MAX_LEN];
    unsigned int padded_len = RSAref_MAX_LEN;
    unsigned int output_len = *siglen;
    int ret;
    
    if (!ctx || !ctx->initialized) {
        if (!sdf_init_device(ctx)) {
            return 0;
        }
    }
    
    key_ctx = RSA_get_ex_data(rsa, 0);
    if (!key_ctx) {
        SDFerr(0, 8);
        return 0;
    }
    
    sdf_lock(ctx);
    
    /* RSA PKCS#1 填充 */
    if (RSA_padding_add_PKCS1_type_1(padded, padded_len, m, m_len) != 1) {
        sdf_unlock(ctx);
        return 0;
    }
    
    /* 调用 SDF 内部私钥运算 */
    ret = ctx->p_SDF_InternalPrivateKeyOperation_RSA(ctx->hSession, key_ctx->key_index,
                                                     padded, padded_len,
                                                     sigret, &output_len);
    
    sdf_unlock(ctx);
    
    if (ret != SDR_OK) {
        SDFerr(0, 3);
        return 0;
    }
    
    *siglen = output_len;
    return 1;
}

/* RSA 验证函数 */
static int sdf_rsa_verify(int type, const unsigned char *m, unsigned int m_len,
                          const unsigned char *sigbuf, unsigned int siglen, const RSA *rsa)
{
    SDF_CTX *ctx = global_sdf_ctx;
    SDF_KEY_CTX *key_ctx;
    unsigned char decrypted[RSAref_MAX_LEN];
    unsigned int decrypted_len = RSAref_MAX_LEN;
    unsigned char *padded_msg;
    unsigned int padded_msg_len;
    int ret;
    
    if (!ctx || !ctx->initialized) {
        if (!sdf_init_device(ctx)) {
            return 0;
        }
    }
    
    key_ctx = RSA_get_ex_data(rsa, 0);
    if (!key_ctx) {
        SDFerr(0, 8);
        return 0;
    }
    
    sdf_lock(ctx);
    
    /* 调用 SDF 内部公钥运算 */
    ret = ctx->p_SDF_InternalPublicKeyOperation_RSA(ctx->hSession, key_ctx->key_index,
                                                    (unsigned char *)sigbuf, siglen,
                                                    decrypted, &decrypted_len);
    
    sdf_unlock(ctx);
    
    if (ret != SDR_OK) {
        SDFerr(0, 3);
        return 0;
    }
    
    /* 验证 PKCS#1 填充 */
    padded_msg_len = decrypted_len;
    if (RSA_padding_check_PKCS1_type_1(&padded_msg, &padded_msg_len,
                                       decrypted, decrypted_len, RSA_size(rsa)) != 1) {
        return 0;
    }
    
    /* 比较消息 */
    if (padded_msg_len != m_len || memcmp(padded_msg, m, m_len) != 0) {
        OPENSSL_free(padded_msg);
        return 0;
    }
    
    OPENSSL_free(padded_msg);
    return 1;
}

/* RSA 方法表 */
static RSA_METHOD *sdf_rsa_method = NULL;

static RSA_METHOD *get_sdf_rsa_method(void)
{
    if (sdf_rsa_method) return sdf_rsa_method;
    
    sdf_rsa_method = RSA_meth_new("SDF RSA method", 0);
    if (!sdf_rsa_method) return NULL;
    
    RSA_meth_set_sign(sdf_rsa_method, sdf_rsa_sign);
    RSA_meth_set_verify(sdf_rsa_method, sdf_rsa_verify);
    
    return sdf_rsa_method;
}

/* ECC/SM2 签名函数 */
static int sdf_ecdsa_sign(int type, const unsigned char *dgst, int dgst_len,
                          unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv,
                          const BIGNUM *r, EC_KEY *eckey)
{
    SDF_CTX *ctx = global_sdf_ctx;
    SDF_KEY_CTX *key_ctx;
    ECCSignature ecc_sig;
    int ret;
    
    if (!ctx || !ctx->initialized) {
        if (!sdf_init_device(ctx)) {
            return 0;
        }
    }
    
    key_ctx = EC_KEY_get_ex_data(eckey, 0);
    if (!key_ctx) {
        SDFerr(0, 8);
        return 0;
    }
    
    sdf_lock(ctx);
    
    /* 调用 SDF ECC 内部签名 */
    ret = ctx->p_SDF_InternalSign_ECC(ctx->hSession, key_ctx->key_index,
                                      (unsigned char *)dgst, dgst_len, &ecc_sig);
    
    sdf_unlock(ctx);
    
    if (ret != SDR_OK) {
        SDFerr(0, 3);
        return 0;
    }
    
    /* 转换签名格式为 DER */
    ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
    if (!ecdsa_sig) return 0;
    
    BIGNUM *bn_r = BN_bin2bn(ecc_sig.r, ECCref_MAX_LEN, NULL);
    BIGNUM *bn_s = BN_bin2bn(ecc_sig.s, ECCref_MAX_LEN, NULL);
    
    if (!bn_r || !bn_s) {
        BN_free(bn_r);
        BN_free(bn_s);
        ECDSA_SIG_free(ecdsa_sig);
        return 0;
    }
    
    ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s);
    
    int der_len = i2d_ECDSA_SIG(ecdsa_sig, &sig);
    ECDSA_SIG_free(ecdsa_sig);
    
    if (der_len < 0) return 0;
    
    *siglen = der_len;
    return 1;
}

/* ECC/SM2 验证函数 */
static int sdf_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                            const unsigned char *sigbuf, int sig_len, EC_KEY *eckey)
{
    SDF_CTX *ctx = global_sdf_ctx;
    SDF_KEY_CTX *key_ctx;
    ECCSignature ecc_sig;
    ECDSA_SIG *ecdsa_sig;
    const BIGNUM *bn_r, *bn_s;
    int ret;
    
    if (!ctx || !ctx->initialized) {
        if (!sdf_init_device(ctx)) {
            return 0;
        }
    }
    
    key_ctx = EC_KEY_get_ex_data(eckey, 0);
    if (!key_ctx) {
        SDFerr(0, 8);
        return 0;
    }
    
    /* 解析 DER 格式签名 */
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &sigbuf, sig_len);
    if (!ecdsa_sig) return 0;
    
    ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);
    
    /* 转换为 SDF 格式 */
    memset(&ecc_sig, 0, sizeof(ecc_sig));
    BN_bn2binpad(bn_r, ecc_sig.r, ECCref_MAX_LEN);
    BN_bn2binpad(bn_s, ecc_sig.s, ECCref_MAX_LEN);
    
    ECDSA_SIG_free(ecdsa_sig);
    
    sdf_lock(ctx);
    
    /* 调用 SDF ECC 内部验证 */
    ret = ctx->p_SDF_InternalVerify_ECC(ctx->hSession, key_ctx->key_index,
                                        (unsigned char *)dgst, dgst_len, &ecc_sig);
    
    sdf_unlock(ctx);
    
    return (ret == SDR_OK) ? 1 : 0;
}

/* ECC 方法表 */
static EC_KEY_METHOD *sdf_ec_method = NULL;

static EC_KEY_METHOD *get_sdf_ec_method(void)
{
    if (sdf_ec_method) return sdf_ec_method;
    
    sdf_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if (!sdf_ec_method) return NULL;
    
    EC_KEY_METHOD_set_sign(sdf_ec_method, sdf_ecdsa_sign, NULL, NULL);
    EC_KEY_METHOD_set_verify(sdf_ec_method, sdf_ecdsa_verify, NULL);
    
    return sdf_ec_method;
}

/* 随机数生成函数 */
static int sdf_rand_bytes(unsigned char *buf, int num)
{
    SDF_CTX *ctx = global_sdf_ctx;
    int ret;
    
    if (!ctx || !ctx->initialized) {
        if (!sdf_init_device(ctx)) {
            return 0;
        }
    }
    
    if (!ctx->p_SDF_GenerateRandom) {
        return 0;
    }
    
    sdf_lock(ctx);
    ret = ctx->p_SDF_GenerateRandom(ctx->hSession, num, buf);
    sdf_unlock(ctx);
    
    return (ret == SDR_OK) ? 1 : 0;
}

/* 随机数状态函数 */
static int sdf_rand_status(void)
{
    return global_sdf_ctx && global_sdf_ctx->initialized;
}

/* 随机数方法表 */
static RAND_METHOD sdf_rand_method = {
    NULL,               /* seed */
    sdf_rand_bytes,     /* bytes */
    NULL,               /* cleanup */
    NULL,               /* add */
    sdf_rand_bytes,     /* pseudorand */
    sdf_rand_status     /* status */
};

/* 加载私钥 */
static EVP_PKEY *sdf_load_privkey(ENGINE *e, const char *key_id,
                                  UI_METHOD *ui_method, void *callback_data)
{
    SDF_CTX *ctx = global_sdf_ctx;
    SDF_KEY_CTX *key_ctx;
    EVP_PKEY *pkey = NULL;
    RSA *rsa = NULL;
    EC_KEY *ec_key = NULL;
    RSArefPublicKey rsa_pub;
    ECCrefPublicKey ecc_pub;
    unsigned int key_index = ctx ? ctx->key_index : 1;
    int key_type = 0;  /* 0: RSA, 1: ECC */
    int is_sign_key = 1;
    int ret;
    
    if (!ctx || !ctx->initialized) {
        if (!sdf_init_device(ctx)) {
            return NULL;
        }
    }
    
    /* 解析密钥 ID */
    if (key_id) {
        if (strncmp(key_id, "rsa:", 4) == 0) {
            key_type = 0;
            key_index = atoi(key_id + 4);
        } else if (strncmp(key_id, "sm2:", 4) == 0 || strncmp(key_id, "ecc:", 4) == 0) {
            key_type = 1;
            key_index = atoi(key_id + 4);
        }
        
        if (strstr(key_id, "sign")) {
            is_sign_key = 1;
        } else if (strstr(key_id, "enc")) {
            is_sign_key = 0;
        }
    }
    
    /* 创建密钥上下文 */
    key_ctx = OPENSSL_zalloc(sizeof(SDF_KEY_CTX));
    if (!key_ctx) return NULL;
    
    key_ctx->sdf_ctx = ctx;
    key_ctx->key_index = key_index;
    key_ctx->key_type = key_type;
    key_ctx->is_sign_key = is_sign_key;
    
    sdf_lock(ctx);
    
    if (key_type == 0) {  /* RSA */
        /* 导出 RSA 公钥 */
        if (is_sign_key) {
            ret = ctx->p_SDF_ExportSignPublicKey_RSA(ctx->hSession, key_index, &rsa_pub);
        } else {
            ret = ctx->p_SDF_ExportEncPublicKey_RSA(ctx->hSession, key_index, &rsa_pub);
        }
        
        if (ret != SDR_OK) {
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
        /* 创建 RSA 对象 */
        rsa = RSA_new();
        if (!rsa) {
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
        /* 设置 RSA 公钥 */
        BIGNUM *n = BN_bin2bn(rsa_pub.m, RSAref_MAX_LEN, NULL);
        BIGNUM *e = BN_bin2bn(rsa_pub.e, RSAref_MAX_LEN, NULL);
        
        if (!n || !e || !RSA_set0_key(rsa, n, e, NULL)) {
            BN_free(n);
            BN_free(e);
            RSA_free(rsa);
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
        /* 设置 RSA 方法和上下文 */
        RSA_set_method(rsa, get_sdf_rsa_method());
        RSA_set_ex_data(rsa, 0, key_ctx);
        
        /* 创建 EVP_PKEY */
        pkey = EVP_PKEY_new();
        if (!pkey || !EVP_PKEY_assign_RSA(pkey, rsa)) {
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
    } else {  /* ECC/SM2 */
        /* 导出 ECC 公钥 */
        if (is_sign_key) {
            ret = ctx->p_SDF_ExportSignPublicKey_ECC(ctx->hSession, key_index, &ecc_pub);
        } else {
            ret = ctx->p_SDF_ExportEncPublicKey_ECC(ctx->hSession, key_index, &ecc_pub);
        }
        
        if (ret != SDR_OK) {
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
        /* 创建 EC_KEY 对象 */
        ec_key = EC_KEY_new_by_curve_name(NID_sm2);
        if (!ec_key) {
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
        /* 设置 ECC 公钥 */
        const EC_GROUP *group = EC_KEY_get0_group(ec_key);
        EC_POINT *pub_point = EC_POINT_new(group);
        BIGNUM *x = BN_bin2bn(ecc_pub.x, ECCref_MAX_LEN, NULL);
        BIGNUM *y = BN_bin2bn(ecc_pub.y, ECCref_MAX_LEN, NULL);
        
        if (!pub_point || !x || !y ||
            !EC_POINT_set_affine_coordinates_GFp(group, pub_point, x, y, NULL) ||
            !EC_KEY_set_public_key(ec_key, pub_point)) {
            EC_POINT_free(pub_point);
            BN_free(x);
            BN_free(y);
            EC_KEY_free(ec_key);
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
        
        EC_POINT_free(pub_point);
        BN_free(x);
        BN_free(y);
        
        /* 设置 EC 方法和上下文 */
        EC_KEY_set_method(ec_key, get_sdf_ec_method());
        EC_KEY_set_ex_data(ec_key, 0, key_ctx);
        
        /* 创建 EVP_PKEY */
        pkey = EVP_PKEY_new();
        if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
            EC_KEY_free(ec_key);
            EVP_PKEY_free(pkey);
            sdf_unlock(ctx);
            OPENSSL_free(key_ctx);
            return NULL;
        }
    }
    
    sdf_unlock(ctx);
    key_ctx->pkey = pkey;
    return pkey;
}

/* 加载公钥 */
static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data)
{
    /* 公钥和私钥加载逻辑相同，因为我们只使用公钥部分 */
    return sdf_load_privkey(e, key_id, ui_method, callback_data);
}

/* SSL 客户端证书加载函数 */
static int sdf_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                    STACK_OF(X509_NAME) *ca_dn, X509 **pcert,
                                    EVP_PKEY **pkey, STACK_OF(X509) **pother,
                                    UI_METHOD *ui_method, void *callback_data)
{
    /* 这里可以实现从 SDF 设备加载客户端证书的逻辑 */
    /* 目前返回 0 表示不支持 */
    return 0;
}

/*---------------------------------pkey method---------------------------------------------*/

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
    /* Duplicate key if custom cofactor needed */
    EC_KEY *co_key;
    /* Cofactor mode */
    signed char cofactor_mode;
    /* KDF (if any) to use for ECDH */
    char kdf_type;
    /* Message digest to use for key derivation */
    const EVP_MD *kdf_md;
    /* User key material */
    unsigned char *kdf_ukm;
    size_t kdf_ukmlen;
    /* KDF output length */
    size_t kdf_outlen;
#ifndef OPENSSL_NO_SM2
    int ec_scheme;
    char *signer_id;
    size_t signer_id_len;
    unsigned char *signer_zid;
    size_t signer_zid_len;
    int ec_encrypt_param;
#endif
} SDF_EC_PKEY_CTX;

static int sdf_pkey_ec_init(EVP_PKEY_CTX *ctx)
{
    SDF_EC_PKEY_CTX *dctx;

    dctx = OPENSSL_zalloc(sizeof(*dctx));
    if (dctx == NULL)
        return 0;

    dctx->cofactor_mode = -1;
    dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
#ifndef OPENSSL_NO_SM2
    dctx->ec_scheme = NID_sm_scheme;
    dctx->signer_id = NULL;
    dctx->signer_id_len = 0;
    dctx->signer_zid = NULL;
    dctx->signer_zid_len = 0;
    dctx->ec_encrypt_param = NID_undef;
#endif

    EVP_PKEY_CTX_set_data(ctx, dctx);
    return 1;
}

static int sdf_pkey_ec_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    SDF_EC_PKEY_CTX *dctx, *sctx;
    if (!sdf_pkey_ec_init(dst))
        return 0;
    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);
    if (sctx->gen_group) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (!dctx->gen_group)
            return 0;
    }
    dctx->md = sctx->md;

    if (sctx->co_key) {
        dctx->co_key = EC_KEY_dup(sctx->co_key);
        if (!dctx->co_key)
            return 0;
    }
    dctx->kdf_type = sctx->kdf_type;
    dctx->kdf_md = sctx->kdf_md;
    dctx->kdf_outlen = sctx->kdf_outlen;
    if (sctx->kdf_ukm) {
        dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
        if (!dctx->kdf_ukm)
            return 0;
    } else
        dctx->kdf_ukm = NULL;
    dctx->kdf_ukmlen = sctx->kdf_ukmlen;
#ifndef OPENSSL_NO_SM2
    dctx->ec_scheme = sctx->ec_scheme;
    if (sctx->signer_id) {
        dctx->signer_id = OPENSSL_strdup(sctx->signer_id);
        if (!dctx->signer_id)
            return 0;
        dctx->signer_id_len = sctx->signer_id_len;
    } else {
        dctx->signer_id_len = 0;
    }
    dctx->signer_zid = NULL;
    dctx->signer_zid_len = 0;
    dctx->ec_encrypt_param = sctx->ec_encrypt_param;
#endif
    return 1;
}

static void sdf_pkey_ec_cleanup(EVP_PKEY_CTX *ctx)
{
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    if (dctx) {
        EC_GROUP_free(dctx->gen_group);
        EC_KEY_free(dctx->co_key);
        OPENSSL_free(dctx->kdf_ukm);
#ifndef OPENSSL_NO_SM2
        OPENSSL_free(dctx->signer_id);
        OPENSSL_free(dctx->signer_zid);
#endif
        OPENSSL_free(dctx);
    }
}

static int sdf_pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    int ret = 0;
    if (dctx->gen_group == NULL) {
        return 0;
    }
    ec = EC_KEY_new();
    if (ec == NULL)
        return 0;
    ret = EC_KEY_set_group(ec, dctx->gen_group);
    if (ret)
        EVP_PKEY_assign_EC_KEY(pkey, ec);
    else
        EC_KEY_free(ec);
    return ret;
}

static int sdf_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    EC_KEY *ec = NULL;
    EVP_PKEY *ctx_pkey = NULL;
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    
    ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    if (ctx_pkey == NULL && dctx->gen_group == NULL) {
        return 0;
    }
    ec = EC_KEY_new();
    if (!ec)
        return 0;
    EVP_PKEY_assign_EC_KEY(pkey, ec);
    if (ctx_pkey) {
        /* Note: if error return, pkey is freed by parent routine */
        if (!EVP_PKEY_copy_parameters(pkey, ctx_pkey))
            return 0;
    } else {
        if (!EC_KEY_set_group(ec, dctx->gen_group))
            return 0;
    }

    return EC_KEY_generate_key(ec);
}

static int sdf_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    unsigned int sltmp;
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

    if (!sig) {
        *siglen = ECDSA_size(ec);
        return 1;
    } else if (*siglen < (size_t)ECDSA_size(ec)) {
        return 0;
    }

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

#ifndef OPENSSL_NO_SM2
    if (dctx->ec_scheme == NID_sm_scheme)
        ret = sdf_ecdsa_sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);
    else
#endif
    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int sdf_pkey_ec_verify(EVP_PKEY_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    int ret, type;
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

    if (dctx->md)
        type = EVP_MD_type(dctx->md);
    else
        type = NID_sha1;

#ifndef OPENSSL_NO_SM2
    if (dctx->ec_scheme == NID_sm_scheme)
        ret = sdf_ecdsa_verify(NID_undef, tbs, tbslen, sig, siglen, ec);
    else
#endif
        ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);

    return ret;
}

static int sdf_pkey_ec_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    
    switch (dctx->ec_scheme) {
    case NID_sm_scheme:
        /* 这里应该调用 SDF SM2 加密函数 */
        return 0;  /* 暂时不支持 */
    case NID_secg_scheme:
        /* 这里应该调用 ECIES 加密函数 */
        return 0;  /* 暂时不支持 */
    default:
        return 0;
    }
}

static int sdf_pkey_ec_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    
    switch (dctx->ec_scheme) {
    case  NID_sm_scheme:
        /* 这里应该调用 SDF SM2 解密函数 */
        return 0;  /* 暂时不支持 */
    case NID_secg_scheme:
        /* 这里应该调用 ECIES 解密函数 */
        return 0;  /* 暂时不支持 */
    default:
        return 0;
    }
}

#ifndef OPENSSL_NO_EC
static int sdf_pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                          size_t *keylen)
{
    int ret;
    size_t outlen;
    const EC_POINT *pubkey = NULL;
    EC_KEY *eckey;
    EVP_PKEY *pkey, *peerkey;
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    
    pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);
    
    if (!pkey || !peerkey) {
        return 0;
    }

    eckey = dctx->co_key ? dctx->co_key : EVP_PKEY_get0_EC_KEY(pkey);

    if (!key) {
        const EC_GROUP *group;
        group = EC_KEY_get0_group(eckey);
        *keylen = (EC_GROUP_get_degree(group) + 7) / 8;
        return 1;
    }
    pubkey = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(peerkey));

    outlen = *keylen;

    ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
    if (ret <= 0)
        return 0;
    *keylen = ret;
    return 1;
}

static int sdf_pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx,
                              unsigned char *key, size_t *keylen)
{
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    unsigned char *ktmp = NULL;
    size_t ktmplen;
    int rv = 0;
    if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
        return sdf_pkey_ec_derive(ctx, key, keylen);
    if (!key) {
        *keylen = dctx->kdf_outlen;
        return 1;
    }
    if (*keylen != dctx->kdf_outlen)
        return 0;
    if (!sdf_pkey_ec_derive(ctx, NULL, &ktmplen))
        return 0;
    ktmp = OPENSSL_malloc(ktmplen);
    if (ktmp == NULL)
        return 0;
    if (!sdf_pkey_ec_derive(ctx, ktmp, &ktmplen))
        goto err;
    /* Do KDF stuff */
    if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen,
                        dctx->kdf_ukm, dctx->kdf_ukmlen, dctx->kdf_md))
        goto err;
    rv = 1;

 err:
    OPENSSL_clear_free(ktmp, ktmplen);
    return rv;
}
#endif

static int sdf_pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
    EVP_PKEY *pkey;
    EC_GROUP *group;
    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (!dctx->gen_group) {
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;

#ifndef OPENSSL_NO_EC
    case EVP_PKEY_CTRL_EC_ECDH_COFACTOR:
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        if (p1 == -2) {
            if (dctx->cofactor_mode != -1)
                return dctx->cofactor_mode;
            else {
                EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
                return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 : 0;
            }
        } else if (p1 < -1 || p1 > 1)
            return -2;
        dctx->cofactor_mode = p1;
        if (p1 != -1) {
            EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            const EC_GROUP *group = EC_KEY_get0_group(ec_key);
            const BIGNUM *cofactor = EC_GROUP_get0_cofactor(group);
            if (!group)
                return -2;
            /* If cofactor is 1 cofactor mode does nothing */
            if (BN_is_one(cofactor))
                return 1;
            if (!dctx->co_key) {
                dctx->co_key = EC_KEY_dup(ec_key);
                if (!dctx->co_key)
                    return 0;
            }
            if (p1)
                EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
            else
                EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
        } else {
            EC_KEY_free(dctx->co_key);
            dctx->co_key = NULL;
        }
        return 1;
#endif

    case EVP_PKEY_CTRL_EC_KDF_TYPE:
        if (p1 == -2)
            return dctx->kdf_type;
        if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62)
            return -2;
        dctx->kdf_type = p1;
        return 1;

#ifndef OPENSSL_NO_SM2
    case EVP_PKEY_CTRL_EC_SCHEME:
        if (p1 == -2) {
            return dctx->ec_scheme;
        }
        if (p1 != NID_secg_scheme && p1 != NID_sm_scheme) {
            return 0;
        }
        dctx->ec_scheme = p1;
        return 1;

    case EVP_PKEY_CTRL_SIGNER_ID:
        if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > 255) {
            return 0;
        } else {
            char *id = NULL;
            if (!(id = OPENSSL_strdup((char *)p2))) {
                return 0;
            }
            if (dctx->signer_id)
                OPENSSL_free(dctx->signer_id);
            dctx->signer_id = id;
            dctx->signer_id_len = strlen(id);
            if (dctx->ec_scheme == NID_sm_scheme) {
                pkey = EVP_PKEY_CTX_get0_pkey(ctx);
                EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
                unsigned char zid[32];
                size_t zidlen = 32;
                /* 这里应该计算 SM2 ID 摘要，暂时跳过 */
                if (!dctx->signer_zid) {
                    if (!(dctx->signer_zid = OPENSSL_malloc(zidlen))) {
                        return 0;
                    }
                }
                memcpy(dctx->signer_zid, zid, zidlen);
                dctx->signer_zid_len = zidlen;
            }
        }
        return 1;

    case EVP_PKEY_CTRL_GET_SIGNER_ID:
        *(const char **)p2 = dctx->signer_id;
        return 1;

    case EVP_PKEY_CTRL_GET_SIGNER_ZID:
        if (dctx->ec_scheme != NID_sm_scheme) {
            *(const unsigned char **)p2 = NULL;
            return -2;
        }
        if (!dctx->signer_zid) {
            pkey = EVP_PKEY_CTX_get0_pkey(ctx);
            EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
            unsigned char *zid;
            size_t zidlen = 32;
            if (!(zid = OPENSSL_malloc(zidlen))) {
                return 0;
            }
            /* 这里应该计算默认 ID 摘要，暂时跳过 */
            dctx->signer_zid = zid;
            dctx->signer_zid_len = zidlen;
        }
        *(const unsigned char **)p2 = dctx->signer_zid;
        return dctx->signer_zid_len;

    case EVP_PKEY_CTRL_EC_ENCRYPT_PARAM:
        if (p1 == -2) {
            return dctx->ec_encrypt_param;
        }
        dctx->ec_encrypt_param = p1;
        return 1;
#endif

    case EVP_PKEY_CTRL_EC_KDF_MD:
        dctx->kdf_md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_MD:
        *(const EVP_MD **)p2 = dctx->kdf_md;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
        if (p1 <= 0)
            return -2;
        dctx->kdf_outlen = (size_t)p1;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
        *(int *)p2 = dctx->kdf_outlen;
        return 1;

    case EVP_PKEY_CTRL_EC_KDF_UKM:
        OPENSSL_free(dctx->kdf_ukm);
        dctx->kdf_ukm = p2;
        if (p2)
            dctx->kdf_ukmlen = p1;
        else
            dctx->kdf_ukmlen = 0;
        return 1;

    case EVP_PKEY_CTRL_GET_EC_KDF_UKM:
        *(unsigned char **)p2 = dctx->kdf_ukm;
        return dctx->kdf_ukmlen;

    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_sha1 &&
#ifndef OPENSSL_NO_SM3
            EVP_MD_type((const EVP_MD *)p2) != NID_sm3 &&
#endif
            EVP_MD_type((const EVP_MD *)p2) != NID_ecdsa_with_SHA1 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha224 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha256 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha384 &&
            EVP_MD_type((const EVP_MD *)p2) != NID_sha512) {
            return 0;
        }
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    case EVP_PKEY_CTRL_PEER_KEY:
        /* Default behaviour is OK */
    case EVP_PKEY_CTRL_DIGESTINIT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
    case EVP_PKEY_CTRL_CMS_SIGN:
        return 1;

    default:
        return -2;
    }
}

static int sdf_pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx,
                            const char *type, const char *value)
{
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid;
        nid = EC_curve_nist2nid(value);
        if (nid == NID_undef)
            nid = OBJ_sn2nid(value);
        if (nid == NID_undef)
            nid = OBJ_ln2nid(value);
        if (nid == NID_undef) {
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
#ifndef OPENSSL_NO_SM2
    } else if (!strcmp(type, "ec_scheme")) {
        int scheme;
        if (!strcmp(value, "secg"))
            scheme = NID_secg_scheme;
        else if (!strcmp(value, "sm2"))
            scheme = NID_sm_scheme;
        else
            return -2;
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_SCHEME, scheme, NULL);
    } else if (!strcmp(type, "signer_id")) {
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_SIGNER_ID, 0, (void *)value);
    } else if (!strcmp(type, "ec_encrypt_param")) {
        int encrypt_param;
        if (!(encrypt_param = OBJ_txt2nid(value))) {
            return 0;
        }
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, encrypt_param, NULL);
#endif
    } else if (strcmp(type, "ec_param_enc") == 0) {
        int param_enc;
        if (strcmp(value, "explicit") == 0)
            param_enc = 0;
        else if (strcmp(value, "named_curve") == 0)
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    } else if (strcmp(type, "ecdh_kdf_md") == 0) {
        const EVP_MD *md;
        if ((md = EVP_get_digestbyname(value)) == NULL) {
            return 0;
        }
        return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
    } else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
        int co_mode;
        co_mode = atoi(value);
        return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
    }

    return -2;
}

static EVP_PKEY_METHOD *sdf_ec_pkey_meth = NULL;

static EVP_PKEY_METHOD *get_sdf_ec_pkey_method(void)
{
    if (sdf_ec_pkey_meth)
        return sdf_ec_pkey_meth;

    sdf_ec_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
    if (!sdf_ec_pkey_meth)
        return NULL;

    EVP_PKEY_meth_set_init(sdf_ec_pkey_meth, sdf_pkey_ec_init);
    EVP_PKEY_meth_set_copy(sdf_ec_pkey_meth, sdf_pkey_ec_copy);
    EVP_PKEY_meth_set_cleanup(sdf_ec_pkey_meth, sdf_pkey_ec_cleanup);
    EVP_PKEY_meth_set_paramgen(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_paramgen);
    EVP_PKEY_meth_set_keygen(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_keygen);
    EVP_PKEY_meth_set_sign(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_sign);
    EVP_PKEY_meth_set_verify(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_verify);
    EVP_PKEY_meth_set_encrypt(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_encrypt);
    EVP_PKEY_meth_set_decrypt(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_decrypt);
    EVP_PKEY_meth_set_derive(sdf_ec_pkey_meth, NULL, sdf_pkey_ec_kdf_derive);
    EVP_PKEY_meth_set_ctrl(sdf_ec_pkey_meth, sdf_pkey_ec_ctrl, sdf_pkey_ec_ctrl_str);

    return sdf_ec_pkey_meth;
}
/* 这是 高层 EVP 接口，注册的是 EVP_PKEY_METHOD 
作用是：改变 EVP_PKEY 层的行为
（如 EVP_PKEY_sign/EVP_PKEY_verify/EVP_PKEY_encrypt/EVP_PKEY_decrypt）
bind_sdf 函数中，将 EVP_PKEY_METHOD 与 ENGINE 关联起来

ENGINE_set_xxx 是低层接口，直接替换 OpenSSL 内部的 EC_KEY_METHOD
ENGINE_set_EC作用是：改变 EC_KEY_new/EC_KEY_generate_key/EC_KEY_sign/EC_KEY_verify 这些底层函数的实现。
相当于替换 EC 算法引擎，是和 OpenSSL EC_KEY 结构紧耦合的。
*/
static int sdf_pkey_meths(ENGINE * e, EVP_PKEY_METHOD ** pmeth,
                                      const int **nids, int nid)
{
    static int sdf_pkey_nids[] = {
        EVP_PKEY_EC,
        0
    };
    if (!pmeth) {
        *nids = sdf_pkey_nids;
        return 1;
    }

    if (nid == EVP_PKEY_EC) {
        *pmeth = get_sdf_ec_pkey_method();
        return *pmeth ? 1 : 0;
    }
    /* TODO：以下需要实现 SM2 、 RSA*/
    /*if (nid == EVP_PKEY_SM2) {
        *pmeth = get_skf_sm2_pkey_method();
        return (*pmeth != NULL) ? 1 : 0;
    }
    if (nid == EVP_PKEY_RSA) {
        *pmeth = get_skf_rsa_pkey_method();
        return (*pmeth != NULL) ? 1 : 0;
    }
    if (nid == EVP_PKEY_DSA) {
        *pmeth = get_skf_dsa_pkey_method();
        return (*pmeth != NULL) ? 1 : 0;
    }*/

    *pmeth = NULL;
    return 0;
}

/* ENGINE 初始化 */
static int sdf_init(ENGINE *e)
{
    SDF_CTX *ctx = global_sdf_ctx;
    
    if (!ctx) {
        ctx = sdf_ctx_new();
        if (!ctx) return 0;
        global_sdf_ctx = ctx;
    }
    
    /* 如果已经设置了模块路径，立即初始化设备 */
    if (ctx->module_path) {
        return sdf_init_device(ctx);
    }
    
    return 1;  /* 延迟初始化 */
}

/* ENGINE 清理 */
static int sdf_finish(ENGINE *e)
{
    if (global_sdf_ctx) {
        sdf_ctx_free(global_sdf_ctx);
        global_sdf_ctx = NULL;
    }
    return 1;
}

/* ENGINE 销毁 */
static int sdf_destroy(ENGINE *e)
{
    if (sdf_rsa_method) {
        RSA_meth_free(sdf_rsa_method);
        sdf_rsa_method = NULL;
    }
    
    if (sdf_ec_method) {
        EC_KEY_METHOD_free(sdf_ec_method);
        sdf_ec_method = NULL;
    }
    
	/*if (sdf_ec_pkey_meth) {
		EVP_PKEY_meth_free(sdf_ec_pkey_meth);
		sdf_ec_pkey_meth = NULL;
	}*/ //pkey_meths 框架会释放
    
    ERR_unload_strings(0, sdf_str_functs);
    ERR_unload_strings(0, sdf_str_reasons);
    
    return 1;
}

/* ENGINE 绑定函数 */
static int bind_sdf(ENGINE *e)
{
    if (!ENGINE_set_id(e, engine_sdf_id) ||
        !ENGINE_set_name(e, engine_sdf_name) ||
        !ENGINE_set_init_function(e, sdf_init) ||
        !ENGINE_set_finish_function(e, sdf_finish) ||
        !ENGINE_set_destroy_function(e, sdf_destroy) ||
        !ENGINE_set_ctrl_function(e, sdf_ctrl) ||
        !ENGINE_set_cmd_defns(e, sdf_cmd_defns) ||
        !ENGINE_set_load_privkey_function(e, sdf_load_privkey) ||
        !ENGINE_set_load_pubkey_function(e, sdf_load_pubkey) ||
        !ENGINE_set_load_ssl_client_cert_function(e, sdf_load_ssl_client_cert) ||
        !ENGINE_set_RAND(e, &sdf_rand_method) ||
        //!ENGINE_set_digests(e,xxx) ||
        //!ENGINE_set_ciphers(e,xxx) ||
        //!ENGINE_set_RSA(e,xxx) ||
        //!ENGINE_set_SM2(e,xxx) ||
        //!ENGINE_set_EC(e,xxx) ||
        //!ENGINE_set_DSA(e,xxx) ||
        !ENGINE_set_pkey_meths(e, sdf_pkey_meths)) {
        return 0;
    }
    
    /* 注册错误字符串 */
    ERR_load_strings(0, sdf_str_functs);
    ERR_load_strings(0, sdf_str_reasons);
    
    return 1;
}

/* 动态引擎绑定 */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_sdf_id) != 0))
        return 0;
    if (!bind_sdf(e))
        return 0;
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
/* 静态引擎注册 */
static ENGINE *engine_sdf(void)
{
    ENGINE *ret = ENGINE_new();
    if (ret == NULL)
        return NULL;
    if (!bind_sdf(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}

void engine_load_sdf_int(void)
{
    /* Copied from eng_[openssl|dyn].c */
    ENGINE *toadd = engine_sdf();
    if (!toadd)
        return;
    ERR_set_mark();
    ENGINE_add(toadd);
    /*
     * If the "add" worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     */
    ENGINE_free(toadd);
    /*
     * If the "add" didn't work, it was probably a conflict because it was
     * already added (eg. someone calling ENGINE_load_blah then calling
     * ENGINE_load_builtin_engines() perhaps).
     */
    ERR_pop_to_mark();
}

void ENGINE_load_sdf(void)
{
    engine_load_sdf_int();
}
#endif
