/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * SDF Engine Implementation for GMT 0018-2012
 * 支持 RSA 和 ECC/SM2 算法，签名、验证、加密、解密操作，随机数生成
 * 支持 SSL 相关功能，支持 openssl.cnf 加载和代码加载
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL 头文件 */
#include "e_sdf.h"
#include "e_sdf_err.c"
#include "e_sdf_err.h"
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/opensslconf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

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
#define EVP_PKEY_CTX_set_ec_scheme(ctx, scheme)                                \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_SCHEME, scheme, NULL)

#define EVP_PKEY_CTX_set_signer_id(ctx, id)                                    \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_SIGNER_ID, 0,          \
                    (void *)id)

#define EVP_PKEY_CTX_set_ec_encrypt_param(ctx, param)                          \
  EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_ENCRYPT_PARAM,      \
                    param, NULL)

/* 厂商配置结构 */
typedef struct vendor_config_st {
  const char *name;
  const char *library_path;
  const char *display_name;
  int priority; // 优先级，数字越小优先级越高
} vendor_config;

/* 预定义的厂商配置；1）可以检测待加载的库是否在列表中；2）可以根据优先级自动加载库，完成密码运算
 */
static const vendor_config vendor_configs[] = {
    {"byzk", "byzk0018.dll", "软件密码模块", 100},
    {"sansec", "swsds.dll", "三未信安SDF", 99},
    {"generic", "sdf.dll", "通用SDF", 98},
    {NULL, NULL, NULL, 0}};

// 全局当前使用的厂商
// static sdf_vendor_ops_t* current_vendor = NULL;
// static sdf_vendor_ops_t* available_vendors[MAX_VENDORS];
static int vendor_count = 6;

#ifdef _WIN32
#include <windows.h>

/* Windows 加载动态库 */
static FARPROC win32_getproc_multi(HMODULE h, const char *name) {
  FARPROC fp;
  char buf[256];
  int i;

  if (!h || !name) {
    SDF_ERR("win32_getproc_multi: invalid handle or name");
    SDFerr(SDF_F_SDF_INIT, SDF_R_INVALID_PARAMETER);
    return NULL;
  }

  /* 1) 原名 */
  fp = GetProcAddress(h, name);
  if (fp)
    return fp;

  /* 2) C/cdecl 常见前导下划线 */
  if ((int)strlen(name) + 2 < (int)sizeof(buf)) {
    _snprintf(buf, sizeof(buf), "_%s", name);
    fp = GetProcAddress(h, buf);
    if (fp)
      return fp;
  }

  /* 3) stdcall 装饰：Name@N 与 _Name@N，尝试常见栈大小 */
  for (i = 0; i <= 64; i += 4) {
    if ((int)strlen(name) + 8 < (int)sizeof(buf)) {
      _snprintf(buf, sizeof(buf), "%s@%d", name, i);
      fp = GetProcAddress(h, buf);
      if (fp)
        return fp;
      _snprintf(buf, sizeof(buf), "_%s@%d", name, i);
      fp = GetProcAddress(h, buf);
      if (fp)
        return fp;
    }
  }

  return NULL;
}
static HMODULE sdf_load_library_win32(const char *filename) {
  HMODULE handle = NULL;
  WCHAR *wfilename = NULL;
  int wlen;
  /* 可选：临时将 DLL 所在目录加入安全搜索目录，以便解析其依赖 */
  HMODULE hKernel32;
  BOOL(WINAPI * pSetDefaultDllDirectories)(DWORD) = NULL;
  PVOID(WINAPI * pAddDllDirectory)
  (PCWSTR) = NULL; /* DLL_DIRECTORY_COOKIE 兼容声明 */
  BOOL(WINAPI * pRemoveDllDirectory)(PVOID) = NULL;
  PVOID add_cookie = NULL;
  WCHAR *wdir = NULL;

  if (!filename) {
    SDF_ERR("sdf_load_library_win32: filename is null");
    SDFerr(SDF_F_SDF_INIT, SDF_R_INVALID_PARAMETER);
    return NULL;
  }

  /* 尝试解析新式 DLL 目录 API（Windows 8+/Win7+KB2533623） */
  hKernel32 = GetModuleHandleW(L"kernel32.dll");
  if (hKernel32) {
    pSetDefaultDllDirectories = (BOOL(WINAPI *)(DWORD))GetProcAddress(
        hKernel32, "SetDefaultDllDirectories");
    pAddDllDirectory =
        (PVOID(WINAPI *)(PCWSTR))GetProcAddress(hKernel32, "AddDllDirectory");
    pRemoveDllDirectory =
        (BOOL(WINAPI *)(PVOID))GetProcAddress(hKernel32, "RemoveDllDirectory");
  }

  /* 首先尝试直接加载（ANSI 版本） */
  handle = LoadLibraryA(filename);
  if (handle)
    return handle;

  /* 如果失败，尝试 UTF-8 到 UTF-16 转换 */
  wlen = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
  if (wlen > 0) {
    wfilename = (WCHAR *)OPENSSL_malloc(wlen * sizeof(WCHAR));
    if (wfilename) {
      if (MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, wlen) > 0) {
        /* 在可用时，将 DLL 所在目录加入安全搜索列表，以便其依赖可解析 */
        if (pAddDllDirectory && pRemoveDllDirectory) {
          WCHAR *last_slash = NULL;
          for (WCHAR *p = wfilename; *p; ++p) {
            if (*p == L'\\' || *p == L'/')
              last_slash = p;
          }
          if (last_slash) {
            size_t dir_len = (size_t)(last_slash - wfilename);
            wdir = (WCHAR *)OPENSSL_malloc((dir_len + 1) * sizeof(WCHAR));
            if (wdir) {
              wcsncpy(wdir, wfilename, dir_len);
              wdir[dir_len] = L'\0';
              /* 可用则切换到默认安全目录集，避免不必要目录参与搜索 */
              if (pSetDefaultDllDirectories) {
                pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
              }
              add_cookie = pAddDllDirectory(wdir);
            }
          }
        }
        handle = LoadLibraryExW(wfilename, NULL,
                                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        if (add_cookie && pRemoveDllDirectory) {
          pRemoveDllDirectory(add_cookie);
          add_cookie = NULL;
        }
      }
      OPENSSL_free(wfilename);
      if (wdir) {
        OPENSSL_free(wdir);
        wdir = NULL;
      }
    }
  }

  /* 如果还是失败，尝试当前代码页转换 */
  if (!handle) {
    wlen = MultiByteToWideChar(CP_ACP, 0, filename, -1, NULL, 0);
    if (wlen > 0) {
      wfilename = (WCHAR *)OPENSSL_malloc(wlen * sizeof(WCHAR));
      if (wfilename) {
        if (MultiByteToWideChar(CP_ACP, 0, filename, -1, wfilename, wlen) > 0) {
          if (pAddDllDirectory && pRemoveDllDirectory) {
            WCHAR *last_slash = NULL;
            for (WCHAR *p = wfilename; *p; ++p) {
              if (*p == L'\\' || *p == L'/')
                last_slash = p;
            }
            if (last_slash) {
              size_t dir_len = (size_t)(last_slash - wfilename);
              wdir = (WCHAR *)OPENSSL_malloc((dir_len + 1) * sizeof(WCHAR));
              if (wdir) {
                wcsncpy(wdir, wfilename, dir_len);
                wdir[dir_len] = L'\0';
                if (pSetDefaultDllDirectories) {
                  pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                }
                add_cookie = pAddDllDirectory(wdir);
              }
            }
          }
          handle = LoadLibraryExW(wfilename, NULL,
                                  LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                      LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
          if (add_cookie && pRemoveDllDirectory) {
            pRemoveDllDirectory(add_cookie);
            add_cookie = NULL;
          }
        }
        OPENSSL_free(wfilename);
        if (wdir) {
          OPENSSL_free(wdir);
          wdir = NULL;
        }
      }
    }
  }

  return handle;
}

#define DLOPEN(filename) sdf_load_library_win32(filename)
#define DLSYM(handle, symbol) win32_getproc_multi(handle, symbol)
#define DLCLOSE(handle) FreeLibrary(handle)
#define DLERROR() "Windows DLL error"
#else
#include <dlfcn.h>
#include <pthread.h>
#define DLOPEN(filename) dlopen(filename, RTLD_LAZY)
#define DLSYM(handle, symbol) dlsym(handle, symbol)
#define DLCLOSE(handle) dlclose(handle)
#define DLERROR() dlerror()
#endif

/* ENGINE 控制命令 */
#define SDF_CMD_MODULE_PATH ENGINE_CMD_BASE
#define SDF_CMD_MODULE_TYPE ENGINE_CMD_BASE + 1
#define SDF_CMD_DEVICE_NAME (ENGINE_CMD_BASE + 2)
#define SDF_CMD_KEY_INDEX (ENGINE_CMD_BASE + 3)
#define SDF_CMD_PASSWORD (ENGINE_CMD_BASE + 4)
#define SDF_CMD_START_PASSWORD (ENGINE_CMD_BASE + 5)
#define SDF_CMD_LIST_VENDORS (ENGINE_CMD_BASE + 6)
#define SDF_CMD_SWITCH_VENDOR (ENGINE_CMD_BASE + 7)
#define SDF_CMD_GET_CURRENT (ENGINE_CMD_BASE + 8)
#define SDF_CMD_AUTO_SELECT (ENGINE_CMD_BASE + 9)
#define SDF_CMD_HELP (ENGINE_CMD_BASE + 10)
#define SDF_CMD_IMPORT_KEY (ENGINE_CMD_BASE + 11)
#define SDF_CMD_IMPORT_CERT (ENGINE_CMD_BASE + 12)
#define SDF_CMD_DELETE_KEY (ENGINE_CMD_BASE + 13)
#define SDF_CMD_DELETE_CERT (ENGINE_CMD_BASE + 14)
#define SDF_CMD_GEN_SYM_KEY (ENGINE_CMD_BASE + 15)
#define SDF_CMD_DELETE_SYM_KEY (ENGINE_CMD_BASE + 16)
#define SDF_CMD_IMPORT_SYM_KEY (ENGINE_CMD_BASE + 17)
/* 完整的位掩码功能控制命令 */
#define SDF_CMD_SET_FEATURE_MASK (ENGINE_CMD_BASE + 18)
#define SDF_CMD_GET_FEATURE_MASK (ENGINE_CMD_BASE + 19)
#define SDF_CMD_SET_MODE_PRESET (ENGINE_CMD_BASE + 20)
#define SDF_CMD_LIST_FEATURES (ENGINE_CMD_BASE + 21)
#define SDF_CMD_VALIDATE_MASK (ENGINE_CMD_BASE + 22)

/* ENGINE 控制命令定义 */
static const ENGINE_CMD_DEFN sdf_cmd_defns[] = {
    {SDF_CMD_MODULE_PATH, "MODULE_PATH", "SDF library path",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_MODULE_TYPE, "MODULE_TYPE", "SDF library type",
     ENGINE_CMD_FLAG_NUMERIC},
    {SDF_CMD_DEVICE_NAME, "DEVICE_NAME", "Device name", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_KEY_INDEX, "KEY_INDEX", "Key index", ENGINE_CMD_FLAG_NUMERIC},
    {SDF_CMD_PASSWORD, "PASSWORD", "Password", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_START_PASSWORD, "START_PASSWORD", "Start Password",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_LIST_VENDORS, "LIST_VENDORS", "List all vendors",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SDF_CMD_SWITCH_VENDOR, "SWITCH_VENDOR", "Switch vendor",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_GET_CURRENT, "GET_CURRENT", "Get current vendor",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SDF_CMD_AUTO_SELECT, "AUTO_SELECT", "Auto select vendor",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SDF_CMD_HELP, "HELP", "Print all available control commands",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SDF_CMD_IMPORT_KEY, "IMPORT_KEY",
     "Import asymmetric key pair (format: type:index:file_path)",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_IMPORT_CERT, "IMPORT_CERT",
     "Import certificate (format: index:cert_file_path)",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_DELETE_KEY, "DELETE_KEY",
     "Delete asymmetric key pair (format: type:index)", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_DELETE_CERT, "DELETE_CERT", "Delete certificate (format: index)",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_GEN_SYM_KEY, "GEN_SYM_KEY",
     "Generate symmetric key (format: alg_id:key_index:key_length)",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_DELETE_SYM_KEY, "DELETE_SYM_KEY",
     "Delete symmetric key (format: key_index)", ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_IMPORT_SYM_KEY, "IMPORT_SYM_KEY",
     "Import symmetric key (format: alg_id:key_index:key_data)",
     ENGINE_CMD_FLAG_STRING},

    /* 位掩码功能控制命令 */
    {SDF_CMD_SET_FEATURE_MASK, "FEATURE_MASK",
     "Set feature mask (hex): SSL_KEYS=0x1, BASIC_MGMT=0x2, RSA=0x10, EC=0x40, "
     "RAND=0x100",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_GET_FEATURE_MASK, "GET_FEATURE_MASK",
     "Get current feature mask and status", ENGINE_CMD_FLAG_NO_INPUT},
    {SDF_CMD_SET_MODE_PRESET, "MODE_PRESET",
     "Set preset mode: ssl_only|ssl_hw_sign|full_hw|dangerous|all_features",
     ENGINE_CMD_FLAG_STRING},
    {SDF_CMD_LIST_FEATURES, "LIST_FEATURES",
     "List all available features and their descriptions",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SDF_CMD_VALIDATE_MASK, "VALIDATE_MASK", "Validate feature mask (hex)",
     ENGINE_CMD_FLAG_STRING},

    {0, NULL, NULL, 0}};

/* SDF 引擎上下文 */
typedef struct {
  void *dll_handle;
  char *module_path;
  int module_type;
  char *device_name;
  char *password;
  char *start_password;
  unsigned int key_index;
  int initialized;

  /* 设备和会话句柄 */
  void *hDevice;
  void *hSession;

  /* 设备信息 */
  DEVICEINFO device_info;

  /* SDF 函数指针 */
  SD_FUNCTION_LIST sdfList;

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
  int key_type; /* 0: RSA, 1: ECC/SM2 */
  int is_sign_key;
  EVP_PKEY *pkey;
} SDF_KEY_CTX;

/* 全局 ENGINE index，用于存储 SDF 上下文 */
static int sdf_engine_idx = -1;

/* 完整的位掩码功能控制 */

/* 核心功能层 (0x0001 - 0x000F) */
#define ENGINE_FEATURE_SSL_KEYS 0x0001 /* SSL密钥加载功能 */
#define ENGINE_FEATURE_BASIC_MGMT                                              \
  0x0002 /* 基础管理功能 (init/finish/destroy/ctrl) */
#define ENGINE_FEATURE_USER_INTERFACE 0x0004 /* 用户接口功能 */
#define ENGINE_FEATURE_SSL_EXTENSIONS                                          \
  0x0008 /* SSL扩展功能 (master_secret, key_block) */

/* 密码算法层 (0x0010 - 0x00FF) */
#define ENGINE_FEATURE_RSA 0x0010 /* RSA算法 */
#define ENGINE_FEATURE_DSA 0x0020 /* DSA算法 */
#define ENGINE_FEATURE_EC 0x0040 /* EC/ECDSA算法 */
#define ENGINE_FEATURE_DH 0x0080 /* DH算法 */
#define ENGINE_FEATURE_RAND 0x0100 /* 随机数生成 */
#define ENGINE_FEATURE_BN 0x0200 /* 大数运算 */

/* 高级功能层 (0x0400 - 0x3F00) */
#define ENGINE_FEATURE_CIPHERS 0x0400 /* 对称加密算法 */
#define ENGINE_FEATURE_DIGESTS 0x0800 /* 摘要算法 */
#define ENGINE_FEATURE_PKEY_METHS 0x1000 /* EVP_PKEY_METHOD */
#define ENGINE_FEATURE_PKEY_ASN1_METHS 0x2000 /* EVP_PKEY_ASN1_METHOD */
#define ENGINE_FEATURE_ECP_METHS 0x4000 /* EC点运算方法 */

/* 预设模式组合 */
#define ENGINE_MODE_SSL_ONLY                                                   \
  (ENGINE_FEATURE_SSL_KEYS | ENGINE_FEATURE_BASIC_MGMT) /* 0x0003: SSL Only */
#define ENGINE_MODE_SSL_HW_SIGN                                                \
  (ENGINE_MODE_SSL_ONLY | ENGINE_FEATURE_RSA |                                 \
   ENGINE_FEATURE_EC) /* 0x0053: SSL + HW Sign */
#define ENGINE_MODE_FULL_HARDWARE                                              \
  (ENGINE_MODE_SSL_HW_SIGN | ENGINE_FEATURE_PKEY_METHS |                       \
   ENGINE_FEATURE_CIPHERS | ENGINE_FEATURE_DIGESTS) /* 0x1C53: Full HW */
#define ENGINE_MODE_DANGEROUS                                                  \
  (ENGINE_MODE_FULL_HARDWARE | ENGINE_FEATURE_RAND) /* 0x1D53: Dangerous */
#define ENGINE_MODE_ALL_FEATURES 0xFFFF /* 0xFFFF: All */

/* 国密SSL专用模式 */
#define ENGINE_MODE_GM_SSL_FULL                                                \
  (ENGINE_MODE_SSL_ONLY | ENGINE_FEATURE_SSL_EXTENSIONS |                      \
   ENGINE_FEATURE_EC) /* 0x004B: GM SSL Full */
#define ENGINE_MODE_GM_SSL_HW                                                  \
  (ENGINE_MODE_GM_SSL_FULL | ENGINE_FEATURE_CIPHERS |                          \
   ENGINE_FEATURE_DIGESTS) /* 0x0C4B: GM SSL HW */

static unsigned int sdf_global_feature_mask =
    ENGINE_MODE_SSL_ONLY; /* 默认SSL模式 */

/* 位掩码功能控制函数声明 */
static int sdf_rebind_features(ENGINE *e);
static unsigned int sdf_get_feature_mask(void);
static int sdf_set_feature_mask(unsigned int mask);
static int sdf_validate_mask(unsigned int mask);
static void sdf_clear_all_bindings(ENGINE *e);

/* 错误处理使用 e_sdf_err 提供的接口 */

/* 引擎 ID 和名称 */
static const char *engine_sdf_id = "sdf";
static const char *engine_sdf_name = "SDF Engine";

/* 函数声明 */
static int sdf_init(ENGINE *e);
static int sdf_finish(ENGINE *e);
static int sdf_destroy(ENGINE *e);
static int sdf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));
static EVP_PKEY *sdf_load_privkey(ENGINE *e, const char *key_id,
                                  UI_METHOD *ui_method, void *callback_data);
static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data);
static int sdf_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                    STACK_OF(X509_NAME) * ca_dn, X509 **pcert,
                                    EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                                    UI_METHOD *ui_method, void *callback_data);

/* SDF 上下文管理函数 */
static SDF_CTX *sdf_get_ctx(ENGINE *e);
static int sdf_set_ctx(ENGINE *e, SDF_CTX *ctx);

/* 获取SDF函数指针 */
static void setFunctionList(void *hCT32, SD_FUNCTION_LIST_PTR pList,
                            SGD_UINT32 iGetProcAddressID) {
  //=====================================设备管理============================================//
  pList->SDF_OpenDevice = (_CP_SDF_OpenDevice *)DLSYM(hCT32, "SDF_OpenDevice");
  pList->SDF_CloseDevice =
      (_CP_SDF_CloseDevice *)DLSYM(hCT32, "SDF_CloseDevice");
  pList->SDF_OpenSession =
      (_CP_SDF_OpenSession *)DLSYM(hCT32, "SDF_OpenSession");
  pList->SDF_CloseSession =
      (_CP_SDF_CloseSession *)DLSYM(hCT32, "SDF_CloseSession");
  pList->SDF_GetDeviceInfo =
      (_CP_SDF_GetDeviceInfo *)DLSYM(hCT32, "SDF_GetDeviceInfo");
  pList->SDF_GenerateRandom =
      (_CP_SDF_GenerateRandom *)DLSYM(hCT32, "SDF_GenerateRandom");
  pList->SDF_GetPrivateKeyAccessRight =
      (_CP_SDF_GetPrivateKeyAccessRight *)DLSYM(hCT32,
                                                "SDF_GetPrivateKeyAccessRight");
  pList->SDF_ReleasePrivateKeyAccessRight =
      (_CP_SDF_ReleasePrivateKeyAccessRight *)DLSYM(
          hCT32, "SDF_ReleasePrivateKeyAccessRight");
  //=====================================密钥管理============================================//
  pList->SDF_GenerateKeyPair_RSA =
      (_CP_SDF_GenerateKeyPair_RSA *)DLSYM(hCT32, "SDF_GenerateKeyPair_RSA");
  pList->SDF_GenerateKeyPair_RSAEx = (_CP_SDF_GenerateKeyPair_RSAEx *)DLSYM(
      hCT32, "SDF_GenerateKeyPair_RSAEx");
  pList->SDF_ExportSignPublicKey_RSA = (_CP_SDF_ExportSignPublicKey_RSA *)DLSYM(
      hCT32, "SDF_ExportSignPublicKey_RSA");
  pList->SDF_ExportSignPublicKey_RSAEx =
      (_CP_SDF_ExportSignPublicKey_RSAEx *)DLSYM(
          hCT32, "SDF_ExportSignPublicKey_RSAEx");
  pList->SDF_ExportEncPublicKey_RSA = (_CP_SDF_ExportEncPublicKey_RSA *)DLSYM(
      hCT32, "SDF_ExportEncPublicKey_RSA");
  pList->SDF_ExportEncPublicKey_RSAEx =
      (_CP_SDF_ExportEncPublicKey_RSAEx *)DLSYM(hCT32,
                                                "SDF_ExportEncPublicKey_RSAEx");
  pList->SDF_GenerateKeyWithIPK_RSA = (_CP_SDF_GenerateKeyWithIPK_RSA *)DLSYM(
      hCT32, "SDF_GenerateKeyWithIPK_RSA");
  pList->SDF_GenerateKeyWithEPK_RSA = (_CP_SDF_GenerateKeyWithEPK_RSA *)DLSYM(
      hCT32, "SDF_GenerateKeyWithEPK_RSA");
  pList->SDF_GenerateKeyWithEPK_RSAEx =
      (_CP_SDF_GenerateKeyWithEPK_RSAEx *)DLSYM(hCT32,
                                                "SDF_GenerateKeyWithEPK_RSAEx");
  pList->SDF_ImportKeyWithISK_RSA =
      (_CP_SDF_ImportKeyWithISK_RSA *)DLSYM(hCT32, "SDF_ImportKeyWithISK_RSA");
  pList->SDF_ExchangeDigitEnvelopeBaseOnRSA =
      (_CP_SDF_ExchangeDigitEnvelopeBaseOnRSA *)DLSYM(
          hCT32, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
  pList->SDF_ExchangeDigitEnvelopeBaseOnRSAEx =
      (_CP_SDF_ExchangeDigitEnvelopeBaseOnRSAEx *)DLSYM(
          hCT32, "SDF_ExchangeDigitEnvelopeBaseOnRSAEx");

  pList->SDF_ImportKey = (_CP_SDF_ImportKey *)DLSYM(hCT32, "SDF_ImportKey");
  pList->SDF_DestroyKey = (_CP_SDF_DestroyKey *)DLSYM(hCT32, "SDF_DestroyKey");
  pList->SDF_GetSymmKeyHandle =
      (_CP_SDF_GetSymmKeyHandle *)DLSYM(hCT32, "SDF_GetSymmKeyHandle");
  pList->SDF_GenerateKeyWithKEK =
      (_CP_SDF_GenerateKeyWithKEK *)DLSYM(hCT32, "SDF_GenerateKeyWithKEK");
  pList->SDF_ImportKeyWithKEK =
      (_CP_SDF_ImportKeyWithKEK *)DLSYM(hCT32, "SDF_ImportKeyWithKEK");

  pList->SDF_GenerateKeyPair_ECC =
      (_CP_SDF_GenerateKeyPair_ECC *)DLSYM(hCT32, "SDF_GenerateKeyPair_ECC");
  pList->SDF_ExportSignPublicKey_ECC = (_CP_SDF_ExportSignPublicKey_ECC *)DLSYM(
      hCT32, "SDF_ExportSignPublicKey_ECC");
  pList->SDF_ExportEncPublicKey_ECC = (_CP_SDF_ExportEncPublicKey_ECC *)DLSYM(
      hCT32, "SDF_ExportEncPublicKey_ECC");
  pList->SDF_GenerateAgreementDataWithECC =
      (_CP_SDF_GenerateAgreementDataWithECC *)DLSYM(
          hCT32, "SDF_GenerateAgreementDataWithECC");
  pList->SDF_GenerateKeyWithECC =
      (_CP_SDF_GenerateKeyWithECC *)DLSYM(hCT32, "SDF_GenerateKeyWithECC");
  pList->SDF_GenerateAgreementDataAndKeyWithECC =
      (_CP_SDF_GenerateAgreementDataAndKeyWithECC *)DLSYM(
          hCT32, "SDF_GenerateAgreementDataAndKeyWithECC");
  pList->SDF_GenerateKeyWithIPK_ECC = (_CP_SDF_GenerateKeyWithIPK_ECC *)DLSYM(
      hCT32, "SDF_GenerateKeyWithIPK_ECC");
  pList->SDF_GenerateKeyWithEPK_ECC = (_CP_SDF_GenerateKeyWithEPK_ECC *)DLSYM(
      hCT32, "SDF_GenerateKeyWithEPK_ECC");
  pList->SDF_ImportKeyWithISK_ECC =
      (_CP_SDF_ImportKeyWithISK_ECC *)DLSYM(hCT32, "SDF_ImportKeyWithISK_ECC");
  pList->SDF_ExchangeDigitEnvelopeBaseOnECC =
      (_CP_SDF_ExchangeDigitEnvelopeBaseOnECC *)DLSYM(
          hCT32, "SDF_ExchangeDigitEnvelopeBaseOnECC");
  //=====================================非对称密码运算============================================//
  pList->SDF_ExternalPublicKeyOperation_RSA =
      (_CP_SDF_ExternalPublicKeyOperation_RSA *)DLSYM(
          hCT32, "SDF_ExternalPublicKeyOperation_RSA");
  pList->SDF_ExternalPublicKeyOperation_RSAEx =
      (_CP_SDF_ExternalPublicKeyOperation_RSAEx *)DLSYM(
          hCT32, "SDF_ExternalPublicKeyOperation_RSAEx");
  pList->SDF_ExternalPrivateKeyOperation_RSA =
      (_CP_SDF_ExternalPrivateKeyOperation_RSA *)DLSYM(
          hCT32, "SDF_ExternalPrivateKeyOperation_RSA");
  pList->SDF_ExternalPrivateKeyOperation_RSAEx =
      (_CP_SDF_ExternalPrivateKeyOperation_RSAEx *)DLSYM(
          hCT32, "SDF_ExternalPrivateKeyOperation_RSAEx");
  pList->SDF_InternalPublicKeyOperation_RSA =
      (_CP_SDF_InternalPublicKeyOperation_RSA *)DLSYM(
          hCT32, "SDF_InternalPublicKeyOperation_RSA");
  pList->SDF_InternalPrivateKeyOperation_RSA =
      (_CP_SDF_InternalPrivateKeyOperation_RSA *)DLSYM(
          hCT32, "SDF_InternalPrivateKeyOperation_RSA");
  pList->SDF_InternalPublicKeyOperation_RSA_Ex =
      (_CP_SDF_InternalPublicKeyOperation_RSA_Ex *)DLSYM(
          hCT32, "SDF_InternalPublicKeyOperation_RSA_Ex");
  pList->SDF_InternalPrivateKeyOperation_RSA_Ex =
      (_CP_SDF_InternalPrivateKeyOperation_RSA_Ex *)DLSYM(
          hCT32, "SDF_InternalPrivateKeyOperation_RSA_Ex");

  pList->SDF_ExternalSign_ECC =
      (_CP_SDF_ExternalSign_ECC *)DLSYM(hCT32, "SDF_ExternalSign_ECC");
  pList->SDF_ExternalVerify_ECC =
      (_CP_SDF_ExternalVerify_ECC *)DLSYM(hCT32, "SDF_ExternalVerify_ECC");
  pList->SDF_InternalSign_ECC =
      (_CP_SDF_InternalSign_ECC *)DLSYM(hCT32, "SDF_InternalSign_ECC");
  pList->SDF_InternalVerify_ECC =
      (_CP_SDF_InternalVerify_ECC *)DLSYM(hCT32, "SDF_InternalVerify_ECC");
  pList->SDF_ExternalEncrypt_ECC =
      (_CP_SDF_ExternalEncrypt_ECC *)DLSYM(hCT32, "SDF_ExternalEncrypt_ECC");
  pList->SDF_ExternalDecrypt_ECC =
      (_CP_SDF_ExternalDecrypt_ECC *)DLSYM(hCT32, "SDF_ExternalDecrypt_ECC");
  pList->SDF_InternalEncrypt_ECC =
      (_CP_SDF_InternalEncrypt_ECC *)DLSYM(hCT32, "SDF_InternalEncrypt_ECC");
  pList->SDF_InternalDecrypt_ECC =
      (_CP_SDF_InternalDecrypt_ECC *)DLSYM(hCT32, "SDF_InternalDecrypt_ECC");

  //=====================================对称密码运算============================================//
  pList->SDF_Encrypt = (_CP_SDF_Encrypt *)DLSYM(hCT32, "SDF_Encrypt");
  pList->SDF_Decrypt = (_CP_SDF_Decrypt *)DLSYM(hCT32, "SDF_Decrypt");
  pList->SDF_CalculateMAC =
      (_CP_SDF_CalculateMAC *)DLSYM(hCT32, "SDF_CalculateMAC");

  //=====================================杂凑运算============================================//
  pList->SDF_HashInit = (_CP_SDF_HashInit *)DLSYM(hCT32, "SDF_HashInit");
  pList->SDF_HashUpdate = (_CP_SDF_HashUpdate *)DLSYM(hCT32, "SDF_HashUpdate");
  pList->SDF_HashFinal = (_CP_SDF_HashFinal *)DLSYM(hCT32, "SDF_HashFinal");

  //=====================================用户文件操作============================================//
  pList->SDF_CreateFile = (_CP_SDF_CreateFile *)DLSYM(hCT32, "SDF_CreateFile");
  pList->SDF_ReadFile = (_CP_SDF_ReadFile *)DLSYM(hCT32, "SDF_ReadFile");
  pList->SDF_WriteFile = (_CP_SDF_WriteFile *)DLSYM(hCT32, "SDF_WriteFile");
  pList->SDF_DeleteFile = (_CP_SDF_DeleteFile *)DLSYM(hCT32, "SDF_DeleteFile");
  //=====================================扩展接口============================================//
  pList->SDF_InputRSAKeyPair =
      (_CP_SDF_InputRSAKeyPair *)DLSYM(hCT32, "SDF_InputRSAKeyPair");
  pList->SDF_InputRSAKeyPairEx =
      (_CP_SDF_InputRSAKeyPairEx *)DLSYM(hCT32, "SDF_InputRSAKeyPairEx");
  pList->SDF_ImportKeyPair_ECC =
      (_CP_SDF_ImportKeyPair_ECC *)DLSYM(hCT32, "SDF_ImportKeyPair_ECC");
  pList->SDF_GetErrMsg = (_CP_SDF_GetErrMsg *)DLSYM(hCT32, "SDF_GetErrMsg");
  pList->SDF_GetKekAccessRight =
      (_CP_SDF_GetKekAccessRight *)DLSYM(hCT32, "SDF_GetKekAccessRight");
  pList->SDF_ReleaseKekAccessRight = (_CP_SDF_ReleaseKekAccessRight *)DLSYM(
      hCT32, "SDF_ReleaseKekAccessRight");

  //=====================================管理接口============================================//
  pList->BYCSM_LoadModule =
      (_CP_BYCSM_LoadModule *)DLSYM(hCT32, "BYCSM_LoadModule");
  pList->BYCSM_UninstallModule =
      (_CP_BYCSM_UninstallModule *)DLSYM(hCT32, "BYCSM_UninstallModule");
}

/* 辅助函数 */
static void sdf_lock(SDF_CTX *ctx) {
  if (!ctx)
    return;
#ifdef _WIN32
  EnterCriticalSection(&ctx->lock);
#else
  pthread_mutex_lock(&ctx->lock);
#endif
}

static void sdf_unlock(SDF_CTX *ctx) {
  if (!ctx)
    return;
#ifdef _WIN32
  LeaveCriticalSection(&ctx->lock);
#else
  pthread_mutex_unlock(&ctx->lock);
#endif
}

static SDF_CTX *sdf_ctx_new(void) {
  SDF_CTX *ctx = OPENSSL_zalloc(sizeof(SDF_CTX));
  if (!ctx) {
    SDFerr(SDF_F_SDF_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  ctx->key_index = 1; /* 默认密钥索引 */

#ifdef _WIN32
  InitializeCriticalSection(&ctx->lock);
#else
  pthread_mutex_init(&ctx->lock, NULL);
#endif

  return ctx;
}

static void sdf_ctx_free(SDF_CTX *ctx) {
  if (!ctx)
    return;

  /* 释放私钥访问权限 */
  if (ctx->hSession && ctx->sdfList.SDF_ReleasePrivateKeyAccessRight) {
    ctx->sdfList.SDF_ReleasePrivateKeyAccessRight(ctx->hSession,
                                                  ctx->key_index);
  }

  /* 关闭会话和设备 */
  if (ctx->hSession && ctx->sdfList.SDF_CloseSession) {
    ctx->sdfList.SDF_CloseSession(ctx->hSession);
  }
  if (ctx->hDevice && ctx->sdfList.SDF_CloseDevice) {
    ctx->sdfList.SDF_CloseDevice(ctx->hDevice);
  }

  /* 卸载模块 */
  if (ctx->sdfList.BYCSM_UninstallModule) {
    if (ctx->start_password) {
      ctx->sdfList.BYCSM_UninstallModule(ctx->start_password);
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

/* SDF 上下文管理函数 */
static SDF_CTX *sdf_get_ctx(ENGINE *e) {
  if (sdf_engine_idx == -1) {
    SDFerr(SDF_F_SDF_INIT, SDF_R_LIBRARY_NOT_INITIALIZED);
    return NULL;
  }
  return ENGINE_get_ex_data(e, sdf_engine_idx);
}

static int sdf_set_ctx(ENGINE *e, SDF_CTX *ctx) {
  if (sdf_engine_idx == -1) {
    SDF_ERR("sdf_set_ctx: engine index not initialized");
    SDFerr(SDF_F_SDF_INIT, SDF_R_LIBRARY_NOT_INITIALIZED);
    return 0;
  }
  return ENGINE_set_ex_data(e, sdf_engine_idx, ctx);
}

/*static int sdf_switch_to_vendor(const char* vendor_name) {
                // 如果已经是当前厂商，直接返回
                if (current_vendor && strcmp(current_vendor->vendor_name,
vendor_name)
== 0) { return 0;
                }

                // 清理当前厂商
                if (current_vendor && current_vendor->is_initialized) {
                                if (current_vendor->session_handle) {
                                                current_vendor->SDF_CloseSession(current_vendor->session_handle);
                                                current_vendor->session_handle =
NULL;
                                }
                                if (current_vendor->device_handle) {
                                                current_vendor->SDF_CloseDevice(current_vendor->device_handle);
                                                current_vendor->device_handle =
NULL;
                                }
                                current_vendor->is_initialized = 0;
                }

                // 查找目标厂商
                sdf_vendor_ops_t* target_vendor = NULL;
                for (int i = 0; i < vendor_count; i++) {
                                if (strcmp(available_vendors[i]->vendor_name,
vendor_name) == 0) { target_vendor = available_vendors[i]; break;
                                }
                }

                if (!target_vendor) {
                                printf("Vendor %s not found\n", vendor_name);
                                return -1;
                }

                // 初始化新厂商
                if (sdf_init_vendor(target_vendor) == 0) {
                                current_vendor = target_vendor;
                                printf("Switched to SDF vendor: %s\n",
vendor_name); return 0;
                }

                return -1;
}*/

/* 加载 SDF 动态库 */
static int sdf_load_library(SDF_CTX *ctx) {
  if (!ctx || !ctx->module_path) {
    SDF_ERR("module path not set");
    SDFerr(SDF_F_SDF_INIT, SDF_R_CANT_LOAD_SDF_MODULE);
    return 0;
  }

  if (ctx->dll_handle) {
    return 1; /* 已经加载 */
  }

  ctx->dll_handle = DLOPEN(ctx->module_path);
  if (!ctx->dll_handle) {
    SDF_ERR("failed to load library: %s", ctx->module_path);
    SDFerr(SDF_F_SDF_INIT, SDF_R_CANT_LOAD_SDF_MODULE);
    return 0;
  }

  /* 加载函数指针 */
  setFunctionList(ctx->dll_handle, &ctx->sdfList, ctx->module_type);

  /* 检查必要函数是否加载成功 */
  if (!ctx->sdfList.SDF_OpenDevice || !ctx->sdfList.SDF_CloseDevice ||
      !ctx->sdfList.SDF_OpenSession || !ctx->sdfList.SDF_CloseSession) {
    SDF_ERR("missing required SDF symbols in %s", ctx->module_path);
    SDFerr(SDF_F_SDF_INIT, SDF_R_DSO_FAILURE);
    DLCLOSE(ctx->dll_handle);
    ctx->dll_handle = NULL;
    return 0;
  }

  return 1;
}

/* 初始化设备和会话 */
static int sdf_init_device(SDF_CTX *ctx) {
  int ret;

  if (!ctx || ctx->initialized) {
    return ctx ? ctx->initialized : 0;
  }

  if (!sdf_load_library(ctx)) {
    SDF_ERR("sdf_load_library failed");
    SDFerr(SDF_F_SDF_INIT, SDF_R_INIT_FAILED);
    return 0;
  }

  /* 加载模块 */
  if (ctx->sdfList.BYCSM_LoadModule) {
    if (ctx->start_password) {
      ret = ctx->sdfList.BYCSM_LoadModule(ctx->start_password);
      if (ret != SDR_OK) {
        SDF_ERR("BYCSM_LoadModule failed (ret=%d)", ret);
        SDFerr(SDF_F_SDF_INIT, SDF_R_CANT_LOAD_SDF_MODULE);
        return 0;
      }
    }
  }
  /* 打开设备 */
  ret = ctx->sdfList.SDF_OpenDevice(&ctx->hDevice);
  if (ret != SDR_OK) {
    SDF_ERR("SDF_OpenDevice failed (ret=%d)", ret);
    SDFerr(SDF_F_SDF_INIT, SDF_R_DEVICE_OPEN_FAILED);
    return 0;
  }

  /* 打开会话 */
  ret = ctx->sdfList.SDF_OpenSession(ctx->hDevice, &ctx->hSession);
  if (ret != SDR_OK) {
    SDF_ERR("SDF_OpenSession failed (ret=%d)", ret);
    SDFerr(SDF_F_SDF_INIT, SDF_R_SESSION_OPEN_FAILED);
    ctx->sdfList.SDF_CloseDevice(ctx->hDevice);
    ctx->hDevice = NULL;
    return 0;
  }

  /* 获取设备信息 */
  if (ctx->sdfList.SDF_GetDeviceInfo) {
    ret = ctx->sdfList.SDF_GetDeviceInfo(ctx->hSession, &ctx->device_info);
    if (ret != SDR_OK) {
      /* 获取设备信息失败不影响继续使用 */
      SDF_WARN("SDF_GetDeviceInfo failed (ret=%d)", ret);
    }
  }

  ctx->initialized = 1;
  return 1;
}

/* ENGINE 控制函数 */
static int sdf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {
  SDF_CTX *ctx = sdf_get_ctx(e);

  if (!ctx) {
    ctx = sdf_ctx_new();
    if (!ctx) {
      SDF_ERR("ctrl: allocate SDF_CTX failed");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    if (!sdf_set_ctx(e, ctx)) {
      sdf_ctx_free(ctx);
      SDF_ERR("ctrl: set ex_data failed");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }

  switch (cmd) {
  case SDF_CMD_MODULE_PATH:
    if (!p) {
      SDF_ERR("ctrl MODULE_PATH: null pointer");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->module_path);
    ctx->module_path = OPENSSL_strdup((char *)p);
    return ctx->module_path ? 1 : 0;
  case SDF_CMD_MODULE_TYPE:
    ctx->module_type = (unsigned int)i;
    return 1;
  case SDF_CMD_DEVICE_NAME:
    if (!p) {
      SDF_ERR("ctrl DEVICE_NAME: null pointer");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->device_name);
    ctx->device_name = OPENSSL_strdup((char *)p);
    return ctx->device_name ? 1 : 0;

  case SDF_CMD_KEY_INDEX:
    ctx->key_index = (unsigned int)i;
    return 1;

  case SDF_CMD_PASSWORD:
    if (!p) {
      SDF_ERR("ctrl PASSWORD: null pointer");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->password);
    ctx->password = OPENSSL_strdup((char *)p);
    return ctx->password ? 1 : 0;
  case SDF_CMD_START_PASSWORD:
    if (!p) {
      SDF_ERR("ctrl START_PASSWORD: null pointer");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->start_password);
    ctx->start_password = OPENSSL_strdup((char *)p);
    return ctx->start_password ? 1 : 0;
  case SDF_CMD_LIST_VENDORS: {
    // 列出所有可用厂商
    if (!p) {
      SDF_ERR("ctrl LIST_VENDORS: buffer pointer null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    for (int j = 0; j < vendor_count; j++) {
      offset +=
          snprintf(buffer + offset, 1024 - offset,
                   "name:%s,library_path:%s,display_name:%s,priority:%d\n",
                   vendor_configs[j].name, vendor_configs[j].library_path,
                   vendor_configs[j].display_name, vendor_configs[j].priority);
    }
    return 1;
  }
  case SDF_CMD_SWITCH_VENDOR: {
    // 切换到指定厂商
    if (!p) {
      SDF_ERR("ctrl SWITCH_VENDOR: null pointer");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    // return switch_to_vendor((char*)p);
    char *buffer = (char *)p;
    sprintf(buffer, "%s", "not support");
    return 1;
  }
  case SDF_CMD_GET_CURRENT: {
    // 获取当前厂商名称
    if (!p) {
      SDF_ERR("ctrl GET_CURRENT: buffer pointer null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    if (ctx->module_path) {
      strncpy((char *)p, ctx->module_path, strlen(ctx->module_path));
      return 1;
    }
    SDF_ERR("ctrl GET_CURRENT: module_path not set");
    SDFerr(SDF_F_SDF_CTRL, SDF_R_NOT_LOADED);
    return 0;
  }
  case SDF_CMD_AUTO_SELECT: {
    // return auto_select_vendor();
    if (!p) {
      SDF_ERR("ctrl AUTO_SELECT: buffer pointer null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    // return switch_to_vendor((char*)p);
    char *buffer = (char *)p;
    sprintf(buffer, "%s", "not support");
    return 1;
  }
  case SDF_CMD_HELP: {
    // 打印所有可用的控制命令
    if (!p) {
      SDF_ERR("ctrl HELP: buffer pointer null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    offset += snprintf(buffer + offset, 2048 - offset,
                       "Available SDF Engine Control Commands:\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "MODULE_PATH: Set SDF library path\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "DEVICE_NAME: Set device name\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "KEY_INDEX: Set key index\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "PASSWORD: Set password\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "START_PASSWORD: Set start password\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "LIST_VENDORS: List all vendors\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "SWITCH_VENDOR: Switch vendor\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "GET_CURRENT: Get current vendor\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "AUTO_SELECT: Auto select vendor\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "IMPORT_KEY: Import asymmetric key pair (format: "
                       "type:index:file_path)\n");
    offset += snprintf(
        buffer + offset, 2048 - offset,
        "IMPORT_CERT: Import certificate (format: index:cert_file_path)\n");
    offset += snprintf(
        buffer + offset, 2048 - offset,
        "DELETE_KEY: Delete asymmetric key pair (format: type:index)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "DELETE_CERT: Delete certificate (format: index)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "GEN_SYM_KEY: Generate symmetric key (format: "
                       "alg_id:key_index:key_length)\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset,
                 "DELETE_SYM_KEY: Delete symmetric key (format: key_index)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "IMPORT_SYM_KEY: Import symmetric key (format: "
                       "alg_id:key_index:key_data)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "FEATURE_MASK: Set feature mask (hex)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "MODE_PRESET: Set preset mode\n");
    return 1;
  }

    /* 位掩码功能控制命令 */
  case SDF_CMD_SET_FEATURE_MASK: {
    if (!p) {
      SDF_ERR("ctrl SET_FEATURE_MASK: mask string null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }

    unsigned int new_mask = 0;
    char *mask_str = (char *)p;

    /* 支持十六进制输入，如 "0x0053" 或 "83" */
    if (strncmp(mask_str, "0x", 2) == 0 || strncmp(mask_str, "0X", 2) == 0) {
      new_mask = (unsigned int)strtoul(mask_str, NULL, 16);
    } else {
      new_mask = (unsigned int)strtoul(mask_str, NULL, 10);
    }

    /* 验证掉码 */
    if (!sdf_validate_mask(new_mask)) {
      SDF_ERR("Invalid feature mask: 0x%04X", new_mask);
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }

    sdf_global_feature_mask = new_mask;

    SDF_INFO("SDF Feature mask set to: 0x%04X", new_mask);
    SDF_INFO("  SSL Keys: %s",
             (new_mask & ENGINE_FEATURE_SSL_KEYS) ? "ON" : "OFF");
    SDF_INFO("  Basic Mgmt: %s",
             (new_mask & ENGINE_FEATURE_BASIC_MGMT) ? "ON" : "OFF");
    SDF_INFO("  SSL Extensions (GM SSL): %s",
             (new_mask & ENGINE_FEATURE_SSL_EXTENSIONS) ? "ON" : "OFF");
    SDF_INFO("  RSA: %s", (new_mask & ENGINE_FEATURE_RSA) ? "ON" : "OFF");
    SDF_INFO("  EC: %s", (new_mask & ENGINE_FEATURE_EC) ? "ON" : "OFF");
    SDF_INFO("  RAND: %s", (new_mask & ENGINE_FEATURE_RAND) ? "ON" : "OFF");
    SDF_INFO("  PKEY Methods: %s",
             (new_mask & ENGINE_FEATURE_PKEY_METHS) ? "ON" : "OFF");

    if (new_mask & ENGINE_FEATURE_RAND) {
      SDF_WARN("  RAND takeover enabled! May cause static linking issues.");
    }

    /* 重新绑定引擎功能 */
    return sdf_rebind_features(e);
  }

  case SDF_CMD_GET_FEATURE_MASK: {
    if (!p) {
      SDF_ERR("ctrl GET_FEATURE_MASK: buffer pointer null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    offset +=
        snprintf(buffer + offset, 1024 - offset,
                 "Current SDF Feature Mask: 0x%04X\n", sdf_global_feature_mask);
    offset += snprintf(
        buffer + offset, 1024 - offset, "  SSL Keys (0x0001): %s\n",
        (sdf_global_feature_mask & ENGINE_FEATURE_SSL_KEYS) ? "ON" : "OFF");
    offset += snprintf(
        buffer + offset, 1024 - offset, "  Basic Mgmt (0x0002): %s\n",
        (sdf_global_feature_mask & ENGINE_FEATURE_BASIC_MGMT) ? "ON" : "OFF");
    offset +=
        snprintf(buffer + offset, 1024 - offset, "  RSA (0x0010): %s\n",
                 (sdf_global_feature_mask & ENGINE_FEATURE_RSA) ? "ON" : "OFF");
    offset +=
        snprintf(buffer + offset, 1024 - offset, "  EC (0x0040): %s\n",
                 (sdf_global_feature_mask & ENGINE_FEATURE_EC) ? "ON" : "OFF");
    offset += snprintf(buffer + offset, 1024 - offset, "  RAND (0x0100): %s\n",
                       (sdf_global_feature_mask & ENGINE_FEATURE_RAND) ? "ON"
                                                                       : "OFF");
    offset += snprintf(
        buffer + offset, 1024 - offset, "  PKEY Methods (0x1000): %s\n",
        (sdf_global_feature_mask & ENGINE_FEATURE_PKEY_METHS) ? "ON" : "OFF");
    return 1;
  }

  case SDF_CMD_SET_MODE_PRESET: {
    if (!p) {
      SDF_ERR("ctrl SET_MODE_PRESET: mode string null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *mode_str = (char *)p;

    if (strcmp(mode_str, "ssl_only") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_SSL_ONLY;
      SDF_INFO("Mode set to: SSL Only (0x%04X) - Recommended for Nginx",
               ENGINE_MODE_SSL_ONLY);
    } else if (strcmp(mode_str, "ssl_hw_sign") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_SSL_HW_SIGN;
      SDF_INFO("Mode set to: SSL + HW Sign (0x%04X) - SSL + Hardware signing",
               ENGINE_MODE_SSL_HW_SIGN);
    } else if (strcmp(mode_str, "full_hw") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_FULL_HARDWARE;
      SDF_INFO("Mode set to: Full Hardware (0x%04X) - Complete hardware "
               "acceleration",
               ENGINE_MODE_FULL_HARDWARE);
    } else if (strcmp(mode_str, "dangerous") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_DANGEROUS;
      SDF_WARN("Mode set to: Dangerous (0x%04X) - Includes RAND takeover!",
               ENGINE_MODE_DANGEROUS);
    } else if (strcmp(mode_str, "all_features") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_ALL_FEATURES;
      SDF_INFO("Mode set to: All Features (0x%04X) - Maximum functionality",
               ENGINE_MODE_ALL_FEATURES);
    } else if (strcmp(mode_str, "gm_ssl_full") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_GM_SSL_FULL;
      SDF_INFO("Mode set to: GM SSL Full (0x%04X) - Complete GM SSL support",
               ENGINE_MODE_GM_SSL_FULL);
    } else if (strcmp(mode_str, "gm_ssl_hw") == 0) {
      sdf_global_feature_mask = ENGINE_MODE_GM_SSL_HW;
      SDF_INFO("Mode set to: GM SSL Hardware (0x%04X) - GM SSL with hardware "
               "acceleration",
               ENGINE_MODE_GM_SSL_HW);
    } else {
      SDF_ERR("Invalid mode. Available: ssl_only, ssl_hw_sign, full_hw, "
              "dangerous, all_features, gm_ssl_full, gm_ssl_hw");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_UNKNOWN_COMMAND);
      return 0;
    }

    /* 重新绑定引擎功能 */
    return sdf_rebind_features(e);
  }

  case SDF_CMD_LIST_FEATURES: {
    if (!p) {
      SDF_ERR("ctrl LIST_FEATURES: buffer pointer null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    offset += snprintf(buffer + offset, 2048 - offset,
                       "Available SDF Engine Features:\n");
    offset += snprintf(buffer + offset, 2048 - offset, "\n核心功能层:\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0001 - SSL_KEYS: SSL密钥加载功能\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0002 - BASIC_MGMT: 基础管理功能\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0004 - USER_INTERFACE: 用户接口功能\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0008 - SSL_EXTENSIONS: SSL扩展功能\n");
    offset += snprintf(buffer + offset, 2048 - offset, "\n密码算法层:\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "  0x0010 - RSA: RSA算法\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "  0x0020 - DSA: DSA算法\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0040 - EC: EC/ECDSA算法\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "  0x0080 - DH: DH算法\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0100 - RAND: 随机数生成(慎用!)\n");
    offset += snprintf(buffer + offset, 2048 - offset, "\n高级功能层:\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0400 - CIPHERS: 对称加密算法\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x0800 - DIGESTS: 摘要算法\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  0x1000 - PKEY_METHS: EVP_PKEY_METHOD\n");
    offset += snprintf(buffer + offset, 2048 - offset, "\n预设模式:\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  ssl_only (0x0003): 仅SSL功能(推荐Nginx)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  ssl_hw_sign (0x0053): SSL+硬件签名\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  full_hw (0x1C53): 完整硬件加速\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  dangerous (0x1D53): 包含RAND接管(危险!)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  gm_ssl_full (0x004B): 国密SSL完整支持\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "  gm_ssl_hw (0x0C4B): 国密SSL硬件加速\n");
    return 1;
  }

  case SDF_CMD_VALIDATE_MASK: {
    if (!p) {
      SDF_ERR("ctrl VALIDATE_MASK: mask string null");
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *mask_str = (char *)p;

    unsigned int mask = 0;
    if (strncmp(mask_str, "0x", 2) == 0 || strncmp(mask_str, "0X", 2) == 0) {
      mask = (unsigned int)strtoul(mask_str, NULL, 16);
    } else {
      mask = (unsigned int)strtoul(mask_str, NULL, 10);
    }

    int valid = sdf_validate_mask(mask);
    SDF_INFO("Feature mask 0x%04X validation: %s", mask,
             valid ? "VALID" : "INVALID");
    return valid;
  }
  case SDF_CMD_IMPORT_KEY: {
    // 导入非对称密钥对
    // 格式: type:index:file_path (例如 "RSA:1:/path/to/key.pem" 或
    // "ECC:2:/path/to/key.pem")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_ImportKeyPair_RSA 或 SDF_ImportKeyPair_ECC
    // 目前返回不支持的状态
    SDF_WARN("SDF_CMD_IMPORT_KEY: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  case SDF_CMD_IMPORT_CERT: {
    // 导入证书
    // 格式: index:cert_file_path (例如 "1:/path/to/cert.pem")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_ImportCertificate
    SDF_WARN("SDF_CMD_IMPORT_CERT: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  case SDF_CMD_DELETE_KEY: {
    // 删除非对称密钥对
    // 格式: type:index (例如 "RSA:1" 或 "ECC:2")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_DestroyKey
    SDF_WARN("SDF_CMD_DELETE_KEY: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  case SDF_CMD_DELETE_CERT: {
    // 删除证书
    // 格式: index (例如 "1")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_DeleteCertificate
    SDF_WARN("SDF_CMD_DELETE_CERT: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  case SDF_CMD_GEN_SYM_KEY: {
    // 生成对称密钥
    // 格式: alg_id:key_index:key_length (例如 "SGD_SMS4_ECB:1:16")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_GenerateKeyWithKEK
    SDF_WARN("SDF_CMD_GEN_SYM_KEY: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  case SDF_CMD_DELETE_SYM_KEY: {
    // 删除对称密钥
    // 格式: key_index (例如 "1")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_DestroyKey
    SDF_WARN("SDF_CMD_DELETE_SYM_KEY: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  case SDF_CMD_IMPORT_SYM_KEY: {
    // 导入对称密钥
    // 格式: alg_id:key_index:key_data (例如
    // "SGD_SMS4_ECB:1:0123456789ABCDEF0123456789ABCDEF")
    if (!p) {
      SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
      return 0;
    }
    char *param = (char *)p;

    // TODO: 解析参数并调用 SDF_ImportKeyWithKEK
    SDF_WARN("SDF_CMD_IMPORT_SYM_KEY: %s (not implemented yet)", param);
    SDFerr(SDF_F_SDF_CTRL, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }
  default:
    SDFerr(SDF_F_SDF_CTRL, SDF_R_UNKNOWN_COMMAND);
    return 0;
  }
}

/* RSA 签名函数 */
static int sdf_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                        unsigned char *sigret, unsigned int *siglen,
                        const RSA *rsa) {
  SDF_KEY_CTX *key_ctx;
  SDF_CTX *ctx;
  unsigned char padded[RSAref_MAX_LEN];
  unsigned int padded_len = RSAref_MAX_LEN;
  unsigned int output_len = *siglen;
  int ret;

  key_ctx = RSA_get_ex_data(rsa, 0);
  if (!key_ctx || !key_ctx->sdf_ctx) {
    SDF_ERR("rsa sign: key ctx missing");
    SDFerr(SDF_F_SDF_RSA_PRIV_ENC, SDF_R_NOT_INITIALIZED);
    return 0;
  }

  ctx = key_ctx->sdf_ctx;

  if (!ctx->initialized) {
    if (!sdf_init_device(ctx)) {
      SDF_ERR("rsa sign: device init failed");
      SDFerr(SDF_F_SDF_RSA_PRIV_ENC, SDF_R_INIT_FAILED);
      return 0;
    }
  }

  sdf_lock(ctx);

  /* RSA PKCS#1 填充 */
  if (RSA_padding_add_PKCS1_type_1(padded, padded_len, m, m_len) != 1) {
    sdf_unlock(ctx);
    SDF_ERR("rsa sign: PKCS#1 v1.5 padding failed");
    SDFerr(SDF_F_SDF_RSA_PRIV_ENC, SDF_R_INVALID_PADDING);
    return 0;
  }

  /* 调用 SDF 内部私钥运算 */
  ret = ctx->sdfList.SDF_InternalPrivateKeyOperation_RSA(
      ctx->hSession, key_ctx->key_index, padded, padded_len, sigret,
      &output_len);

  sdf_unlock(ctx);

  if (ret != SDR_OK) {
    SDF_ERR("rsa sign: SDF_InternalPrivateKeyOperation_RSA failed ret=%d", ret);
    SDFerr(SDF_F_SDF_RSA_PRIV_ENC, SDF_R_REQUEST_FAILED);
    return 0;
  }

  *siglen = output_len;
  return 1;
}

/* RSA 验证函数 */
static int sdf_rsa_verify(int type, const unsigned char *m, unsigned int m_len,
                          const unsigned char *sigbuf, unsigned int siglen,
                          const RSA *rsa) {
  SDF_KEY_CTX *key_ctx;
  SDF_CTX *ctx;
  unsigned char decrypted[RSAref_MAX_LEN];
  unsigned int decrypted_len = RSAref_MAX_LEN;
  unsigned char *padded_msg = NULL;
  int padded_msg_len;
  int ret;
  int rsa_len;

  // 参数验证
  if (!m || !sigbuf || !rsa || m_len == 0 || siglen == 0) {
    SDF_ERR("rsa verify: invalid arguments (m_len=%u, siglen=%u)", m_len,
            siglen);
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_INVALID_PARAMETER);
    return 0;
  }

  rsa_len = RSA_size(rsa);
  if (siglen != (unsigned int)rsa_len) {
    SDF_ERR("rsa verify: siglen != rsa_len (%u != %d)", siglen, rsa_len);
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_INVALID_SIGNATURE_LENGTH);
    return 0;
  }

  key_ctx = RSA_get_ex_data(rsa, 0);
  if (!key_ctx || !key_ctx->sdf_ctx) {
    SDF_ERR("rsa verify: key ctx missing");
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_NOT_INITIALIZED);
    return 0;
  }

  ctx = key_ctx->sdf_ctx;

  if (!ctx->initialized) {
    if (!sdf_init_device(ctx)) {
      SDF_ERR("rsa verify: device init failed");
      SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_INIT_FAILED);
      return 0;
    }
  }

  sdf_lock(ctx);

  /* 调用 SDF 内部公钥运算 */
  ret = ctx->sdfList.SDF_InternalPublicKeyOperation_RSA(
      ctx->hSession, key_ctx->key_index, (unsigned char *)sigbuf, siglen,
      decrypted, &decrypted_len);

  sdf_unlock(ctx);

  if (ret != SDR_OK) {
    SDF_ERR("rsa verify: SDF_InternalPublicKeyOperation_RSA failed ret=%d",
            ret);
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_REQUEST_FAILED);
    return 0;
  }

  // 验证解密长度
  if (decrypted_len != (unsigned int)rsa_len) {
    SDF_ERR("rsa verify: decrypted_len != rsa_len (%u != %d)", decrypted_len,
            rsa_len);
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_INVALID_SIGNATURE_LENGTH);
    return 0;
  }

  /* 分配padded_msg缓冲区 */
  padded_msg = OPENSSL_malloc(rsa_len);
  if (!padded_msg) {
    SDF_ERR("rsa verify: alloc padded_msg failed");
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  /* 验证并移除PKCS#1 v1.5填充 */
  padded_msg_len = RSA_padding_check_PKCS1_type_1(
      padded_msg, rsa_len, decrypted, decrypted_len, rsa_len);

  if (padded_msg_len < 0) {
    OPENSSL_free(padded_msg);
    SDF_ERR("rsa verify: padding check failed");
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  /* 比较消息内容 */
  ret = 0; // 默认验证失败
  if ((unsigned int)padded_msg_len == m_len &&
      CRYPTO_memcmp(padded_msg, m, m_len) == 0) {
    ret = 1; // 验证成功
  } else {
    SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    ret = 0;
  }

  /* 清理敏感数据 */
  OPENSSL_clear_free(padded_msg, rsa_len);

  return ret;
}

/* RSA 方法表 */
static RSA_METHOD *sdf_rsa_method = NULL;

static RSA_METHOD *get_sdf_rsa_method(void) {
  if (sdf_rsa_method)
    return sdf_rsa_method;

  sdf_rsa_method = RSA_meth_new("SDF RSA method", 0);
  if (!sdf_rsa_method) {
    SDFerr(SDF_F_SDF_RSA_PRIV_ENC, SDF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  RSA_meth_set_sign(sdf_rsa_method, sdf_rsa_sign);
  RSA_meth_set_verify(sdf_rsa_method, sdf_rsa_verify);

  return sdf_rsa_method;
}

/* ECC/SM2 签名函数 */
static int sdf_ecdsa_sign(int type, const unsigned char *dgst, int dgst_len,
                          unsigned char *sig, unsigned int *siglen,
                          const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) {
  SDF_KEY_CTX *key_ctx;
  SDF_CTX *ctx;
  ECCSignature ecc_sig;
  int ret;

  key_ctx = EC_KEY_get_ex_data(eckey, 0);
  if (!key_ctx || !key_ctx->sdf_ctx) {
    SDF_ERR("ecdsa sign: key ctx missing");
    SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_NOT_INITIALIZED);
    return 0;
  }

  ctx = key_ctx->sdf_ctx;

  if (!ctx->initialized) {
    if (!sdf_init_device(ctx)) {
      SDF_ERR("ecdsa sign: device init failed");
      SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_INIT_FAILED);
      return 0;
    }
  }

  sdf_lock(ctx);

  /* 调用 SDF ECC 内部签名 */
  ret = ctx->sdfList.SDF_InternalSign_ECC(ctx->hSession, key_ctx->key_index,
                                          (unsigned char *)dgst, dgst_len,
                                          &ecc_sig);

  sdf_unlock(ctx);

  if (ret != SDR_OK) {
    SDF_ERR("ecdsa sign: SDF_InternalSign_ECC failed ret=%d", ret);
    SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_REQUEST_FAILED);
    return 0;
  }

  /* 转换签名格式为 DER */
  ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
  if (!ecdsa_sig) {
    SDF_ERR("ecdsa sign: alloc ECDSA_SIG failed");
    SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  BIGNUM *bn_r = BN_bin2bn(ecc_sig.r, ECCref_MAX_LEN, NULL);
  BIGNUM *bn_s = BN_bin2bn(ecc_sig.s, ECCref_MAX_LEN, NULL);

  if (!bn_r || !bn_s) {
    BN_free(bn_r);
    BN_free(bn_s);
    ECDSA_SIG_free(ecdsa_sig);
    SDF_ERR("ecdsa sign: BN conversion failed");
    SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s);

  int der_len = i2d_ECDSA_SIG(ecdsa_sig, &sig);
  ECDSA_SIG_free(ecdsa_sig);

  if (der_len < 0) {
    SDF_ERR("ecdsa sign: i2d_ECDSA_SIG failed");
    SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  *siglen = der_len;
  return 1;
}

/* ECC/SM2 验证函数 */
static int sdf_ecdsa_verify(int type, const unsigned char *dgst, int dgst_len,
                            const unsigned char *sigbuf, int sig_len,
                            EC_KEY *eckey) {
  SDF_KEY_CTX *key_ctx;
  SDF_CTX *ctx;
  ECCSignature ecc_sig;
  ECDSA_SIG *ecdsa_sig;
  const BIGNUM *bn_r, *bn_s;
  int ret;

  key_ctx = EC_KEY_get_ex_data(eckey, 0);
  if (!key_ctx || !key_ctx->sdf_ctx) {
    SDF_ERR("ecdsa verify: key ctx missing");
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_NOT_INITIALIZED);
    return 0;
  }

  ctx = key_ctx->sdf_ctx;

  if (!ctx->initialized) {
    if (!sdf_init_device(ctx)) {
      SDF_ERR("ecdsa verify: device init failed");
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INIT_FAILED);
      return 0;
    }
  }

  /* 解析 DER 格式签名 */
  ecdsa_sig = d2i_ECDSA_SIG(NULL, &sigbuf, sig_len);
  if (!ecdsa_sig) {
    SDF_ERR("ecdsa verify: parse DER signature failed");
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_SIGNATURE_LENGTH);
    return 0;
  }

  ECDSA_SIG_get0(ecdsa_sig, &bn_r, &bn_s);

  /* 转换为 SDF 格式 */
  memset(&ecc_sig, 0, sizeof(ecc_sig));
  BN_bn2binpad(bn_r, ecc_sig.r, ECCref_MAX_LEN);
  BN_bn2binpad(bn_s, ecc_sig.s, ECCref_MAX_LEN);

  ECDSA_SIG_free(ecdsa_sig);

  sdf_lock(ctx);

  /* 调用 SDF ECC 内部验证 */
  ret = ctx->sdfList.SDF_InternalVerify_ECC(ctx->hSession, key_ctx->key_index,
                                            (unsigned char *)dgst, dgst_len,
                                            &ecc_sig);

  sdf_unlock(ctx);

  if (ret != SDR_OK) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  return 1;
}

/* ECC 方法表 */
static EC_KEY_METHOD *sdf_ec_method = NULL;

static EC_KEY_METHOD *get_sdf_ec_method(void) {
  if (sdf_ec_method)
    return sdf_ec_method;

  sdf_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
  if (!sdf_ec_method) {
    SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  EC_KEY_METHOD_set_sign(sdf_ec_method, sdf_ecdsa_sign, NULL, NULL);
  EC_KEY_METHOD_set_verify(sdf_ec_method, sdf_ecdsa_verify, NULL);

  return sdf_ec_method;
}

/* 随机数生成函数 */
static int sdf_rand_bytes(unsigned char *buf, int num) {
  /* 获取当前活跃的 ENGINE */
  ENGINE *e = ENGINE_get_default_RAND();
  SDF_CTX *ctx = NULL;
  int ret;

  if (e && strcmp(ENGINE_get_id(e), engine_sdf_id) == 0) {
    ctx = sdf_get_ctx(e);
  }

  if (!ctx || !ctx->initialized) {
    if (ctx && !sdf_init_device(ctx)) {
      SDF_ERR("rand bytes: library not initialized");
      SDFerr(SDF_F_SDF_RAND_BYTES, SDF_R_LIBRARY_NOT_INITIALIZED);
      return 0;
    } else if (!ctx) {
      SDF_ERR("rand bytes: no active SDF engine context");
      SDFerr(SDF_F_SDF_RAND_BYTES, SDF_R_LIBRARY_NOT_INITIALIZED);
      return 0;
    }
  }

  if (!ctx->sdfList.SDF_GenerateRandom) {
    SDF_ERR("rand bytes: SDF_GenerateRandom not available");
    SDFerr(SDF_F_SDF_RAND_BYTES, SDF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }

  sdf_lock(ctx);
  ret = ctx->sdfList.SDF_GenerateRandom(ctx->hSession, num, buf);
  sdf_unlock(ctx);

  if (ret != SDR_OK) {
    SDF_ERR("rand bytes: generate failed ret=%d", ret);
    SDFerr(SDF_F_SDF_RAND_BYTES, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  return 1;
}

/* 随机数状态函数 */
static int sdf_rand_status(void) {
  ENGINE *e = ENGINE_get_default_RAND();
  SDF_CTX *ctx = NULL;

  if (e && strcmp(ENGINE_get_id(e), engine_sdf_id) == 0) {
    ctx = sdf_get_ctx(e);
  }

  return ctx && ctx->initialized;
}

/* 随机数方法表 */
static RAND_METHOD sdf_rand_method = {
    NULL,           /* seed */
    sdf_rand_bytes, /* bytes */
    NULL,           /* cleanup */
    NULL,           /* add */
    sdf_rand_bytes, /* pseudorand */
    sdf_rand_status /* status */
};

/* 加载私钥 */
static EVP_PKEY *sdf_load_privkey(ENGINE *e, const char *key_id,
                                  UI_METHOD *ui_method, void *callback_data) {
  SDF_CTX *ctx = sdf_get_ctx(e);
  SDF_KEY_CTX *key_ctx;
  EVP_PKEY *pkey = NULL;
  RSA *rsa = NULL;
  EC_KEY *ec_key = NULL;
  RSArefPublicKey rsa_pub;
  ECCrefPublicKey ecc_pub;
  unsigned int key_index = ctx ? ctx->key_index : 1;
  int key_type = 0; /* 0: RSA, 1: ECC */
  int is_sign_key = 1;
  int ret;

  if (!ctx || !ctx->initialized) {
    if (!ctx || !sdf_init_device(ctx)) {
      SDF_ERR("load_privkey: context not initialized");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_NOT_INITIALIZED);
      return NULL;
    }
  }

  /* 解析密钥 ID 算法:索引:密钥类型
     例如 "rsa:1:sign" 或 "sm2:2:enc"
     目前仅支持全局密码,通过crtl
     PASSWORD设置，一些厂家可以关闭私钥访问控制码，并且私钥访问控制码没有区分算法
     TODO:此处如果想使用每个索引的私钥访问控制码，应该还增加pwd
     例如 "rsa:1:sign:11111111" 或 "sm2:2:enc:12345678"
  */
  if (key_id) {
    if (strncmp(key_id, "rsa:", 4) == 0) {
      key_type = 0;
      key_index = atoi(key_id + 4);
    } else if (strncmp(key_id, "sm2:", 4) == 0 ||
               strncmp(key_id, "ecc:", 4) == 0) {
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
  if (!key_ctx) {
    SDF_ERR("load_privkey: allocate key ctx failed");
    SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  key_ctx->sdf_ctx = ctx;
  key_ctx->key_index = key_index;
  key_ctx->key_type = key_type;
  key_ctx->is_sign_key = is_sign_key;

  sdf_lock(ctx);

  /* 获取密钥访问权限 */
  if (ctx->password && ctx->sdfList.SDF_GetPrivateKeyAccessRight) {
    ret = ctx->sdfList.SDF_GetPrivateKeyAccessRight(
        ctx->hSession, ctx->key_index, (unsigned char *)ctx->password,
        strlen(ctx->password));
    if (ret != SDR_OK) {
      SDF_WARN("load_privkey: authentication failed ret=%d", ret);
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_AUTHENTICATION_FAILED);
      /* 继续执行，某些操作可能不需要认证 */
    }
  }

  if (key_type == 0) { /* RSA */
    /* 导出 RSA 公钥 */
    if (is_sign_key) {
      ret = ctx->sdfList.SDF_ExportSignPublicKey_RSA(ctx->hSession, key_index,
                                                     &rsa_pub);
    } else {
      ret = ctx->sdfList.SDF_ExportEncPublicKey_RSA(ctx->hSession, key_index,
                                                    &rsa_pub);
    }

    if (ret != SDR_OK) {
      sdf_unlock(ctx);
      OPENSSL_free(key_ctx);
      SDF_ERR("load_privkey: export RSA public key failed ret=%d", ret);
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_PUBLIC_KEY_NOT_FOUND);
      return NULL;
    }

    /* 创建 RSA 对象 */
    rsa = RSA_new();
    if (!rsa) {
      sdf_unlock(ctx);
      OPENSSL_free(key_ctx);
      SDF_ERR("load_privkey: RSA_new failed");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_MEMORY_ALLOCATION_FAILED);
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
      SDF_ERR("load_privkey: set RSA key failed");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_INTERNAL_ERROR);
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
      SDF_ERR("load_privkey: assign RSA to EVP_PKEY failed");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_INTERNAL_ERROR);
      return NULL;
    }

  } else { /* ECC/SM2 */
    /* 导出 ECC 公钥 */
    if (is_sign_key) {
      ret = ctx->sdfList.SDF_ExportSignPublicKey_ECC(ctx->hSession, key_index,
                                                     &ecc_pub);
    } else {
      ret = ctx->sdfList.SDF_ExportEncPublicKey_ECC(ctx->hSession, key_index,
                                                    &ecc_pub);
    }

    if (ret != SDR_OK) {
      sdf_unlock(ctx);
      OPENSSL_free(key_ctx);
      SDF_ERR("load_privkey: export ECC public key failed ret=%d", ret);
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_PUBLIC_KEY_NOT_FOUND);
      return NULL;
    }

    /* 创建 EC_KEY 对象 */
    ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    if (!ec_key) {
      sdf_unlock(ctx);
      OPENSSL_free(key_ctx);
      SDF_ERR("load_privkey: EC_KEY_new_by_curve_name failed");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_MEMORY_ALLOCATION_FAILED);
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
      SDF_ERR("load_privkey: set ECC public key failed");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_INTERNAL_ERROR);
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
      SDF_ERR("load_privkey: assign EC_KEY to EVP_PKEY failed");
      SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_INTERNAL_ERROR);
      return NULL;
    }
  }

  sdf_unlock(ctx);
  key_ctx->pkey = pkey;
  return pkey;
}

/* 加载公钥 */
static EVP_PKEY *sdf_load_pubkey(ENGINE *e, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data) {
  /* 公钥和私钥加载逻辑相同，因为我们只使用公钥部分 */
  return sdf_load_privkey(e, key_id, ui_method, callback_data);
}

/* SSL 客户端证书加载函数 */
static int sdf_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                    STACK_OF(X509_NAME) * ca_dn, X509 **pcert,
                                    EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                                    UI_METHOD *ui_method, void *callback_data) {
  /* 这里可以实现从 SDF 设备加载客户端证书的逻辑 */
  /* 目前返回 0 表示不支持 */
  SDFerr(SDF_F_SDF_LOAD_SSL_CLIENT_CERT, SDF_R_NOT_SUPPORTED);
  return 0;
}

/*---------------------------------pkey
 * method---------------------------------------------*/

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

static int sdf_pkey_ec_init(EVP_PKEY_CTX *ctx) {
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

static int sdf_pkey_ec_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src) {
  SDF_EC_PKEY_CTX *dctx, *sctx;
  if (!sdf_pkey_ec_init(dst)) {
    SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  sctx = EVP_PKEY_CTX_get_data(src);
  dctx = EVP_PKEY_CTX_get_data(dst);
  if (sctx->gen_group) {
    dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
    if (!dctx->gen_group) {
      SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }
  dctx->md = sctx->md;

  if (sctx->co_key) {
    dctx->co_key = EC_KEY_dup(sctx->co_key);
    if (!dctx->co_key) {
      SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }
  dctx->kdf_type = sctx->kdf_type;
  dctx->kdf_md = sctx->kdf_md;
  dctx->kdf_outlen = sctx->kdf_outlen;
  if (sctx->kdf_ukm) {
    dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
    if (!dctx->kdf_ukm) {
      SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  } else
    dctx->kdf_ukm = NULL;
  dctx->kdf_ukmlen = sctx->kdf_ukmlen;
#ifndef OPENSSL_NO_SM2
  dctx->ec_scheme = sctx->ec_scheme;
  if (sctx->signer_id) {
    dctx->signer_id = OPENSSL_strdup(sctx->signer_id);
    if (!dctx->signer_id) {
      SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
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

static void sdf_pkey_ec_cleanup(EVP_PKEY_CTX *ctx) {
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

static int sdf_pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_KEY *ec = NULL;
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  int ret = 0;
  if (dctx->gen_group == NULL) {
    SDFerr(SDF_F_SDF_PKEY_EC_PARAMGEN, SDF_R_INVALID_PARAMETER);
    return 0;
  }
  ec = EC_KEY_new();
  if (ec == NULL) {
    SDFerr(SDF_F_SDF_PKEY_EC_PARAMGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  ret = EC_KEY_set_group(ec, dctx->gen_group);
  if (ret)
    EVP_PKEY_assign_EC_KEY(pkey, ec);
  else {
    EC_KEY_free(ec);
    SDFerr(SDF_F_SDF_PKEY_EC_PARAMGEN, SDF_R_INVALID_PARAMETER);
    ret = 0;
  }

  return ret;
}

static int sdf_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_KEY *ec = NULL;
  EVP_PKEY *ctx_pkey = NULL;
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

  ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  if (ctx_pkey == NULL && dctx->gen_group == NULL) {
    SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
    return 0;
  }
  ec = EC_KEY_new();
  if (!ec) {
    SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  if (ctx_pkey) {
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx_pkey)) {
      SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
      return 0;
    }
  } else {
    if (!EC_KEY_set_group(ec, dctx->gen_group)) {
      SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
      return 0;
    }
  }

  return EC_KEY_generate_key(ec);
}

static int sdf_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                            size_t *siglen, const unsigned char *tbs,
                            size_t tbslen) {
  int ret, type;
  unsigned int sltmp;
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

  if (!sig) {
    *siglen = ECDSA_size(ec);
    return 1;
  } else if (*siglen < (size_t)ECDSA_size(ec)) {
    SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_BUFFER_TOO_SMALL);
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

  if (ret <= 0) {
    SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  *siglen = (size_t)sltmp;
  return 1;
}

static int sdf_pkey_ec_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen) {
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
  if (ret <= 0) {
    SDFerr(SDF_F_SDF_PKEY_EC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  return ret;
}

static int sdf_pkey_ec_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                               size_t *outlen, const unsigned char *in,
                               size_t inlen) {
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  switch (dctx->ec_scheme) {
  case NID_sm_scheme:
    /* 这里应该调用 SDF SM2 加密函数 */
    SDFerr(SDF_F_SDF_PKEY_EC_ENCRYPT, SDF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  case NID_secg_scheme:
    /* 这里应该调用 ECIES 加密函数 */
    SDFerr(SDF_F_SDF_PKEY_EC_ENCRYPT, SDF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  default:
    SDFerr(SDF_F_SDF_PKEY_EC_ENCRYPT, SDF_R_NOT_SUPPORTED);
    return 0;
  }
}

static int sdf_pkey_ec_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                               size_t *outlen, const unsigned char *in,
                               size_t inlen) {
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  switch (dctx->ec_scheme) {
  case NID_sm_scheme:
    /* 这里应该调用 SDF SM2 解密函数 */
    SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  case NID_secg_scheme:
    /* 这里应该调用 ECIES 解密函数 */
    SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  default:
    SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_NOT_SUPPORTED);
    return 0;
  }
}

#ifndef OPENSSL_NO_EC
static int sdf_pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                              size_t *keylen) {
  int ret;
  size_t outlen;
  const EC_POINT *pubkey = NULL;
  EC_KEY *eckey;
  EVP_PKEY *pkey, *peerkey;
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

  pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);

  if (!pkey || !peerkey) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_PARAMETER);
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
  if (ret <= 0) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  *keylen = ret;
  return 1;
}

static int sdf_pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                  size_t *keylen) {
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
  if (*keylen != dctx->kdf_outlen) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  if (!sdf_pkey_ec_derive(ctx, NULL, &ktmplen)) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  ktmp = OPENSSL_malloc(ktmplen);
  if (ktmp == NULL) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  if (!sdf_pkey_ec_derive(ctx, ktmp, &ktmplen)) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    goto err;
  }
  /* Do KDF stuff */
  if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen, dctx->kdf_ukm,
                      dctx->kdf_ukmlen, dctx->kdf_md)) {
    SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
    goto err;
  }
  rv = 1;

err:
  OPENSSL_clear_free(ktmp, ktmplen);
  return rv;
}
#endif

static int sdf_pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  SDF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey;
  EC_GROUP *group;
  switch (type) {
  case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
    group = EC_GROUP_new_by_curve_name(p1);
    if (group == NULL) {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
    EC_GROUP_free(dctx->gen_group);
    dctx->gen_group = group;
    return 1;

  case EVP_PKEY_CTRL_EC_PARAM_ENC:
    if (!dctx->gen_group) {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
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
        if (!dctx->co_key) {
          SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
          return 0;
        }
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
    if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62) {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
    dctx->kdf_type = p1;
    return 1;

#ifndef OPENSSL_NO_SM2
  case EVP_PKEY_CTRL_EC_SCHEME:
    if (p1 == -2) {
      return dctx->ec_scheme;
    }
    if (p1 != NID_secg_scheme && p1 != NID_sm_scheme) {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
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
        SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
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
            SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
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
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
    if (!dctx->signer_zid) {
      pkey = EVP_PKEY_CTX_get0_pkey(ctx);
      EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
      unsigned char *zid;
      size_t zidlen = 32;
      if (!(zid = OPENSSL_malloc(zidlen))) {
        SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
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
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
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
    if (p1 <= 0) {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
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

static int sdf_pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                const char *value) {
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
    else {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_EC_SCHEME,
                             scheme, NULL);
  } else if (!strcmp(type, "signer_id")) {
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_SIGNER_ID, 0,
                             (void *)value);
  } else if (!strcmp(type, "ec_encrypt_param")) {
    int encrypt_param;
    if (!(encrypt_param = OBJ_txt2nid(value))) {
      return 0;
    }
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1,
                             EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, encrypt_param,
                             NULL);
#endif
  } else if (strcmp(type, "ec_param_enc") == 0) {
    int param_enc;
    if (strcmp(value, "explicit") == 0)
      param_enc = 0;
    else if (strcmp(value, "named_curve") == 0)
      param_enc = OPENSSL_EC_NAMED_CURVE;
    else {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
    return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
  } else if (strcmp(type, "ecdh_kdf_md") == 0) {
    const EVP_MD *md;
    if ((md = EVP_get_digestbyname(value)) == NULL) {
      SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
      return 0;
    }
    return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
  } else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
    int co_mode;
    co_mode = atoi(value);
    return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
  }

  SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
  return 0;
}

static EVP_PKEY_METHOD *sdf_ec_pkey_meth = NULL;

static EVP_PKEY_METHOD *get_sdf_ec_pkey_method(void) {
  if (sdf_ec_pkey_meth)
    return sdf_ec_pkey_meth;

  sdf_ec_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
  if (!sdf_ec_pkey_meth) {
    SDFerr(SDF_F_SDF_CTRL, SDF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

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
  EVP_PKEY_meth_set_ctrl(sdf_ec_pkey_meth, sdf_pkey_ec_ctrl,
                         sdf_pkey_ec_ctrl_str);

  return sdf_ec_pkey_meth;
}
/* 这是 高层 EVP 接口，注册的是 EVP_PKEY_METHOD
作用是：改变 EVP_PKEY 层的行为
（如 EVP_PKEY_sign/EVP_PKEY_verify/EVP_PKEY_encrypt/EVP_PKEY_decrypt）
bind_sdf 函数中，将 EVP_PKEY_METHOD 与 ENGINE 关联起来

ENGINE_set_xxx 是低层接口，直接替换 OpenSSL 内部的 EC_KEY_METHOD
ENGINE_set_EC作用是：改变
EC_KEY_new/EC_KEY_generate_key/EC_KEY_sign/EC_KEY_verify 这些底层函数的实现。
相当于替换 EC 算法引擎，是和 OpenSSL EC_KEY 结构紧耦合的。
*/
static int sdf_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
                          int nid) {
  static int sdf_pkey_nids[] = {EVP_PKEY_EC, 0};
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
static int sdf_init(ENGINE *e) {
  SDF_CTX *ctx;

  /* 初始化 ENGINE 索引 */
  if (sdf_engine_idx == -1) {
    sdf_engine_idx = ENGINE_get_ex_new_index(0, "SDF_CTX", NULL, NULL, NULL);
    if (sdf_engine_idx == -1) {
      SDFerr(SDF_F_SDF_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }

  ctx = sdf_get_ctx(e);
  if (!ctx) {
    ctx = sdf_ctx_new();
    if (!ctx)
      return 0;
    if (!sdf_set_ctx(e, ctx)) {
      sdf_ctx_free(ctx);
      SDFerr(SDF_F_SDF_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }

  /* 如果已经设置了模块路径，立即初始化设备 */
  if (ctx->module_path) {
    return sdf_init_device(ctx);
  }

  return 1; /* 延迟初始化 */
}

/* ENGINE 清理 */
static int sdf_finish(ENGINE *e) {
  SDF_CTX *ctx = sdf_get_ctx(e);
  if (ctx) {
    sdf_ctx_free(ctx);
    sdf_set_ctx(e, NULL);
  }
  return 1;
}

/* ENGINE 销毁 */
static int sdf_destroy(ENGINE *e) {
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

  ERR_unload_SDF_strings();

  /* 清理 ENGINE 索引 */
  sdf_engine_idx = -1;

  return 1;
}

/* SSL扩展接口实现 - 使用软件回退实现 */
#ifndef OPENSSL_NO_SM2

/* SSL主密钥生成函数 - 软件实现 */
static int sdf_ssl_generate_master_secret(
    ENGINE *e, unsigned char *out, size_t outlen,
    const unsigned char *premaster, size_t premasterlen,
    const unsigned char *client_random, size_t client_randomlen,
    const unsigned char *server_random, size_t server_randomlen,
    const SSL *ssl) {
  /* 使用OpenSSL默认实现，不使用硬件加速 */
  SDF_INFO("SDF: Using software implementation for master secret generation");
  return 0; /* 返回0让OpenSSL使用默认实现 */
}

/* TLS密钥块生成函数 - 软件实现 */
static int sdf_tls1_generate_key_block(
    ENGINE *e, unsigned char *km, size_t kmlen, const unsigned char *master,
    size_t masterlen, const unsigned char *client_random,
    size_t client_randomlen, const unsigned char *server_random,
    size_t server_randomlen, const SSL *ssl) {
  /* 使用OpenSSL默认实现，不使用硬件加速 */
  SDF_INFO("SDF: Using software implementation for key block generation");
  return 0; /* 返回0让OpenSSL使用默认实现 */
}

/* 私钥转换函数 - 硬件实现 */
static EVP_PKEY *sdf_convert_privkey(ENGINE *e, const char *key_id,
                                     UI_METHOD *ui_method,
                                     void *callback_data) {
  SDF_CTX *ctx = sdf_get_ctx(e);
  if (!ctx) {
    SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_LIBRARY_NOT_INITIALIZED);
    return NULL;
  }

  SDF_INFO("SDF: Converting private key from hardware device: %s",
           key_id ? key_id : "default");

  /* 这里可以实现从 SDF 设备中加载私钥的逻辑 */
  /* 目前回退到标准的私钥加载函数 */
  return sdf_load_privkey(e, key_id, ui_method, callback_data);
}

#endif /* OPENSSL_NO_SM2 */

/* 位掩码功能控制函数实现 */

/* 清理所有引擎绑定 */
static void sdf_clear_all_bindings(ENGINE *e) {
  ENGINE_set_load_privkey_function(e, NULL);
  ENGINE_set_load_pubkey_function(e, NULL);
  ENGINE_set_load_ssl_client_cert_function(e, NULL);
  ENGINE_set_RSA(e, NULL);
  ENGINE_set_DSA(e, NULL);
  ENGINE_set_EC(e, NULL);
  ENGINE_set_DH(e, NULL);
  ENGINE_set_RAND(e, NULL);
  ENGINE_set_ciphers(e, NULL);
  ENGINE_set_digests(e, NULL);
  ENGINE_set_pkey_meths(e, NULL);
  ENGINE_set_pkey_asn1_meths(e, NULL);
}

/* 根据位掩码动态重新绑定功能 */
static int sdf_rebind_features(ENGINE *e) {
  SDF_INFO("Rebinding SDF engine features based on mask: 0x%04X",
           sdf_global_feature_mask);

  /* 清理所有功能绑定 */
  sdf_clear_all_bindings(e);

  /* 基础管理功能 (总是绑定，确保引擎正常工作) */
  if (sdf_global_feature_mask & ENGINE_FEATURE_BASIC_MGMT) {
    /* 这些在bind_sdf中已经设置，无需重复绑定 */
    SDF_INFO("  Basic management: ENABLED");
  }

  /* SSL密钥加载功能 */
  if (sdf_global_feature_mask & ENGINE_FEATURE_SSL_KEYS) {
    ENGINE_set_load_privkey_function(e, sdf_load_privkey);
    ENGINE_set_load_pubkey_function(e, sdf_load_pubkey);
    ENGINE_set_load_ssl_client_cert_function(e, sdf_load_ssl_client_cert);
    SDF_INFO("  SSL key loading: ENABLED");
  }

  /* RSA算法功能 */
  if (sdf_global_feature_mask & ENGINE_FEATURE_RSA) {
    /* RSA方法需要先初始化 */
    /* ENGINE_set_RSA(e, sdf_rsa_method); */
    SDF_INFO("  RSA methods: ENABLED (TODO: implement sdf_rsa_method)");
  }

  /* EC/ECDSA算法功能 */
  if (sdf_global_feature_mask & ENGINE_FEATURE_EC) {
    /* EC方法需要先初始化 */
    /* ENGINE_set_EC(e, sdf_ec_method); */
    SDF_INFO("  EC methods: ENABLED (TODO: implement sdf_ec_method)");
  }

  /* 随机数生成功能 (危险) */
  if (sdf_global_feature_mask & ENGINE_FEATURE_RAND) {
    /* ENGINE_set_RAND(e, &sdf_rand_method); */
    SDF_WARN("  RAND takeover: ENABLED (May cause static linking issues!)");
  }

  /* EVP_PKEY_METHOD功能 */
  if (sdf_global_feature_mask & ENGINE_FEATURE_PKEY_METHS) {
    ENGINE_set_pkey_meths(e, sdf_pkey_meths);
    SDF_INFO("  PKEY methods: ENABLED");
  }

  /* SSL扩展功能（国密SSL支持）*/
  if (sdf_global_feature_mask & ENGINE_FEATURE_SSL_EXTENSIONS) {
#ifndef OPENSSL_NO_SM2
    ENGINE_set_ssl_generate_master_secret_function(
        e, sdf_ssl_generate_master_secret);
    ENGINE_set_tls1_generate_key_block_function(e, sdf_tls1_generate_key_block);
    ENGINE_set_convert_privkey_function(e, sdf_convert_privkey);
    SDF_INFO("  SSL Extensions (GM SSL/TLS): ENABLED");
#else
    SDF_WARN("  SSL Extensions: DISABLED (SM2 not compiled)");
#endif
  }

  /* 对称加密算法功能 */
  if (sdf_global_feature_mask & ENGINE_FEATURE_CIPHERS) {
    /* ENGINE_set_ciphers(e, sdf_ciphers); */
    SDF_INFO("  Ciphers: ENABLED (TODO: implement sdf_ciphers)");
  }

  /* 摘要算法功能 */
  if (sdf_global_feature_mask & ENGINE_FEATURE_DIGESTS) {
    /* ENGINE_set_digests(e, sdf_digests); */
    SDF_INFO("  Digests: ENABLED (TODO: implement sdf_digests)");
  }

  return 1;
}

/* 获取当前功能掩码 */
static unsigned int sdf_get_feature_mask(void) {
  return sdf_global_feature_mask;
}

/* 设置功能掩码 */
static int sdf_set_feature_mask(unsigned int mask) {
  if (!sdf_validate_mask(mask)) {
    SDFerr(SDF_F_SDF_SET_FEATURE_MASK, SDF_R_INVALID_PARAMETER);
    return 0;
  }

  sdf_global_feature_mask = mask;
  return 1;
}

/* 验证功能掩码有效性 */
static int sdf_validate_mask(unsigned int mask) {
  /* 基本有效性检查 */
  if (mask == 0)
    return 0; /* 不允许全部禁用 */

  /* 检查未定义的位 */
  unsigned int valid_bits =
      ENGINE_FEATURE_SSL_KEYS | ENGINE_FEATURE_BASIC_MGMT |
      ENGINE_FEATURE_USER_INTERFACE | ENGINE_FEATURE_SSL_EXTENSIONS |
      ENGINE_FEATURE_RSA | ENGINE_FEATURE_DSA | ENGINE_FEATURE_EC |
      ENGINE_FEATURE_DH | ENGINE_FEATURE_RAND | ENGINE_FEATURE_BN |
      ENGINE_FEATURE_CIPHERS | ENGINE_FEATURE_DIGESTS |
      ENGINE_FEATURE_PKEY_METHS | ENGINE_FEATURE_PKEY_ASN1_METHS |
      ENGINE_FEATURE_ECP_METHS;

  if (mask & ~valid_bits) {
    SDF_ERR("Invalid bits in mask: 0x%04X", mask & ~valid_bits);
    SDFerr(SDF_F_SDF_VALIDATE_MASK, SDF_R_INVALID_PARAMETER);
    return 0;
  }

  /* 功能依赖检查 */
  if ((mask & ENGINE_FEATURE_SSL_KEYS) && !(mask & ENGINE_FEATURE_BASIC_MGMT)) {
    SDF_ERR("SSL_KEYS requires BASIC_MGMT");
    SDFerr(SDF_F_SDF_VALIDATE_MASK, SDF_R_INVALID_PARAMETER);
    return 0;
  }

  /* RAND功能警告检查 */
  if (mask & ENGINE_FEATURE_RAND) {
    SDF_WARN("RAND feature may cause static linking issues");
  }

  return 1;
}
/* ENGINE 绑定函数 - 支持完整的位掩码功能控制 */
static int bind_sdf(ENGINE *e) {
  /* 设置基本属性和标志 */
  if (!ENGINE_set_id(e, engine_sdf_id) ||
      !ENGINE_set_name(e, engine_sdf_name) ||
      !ENGINE_set_init_function(e, sdf_init) ||
      !ENGINE_set_finish_function(e, sdf_finish) ||
      !ENGINE_set_destroy_function(e, sdf_destroy) ||
      !ENGINE_set_ctrl_function(e, sdf_ctrl) ||
      !ENGINE_set_cmd_defns(e, sdf_cmd_defns)) {
    SDFerr(SDF_F_BIND_SDF, SDF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  /* 根据全局功能掩码动态绑定功能 */
  sdf_rebind_features(e);

  /* 注册错误字符串 */
  ERR_load_SDF_strings();

  SDF_INFO("SDF Engine initialized with feature mask: 0x%04X",
           sdf_global_feature_mask);
  SDF_INFO("Available control commands: FEATURE_MASK, MODE_PRESET, "
           "LIST_FEATURES, GET_FEATURE_MASK");

  return 1;
}

/* 动态引擎绑定 */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id) {
  if (id && (strcmp(id, engine_sdf_id) != 0)) {
    SDFerr(SDF_F_BIND_SDF, SDF_R_INVALID_PARAMETER);
    return 0;
  }
  if (!bind_sdf(e)) {
    SDFerr(SDF_F_BIND_SDF, SDF_R_MEMORY_ALLOCATION_FAILED);
  }
}
return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
/* 静态引擎注册 */
static ENGINE *engine_sdf(void) {
  ENGINE *ret = ENGINE_new();
  if (ret == NULL) {
    SDFerr(SDF_F_BIND_SDF, SDF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }
  if (!bind_sdf(ret)) {
    ENGINE_free(ret);
    SDFerr(SDF_F_BIND_SDF, SDF_R_INTERNAL_ERROR);
    return NULL;
  }
  return ret;
}

void engine_load_sdf_int(void) {
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

void ENGINE_load_sdf(void) { engine_load_sdf_int(); }
#endif
