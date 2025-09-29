/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * SKF Engine for GMT 0016-2012 Smart Key Interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "e_skf.h"
#include "e_skf_err.c"
#include "e_skf_err.h"
#include <crypto/sm2.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#ifdef _WIN32
#include <windows.h>

/* Windows 加载动态库 */
static FARPROC win32_getproc_multi(HMODULE h, const char *name) {
  FARPROC fp;
  char buf[256];
  int i;

  if (!h || !name) {
    SKF_ERR("win32_getproc_multi: invalid handle or name");
    SKFerr(SKF_F_SKF_LOAD_LIBRARY, SKF_R_INVALID_PARAMETER);
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

  SKF_ERR("win32_getproc_multi: symbol not found: %s", name);
  SKFerr(SKF_F_SKF_LOAD_LIBRARY, SKF_R_DSO_FAILURE);
  return NULL;
}
static HMODULE skf_load_library_win32(const char *filename) {
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
    SKF_ERR("skf_load_library_win32: filename is null");
    SKFerr(SKF_F_SKF_LOAD_LIBRARY, SKF_R_INVALID_PARAMETER);
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

#define DLOPEN(filename) skf_load_library_win32(filename)
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

/* ENGINE 标识 */
static const char *engine_skf_id = "skf";
static const char *engine_skf_name = "SKF Engine";

/* SKF 控制命令 */
#define SKF_CMD_MODULE_PATH ENGINE_CMD_BASE
#define SKF_CMD_MODULE_TYPE (ENGINE_CMD_BASE + 1)
#define SKF_CMD_DEVICE_NAME (ENGINE_CMD_BASE + 2)
#define SKF_CMD_APP_NAME (ENGINE_CMD_BASE + 3)
#define SKF_CMD_CONTAINER_NAME (ENGINE_CMD_BASE + 4)
#define SKF_CMD_USER_PIN (ENGINE_CMD_BASE + 5)
#define SKF_CMD_ADMIN_PIN (ENGINE_CMD_BASE + 6)
#define SKF_CMD_ENUM_DEVICES (ENGINE_CMD_BASE + 7)
#define SKF_CMD_ENUM_APPS (ENGINE_CMD_BASE + 8)
#define SKF_CMD_ENUM_CONTAINERS (ENGINE_CMD_BASE + 9)
#define SKF_CMD_HELP (ENGINE_CMD_BASE + 10)
/* 完整的位掩码功能控制命令 */
#define SKF_CMD_SET_FEATURE_MASK (ENGINE_CMD_BASE + 11)
#define SKF_CMD_GET_FEATURE_MASK (ENGINE_CMD_BASE + 12)
#define SKF_CMD_SET_MODE_PRESET (ENGINE_CMD_BASE + 13)
#define SKF_CMD_LIST_FEATURES (ENGINE_CMD_BASE + 14)
#define SKF_CMD_VALIDATE_MASK (ENGINE_CMD_BASE + 15)

static const ENGINE_CMD_DEFN skf_cmd_defns[] = {
    /* 基本配置命令 */
    {SKF_CMD_MODULE_PATH, "MODULE_PATH", "SKF module path",
     ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_MODULE_TYPE, "MODULE_TYPE", "SKF module type,1:sw 2:ydx defaule:0",
     ENGINE_CMD_FLAG_NUMERIC},
    {SKF_CMD_DEVICE_NAME, "DEVICE_NAME", "SKF device name",
     ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_APP_NAME, "APP_NAME", "SKF application name",
     ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_CONTAINER_NAME, "CONTAINER_NAME", "SKF container name",
     ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_USER_PIN, "USER_PIN", "SKF user PIN", ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_ADMIN_PIN, "ADMIN_PIN", "SKF admin PIN", ENGINE_CMD_FLAG_STRING},

    /* 查询命令 */
    {SKF_CMD_ENUM_DEVICES, "ENUM_DEVICES", "Enumerate SKF devices",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SKF_CMD_ENUM_APPS, "ENUM_APPS", "Enumerate SKF applications",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SKF_CMD_ENUM_CONTAINERS, "ENUM_CONTAINERS", "Enumerate SKF containers",
     ENGINE_CMD_FLAG_NO_INPUT},

    /* 完整的位掩码功能控制命令 */
    {SKF_CMD_SET_FEATURE_MASK, "FEATURE_MASK",
     "Set feature mask (hex): SSL_KEYS=0x1, BASIC_MGMT=0x2, RSA=0x10, EC=0x40, "
     "RAND=0x100",
     ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_GET_FEATURE_MASK, "GET_FEATURE_MASK",
     "Get current feature mask and status", ENGINE_CMD_FLAG_NO_INPUT},
    {SKF_CMD_SET_MODE_PRESET, "MODE_PRESET",
     "Set preset mode: ssl_only|ssl_hw_sign|full_hw|dangerous|all_features",
     ENGINE_CMD_FLAG_STRING},
    {SKF_CMD_LIST_FEATURES, "LIST_FEATURES",
     "List all available features and their descriptions",
     ENGINE_CMD_FLAG_NO_INPUT},
    {SKF_CMD_VALIDATE_MASK, "VALIDATE_MASK", "Validate feature mask (hex)",
     ENGINE_CMD_FLAG_STRING},

    /* 帮助命令 */
    {SKF_CMD_HELP, "HELP", "Print all available control commands",
     ENGINE_CMD_FLAG_NO_INPUT},

    {0, NULL, NULL, 0}};

/* 使用 Tongsuo 中已定义的宏和控制命令 */
#include <openssl/obj_mac.h>

/* 定义标准 ECC 方案标识符 - 用于区分 SM2 和标准 ECDSA */
#define NID_secg_scheme NID_undef /* 标准 ECDSA/ECDH 不需要特殊标识符 */

/* 定义 ENGINE 特定的控制命令 */
#define SKF_PKEY_CTRL_EC_SCHEME (EVP_PKEY_ALG_CTRL + 50)
#define SKF_PKEY_CTRL_SIGNER_ID EVP_PKEY_CTRL_SET_PEER_ID
#define SKF_PKEY_CTRL_GET_SIGNER_ID (EVP_PKEY_ALG_CTRL + 51)
#define SKF_PKEY_CTRL_GET_SIGNER_ZID (EVP_PKEY_ALG_CTRL + 52)
#define SKF_PKEY_CTRL_EC_ENCRYPT_PARAM EVP_PKEY_CTRL_SET_ENCDATA

/* SKF 引擎上下文 */
typedef struct {
  void *dll_handle;
  char *module_path;
  int module_type; /* 0: sw, 1: ydx */
  char *device_name;
  char *app_name;
  char *container_name;
  char *user_pin;
  char *admin_pin;

  /* 设备和应用句柄 */
  void *hDev;
  void *hApplication;
  void *hContainer;

  int initialized;
  int logged_in;

#ifdef _WIN32
  CRITICAL_SECTION lock;
#else
  pthread_mutex_t lock;
#endif

  /* SKF 函数指针 */
  SK_FUNCTION_LIST skfList;

} SKF_CTX;

/* SKF 密钥上下文 */
typedef struct {
  SKF_CTX *skf_ctx;
  void *hContainer;
  int key_type;    /* 0: RSA, 1: ECC/SM2 */
  int is_sign_key; /* 1: 签名密钥, 0: 加密密钥 */
  EVP_PKEY *pkey;
} SKF_KEY_CTX;

/* 错误处理 */
static ERR_STRING_DATA skf_str_functs[] = {{ERR_PACK(0, 0, 0), "skf engine"},
                                           {0, NULL}};

static ERR_STRING_DATA skf_str_reasons[] = {
    {1, "skf library not found"}, {2, "skf function not found"},
    {3, "skf operation failed"},  {4, "invalid parameter"},
    {5, "device not found"},      {6, "application not found"},
    {7, "container not found"},   {8, "authentication failed"},
    {9, "key not found"},         {0, NULL}};

#include "e_skf_err.h"

/* 全局 ENGINE index，用于存储 SKF 上下文 */
static int skf_engine_idx = -1;

/* 完整的位掩码功能控制 - 基于 engine.h 接口分析 */

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

static unsigned int skf_global_feature_mask =
    ENGINE_MODE_SSL_ONLY; /* 默认SSL模式 */

/* 位掩码功能控制函数声明 */
static int skf_rebind_features(ENGINE *e);
static unsigned int skf_get_feature_mask(void);
static int skf_set_feature_mask(unsigned int mask);
static int skf_validate_mask(unsigned int mask);
static void skf_clear_all_bindings(ENGINE *e);

/* 函数声明 */
static int skf_init(ENGINE *e);
static int skf_finish(ENGINE *e);
static int skf_destroy(ENGINE *e);
static int skf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void));
static int skf_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
                          int nid);

/* SKF 上下文管理函数 */
static SKF_CTX *skf_get_ctx(ENGINE *e);
static int skf_set_ctx(ENGINE *e, SKF_CTX *ctx);

/* 枚举函数声明 */
static int skf_enum_devices(SKF_CTX *ctx, char **device_list);
static int skf_enum_applications(SKF_CTX *ctx, char **app_list);
static int skf_enum_containers(SKF_CTX *ctx, char **container_list);
static void skf_print_device_list(const char *device_list);
static void skf_print_app_list(const char *app_list);
static void skf_print_container_list(const char *container_list);

/* 获取SKF函数指针 */
static void setFunctionList(HMODULE hCT32, SK_FUNCTION_LIST_PTR pList,
                            UINT4 iGetProcAddressID) {
  //=====================================设备管理============================================//
  pList->SKF_WaitForDevEvent =
      (_CP_SKF_WaitForDevEvent *)DLSYM(hCT32, "SKF_WaitForDevEvent");
  pList->SKF_CancelWaitForDevEvent = (_CP_SKF_CancelWaitForDevEvent *)DLSYM(
      hCT32, "SKF_CancelWaitForDevEvent");
  pList->SKF_EnumDev = (_CP_SKF_EnumDev *)DLSYM(hCT32, "SKF_EnumDev");
  pList->SKF_ConnectDev = (_CP_SKF_ConnectDev *)DLSYM(hCT32, "SKF_ConnectDev");
  pList->SKF_DisConnectDev =
      (_CP_SKF_DisConnectDev *)DLSYM(hCT32, "SKF_DisConnectDev");
  pList->SKF_GetDevState =
      (_CP_SKF_GetDevState *)DLSYM(hCT32, "SKF_GetDevState");
  pList->SKF_SetLabel = (_CP_SKF_SetLabel *)DLSYM(hCT32, "SKF_SetLabel");
  pList->SKF_GetDevInfo = (_CP_SKF_GetDevInfo *)DLSYM(hCT32, "SKF_GetDevInfo");
  pList->SKF_LockDev = (_CP_SKF_LockDev *)DLSYM(hCT32, "SKF_LockDev");
  pList->SKF_UnlockDev = (_CP_SKF_UnlockDev *)DLSYM(hCT32, "SKF_UnlockDev");
  pList->SKF_Transmit = (_CP_SKF_Transmit *)DLSYM(hCT32, "SKF_Transmit");
  //=====================================访问控制============================================//
  pList->SKF_ChangeDevAuthKey =
      (_CP_SKF_ChangeDevAuthKey *)DLSYM(hCT32, "SKF_ChangeDevAuthKey");
  pList->SKF_DevAuth = (_CP_SKF_DevAuth *)DLSYM(hCT32, "SKF_DevAuth");
  pList->SKF_ChangePIN = (_CP_SKF_ChangePIN *)DLSYM(hCT32, "SKF_ChangePIN");
  pList->SKF_GetPINInfo = (_CP_SKF_GetPINInfo *)DLSYM(hCT32, "SKF_GetPINInfo");
  pList->SKF_VerifyPIN = (_CP_SKF_VerifyPIN *)DLSYM(hCT32, "SKF_VerifyPIN");
  pList->SKF_UnblockPIN = (_CP_SKF_UnblockPIN *)DLSYM(hCT32, "SKF_UnblockPIN");
  pList->SKF_ClearSecureState =
      (_CP_SKF_ClearSecureState *)DLSYM(hCT32, "SKF_ClearSecureState");
  //=====================================应用管理============================================//
  pList->SKF_CreateApplication =
      (_CP_SKF_CreateApplication *)DLSYM(hCT32, "SKF_CreateApplication");
  pList->SKF_EnumApplication =
      (_CP_SKF_EnumApplication *)DLSYM(hCT32, "SKF_EnumApplication");
  pList->SKF_DeleteApplication =
      (_CP_SKF_DeleteApplication *)DLSYM(hCT32, "SKF_DeleteApplication");
  pList->SKF_OpenApplication =
      (_CP_SKF_OpenApplication *)DLSYM(hCT32, "SKF_OpenApplication");
  pList->SKF_CloseApplication =
      (_CP_SKF_CloseApplication *)DLSYM(hCT32, "SKF_CloseApplication");
  //=====================================文件管理============================================//
  pList->SKF_CreateFile = (_CP_SKF_CreateFile *)DLSYM(hCT32, "SKF_CreateFile");
  pList->SKF_DeleteFile = (_CP_SKF_DeleteFile *)DLSYM(hCT32, "SKF_DeleteFile");
  pList->SKF_EnumFiles = (_CP_SKF_EnumFiles *)DLSYM(hCT32, "SKF_EnumFiles");
  pList->SKF_GetFileInfo =
      (_CP_SKF_GetFileInfo *)DLSYM(hCT32, "SKF_GetFileInfo");
  pList->SKF_ReadFile = (_CP_SKF_ReadFile *)DLSYM(hCT32, "SKF_ReadFile");
  pList->SKF_WriteFile = (_CP_SKF_WriteFile *)DLSYM(hCT32, "SKF_WriteFile");
  //=====================================容器管理============================================//
  pList->SKF_CreateContainer =
      (_CP_SKF_CreateContainer *)DLSYM(hCT32, "SKF_CreateContainer");
  pList->SKF_DeleteContainer =
      (_CP_SKF_DeleteContainer *)DLSYM(hCT32, "SKF_DeleteContainer");
  pList->SKF_OpenContainer =
      (_CP_SKF_OpenContainer *)DLSYM(hCT32, "SKF_OpenContainer");
  pList->SKF_CloseContainer =
      (_CP_SKF_CloseContainer *)DLSYM(hCT32, "SKF_CloseContainer");
  pList->SKF_EnumContainer =
      (_CP_SKF_EnumContainer *)DLSYM(hCT32, "SKF_EnumContainer");
  pList->SKF_GetContainerType =
      (_CP_SKF_GetContainerType *)DLSYM(hCT32, "SKF_GetContainerType");
  pList->SKF_ImportCertificate =
      (_CP_SKF_ImportCertificate *)DLSYM(hCT32, "SKF_ImportCertificate");
  pList->SKF_ExportCertificate =
      (_CP_SKF_ExportCertificate *)DLSYM(hCT32, "SKF_ExportCertificate");
  //=====================================密码服务============================================//
  pList->SKF_GenRandom = (_CP_SKF_GenRandom *)DLSYM(hCT32, "SKF_GenRandom");
  pList->SKF_GenRSAKeyPair =
      (_CP_SKF_GenRSAKeyPair *)DLSYM(hCT32, "SKF_GenRSAKeyPair");
  pList->SKF_ImportRSAKeyPair =
      (_CP_SKF_ImportRSAKeyPair *)DLSYM(hCT32, "SKF_ImportRSAKeyPair");
  pList->SKF_RSASignData =
      (_CP_SKF_RSASignData *)DLSYM(hCT32, "SKF_RSASignData");
  pList->SKF_RSAVerify = (_CP_SKF_RSAVerify *)DLSYM(hCT32, "SKF_RSAVerify");
  pList->SKF_RSAExportSessionKey =
      (_CP_SKF_RSAExportSessionKey *)DLSYM(hCT32, "SKF_RSAExportSessionKey");
  pList->SKF_GenECCKeyPair =
      (_CP_SKF_GenECCKeyPair *)DLSYM(hCT32, "SKF_GenECCKeyPair");
  pList->SKF_ImportECCKeyPair =
      (_CP_SKF_ImportECCKeyPair *)DLSYM(hCT32, "SKF_ImportECCKeyPair");
  pList->SKF_ECCSignData =
      (_CP_SKF_ECCSignData *)DLSYM(hCT32, "SKF_ECCSignData");
  pList->SKF_ECCVerify = (_CP_SKF_ECCVerify *)DLSYM(hCT32, "SKF_ECCVerify");
  pList->SKF_ECCExportSessionKey =
      (_CP_SKF_ECCExportSessionKey *)DLSYM(hCT32, "SKF_ECCExportSessionKey");
  pList->SKF_ExtECCEncrypt =
      (_CP_SKF_ExtECCEncrypt *)DLSYM(hCT32, "SKF_ExtECCEncrypt");
  pList->SKF_ExtECCDecrypt =
      (_CP_SKF_ExtECCDecrypt *)DLSYM(hCT32, "SKF_ExtECCDecrypt");
  pList->SKF_ExtECCSign = (_CP_SKF_ExtECCSign *)DLSYM(hCT32, "SKF_ExtECCSign");
  pList->SKF_GenerateAgreementDataWithECC =
      (_CP_SKF_GenerateAgreementDataWithECC *)DLSYM(
          hCT32, "SKF_GenerateAgreementDataWithECC");
  pList->SKF_GenerateAgreementDataAndKeyWithECC =
      (_CP_SKF_GenerateAgreementDataAndKeyWithECC *)DLSYM(
          hCT32, "SKF_GenerateAgreementDataAndKeyWithECC");
  pList->SKF_GenerateKeyWithECC =
      (_CP_SKF_GenerateKeyWithECC *)DLSYM(hCT32, "SKF_GenerateKeyWithECC");
  pList->SKF_ExportPublicKey =
      (_CP_SKF_ExportPublicKey *)DLSYM(hCT32, "SKF_ExportPublicKey");
  pList->SKF_ImportSessionKey =
      (_CP_SKF_ImportSessionKey *)DLSYM(hCT32, "SKF_ImportSessionKey");
  pList->SKF_EncryptInit =
      (_CP_SKF_EncryptInit *)DLSYM(hCT32, "SKF_EncryptInit");
  pList->SKF_Encrypt = (_CP_SKF_Encrypt *)DLSYM(hCT32, "SKF_Encrypt");
  pList->SKF_EncryptUpdate =
      (_CP_SKF_EncryptUpdate *)DLSYM(hCT32, "SKF_EncryptUpdate");
  pList->SKF_EncryptFinal =
      (_CP_SKF_EncryptFinal *)DLSYM(hCT32, "SKF_EncryptFinal");
  pList->SKF_DecryptInit =
      (_CP_SKF_DecryptInit *)DLSYM(hCT32, "SKF_DecryptInit");
  pList->SKF_Decrypt = (_CP_SKF_Decrypt *)DLSYM(hCT32, "SKF_Decrypt");
  pList->SKF_DecryptUpdate =
      (_CP_SKF_DecryptUpdate *)DLSYM(hCT32, "SKF_DecryptUpdate");
  pList->SKF_DecryptFinal =
      (_CP_SKF_DecryptFinal *)DLSYM(hCT32, "SKF_DecryptFinal");
  pList->SKF_DigestInit = (_CP_SKF_DigestInit *)DLSYM(hCT32, "SKF_DigestInit");
  pList->SKF_Digest = (_CP_SKF_Digest *)DLSYM(hCT32, "SKF_Digest");
  pList->SKF_DigestUpdate =
      (_CP_SKF_DigestUpdate *)DLSYM(hCT32, "SKF_DigestUpdate");
  pList->SKF_DigestFinal =
      (_CP_SKF_DigestFinal *)DLSYM(hCT32, "SKF_DigestFinal");
  pList->SKF_MacInit = (_CP_SKF_MacInit *)DLSYM(hCT32, "SKF_MacInit");
  pList->SKF_Mac = (_CP_SKF_Mac *)DLSYM(hCT32, "SKF_Mac");
  pList->SKF_MacUpdate = (_CP_SKF_MacUpdate *)DLSYM(hCT32, "SKF_MacUpdate");
  pList->SKF_MacFinal = (_CP_SKF_MacFinal *)DLSYM(hCT32, "SKF_MacFinal");
  pList->SKF_CloseHandle =
      (_CP_SKF_CloseHandle *)DLSYM(hCT32, "SKF_CloseHandle");
  //=================================应用扩展接口=====================================//
  pList->SKF_SetSymmKey = (_CP_SKF_SetSymmKey *)DLSYM(hCT32, "SKF_SetSymmKey");
  pList->SKF_ImportCACertificate =
      (_CP_SKF_ImportCACertificate *)DLSYM(hCT32, "SKF_ImportCACertificate");
  pList->SKF_ExportCACertificate =
      (_CP_SKF_ExportCACertificate *)DLSYM(hCT32, "SKF_ExportCACertificate");
  pList->SKF_ImportECCKeyPair2 =
      (_CP_SKF_ImportECCKeyPair2 *)DLSYM(hCT32, "SKF_ImportECCKeyPair2");
  if (iGetProcAddressID & 0x1) {
    pList->SKF_RSADecryptA =
        (_CP_SKF_RSADecryptA *)DLSYM(hCT32, "SKF_RSADecrypt");
  } else if (iGetProcAddressID & 0x2) {
    pList->SKF_RSADecryptB =
        (_CP_SKF_RSADecryptB *)DLSYM(hCT32, "SKF_RSADecrypt");
  } else {
    pList->SKF_RSADecrypt =
        (_CP_SKF_RSADecrypt *)DLSYM(hCT32, "SKF_RSADecrypt");
  }
  if (iGetProcAddressID & 0x1) {
    pList->SKF_ECCDecryptA =
        (_CP_SKF_ECCDecryptA *)DLSYM(hCT32, "SKF_ECCDecrypt");
  } else if (iGetProcAddressID & 0x2) {
    pList->SKF_ECCDecryptB =
        (_CP_SKF_ECCDecryptB *)DLSYM(hCT32, "SKF_ECCDecrypt");
  } else {
    pList->SKF_ECCDecrypt =
        (_CP_SKF_ECCDecrypt *)DLSYM(hCT32, "SKF_ECCDecrypt");
  }
  //=================================电子印章扩展接口=====================================//
  pList->EPS_ImportSymmKey =
      (_CP_EPS_ImportSymmKey *)DLSYM(hCT32, "EPS_ImportSymmKey");
  pList->EPS_WriteESealData =
      (_CP_EPS_WriteESealData *)DLSYM(hCT32, "EPS_WriteESealData");
  pList->EPS_ReadESealData =
      (_CP_EPS_ReadESealData *)DLSYM(hCT32, "EPS_ReadESealData");
  pList->EPS_Encrypt = (_CP_EPS_Encrypt *)DLSYM(hCT32, "EPS_Encrypt");
  pList->EPS_Decrypt = (_CP_EPS_Decrypt *)DLSYM(hCT32, "EPS_Decrypt");
  pList->EPS_Mac = (_CP_EPS_Mac *)DLSYM(hCT32, "EPS_Mac");
  //=================================自定义扩展接口=====================================//
  pList->SLF_Initialize = (_CP_SLF_Initialize *)DLSYM(hCT32, "SLF_Initialize");
  pList->SLF_Finalize = (_CP_SLF_Finalize *)DLSYM(hCT32, "SLF_Finalize");
  pList->SLF_InitDevToken =
      (_CP_SLF_InitDevToken *)DLSYM(hCT32, "SLF_InitDevToken");
  pList->SLF_SetInitStyle =
      (_CP_SLF_SetInitStyle *)DLSYM(hCT32, "SLF_SetInitStyle");
  pList->SLF_SetLogFilePath =
      (_CP_SLF_SetLogFilePath *)DLSYM(hCT32, "SLF_SetLogFilePath");
  pList->SLF_SetSymmSFID =
      (_CP_SLF_SetSymmSFID *)DLSYM(hCT32, "SLF_SetSymmSFID");
  pList->SLF_RSASignData =
      (_CP_SLF_RSASignData *)DLSYM(hCT32, "SLF_RSASignData");
  pList->SLF_GenRSAKeyPair =
      (_CP_SLF_GenRSAKeyPair *)DLSYM(hCT32, "SLF_GenRSAKeyPair");
  pList->SLF_UpdateKeyUsage =
      (_CP_SLF_UpdateKeyUsage *)DLSYM(hCT32, "SLF_UpdateKeyUsage");
  pList->SLF_SetKeyIDAttribute =
      (_CP_SLF_SetKeyIDAttribute *)DLSYM(hCT32, "SLF_SetKeyIDAttribute");

#ifdef CLACLIENT // 2022年9月15日21:08:23 沈雪冰 add
#include "CLAKeyPlugInAPI.h"
  pList->CLASKF_GenECCKeyPair = CLASKF_GenECCKeyPair;
  pList->CLASKF_ImportECCKeyPair = CLASKF_ImportECCKeyPair;
  pList->CLASKF_ImportECCKeyPair2 = CLASKF_ImportECCKeyPair2;
  pList->CLASKF_ExportPublicKey = CLASKF_ExportPublicKey;
  pList->CLASKF_ECCSignData = CLASKF_ECCSignData;
  pList->CLASKF_ECCDecrypt = CLASKF_ECCDecrypt;

#endif
}

/* 线程锁函数 */
static void skf_lock(SKF_CTX *ctx) {
  if (!ctx)
    return;
#ifdef _WIN32
  EnterCriticalSection(&ctx->lock);
#else
  pthread_mutex_lock(&ctx->lock);
#endif
}

static void skf_unlock(SKF_CTX *ctx) {
  if (!ctx)
    return;
#ifdef _WIN32
  LeaveCriticalSection(&ctx->lock);
#else
  pthread_mutex_unlock(&ctx->lock);
#endif
}

/* SKF 上下文创建 */
static SKF_CTX *skf_ctx_new(void) {
  SKF_CTX *ctx = OPENSSL_zalloc(sizeof(SKF_CTX));
  if (!ctx) {
    SKF_ERR("skf_ctx_new: alloc failed");
    SKFerr(SKF_F_SKF_INIT, SKF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

#ifdef _WIN32
  InitializeCriticalSection(&ctx->lock);
#else
  pthread_mutex_init(&ctx->lock, NULL);
#endif

  return ctx;
}

/* SKF 上下文释放 */
static void skf_ctx_free(SKF_CTX *ctx) {
  if (!ctx)
    return;

  /* 关闭句柄 */
  if (ctx->hContainer && ctx->skfList.SKF_CloseContainer) {
    ctx->skfList.SKF_CloseContainer(ctx->hContainer);
  }
  if (ctx->hApplication && ctx->skfList.SKF_CloseApplication) {
    ctx->skfList.SKF_CloseApplication(ctx->hApplication);
  }
  if (ctx->hDev && ctx->skfList.SKF_DisConnectDev) {
    ctx->skfList.SKF_DisConnectDev(ctx->hDev);
  }

  /* 卸载动态库 */
  if (ctx->dll_handle) {
    DLCLOSE((HMODULE)ctx->dll_handle);
  }

  /* 释放字符串 */
  OPENSSL_free(ctx->module_path);
  OPENSSL_free(ctx->device_name);
  OPENSSL_free(ctx->app_name);
  OPENSSL_free(ctx->container_name);
  OPENSSL_free(ctx->user_pin);
  OPENSSL_free(ctx->admin_pin);

#ifdef _WIN32
  DeleteCriticalSection(&ctx->lock);
#else
  pthread_mutex_destroy(&ctx->lock);
#endif

  OPENSSL_free(ctx);
}

/* SKF 上下文管理函数 */
static SKF_CTX *skf_get_ctx(ENGINE *e) {
  if (skf_engine_idx == -1) {
    SKF_ERR("skf_get_ctx: engine index not initialized");
    SKFerr(SKF_F_SKF_INIT, SKF_R_LIBRARY_NOT_INITIALIZED);
    SKF_ERR("load_privkey: RSA KEY blob too short");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_PUBLIC_KEY_NOT_FOUND);
    return NULL;
  }
  return ENGINE_get_ex_data(e, skf_engine_idx);
}

static int skf_set_ctx(ENGINE *e, SKF_CTX *ctx) {
  if (skf_engine_idx == -1) {
    SKF_ERR("skf_set_ctx: engine index not initialized");
    SKFerr(SKF_F_SKF_INIT, SKF_R_LIBRARY_NOT_INITIALIZED);
    return 0;
  }
  return ENGINE_set_ex_data(e, skf_engine_idx, ctx);
}

/* 加载 SKF 动态库 */
static int skf_load_library(SKF_CTX *ctx) {
  if (!ctx || !ctx->module_path) {
    SKF_ERR("skf_load_library: module path not set");
    SKFerr(SKF_F_SKF_LOAD_LIBRARY, SKF_R_MODULE_PATH_REQUIRED);
    return 0;
  }

  if (ctx->dll_handle)
    return 1; /* 已经加载 */

  ctx->dll_handle = DLOPEN(ctx->module_path);

  if (!ctx->dll_handle) {
    SKF_ERR("skf_load_library: failed to load %s", ctx->module_path);
    SKFerr(SKF_F_SKF_LOAD_LIBRARY, SKF_R_CANT_LOAD_SKF_MODULE);
    return 0;
  }

  /* 加载函数指针 */
  setFunctionList(ctx->dll_handle, &ctx->skfList, ctx->module_type);

  /* 检查必要的函数 */
  if (!ctx->skfList.SKF_EnumDev || !ctx->skfList.SKF_ConnectDev ||
      !ctx->skfList.SKF_OpenApplication) {
    SKF_ERR("skf_load_library: missing required symbols");
    SKFerr(SKF_F_SKF_LOAD_LIBRARY, SKF_R_DSO_FAILURE);
    return 0;
  }

  return 1;
}

/* 设备初始化 */
static int skf_init_device(SKF_CTX *ctx) {
  ULONG ret;

  if (!ctx || ctx->initialized)
    return 1;

  if (!ctx->module_path) {
    SKF_ERR("skf_init_device: module path required");
    SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_MODULE_PATH_REQUIRED);
    return 0;
  }

  /* 加载动态库 */
  if (!skf_load_library(ctx)) {
    SKF_ERR("skf_init_device: load library failed");
    SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_INIT_FAILED);
    return 0;
  }

  /* 连接设备 */
  if (ctx->device_name) {
    ret = ctx->skfList.SKF_ConnectDev(ctx->device_name, &ctx->hDev);
    if (ret != SAR_OK) {
      SKF_ERR("BYCSM_LoadModule failed ret=%d", ret);
      SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_INIT_FAILED);
      return 0;
    }
  } else {
    //枚举设备
    char pDevName[256] = {0};
    ULONG count = 0;
    ret = ctx->skfList.SKF_EnumDev(TRUE, pDevName, &count);
    if (ret != SAR_OK) {
      SKF_ERR("SKF_ConnectDev failed ret=%d", ret);
      SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_DEVICE_OPEN_FAILED);
      return 0;
    }
    if (count > 0 && strlen(pDevName) > 0) {
      //暂时只支持一个设备，如果有多个设备，需要用户选择
      ret = ctx->skfList.SKF_ConnectDev(pDevName, &ctx->hDev);
      if (ret != SAR_OK) {
        SKF_ERR("SKF_OpenApplication failed ret=%d", ret);
        SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_APPLICATION_OPEN_FAILED);
        return 0;
      }
    } else {
      SKF_ERR("device not found");
      SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_DEVICE_NOT_FOUND);
      return 0;
    }
  }

  /* 打开应用 - 当前版本要求必须配置应用名 */
  if (ctx->app_name && ctx->hDev) {
    ret = ctx->skfList.SKF_OpenApplication(ctx->hDev, ctx->app_name,
                                           &ctx->hApplication);
    if (ret != SAR_OK) {
      SKF_ERR("SKF_EnumDev failed ret=%d", ret);
      SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_ENUMERATION_FAILED);
      return ret;
    }
  } else if (!ctx->app_name) {
    /* TODO: 后续版本应该枚举所有应用让用户选择，当前版本要求必须配置应用名 */
    SKF_ERR("application name required");
    SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_APPLICATION_NAME_REQUIRED);
    return 0;
  }

  /* 验证容器名是否配置 - 当前版本要求必须配置容器名 */
  if (!ctx->container_name) {
    /* TODO: 后续版本应该枚举所有容器让用户选择，当前版本要求必须配置容器名 */
    SKF_ERR("container name required");
    SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_CONTAINER_NAME_REQUIRED);
    return 0;
  }

  /* 验证 PIN */
  if (ctx->user_pin && ctx->hApplication) {
    ULONG retry_count;
    ret = ctx->skfList.SKF_VerifyPIN(ctx->hApplication, 1, ctx->user_pin,
                                     &retry_count);
    if (ret != SAR_OK) {
      SKF_ERR("SKF_VerifyPIN failed ret=%d", ret);
      SKFerr(SKF_F_SKF_INIT_DEVICE, SKF_R_AUTHENTICATION_FAILED);
      /* 继续执行，某些操作可能不需要认证 */
    } else {
      ctx->logged_in = 1;
    }
  }

  ctx->initialized = 1;
  return 1;
}

/* ENGINE 控制函数 */
static int skf_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {
  SKF_CTX *ctx = skf_get_ctx(e);

  if (!ctx) {
    ctx = skf_ctx_new();
    if (!ctx) {
      SKF_ERR("ctrl: allocate SKF_CTX failed");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    if (!skf_set_ctx(e, ctx)) {
      skf_ctx_free(ctx);
      SKF_ERR("ctrl: set ex_data failed");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }

  switch (cmd) {
  case SKF_CMD_MODULE_PATH:
    if (!p) {
      SKF_ERR("ctrl MODULE_PATH: null pointer");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->module_path);
    ctx->module_path = OPENSSL_strdup((char *)p);
    return ctx->module_path ? 1 : 0;
  case SKF_CMD_MODULE_TYPE:
    ctx->module_type = (unsigned int)i;
    return 1;
  case SKF_CMD_DEVICE_NAME:
    if (!p) {
      SKF_ERR("ctrl DEVICE_NAME: null pointer");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->device_name);
    ctx->device_name = OPENSSL_strdup((char *)p);
    return ctx->device_name ? 1 : 0;

  case SKF_CMD_APP_NAME:
    if (!p) {
      SKF_ERR("ctrl APP_NAME: null pointer");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->app_name);
    ctx->app_name = OPENSSL_strdup((char *)p);
    return ctx->app_name ? 1 : 0;

  case SKF_CMD_CONTAINER_NAME:
    if (!p) {
      SKF_ERR("ctrl CONTAINER_NAME: null pointer");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->container_name);
    ctx->container_name = OPENSSL_strdup((char *)p);
    return ctx->container_name ? 1 : 0;

  case SKF_CMD_USER_PIN:
    if (!p) {
      SKF_ERR("ctrl USER_PIN: null pointer");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->user_pin);
    ctx->user_pin = OPENSSL_strdup((char *)p);
    return ctx->user_pin ? 1 : 0;

  case SKF_CMD_ADMIN_PIN:
    if (!p) {
      SKF_ERR("ctrl ADMIN_PIN: null pointer");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    OPENSSL_free(ctx->admin_pin);
    ctx->admin_pin = OPENSSL_strdup((char *)p);
    return ctx->admin_pin ? 1 : 0;

  case SKF_CMD_ENUM_DEVICES: {
    char *device_list = NULL;
    int ret = skf_enum_devices(ctx, &device_list);
    if (ret && device_list) {
      printf("可用的 SKF 设备:\n");
      skf_print_device_list(device_list);
      OPENSSL_free(device_list);
    }
    return ret;
  }

  case SKF_CMD_ENUM_APPS: {
    char *app_list = NULL;
    int ret = skf_enum_applications(ctx, &app_list);
    if (ret && app_list) {
      printf("可用的 SKF 应用:\n");
      skf_print_app_list(app_list);
      OPENSSL_free(app_list);
    }
    return ret;
  }

  case SKF_CMD_ENUM_CONTAINERS: {
    char *container_list = NULL;
    int ret = skf_enum_containers(ctx, &container_list);
    if (ret && container_list) {
      printf("可用的 SKF 容器:\n");
      skf_print_container_list(container_list);
      OPENSSL_free(container_list);
    }
    return ret;
  }

  case SKF_CMD_HELP: {
    // 打印所有可用的控制命令
    if (!p) {
      SKF_ERR("ctrl HELP: buffer pointer null");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    offset += snprintf(buffer + offset, 2048 - offset,
                       "Available SKF Engine Control Commands:\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "MODULE_PATH: Set SKF library path\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "DEVICE_NAME: Set device name\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "APP_NAME: Set application name\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "CONTAINER_NAME: Set container name\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "USER_PIN: Set user PIN\n");
    offset +=
        snprintf(buffer + offset, 2048 - offset, "ADMIN_PIN: Set admin PIN\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "ENUM_DEVICES: Enumerate SKF devices\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "ENUM_APPS: Enumerate SKF applications\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "ENUM_CONTAINERS: Enumerate SKF containers\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "FEATURE_MASK: Set feature mask (hex)\n");
    offset += snprintf(buffer + offset, 2048 - offset,
                       "MODE_PRESET: Set preset mode\n");
    return 1;
  }

    /* 位掩码功能控制命令 */
  case SKF_CMD_SET_FEATURE_MASK: {
    if (!p) {
      SKF_ERR("ctrl SET_FEATURE_MASK: mask string null");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
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
    if (!skf_validate_mask(new_mask)) {
      SKF_ERR("Invalid feature mask: 0x%04X", new_mask);
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }

    skf_global_feature_mask = new_mask;

    printf("SKF Feature mask set to: 0x%04X\n", new_mask);
    printf("  SSL Keys: %s\n",
           (new_mask & ENGINE_FEATURE_SSL_KEYS) ? "ON" : "OFF");
    printf("  Basic Mgmt: %s\n",
           (new_mask & ENGINE_FEATURE_BASIC_MGMT) ? "ON" : "OFF");
    printf("  SSL Extensions (GM SSL): %s\n",
           (new_mask & ENGINE_FEATURE_SSL_EXTENSIONS) ? "ON" : "OFF");
    printf("  RSA: %s\n", (new_mask & ENGINE_FEATURE_RSA) ? "ON" : "OFF");
    printf("  EC: %s\n", (new_mask & ENGINE_FEATURE_EC) ? "ON" : "OFF");
    printf("  RAND: %s\n", (new_mask & ENGINE_FEATURE_RAND) ? "ON" : "OFF");
    printf("  PKEY Methods: %s\n",
           (new_mask & ENGINE_FEATURE_PKEY_METHS) ? "ON" : "OFF");

    if (new_mask & ENGINE_FEATURE_RAND) {
      printf("  WARNING: RAND takeover enabled! May cause static linking "
             "issues.\n");
    }

    /* 重新绑定引擎功能 */
    return skf_rebind_features(e);
  }

  case SKF_CMD_GET_FEATURE_MASK: {
    if (!p) {
      SKF_ERR("ctrl GET_FEATURE_MASK: buffer pointer null");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    offset +=
        snprintf(buffer + offset, 1024 - offset,
                 "Current SKF Feature Mask: 0x%04X\n", skf_global_feature_mask);
    offset += snprintf(
        buffer + offset, 1024 - offset, "  SSL Keys (0x0001): %s\n",
        (skf_global_feature_mask & ENGINE_FEATURE_SSL_KEYS) ? "ON" : "OFF");
    offset += snprintf(
        buffer + offset, 1024 - offset, "  Basic Mgmt (0x0002): %s\n",
        (skf_global_feature_mask & ENGINE_FEATURE_BASIC_MGMT) ? "ON" : "OFF");
    offset +=
        snprintf(buffer + offset, 1024 - offset, "  RSA (0x0010): %s\n",
                 (skf_global_feature_mask & ENGINE_FEATURE_RSA) ? "ON" : "OFF");
    offset +=
        snprintf(buffer + offset, 1024 - offset, "  EC (0x0040): %s\n",
                 (skf_global_feature_mask & ENGINE_FEATURE_EC) ? "ON" : "OFF");
    offset += snprintf(buffer + offset, 1024 - offset, "  RAND (0x0100): %s\n",
                       (skf_global_feature_mask & ENGINE_FEATURE_RAND) ? "ON"
                                                                       : "OFF");
    offset += snprintf(
        buffer + offset, 1024 - offset, "  PKEY Methods (0x1000): %s\n",
        (skf_global_feature_mask & ENGINE_FEATURE_PKEY_METHS) ? "ON" : "OFF");
    return 1;
  }

  case SKF_CMD_SET_MODE_PRESET: {
    if (!p) {
      SKF_ERR("ctrl SET_MODE_PRESET: mode string null");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    char *mode_str = (char *)p;

    if (strcmp(mode_str, "ssl_only") == 0) {
      skf_global_feature_mask = ENGINE_MODE_SSL_ONLY;
      printf("Mode set to: SSL Only (0x%04X) - Recommended for Nginx\n",
             ENGINE_MODE_SSL_ONLY);
    } else if (strcmp(mode_str, "ssl_hw_sign") == 0) {
      skf_global_feature_mask = ENGINE_MODE_SSL_HW_SIGN;
      printf("Mode set to: SSL + HW Sign (0x%04X) - SSL + Hardware signing\n",
             ENGINE_MODE_SSL_HW_SIGN);
    } else if (strcmp(mode_str, "full_hw") == 0) {
      skf_global_feature_mask = ENGINE_MODE_FULL_HARDWARE;
      printf("Mode set to: Full Hardware (0x%04X) - Complete hardware "
             "acceleration\n",
             ENGINE_MODE_FULL_HARDWARE);
    } else if (strcmp(mode_str, "dangerous") == 0) {
      skf_global_feature_mask = ENGINE_MODE_DANGEROUS;
      printf("Mode set to: Dangerous (0x%04X) - WARNING: Includes RAND "
             "takeover!\n",
             ENGINE_MODE_DANGEROUS);
    } else if (strcmp(mode_str, "all_features") == 0) {
      skf_global_feature_mask = ENGINE_MODE_ALL_FEATURES;
      printf("Mode set to: All Features (0x%04X) - Maximum functionality\n",
             ENGINE_MODE_ALL_FEATURES);
    } else if (strcmp(mode_str, "gm_ssl_full") == 0) {
      skf_global_feature_mask = ENGINE_MODE_GM_SSL_FULL;
      printf("Mode set to: GM SSL Full (0x%04X) - Complete GM SSL support\n",
             ENGINE_MODE_GM_SSL_FULL);
    } else if (strcmp(mode_str, "gm_ssl_hw") == 0) {
      skf_global_feature_mask = ENGINE_MODE_GM_SSL_HW;
      printf("Mode set to: GM SSL Hardware (0x%04X) - GM SSL with hardware "
             "acceleration\n",
             ENGINE_MODE_GM_SSL_HW);
    } else {
      SKF_ERR("Invalid mode. Available: ssl_only, ssl_hw_sign, full_hw, "
              "dangerous, all_features, gm_ssl_full, gm_ssl_hw");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_UNKNOWN_COMMAND);
      return 0;
    }

    /* 重新绑定引擎功能 */
    return skf_rebind_features(e);
  }

  case SKF_CMD_LIST_FEATURES: {
    if (!p) {
      SKF_ERR("ctrl LIST_FEATURES: buffer pointer null");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    char *buffer = (char *)p;
    int offset = 0;

    offset += snprintf(buffer + offset, 2048 - offset,
                       "Available SKF Engine Features:\n");
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

  case SKF_CMD_VALIDATE_MASK: {
    if (!p) {
      SKF_ERR("ctrl VALIDATE_MASK: mask string null");
      SKFerr(SKF_F_SKF_CTRL, SKF_R_INVALID_PARAMETER);
      return 0;
    }
    char *mask_str = (char *)p;

    unsigned int mask = 0;
    if (strncmp(mask_str, "0x", 2) == 0 || strncmp(mask_str, "0X", 2) == 0) {
      mask = (unsigned int)strtoul(mask_str, NULL, 16);
    } else {
      mask = (unsigned int)strtoul(mask_str, NULL, 10);
    }

    int valid = skf_validate_mask(mask);
    printf("Feature mask 0x%04X validation: %s\n", mask,
           valid ? "VALID" : "INVALID");
    return valid;
  }

  default:
    SKFerr(SKF_F_SKF_CTRL, SKF_R_UNKNOWN_COMMAND);
    return 0;
  }
}

/* 枚举设备函数 */
static int skf_enum_devices(SKF_CTX *ctx, char **device_list) {
  char dev_list[4096] = {0};
  ULONG dev_list_len = sizeof(dev_list);
  ULONG ret;

  if (!ctx || !device_list) {
    SKF_ERR("enum devices: invalid parameter");
    SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_INVALID_PARAMETER);
    return 0;
  }

  *device_list = NULL;

  /* 确保库已加载 */
  if (!ctx->dll_handle && !skf_load_library(ctx)) {
    SKF_ERR("enum devices: load library failed");
    SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_CANT_LOAD_SKF_MODULE);
    return 0;
  }

  if (!ctx->skfList.SKF_EnumDev) {
    SKF_ERR("enum devices: missing SKF_EnumDev symbol");
    SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_DSO_FAILURE);
    return 0;
  }

  /* 枚举设备 */
  ret = ctx->skfList.SKF_EnumDev(1, dev_list, &dev_list_len);
  if (ret != SAR_OK) {
    if (ret == SAR_BUFFER_TOO_SMALL) {
      /* 缓冲区太小，尝试更大的缓冲区 */
      char *large_buf = OPENSSL_malloc(dev_list_len);
      if (!large_buf) {
        SKF_ERR("enum devices: allocate large buffer failed");
        SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
      ret = ctx->skfList.SKF_EnumDev(1, large_buf, &dev_list_len);
      if (ret == SAR_OK) {
        *device_list = large_buf;
        return 1;
      }
      OPENSSL_free(large_buf);
    }
    SKF_ERR("enum devices: enumeration failed");
    SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_ENUMERATION_FAILED);
    return 0;
  }

  if (dev_list_len > 0) {
    *device_list = OPENSSL_malloc(dev_list_len);
    if (!*device_list) {
      SKF_ERR("enum devices: allocate output buffer failed");
      SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    memcpy(*device_list, dev_list, dev_list_len);
    return 1;
  }

  SKF_ERR("enum devices: no devices found");
  SKFerr(SKF_F_SKF_ENUM_DEVICES, SKF_R_NO_DEVICES_FOUND);
  return 0;
}

/* 枚举应用函数 */
static int skf_enum_applications(SKF_CTX *ctx, char **app_list) {
  char apps[4096] = {0};
  ULONG apps_len = sizeof(apps);
  ULONG ret;

  if (!ctx || !app_list) {
    SKF_ERR("enum apps: invalid parameter");
    SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_INVALID_PARAMETER);
    return 0;
  }

  *app_list = NULL;

  /* 确保设备已连接 */
  if (!ctx->hDev) {
    if (!skf_init_device(ctx)) {
      SKF_ERR("enum apps: init device failed");
      SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_DEVICE_OPEN_FAILED);
      return 0;
    }
  }

  if (!ctx->skfList.SKF_EnumApplication) {
    SKF_ERR("enum apps: missing SKF_EnumApplication symbol");
    SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_DSO_FAILURE);
    return 0;
  }

  /* 枚举应用 */
  ret = ctx->skfList.SKF_EnumApplication(ctx->hDev, apps, &apps_len);
  if (ret != SAR_OK) {
    if (ret == SAR_BUFFER_TOO_SMALL) {
      /* 缓冲区太小，尝试更大的缓冲区 */
      char *large_buf = OPENSSL_malloc(apps_len);
      if (!large_buf) {
        SKF_ERR("enum apps: allocate large buffer failed");
        SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
      ret = ctx->skfList.SKF_EnumApplication(ctx->hDev, large_buf, &apps_len);
      if (ret == SAR_OK) {
        *app_list = large_buf;
        return 1;
      }
      OPENSSL_free(large_buf);
    }
    SKF_ERR("enum apps: enumeration failed");
    SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_ENUMERATION_FAILED);
    return 0;
  }

  if (apps_len > 0) {
    *app_list = OPENSSL_malloc(apps_len);
    if (!*app_list) {
      SKF_ERR("enum apps: allocate output buffer failed");
      SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    memcpy(*app_list, apps, apps_len);
    return 1;
  }

  SKF_ERR("enum apps: no applications found");
  SKFerr(SKF_F_SKF_ENUM_APPLICATIONS, SKF_R_NO_APPLICATIONS_FOUND);
  return 0;
}

/* 枚举容器函数 */
static int skf_enum_containers(SKF_CTX *ctx, char **container_list) {
  char containers[4096] = {0};
  ULONG containers_len = sizeof(containers);
  ULONG ret;

  if (!ctx || !container_list) {
    SKF_ERR("enum containers: invalid parameter");
    SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_INVALID_PARAMETER);
    return 0;
  }

  *container_list = NULL;

  /* 确保应用已打开 */
  if (!ctx->hApplication) {
    if (!skf_init_device(ctx)) {
      SKF_ERR("enum containers: init device failed");
      SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_APPLICATION_OPEN_FAILED);
      return 0;
    }
  }

  if (!ctx->skfList.SKF_EnumContainer) {
    SKF_ERR("enum containers: missing SKF_EnumContainer symbol");
    SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_DSO_FAILURE);
    return 0;
  }

  /* 枚举容器 */
  ret = ctx->skfList.SKF_EnumContainer(ctx->hApplication, containers,
                                       &containers_len);
  if (ret != SAR_OK) {
    if (ret == SAR_BUFFER_TOO_SMALL) {
      /* 缓冲区太小，尝试更大的缓冲区 */
      char *large_buf = OPENSSL_malloc(containers_len);
      if (!large_buf) {
        SKF_ERR("enum containers: allocate large buffer failed");
        SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
      ret = ctx->skfList.SKF_EnumContainer(ctx->hApplication, large_buf,
                                           &containers_len);
      if (ret == SAR_OK) {
        *container_list = large_buf;
        return 1;
      }
      OPENSSL_free(large_buf);
    }
    SKF_ERR("enum containers: enumeration failed");
    SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_ENUMERATION_FAILED);
    return 0;
  }

  if (containers_len > 0) {
    *container_list = OPENSSL_malloc(containers_len);
    if (!*container_list) {
      SKF_ERR("enum containers: allocate output buffer failed");
      SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    memcpy(*container_list, containers, containers_len);
    return 1;
  }

  SKF_ERR("enum containers: no containers found");
  SKFerr(SKF_F_SKF_ENUM_CONTAINERS, SKF_R_NO_CONTAINERS_FOUND);
  return 0;
}

/* 打印设备列表 */
static void skf_print_device_list(const char *device_list) {
  const char *p = device_list;
  int index = 1;

  if (!device_list)
    return;

  while (*p) {
    printf("  %d. %s\n", index++, p);
    p += strlen(p) + 1;
  }

  if (index == 1) {
    printf("  (未找到设备)\n");
  }
}

/* 打印应用列表 */
static void skf_print_app_list(const char *app_list) {
  const char *p = app_list;
  int index = 1;

  if (!app_list)
    return;

  while (*p) {
    printf("  %d. %s\n", index++, p);
    p += strlen(p) + 1;
  }

  if (index == 1) {
    printf("  (未找到应用)\n");
  }
}

/* 打印容器列表 */
static void skf_print_container_list(const char *container_list) {
  const char *p = container_list;
  int index = 1;

  if (!container_list)
    return;

  while (*p) {
    printf("  %d. %s\n", index++, p);
    p += strlen(p) + 1;
  }

  if (index == 1) {
    printf("  (未找到容器)\n");
  }
}

/* RSA 签名函数 */
static int skf_rsa_sign(int type, const unsigned char *m, unsigned int m_len,
                        unsigned char *sigret, unsigned int *siglen,
                        const RSA *rsa) {
  SKF_KEY_CTX *key_ctx;
  SKF_CTX *ctx;
  ULONG output_len = *siglen;
  int ret;

  key_ctx = RSA_get_ex_data(rsa, 0);
  if (!key_ctx || !key_ctx->skf_ctx) {
    SKF_ERR("rsa sign: key ctx missing");
    SKFerr(SKF_F_SKF_RSA_SIGN, SKF_R_KEY_NOT_FOUND);
    return 0;
  }

  ctx = key_ctx->skf_ctx;

  if (!ctx->initialized) {
    if (!skf_init_device(ctx)) {
      return 0;
    }
  }

  skf_lock(ctx);

  /* 调用 SKF RSA 签名 */
  ret = ctx->skfList.SKF_RSASignData(key_ctx->hContainer, (unsigned char *)m,
                                     m_len, sigret, &output_len);

  skf_unlock(ctx);

  if (ret != SAR_OK) {
    SKF_ERR("rsa sign: device operation failed ret=%d", ret);
    SKFerr(SKF_F_SKF_RSA_SIGN, SKF_R_REQUEST_FAILED);
    return 0;
  }
  if (ret != SAR_OK) {
    SKF_ERR("rsa priv dec: device operation failed ret=%d", ret);
    SKFerr(SKF_F_SKF_RSA_PRIV_DEC, SKF_R_REQUEST_FAILED);
    return 0;
  }

  *siglen = output_len;
  return 1;
}

/* RSA 私钥解密函数 */
static int skf_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding) {
  SKF_KEY_CTX *key_ctx;
  SKF_CTX *ctx;
  ULONG output_len = RSA_size(rsa);
  int ret;

  key_ctx = RSA_get_ex_data(rsa, 0);
  if (!key_ctx || !key_ctx->skf_ctx) {
    SKF_ERR("rsa priv dec: key ctx missing");
    SKFerr(SKF_F_SKF_RSA_PRIV_DEC, SKF_R_KEY_NOT_FOUND);
    return 0;
  }

  ctx = key_ctx->skf_ctx;

  if (!ctx->initialized) {
    if (!skf_init_device(ctx)) {
      SKF_ERR("rsa priv dec: device init failed");
      SKFerr(SKF_F_SKF_RSA_PRIV_DEC, SKF_R_INIT_FAILED);
      return 0;
    }
  }

  skf_lock(ctx);

  /* 调用 SKF RSA 私钥运算 */
  ret = ctx->skfList.SKF_RSADecrypt(key_ctx->hContainer, (unsigned char *)from,
                                    flen, to, &output_len);

  skf_unlock(ctx);

  if (ret != SAR_OK) {
    SKF_ERR("rsa priv dec: device operation failed ret=%d", ret);
    SKFerr(SKF_F_SKF_RSA_PRIV_DEC, SKF_R_REQUEST_FAILED);
    return 0;
  }

  return (int)output_len;
}

/* RSA 方法表 */
static RSA_METHOD *skf_rsa_method = NULL;

static RSA_METHOD *get_skf_rsa_method(void) {
  if (skf_rsa_method)
    return skf_rsa_method;

  skf_rsa_method = RSA_meth_new("SKF RSA method", 0);
  if (!skf_rsa_method) {
    SKF_ERR("get_skf_rsa_method: alloc failed");
    SKFerr(SKF_F_SKF_RSA_SIGN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  RSA_meth_set_sign(skf_rsa_method, skf_rsa_sign);
  RSA_meth_set_priv_dec(skf_rsa_method, skf_rsa_priv_dec);

  return skf_rsa_method;
}

/* ECC/SM2 签名函数 */
static int skf_ecdsa_sign(int type, const unsigned char *dgst, int dgst_len,
                          unsigned char *sig, unsigned int *siglen,
                          const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey) {
  SKF_KEY_CTX *key_ctx;
  SKF_CTX *ctx;
  ECCSIGNATUREBLOB ecc_sig;
  ULONG sig_len = sizeof(ecc_sig);
  int ret;

  key_ctx = EC_KEY_get_ex_data(eckey, 0);
  if (!key_ctx || !key_ctx->skf_ctx) {
    SKF_ERR("ecdsa sign: key ctx missing");
    SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_KEY_NOT_FOUND);
    return 0;
  }

  ctx = key_ctx->skf_ctx;

  if (!ctx->initialized) {
    if (!skf_init_device(ctx)) {
      SKF_ERR("ecdsa sign: device init failed");
      SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_INIT_FAILED);
      return 0;
    }
  }

  skf_lock(ctx);

  /* 调用 SKF ECC 签名 */
  ret = ctx->skfList.SKF_ECCSignData(key_ctx->hContainer, (unsigned char *)dgst,
                                     dgst_len, &ecc_sig);

  skf_unlock(ctx);

  if (ret != SAR_OK) {
    SKF_ERR("ecdsa sign: device operation failed ret=%d", ret);
    SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_REQUEST_FAILED);
    return 0;
  }

  /* 转换签名格式为 DER */
  ECDSA_SIG *ecdsa_sig = ECDSA_SIG_new();
  if (!ecdsa_sig) {
    SKF_ERR("ecdsa sign: alloc ECDSA_SIG failed");
    SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  BIGNUM *bn_r =
      BN_bin2bn(ecc_sig.r + 32, ECC_MAX_XCOORDINATE_BITS_LEN / 8, NULL);
  BIGNUM *bn_s =
      BN_bin2bn(ecc_sig.s + 32, ECC_MAX_XCOORDINATE_BITS_LEN / 8, NULL);

  if (!bn_r || !bn_s) {
    BN_free(bn_r);
    BN_free(bn_s);
    ECDSA_SIG_free(ecdsa_sig);
    SKF_ERR("ecdsa sign: BN conversion failed");
    SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s);

  unsigned char *der_sig = sig;
  int der_len = i2d_ECDSA_SIG(ecdsa_sig, &der_sig);
  ECDSA_SIG_free(ecdsa_sig);

  if (der_len < 0) {
    SKF_ERR("ecdsa sign: i2d_ECDSA_SIG failed");
    SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  *siglen = der_len;
  return 1;
}

/* ECC 方法表 */
static EC_KEY_METHOD *skf_ec_method = NULL;

static EC_KEY_METHOD *get_skf_ec_method(void) {
  if (skf_ec_method)
    return skf_ec_method;

  skf_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
  if (!skf_ec_method) {
    SKF_ERR("get_skf_ec_method: alloc failed");
    SKFerr(SKF_F_SKF_ECDSA_SIGN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  EC_KEY_METHOD_set_sign(skf_ec_method, skf_ecdsa_sign, NULL, NULL);
  EC_KEY_METHOD_set_verify(skf_ec_method, NULL, NULL);

  return skf_ec_method;
}

/* 随机数生成函数 */
static int skf_rand_bytes(unsigned char *buf, int num) {
  /* 获取当前活跃的 ENGINE */
  ENGINE *e = ENGINE_get_default_RAND();
  SKF_CTX *ctx = NULL;
  int ret;

  if (e && strcmp(ENGINE_get_id(e), engine_skf_id) == 0) {
    ctx = skf_get_ctx(e);
  }

  if (!ctx || !ctx->initialized) {
    if (ctx && !skf_init_device(ctx)) {
      SKF_ERR("rand_bytes: device init failed");
      SKFerr(SKF_F_SKF_RAND_BYTES, SKF_R_INIT_FAILED);
      return 0;
    } else if (!ctx) {
      SKF_ERR("rand_bytes: no active SKF engine context");
      SKFerr(SKF_F_SKF_RAND_BYTES, SKF_R_LIBRARY_NOT_INITIALIZED);
      return 0;
    }
  }

  if (!ctx->skfList.SKF_GenRandom) {
    SKF_ERR("rand_bytes: SKF_GenRandom not available");
    SKFerr(SKF_F_SKF_RAND_BYTES, SKF_R_FUNCTION_NOT_SUPPORTED);
    return 0;
  }

  skf_lock(ctx);
  ret = ctx->skfList.SKF_GenRandom(ctx->hDev, num, buf);
  skf_unlock(ctx);

  if (ret != SAR_OK) {
    SKF_ERR("rand_bytes: generate failed ret=%d", ret);
    SKFerr(SKF_F_SKF_RAND_BYTES, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  return 1;
}

/* 随机数状态函数 */
static int skf_rand_status(void) {
  ENGINE *e = ENGINE_get_default_RAND();
  SKF_CTX *ctx = NULL;

  if (e && strcmp(ENGINE_get_id(e), engine_skf_id) == 0) {
    ctx = skf_get_ctx(e);
  }

  return ctx && ctx->initialized;
}

/* 随机数方法表 */
static RAND_METHOD skf_rand_method = {
    NULL,           /* seed */
    skf_rand_bytes, /* bytes */
    NULL,           /* cleanup */
    NULL,           /* add */
    skf_rand_bytes, /* pseudorand */
    skf_rand_status /* status */
};

/* 加载私钥 */
static EVP_PKEY *skf_load_privkey(ENGINE *e, const char *key_id,
                                  UI_METHOD *ui_method, void *callback_data) {
  SKF_CTX *ctx = skf_get_ctx(e);
  SKF_KEY_CTX *key_ctx;
  EVP_PKEY *pkey = NULL;
  RSA *rsa = NULL;
  EC_KEY *ec_key = NULL;
  void *hContainer = NULL;
  RSAPUBLICKEYBLOB rsa_pub;
  ECCPUBLICKEYBLOB ecc_pub;
  char *container_name = NULL;
  int is_sign_key = 1;
  int key_type = 0; /* 0: RSA, 1: ECC */
  int ret;

  if (!ctx || !ctx->initialized) {
    if (!ctx || !skf_init_device(ctx)) {
      SKF_ERR("load_privkey: context not initialized");
      SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_NOT_INITIALIZED);
      SKF_ERR("load_privkey: set RSA public key failed");
      SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
      return NULL;
    }
  }

  /* 解析密钥 ID */
  if (key_id) {
    container_name = OPENSSL_strdup(key_id);
    char *key_type_str = strchr(container_name, ':');
    if (key_type_str) {
      *key_type_str = '\0';
      key_type_str++;
      if (strncmp(key_type_str, "rsa", 3) == 0) {
        key_type = 0;
      } else if (strncmp(key_type_str, "sm2", 3) == 0 ||
                 strncmp(key_type_str, "ecc", 3) == 0) {
        key_type = 1;
      }

      if (strstr(key_type_str, "sign")) {
        is_sign_key = 1;
      } else if (strstr(key_type_str, "enc")) {
        is_sign_key = 0;
      }
    }
  } else {
    container_name =
        OPENSSL_strdup(ctx->container_name ? ctx->container_name : "default");
  }

  if (!container_name) {
    SKF_ERR("load_privkey: invalid parameter (container name)");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INVALID_PARAMETER);
    SKF_ERR("load_privkey: assign RSA to EVP_PKEY failed");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
    return NULL;
  }

  /* 创建密钥上下文 */
  key_ctx = OPENSSL_zalloc(sizeof(SKF_KEY_CTX));
  if (!key_ctx) {
    OPENSSL_free(container_name);
    SKF_ERR("load_privkey: allocate key ctx failed");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_MEMORY_ALLOCATION_FAILED);
    SKF_ERR("load_privkey: read container public key failed");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_PUBLIC_KEY_NOT_FOUND);
    return NULL;
  }

  key_ctx->skf_ctx = ctx;
  key_ctx->key_type = key_type;
  key_ctx->is_sign_key = is_sign_key;

  skf_lock(ctx);

  /* 打开容器 */
  ret = ctx->skfList.SKF_OpenContainer(ctx->hApplication, container_name,
                                       &hContainer);
  if (ret != SAR_OK) {
    skf_unlock(ctx);
    OPENSSL_free(key_ctx);
    OPENSSL_free(container_name);
    SKF_ERR("load_privkey: container not found");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_CONTAINER_NOT_FOUND);
    SKF_ERR("load_privkey: ECC KEY blob too short");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_PUBLIC_KEY_NOT_FOUND);
    return NULL;
  }

  key_ctx->hContainer = hContainer;

  if (key_type == 0) { /* RSA */
    /* 导出 RSA 公钥 */
    unsigned char blob_data[1024];
    ULONG blob_len = sizeof(blob_data);

    ret = ctx->skfList.SKF_ExportPublicKey(hContainer, is_sign_key, blob_data,
                                           &blob_len);
    if (ret != SAR_OK) {
      skf_unlock(ctx);
      ctx->skfList.SKF_CloseContainer(hContainer);
      OPENSSL_free(key_ctx);
      OPENSSL_free(container_name);
      SKF_ERR("load_privkey: export ECC/SM2 public key failed ret=%d", ret);
      SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_PUBLIC_KEY_NOT_FOUND);
      return NULL;
    }

    if (blob_len >= sizeof(RSAPUBLICKEYBLOB)) {
      memcpy(&rsa_pub, blob_data, sizeof(RSAPUBLICKEYBLOB));

      /* 创建 RSA 对象 */
      rsa = RSA_new();
      if (!rsa) {
        skf_unlock(ctx);
        ctx->skfList.SKF_CloseContainer(hContainer);
        OPENSSL_free(key_ctx);
        OPENSSL_free(container_name);
        SKF_ERR("load_privkey: assign EC_KEY to EVP_PKEY failed");
        SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
        return NULL;
      }

      /* 设置 RSA 公钥 */
      BIGNUM *n = BN_bin2bn(rsa_pub.Modulus, rsa_pub.BitLen / 8, NULL);
      BIGNUM *e = BN_bin2bn(rsa_pub.PublicExponent, 4, NULL);

      if (!n || !e || !RSA_set0_key(rsa, n, e, NULL)) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        skf_unlock(ctx);
        ctx->skfList.SKF_CloseContainer(hContainer);
        OPENSSL_free(key_ctx);
        OPENSSL_free(container_name);
        SKF_ERR("load_privkey: set RSA key components failed");
        SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
        return NULL;
      }

      /* 设置 RSA 方法和上下文 */
      RSA_set_method(rsa, get_skf_rsa_method());
      RSA_set_ex_data(rsa, 0, key_ctx);

      /* 创建 EVP_PKEY */
      pkey = EVP_PKEY_new();
      if (!pkey || !EVP_PKEY_assign_RSA(pkey, rsa)) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        skf_unlock(ctx);
        ctx->skfList.SKF_CloseContainer(hContainer);
        OPENSSL_free(key_ctx);
        OPENSSL_free(container_name);
        SKF_ERR("load_privkey: assign RSA to EVP_PKEY failed");
        SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
        return NULL;
      }
    }

  } else { /* ECC/SM2 */
    /* 导出 ECC 公钥 */
    unsigned char blob_data[1024];
    ULONG blob_len = sizeof(blob_data);

    ret = ctx->skfList.SKF_ExportPublicKey(hContainer, is_sign_key, blob_data,
                                           &blob_len);
    if (ret != SAR_OK) {
      skf_unlock(ctx);
      ctx->skfList.SKF_CloseContainer(hContainer);
      OPENSSL_free(key_ctx);
      OPENSSL_free(container_name);
      SKF_ERR("load_privkey: export ECC/SM2 public key failed ret=%lu", ret);
      SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_PUBLIC_KEY_NOT_FOUND);
      return NULL;
    }

    if (blob_len >= sizeof(ECCPUBLICKEYBLOB)) {
      memcpy(&ecc_pub, blob_data, sizeof(ECCPUBLICKEYBLOB));

      /* 创建 EC_KEY 对象 */
      ec_key = EC_KEY_new_by_curve_name(NID_sm2);
      if (!ec_key) {
        skf_unlock(ctx);
        ctx->skfList.SKF_CloseContainer(hContainer);
        OPENSSL_free(key_ctx);
        OPENSSL_free(container_name);
        SKF_ERR("load_privkey: create EC_KEY failed");
        SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_MEMORY_ALLOCATION_FAILED);
        return NULL;
      }

      /* 设置 ECC 公钥 */
      const EC_GROUP *group = EC_KEY_get0_group(ec_key);
      EC_POINT *pub_point = EC_POINT_new(group);
      BIGNUM *x = BN_bin2bn(ecc_pub.XCoordinate, ecc_pub.BitLen / 8, NULL);
      BIGNUM *y = BN_bin2bn(ecc_pub.YCoordinate, ecc_pub.BitLen / 8, NULL);

      if (!pub_point || !x || !y ||
          !EC_POINT_set_affine_coordinates_GFp(group, pub_point, x, y, NULL) ||
          !EC_KEY_set_public_key(ec_key, pub_point)) {
        EC_POINT_free(pub_point);
        BN_free(x);
        BN_free(y);
        EC_KEY_free(ec_key);
        skf_unlock(ctx);
        ctx->skfList.SKF_CloseContainer(hContainer);
        OPENSSL_free(key_ctx);
        OPENSSL_free(container_name);
        SKF_ERR("load_privkey: set ECC public key failed");
        SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
        return NULL;
      }

      EC_POINT_free(pub_point);
      BN_free(x);
      BN_free(y);

      /* 设置 EC 方法和上下文 */
      EC_KEY_set_method(ec_key, get_skf_ec_method());
      EC_KEY_set_ex_data(ec_key, 0, key_ctx);

      /* 创建 EVP_PKEY */
      pkey = EVP_PKEY_new();
      if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        skf_unlock(ctx);
        ctx->skfList.SKF_CloseContainer(hContainer);
        OPENSSL_free(key_ctx);
        OPENSSL_free(container_name);
        SKF_ERR("load_privkey: assign EC_KEY to EVP_PKEY failed");
        SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_INTERNAL_ERROR);
        return NULL;
      }
    }
  }

  skf_unlock(ctx);
  key_ctx->pkey = pkey;
  OPENSSL_free(container_name);
  return pkey;
}

/* 加载公钥 */
static EVP_PKEY *skf_load_pubkey(ENGINE *e, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data) {
  /* 公钥和私钥加载逻辑相同，因为我们只使用公钥部分 */
  return skf_load_privkey(e, key_id, ui_method, callback_data);
}

/* SSL 客户端证书加载函数 */
static int skf_load_ssl_client_cert(ENGINE *e, SSL *ssl,
                                    STACK_OF(X509_NAME) * ca_dn, X509 **pcert,
                                    EVP_PKEY **pkey, STACK_OF(X509) * *pother,
                                    UI_METHOD *ui_method, void *callback_data) {
  /* 这里可以实现从 SKF 设备加载客户端证书的逻辑 */
  /* 目前返回 0 表示不支持 */
  SKF_ERR("load_ssl_client_cert: not supported");
  SKFerr(SKF_F_SKF_LOAD_SSL_CLIENT_CERT, SKF_R_NOT_SUPPORTED);
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
  unsigned char *signer_zid;
  int ec_encrypt_param;
#endif
} SKF_EC_PKEY_CTX;

static int skf_pkey_ec_init(EVP_PKEY_CTX *ctx) {
  SKF_EC_PKEY_CTX *dctx;

  dctx = OPENSSL_zalloc(sizeof(*dctx));
  if (dctx == NULL)
    return 0;

  dctx->cofactor_mode = -1;
  dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
#ifndef OPENSSL_NO_SM2
  dctx->ec_scheme = NID_undef; /* 默认使用标准 ECDSA */
  dctx->signer_id = NULL;
  dctx->signer_zid = NULL;
  dctx->ec_encrypt_param = NID_undef;
#endif

  EVP_PKEY_CTX_set_data(ctx, dctx);
  return 1;
}

static int skf_pkey_ec_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src) {
  SKF_EC_PKEY_CTX *dctx, *sctx;
  if (!skf_pkey_ec_init(dst))
    return 0;
  sctx = EVP_PKEY_CTX_get_data(src);
  dctx = EVP_PKEY_CTX_get_data(dst);
  if (sctx->gen_group) {
    dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
    if (!dctx->gen_group) {
      SKF_ERR("pkey_ec_copy: alloc EC_GROUP failed");
      SKFerr(SKF_F_SKF_PKEY_EC_COPY, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }
  dctx->md = sctx->md;

  if (sctx->co_key) {
    dctx->co_key = EC_KEY_dup(sctx->co_key);
    if (!dctx->co_key) {
      SKF_ERR("pkey_ec_copy: alloc EC_KEY failed");
      SKFerr(SKF_F_SKF_PKEY_EC_COPY, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }
  dctx->kdf_type = sctx->kdf_type;
  dctx->kdf_md = sctx->kdf_md;
  dctx->kdf_outlen = sctx->kdf_outlen;
  if (sctx->kdf_ukm) {
    dctx->kdf_ukm = OPENSSL_memdup(sctx->kdf_ukm, sctx->kdf_ukmlen);
    if (!dctx->kdf_ukm) {
      SKF_ERR("pkey_ec_copy: alloc kdf_ukm failed");
      SKFerr(SKF_F_SKF_PKEY_EC_COPY, SKF_R_MEMORY_ALLOCATION_FAILED);
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
      SKF_ERR("pkey_ec_copy: alloc signer_id failed");
      SKFerr(SKF_F_SKF_PKEY_EC_COPY, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }
  dctx->signer_zid = NULL;
  dctx->ec_encrypt_param = sctx->ec_encrypt_param;
#endif
  return 1;
}

static void skf_pkey_ec_cleanup(EVP_PKEY_CTX *ctx) {
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
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

static int skf_pkey_ec_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_KEY *ec = NULL;
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  int ret = 0;
  if (dctx->gen_group == NULL) {
    SKF_ERR("pkey_ec_paramgen: gen_group is null");
    SKFerr(SKF_F_SKF_PKEY_EC_PARAMGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  ec = EC_KEY_new();
  if (ec == NULL) {
    SKF_ERR("pkey_ec_paramgen: alloc EC_KEY failed");
    SKFerr(SKF_F_SKF_PKEY_EC_PARAMGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  ret = EC_KEY_set_group(ec, dctx->gen_group);
  if (ret)
    EVP_PKEY_assign_EC_KEY(pkey, ec);
  else {
    SKF_ERR("pkey_ec_paramgen: set EC_KEY group failed");
    SKFerr(SKF_F_SKF_PKEY_EC_PARAMGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
    ret = 0;
  }
  EC_KEY_free(ec);
  return ret;
}

static int skf_pkey_ec_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  EC_KEY *ec = NULL;
  EVP_PKEY *ctx_pkey = NULL;
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

  ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  if (ctx_pkey == NULL && dctx->gen_group == NULL) {
    SKF_ERR("pkey_ec_keygen: gen_group is null");
    SKFerr(SKF_F_SKF_PKEY_EC_KEYGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  ec = EC_KEY_new();
  if (!ec) {
    SKF_ERR("pkey_ec_keygen: alloc EC_KEY failed");
    SKFerr(SKF_F_SKF_PKEY_EC_KEYGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  EVP_PKEY_assign_EC_KEY(pkey, ec);
  if (ctx_pkey) {
    /* Note: if error return, pkey is freed by parent routine */
    if (!EVP_PKEY_copy_parameters(pkey, ctx_pkey)) {
      SKF_ERR("pkey_ec_keygen: copy parameters failed");
      SKFerr(SKF_F_SKF_PKEY_EC_KEYGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    } else {
      if (!EC_KEY_set_group(ec, dctx->gen_group)) {
        SKF_ERR("pkey_ec_keygen: set EC_KEY group failed");
        SKFerr(SKF_F_SKF_PKEY_EC_KEYGEN, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
    }

    return EC_KEY_generate_key(ec);
  }
}

static int skf_pkey_ec_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
                            size_t *siglen, const unsigned char *tbs,
                            size_t tbslen) {
  int ret, type;
  unsigned int sltmp;
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

  if (!sig) {
    *siglen = ECDSA_size(ec);
    return 1;
  } else if (*siglen < (size_t)ECDSA_size(ec)) {
    SKF_ERR("pkey_ec_sign: siglen too small");
    SKFerr(SKF_F_SKF_PKEY_EC_SIGN, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  if (dctx->md)
    type = EVP_MD_type(dctx->md);
  else
    type = NID_sha1;

#ifndef OPENSSL_NO_SM2
  if (dctx->ec_scheme == NID_sm_scheme)
    ret = skf_ecdsa_sign(NID_undef, tbs, tbslen, sig, &sltmp, NULL, NULL, ec);
  else
#endif
    ret = ECDSA_sign(type, tbs, tbslen, sig, &sltmp, ec);

  if (ret <= 0) {
    SKF_ERR("pkey_ec_sign: sign failed");
    SKFerr(SKF_F_SKF_PKEY_EC_SIGN, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  *siglen = (size_t)sltmp;
  return 1;
}

static int skf_pkey_ec_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen) {
  int ret, type;
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec = EVP_PKEY_get0_EC_KEY(pkey);

  if (dctx->md)
    type = EVP_MD_type(dctx->md);
  else
    type = NID_sha1;

#ifndef OPENSSL_NO_SM2
  if (dctx->ec_scheme == NID_sm_scheme)
    ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);
  else
#endif
    ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);

  if (ret <= 0) {
    SKF_ERR("pkey_ec_verify: verify failed");
    SKFerr(SKF_F_SKF_PKEY_EC_VERIFY, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  return ret;
}

static int skf_pkey_ec_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                               size_t *outlen, const unsigned char *in,
                               size_t inlen) {
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  switch (dctx->ec_scheme) {
  case NID_sm_scheme:
    /* 这里应该调用 SKF SM2 加密函数 */
    SKF_ERR("pkey_ec_encrypt: SM2 encrypt not supported");
    SKFerr(SKF_F_SKF_PKEY_EC_ENCRYPT, SKF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  default:
    /* 标准 ECIES 加密 */
    SKF_ERR("pkey_ec_encrypt: ECIES encrypt not supported");
    SKFerr(SKF_F_SKF_PKEY_EC_ENCRYPT, SKF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  }
}

static int skf_pkey_ec_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
                               size_t *outlen, const unsigned char *in,
                               size_t inlen) {
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);

  switch (dctx->ec_scheme) {
  case NID_sm_scheme:
    /* 这里应该调用 SKF SM2 解密函数 */
    SKF_ERR("pkey_ec_decrypt: SM2 decrypt not supported");
    SKFerr(SKF_F_SKF_PKEY_EC_DECRYPT, SKF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  default:
    /* 标准 ECIES 解密 */
    SKF_ERR("pkey_ec_decrypt: ECIES decrypt not supported");
    SKFerr(SKF_F_SKF_PKEY_EC_DECRYPT, SKF_R_NOT_SUPPORTED);
    return 0; /* 暂时不支持 */
  }
}

#ifndef OPENSSL_NO_EC
static int skf_pkey_ec_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                              size_t *keylen) {
  int ret;
  size_t outlen;
  const EC_POINT *pubkey = NULL;
  EC_KEY *eckey;
  EVP_PKEY *pkey, *peerkey;
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);

  pkey = EVP_PKEY_CTX_get0_pkey(ctx);
  peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);
  if (!pkey || !peerkey) {
    SKF_ERR("pkey_ec_derive: pkey or peerkey is null");
    SKFerr(SKF_F_SKF_PKEY_EC_DERIVE, SKF_R_MEMORY_ALLOCATION_FAILED);
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
    SKF_ERR("pkey_ec_derive: derive failed");
    SKFerr(SKF_F_SKF_PKEY_EC_DERIVE, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  *keylen = ret;
  return 1;
}

static int skf_pkey_ec_kdf_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
                                  size_t *keylen) {
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  unsigned char *ktmp = NULL;
  size_t ktmplen;
  int rv = 0;
  if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE)
    return skf_pkey_ec_derive(ctx, key, keylen);
  if (!key) {
    *keylen = dctx->kdf_outlen;
    return 1;
  }
  if (*keylen != dctx->kdf_outlen) {
    SKF_ERR("pkey_ec_kdf_derive: keylen != kdf_outlen");
    SKFerr(SKF_F_SKF_PKEY_EC_KDF_DERIVE, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }

  if (!skf_pkey_ec_derive(ctx, NULL, &ktmplen)) {
    SKF_ERR("pkey_ec_kdf_derive: derive failed");
    SKFerr(SKF_F_SKF_PKEY_EC_KDF_DERIVE, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    return 0;
  }
  ktmp = OPENSSL_malloc(ktmplen);
  if (ktmp == NULL) {
    SKF_ERR("pkey_ec_kdf_derive: alloc ktmp failed");
    SKFerr(SKF_F_SKF_PKEY_EC_KDF_DERIVE, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
  if (!skf_pkey_ec_derive(ctx, ktmp, &ktmplen)) {
    SKF_ERR("pkey_ec_kdf_derive: derive failed");
    SKFerr(SKF_F_SKF_PKEY_EC_KDF_DERIVE, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    goto err;
  }
  /* Do KDF stuff */
  if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen, dctx->kdf_ukm,
                      dctx->kdf_ukmlen, dctx->kdf_md)) {
    SKF_ERR("pkey_ec_kdf_derive: KDF failed");
    SKFerr(SKF_F_SKF_PKEY_EC_KDF_DERIVE, SKF_R_SIGNATURE_VERIFICATION_FAILED);
    goto err;
  }
  rv = 1;

err:
  OPENSSL_clear_free(ktmp, ktmplen);
  return rv;
}
#endif

static int skf_pkey_ec_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  SKF_EC_PKEY_CTX *dctx = EVP_PKEY_CTX_get_data(ctx);
  EVP_PKEY *pkey;
  EC_GROUP *group;
  switch (type) {
  case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
    group = EC_GROUP_new_by_curve_name(p1);
    if (group == NULL) {
      SKF_ERR("pkey_ec_ctrl: alloc group failed");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    EC_GROUP_free(dctx->gen_group);
    dctx->gen_group = group;
    return 1;

  case EVP_PKEY_CTRL_EC_PARAM_ENC:
    if (!dctx->gen_group) {
      SKF_ERR("pkey_ec_ctrl: gen_group is null");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
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
    } else if (p1 < -1 || p1 > 1) {
      SKF_ERR("pkey_ec_ctrl: p1 is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    dctx->cofactor_mode = p1;
    if (p1 != -1) {
      EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
      const EC_GROUP *group = EC_KEY_get0_group(ec_key);
      const BIGNUM *cofactor = EC_GROUP_get0_cofactor(group);
      if (!group) {
        SKF_ERR("pkey_ec_ctrl: group is null");
        SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
      /* If cofactor is 1 cofactor mode does nothing */
      if (BN_is_one(cofactor))
        return 1;
      if (!dctx->co_key) {
        dctx->co_key = EC_KEY_dup(ec_key);
        if (!dctx->co_key) {
          SKF_ERR("pkey_ec_ctrl: alloc co_key failed");
          SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
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
      SKF_ERR("pkey_ec_ctrl: p1 is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    dctx->kdf_type = p1;
    return 1;

#ifndef OPENSSL_NO_SM2
  case SKF_PKEY_CTRL_EC_SCHEME:
    if (p1 == -2) {
      return dctx->ec_scheme;
    }
    if (p1 != NID_undef && p1 != NID_sm_scheme) {
      SKF_ERR("pkey_ec_ctrl: p1 is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    dctx->ec_scheme = p1;
    return 1;

  case SKF_PKEY_CTRL_SIGNER_ID:
    if (!p2 || !strlen((char *)p2) || strlen((char *)p2) > 255) {
      SKF_ERR("pkey_ec_ctrl: p2 is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    } else {
      char *id = NULL;
      if (!(id = OPENSSL_strdup((char *)p2))) {
        SKF_ERR("pkey_ec_ctrl: alloc id failed");
        SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
      if (dctx->signer_id)
        OPENSSL_free(dctx->signer_id);
      dctx->signer_id = id;
      if (dctx->ec_scheme == NID_sm_scheme) {
        pkey = EVP_PKEY_CTX_get0_pkey(ctx);
        EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        unsigned char zid[32];
        size_t zidlen = 32;
        /* 这里应该计算 SM2 ID 摘要，暂时跳过 */
        if (!dctx->signer_zid) {
          if (!(dctx->signer_zid = OPENSSL_malloc(zidlen))) {
            SKF_ERR("pkey_ec_ctrl: alloc zid failed");
            SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
            return 0;
          }
        }
        memcpy(dctx->signer_zid, zid, zidlen);
      }
    }
    return 1;

  case SKF_PKEY_CTRL_GET_SIGNER_ID:
    *(const char **)p2 = dctx->signer_id;
    return 1;

  case SKF_PKEY_CTRL_GET_SIGNER_ZID:
    if (dctx->ec_scheme != NID_sm_scheme) {
      *(const unsigned char **)p2 = NULL;
      SKF_ERR("pkey_ec_ctrl: p2 is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    if (!dctx->signer_zid) {
      pkey = EVP_PKEY_CTX_get0_pkey(ctx);
      EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
      unsigned char *zid;
      size_t zidlen = 32;
      if (!(zid = OPENSSL_malloc(zidlen))) {
        SKF_ERR("pkey_ec_ctrl: alloc zid failed");
        SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
        return 0;
      }
      /* 这里应该计算默认 ID 摘要，暂时跳过 */
      dctx->signer_zid = zid;
    }
    *(const unsigned char **)p2 = dctx->signer_zid;
    return 1;

  case SKF_PKEY_CTRL_EC_ENCRYPT_PARAM:
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
      return 0;
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
    SKF_ERR("pkey_ec_ctrl: p1 is invalid");
    SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }
}

static int skf_pkey_ec_ctrl_str(EVP_PKEY_CTX *ctx, const char *type,
                                const char *value) {
  if (strcmp(type, "ec_paramgen_curve") == 0) {
    int nid;
    nid = EC_curve_nist2nid(value);
    if (nid == NID_undef)
      nid = OBJ_sn2nid(value);
    if (nid == NID_undef)
      nid = OBJ_ln2nid(value);
    if (nid == NID_undef) {
      SKF_ERR("pkey_ec_ctrl: nid is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
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
      SKF_ERR("pkey_ec_ctrl: scheme is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, SKF_PKEY_CTRL_EC_SCHEME,
                             scheme, NULL);
  } else if (!strcmp(type, "signer_id")) {
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, SKF_PKEY_CTRL_SIGNER_ID, 0,
                             (void *)value);
  } else if (!strcmp(type, "ec_encrypt_param")) {
    int encrypt_param;
    if (!(encrypt_param = OBJ_txt2nid(value))) {
      SKF_ERR("pkey_ec_ctrl: encrypt_param is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1,
                             SKF_PKEY_CTRL_EC_ENCRYPT_PARAM, encrypt_param,
                             NULL);
#endif
  } else if (strcmp(type, "ec_param_enc") == 0) {
    int param_enc;
    if (strcmp(value, "explicit") == 0)
      param_enc = 0;
    else if (strcmp(value, "named_curve") == 0)
      param_enc = OPENSSL_EC_NAMED_CURVE;
    else {
      SKF_ERR("pkey_ec_ctrl: param_enc is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }

    return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
  } else if (strcmp(type, "ecdh_kdf_md") == 0) {
    const EVP_MD *md;
    if ((md = EVP_get_digestbyname(value)) == NULL) {
      SKF_ERR("pkey_ec_ctrl: md is invalid");
      SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
    return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
  } else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
    int co_mode;
    co_mode = atoi(value);
    return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
  }
  SKF_ERR("pkey_ec_ctrl: type is invalid");
  SKFerr(SKF_F_SKF_PKEY_EC_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
  return 0;
}

static EVP_PKEY_METHOD *skf_ec_pkey_meth = NULL;

static EVP_PKEY_METHOD *get_skf_ec_pkey_method(void) {
  if (skf_ec_pkey_meth)
    return skf_ec_pkey_meth;

  skf_ec_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
  if (!skf_ec_pkey_meth) {
    SKF_ERR("get_skf_ec_pkey_method: alloc failed");
    SKFerr(SKF_F_SKF_CTRL, SKF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }

  EVP_PKEY_meth_set_init(skf_ec_pkey_meth, skf_pkey_ec_init);
  EVP_PKEY_meth_set_copy(skf_ec_pkey_meth, skf_pkey_ec_copy);
  EVP_PKEY_meth_set_cleanup(skf_ec_pkey_meth, skf_pkey_ec_cleanup);
  EVP_PKEY_meth_set_paramgen(skf_ec_pkey_meth, NULL, skf_pkey_ec_paramgen);
  EVP_PKEY_meth_set_keygen(skf_ec_pkey_meth, NULL, skf_pkey_ec_keygen);
  EVP_PKEY_meth_set_sign(skf_ec_pkey_meth, NULL, skf_pkey_ec_sign);
  EVP_PKEY_meth_set_verify(skf_ec_pkey_meth, NULL, skf_pkey_ec_verify);
  EVP_PKEY_meth_set_encrypt(skf_ec_pkey_meth, NULL, skf_pkey_ec_encrypt);
  EVP_PKEY_meth_set_decrypt(skf_ec_pkey_meth, NULL, skf_pkey_ec_decrypt);
  EVP_PKEY_meth_set_derive(skf_ec_pkey_meth, NULL, skf_pkey_ec_kdf_derive);
  EVP_PKEY_meth_set_ctrl(skf_ec_pkey_meth, skf_pkey_ec_ctrl,
                         skf_pkey_ec_ctrl_str);

  return skf_ec_pkey_meth;
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
static int skf_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids,
                          int nid) {
  static int skf_pkey_nids[] = {EVP_PKEY_EC, 0};

  if (!pmeth) {
    *nids = skf_pkey_nids;
    return 1;
  }

  if (nid == EVP_PKEY_EC) {
    *pmeth = get_skf_ec_pkey_method();
    return (*pmeth != NULL) ? 1 : 0;
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
static int skf_init(ENGINE *e) {
  SKF_CTX *ctx;

  /* 初始化 ENGINE 索引 */
  if (skf_engine_idx == -1) {
    skf_engine_idx = ENGINE_get_ex_new_index(0, "SKF_CTX", NULL, NULL, NULL);
    if (skf_engine_idx == -1) {
      SKF_ERR("skf_init: alloc engine idx failed");
      SKFerr(SKF_F_SKF_INIT, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }

  ctx = skf_get_ctx(e);
  if (!ctx) {
    ctx = skf_ctx_new();
    if (!ctx)
      return 0;
    if (!skf_set_ctx(e, ctx)) {
      skf_ctx_free(ctx);
      SKF_ERR("skf_init: set ex_data failed");
      SKFerr(SKF_F_SKF_INIT, SKF_R_MEMORY_ALLOCATION_FAILED);
      return 0;
    }
  }

  /* 如果已经设置了模块路径，立即初始化设备 */
  if (ctx->module_path) {
    return skf_init_device(ctx);
  }

  return 1; /* 延迟初始化 */
}

/* ENGINE 清理 */
static int skf_finish(ENGINE *e) {
  SKF_CTX *ctx = skf_get_ctx(e);
  if (ctx) {
    skf_ctx_free(ctx);
    skf_set_ctx(e, NULL);
  }
  return 1;
}

/* ENGINE 销毁 */
static int skf_destroy(ENGINE *e) {
  if (skf_rsa_method) {
    RSA_meth_free(skf_rsa_method);
    skf_rsa_method = NULL;
  }

  if (skf_ec_method) {
    EC_KEY_METHOD_free(skf_ec_method);
    skf_ec_method = NULL;
  }

  /*if (skf_ec_pkey_meth) {
                  EVP_PKEY_meth_free(skf_ec_pkey_meth);
                  skf_ec_pkey_meth = NULL;
  }*/ //pkey_meths 框架会释放

  ERR_unload_SKF_strings();

  /* 清理 ENGINE 索引 */
  skf_engine_idx = -1;

  return 1;
}
/* SSL扩展接口实现 - 使用软件回退实现 */
#ifndef OPENSSL_NO_SM2

/* SSL主密钥生成函数 - 软件实现 */
static int skf_ssl_generate_master_secret(
    ENGINE *e, unsigned char *out, size_t outlen,
    const unsigned char *premaster, size_t premasterlen,
    const unsigned char *client_random, size_t client_randomlen,
    const unsigned char *server_random, size_t server_randomlen,
    const SSL *ssl) {
  /* 使用OpenSSL默认实现，不使用硬件加速 */
  SKF_ERR("skf_ssl_generate_master_secret: using software implementation for "
          "master secret generation");
  SKFerr(SKF_F_SKF_SSL_GENERATE_MASTER_SECRET, SKF_R_MEMORY_ALLOCATION_FAILED);
  return 0; /* 返回0让OpenSSL使用默认实现 */
}

/* TLS密钥块生成函数 - 软件实现 */
static int skf_tls1_generate_key_block(
    ENGINE *e, unsigned char *km, size_t kmlen, const unsigned char *master,
    size_t masterlen, const unsigned char *client_random,
    size_t client_randomlen, const unsigned char *server_random,
    size_t server_randomlen, const SSL *ssl) {
  /* 使用OpenSSL默认实现，不使用硬件加速 */
  SKF_ERR("skf_tls1_generate_key_block: using software implementation for "
          "key block generation");
  SKFerr(SKF_F_SKF_TLS1_GENERATE_KEY_BLOCK, SKF_R_MEMORY_ALLOCATION_FAILED);
  return 0; /* 返回0让OpenSSL使用默认实现 */
}

/* 私钥转换函数 - 硬件实现 */
static EVP_PKEY *skf_convert_privkey(ENGINE *e, const char *key_id,
                                     UI_METHOD *ui_method,
                                     void *callback_data) {
  SKF_CTX *ctx = skf_get_ctx(e);
  if (!ctx) {
    SKF_ERR("sdf_convert_privkey: ctx null");
    SKFerr(SKF_F_SKF_LOAD_PRIVKEY, SKF_R_LIBRARY_NOT_INITIALIZED);
    return NULL;
  }

  SKF_INFO(
      "skf_convert_privkey: Converting private key from hardware device: %s",
      key_id ? key_id : "default");

  /* 这里可以实现从 SKF 设备中加载私钥的逻辑 */
  /* 目前回退到标准的私钥加载函数 */
  return skf_load_privkey(e, key_id, ui_method, callback_data);
}

#endif /* OPENSSL_NO_SM2 */
/* 位掩码功能控制函数实现 */

/* 清理所有引擎绑定 */
static void skf_clear_all_bindings(ENGINE *e) {
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
static int skf_rebind_features(ENGINE *e) {
  SKF_INFO("skf_rebind_features: Rebinding SKF engine features based on "
           "mask: 0x%04X",
           skf_global_feature_mask);

  /* 清理所有功能绑定 */
  skf_clear_all_bindings(e);

  /* 基础管理功能 (总是绑定，确保引擎正常工作) */
  if (skf_global_feature_mask & ENGINE_FEATURE_BASIC_MGMT) {
    /* 这些在bind_skf中已经设置，无需重复绑定 */
    SKF_INFO("  Basic management: ENABLED");
  }

  /* SSL密钥加载功能 */
  if (skf_global_feature_mask & ENGINE_FEATURE_SSL_KEYS) {
    ENGINE_set_load_privkey_function(e, skf_load_privkey);
    ENGINE_set_load_pubkey_function(e, skf_load_pubkey);
    ENGINE_set_load_ssl_client_cert_function(e, skf_load_ssl_client_cert);
    SKF_INFO("  SSL key loading: ENABLED");
  }

  /* RSA算法功能 */
  if (skf_global_feature_mask & ENGINE_FEATURE_RSA) {
    /* RSA方法需要先初始化 */
    /* ENGINE_set_RSA(e, skf_rsa_method); */
    SKF_INFO("  RSA methods: ENABLED (TODO: implement skf_rsa_method)");
  }

  /* EC/ECDSA算法功能 */
  if (skf_global_feature_mask & ENGINE_FEATURE_EC) {
    /* EC方法需要先初始化 */
    /* ENGINE_set_EC(e, skf_ec_method); */
    SKF_INFO("  EC methods: ENABLED (TODO: implement skf_ec_method)");
  }

  /* 随机数生成功能 (危险) */
  if (skf_global_feature_mask & ENGINE_FEATURE_RAND) {
    /* ENGINE_set_RAND(e, &skf_rand_method); */
    SKF_INFO("  RAND takeover: ENABLED (WARNING: May cause static linking "
             "issues!)");
  }

  /* EVP_PKEY_METHOD功能 */
  if (skf_global_feature_mask & ENGINE_FEATURE_PKEY_METHS) {
    ENGINE_set_pkey_meths(e, skf_pkey_meths);
    SKF_INFO("  PKEY methods: ENABLED");
  }

  /* SSL扩展功能（国密SSL支持）*/
  if (skf_global_feature_mask & ENGINE_FEATURE_SSL_EXTENSIONS) {
#ifndef OPENSSL_NO_SM2
    ENGINE_set_ssl_generate_master_secret_function(
        e, skf_ssl_generate_master_secret);
    ENGINE_set_tls1_generate_key_block_function(e, skf_tls1_generate_key_block);
    ENGINE_set_convert_privkey_function(e, skf_convert_privkey);
    SKF_INFO("  SSL Extensions (GM SSL/TLS): ENABLED");
#else
    SKF_INFO("  SSL Extensions: DISABLED (SM2 not compiled)");
#endif
  }

  /* 对称加密算法功能 */
  if (skf_global_feature_mask & ENGINE_FEATURE_CIPHERS) {
    /* ENGINE_set_ciphers(e, skf_ciphers); */
    SKF_INFO("  Ciphers: ENABLED (TODO: implement skf_ciphers)");
  }

  /* 摘要算法功能 */
  if (skf_global_feature_mask & ENGINE_FEATURE_DIGESTS) {
    /* ENGINE_set_digests(e, skf_digests); */
    SKF_INFO("  Digests: ENABLED (TODO: implement skf_digests)");
  }

  return 1;
}

/* 获取当前功能掩码 */
static unsigned int skf_get_feature_mask(void) {
  return skf_global_feature_mask;
}

/* 设置功能掩码 */
static int skf_set_feature_mask(unsigned int mask) {
  if (!skf_validate_mask(mask)) {
    SKF_ERR("skf_set_feature_mask: Invalid feature mask: 0x%04X", mask);
    SKFerr(SKF_F_SKF_SET_FEATURE_MASK, SKF_R_INVALID_PARAMETER);
    return 0;
  }

  skf_global_feature_mask = mask;
  return 1;
}

/* 验证功能掩码有效性 */
static int skf_validate_mask(unsigned int mask) {
  /* 基本有效性检查 */
  if (mask == 0) {
    SKF_ERR("skf_validate_mask: Invalid feature mask: 0x%04X", mask);
    SKFerr(SKF_F_SKF_VALIDATE_MASK, SKF_R_INVALID_PARAMETER);
    return 0;
  }

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
    SKF_ERR("skf_validate_mask: Invalid bits in mask: 0x%04X",
            mask & ~valid_bits);
    SKFerr(SKF_F_SKF_VALIDATE_MASK, SKF_R_INVALID_PARAMETER);
    return 0;
  }

  /* 功能依赖检查 */
  if ((mask & ENGINE_FEATURE_SSL_KEYS) && !(mask & ENGINE_FEATURE_BASIC_MGMT)) {
    SKF_ERR("skf_validate_mask: SSL_KEYS requires BASIC_MGMT");
    SKFerr(SKF_F_SKF_VALIDATE_MASK, SKF_R_INVALID_PARAMETER);
    return 0;
  }

  /* RAND功能警告检查 */
  if (mask & ENGINE_FEATURE_RAND) {
    SKF_WARN("skf_validate_mask: WARNING: RAND feature may cause static "
             "linking issues");
  }

  return 1;
}

/* ENGINE 绑定函数 - 支持完整的位掩码功能控制 */
static int bind_skf(ENGINE *e) {
  /* 设置基本属性和标志 */
  if (!ENGINE_set_id(e, engine_skf_id) ||
      !ENGINE_set_name(e, engine_skf_name) ||
      !ENGINE_set_init_function(e, skf_init) ||
      !ENGINE_set_finish_function(e, skf_finish) ||
      !ENGINE_set_destroy_function(e, skf_destroy) ||
      !ENGINE_set_ctrl_function(e, skf_ctrl) ||
      !ENGINE_set_cmd_defns(e, skf_cmd_defns)) {
    SKF_ERR("skf_bind_skf: ENGINE_set_id, ENGINE_set_name, "
            "ENGINE_set_init_function, ENGINE_set_finish_function, "
            "ENGINE_set_destroy_function, ENGINE_set_ctrl_function, "
            "ENGINE_set_cmd_defns failed");
    SKFerr(SKF_F_BIND_SKF, SKF_R_MEMORY_ALLOCATION_FAILED);
    return 0;
  }

  /* 根据全局功能掩码动态绑定功能 */
  skf_rebind_features(e);

  /* 注册错误字符串 */
  ERR_load_SKF_strings();

  printf("SKF Engine initialized with feature mask: 0x%04X\n",
         skf_global_feature_mask);
  printf("Available control commands: FEATURE_MASK, MODE_PRESET, "
         "LIST_FEATURES, GET_FEATURE_MASK\n");

  return 1;
}

/* 动态引擎绑定 */
#ifndef OPENSSL_NO_DYNAMIC_ENGINE
static int bind_helper(ENGINE *e, const char *id) {
  if (id && (strcmp(id, engine_skf_id) != 0)) {
    SKF_ERR("skf_bind_helper: id is not engine_skf_id");
    SKFerr(SKF_F_BIND_SKF, SKF_R_INVALID_PARAMETER);
    return 0;
  }
  if (!bind_skf(e)) {
    SKF_ERR("skf_bind_helper: bind_skf failed");
    SKFerr(SKF_F_BIND_SKF, SKF_R_INTERNAL_ERROR);
    return 0;
  }
  return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
/* 静态引擎注册 */
static ENGINE *engine_skf(void) {
  ENGINE *ret = ENGINE_new();
  if (ret == NULL) {
    SKF_ERR("engine_skf: ENGINE_new failed");
    SKFerr(SKF_F_BIND_SKF, SKF_R_MEMORY_ALLOCATION_FAILED);
    return NULL;
  }
  if (!bind_skf(ret)) {
    ENGINE_free(ret);
    SKF_ERR("engine_skf: bind_skf failed");
    SKFerr(SKF_F_BIND_SKF, SKF_R_INTERNAL_ERROR);
    return NULL;
  }
  return ret;
}

void engine_load_skf_int(void) {
  /* Copied from eng_[openssl|dyn].c */
  ENGINE *toadd = engine_skf();
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

void ENGINE_load_skf(void) { engine_load_skf_int(); }
#endif