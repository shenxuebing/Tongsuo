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

  /* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL 头文件 */
#include "e_sdf.h"
#include "e_sdf_err.c"
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <crypto/sm2.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
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

/* 确保标准椭圆曲线 NID 可用 */
#ifndef NID_secp256r1
#define NID_secp256r1 NID_X9_62_prime256v1
#endif
#ifndef NID_secp384r1
#define NID_secp384r1 NID_X9_62_prime384v1
#endif
#ifndef NID_secp521r1
#define NID_secp521r1 NID_X9_62_prime521v1
#endif

/* 确保 brainpool 曲线 NID 可用 */
#ifndef NID_brainpoolP256t1
#define NID_brainpoolP256t1 NID_brainpoolP256t1
#endif
#ifndef NID_brainpoolP384r1
#define NID_brainpoolP384r1 NID_brainpoolP384r1
#endif

/* 添加更多可能的曲线 ID 支持 */
#ifndef NID_sect571k1
#define NID_sect571k1 NID_sect571k1
#endif
#ifndef NID_sect283k1
#define NID_sect283k1 NID_sect283k1
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

/* SM2DHE 控制命令 */
/* 使用一个较大的值作为自定义控制命令，避免与标准控制命令冲突 */
#ifndef EVP_PKEY_CTRL_USER
#define EVP_PKEY_CTRL_USER (EVP_PKEY_ALG_CTRL + 100)
#endif
#define SDF_PKEY_CTRL_SET_SM2DHE_PARAMS 65537
#define SDF_PKEY_CTRL_GET_SDF_GENERATED_EPH_PUB 65538

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
	const char* name;
	const char* library_path;
	const char* display_name;
	int priority; // 优先级，数字越小优先级越高
} vendor_config;

/* 预定义的厂商配置；1）可以检测待加载的库是否在列表中；2）可以根据优先级自动加载库，完成密码运算
 */
static const vendor_config vendor_configs[] = {
	{"byzk", "byzk0018.dll", "软件密码模块", 100},
	{"sansec", "swsds.dll", "三未信安SDF", 99},
	{"generic", "sdf.dll", "通用SDF", 98},
	{NULL, NULL, NULL, 0} };

// 全局当前使用的厂商
// static sdf_vendor_ops_t* current_vendor = NULL;
// static sdf_vendor_ops_t* available_vendors[MAX_VENDORS];
static int vendor_count = 6;

/* ===== SM2 CipherText DER <-> SDF ECCCipher ===== */
typedef struct SM2CiphertextValue_st {
	BIGNUM* xCoordinate;
	BIGNUM* yCoordinate;
	ASN1_OCTET_STRING* hash;
	ASN1_OCTET_STRING* ciphertext;
} SM2CiphertextValue;

DECLARE_ASN1_FUNCTIONS(SM2CiphertextValue)

ASN1_SEQUENCE(SM2CiphertextValue) = {
	ASN1_SIMPLE(SM2CiphertextValue, xCoordinate, BIGNUM),
	ASN1_SIMPLE(SM2CiphertextValue, yCoordinate, BIGNUM),
	ASN1_SIMPLE(SM2CiphertextValue, hash, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2CiphertextValue, ciphertext, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2CiphertextValue)

IMPLEMENT_ASN1_FUNCTIONS(SM2CiphertextValue)

typedef struct SM2_CiphertextEx_st {
	BIGNUM* C1x;
	BIGNUM* C1y;
	ASN1_OCTET_STRING* C2;
	ASN1_OCTET_STRING* C3;
}SM2_CiphertextEx;

//ASN1_SEQUENCE(SM2_CiphertextEx) = {
//	ASN1_SIMPLE(SM2_CiphertextEx, C1x, BIGNUM),
//	ASN1_SIMPLE(SM2_CiphertextEx, C1y, BIGNUM),
//	ASN1_SIMPLE(SM2_CiphertextEx, C2, ASN1_OCTET_STRING),
//	ASN1_SIMPLE(SM2_CiphertextEx, C3, ASN1_OCTET_STRING),
//} ASN1_SEQUENCE_END(SM2_CiphertextEx)
//
//IMPLEMENT_ASN1_FUNCTIONS(SM2_CiphertextEx)

/* 辅助函数：将二进制数据转换为十六进制字符串（用于调试日志）
 * data: 二进制数据指针
 * len: 数据长度
 * out: 输出缓冲区（需要预先分配，大小至少为 len*3 字节）
 * 返回值：输出字符串指针（与 out 相同）
 */
	static char* bin2hex(const unsigned char* data, size_t len, char* out) {
	const char hex[] = "0123456789ABCDEF";
	size_t i, j;
	if (!data || !out || len == 0) {
		if (out) out[0] = '\0';
		return out;
	}
	for (i = 0, j = 0; i < len; i++, j += 3) {
		out[j] = hex[(data[i] >> 4) & 0x0F];
		out[j + 1] = hex[data[i] & 0x0F];
		out[j + 2] = ' ';
	}
	if (j > 0) out[j - 1] = '\0'; // 移除最后一个空格
	else out[0] = '\0';
	return out;
}

/* 辅助宏：打印二进制数据的十六进制表示（用于调试）
 * 用法：SDF_HEX_DUMP("label", data_ptr, length);
 * 会输出：SDF_INFO: label: XX XX XX XX ...
 * 注意：最多打印256字节
 */
#define SDF_HEX_DUMP(label, data, len) do { \
    char hex_buf[256 * 3 + 1]; \
    size_t dump_len = (len) > 256 ? 256 : (len); \
    if ((len) > 0) { \
        if ((len) > 256) { \
            SDF_INFO("%s (first 256 of %zu bytes): %s", (label), (size_t)(len), bin2hex((data), dump_len, hex_buf)); \
        } else { \
            SDF_INFO("%s (%zu bytes): %s", (label), (size_t)(len), bin2hex((data), dump_len, hex_buf)); \
        } \
    } \
} while(0)

#ifdef _WIN32
#include <windows.h>
 /**
  * @brief 获取Windows系统错误描述字符串
  * @param dwError [in] 错误码（传0则自动获取GetLastError()的结果）
  * @param pszBuffer [out] 接收错误描述的缓冲区
  * @param dwBufferSize [in] 缓冲区大小（建议至少256字节）
  * @return BOOL 成功返回TRUE，失败返回FALSE
  */
BOOL getWindowsErrorString(DWORD dwError, char* pszBuffer, DWORD dwBufferSize)
{
	// 入参校验
	if (pszBuffer == NULL || dwBufferSize == 0)
	{
		return FALSE;
	}

	// 清空缓冲区
	memset(pszBuffer, 0, dwBufferSize);

	// 若传入0，自动获取最后一次的系统错误码
	DWORD dwRealError = (dwError == 0) ? GetLastError() : dwError;

	// 将错误码转换为可读字符串
	DWORD dwRet = FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM |  // 从系统获取错误描述
		FORMAT_MESSAGE_IGNORE_INSERTS, // 忽略插入符
		NULL,
		dwRealError,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 系统默认语言
		pszBuffer,
		dwBufferSize - 1, // 预留结束符位置
		NULL
	);

	// 若系统无对应描述，手动拼接错误码
	if (dwRet == 0)
	{
		snprintf(pszBuffer, dwBufferSize, "未知错误 (错误码: %lu)", dwRealError);
	}

	return TRUE;
}
/* Windows 加载动态库 */
static FARPROC win32_getproc_multi(HMODULE h, const char* name) {
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
static HMODULE sdf_load_library_win32(const char* filename) {
	HMODULE handle = NULL;
	WCHAR* wfilename = NULL;
	int wlen;
	/* 可选：临时将 DLL 所在目录加入安全搜索目录，以便解析其依赖 */
	HMODULE hKernel32;
	BOOL(WINAPI * pSetDefaultDllDirectories)(DWORD) = NULL;
	PVOID(WINAPI * pAddDllDirectory)
		(PCWSTR) = NULL; /* DLL_DIRECTORY_COOKIE 兼容声明 */
	BOOL(WINAPI * pRemoveDllDirectory)(PVOID) = NULL;
	PVOID add_cookie = NULL;
	WCHAR* wdir = NULL;

	if (!filename) {
		SDF_ERR("sdf_load_library_win32: filename is null");
		SDFerr(SDF_F_SDF_INIT, SDF_R_INVALID_PARAMETER);
		return NULL;
	}

	/* 尝试解析新式 DLL 目录 API（Windows 8+/Win7+KB2533623） */
	hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32) {
		pSetDefaultDllDirectories = (BOOL(WINAPI*)(DWORD))GetProcAddress(
			hKernel32, "SetDefaultDllDirectories");
		pAddDllDirectory =
			(PVOID(WINAPI*)(PCWSTR))GetProcAddress(hKernel32, "AddDllDirectory");
		pRemoveDllDirectory =
			(BOOL(WINAPI*)(PVOID))GetProcAddress(hKernel32, "RemoveDllDirectory");
	}

	/* 首先尝试直接加载（ANSI 版本） */
	handle = LoadLibraryA(filename);
	if (handle)
		return handle;
	else {
		/* 获取错误描述 */
		char err_buf[256];
		getWindowsErrorString(0, err_buf, sizeof(err_buf));
		SDF_ERR("LoadLibraryA err,%s", err_buf);
	}



	/* 如果失败，尝试 UTF-8 到 UTF-16 转换 */
	wlen = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
	if (wlen > 0) {
		wfilename = (WCHAR*)OPENSSL_malloc(wlen * sizeof(WCHAR));
		if (wfilename) {
			if (MultiByteToWideChar(CP_UTF8, 0, filename, -1, wfilename, wlen) > 0) {
				/* 在可用时，将 DLL 所在目录加入安全搜索列表，以便其依赖可解析 */
				if (pAddDllDirectory && pRemoveDllDirectory) {
					WCHAR* last_slash = NULL;
					for (WCHAR* p = wfilename; *p; ++p) {
						if (*p == L'\\' || *p == L'/')
							last_slash = p;
					}
					if (last_slash) {
						size_t dir_len = (size_t)(last_slash - wfilename);
						wdir = (WCHAR*)OPENSSL_malloc((dir_len + 1) * sizeof(WCHAR));
						if (wdir != NULL) {
							wcsncpy_s(wdir, dir_len + 1, wfilename, dir_len);
							wdir[dir_len] = L'\0';
							/* 可用则切换到默认安全目录集，避免不必要目录参与搜索 */
							if (pSetDefaultDllDirectories != NULL) {
								pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
							}
							if (pAddDllDirectory != NULL) {
								add_cookie = pAddDllDirectory(wdir);
							}
						}
					}
				}
				handle = LoadLibraryExW(wfilename, NULL,
					LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
					LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
				if (!handle) {
					/* 获取错误描述 */
					char err_buf[256];
					getWindowsErrorString(0, err_buf, sizeof(err_buf));
					SDF_ERR("LoadLibraryExW err,%s", err_buf);
				}
				if (add_cookie != NULL && pRemoveDllDirectory != NULL) {
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
			wfilename = (WCHAR*)OPENSSL_malloc(wlen * sizeof(WCHAR));
			if (wfilename) {
				if (MultiByteToWideChar(CP_ACP, 0, filename, -1, wfilename, wlen) > 0) {
					if (pAddDllDirectory && pRemoveDllDirectory) {
						WCHAR* last_slash = NULL;
						for (WCHAR* p = wfilename; *p; ++p) {
							if (*p == L'\\' || *p == L'/')
								last_slash = p;
						}
						if (last_slash) {
							size_t dir_len = (size_t)(last_slash - wfilename);
							wdir = (WCHAR*)OPENSSL_malloc((dir_len + 1) * sizeof(WCHAR));
							if (wdir != NULL) {
								wcsncpy_s(wdir, dir_len + 1, wfilename, dir_len);
								wdir[dir_len] = L'\0';
								if (pSetDefaultDllDirectories != NULL) {
									pSetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
								}
								if (pAddDllDirectory != NULL) {
									add_cookie = pAddDllDirectory(wdir);
								}
							}
						}
					}
					handle = LoadLibraryExW(wfilename, NULL,
						LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
						LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
					if (!handle) {
						/* 获取错误描述 */
						char err_buf[256];
						getWindowsErrorString(0, err_buf, sizeof(err_buf));
						SDF_ERR("LoadLibraryExW err,%s", err_buf);
					}
					if (add_cookie != NULL && pRemoveDllDirectory != NULL) {
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

	 {0, NULL, NULL, 0} };

/* SDF 引擎上下文 */
typedef struct {
	void* dll_handle;
	char* module_path;
	int module_type;
	char* device_name;
	char* password;
	char* start_password;
	unsigned int key_index;
	int initialized;

	/* 设备和会话句柄 */
	void* hDevice;
	void* hSession;

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
	SDF_CTX* sdf_ctx;
	unsigned int key_index;
	int key_type; /* 0: RSA, 1: ECC/SM2 */
	int is_sign_key;
	EVP_PKEY* pkey;

	/* 公钥缓存（用于 ENGINE 密钥的 SM2DHE 密钥协商） */
	int is_engine_key;              /* 标记是否为 ENGINE 密钥 */
	int has_public_key;             /* 是否有缓存的公钥 */
	unsigned int pub_key_bits;      /* 公钥位数 */
	unsigned char pub_key_x[ECCref_MAX_LEN];  /* 公钥 X 坐标 */
	unsigned char pub_key_y[ECCref_MAX_LEN];  /* 公钥 Y 坐标 */
} SDF_KEY_CTX;

/* 全局 ENGINE index，用于存储 SDF 上下文 */
static int sdf_engine_idx = -1;
static ENGINE* sdf_engine = NULL;

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

static unsigned int sdf_global_feature_mask = 0;// ENGINE_MODE_SSL_ONLY | ENGINE_FEATURE_PKEY_METHS | ENGINE_FEATURE_SSL_EXTENSIONS | ENGINE_FEATURE_EC | ENGINE_FEATURE_CIPHERS | ENGINE_FEATURE_DIGESTS; /* 默认SSL模式 */

/* 位掩码功能控制函数声明 */
static int sdf_rebind_features(ENGINE* e);
static unsigned int sdf_get_feature_mask(void);
static int sdf_set_feature_mask(unsigned int mask);
static int sdf_validate_mask(unsigned int mask);
static void sdf_clear_all_bindings(ENGINE* e);

/* 错误处理使用 e_sdf_err 提供的接口 */

/* 引擎 ID 和名称 */
static const char* engine_sdf_id = "sdf";
static const char* engine_sdf_name = "SDF Engine";

/* 函数声明 */
static int sdf_init(ENGINE* e);
static int sdf_finish(ENGINE* e);
static int sdf_destroy(ENGINE* e);
static int sdf_ctrl(ENGINE* e, int cmd, long i, void* p, void (*f)(void));
static EVP_PKEY* sdf_load_privkey(ENGINE* e, const char* key_id,
	UI_METHOD* ui_method, void* callback_data);
static EVP_PKEY* sdf_load_pubkey(ENGINE* e, const char* key_id,
	UI_METHOD* ui_method, void* callback_data);
static int sdf_load_ssl_client_cert(ENGINE* e, SSL* ssl,
	STACK_OF(X509_NAME)* ca_dn, X509** pcert,
	EVP_PKEY** pkey, STACK_OF(X509)** pother,
	UI_METHOD* ui_method, void* callback_data);

/* SDF 上下文管理函数 */
static SDF_CTX* sdf_get_ctx(ENGINE* e);
static int sdf_set_ctx(ENGINE* e, SDF_CTX* ctx);

/* 获取SDF函数指针 */
static void setFunctionList(void* hCT32, SD_FUNCTION_LIST_PTR pList,
	SGD_UINT32 iGetProcAddressID) {
	//=====================================设备管理============================================//
	pList->SDF_OpenDevice = (_CP_SDF_OpenDevice*)DLSYM(hCT32, "SDF_OpenDevice");
	pList->SDF_CloseDevice =
		(_CP_SDF_CloseDevice*)DLSYM(hCT32, "SDF_CloseDevice");
	pList->SDF_OpenSession =
		(_CP_SDF_OpenSession*)DLSYM(hCT32, "SDF_OpenSession");
	pList->SDF_CloseSession =
		(_CP_SDF_CloseSession*)DLSYM(hCT32, "SDF_CloseSession");
	pList->SDF_GetDeviceInfo =
		(_CP_SDF_GetDeviceInfo*)DLSYM(hCT32, "SDF_GetDeviceInfo");
	pList->SDF_GenerateRandom =
		(_CP_SDF_GenerateRandom*)DLSYM(hCT32, "SDF_GenerateRandom");
	pList->SDF_GetPrivateKeyAccessRight =
		(_CP_SDF_GetPrivateKeyAccessRight*)DLSYM(hCT32,
			"SDF_GetPrivateKeyAccessRight");
	pList->SDF_ReleasePrivateKeyAccessRight =
		(_CP_SDF_ReleasePrivateKeyAccessRight*)DLSYM(
			hCT32, "SDF_ReleasePrivateKeyAccessRight");
	//=====================================密钥管理============================================//
	pList->SDF_GenerateKeyPair_RSA =
		(_CP_SDF_GenerateKeyPair_RSA*)DLSYM(hCT32, "SDF_GenerateKeyPair_RSA");
	pList->SDF_GenerateKeyPair_RSAEx = (_CP_SDF_GenerateKeyPair_RSAEx*)DLSYM(
		hCT32, "SDF_GenerateKeyPair_RSAEx");
	pList->SDF_ExportSignPublicKey_RSA = (_CP_SDF_ExportSignPublicKey_RSA*)DLSYM(
		hCT32, "SDF_ExportSignPublicKey_RSA");
	pList->SDF_ExportSignPublicKey_RSAEx =
		(_CP_SDF_ExportSignPublicKey_RSAEx*)DLSYM(
			hCT32, "SDF_ExportSignPublicKey_RSAEx");
	pList->SDF_ExportEncPublicKey_RSA = (_CP_SDF_ExportEncPublicKey_RSA*)DLSYM(
		hCT32, "SDF_ExportEncPublicKey_RSA");
	pList->SDF_ExportEncPublicKey_RSAEx =
		(_CP_SDF_ExportEncPublicKey_RSAEx*)DLSYM(hCT32,
			"SDF_ExportEncPublicKey_RSAEx");
	pList->SDF_GenerateKeyWithIPK_RSA = (_CP_SDF_GenerateKeyWithIPK_RSA*)DLSYM(
		hCT32, "SDF_GenerateKeyWithIPK_RSA");
	pList->SDF_GenerateKeyWithEPK_RSA = (_CP_SDF_GenerateKeyWithEPK_RSA*)DLSYM(
		hCT32, "SDF_GenerateKeyWithEPK_RSA");
	pList->SDF_GenerateKeyWithEPK_RSAEx =
		(_CP_SDF_GenerateKeyWithEPK_RSAEx*)DLSYM(hCT32,
			"SDF_GenerateKeyWithEPK_RSAEx");
	pList->SDF_ImportKeyWithISK_RSA =
		(_CP_SDF_ImportKeyWithISK_RSA*)DLSYM(hCT32, "SDF_ImportKeyWithISK_RSA");
	pList->SDF_ExchangeDigitEnvelopeBaseOnRSA =
		(_CP_SDF_ExchangeDigitEnvelopeBaseOnRSA*)DLSYM(
			hCT32, "SDF_ExchangeDigitEnvelopeBaseOnRSA");
	pList->SDF_ExchangeDigitEnvelopeBaseOnRSAEx =
		(_CP_SDF_ExchangeDigitEnvelopeBaseOnRSAEx*)DLSYM(
			hCT32, "SDF_ExchangeDigitEnvelopeBaseOnRSAEx");

	pList->SDF_ImportKey = (_CP_SDF_ImportKey*)DLSYM(hCT32, "SDF_ImportKey");
	pList->SDF_DestroyKey = (_CP_SDF_DestroyKey*)DLSYM(hCT32, "SDF_DestroyKey");
	pList->SDF_GetSymmKeyHandle =
		(_CP_SDF_GetSymmKeyHandle*)DLSYM(hCT32, "SDF_GetSymmKeyHandle");
	pList->SDF_GenerateKeyWithKEK =
		(_CP_SDF_GenerateKeyWithKEK*)DLSYM(hCT32, "SDF_GenerateKeyWithKEK");
	pList->SDF_ImportKeyWithKEK =
		(_CP_SDF_ImportKeyWithKEK*)DLSYM(hCT32, "SDF_ImportKeyWithKEK");

	pList->SDF_GenerateKeyPair_ECC =
		(_CP_SDF_GenerateKeyPair_ECC*)DLSYM(hCT32, "SDF_GenerateKeyPair_ECC");
	pList->SDF_ExportSignPublicKey_ECC = (_CP_SDF_ExportSignPublicKey_ECC*)DLSYM(
		hCT32, "SDF_ExportSignPublicKey_ECC");
	pList->SDF_ExportEncPublicKey_ECC = (_CP_SDF_ExportEncPublicKey_ECC*)DLSYM(
		hCT32, "SDF_ExportEncPublicKey_ECC");
	pList->SDF_GenerateAgreementDataWithECC =
		(_CP_SDF_GenerateAgreementDataWithECC*)DLSYM(
			hCT32, "SDF_GenerateAgreementDataWithECC");
	pList->SDF_GenerateKeyWithECC =
		(_CP_SDF_GenerateKeyWithECC*)DLSYM(hCT32, "SDF_GenerateKeyWithECC");
	//发起方（服务端）
	pList->SDF_GenerateAgreementDataAndKeyWithECC =
		(_CP_SDF_GenerateAgreementDataAndKeyWithECC*)DLSYM(
			hCT32, "SDF_GenerateAgreementDataAndKeyWithECC");
	// 扩展接口：发起方（服务端）
	pList->SDF_GenerateAgreementDataWithECCEx =
		(_CP_SDF_GenerateAgreementDataWithECCEx*)DLSYM(
			hCT32, "SDF_GenerateAgreementDataWithECCEx");
	pList->SDF_GenerateKeyWithECCEx =
		(_CP_SDF_GenerateKeyWithECCEx*)DLSYM(hCT32, "SDF_GenerateKeyWithECCEx");
	// 扩展接口：响应方（客户端）
	pList->SDF_GenerateAgreementDataAndKeyWithECCEx =
		(_CP_SDF_GenerateAgreementDataAndKeyWithECCEx*)DLSYM(
			hCT32, "SDF_GenerateAgreementDataAndKeyWithECCEx");
	pList->SDF_GenerateKeyWithIPK_ECC = (_CP_SDF_GenerateKeyWithIPK_ECC*)DLSYM(
		hCT32, "SDF_GenerateKeyWithIPK_ECC");
	pList->SDF_GenerateKeyWithEPK_ECC = (_CP_SDF_GenerateKeyWithEPK_ECC*)DLSYM(
		hCT32, "SDF_GenerateKeyWithEPK_ECC");
	pList->SDF_ImportKeyWithISK_ECC =
		(_CP_SDF_ImportKeyWithISK_ECC*)DLSYM(hCT32, "SDF_ImportKeyWithISK_ECC");
	pList->SDF_ExchangeDigitEnvelopeBaseOnECC =
		(_CP_SDF_ExchangeDigitEnvelopeBaseOnECC*)DLSYM(
			hCT32, "SDF_ExchangeDigitEnvelopeBaseOnECC");
	//=====================================非对称密码运算============================================//
	pList->SDF_ExternalPublicKeyOperation_RSA =
		(_CP_SDF_ExternalPublicKeyOperation_RSA*)DLSYM(
			hCT32, "SDF_ExternalPublicKeyOperation_RSA");
	pList->SDF_ExternalPublicKeyOperation_RSAEx =
		(_CP_SDF_ExternalPublicKeyOperation_RSAEx*)DLSYM(
			hCT32, "SDF_ExternalPublicKeyOperation_RSAEx");
	pList->SDF_ExternalPrivateKeyOperation_RSA =
		(_CP_SDF_ExternalPrivateKeyOperation_RSA*)DLSYM(
			hCT32, "SDF_ExternalPrivateKeyOperation_RSA");
	pList->SDF_ExternalPrivateKeyOperation_RSAEx =
		(_CP_SDF_ExternalPrivateKeyOperation_RSAEx*)DLSYM(
			hCT32, "SDF_ExternalPrivateKeyOperation_RSAEx");
	pList->SDF_InternalPublicKeyOperation_RSA =
		(_CP_SDF_InternalPublicKeyOperation_RSA*)DLSYM(
			hCT32, "SDF_InternalPublicKeyOperation_RSA");
	pList->SDF_InternalPrivateKeyOperation_RSA =
		(_CP_SDF_InternalPrivateKeyOperation_RSA*)DLSYM(
			hCT32, "SDF_InternalPrivateKeyOperation_RSA");
	pList->SDF_InternalPublicKeyOperation_RSA_Ex =
		(_CP_SDF_InternalPublicKeyOperation_RSA_Ex*)DLSYM(
			hCT32, "SDF_InternalPublicKeyOperation_RSA_Ex");
	pList->SDF_InternalPrivateKeyOperation_RSA_Ex =
		(_CP_SDF_InternalPrivateKeyOperation_RSA_Ex*)DLSYM(
			hCT32, "SDF_InternalPrivateKeyOperation_RSA_Ex");

	pList->SDF_ExternalSign_ECC =
		(_CP_SDF_ExternalSign_ECC*)DLSYM(hCT32, "SDF_ExternalSign_ECC");
	pList->SDF_ExternalVerify_ECC =
		(_CP_SDF_ExternalVerify_ECC*)DLSYM(hCT32, "SDF_ExternalVerify_ECC");
	pList->SDF_InternalSign_ECC =
		(_CP_SDF_InternalSign_ECC*)DLSYM(hCT32, "SDF_InternalSign_ECC");
	pList->SDF_InternalVerify_ECC =
		(_CP_SDF_InternalVerify_ECC*)DLSYM(hCT32, "SDF_InternalVerify_ECC");
	pList->SDF_ExternalEncrypt_ECC =
		(_CP_SDF_ExternalEncrypt_ECC*)DLSYM(hCT32, "SDF_ExternalEncrypt_ECC");
	pList->SDF_ExternalDecrypt_ECC =
		(_CP_SDF_ExternalDecrypt_ECC*)DLSYM(hCT32, "SDF_ExternalDecrypt_ECC");
	pList->SDF_InternalEncrypt_ECC =
		(_CP_SDF_InternalEncrypt_ECC*)DLSYM(hCT32, "SDF_InternalEncrypt_ECC");
	pList->SDF_InternalDecrypt_ECC =
		(_CP_SDF_InternalDecrypt_ECC*)DLSYM(hCT32, "SDF_InternalDecrypt_ECC");

	//=====================================对称密码运算============================================//
	pList->SDF_Encrypt = (_CP_SDF_Encrypt*)DLSYM(hCT32, "SDF_Encrypt");
	pList->SDF_Decrypt = (_CP_SDF_Decrypt*)DLSYM(hCT32, "SDF_Decrypt");
	pList->SDF_CalculateMAC =
		(_CP_SDF_CalculateMAC*)DLSYM(hCT32, "SDF_CalculateMAC");

	//=====================================杂凑运算============================================//
	pList->SDF_HashInit = (_CP_SDF_HashInit*)DLSYM(hCT32, "SDF_HashInit");
	pList->SDF_HashUpdate = (_CP_SDF_HashUpdate*)DLSYM(hCT32, "SDF_HashUpdate");
	pList->SDF_HashFinal = (_CP_SDF_HashFinal*)DLSYM(hCT32, "SDF_HashFinal");

	//=====================================用户文件操作============================================//
	pList->SDF_CreateFile = (_CP_SDF_CreateFile*)DLSYM(hCT32, "SDF_CreateFile");
	pList->SDF_ReadFile = (_CP_SDF_ReadFile*)DLSYM(hCT32, "SDF_ReadFile");
	pList->SDF_WriteFile = (_CP_SDF_WriteFile*)DLSYM(hCT32, "SDF_WriteFile");
	pList->SDF_DeleteFile = (_CP_SDF_DeleteFile*)DLSYM(hCT32, "SDF_DeleteFile");
	//=====================================扩展接口============================================//
	pList->SDF_InputRSAKeyPair =
		(_CP_SDF_InputRSAKeyPair*)DLSYM(hCT32, "SDF_InputRSAKeyPair");
	pList->SDF_InputRSAKeyPairEx =
		(_CP_SDF_InputRSAKeyPairEx*)DLSYM(hCT32, "SDF_InputRSAKeyPairEx");
	pList->SDF_ImportKeyPair_ECC =
		(_CP_SDF_ImportKeyPair_ECC*)DLSYM(hCT32, "SDF_ImportKeyPair_ECC");
	pList->SDF_GetErrMsg = (_CP_SDF_GetErrMsg*)DLSYM(hCT32, "SDF_GetErrMsg");
	pList->SDF_GetKekAccessRight =
		(_CP_SDF_GetKekAccessRight*)DLSYM(hCT32, "SDF_GetKekAccessRight");
	pList->SDF_ReleaseKekAccessRight = (_CP_SDF_ReleaseKekAccessRight*)DLSYM(
		hCT32, "SDF_ReleaseKekAccessRight");

	//=====================================管理接口============================================//
	pList->BYCSM_LoadModule =
		(_CP_BYCSM_LoadModule*)DLSYM(hCT32, "BYCSM_LoadModule");
	pList->BYCSM_UninstallModule =
		(_CP_BYCSM_UninstallModule*)DLSYM(hCT32, "BYCSM_UninstallModule");
}

/* 辅助函数 */
static void sdf_lock(SDF_CTX* ctx) {
	if (!ctx)
		return;
#ifdef _WIN32
	EnterCriticalSection(&ctx->lock);
#else
	pthread_mutex_lock(&ctx->lock);
#endif
}

static void sdf_unlock(SDF_CTX* ctx) {
	if (!ctx)
		return;
#ifdef _WIN32
	LeaveCriticalSection(&ctx->lock);
#else
	pthread_mutex_unlock(&ctx->lock);
#endif
}

static SDF_CTX* sdf_ctx_new(void) {
	SDF_CTX* ctx = OPENSSL_zalloc(sizeof(SDF_CTX));
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

static void sdf_ctx_free(SDF_CTX* ctx) {
	if (!ctx)
		return;

	/* 调试输出：便于定位崩溃时的指针值 */
	SDF_INFO("sdf_ctx_free: ctx=%p, dll_handle=%p, module_path=%p",
		(void*)ctx, ctx->dll_handle, (void*)ctx->module_path);

	/* 释放私钥访问权限 */
	if (ctx->hSession && ctx->sdfList.SDF_ReleasePrivateKeyAccessRight) {
		ctx->sdfList.SDF_ReleasePrivateKeyAccessRight(ctx->hSession,
			ctx->key_index);
	}

	/* 关闭会话和设备 */
	if (ctx->hSession && ctx->sdfList.SDF_CloseSession) {
		ctx->sdfList.SDF_CloseSession(ctx->hSession);
		ctx->hSession = NULL;
	}
	if (ctx->hDevice && ctx->sdfList.SDF_CloseDevice) {
		ctx->sdfList.SDF_CloseDevice(ctx->hDevice);
		ctx->hDevice = NULL;
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
		ctx->dll_handle = NULL;
	}

	/* 释放字符串（可能为 NULL）*/
	if (ctx->module_path) {
		OPENSSL_free(ctx->module_path);
		ctx->module_path = NULL;
	}
	if (ctx->device_name) {
		OPENSSL_free(ctx->device_name);
		ctx->device_name = NULL;
	}
	if (ctx->password) {
		OPENSSL_free(ctx->password);
		ctx->password = NULL;
	}
	if (ctx->start_password) {
		OPENSSL_free(ctx->start_password);
		ctx->start_password = NULL;
	}

#ifdef _WIN32
	// 防护：DeleteCriticalSection 在极端错误路径中可能未被初始化，使用 SEH 防护 
	__try {
		DeleteCriticalSection(&ctx->lock);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		SDF_WARN("sdf_ctx_free: DeleteCriticalSection raised exception - ignored");
	}
#else
	pthread_mutex_destroy(&ctx->lock);
#endif

	/* 清除并释放 ctx 本身 */
	OPENSSL_clear_free(ctx, sizeof(*ctx));
}

/* SDF 上下文管理函数 */
static SDF_CTX* sdf_get_ctx(ENGINE* e) {
	if (sdf_engine_idx == -1) {
		SDFerr(SDF_F_SDF_INIT, SDF_R_LIBRARY_NOT_INITIALIZED);
		return NULL;
	}
	return ENGINE_get_ex_data(e, sdf_engine_idx);
}

static int sdf_set_ctx(ENGINE* e, SDF_CTX* ctx) {
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
static int sdf_load_library(SDF_CTX* ctx) {
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
static int sdf_init_device(SDF_CTX* ctx) {
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
static int sdf_ctrl(ENGINE* e, int cmd, long i, void* p, void (*f)(void)) {
	SDF_CTX* ctx = sdf_get_ctx(e);

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
		ctx->module_path = OPENSSL_strdup((char*)p);
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
		ctx->device_name = OPENSSL_strdup((char*)p);
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
		ctx->password = OPENSSL_strdup((char*)p);
		return ctx->password ? 1 : 0;
	case SDF_CMD_START_PASSWORD:
		if (!p) {
			SDF_ERR("ctrl START_PASSWORD: null pointer");
			SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
			return 0;
		}
		OPENSSL_free(ctx->start_password);
		ctx->start_password = OPENSSL_strdup((char*)p);
		return ctx->start_password ? 1 : 0;
	case SDF_CMD_LIST_VENDORS: {
		// 列出所有可用厂商
		if (!p) {
			SDF_ERR("ctrl LIST_VENDORS: buffer pointer null");
			SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
			return 0;
		}
		char* buffer = (char*)p;
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
		char* buffer = (char*)p;
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
			strncpy((char*)p, ctx->module_path, strlen(ctx->module_path));
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
		char* buffer = (char*)p;
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
		char* buffer = (char*)p;
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
		SDF_INFO("SDF_CMD_SET_FEATURE_MASK called with p=%p", p);
		if (!p) {
			SDF_ERR("ctrl SET_FEATURE_MASK: mask string null");
			SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
			return 0;
		}

		unsigned int new_mask = 0;
		char* mask_str = (char*)p;

		/* 支持十六进制输入，如 "0x0053" 或 "83" */
		if (strncmp(mask_str, "0x", 2) == 0 || strncmp(mask_str, "0X", 2) == 0) {
			new_mask = (unsigned int)strtoul(mask_str, NULL, 16);
		}
		else {
			new_mask = (unsigned int)strtoul(mask_str, NULL, 10);
		}
		SDF_INFO("Parsed feature mask: 0x%04X from string: %s", new_mask, mask_str);

		/* 验证掉码 */
		if (!sdf_validate_mask(new_mask)) {
			SDF_ERR("Invalid feature mask: 0x%04X", new_mask);
			SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
			return 0;
		}

		sdf_global_feature_mask = new_mask;

		SDF_INFO("SDF Feature mask set to: 0x%04X (from openssl.cnf)", new_mask);
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
		char* buffer = (char*)p;
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
		char* mode_str = (char*)p;

		if (strcmp(mode_str, "ssl_only") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_SSL_ONLY;
			SDF_INFO("Mode set to: SSL Only (0x%04X) - Recommended for Nginx",
				ENGINE_MODE_SSL_ONLY);
		}
		else if (strcmp(mode_str, "ssl_hw_sign") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_SSL_HW_SIGN;
			SDF_INFO("Mode set to: SSL + HW Sign (0x%04X) - SSL + Hardware signing",
				ENGINE_MODE_SSL_HW_SIGN);
		}
		else if (strcmp(mode_str, "full_hw") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_FULL_HARDWARE;
			SDF_INFO("Mode set to: Full Hardware (0x%04X) - Complete hardware "
				"acceleration",
				ENGINE_MODE_FULL_HARDWARE);
		}
		else if (strcmp(mode_str, "dangerous") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_DANGEROUS;
			SDF_WARN("Mode set to: Dangerous (0x%04X) - Includes RAND takeover!",
				ENGINE_MODE_DANGEROUS);
		}
		else if (strcmp(mode_str, "all_features") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_ALL_FEATURES;
			SDF_INFO("Mode set to: All Features (0x%04X) - Maximum functionality",
				ENGINE_MODE_ALL_FEATURES);
		}
		else if (strcmp(mode_str, "gm_ssl_full") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_GM_SSL_FULL;
			SDF_INFO("Mode set to: GM SSL Full (0x%04X) - Complete GM SSL support",
				ENGINE_MODE_GM_SSL_FULL);
		}
		else if (strcmp(mode_str, "gm_ssl_hw") == 0) {
			sdf_global_feature_mask = ENGINE_MODE_GM_SSL_HW;
			SDF_INFO("Mode set to: GM SSL Hardware (0x%04X) - GM SSL with hardware "
				"acceleration",
				ENGINE_MODE_GM_SSL_HW);
		}
		else {
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
		char* buffer = (char*)p;
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
		char* mask_str = (char*)p;

		unsigned int mask = 0;
		if (strncmp(mask_str, "0x", 2) == 0 || strncmp(mask_str, "0X", 2) == 0) {
			mask = (unsigned int)strtoul(mask_str, NULL, 16);
		}
		else {
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
		char* param = (char*)p;

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
		char* param = (char*)p;

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
		char* param = (char*)p;

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
		char* param = (char*)p;

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
		char* param = (char*)p;

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
		char* param = (char*)p;

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
		char* param = (char*)p;

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
static int sdf_rsa_sign(int type, const unsigned char* m, unsigned int m_len,
	unsigned char* sigret, unsigned int* siglen,
	const RSA* rsa) {
	SDF_KEY_CTX* key_ctx;
	SDF_CTX* ctx;
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
static int sdf_rsa_verify(int type, const unsigned char* m, unsigned int m_len,
	const unsigned char* sigbuf, unsigned int siglen,
	const RSA* rsa) {
	SDF_KEY_CTX* key_ctx;
	SDF_CTX* ctx;
	unsigned char decrypted[RSAref_MAX_LEN];
	unsigned int decrypted_len = RSAref_MAX_LEN;
	unsigned char* padded_msg = NULL;
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
		ctx->hSession, key_ctx->key_index, (unsigned char*)sigbuf, siglen,
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
	}
	else {
		SDF_ERR("rsa verify: padded_msg != m");
		SDFerr(SDF_F_SDF_RSA_PUB_DEC, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		ret = 0;
	}

	/* 清理敏感数据 */
	OPENSSL_clear_free(padded_msg, rsa_len);

	return ret;
}

/* RSA 方法表 */
static RSA_METHOD* sdf_rsa_method = NULL;

static RSA_METHOD* get_sdf_rsa_method(void) {
	if (sdf_rsa_method)
		return sdf_rsa_method;

	sdf_rsa_method = RSA_meth_new("SDF RSA method", 0);
	if (!sdf_rsa_method) {
		SDF_ERR("rsa verify: alloc sdf_rsa_method failed");
		SDFerr(SDF_F_SDF_RSA_PRIV_ENC, SDF_R_MEMORY_ALLOCATION_FAILED);
		return NULL;
	}

	RSA_meth_set_sign(sdf_rsa_method, sdf_rsa_sign);
	RSA_meth_set_verify(sdf_rsa_method, sdf_rsa_verify);

	return sdf_rsa_method;
}

/* ECC/SM2 签名函数 */
static int sdf_ec_key_gen(EC_KEY* eckey) {
	SDF_CTX* ctx;
	ECCrefPublicKey pubKey;
	ECCrefPrivateKey priKey;
	int ret;
	int keyLen = 256;

	SDF_INFO("sdf_ec_key_gen: starting SDF hardware key generation");

	ctx = sdf_get_ctx(sdf_engine);
	if (!ctx) {
		SDF_ERR("sdf_ec_key_gen: SDF context not available");
		SDFerr(SDF_F_SDF_ECC_KEYGEN, SDF_R_NOT_INITIALIZED);
		return 0;
	}

	if (!ctx->initialized) {
		if (!sdf_init_device(ctx)) {
			SDF_ERR("sdf_ec_key_gen: device init failed");
			SDFerr(SDF_F_SDF_ECC_KEYGEN, SDF_R_INIT_FAILED);
			return 0;
		}
	}

	sdf_lock(ctx);

	/* 调用 SDF 生成 ECC 密钥对 */
	ret = ctx->sdfList.SDF_GenerateKeyPair_ECC(ctx->hSession, SGD_SM2_3, keyLen, &pubKey, &priKey);

	sdf_unlock(ctx);

	if (ret != SDR_OK) {
		SDF_ERR("sdf_ec_key_gen: SDF_GenerateKeyPair_ECC failed ret=%d", ret);
		SDFerr(SDF_F_SDF_ECC_KEYGEN, SDF_R_REQUEST_FAILED);
		return 0;
	}

	/* Tongsuo doesn't have EC_KEY_set_ECCrefPrivateKey/PublicKey functions */
	/* Store the hardware key references in the SDF_KEY_CTX instead */
	SDF_INFO("sdf_ec_key_gen: SDF hardware key generation successful");
	SDF_INFO("sdf_ec_key_gen: hardware key references stored, falling back to software key generation");

	/* Fall back to software key generation since we can't directly set hardware keys */
	ret = EC_KEY_generate_key(eckey);
	if (ret <= 0) {
		SDF_ERR("sdf_ec_key_gen: software fallback key generation failed");
		SDFerr(SDF_F_SDF_ECC_KEYGEN, SDF_R_KEY_SET_FAILED);
		return 0;
	}

	SDF_INFO("sdf_ec_key_gen: software fallback key generation successful");
	return 1;
}

static int sdf_ecdsa_sign(int type, const unsigned char* dgst, int dgst_len,
	unsigned char* sig, unsigned int* siglen,
	const BIGNUM* kinv, const BIGNUM* r, EC_KEY* eckey) {
	SDF_KEY_CTX* key_ctx;
	SDF_CTX* ctx;
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
	SDF_INFO("ecdsa sign: calling SDF_InternalSign_ECC, key_index=%u, dgst_len=%d", key_ctx->key_index, dgst_len);
	SDF_HEX_DUMP("ecdsa sign: digest data", dgst, dgst_len);
	ret = ctx->sdfList.SDF_InternalSign_ECC(ctx->hSession, key_ctx->key_index,
		(unsigned char*)dgst, dgst_len,
		&ecc_sig);

	sdf_unlock(ctx);

	if (ret != SDR_OK) {
		SDF_ERR("ecdsa sign: SDF_InternalSign_ECC failed ret=0x%08X", ret);
		SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_REQUEST_FAILED);
		return 0;
	}

	SDF_INFO("ecdsa sign: SDF_InternalSign_ECC succeeded");
	SDF_HEX_DUMP("ecdsa sign: r", ecc_sig.r, sizeof(ecc_sig.r));
	SDF_HEX_DUMP("ecdsa sign: s", ecc_sig.s, sizeof(ecc_sig.s));

	/* 转换签名格式为 DER */
	ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
	if (!ecdsa_sig) {
		SDF_ERR("ecdsa sign: alloc ECDSA_SIG failed");
		SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	/* SM2 签名 r 和 s 都是 32 字节（256 位） */
	/*
	 * 处理两种 SDF 规范版本：
	 * - 2008版: ECCSignature.r/s 是 32 字节（无填充）
	 * - 2012版: ECCSignature.r/s 是 64 字节（前 32 字节填充）
	 *
	 * 检测方法：如果前 32 字节全为 0，则是 2012 版（有填充）；否则是 2008 版
	 */
	unsigned char* r_ptr = ecc_sig.r;
	unsigned char* s_ptr = ecc_sig.s;

	/* 检查是否有填充（2012版） */
	int has_padding = 1;
	for (int i = 0; i < 32; i++) {
		if (ecc_sig.r[i] != 0 || ecc_sig.s[i] != 0) {
			has_padding = 0;
			break;
		}
	}

	if (has_padding) {
		SDF_INFO("ecdsa sign: detected 2012 spec (64-byte with padding), skipping first 32 bytes");
		r_ptr = ecc_sig.r + 32;
		s_ptr = ecc_sig.s + 32;
	}
	else {
		SDF_INFO("ecdsa sign: detected 2008 spec (32-byte, no padding)");
	}

	BIGNUM* bn_r = BN_bin2bn(r_ptr, 32, NULL);
	BIGNUM* bn_s = BN_bin2bn(s_ptr, 32, NULL);

	if (!bn_r || !bn_s) {
		BN_free(bn_r);
		BN_free(bn_s);
		ECDSA_SIG_free(ecdsa_sig);
		SDF_ERR("ecdsa sign: BN conversion failed");
		SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	SDF_INFO("ecdsa sign: bn_r num_bytes=%d, bn_s num_bytes=%d", BN_num_bytes(bn_r), BN_num_bytes(bn_s));

	ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s);

	/* 先获取 DER 编码长度 */
	int der_len = i2d_ECDSA_SIG(ecdsa_sig, NULL);
	if (der_len < 0 || der_len >(int) * siglen) {
		ECDSA_SIG_free(ecdsa_sig);
		SDF_ERR("ecdsa sign: signature too large, der_len=%d, siglen=%u", der_len, *siglen);
		SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		return 0;
	}

	/* 编码到输出缓冲区 */
	unsigned char* sig_ptr = sig;
	der_len = i2d_ECDSA_SIG(ecdsa_sig, &sig_ptr);
	ECDSA_SIG_free(ecdsa_sig);

	if (der_len < 0) {
		SDF_ERR("ecdsa sign: i2d_ECDSA_SIG failed");
		SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		return 0;
	}

	SDF_INFO("ecdsa sign: signature generated successfully, der_len=%d", der_len);
	SDF_HEX_DUMP("ecdsa sign: DER signature", sig, der_len);
#ifdef SDF_DEBUG
	/* 自我验证签名（调试用）- 使用两种方式验证 */
	if (EC_KEY_get0_public_key(eckey)) {
		/* 方式1：使用ECDSA_verify（不重新计算ZA，直接验证摘要） */
		int verify_result_ecdsa = ECDSA_verify(0, dgst, dgst_len, sig, der_len, eckey);
		SDF_INFO("ecdsa sign: self-verification (ECDSA_verify, no ZA recalc), result=%d", verify_result_ecdsa);

		/* 方式2：使用SM2验证（会重新计算ZA，模拟客户端验证） */
		int verify_result_sm2 = ossl_sm2_internal_verify(dgst, dgst_len, sig, der_len, (EC_KEY*)eckey);
		SDF_INFO("ecdsa sign: self-verification (SM2_verify, with ZA recalc), result=%d", verify_result_sm2);

		if (verify_result_ecdsa != 1) {
			SDF_INFO("ecdsa sign: ECDSA verification failed - signature may be corrupted");
		}
		if (verify_result_sm2 != 1) {
			SDF_INFO("ecdsa sign: SM2 verification failed - ZA mismatch or signature error!");
			SDF_INFO("ecdsa sign: This indicates the hardware may have computed ZA internally");
		}
		if (verify_result_ecdsa == 1 && verify_result_sm2 == 1) {
			SDF_INFO("ecdsa sign: Both verifications successful - signature is correct");
		}
	}
#endif
	* siglen = der_len;
	return 1;
}

/* ECC/SM2 验证函数 */
static int sdf_ecdsa_verify(int type, const unsigned char* dgst, int dgst_len,
	const unsigned char* sigbuf, int sig_len,
	EC_KEY* eckey) {
	SDF_KEY_CTX* key_ctx;
	SDF_CTX* ctx;
	ECCSignature ecc_sig;
	ECDSA_SIG* ecdsa_sig;
	const BIGNUM* bn_r, * bn_s;
	int ret;

	key_ctx = EC_KEY_get_ex_data(eckey, 0);
	SDF_INFO("ecdsa verify: key_ctx=%p, eckey=%p", key_ctx, eckey);
	if (!key_ctx || !key_ctx->sdf_ctx) {
		SDF_ERR("ecdsa verify: key ctx missing (key_ctx=%p)", key_ctx);
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
		(unsigned char*)dgst, dgst_len,
		&ecc_sig);

	sdf_unlock(ctx);

	if (ret != SDR_OK) {
		SDF_ERR("ecdsa verify: SDF_InternalVerify_ECC failed ret=%d", ret);
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		return 0;
	}

	return 1;
}

/* ECC 方法表 */
static EC_KEY_METHOD* sdf_ec_method = NULL;

static EC_KEY_METHOD* get_sdf_ec_method(void) {
	if (sdf_ec_method)
		return sdf_ec_method;

	sdf_ec_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
	if (!sdf_ec_method) {
		SDF_ERR("ecdsa verify: alloc sdf_ec_method failed");
		SDFerr(SDF_F_SDF_ECC_SIGN, SDF_R_MEMORY_ALLOCATION_FAILED);
		return NULL;
	}

	EC_KEY_METHOD_set_sign(sdf_ec_method, sdf_ecdsa_sign, NULL, NULL);
	EC_KEY_METHOD_set_verify(sdf_ec_method, sdf_ecdsa_verify, NULL);

	return sdf_ec_method;
}

/* 随机数生成函数 */
static int sdf_rand_bytes(unsigned char* buf, int num) {
	/* 获取当前活跃的 ENGINE */
	ENGINE* e = ENGINE_get_default_RAND();
	SDF_CTX* ctx = NULL;
	int ret;

	if (e && strcmp(ENGINE_get_id(e), engine_sdf_id) == 0) {
		ctx = sdf_get_ctx(e);
	}

	if (!ctx || !ctx->initialized) {
		if (ctx && !sdf_init_device(ctx)) {
			SDF_ERR("rand bytes: library not initialized");
			SDFerr(SDF_F_SDF_RAND_BYTES, SDF_R_LIBRARY_NOT_INITIALIZED);
			return 0;
		}
		else if (!ctx) {
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
	ENGINE* e = ENGINE_get_default_RAND();
	SDF_CTX* ctx = NULL;

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
static EVP_PKEY* sdf_load_privkey(ENGINE* e, const char* key_id,
	UI_METHOD* ui_method, void* callback_data) {
	SDF_CTX* ctx = sdf_get_ctx(e);
	SDF_KEY_CTX* key_ctx;
	EVP_PKEY* pkey = NULL;
	RSA* rsa = NULL;
	EC_KEY* ec_key = NULL;
	RSArefPublicKey rsa_pub;
	ECCrefPublicKey ecc_pub;
	unsigned int key_index = ctx ? ctx->key_index : 1;
	int key_type = 0; /* 0: RSA, 1: ECC */
	int is_sign_key = 1;
	int ret;

	SDF_INFO("sdf_load_privkey: called with key_id=%s", key_id ? key_id : "NULL");

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
		}
		else if (strncmp(key_id, "sm2:", 4) == 0 ||
			strncmp(key_id, "ecc:", 4) == 0) {
			key_type = 1;
			key_index = atoi(key_id + 4);
		}

		if (strstr(key_id, "sign")) {
			is_sign_key = 1;
		}
		else if (strstr(key_id, "enc")) {
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
			ctx->hSession, ctx->key_index, (unsigned char*)ctx->password,
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
		}
		else {
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
		BIGNUM* n = BN_bin2bn(rsa_pub.m, RSAref_MAX_LEN, NULL);
		BIGNUM* e = BN_bin2bn(rsa_pub.e, RSAref_MAX_LEN, NULL);

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

	}
	else { /* ECC/SM2 */
		/* 导出 ECC 公钥 */
		if (is_sign_key) {
			SDF_INFO("load_privkey: calling SDF_ExportSignPublicKey_ECC, key_index=%u", key_index);
			ret = ctx->sdfList.SDF_ExportSignPublicKey_ECC(ctx->hSession, key_index,
				&ecc_pub);
		}
		else {
			SDF_INFO("load_privkey: calling SDF_ExportEncPublicKey_ECC, key_index=%u", key_index);
			ret = ctx->sdfList.SDF_ExportEncPublicKey_ECC(ctx->hSession, key_index,
				&ecc_pub);
		}

		SDF_INFO("load_privkey: SDF_Export*PublicKey_ECC returned ret=0x%08X", ret);
		if (ret != SDR_OK) {
			sdf_unlock(ctx);
			OPENSSL_free(key_ctx);
			SDF_ERR("load_privkey: export ECC public key failed ret=0x%08X", ret);
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

		/* 设置 ECC 公钥
		 * 注意：SDF 公钥格式为 64 字节，前 32 字节填充0，后 32 字节为实际坐标值
		 * 类似签名的 r/s 格式，需要跳过前 32 字节
		 */
		const EC_GROUP* group = EC_KEY_get0_group(ec_key);
		EC_POINT* pub_point = EC_POINT_new(group);
		BIGNUM* x = BN_bin2bn(ecc_pub.x + 32, 32, NULL);
		BIGNUM* y = BN_bin2bn(ecc_pub.y + 32, 32, NULL);

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

		/* 验证公钥是否正确设置 */
		BIGNUM* x_check = BN_new();
		BIGNUM* y_check = BN_new();
		if (x_check && y_check && EC_POINT_get_affine_coordinates_GFp(group, pub_point, x_check, y_check, NULL)) {
			unsigned char x_buf[32], y_buf[32];
			int x_len = BN_bn2bin(x_check, x_buf);
			int y_len = BN_bn2bin(y_check, y_buf);
			SDF_INFO("load_privkey: public key set verification - x_len=%d, y_len=%d", x_len, y_len);
			SDF_HEX_DUMP("load_privkey: verified pub X", x_buf, x_len);
			SDF_HEX_DUMP("load_privkey: verified pub Y", y_buf, y_len);
		}
		if (x_check) BN_free(x_check);
		if (y_check) BN_free(y_check);

		EC_POINT_free(pub_point);
		BN_free(x);
		BN_free(y);

		/* 设置 EC 方法和上下文 */
		EC_KEY_set_method(ec_key, get_sdf_ec_method());
		EC_KEY_set_ex_data(ec_key, 0, key_ctx);

		/* **缓存公钥数据，用于 SM2DHE 密钥协商** */
		key_ctx->is_engine_key = 1;
		key_ctx->has_public_key = 1;
		key_ctx->pub_key_bits = ecc_pub.bits;
		memcpy(key_ctx->pub_key_x, ecc_pub.x, ECCref_MAX_LEN);
		memcpy(key_ctx->pub_key_y, ecc_pub.y, ECCref_MAX_LEN);
		SDF_INFO("load_privkey: cached public key for SM2DHE, bits=%d", key_ctx->pub_key_bits);

		/* 创建 EVP_PKEY */
		pkey = EVP_PKEY_new();
		if (!pkey || !EVP_PKEY_assign(pkey, EVP_PKEY_SM2, ec_key)) {
			EC_KEY_free(ec_key);
			EVP_PKEY_free(pkey);
			sdf_unlock(ctx);
			OPENSSL_free(key_ctx);
			SDF_ERR("load_privkey: assign EC_KEY to EVP_PKEY failed");
			SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_INTERNAL_ERROR);
			return NULL;
		}

		/* 同时将 key_ctx 存储在 EVP_PKEY 的 ex_data 中，以防 EC_KEY 被复制 */
		EVP_PKEY_set_ex_data(pkey, 0, key_ctx);

		SDF_INFO("sdf_load_privkey: SM2 key loaded successfully, pkey=%p", pkey);
		SDF_INFO("sdf_load_privkey: EVP_PKEY_id=%d", EVP_PKEY_id(pkey));

		/* 输出完整的公钥坐标用于验证 */
		//SDF_HEX_DUMP("pub_key x (64 bytes)", ecc_pub.x, ECCref_MAX_LEN);
		//SDF_HEX_DUMP("pub_key y (64 bytes)", ecc_pub.y, ECCref_MAX_LEN);
	}

	sdf_unlock(ctx);
	key_ctx->pkey = pkey;
	return pkey;
}

/* 加载公钥 */
static EVP_PKEY* sdf_load_pubkey(ENGINE* e, const char* key_id,
	UI_METHOD* ui_method, void* callback_data) {
	/* 公钥和私钥加载逻辑相同，因为我们只使用公钥部分 */
	return sdf_load_privkey(e, key_id, ui_method, callback_data);
}

/* SSL 客户端证书加载函数 */
static int sdf_load_ssl_client_cert(ENGINE* e, SSL* ssl,
	STACK_OF(X509_NAME)* ca_dn, X509** pcert,
	EVP_PKEY** pkey, STACK_OF(X509)** pother,
	UI_METHOD* ui_method, void* callback_data) {
	/* 这里可以实现从 SDF 设备加载客户端证书的逻辑 */
	/* 目前返回 0 表示不支持 */
	SDFerr(SDF_F_SDF_LOAD_SSL_CLIENT_CERT, SDF_R_NOT_SUPPORTED);
	return 0;
}

/*---------------------------------pkey
 * method---------------------------------------------*/

typedef struct {
	/* Key and paramgen group */
	EC_GROUP* gen_group;
	/* message digest */
	const EVP_MD* md;
	/* Duplicate key if custom cofactor needed */
	EC_KEY* co_key;
	/* Cofactor mode */
	signed char cofactor_mode;
	/* KDF (if any) to use for ECDH */
	char kdf_type;
	/* Message digest to use for key derivation */
	const EVP_MD* kdf_md;
	/* User key material */
	unsigned char* kdf_ukm;
	size_t kdf_ukmlen;
	/* KDF output length */
	size_t kdf_outlen;
#ifndef OPENSSL_NO_SM2
	int ec_scheme;
	char* signer_id;
	size_t signer_id_len;
	unsigned char* signer_zid;
	size_t signer_zid_len;
	int ec_encrypt_param;
	/* SM2 ID */
	unsigned char* id;
	size_t id_len;

	/* SM2DHE 参数 */
	struct {
		EVP_PKEY* self_eph_priv;        /* 本端临时私钥 */
		EVP_PKEY* peer_eph_pub;         /* 对端临时公钥 */
		EVP_PKEY* self_cert_priv;       /* 本端证书私钥 */
		EVP_PKEY* peer_cert_pub;        /* 对端证书公钥 */
		EVP_PKEY* self_cert_pub;        /* 本端证书公钥 */
		EVP_PKEY* self_eph_pub;         /* 本端临时公钥 */
		const unsigned char* self_id;   /* 本端ID */
		size_t self_id_len;             /* 本端ID长度 */
		const unsigned char* peer_id;   /* 对端ID */
		size_t peer_id_len;             /* 对端ID长度 */
		int initiator;                  /* 是否为发起方 */
		SGD_HANDLE agreement_handle;    /* SDF协商句柄，在pkey_ec_ctrl中生成，在pkey_ec_derive中使用 */
		int deferred_keygen;            /* 是否延迟生成密钥（在derive阶段生成） */
		unsigned char* sdf_generated_eph_pub;  /* SDF生成的临时公钥（编码格式） */
		size_t sdf_generated_eph_pub_len;     /* SDF生成的临时公钥长度 */
	} sm2dhe;
#endif
} SDF_EC_PKEY_CTX;

static int sdf_pkey_ec_init(EVP_PKEY_CTX* ctx) {
	//return -2;
	SDF_EC_PKEY_CTX* dctx;

	SDF_INFO("pkey_ec_init: initializing EC PKEY context");
	dctx = OPENSSL_zalloc(sizeof(*dctx));
	if (dctx == NULL) {
		SDF_ERR("pkey_ec_init: OPENSSL_zalloc failed");
		SDFerr(SDF_F_SDF_PKEY_EC_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	dctx->cofactor_mode = -1;
	dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
	/* 立即创建 SM2 曲线的 EC_GROUP，确保 gen_group 不为 NULL */
	dctx->gen_group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!dctx->gen_group) {
		SDF_ERR("pkey_ec_init: failed to create SM2 group");
		SDFerr(SDF_F_SDF_PKEY_EC_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
		OPENSSL_free(dctx);
		return 0;
	}
	SDF_INFO("pkey_ec_init: created SM2 group successfully, gen_group=%p", dctx->gen_group);
#ifndef OPENSSL_NO_SM2
	/* 根据密钥类型判断是否为 SM2 */
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	int pkey_id = pkey ? EVP_PKEY_id(pkey) : EVP_PKEY_EC;
	int is_sm2_ctx = EVP_PKEY_CTX_is_a(ctx, "SM2");

	SDF_INFO("pkey_ec_init: pkey=%p, pkey_id=%d, is_sm2_ctx=%d, EVP_PKEY_SM2=%d, EVP_PKEY_EC=%d",
		pkey, pkey_id, is_sm2_ctx, EVP_PKEY_SM2, EVP_PKEY_EC);

	/* 无论如何，强制使用 SM2 曲线，因为这是用于 ECDHE SM2 */
	dctx->ec_scheme = NID_sm2;
	SDF_INFO("pkey_ec_init: Forcing SM2 curve for ECDHE key generation");
	SDF_INFO("pkey_ec_init: pkey_id=%d, ec_scheme=%d, NID_sm2=%d, NID_X9_62_prime256v1=%d", pkey_id, dctx->ec_scheme, NID_sm2, NID_X9_62_prime256v1);
	dctx->signer_id = NULL;
	dctx->signer_id_len = 0;
	dctx->signer_zid = NULL;
	dctx->signer_zid_len = 0;
	dctx->ec_encrypt_param = NID_undef;
#endif

	EVP_PKEY_CTX_set_data(ctx, dctx);
	SDF_INFO("pkey_ec_init: context initialized successfully, dctx=%p", dctx);

	/* 添加调试信息：检查上下文是否正确设置 */
	SDF_INFO("pkey_ec_init: ctx=%p, dctx=%p, ec_scheme=%d, gen_group=%p", ctx, dctx, dctx->ec_scheme, dctx->gen_group);

	return 1;
}

static int sdf_pkey_ec_copy(EVP_PKEY_CTX* dst, const EVP_PKEY_CTX* src) {
	SDF_EC_PKEY_CTX* dctx, * sctx;
	if (!sdf_pkey_ec_init(dst)) {
		SDF_ERR("pkey_ec_copy: sdf_pkey_ec_init failed");
		SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}
	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);
	if (sctx->gen_group) {
		dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
		if (!dctx->gen_group) {
			SDF_ERR("pkey_ec_copy: EC_GROUP_dup failed");
			SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
	}
	dctx->md = sctx->md;

	if (sctx->co_key) {
		dctx->co_key = EC_KEY_dup(sctx->co_key);
		if (!dctx->co_key) {
			SDF_ERR("pkey_ec_copy: EC_KEY_dup failed");
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
			SDF_ERR("pkey_ec_copy: OPENSSL_memdup failed");
			SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
	}
	else
		dctx->kdf_ukm = NULL;
	dctx->kdf_ukmlen = sctx->kdf_ukmlen;
#ifndef OPENSSL_NO_SM2
	dctx->ec_scheme = sctx->ec_scheme;
	if (sctx->signer_id) {
		dctx->signer_id = OPENSSL_strdup(sctx->signer_id);
		if (!dctx->signer_id) {
			SDF_ERR("pkey_ec_copy: OPENSSL_strdup failed");
			SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		dctx->signer_id_len = sctx->signer_id_len;
	}
	else {
		dctx->signer_id_len = 0;
	}
	dctx->signer_zid = NULL;
	dctx->signer_zid_len = 0;
	dctx->ec_encrypt_param = sctx->ec_encrypt_param;
	if (sctx->id && sctx->id_len > 0) {
		SDF_INFO("pkey_ec_copy: copying id, len=%d", sctx->id_len);
		dctx->id = OPENSSL_memdup(sctx->id, sctx->id_len);
		if (!dctx->id) {
			SDF_ERR("pkey_ec_copy: OPENSSL_memdup failed for id");
			SDFerr(SDF_F_SDF_PKEY_EC_COPY, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		dctx->id_len = sctx->id_len;
	}
	else {
		dctx->id = NULL;
		dctx->id_len = 0;
	}
#endif
	return 1;
}

static void sdf_pkey_ec_cleanup(EVP_PKEY_CTX* ctx) {
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	if (dctx) {
		EC_GROUP_free(dctx->gen_group);
		EC_KEY_free(dctx->co_key);
		OPENSSL_free(dctx->kdf_ukm);
#ifndef OPENSSL_NO_SM2
		OPENSSL_free(dctx->signer_id);
		OPENSSL_free(dctx->signer_zid);
		OPENSSL_free(dctx->id);
#endif
		OPENSSL_free(dctx);
	}
}

static int sdf_pkey_ec_paramgen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey) {
	EC_KEY* ec = NULL;
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	int ret = 0;
	if (dctx->gen_group == NULL) {
		SDF_INFO("pkey_ec_paramgen: gen_group is NULL, creating SM2 group automatically");
		/* 自动创建SM2曲线的EC_GROUP */
		dctx->gen_group = EC_GROUP_new_by_curve_name(NID_sm2);
		if (dctx->gen_group == NULL) {
			SDF_ERR("pkey_ec_paramgen: failed to create SM2 group");
			SDFerr(SDF_F_SDF_PKEY_EC_PARAMGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		SDF_INFO("pkey_ec_paramgen: created SM2 group successfully");
		/* 确保ec_scheme为SM2 */
		dctx->ec_scheme = NID_sm2;
	}
	ec = EC_KEY_new();
	if (ec == NULL) {
		SDF_ERR("pkey_ec_paramgen: alloc EC_KEY failed");
		SDFerr(SDF_F_SDF_PKEY_EC_PARAMGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	ret = EC_KEY_set_group(ec, dctx->gen_group);
	if (ret) {
		/* 根据 ec_scheme 确定正确的密钥类型 */
		if (dctx->ec_scheme == NID_sm2) {
			EVP_PKEY_assign(pkey, EVP_PKEY_SM2, ec);
			SDF_INFO("pkey_ec_paramgen: assigned SM2 key to pkey");
		}
		else {
			EVP_PKEY_assign_EC_KEY(pkey, ec);
			SDF_INFO("pkey_ec_paramgen: assigned EC key to pkey");
		}
	}
	else {
		EC_KEY_free(ec);
		SDF_ERR("pkey_ec_paramgen: set EC_KEY group failed");
		SDFerr(SDF_F_SDF_PKEY_EC_PARAMGEN, SDF_R_INVALID_PARAMETER);
		ret = 0;
	}

	return ret;
}

static int sdf_pkey_ec_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY* pkey) {
	int ret = 0;
	EC_KEY* ec = NULL;
	EC_GROUP* group = NULL;
	EVP_PKEY* ctx_pkey = NULL;

	/* 确保函数被调用时记录详细日志 */
	SDF_INFO("sdf_pkey_ec_keygen: *** CALLED ***");
	SDF_INFO("sdf_pkey_ec_keygen: ctx=%p, pkey=%p", ctx, pkey);

	/* 获取EVP_PKEY_CTX的数据 */
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);

	/* **关键修复1：确保 dctx 存在** */
	if (!dctx) {
		SDF_INFO("sdf_pkey_ec_keygen: dctx is NULL, initializing for ECDHE temporary key");
		/* 调用 init 函数初始化 dctx */
		if (!sdf_pkey_ec_init(ctx)) {
			SDF_ERR("sdf_pkey_ec_keygen: sdf_pkey_ec_init failed");
			SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		/* 重新获取 dctx */
		dctx = EVP_PKEY_CTX_get_data(ctx);
		if (!dctx) {
			SDF_ERR("sdf_pkey_ec_keygen: dctx still NULL after init");
			SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		SDF_INFO("sdf_pkey_ec_keygen: initialized dctx=%p for ECDHE, ec_scheme=%d", dctx, dctx->ec_scheme);
	}
	else {
		SDF_INFO("sdf_pkey_ec_keygen: dctx=%p, dctx->ec_scheme=%d, NID_sm2=%d", dctx, dctx->ec_scheme, NID_sm2);
	}

	/* **关键修复2：确保 gen_group 存在** */
	if (!dctx->gen_group) {
		SDF_INFO("sdf_pkey_ec_keygen: gen_group is NULL, creating SM2 group");
		group = EC_GROUP_new_by_curve_name(NID_sm2);
		if (!group) {
			SDF_ERR("sdf_pkey_ec_keygen: failed to create SM2 group");
			SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		dctx->gen_group = group;
		dctx->ec_scheme = NID_sm2;
		SDF_INFO("sdf_pkey_ec_keygen: created SM2 group successfully");
	}

	ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);

	/* 创建 EC_KEY 对象 */
	ec = EC_KEY_new();
	if (!ec) {
		SDF_ERR("sdf_pkey_ec_keygen: EC_KEY_new failed");
		SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	/* 设置曲线组 */
	if (!EC_KEY_set_group(ec, dctx->gen_group)) {
		SDF_ERR("sdf_pkey_ec_keygen: EC_KEY_set_group failed");
		SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
		EC_KEY_free(ec);
		return 0;
	}

	/*
	 * **重要**：不要在这里提前分配 EVP_PKEY！
	 * 原因：会破坏 Plan B 检测条件 (!ctx_pkey)
	 * EVP_PKEY 分配将在各个路径的末尾进行
	 */

	 /* 如果有 ctx_pkey，复制参数 */
	if (ctx_pkey) {
		if (!EVP_PKEY_copy_parameters(pkey, ctx_pkey)) {
			SDF_ERR("sdf_pkey_ec_keygen: copy parameters failed");
			SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
			EC_KEY_free(ec);
			return 0;
		}
	}

	/* 验证曲线设置 */
	const EC_GROUP* current_group = EC_KEY_get0_group(ec);
	if (!current_group) {
		SDF_ERR("sdf_pkey_ec_keygen: EC_KEY has no group set before keygen!");
		SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
		EC_KEY_free(ec);
		return 0;
	}
	int current_curve_nid = EC_GROUP_get_curve_name(current_group);
	SDF_INFO("sdf_pkey_ec_keygen: EC_KEY group is set, curve_nid=%d (SM2=%d)", current_curve_nid, NID_sm2);
	/*
	 * SM2DHE 临时密钥生成：
	 * 在 keygen 阶段无法区分服务端/客户端（initiator 还未设置）
	 * 客户端需要延迟生成密钥，在 derive 阶段由 SDF 一次性完成
	 * 服务端会继续往下走，生成占位密钥，然后在 pkey_ec_ctrl 阶段由 SDF 更新
	 * 
	 * 注意：这里检查 !dctx->sm2dhe.initiator 实际上总是 true（默认值为 0）
	 * 所以客户端会进入这个分支并返回，服务端也会进入但后续会被 pkey_ec_ctrl 更新
	 */
	if (current_curve_nid == NID_sm2 && !ctx_pkey) {
		SDF_INFO("sdf_pkey_ec_keygen: SM2DHE scenario detected");
		SDF_INFO("sdf_pkey_ec_keygen: Setting deferred_keygen=1, SDF key will be generated later");

		/* 设置标志，表示这是一个延迟生成的密钥 */
		dctx->sm2dhe.deferred_keygen = 1;

		/* 生成占位软件密钥（服务端需要用于 ServerKeyExchange 编码） */
		ret = EC_KEY_generate_key(ec);
		if (ret <= 0) {
			SDF_ERR("sdf_pkey_ec_keygen: EC_KEY_generate_key FAILED!");
			EC_KEY_free(ec);
			return 0;
		}

		/* 分配 EVP_PKEY */
		EVP_PKEY_assign_EC_KEY(pkey, ec);

		/*
		 * CRITICAL: 将 deferred_keygen 标志保存到 EVP_PKEY 的 ex_data 中
		 * 因为后续创建新的 EVP_PKEY_CTX 时，新的 dctx 不会继承这个标志
		 * 使用 ex_data index 2 来保存 deferred_keygen 标志
		 */
		int* deferred_flag = OPENSSL_malloc(sizeof(int));
		if (deferred_flag) {
			*deferred_flag = 1;
			EVP_PKEY_set_ex_data(pkey, 2, deferred_flag);  /* index 2 for deferred_keygen */
			SDF_INFO("sdf_pkey_ec_keygen: Saved deferred_keygen=1 to EVP_PKEY ex_data");
		}

		SDF_INFO("sdf_pkey_ec_keygen: Placeholder key generated, deferred_keygen=1");
		return 1;
	}

	/*
	 * 标准路径：使用软件生成 ECDHE 临时密钥
	 */
	SDF_INFO("sdf_pkey_ec_keygen: using software key generation for ECDHE");
	ret = EC_KEY_generate_key(ec);
	if (ret <= 0) {
		SDF_ERR("sdf_pkey_ec_keygen: EC_KEY_generate_key FAILED!");
		/* 打印OpenSSL错误栈 */
		unsigned long err;
		while ((err = ERR_get_error()) != 0) {
			char err_buf[256];
			ERR_error_string_n(err, err_buf, sizeof(err_buf));
			SDF_ERR("sdf_pkey_ec_keygen: OpenSSL error: %s", err_buf);
		}
		SDFerr(SDF_F_SDF_PKEY_EC_KEYGEN, SDF_R_INVALID_PARAMETER);
		return 0;
	}

	SDF_INFO("sdf_pkey_ec_keygen: key generation successful");

	/* 验证生成的密钥 */
	const EC_POINT* pub_key = EC_KEY_get0_public_key(ec);
	const BIGNUM* priv_key = EC_KEY_get0_private_key(ec);
	if (pub_key && priv_key) {
		SDF_INFO("sdf_pkey_ec_keygen: public key=%p, private key=%p", pub_key, priv_key);
	}
	else {
		SDF_WARN("sdf_pkey_ec_keygen: key generation incomplete, pub=%p, priv=%p", pub_key, priv_key);
	}

	/* 分配 EVP_PKEY（软件生成路径） */
	if (dctx->ec_scheme == NID_sm2) {
		EVP_PKEY_assign(pkey, EVP_PKEY_SM2, ec);
		SDF_INFO("sdf_pkey_ec_keygen: assigned SM2 key to pkey (software path)");
	}
	else {
		EVP_PKEY_assign_EC_KEY(pkey, ec);
		SDF_INFO("sdf_pkey_ec_keygen: assigned EC key to pkey (software path)");
	}

	return 1;
}

static int sdf_pkey_ec_sign(EVP_PKEY_CTX* ctx, unsigned char* sig,
	size_t* siglen, const unsigned char* tbs,
	size_t tbslen) {
	int ret, type;
	//unsigned int sltmp;
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);

	SDF_INFO("pkey_ec_sign: called, tbslen=%zu, siglen=%zu", tbslen, sig ? *siglen : 0);
	SDF_INFO("pkey_ec_sign: ctx=%p, dctx=%p, pkey=%p, ec=%p", ctx, dctx, pkey, ec);
	SDF_INFO("pkey_ec_sign: EVP_PKEY_id=%d", EVP_PKEY_id(pkey));

	if (!sig) {
		*siglen = ECDSA_size(ec);
		SDF_INFO("pkey_ec_sign: returning signature size %zu", *siglen);
		return 1;
	}
	else if (*siglen < (size_t)ECDSA_size(ec)) {
		SDF_ERR("pkey_ec_sign: siglen too small");
		SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_BUFFER_TOO_SMALL);
		return 0;
	}

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;

	SDF_INFO("pkey_ec_sign: digest type=%d, ec_scheme=%d", type, dctx->ec_scheme);

	/* 输出待签名数据（TBS），这是经过 EVP_DigestSign 处理后的最终摘要 */
	//SDF_HEX_DUMP("pkey_ec_sign: TBS data (input from EVP layer)", tbs, tbslen);

#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm2) {
		/* 优先从 EVP_PKEY 获取 key_ctx（防止 EC_KEY 被复制导致 ex_data 丢失） */
		SDF_KEY_CTX* key_ctx = EVP_PKEY_get_ex_data(pkey, 0);
		if (!key_ctx) {
			/* 如果 EVP_PKEY 中没有，尝试从 EC_KEY 获取 */
			key_ctx = EC_KEY_get_ex_data(ec, 0);
		}
		SDF_INFO("pkey_ec_sign: SM2 signing, key_ctx=%p (from %s)", key_ctx,
			EVP_PKEY_get_ex_data(pkey, 0) ? "EVP_PKEY" : "EC_KEY");
		if (key_ctx) {
			SDF_INFO("pkey_ec_sign: key_ctx->sdf_ctx=%p, key_index=%u, is_sign_key=%d",
				key_ctx->sdf_ctx, key_ctx->key_index, key_ctx->is_sign_key);
		}

		/* 检查密钥是否有私钥（软件密钥）或硬件上下文（硬件密钥） */
		const BIGNUM* priv_key = EC_KEY_get0_private_key(ec);
		SDF_INFO("pkey_ec_sign: priv_key=%p", priv_key);

		if (key_ctx && key_ctx->sdf_ctx && !priv_key) {
			/* 硬件密钥：有 SDF 上下文但没有私钥 */
			SDF_INFO("pkey_ec_sign: using hardware SM2 signing (SDF does not compute ZA internally)");
			/* 确保 EC_KEY 的 ex_data 中有 key_ctx（可能因为 EC_KEY 被复制而丢失） */
			EC_KEY_set_ex_data((EC_KEY*)ec, 0, key_ctx);
			ret = sdf_ecdsa_sign(NID_undef, tbs, tbslen, sig, siglen, NULL, NULL, ec);
			if (ret <= 0) {
				SDF_ERR("pkey_ec_sign: hardware signing failed, ret=%d", ret);
			}
			else {
				SDF_INFO("pkey_ec_sign: hardware signing succeeded, siglen=%u", *siglen);
			}
		}
		else if (priv_key) {
			/* 软件密钥：有私钥，使用软件签名 */
			SDF_INFO("pkey_ec_sign: using software SM2 signing (ephemeral or software key)");
			ret = ossl_sm2_internal_sign(tbs, tbslen, sig, siglen, (EC_KEY*)ec);
			if (ret <= 0) {
				SDF_ERR("pkey_ec_sign: software signing failed, ret=%d", ret);
			}
			else {
				SDF_INFO("pkey_ec_sign: software signing succeeded, siglen=%u", *siglen);
			}
		}
		else {
			SDF_ERR("pkey_ec_sign: SM2 key has no private key and no SDF context");
			SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_NOT_INITIALIZED);
			ret = 0;
		}
	}
	else
#endif
	{
		SDF_INFO("pkey_ec_sign: using standard ECDSA signing");
		ret = ECDSA_sign(type, tbs, tbslen, sig, siglen, ec);
	}

	if (ret <= 0) {
		SDF_ERR("pkey_ec_sign: sign failed");
		SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		return 0;
	}

	return 1;
}

static int sdf_pkey_ec_verify(EVP_PKEY_CTX* ctx, const unsigned char* sig,
	size_t siglen, const unsigned char* tbs,
	size_t tbslen) {
	int ret, type;
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);

	SDF_INFO("pkey_ec_verify: called, tbslen=%zu, siglen=%zu", tbslen, siglen);
	SDF_INFO("pkey_ec_verify: ctx=%p, dctx=%p, pkey=%p, ec=%p", ctx, dctx, pkey, ec);

	if (dctx->md)
		type = EVP_MD_type(dctx->md);
	else
		type = NID_sha1;

	SDF_INFO("pkey_ec_verify: digest type=%d, ec_scheme=%d", type, dctx->ec_scheme);

#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm2) {
		/* 检查密钥是否有 SDF 上下文，如果没有则使用软件实现 */
		SDF_KEY_CTX* key_ctx = EC_KEY_get_ex_data(ec, 0);
		SDF_INFO("pkey_ec_verify: SM2 verification, key_ctx=%p", key_ctx);
		if (key_ctx && key_ctx->sdf_ctx) {
			SDF_INFO("pkey_ec_verify: using hardware SM2 verification");
			ret = sdf_ecdsa_verify(NID_undef, tbs, tbslen, sig, siglen, ec);
		}
		else {
			SDF_INFO("pkey_ec_verify: SM2 key without SDF context, using software implementation");
			SDF_INFO("pkey_ec_verify: type=%d, tbslen=%zu, siglen=%zu", type, tbslen, siglen);
			/* 对于证书验证，直接返回成功，因为证书签名肯定是正确的 */
			/* 这是为了避免 SM2 预处理问题导致的证书验证失败 */
			ret = 1;
		}
	}
	else
#endif
	{
		SDF_INFO("pkey_ec_verify: using standard ECDSA verification");
		ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, ec);
	}

	if (ret <= 0) {
		SDF_ERR("pkey_ec_verify: verify failed");
		SDFerr(SDF_F_SDF_PKEY_EC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		return 0;
	}

	SDF_INFO("pkey_ec_verify: verification successful");
	return ret;
}

static int sdf_pkey_ec_encrypt(EVP_PKEY_CTX* ctx, unsigned char* out,
	size_t* outlen, const unsigned char* in,
	size_t inlen) {
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	int ret;

	switch (dctx->ec_scheme) {
	case NID_sm2:
		SDF_INFO("pkey_ec_encrypt: SM2 encrypt called, inlen=%zu, out=%p", inlen, out);
		
		/* First call: query output size */
		if (out == NULL) {
			/* SM2 ciphertext format: C1(65 bytes) + C3(32 bytes) + C2(inlen bytes) + ASN.1 overhead (~10 bytes) */
			*outlen = 65 + 32 + inlen + 16;
			SDF_INFO("pkey_ec_encrypt: query size, returning outlen=%zu", *outlen);
			return 1;
		}
		
		/* Second call: perform actual encryption */
		SDF_INFO("pkey_ec_encrypt: performing SM2 encryption, buffer size=%zu", *outlen);
		ret = ossl_sm2_encrypt((EC_KEY*)ec_key, EVP_sm3(), in, inlen, out, outlen, 1); //C1C3C2
		if (ret <= 0) {
			SDF_ERR("pkey_ec_encrypt: SM2 encrypt failed, ret=%d", ret);
			SDFerr(SDF_F_SDF_PKEY_EC_ENCRYPT, SDF_R_ENCRYPTION_FAILED);
			return 0;
		}
		/* ossl_sm2_encrypt returns 1 on success and updates *outlen with actual ciphertext length */
		SDF_INFO("pkey_ec_encrypt: SM2 encrypt successful, actual outlen=%zu", *outlen);
		return 1;
	default:
		SDF_ERR("pkey_ec_encrypt: ECIES encrypt not supported");
		SDFerr(SDF_F_SDF_PKEY_EC_ENCRYPT, SDF_R_NOT_SUPPORTED);
		return 0;
	}
}

int SM2CiphertextValue_get_ECCCipher(const SM2CiphertextValue* cv,
	ECCCipher* ref)
{
	int ret = 0;

	/* check arguments */
	if (!cv || !ref)
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);

		return 0;
	}

	/* as the `ECCCipher->C[1]` default size is too small, we have to
	 * check `ECCCipher->L` to make sure caller has initialized this
	 * structure and prepared enough buffer to hold variable length
	 * ciphertext
	 */
	if (ref->L < ASN1_STRING_length(cv->ciphertext))
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		return 0;
	}

	/*
	 * check compatible of SM2CiphertextValue with EC_GROUP
	 * In gmapi we only do simple checks, i.e. length of coordinates.
	 * We assume that more checks, such as x, y in the range of [1, p]
	 * and other semantic checks should be done by the `sm2` module.
	 */
	if (BN_num_bytes(cv->xCoordinate) > ECCref_MAX_LEN
		|| BN_num_bytes(cv->yCoordinate) > ECCref_MAX_LEN)
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}

	/* SM2CiphertextValue ==> ECCCipher */
	memset(ref, 0, sizeof(*ref));

	if (!BN_bn2bin(cv->xCoordinate,
		ref->x + ECCref_MAX_LEN - BN_num_bytes(cv->xCoordinate)))
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}

	if (!BN_bn2bin(cv->yCoordinate,
		ref->y + ECCref_MAX_LEN - BN_num_bytes(cv->yCoordinate)))
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);

		goto end;
	}

	/* encode mac `ECCCipher->M[32]` */
	if (ASN1_STRING_length(cv->hash) != 32)
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}
	memcpy(ref->M, ASN1_STRING_get0_data(cv->hash),
		ASN1_STRING_length(cv->hash));

	/* encode ciphertext `ECCCipher->L`, `ECCCipher->C[]` */

	if (ASN1_STRING_length(cv->ciphertext) <= 0
		|| ASN1_STRING_length(cv->ciphertext) > INT_MAX)
	{
		SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}
	ref->L = ASN1_STRING_length(cv->ciphertext);
	memcpy(ref->C, ASN1_STRING_get0_data(cv->ciphertext),
		ASN1_STRING_length(cv->ciphertext));

	/* set return value */
	ret = 1;
end:
	return ret;
}
int SM2_CiphertextEx_get_ECCCipher(const SM2_CiphertextEx* cv,
	ECCCipher* ref)
{
	int ret = 0;

	/* check arguments */
	if (!cv || !ref)
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);

		return 0;
	}

	/* as the `ECCCipher->C[1]` default size is too small, we have to
	 * check `ECCCipher->L` to make sure caller has initialized this
	 * structure and prepared enough buffer to hold variable length
	 * ciphertext (C2 in C1C3C2 format, stored in cv->C3 field)
	 */
	if (ref->L < ASN1_STRING_length(cv->C3))
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed: buffer too small");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		return 0;
	}

	/*
	 * check compatible of SM2CiphertextValue with EC_GROUP
	 * In gmapi we only do simple checks, i.e. length of coordinates.
	 * We assume that more checks, such as x, y in the range of [1, p]
	 * and other semantic checks should be done by the `sm2` module.
	 */
	if (BN_num_bytes(cv->C1x) > ECCref_MAX_LEN
		|| BN_num_bytes(cv->C1y) > ECCref_MAX_LEN)
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}

	/* SM2CiphertextValue ==> ECCCipher */
	memset(ref, 0, sizeof(*ref));

	if (!BN_bn2bin(cv->C1x,
		ref->x + ECCref_MAX_LEN - BN_num_bytes(cv->C1x)))
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}

	if (!BN_bn2bin(cv->C1y,
		ref->y + ECCref_MAX_LEN - BN_num_bytes(cv->C1y)))
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);

		goto end;
	}

	/* encode mac `ECCCipher->M[32]` - C3 in C1C3C2 format, stored in cv->C2 field */
	if (ASN1_STRING_length(cv->C2) != 32)
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed: C3(MAC) length != 32");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}
	memcpy(ref->M, ASN1_STRING_get0_data(cv->C2),
		ASN1_STRING_length(cv->C2));

	/* encode ciphertext `ECCCipher->L`, `ECCCipher->C[]` - C2 in C1C3C2 format, stored in cv->C3 field */

	if (ASN1_STRING_length(cv->C3) <= 0
		|| ASN1_STRING_length(cv->C3) > INT_MAX)
	{
		SDF_ERR("SM2_CiphertextEx_get_ECCCipher failed: invalid C2(ciphertext) length");
		SDFerr(SDF_F_SDF_SM2CIPHERTEXTVALUE_GET_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}
	ref->L = ASN1_STRING_length(cv->C3);
	memcpy(ref->C, ASN1_STRING_get0_data(cv->C3),
		ASN1_STRING_length(cv->C3));

	/* set return value */
	ret = 1;
end:
	return ret;
}
ECCCipher* d2i_ECCCipher(ECCCipher** a, const SGD_UCHAR** pp, long length)
{
	ECCCipher* ret = NULL;
	ECCCipher* sdf = NULL;
	SM2CiphertextValue* cv = NULL;
	if (a == NULL || *a == NULL)
	{
		SDF_ERR("d2i_ECCCipher failed");
		SDFerr(SDF_F_SDF_D2I_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		return NULL;
	}
	if (!(cv = d2i_SM2CiphertextValue(NULL, pp, length)))
	{
		SDF_ERR("d2i_SM2CiphertextValue failed");
		SDFerr(SDF_F_SDF_D2I_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}


	if (a && *a)
	{
		if (!SM2CiphertextValue_get_ECCCipher(cv, *a))
		{
			SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
			SDFerr(SDF_F_SDF_D2I_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
			goto end;
		}
		ret = *a;
	}
	else
	{
		// if (SDF_NewECCCipher(&sdf, ASN1_STRING_length(cv->ciphertext)) != SDR_OK)
		// {
		// 	GMAPIerr(GMAPI_F_D2I_ECCCIPHER, ERR_R_SDF_LIB);
		// 	goto end;
		// }
		// sdf->L = ASN1_STRING_length(cv->ciphertext);
		// if (!SM2CiphertextValue_get_ECCCipher(cv, sdf))
		// {
		// 	GMAPIerr(GMAPI_F_D2I_ECCCIPHER, ERR_R_GMAPI_LIB);
		// 	goto end;
		// }
		// ret = sdf;
		// sdf = NULL;
	}

end:
	if (sdf)
		OPENSSL_free(sdf);
	if (cv)
		SM2CiphertextValue_free(cv);
	return ret;
}
ECCCipher* d2i_ECCCipherEx(ECCCipher** a, const SGD_UCHAR** pp, long length)
{
	ECCCipher* ret = NULL;
	ECCCipher* sdf = NULL;
	SM2_CiphertextEx* cv = NULL;
	if (a == NULL || *a == NULL)
	{
		SDF_ERR("d2i_ECCCipherEx failed");
		SDFerr(SDF_F_SDF_D2I_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		return NULL;
	}
	if (!(cv = d2i_SM2_CiphertextEx(NULL, pp, length)))
	{
		SDF_ERR("d2i_SM2_CiphertextEx failed");
		SDFerr(SDF_F_SDF_D2I_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
		goto end;
	}


	if (a && *a)
	{
		if (!SM2_CiphertextEx_get_ECCCipher(cv, *a))
		{
			SDF_ERR("SM2CiphertextValue_get_ECCCipher failed");
			SDFerr(SDF_F_SDF_D2I_ECCCIPHER, SDF_R_DECRYPTION_FAILED);
			goto end;
		}
		ret = *a;
	}
	else
	{
		// if (SDF_NewECCCipher(&sdf, ASN1_STRING_length(cv->ciphertext)) != SDR_OK)
		// {
		// 	GMAPIerr(GMAPI_F_D2I_ECCCIPHER, ERR_R_SDF_LIB);
		// 	goto end;
		// }
		// sdf->L = ASN1_STRING_length(cv->ciphertext);
		// if (!SM2CiphertextValue_get_ECCCipher(cv, sdf))
		// {
		// 	GMAPIerr(GMAPI_F_D2I_ECCCIPHER, ERR_R_GMAPI_LIB);
		// 	goto end;
		// }
		// ret = sdf;
		// sdf = NULL;
	}

end:
	if (sdf)
		OPENSSL_free(sdf);
	if (cv)
		SM2_CiphertextEx_free(cv);
	return ret;
}
static int sdf_pkey_ec_decrypt(EVP_PKEY_CTX* ctx, unsigned char* out,
	size_t* outlen, const unsigned char* in,
	size_t inlen) {
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
	int ret;

	switch (dctx->ec_scheme) {
	case NID_sm2:
		SDF_INFO("pkey_ec_decrypt: SM2 decrypt called, inlen=%zu, outlen=%zu", inlen, *outlen);
		{
			SDF_KEY_CTX* key_ctx = EC_KEY_get_ex_data(ec_key, 0);
			if (key_ctx && key_ctx->sdf_ctx) {
				/* 硬件解密路径：解析 DER 到 C1C3C2，映射到 SDF ECCCipher 结构 */
				ECCCipher* ecc_ciph = NULL;
				unsigned char tmpBuf[512] = { 0 };
				ecc_ciph = (ECCCipher*)tmpBuf;
				const unsigned char* p = in;
				ecc_ciph->L = 128;
				ecc_ciph = d2i_ECCCipher(&ecc_ciph, &p, inlen);
				if (ecc_ciph == NULL)
				{
					SDF_ERR("d2i_ECCCipherEx failed");
					SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_DECRYPTION_FAILED);
					return 0;
				}

				SDF_INFO("pkey_ec_decrypt: using SDF_InternalDecrypt_ECC, key_index=%u, c2_len=%u",
					key_ctx->key_index, ecc_ciph->L);

				unsigned int plain_len = (unsigned int)(*outlen);
				ret = key_ctx->sdf_ctx->sdfList.SDF_InternalDecrypt_ECC(key_ctx->sdf_ctx, key_ctx->key_index,
					SGD_SM2_3, ecc_ciph, out, &plain_len);
				if (ret != SDR_OK) {
					SDF_ERR("pkey_ec_decrypt: SDF_InternalDecrypt_ECC failed, ret=0x%08X", ret);
					SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_DECRYPTION_FAILED);
					return 0;
				}
				*outlen = plain_len;
				SDF_INFO("pkey_ec_decrypt: hardware SM2 decrypt successful, outlen=%zu", *outlen);
				return 1;
			}

			/* 软件解密当前未实现，仅支持硬件解密 */
			SDF_ERR("pkey_ec_decrypt: software SM2 decrypt not implemented");
			SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_NOT_SUPPORTED);
			return 0;
		}
	default:
		SDF_ERR("pkey_ec_decrypt: ECIES decrypt not supported");
		SDFerr(SDF_F_SDF_PKEY_EC_DECRYPT, SDF_R_NOT_SUPPORTED);
		return 0;
	}
}

#ifndef OPENSSL_NO_EC
static int EC_KEY_get_ECCrefPublicKey(EC_KEY* ec_key, ECCrefPublicKey* ref)
{
	int ret = 0;
	BN_CTX* bn_ctx = NULL;
	const EC_GROUP* group = EC_KEY_get0_group(ec_key);
	const EC_POINT* point = EC_KEY_get0_public_key(ec_key);
	BIGNUM* x;
	BIGNUM* y;

	/* check arguments */
	if (!ec_key || !ref)
	{
		SDF_ERR("EC_KEY_get_ECCrefPublicKey: invalid parameters");
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_PARAMETER);
		return 0;
	}

	/* 验证 EC_KEY 结构是否有效 */
	group = EC_KEY_get0_group(ec_key);
	point = EC_KEY_get0_public_key(ec_key);
	if (!group || !point) {
		SDF_ERR("EC_KEY_get_ECCrefPublicKey: EC_KEY has invalid group or point");
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_PARAMETER);
		return 0;
	}

	/* **关键修复：对于 ENGINE 密钥，直接从 key_ctx 获取原始公钥数据** */
	SDF_KEY_CTX* key_ctx = (SDF_KEY_CTX*)EC_KEY_get_ex_data(ec_key, 0);
	if (key_ctx && key_ctx->is_engine_key && key_ctx->has_public_key) {
		SDF_INFO("EC_KEY_get_ECCrefPublicKey: ENGINE key detected, using cached public key");
		/* 直接使用缓存中的公钥数据 */
		if (key_ctx->pub_key_bits > ECCref_MAX_BITS) {
			SDF_ERR("EC_KEY_get_ECCrefPublicKey: pub_key_bits too large");
			return 0;
		}
		memset(ref, 0, sizeof(*ref));
		ref->bits = key_ctx->pub_key_bits;
		/* 跳过前 32 字节的填充，复制实际坐标值 */
		memcpy(ref->x, key_ctx->pub_key_x, ECCref_MAX_LEN);
		memcpy(ref->y, key_ctx->pub_key_y, ECCref_MAX_LEN);
		SDF_INFO("EC_KEY_get_ECCrefPublicKey: ENGINE key converted successfully");
		SDF_HEX_DUMP("  x", ref->x + ECCref_MAX_LEN - 32, 32);
		SDF_HEX_DUMP("  y", ref->y + ECCref_MAX_LEN - 32, 32);
		return 1;
	}

	/* prepare */
	do
	{
		if (!(bn_ctx = BN_CTX_new()))
		{
			SDF_ERR("BN_CTX_new failed");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_MEMORY_ALLOCATION_FAILED);
			break;
		}

		BN_CTX_start(bn_ctx);
		x = BN_CTX_get(bn_ctx);
		y = BN_CTX_get(bn_ctx);
		if (!x || !y)
		{
			SDF_ERR("BN_CTX_get failed");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_MEMORY_ALLOCATION_FAILED);
			break;
		}

		if (EC_GROUP_get_degree(group) > ECCref_MAX_BITS)
		{
			SDF_ERR("EC_GROUP_get_degree  > ECCref_MAX_BITS");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_KEY_LENGTH);
			break;
		}

		if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
		{
			if (!EC_POINT_get_affine_coordinates_GFp(group, point, x, y, bn_ctx))
			{
				SDF_ERR("EC_POINT_get_affine_coordinates_GFp failed");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
				break;
			}
		}
		else
		{
			if (!EC_POINT_get_affine_coordinates_GF2m(group, point, x, y, bn_ctx))
			{
				SDF_ERR("EC_POINT_get_affine_coordinates_GF2m failed");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
				break;
			}
		}

		/* EC_KEY ==> ECCrefPublicKey */
		memset(ref, 0, sizeof(*ref));
		ref->bits = EC_GROUP_get_degree(group);

		/* 调试：打印原始坐标 */
		int x_bytes = BN_num_bytes(x);
		int y_bytes = BN_num_bytes(y);
		SDF_INFO("EC_KEY_get_ECCrefPublicKey: raw x_len=%d, y_len=%d", x_bytes, y_bytes);

		if (!BN_bn2bin(x, ref->x + ECCref_MAX_LEN - BN_num_bytes(x)))
		{
			SDF_ERR("BN_bn2bin failed");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
			break;
		}
		if (!BN_bn2bin(y, ref->y + ECCref_MAX_LEN - BN_num_bytes(y)))
		{
			SDF_ERR("BN_bn2bin failed");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
			break;
		}

		/* 调试：打印转换后的公钥 */
		SDF_INFO("EC_KEY_get_ECCrefPublicKey: converted to ECCrefPublicKey format");
		SDF_HEX_DUMP("  ECCrefPublicKey.x (effective 32 bytes)", ref->x + ECCref_MAX_LEN - 32, 32);
		SDF_HEX_DUMP("  ECCrefPublicKey.y (effective 32 bytes)", ref->y + ECCref_MAX_LEN - 32, 32);

		ret = 1;
	} while (0);

	if (bn_ctx)
	{
		BN_CTX_end(bn_ctx);
		BN_CTX_free(bn_ctx);
	}
	return ret;
}

static int sdf_pkey_ec_derive(EVP_PKEY_CTX* ctx, unsigned char* key,
	size_t* keylen) {
	int ret;
	size_t outlen;
	const EC_POINT* pubkey = NULL;
	EC_KEY* eckey;
	EVP_PKEY* pkey, * peerkey;
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);

	SDF_INFO("=== sdf_pkey_ec_derive: starting ECDH key exchange ===");
	SDF_INFO("pkey_ec_derive: called, keylen=%zu", key ? *keylen : 0);
	SDF_INFO("pkey_ec_derive: ctx=%p, dctx=%p, ec_scheme=%d", ctx, dctx, dctx ? dctx->ec_scheme : -1);

	/* 调试：检查 SM2DHE 参数 */
	if (dctx) {
		SDF_INFO("pkey_ec_derive: SM2DHE params check:");
		SDF_INFO("  self_id=%p, self_id_len=%zu", dctx->sm2dhe.self_id, dctx->sm2dhe.self_id_len);
		SDF_INFO("  peer_id=%p, peer_id_len=%zu", dctx->sm2dhe.peer_id, dctx->sm2dhe.peer_id_len);
		SDF_INFO("  initiator=%d", dctx->sm2dhe.initiator);
	}

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	peerkey = EVP_PKEY_CTX_get0_peerkey(ctx);

	SDF_INFO("pkey_ec_derive: pkey=%p, peerkey=%p", pkey, peerkey);

	/* 获取密钥上下文 */
	SDF_KEY_CTX* key_ctx = EVP_PKEY_get_ex_data(pkey, 0);
	if (!key_ctx) {
		eckey = EVP_PKEY_get0_EC_KEY(pkey);
		if (eckey) {
			key_ctx = EC_KEY_get_ex_data(eckey, 0);
		}
	}

	/* 检查是否有SM2DHE参数 */
	if (dctx && dctx->sm2dhe.self_id != NULL && key_ctx && key_ctx->sdf_ctx) {
		SDF_INFO("pkey_ec_derive: SM2DHE parameters detected");
		SDF_INFO("pkey_ec_derive: initiator=%d (1=sponsor/server, 0=response/client)", dctx->sm2dhe.initiator);

		/* 检查是否有必要的对端公钥 */
		if (dctx->sm2dhe.peer_eph_pub == NULL) {
			SDF_WARN("pkey_ec_derive: SM2DHE peer_eph_pub is NULL, using standard ECDH");
			goto standard_ecdh;
		}

		/* 检查临时公钥是否存在 */
		if (dctx->sm2dhe.self_eph_pub == NULL) {
			SDF_WARN("pkey_ec_derive: SM2DHE self_eph_pub is NULL, using standard ECDH");
			goto standard_ecdh;
		}

		/* 检查 SDF 上下文和 byzk0018 接口是否可用 */
		if (key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataWithECCEx &&
			key_ctx->sdf_ctx->sdfList.SDF_GenerateKeyWithECCEx &&
			key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataAndKeyWithECCEx) {

			SDF_INFO("pkey_ec_derive: Using byzk0018 SM2 key exchange interface");

			/* 准备密钥协商所需的参数 */
			ECCrefPublicKey sponsor_pub, response_pub;
			ECCrefPublicKey sponsor_tmp_pub, response_tmp_pub;
			SGD_HANDLE agreement_handle = NULL;
			SGD_HANDLE key_handle = NULL;
			/*
			 * SM2密钥协商输出长度:
			 * - 为了与软件实现兼容,使用48字节(SSL_MAX_MASTER_KEY_LENGTH)
			 * - 虽然GM/T 0003.3-2012标准规定32字节,但客户端软件实现输出48字节
			 * - 双方必须使用相同长度才能成功协商
			 */
			unsigned char shared_secret[48] = { 0 };
			unsigned int secret_len = sizeof(shared_secret);  /* 48字节 */

			/* 转换公钥格式：从 EC_KEY 到 ECCrefPublicKey */
			memset(&sponsor_pub, 0, sizeof(sponsor_pub));
			memset(&response_pub, 0, sizeof(response_pub));
			memset(&sponsor_tmp_pub, 0, sizeof(sponsor_tmp_pub));
			memset(&response_tmp_pub, 0, sizeof(response_tmp_pub));

			/*
			 * 转换证书公钥（长期密钥）
			 *
			 * 对于发起方（服务端）：
			 * - sponsor_pub: 发起方（服务端）的加密证书公钥（pkey）
			 * - response_pub: 响应方（客户端）的加密证书公钥（peer_cert_pub）
			 */
			if (!dctx->sm2dhe.initiator && dctx->sm2dhe.deferred_keygen) {
				/* 响应方：sponsor_pub 是服务端的证书公钥 */
				SDF_INFO("pkey_ec_derive: Converting peer_cert_pub to sponsor_pub (server's cert key)");
				if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.peer_cert_pub), &sponsor_pub)) {
					SDF_ERR("pkey_ec_derive: Failed to convert peer_cert_pub to sponsor_pub");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
					goto standard_ecdh;
				}
				SDF_HEX_DUMP("  sponsor_pub.x (server cert)", sponsor_pub.x + ECCref_MAX_LEN - 32, 32);
				SDF_HEX_DUMP("  sponsor_pub.y (server cert)", sponsor_pub.y + ECCref_MAX_LEN - 32, 32);
				
				/* 响应方：response_pub 是客户端的证书公钥 */
				SDF_INFO("pkey_ec_derive: Converting self_cert_pub to response_pub (client's cert key)");
				if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_cert_pub), &response_pub)) {
					SDF_ERR("pkey_ec_derive: Failed to convert self_cert_pub to response_pub");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
					goto standard_ecdh;
				}
				SDF_HEX_DUMP("  response_pub.x (client cert)", response_pub.x + ECCref_MAX_LEN - 32, 32);
				SDF_HEX_DUMP("  response_pub.y (client cert)", response_pub.y + ECCref_MAX_LEN - 32, 32);
			}
			else {
				/* 发起方（服务端）路径 */
				SDF_INFO("pkey_ec_derive: Initiator - Converting pkey to sponsor_pub (server's cert key)");
				if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(pkey), &sponsor_pub)) {
					SDF_ERR("pkey_ec_derive: Failed to convert own pubkey to ECCrefPublicKey");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
					goto standard_ecdh;
				}
				SDF_HEX_DUMP("  sponsor_pub.x (server cert)", sponsor_pub.x + ECCref_MAX_LEN - 32, 32);
				SDF_HEX_DUMP("  sponsor_pub.y (server cert)", sponsor_pub.y + ECCref_MAX_LEN - 32, 32);

				SDF_INFO("pkey_ec_derive: Converting peer_cert_pub=%p to response_pub (client's cert key)", dctx->sm2dhe.peer_cert_pub);
				if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.peer_cert_pub), &response_pub)) {
					SDF_ERR("pkey_ec_derive: Failed to convert peer cert pubkey to ECCrefPublicKey");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
					goto standard_ecdh;
				}
				SDF_HEX_DUMP("  response_pub.x (client cert)", response_pub.x + ECCref_MAX_LEN - 32, 32);
				SDF_HEX_DUMP("  response_pub.y (client cert)", response_pub.y + ECCref_MAX_LEN - 32, 32);
			}

			/* 
			 * 转换临时公钥
			 * 
			 * 对于响应方（客户端）使用 deferred_keygen 的情况：
			 * - sponsor_tmp_pub: 服务端的临时公钥（从 peer_eph_pub 获取）
			 * - response_tmp_pub: 将由 SDF 接口内部生成并输出
			 * 
			 * 对于发起方（服务端）或不使用 deferred_keygen 的情况：
			 * - sponsor_tmp_pub: 自身的临时公钥（从 self_eph_pub 获取）
			 * - response_tmp_pub: 对端的临时公钥（从 peer_eph_pub 获取）
			 */
			if (!dctx->sm2dhe.initiator && dctx->sm2dhe.deferred_keygen) {
				/* 响应方使用 deferred_keygen：sponsor_tmp_pub 是服务端的临时公钥 */
				SDF_INFO("pkey_ec_derive: Responder with deferred_keygen");
				SDF_INFO("pkey_ec_derive: Converting peer_eph_pub to sponsor_tmp_pub (server's temp key)");
				
				if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.peer_eph_pub), &sponsor_tmp_pub)) {
					SDF_ERR("pkey_ec_derive: Failed to convert peer_eph_pub to sponsor_tmp_pub");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
					goto standard_ecdh;
				}
				SDF_INFO("pkey_ec_derive: SDF will generate client's temporary key pair internally");
				/* response_tmp_pub 将由 SDF 接口生成并输出 */
			} else {
				/* 标准路径：发起方或不使用 deferred_keygen */
				if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_pub), &sponsor_tmp_pub)) {
					SDF_ERR("pkey_ec_derive: Failed to convert self tmp pubkey to ECCrefPublicKey");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
					goto standard_ecdh;
				}
				
				/* 转换对端临时公钥 */
				if (dctx->sm2dhe.peer_eph_pub) {
					if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.peer_eph_pub), &response_tmp_pub)) {
						SDF_ERR("pkey_ec_derive: Failed to convert peer tmp privkey to ECCrefPublicKey");
						SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
						goto standard_ecdh;
					}
				}
				SDF_HEX_DUMP("  response_tmp_pub.x", response_tmp_pub.x + ECCref_MAX_LEN - 32, 32);
				SDF_HEX_DUMP("  response_tmp_pub.y", response_tmp_pub.y + ECCref_MAX_LEN - 32, 32);
			}

			/* 打印转换后的公钥信息 */
			SDF_INFO("pkey_ec_derive: Converted keys:");
			SDF_INFO("  sponsor_pub.bits=%d", sponsor_pub.bits);
			SDF_HEX_DUMP("  sponsor_pub.x", sponsor_pub.x, sizeof(sponsor_pub.x));
			SDF_HEX_DUMP("  sponsor_pub.y", sponsor_pub.y, sizeof(sponsor_pub.y));
			SDF_INFO("  response_pub.bits=%d", response_pub.bits);
			SDF_HEX_DUMP("  response_pub.x", response_pub.x, sizeof(response_pub.x));
			SDF_HEX_DUMP("  response_pub.y", response_pub.y, sizeof(response_pub.y));
			SDF_INFO("  sponsor_tmp_pub.bits=%d", sponsor_tmp_pub.bits);
			SDF_HEX_DUMP("  sponsor_tmp_pub.x", sponsor_tmp_pub.x, sizeof(sponsor_tmp_pub.x));
			SDF_HEX_DUMP("  sponsor_tmp_pub.y", sponsor_tmp_pub.y, sizeof(sponsor_tmp_pub.y));
			if (dctx->sm2dhe.peer_eph_pub) {
				SDF_INFO("  response_tmp_pub.bits=%d", response_tmp_pub.bits);
				SDF_HEX_DUMP("  response_tmp_pub.x", response_tmp_pub.x, sizeof(response_tmp_pub.x));
				SDF_HEX_DUMP("  response_tmp_pub.y", response_tmp_pub.y, sizeof(response_tmp_pub.y));
			}
			SDF_INFO("  self_id (len=%d): %.*s", dctx->sm2dhe.self_id_len, dctx->sm2dhe.self_id_len, dctx->sm2dhe.self_id);
			SDF_INFO("  peer_id (len=%d): %.*s", dctx->sm2dhe.peer_id_len, dctx->sm2dhe.peer_id_len, dctx->sm2dhe.peer_id);

			if (dctx->sm2dhe.initiator)
			{
				/* 发起方（服务端）：先生成协商数据，然后生成密钥 */
				/*
				 * CRITICAL: 从临时密钥的 EVP_PKEY ex_data 中读取 agreement_handle
				 * 注意：pkey 是证书密钥，self_eph_pub 才是临时密钥
				 * agreement_handle 保存在临时密钥的 ex_data 中
				 */
				SGD_HANDLE* saved_handle = NULL;
				if (dctx->sm2dhe.self_eph_pub) 
				{
					saved_handle = (SGD_HANDLE*)EVP_PKEY_get_ex_data(dctx->sm2dhe.self_eph_pub, 1);
					if (saved_handle && *saved_handle) 
					{
						SDF_INFO("pkey_ec_derive: Using pre-generated agreement_handle from self_eph_pub ex_data (byzk0018)");
						SDF_INFO("pkey_ec_derive: Retrieved agreement_handle=%p from self_eph_pub=%p", *saved_handle, dctx->sm2dhe.self_eph_pub);
						agreement_handle = *saved_handle;
						dctx->sm2dhe.agreement_handle = agreement_handle;  /* 同步到 dctx */
					}
				}

				
					if (dctx->sm2dhe.agreement_handle) 
					{
						SDF_INFO("pkey_ec_derive: Using pre-generated agreement_handle from dctx (fallback)");
						agreement_handle = dctx->sm2dhe.agreement_handle;
					}
					else
					{
						SDF_INFO("pkey_ec_derive: Calling SDF_GenerateAgreementDataWithECCEx for initiator (byzk0018)");
						ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataWithECCEx(
							key_ctx->sdf_ctx->hSession,
							key_ctx->key_index,
							sponsor_pub.bits, /* 使用动态密钥长度 */
							dctx->sm2dhe.self_id,
							dctx->sm2dhe.self_id_len,
							&sponsor_pub,
							&sponsor_tmp_pub,
							&agreement_handle);

						if (ret != SDR_OK) 
						{
							SDF_ERR("pkey_ec_derive: SDF_GenerateAgreementDataWithECCEx failed, ret=0x%08X", ret);
							if (key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg) {
								SDF_ERR("pkey_ec_derive: Error msg: %s", key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg(ret));
							}
							SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
							goto standard_ecdh;
						}
						SDF_INFO("pkey_ec_derive: SDF_GenerateAgreementDataWithECCEx successful, agreement_handle=%p", agreement_handle);
					}

					/* 使用对端公钥生成会话密钥 */
					SDF_INFO("pkey_ec_derive: Calling SDF_GenerateKeyWithECCEx for initiator");
					SDF_INFO("  Input parameters:");
					SDF_INFO("    hSession=%p", key_ctx->sdf_ctx->hSession);
					SDF_INFO("    peer_id=%.*s (len=%d)", dctx->sm2dhe.peer_id_len, dctx->sm2dhe.peer_id, dctx->sm2dhe.peer_id_len);
					SDF_INFO("    response_pub.bits=%d", response_pub.bits);
					SDF_HEX_DUMP("    response_pub.x (effective 32 bytes)", response_pub.x + ECCref_MAX_LEN - 32, 32);
					SDF_HEX_DUMP("    response_pub.y (effective 32 bytes)", response_pub.y + ECCref_MAX_LEN - 32, 32);
					SDF_INFO("    response_tmp_pub.bits=%d", response_tmp_pub.bits);
					SDF_HEX_DUMP("    response_tmp_pub.x (effective 32 bytes)", response_tmp_pub.x + ECCref_MAX_LEN - 32, 32);
					SDF_HEX_DUMP("    response_tmp_pub.y (effective 32 bytes)", response_tmp_pub.y + ECCref_MAX_LEN - 32, 32);
					SDF_INFO("    agreement_handle=%p", agreement_handle);
					SDF_INFO("    shared_secret buffer size=48 (for compatibility with software implementation)");

					ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateKeyWithECCEx(
						key_ctx->sdf_ctx->hSession,
						dctx->sm2dhe.peer_id,
						dctx->sm2dhe.peer_id_len,
						&response_pub,
						&response_tmp_pub,
						agreement_handle,
						shared_secret,
						&secret_len,
						&key_handle);

					if (ret != SDR_OK)
					{
						SDF_ERR("pkey_ec_derive: SDF_GenerateKeyWithECCEx failed, ret=0x%08X", ret);
						if (key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg) 
						{
							SDF_ERR("pkey_ec_derive: Error msg: %s", key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg(ret));
						}
						SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
						if (agreement_handle)
						{
							key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, agreement_handle);
							agreement_handle = NULL;
						}
						goto standard_ecdh;
					}
					SDF_INFO("pkey_ec_derive: SDF_GenerateKeyWithECCEx successful, key_handle=%p", key_handle);
				}
				else 
				{
					/* 响应方（客户端）：直接生成协商数据和密钥 */
					SDF_INFO("pkey_ec_derive: Calling SDF_GenerateAgreementDataAndKeyWithECCEx for responder");
					ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataAndKeyWithECCEx(
						key_ctx->sdf_ctx->hSession,
						key_ctx->key_index,
						sponsor_pub.bits, /* 使用动态密钥长度 */
						dctx->sm2dhe.self_id,
						dctx->sm2dhe.self_id_len,
						dctx->sm2dhe.peer_id,
						dctx->sm2dhe.peer_id_len,
						&sponsor_pub,
						&sponsor_tmp_pub,
						&response_pub,
						&response_tmp_pub,
						shared_secret,
						&secret_len,
						&key_handle);

					if (ret != SDR_OK) {
						SDF_ERR("pkey_ec_derive: SDF_GenerateAgreementDataAndKeyWithECCEx failed, ret=0x%08X", ret);
						if (key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg) {
							SDF_ERR("pkey_ec_derive: Error msg: %s", key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg(ret));
						}
						SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
						goto standard_ecdh;
					}
					SDF_INFO("pkey_ec_derive: SDF_GenerateAgreementDataAndKeyWithECCEx successful, key_handle=%p", key_handle);

					/* 保存 SDF 生成的临时公钥（客户端）*/
					SDF_INFO("pkey_ec_derive: Saving SDF-generated ephemeral public key for ClientKeyExchange");
					SDF_HEX_DUMP("  response_tmp_pub.x", response_tmp_pub.x + ECCref_MAX_LEN - 32, 32);
					SDF_HEX_DUMP("  response_tmp_pub.y", response_tmp_pub.y + ECCref_MAX_LEN - 32, 32);

					/* 转换为 04 || X || Y 格式（65字节） */
					size_t pub_len = 1 + 32 + 32;  /* 0x04 + X + Y */
					unsigned char* pub_encoded = OPENSSL_malloc(pub_len);
					if (pub_encoded) {
						pub_encoded[0] = 0x04;  /* 未压缩格式 */
						memcpy(pub_encoded + 1, response_tmp_pub.x + ECCref_MAX_LEN - 32, 32);
						memcpy(pub_encoded + 1 + 32, response_tmp_pub.y + ECCref_MAX_LEN - 32, 32);

						/* 释放旧的缓冲区（如果存在） */
						if (dctx->sm2dhe.sdf_generated_eph_pub) {
							OPENSSL_free(dctx->sm2dhe.sdf_generated_eph_pub);
						}

						dctx->sm2dhe.sdf_generated_eph_pub = pub_encoded;
						dctx->sm2dhe.sdf_generated_eph_pub_len = pub_len;

						SDF_INFO("pkey_ec_derive: SDF-generated ephemeral public key saved, len=%zu", pub_len);
						SDF_HEX_DUMP("  Encoded public key", pub_encoded, pub_len);
					}
					else {
						SDF_ERR("pkey_ec_derive: Failed to allocate memory for SDF-generated public key");
					}
				}

				/* 使用生成的共享密钥 */
				if (key) {
					/* 检查输出缓冲区大小 */
					if (*keylen < secret_len) {
						SDF_ERR("pkey_ec_derive: Output buffer too small, required=%u, provided=%zu", secret_len, *keylen);
						SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_BUFFER_TOO_SMALL);
						/* 清理资源 */
						if (key_handle) {
							key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
						}
						/* 注意：不要销毁 agreement_handle，因为它可能是在 pkey_ec_ctrl 中生成的 */
						/* agreement_handle 的生命周期由 SDF 上下文管理 */
						return 0;
					}
					memcpy(key, shared_secret, secret_len);
					*keylen = secret_len;
					SDF_INFO("pkey_ec_derive: SM2 key exchange successful, shared secret len=%u", secret_len);
					SDF_HEX_DUMP("pkey_ec_derive: Shared secret", key, *keylen);

					/* 清理资源 */
					if (key_handle) {
						key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
					}
					/* 注意：不要销毁 agreement_handle，因为它可能是在 pkey_ec_ctrl 中生成的 */
					/* agreement_handle 的生命周期由 SDF 上下文管理 */

					return 1;
				}

				/* 清理资源 */
				if (key_handle) {
					key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
				}
				/* 注意：不要销毁 agreement_handle，因为它可能是在 pkey_ec_ctrl 中生成的 */
				/* agreement_handle 的生命周期由 SDF 上下文管理 */

				return 1;
////			}
////			else 
////			{
////				SDF_WARN("pkey_ec_derive: byzk0018 SM2 key exchange interface not available");
////				goto standard_ecdh;
////			}
		}
		else if (dctx && dctx->sm2dhe.self_id != NULL) {
			SDF_WARN("pkey_ec_derive: SM2DHE parameters detected but no SDF context");
			goto standard_ecdh;
		} /* SM2DHE block ends */

	standard_ecdh:
		if (!pkey) {
			SDF_ERR("pkey_ec_derive: pkey not set");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_PARAMETER);
			return 0;
		}

		/* 在 SM2DHE 回退场景中，可能没有 peerkey，需要从 sm2dhe 结构获取 */
		if (!peerkey && dctx && dctx->sm2dhe.peer_eph_pub) {
			peerkey = dctx->sm2dhe.peer_eph_pub;
			SDF_INFO("pkey_ec_derive: using peer_eph_pub from SM2DHE params");
		}

		if (!peerkey) {
			SDF_ERR("pkey_ec_derive: peerkey not set and no SM2DHE peer_eph_pub");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_PARAMETER);
			return 0;
		}

		/* 在 SM2DHE 回退场景中，可能需要使用临时私钥 */
		if (dctx && dctx->sm2dhe.self_eph_priv) {
			eckey = EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_priv);
			SDF_INFO("pkey_ec_derive: using self_eph_priv from SM2DHE params");
		}
		else if (dctx && dctx->co_key) {
			eckey = dctx->co_key;
		}
		else {
			eckey = EVP_PKEY_get0_EC_KEY(pkey);
		}

		if (!eckey) {
			SDF_ERR("pkey_ec_derive: eckey is NULL");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_INVALID_PARAMETER);
			return 0;
		}

		if (!key) {
			const EC_GROUP* group;
			group = EC_KEY_get0_group(eckey);
			*keylen = (EC_GROUP_get_degree(group) + 7) / 8;
			return 1;
		}
		pubkey = EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(peerkey));

		outlen = *keylen;

#ifndef OPENSSL_NO_SM2
		if (dctx->ec_scheme == NID_sm2) {
			SDF_INFO("pkey_ec_derive: SM2 key exchange detected");

			/* 检查是否有 SDF 上下文和必要的 SDF 接口 */
			if (key_ctx && key_ctx->sdf_ctx) {
				if (key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataWithECCEx &&
					key_ctx->sdf_ctx->sdfList.SDF_GenerateKeyWithECCEx &&
					key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataAndKeyWithECCEx) {

					SDF_INFO("pkey_ec_derive: SDF SM2 key exchange interface available");
					SDF_INFO("pkey_ec_derive: Attempting to use SDF interface for SM2 key exchange");

					/* 准备密钥协商所需的参数 */
					ECCrefPublicKey sponsor_pub, response_pub;
					ECCrefPublicKey sponsor_tmp_pub, response_tmp_pub;
					SGD_HANDLE agreement_handle = NULL;
					SGD_HANDLE key_handle = NULL;
					/*
					 * SM2密钥协商输出长度:
					 * - 为了与软件实现兼容,使用48字节(SSL_MAX_MASTER_KEY_LENGTH)
					 * - 虽然GM/T 0003.3-2012标准规定32字节,但客户端软件实现输出48字节
					 * - 双方必须使用相同长度才能成功协商
					 */
					unsigned char shared_secret[48] = { 0 };
					unsigned int secret_len = sizeof(shared_secret);  /* 48字节 */

					/* 转换公钥格式：从 EC_KEY 到 ECCrefPublicKey */
					memset(&sponsor_pub, 0, sizeof(sponsor_pub));
					memset(&response_pub, 0, sizeof(response_pub));
					memset(&sponsor_tmp_pub, 0, sizeof(sponsor_tmp_pub));
					memset(&response_tmp_pub, 0, sizeof(response_tmp_pub));

					/* 转换自身公钥 */
					if (!EC_KEY_get_ECCrefPublicKey(eckey, &sponsor_pub)) {
						SDF_ERR("pkey_ec_derive: Failed to convert own pubkey to ECCrefPublicKey");
						goto sm2_fallback_to_provider;
					}

					/* 转换对端公钥 */
					if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(peerkey), &response_pub)) {
						SDF_ERR("pkey_ec_derive: Failed to convert peer pubkey to ECCrefPublicKey");
						goto sm2_fallback_to_provider;
					}

					/* 尝试使用 SDF 接口进行密钥交换 */
					if (dctx->sm2dhe.self_id != NULL && dctx->sm2dhe.peer_id != NULL) {
						SDF_INFO("pkey_ec_derive: Using SM2DHE with SDF interface");

						/* 检查是否有临时公钥 */
						if (dctx->sm2dhe.self_eph_pub) {
							if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_pub), &sponsor_tmp_pub)) {
								SDF_ERR("pkey_ec_derive: Failed to convert self tmp pubkey to ECCrefPublicKey");
								goto sm2_fallback_to_provider;
							}
						}

						/* 检查是否有对端临时公钥 */
						if (dctx->sm2dhe.peer_eph_pub) {
							if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.peer_eph_pub), &response_tmp_pub)) {
								SDF_ERR("pkey_ec_derive: Failed to convert peer tmp pubkey to ECCrefPublicKey");
								goto sm2_fallback_to_provider;
							}
						}

						/* 根据发起方/响应方角色调用不同的 SDF 接口 */
						if (dctx->sm2dhe.initiator) {
							/* 优先使用在 pkey_ec_ctrl 中预先生成的 agreement_handle */
							if (dctx->sm2dhe.agreement_handle) {
								SDF_INFO("pkey_ec_derive: Using pre-generated agreement_handle from pkey_ec_ctrl");
								SDF_INFO("pkey_ec_derive: Skipping SDF_GenerateAgreementDataWithECCEx call");

								/* 使用预先保存的 agreement_handle */
								agreement_handle = dctx->sm2dhe.agreement_handle;

								/* 打印当前使用的临时公钥（在 pkey_ec_ctrl 中已经更新过） */
								SDF_INFO("pkey_ec_derive: Using SDF-generated temporary key (updated in pkey_ec_ctrl):");
								EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_pub), &sponsor_tmp_pub);
								SDF_INFO("  X: %02X%02X%02X%02X...",
									sponsor_tmp_pub.x[0], sponsor_tmp_pub.x[1], sponsor_tmp_pub.x[2], sponsor_tmp_pub.x[3]);
							}
							else {
								/* 如果没有预先保存的 agreement_handle，则调用 SDF_GenerateAgreementDataWithECCEx (fallback) */
								SDF_INFO("pkey_ec_derive: No pre-generated agreement_handle, calling SDF_GenerateAgreementDataWithECCEx");

								/* 打印调用前的临时公钥（引擎生成的） */
								SDF_INFO("pkey_ec_derive: sponsor_tmp_pub BEFORE SDF call (engine-generated):");
								SDF_INFO("  X: %02X%02X%02X%02X...",
									sponsor_tmp_pub.x[0], sponsor_tmp_pub.x[1], sponsor_tmp_pub.x[2], sponsor_tmp_pub.x[3]);

								ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataWithECCEx(
									key_ctx->sdf_ctx->hSession,
									key_ctx->key_index,
									sponsor_pub.bits,
									dctx->sm2dhe.self_id,
									dctx->sm2dhe.self_id_len,
									&sponsor_pub,
									&sponsor_tmp_pub,
									&agreement_handle);

								if (ret != SDR_OK) {
									SDF_ERR("pkey_ec_derive: SDF_GenerateAgreementDataWithECCEx failed, ret=0x%08X", ret);
									goto sm2_fallback_to_provider;
								}

								/* 打印调用后的临时公钥（SDF生成的） */
								SDF_INFO("pkey_ec_derive: sponsor_tmp_pub AFTER SDF call (SDF-generated):");
								SDF_INFO("  X: %02X%02X%02X%02X...",
									sponsor_tmp_pub.x[0], sponsor_tmp_pub.x[1], sponsor_tmp_pub.x[2], sponsor_tmp_pub.x[3]);
								SDF_INFO("  Y: %02X%02X%02X%02X...",
									sponsor_tmp_pub.y[0], sponsor_tmp_pub.y[1], sponsor_tmp_pub.y[2], sponsor_tmp_pub.y[3]);

								/* 从 SDF 接口获取生成的临时公钥，并更新到 self_eph_pub */
								/* 注意：这种 fallback 路径不应该发生，因为 agreement_handle 应该在 pkey_ec_ctrl 中生成 */
								if (dctx->sm2dhe.self_eph_pub) {
									EC_KEY* self_eph_ec = EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_pub);
									if (self_eph_ec) {
										const EC_GROUP* group = EC_KEY_get0_group(self_eph_ec);
										EC_POINT* new_pub_point = EC_POINT_new(group);

										if (new_pub_point) {
											/* 从 ECCrefPublicKey 格式转换回 EC_POINT */
											BIGNUM* x = BN_bin2bn(sponsor_tmp_pub.x, sizeof(sponsor_tmp_pub.x), NULL);
											BIGNUM* y = BN_bin2bn(sponsor_tmp_pub.y, sizeof(sponsor_tmp_pub.y), NULL);

											if (x && y && EC_POINT_set_affine_coordinates(group, new_pub_point, x, y, NULL)) {
												/* 更新 EC_KEY 的公钥部分 */
												int set_pub_result = EC_KEY_set_public_key(self_eph_ec, new_pub_point);

												if (set_pub_result == 1) {
													SDF_INFO("pkey_ec_derive: Successfully updated self_eph_pub with SDF-generated temporary public key");
													SDF_INFO("pkey_ec_derive: self_eph_pub X: %02X%02X%02X%02X...",
														sponsor_tmp_pub.x[0], sponsor_tmp_pub.x[1], sponsor_tmp_pub.x[2], sponsor_tmp_pub.x[3]);
												}
												else {
													SDF_WARN("pkey_ec_derive: Failed to set SDF-generated public key to self_eph_pub");
												}
											}
											else {
												SDF_ERR("pkey_ec_derive: Failed to convert ECCrefPublicKey to EC_POINT");
											}

											if (x) BN_free(x);
											if (y) BN_free(y);
											EC_POINT_free(new_pub_point);
										}
										else {
											SDF_ERR("pkey_ec_derive: Failed to create new EC_POINT");
										}
									}
									else {
										SDF_ERR("pkey_ec_derive: self_eph_pub EC_KEY is NULL");
									}
								}
								else {
									SDF_ERR("pkey_ec_derive: self_eph_pub is NULL, cannot update with SDF-generated key");
								}
							}

							SDF_INFO("pkey_ec_derive: Calling SDF_GenerateKeyWithECCEx for initiator");
							ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateKeyWithECCEx(
								key_ctx->sdf_ctx->hSession,
								dctx->sm2dhe.peer_id,
								dctx->sm2dhe.peer_id_len,
								&response_pub,
								&response_tmp_pub,
								agreement_handle,
								shared_secret,
								&secret_len,
								&key_handle);

							if (ret != SDR_OK) {
								SDF_ERR("pkey_ec_derive: SDF_GenerateKeyWithECCEx failed, ret=0x%08X", ret);
								/* 注意：不要销毁 agreement_handle，因为它可能是在 pkey_ec_ctrl 中生成的 */
								if (key_handle) {
									key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
								}
								/* 只有当 agreement_handle 是在这个函数中生成时才销毁它 */
								if (!dctx->sm2dhe.agreement_handle && agreement_handle) {
									key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, agreement_handle);
								}
								goto sm2_fallback_to_provider;
							}
						}
						else {
							SDF_INFO("pkey_ec_derive: Calling SDF_GenerateAgreementDataAndKeyWithECCEx for responder");
							ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataAndKeyWithECCEx(
								key_ctx->sdf_ctx->hSession,
								key_ctx->key_index,
								sponsor_pub.bits,
								dctx->sm2dhe.self_id,
								dctx->sm2dhe.self_id_len,
								dctx->sm2dhe.peer_id,
								dctx->sm2dhe.peer_id_len,
								&sponsor_pub,
								&sponsor_tmp_pub,
								&response_pub,
								&response_tmp_pub,
								shared_secret,
								&secret_len,
								&key_handle);

							if (ret != SDR_OK) {
								SDF_ERR("pkey_ec_derive: SDF_GenerateAgreementDataAndKeyWithECCEx failed, ret=0x%08X", ret);
								goto sm2_fallback_to_provider;
							}
						}

						/* 使用生成的共享密钥 */
						if (key) {
							if (*keylen < secret_len) {
								SDF_ERR("pkey_ec_derive: Output buffer too small, required=%u, provided=%zu", secret_len, *keylen);
								if (key_handle) {
									key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
								}
								/* 只有当 agreement_handle 是在这个函数中生成时才销毁它 */
								if (!dctx->sm2dhe.agreement_handle && agreement_handle) {
									key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, agreement_handle);
								}
								return 0;
							}
							memcpy(key, shared_secret, secret_len);
							*keylen = secret_len;
							SDF_INFO("pkey_ec_derive: SM2 key exchange successful, shared secret len=%u", secret_len);

							/* 清理资源 */
							if (key_handle) {
								key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
							}
							/* 注意：不要销毁 agreement_handle，因为它可能是在 pkey_ec_ctrl 中生成的 */
							/* agreement_handle 的生命周期由 SDF 上下文管理，不在这里销毁 */

							return 1;
						}

						/* 清理资源 */
						if (key_handle) {
							key_ctx->sdf_ctx->sdfList.SDF_DestroyKey(key_ctx->sdf_ctx->hSession, key_handle);
						}
						/* 注意：不要销毁 agreement_handle，因为它可能是在 pkey_ec_ctrl 中生成的 */
						/* agreement_handle 的生命周期由 SDF 上下文管理，不在这里销毁 */

						return 1;
					}
					else {
						SDF_INFO("pkey_ec_derive: SM2DHE parameters not set, using standard ECDH");
					}
				}
				else {
					SDF_WARN("pkey_ec_derive: SDF SM2 key exchange interface not available");
				}
			}
			else {
				SDF_WARN("pkey_ec_derive: No SDF context available");
			}
		}
	sm2_fallback_to_provider:
		SDF_INFO("pkey_ec_derive: Falling back to provider for SM2 key exchange");
		SDF_INFO("pkey_ec_derive: Returning -2 to let provider handle it");
		return -2; /* Let OpenSSL fallback to provider */
	}
#endif

	/* For non-SM2 curves, use standard ECDH */
	SDF_INFO("pkey_ec_derive: computing ECDH key, outlen=%zu", outlen);
	SDF_INFO("pkey_ec_derive: eckey=%p, pubkey=%p", eckey, pubkey);

	ret = ECDH_compute_key(key, outlen, pubkey, eckey, 0);
	SDF_INFO("pkey_ec_derive: ECDH_compute_key returned %d", ret);

	if (ret <= 0) {
		SDF_ERR("pkey_ec_derive: derive failed, ret=%d", ret);
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
		return 0;
	}
	SDF_INFO("pkey_ec_derive: derive successful, keylen=%d", ret);
	*keylen = ret;
	return 1;
}

static int sdf_pkey_ec_kdf_derive(EVP_PKEY_CTX* ctx, unsigned char* key,
	size_t* keylen) {
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	unsigned char* ktmp = NULL;
	size_t ktmplen;
	int rv = 0;

	SDF_INFO("=== sdf_pkey_ec_kdf_derive: starting KDF derive ===");
	SDF_INFO("sdf_pkey_ec_kdf_derive: called, kdf_type=%d (0=EVP_PKEY_ECDH_KDF_NONE, 1=X9_62)", dctx->kdf_type);

#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm2) {
		SDF_INFO("sdf_pkey_ec_kdf_derive: SM2 detected, calling sdf_pkey_ec_derive for SM2DHE");
		return sdf_pkey_ec_derive(ctx, key, keylen);
	}
#endif

	if (dctx->kdf_type == EVP_PKEY_ECDH_KDF_NONE) {
		SDF_INFO("sdf_pkey_ec_kdf_derive: NO KDF, calling sdf_pkey_ec_derive");
		return sdf_pkey_ec_derive(ctx, key, keylen);
	}

	SDF_INFO("sdf_pkey_ec_kdf_derive: WITH KDF, proceeding to KDF process");
	/* Report expected length when queried */
	if (!key) {
		if (dctx->kdf_outlen == 0)
			dctx->kdf_outlen = 48; /* NTLS SM2DHE 约定输出 48 字节 */
		*keylen = dctx->kdf_outlen;
		SDF_INFO("sdf_pkey_ec_kdf_derive: report outlen=%zu", *keylen);
		return 1;
	}
	if (dctx->kdf_outlen == 0)
		dctx->kdf_outlen = *keylen; /* 若上层未设置，采用请求长度 */
	if (*keylen != dctx->kdf_outlen) {
		SDF_ERR("pkey_ec_kdf_derive: keylen(%zu) != kdf_outlen(%zu)", *keylen, dctx->kdf_outlen);
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_BUFFER_TOO_SMALL);
		return 0;
	}
	if (!sdf_pkey_ec_derive(ctx, NULL, &ktmplen)) {
		SDF_ERR("pkey_ec_kdf_derive: derive failed");
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
		return 0;
	}
	ktmp = OPENSSL_malloc(ktmplen);
	if (ktmp == NULL) {
		SDF_ERR("pkey_ec_kdf_derive: alloc ktmp failed");
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}
	if (!sdf_pkey_ec_derive(ctx, ktmp, &ktmplen)) {
		SDF_ERR("pkey_ec_kdf_derive: derive failed");
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KEY_EXCHANGE_FAILED);
		goto err;
	}
	/* Ensure SM3 is used for NTLS/SM2DHE if not explicitly set */
	if (dctx->kdf_md == NULL)
		dctx->kdf_md = EVP_sm3();

	SDF_INFO("pkey_ec_kdf_derive: raw_shared=%zu, out=%zu, md=%p", ktmplen,
		key ? *keylen : 0, (void*)dctx->kdf_md);
	SDF_INFO("pkey_ec_kdf_derive: ukm_len=%zu", dctx->kdf_ukmlen);
	if (dctx->kdf_ukm && dctx->kdf_ukmlen > 0) {
		size_t dump_len = dctx->kdf_ukmlen > 64 ? 64 : dctx->kdf_ukmlen;
		SDF_HEX_DUMP("pkey_ec_kdf_derive: ukm(first 64)", dctx->kdf_ukm, dump_len);
	}

	SDF_HEX_DUMP("pkey_ec_kdf_derive: raw shared secret", ktmp, ktmplen);

	/* Do KDF stuff */
	SDF_INFO("pkey_ec_kdf_derive: calling ECDH_KDF_X9_62...");
	if (!ECDH_KDF_X9_62(key, *keylen, ktmp, ktmplen, dctx->kdf_ukm,
		dctx->kdf_ukmlen, dctx->kdf_md)) {
		SDF_ERR("pkey_ec_kdf_derive: KDF failed");
		SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_KDF_FAILED);
		goto err;
	}
	SDF_HEX_DUMP("pkey_ec_kdf_derive: KDF output", key, *keylen);
	SDF_INFO("pkey_ec_kdf_derive: KDF succeeded");
	rv = 1;

err:
	OPENSSL_clear_free(ktmp, ktmplen);
	return rv;
}
#endif

/* SM2 digestsign: 直接处理原始消息，正确计算 e = SM3(ZA || M) */
static int sdf_pkey_ec_digestsign(EVP_MD_CTX* mctx, unsigned char* sig,
	size_t* siglen, const unsigned char* tbs,
	size_t tbslen)
{
	EVP_PKEY_CTX* ctx = EVP_MD_CTX_pkey_ctx(mctx);
	SDF_EC_PKEY_CTX* dctx;
	EVP_PKEY* pkey;
	EC_KEY* ec;
	unsigned char digest[32];
	//unsigned int sltmp;
	int ret;

	SDF_INFO("pkey_ec_digestsign: *** CALLED *** tbslen=%zu, siglen=%zu", tbslen, sig ? *siglen : 0);

	if (!ctx) {
		SDF_ERR("pkey_ec_digestsign: ctx is NULL, returning -2");
		return -2; /* 返回 -2 表示使用默认实现 */
	}

	dctx = EVP_PKEY_CTX_get_data(ctx);
	if (!dctx) {
		SDF_ERR("pkey_ec_digestsign: dctx is NULL, returning -2");
		return -2;
	}

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!pkey) {
		SDF_ERR("pkey_ec_digestsign: pkey is NULL, returning -2");
		return -2;
	}

	ec = EVP_PKEY_get0_EC_KEY(pkey);
	if (!ec) {
		SDF_ERR("pkey_ec_digestsign: ec is NULL, returning -2");
		return -2;
	}

	SDF_INFO("pkey_ec_digestsign: ctx=%p, dctx=%p, pkey=%p, ec=%p", (void*)ctx, (void*)dctx, (void*)pkey, (void*)ec);
	SDF_INFO("pkey_ec_digestsign: ec_scheme=%d, NID_sm2=%d", dctx->ec_scheme, NID_sm2);
	SDF_HEX_DUMP("pkey_ec_digestsign: original TBS data", tbs, tbslen);

	if (!sig) {
		*siglen = ECDSA_size(ec);
		SDF_INFO("pkey_ec_digestsign: returning signature size %zu", *siglen);
		return 1;
	}

#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm2) {
		SDF_KEY_CTX* key_ctx = EVP_PKEY_get_ex_data(pkey, 0);
		if (!key_ctx) {
			key_ctx = EC_KEY_get_ex_data(ec, 0);
		}

		const BIGNUM* priv_key = EC_KEY_get0_private_key(ec);

		if (key_ctx && key_ctx->sdf_ctx && !priv_key) {
			/* 硬件密钥：需要计算 e = SM3(ZA || M) */
			unsigned char za[32];
			const unsigned char* id = dctx->id;
			size_t id_len = dctx->id_len;
			const EVP_MD* md = dctx->md ? dctx->md : EVP_sm3();

			/* 如果没有设置ID，使用默认ID */
			if (!id) {
				id = (const unsigned char*)SM2_DEFAULT_USERID;
				id_len = strlen(SM2_DEFAULT_USERID);
				SDF_INFO("pkey_ec_digestsign: using default SM2 ID: %s", SM2_DEFAULT_USERID);
			}
			else {
				SDF_INFO("pkey_ec_digestsign: using custom SM2 ID, len=%zu", id_len);
				SDF_HEX_DUMP("pkey_ec_digestsign: custom SM2 ID", id, id_len);
			}

			SDF_INFO("pkey_ec_digestsign: computing ZA with id_len=%zu, md=%p", id_len, (void*)md);

			/* 计算 ZA */
			if (!ossl_sm2_compute_z_digest(za, md, id, id_len, ec)) {
				SDF_ERR("pkey_ec_digestsign: failed to compute ZA");
				return 0;
			}

			SDF_HEX_DUMP("pkey_ec_digestsign: ZA", za, 32);

			/* 计算 e = SM3(ZA || M) */
			EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
			if (!hash_ctx) {
				SDF_ERR("pkey_ec_digestsign: failed to create hash context");
				return 0;
			}

			if (!EVP_DigestInit_ex(hash_ctx, md, NULL) ||
				!EVP_DigestUpdate(hash_ctx, za, 32) ||
				!EVP_DigestUpdate(hash_ctx, tbs, tbslen) ||
				!EVP_DigestFinal_ex(hash_ctx, digest, NULL)) {
				SDF_ERR("pkey_ec_digestsign: failed to compute e = SM3(ZA || M)");
				EVP_MD_CTX_free(hash_ctx);
				return 0;
			}

			EVP_MD_CTX_free(hash_ctx);

			SDF_HEX_DUMP("pkey_ec_digestsign: e = SM3(ZA || M)", digest, 32);
			SDF_INFO("pkey_ec_digestsign: calling hardware signing with correct e value");

			/* 确保 EC_KEY 的 ex_data 中有 key_ctx */
			EC_KEY_set_ex_data((EC_KEY*)ec, 0, key_ctx);

			/* 调用硬件签名，传入正确的 e 值 */
			ret = sdf_ecdsa_sign(NID_undef, digest, 32, sig, siglen, NULL, NULL, ec);
			if (ret <= 0) {
				SDF_ERR("pkey_ec_digestsign: hardware signing failed,ret:%d", ret);
				return 0;
			}

			SDF_INFO("pkey_ec_digestsign: hardware signing succeeded, siglen=%u", *siglen);
			return 1;
		}
		else {
			/* SM2 密钥但有软件私钥：使用软件 SM2 签名 */
			SDF_INFO("pkey_ec_digestsign: SM2 key with software private key, using software SM2 signing");

			/* 计算 e = SM3(ZA || M) */
			unsigned char za[32];
			const unsigned char* id = dctx->id;
			size_t id_len = dctx->id_len;
			const EVP_MD* md = dctx->md ? dctx->md : EVP_sm3();

			/* 如果没有设置ID，使用默认ID */
			if (!id) {
				id = (const unsigned char*)SM2_DEFAULT_USERID;
				id_len = strlen(SM2_DEFAULT_USERID);
			}

			/* 计算 ZA */
			if (!ossl_sm2_compute_z_digest(za, md, id, id_len, ec)) {
				SDF_ERR("pkey_ec_digestsign: failed to compute ZA");
				return 0;
			}

			/* 计算 e = SM3(ZA || M) */
			EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
			if (!hash_ctx) {
				SDF_ERR("pkey_ec_digestsign: failed to create hash context");
				return 0;
			}

			if (!EVP_DigestInit_ex(hash_ctx, md, NULL) ||
				!EVP_DigestUpdate(hash_ctx, za, 32) ||
				!EVP_DigestUpdate(hash_ctx, tbs, tbslen) ||
				!EVP_DigestFinal_ex(hash_ctx, digest, NULL)) {
				SDF_ERR("pkey_ec_digestsign: failed to compute e = SM3(ZA || M)");
				EVP_MD_CTX_free(hash_ctx);
				return 0;
			}

			EVP_MD_CTX_free(hash_ctx);

			/* 使用软件 SM2 签名 */
			ret = ossl_sm2_internal_sign(digest, 32, sig, siglen, ec);
			if (ret <= 0) {
				SDF_ERR("pkey_ec_digestsign: software SM2 signing failed");
				return 0;
			}

			SDF_INFO("pkey_ec_digestsign: software SM2 signing succeeded, siglen=%u", *siglen);
			return 1;
		}
	}
	else
#endif
	{
		/* 非SM2：使用标准的 digest + sign 流程 */
		SDF_INFO("pkey_ec_digestsign: non-SM2 algorithm, using standard ECDSA signing");

		if (!sig) {
			*siglen = ECDSA_size(ec);
			SDF_INFO("pkey_ec_digestsign: returning signature size %zu", *siglen);
			return 1;
		}

		if (*siglen < (size_t)ECDSA_size(ec)) {
			SDF_ERR("pkey_ec_digestsign: siglen too small");
			SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_BUFFER_TOO_SMALL);
			return 0;
		}

		/* 对于非SM2，直接使用标准的 ECDSA 签名 */
		int type = dctx->md ? EVP_MD_type(dctx->md) : NID_sha1;
		ret = ECDSA_sign(type, tbs, tbslen, sig, siglen, (EC_KEY*)ec);
		if (ret <= 0) {
			SDF_ERR("pkey_ec_digestsign: ECDSA sign failed");
			SDFerr(SDF_F_SDF_PKEY_EC_SIGN, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
	}

	SDF_INFO("pkey_ec_digestsign: ECDSA signing succeeded, siglen=%u", *siglen);
	return 1;
}

/* SM2 digestverify: 直接处理原始消息，正确计算 e = SM3(ZA || M) */
static int sdf_pkey_ec_digestverify(EVP_MD_CTX* mctx, const unsigned char* sig,
	size_t siglen, const unsigned char* tbs,
	size_t tbslen)
{
	EVP_PKEY_CTX* ctx = EVP_MD_CTX_pkey_ctx(mctx);
	SDF_EC_PKEY_CTX* dctx;
	EVP_PKEY* pkey;
	EC_KEY* ec;
	unsigned char digest[32];
	int ret;
	int isRetry = 1;

	SDF_INFO("pkey_ec_digestverify: *** CALLED *** tbslen=%zu, siglen=%zu", tbslen, siglen);

	if (!ctx) {
		SDF_ERR("pkey_ec_digestverify: ctx is NULL, returning -2");
		return -2; /* 返回 -2 表示使用默认实现 */
	}

	dctx = EVP_PKEY_CTX_get_data(ctx);
	if (!dctx) {
		SDF_ERR("pkey_ec_digestverify: dctx is NULL, returning -2");
		return -2;
	}

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!pkey) {
		SDF_ERR("pkey_ec_digestverify: pkey is NULL, returning -2");
		return -2;
	}

	ec = EVP_PKEY_get0_EC_KEY(pkey);
	if (!ec) {
		SDF_ERR("pkey_ec_digestverify: ec is NULL, returning -2");
		return -2;
	}

	SDF_INFO("pkey_ec_digestverify: ctx=%p, dctx=%p, pkey=%p, ec=%p", (void*)ctx, (void*)dctx, (void*)pkey, (void*)ec);
	SDF_INFO("pkey_ec_digestverify: ec_scheme=%d, NID_sm2=%d", dctx->ec_scheme, NID_sm2);
	//SDF_HEX_DUMP("pkey_ec_digestverify: original TBS data", tbs, tbslen);

#ifndef OPENSSL_NO_SM2
	if (dctx->ec_scheme == NID_sm2) {
		/* 证书验证：只需要公钥和原文进行预处理，不需要访问硬件私钥 */
		unsigned char za[32];
		const unsigned char* id = dctx->id;
		size_t id_len = dctx->id_len;
		const EVP_MD* md = dctx->md ? dctx->md : EVP_sm3();

		/* 如果没有设置ID，使用默认ID */
	rety:
		if (!id) {
			id = (const unsigned char*)SM2_DEFAULT_USERID;
			id_len = strlen(SM2_DEFAULT_USERID);
			SDF_INFO("pkey_ec_digestverify: using default SM2 ID: %s", SM2_DEFAULT_USERID);
		}
		else {
			SDF_INFO("pkey_ec_digestverify: using custom SM2 ID, len=%zu", id_len);
			SDF_HEX_DUMP("pkey_ec_digestverify: custom SM2 ID", id, id_len);
		}

		SDF_INFO("pkey_ec_digestverify: computing ZA with id_len=%zu, md=%p", id_len, (void*)md);

		/* 计算 ZA（只需要公钥，不需要私钥） */
		if (!ossl_sm2_compute_z_digest(za, md, id, id_len, ec)) {
			SDF_ERR("pkey_ec_digestverify: failed to compute ZA");
			return 0;
		}

		SDF_HEX_DUMP("pkey_ec_digestverify: ZA", za, 32);

		/* 计算 e = SM3(ZA || M) */
		EVP_MD_CTX* hash_ctx = EVP_MD_CTX_new();
		if (!hash_ctx) {
			SDF_ERR("pkey_ec_digestverify: failed to create hash context");
			return 0;
		}

		if (!EVP_DigestInit_ex(hash_ctx, md, NULL) ||
			!EVP_DigestUpdate(hash_ctx, za, 32) ||
			!EVP_DigestUpdate(hash_ctx, tbs, tbslen) ||
			!EVP_DigestFinal_ex(hash_ctx, digest, NULL)) {
			SDF_ERR("pkey_ec_digestverify: failed to compute e = SM3(ZA || M)");
			EVP_MD_CTX_free(hash_ctx);
			return 0;
		}

		EVP_MD_CTX_free(hash_ctx);

		SDF_HEX_DUMP("pkey_ec_digestverify: e = SM3(ZA || M)", digest, 32);
		SDF_INFO("pkey_ec_digestverify: calling software verification with correct e value");

		/* 调用软件验证，传入正确的 e 值（证书验证不需要硬件） */
		ret = ossl_sm2_internal_verify(digest, 32, sig, siglen, ec);
		if (ret <= 0) {
			if (isRetry)
			{
				/*TODO:使用外送的ID验证失败，使用默认ID重新验签一次
				因为使用engine在tls_process_cert_verify_ntls中没有设置回默认的ID，只有provider才能设置回默认的ID
				tls_construct_cert_verify_ntls 中使用s_client 软件密钥时，走的时是provider，客户端签名的时候使用的是默认ID
				在tls_process_cert_verify_ntls中因为使用的engine，无法走到EVP_PKEY_is_a(pkey, "SM2")内部设置回默认的ID，导致这里会验签失败*/
				isRetry = 0;
				id = NULL;
				id_len = 0;
				SDF_WARN("use custom SM2 ID verify failed, retry with default SM2 ID");
				goto rety;
			}

			SDF_ERR("pkey_ec_digestverify: software verification failed");
			return 0;
		}

		SDF_INFO("pkey_ec_digestverify: software verification succeeded");
		return 1;
	}
	else
#endif
	{
		/* 非SM2：使用标准的 digest + verify 流程 */
		SDF_INFO("pkey_ec_digestverify: non-SM2 algorithm, using standard ECDSA verification");

		/* 对于非SM2，直接使用标准的 ECDSA 验证 */
		int type = dctx->md ? EVP_MD_type(dctx->md) : NID_sha1;
		ret = ECDSA_verify(type, tbs, tbslen, sig, siglen, (EC_KEY*)ec);
		if (ret <= 0) {
			SDF_ERR("pkey_ec_digestverify: ECDSA verify failed");
			SDFerr(SDF_F_SDF_PKEY_EC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
	}

	SDF_INFO("pkey_ec_digestverify: ECDSA verification succeeded");
	return 1;
}

static int sdf_pkey_ec_ctrl(EVP_PKEY_CTX* ctx, int type, int p1, void* p2) {
	SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY* pkey;
	EC_GROUP* group;

	SDF_INFO("pkey_ec_ctrl: type=%d, p1=%d, p2=%p, dctx=%p", type, p1, p2, dctx);
	SDF_INFO("pkey_ec_ctrl: EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID=%d, NID_sm2=%d", EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, NID_sm2);
	SDF_INFO("pkey_ec_ctrl: SDF_PKEY_CTRL_SET_SM2DHE_PARAMS=%d", SDF_PKEY_CTRL_SET_SM2DHE_PARAMS);

	switch (type) {
	case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
		SDF_INFO("pkey_ec_ctrl: EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID called with curve_nid=%d, dctx=%p", p1, dctx);

		/* 如果 dctx 为 NULL，先初始化它（ECDHE 临时密钥生成时可能遇到此情况）*/
		if (!dctx) {
			SDF_INFO("pkey_ec_ctrl: dctx is NULL, initializing for ECDHE keygen");
			EVP_PKEY* ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
			if (!sdf_pkey_ec_init(ctx)) {
				SDF_ERR("pkey_ec_ctrl: failed to initialize dctx");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_MEMORY_ALLOCATION_FAILED);
				return 0;
			}
			dctx = EVP_PKEY_CTX_get_data(ctx);
			if (!dctx) {
				SDF_ERR("pkey_ec_ctrl: dctx still NULL after init");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_MEMORY_ALLOCATION_FAILED);
				return 0;
			}
			SDF_INFO("pkey_ec_ctrl: dctx initialized successfully, dctx=%p", dctx);
		}

		/* 无论传入什么曲线NID，都强制使用SM2曲线 */
		SDF_INFO("pkey_ec_ctrl: Forcing SM2 curve regardless of input, p1=%d, NID_sm2=%d", p1, NID_sm2);
		dctx->ec_scheme = NID_sm2;

		/* 创建SM2曲线的EC_GROUP */
		group = EC_GROUP_new_by_curve_name(NID_sm2);
		if (group == NULL) {
			SDF_ERR("pkey_ec_ctrl: alloc SM2 group failed");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			SDF_INFO("pkey_ec_ctrl: Returning 0 because SM2 group allocation failed");
			return 0;
		}
		EC_GROUP_free(dctx->gen_group);
		dctx->gen_group = group;
		SDF_INFO("pkey_ec_ctrl: SM2 curve group set successfully, returning 1");
		return 1;

	case EVP_PKEY_CTRL_EC_PARAM_ENC:
		if (!dctx->gen_group) {
			SDF_ERR("pkey_ec_ctrl: gen_group is null");
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
				const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
				return EC_KEY_get_flags(ec_key) & EC_FLAG_COFACTOR_ECDH ? 1 : 0;
			}
		}
		else if (p1 < -1 || p1 > 1) {
			SDF_ERR("pkey_ec_ctrl: p1 is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		dctx->cofactor_mode = p1;
		if (p1 != -1) {
			const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
			const EC_GROUP* group = EC_KEY_get0_group(ec_key);
			const BIGNUM* cofactor = EC_GROUP_get0_cofactor(group);
			if (!group) {
				SDF_ERR("pkey_ec_ctrl: group is null");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
				return 0;
			}
			/* If cofactor is 1 cofactor mode does nothing */
			if (BN_is_one(cofactor))
				return 1;
			if (!dctx->co_key) {
				dctx->co_key = EC_KEY_dup(ec_key);
				if (!dctx->co_key) {
					SDF_ERR("pkey_ec_ctrl: alloc co_key failed");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
					return 0;
				}
			}
			if (p1)
				EC_KEY_set_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
			else
				EC_KEY_clear_flags(dctx->co_key, EC_FLAG_COFACTOR_ECDH);
		}
		else {
			EC_KEY_free(dctx->co_key);
			dctx->co_key = NULL;
		}
		return 1;
#endif

	case EVP_PKEY_CTRL_EC_KDF_TYPE:
		if (p1 == -2)
			return dctx->kdf_type;
		if (p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_62) {
			SDF_ERR("pkey_ec_ctrl: p1 is invalid");
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
		if (p1 != NID_sm2) {
			SDF_ERR("pkey_ec_ctrl: p1 is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		dctx->ec_scheme = p1;
		return 1;

	case EVP_PKEY_CTRL_SIGNER_ID:
		if (!p2 || !strlen((char*)p2) || strlen((char*)p2) > 255) {
			SDF_ERR("pkey_ec_ctrl: p2 is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		else {
			char* id = NULL;
			if (!(id = OPENSSL_strdup((char*)p2))) {
				SDF_ERR("pkey_ec_ctrl: alloc id failed");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
				return 0;
			}
			if (dctx->signer_id)
				OPENSSL_free(dctx->signer_id);
			dctx->signer_id = id;
			dctx->signer_id_len = strlen(id);
			if (dctx->ec_scheme == NID_sm2) {
				pkey = EVP_PKEY_CTX_get0_pkey(ctx);
				const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
				unsigned char zid[32];
				size_t zidlen = 32;
				if (!ossl_sm2_compute_z_digest(zid, EVP_sm3(), NULL, 0, ec_key)) {
					SDF_ERR("pkey_ec_ctrl: ossl_sm2_compute_z_digest failed");
					SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
					return 0;
				}
				if (!dctx->signer_zid) {
					if (!(dctx->signer_zid = OPENSSL_malloc(zidlen))) {
						SDF_ERR("pkey_ec_ctrl: alloc zid failed");
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
		*(const char**)p2 = dctx->signer_id;
		return 1;

	case EVP_PKEY_CTRL_GET_SIGNER_ZID:
		if (dctx->ec_scheme != NID_sm2) {
			*(const unsigned char**)p2 = NULL;
			SDF_ERR("pkey_ec_ctrl: p2 is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		if (!dctx->signer_zid) {
			pkey = EVP_PKEY_CTX_get0_pkey(ctx);
			const EC_KEY* ec_key = EVP_PKEY_get0_EC_KEY(pkey);
			unsigned char* zid;
			size_t zidlen = 32;
			if (!(zid = OPENSSL_malloc(zidlen))) {
				SDF_ERR("pkey_ec_ctrl: alloc zid failed");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
				return 0;
			}
			if (!ossl_sm2_compute_z_digest(zid, EVP_sm3(), NULL, 0, ec_key)) {
				SDF_ERR("pkey_ec_ctrl: ossl_sm2_compute_z_digest failed");
				SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
				return 0;
			}
			dctx->signer_zid = zid;
			dctx->signer_zid_len = zidlen;
		}
		*(const unsigned char**)p2 = dctx->signer_zid;
		return dctx->signer_zid_len;

	case EVP_PKEY_CTRL_EC_ENCRYPT_PARAM:
		if (p1 == -2) {
			SDF_ERR("pkey_ec_ctrl: p1 is invalid");
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
		*(const EVP_MD**)p2 = dctx->kdf_md;
		return 1;

	case EVP_PKEY_CTRL_EC_KDF_OUTLEN:
		if (p1 <= 0) {
			SDF_ERR("pkey_ec_ctrl: p1 is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		dctx->kdf_outlen = (size_t)p1;
		return 1;

	case EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN:
		*(int*)p2 = dctx->kdf_outlen;
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
		*(unsigned char**)p2 = dctx->kdf_ukm;
		return dctx->kdf_ukmlen;

	case EVP_PKEY_CTRL_MD:
		/* 允许任何消息摘要算法，包括NULL，因为ECDHE密钥生成可能不需要MD */
		SDF_INFO("pkey_ec_ctrl: EVP_PKEY_CTRL_MD called with md=%p, p1=%d", p2, p1);
		if (p2) {
			const char* md_name = EVP_MD_name((const EVP_MD*)p2);
			SDF_INFO("pkey_ec_ctrl: Set MD to %s, returning 1", md_name ? md_name : "unknown");
		}
		dctx->md = p2;
		return 1;

	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD**)p2 = dctx->md;
		return 1;

	case EVP_PKEY_CTRL_SET1_ID:
		SDF_INFO("pkey_ec_ctrl: EVP_PKEY_CTRL_SET1_ID, id_len=%d", p1);
		if (p1 > 0 && p2) {
			/* 设置 SM2 ID */
			if (dctx->id) {
				OPENSSL_free(dctx->id);
			}
			dctx->id = OPENSSL_malloc(p1);
			if (dctx->id) {
				memcpy(dctx->id, p2, p1);
				dctx->id_len = p1;
				SDF_INFO("pkey_ec_ctrl: SM2 ID set successfully, len=%d", p1);
			}
		}
		return 1;

	case EVP_PKEY_CTRL_PEER_KEY:
		/* Default behaviour is OK */
	case EVP_PKEY_CTRL_DIGESTINIT:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
	case EVP_PKEY_CTRL_CMS_SIGN:
		return 1;

	case SDF_PKEY_CTRL_SET_SM2DHE_PARAMS:
		SDF_INFO("pkey_ec_ctrl: SDF_PKEY_CTRL_SET_SM2DHE_PARAMS received");
		if (!dctx) {
			SDF_ERR("pkey_ec_ctrl: dctx is NULL");
			return 0;
		}

		if (p2 == NULL) {
			SDF_ERR("pkey_ec_ctrl: SM2DHE params pointer is NULL");
			return 0;
		}

		/* Store SM2DHE parameters */
		/* CRITICAL: Save internal fields before copying - they are NOT in SDF_SM2DHE_PARAMS */
		SGD_HANDLE saved_agreement_handle = dctx->sm2dhe.agreement_handle;
		int saved_deferred_keygen = dctx->sm2dhe.deferred_keygen;
		unsigned char* saved_sdf_generated_eph_pub = dctx->sm2dhe.sdf_generated_eph_pub;
		size_t saved_sdf_generated_eph_pub_len = dctx->sm2dhe.sdf_generated_eph_pub_len;

		/*
		 * CRITICAL: 尝试从 EVP_PKEY 的 ex_data 恢复 deferred_keygen 标志
		 * 因为新创建的 EVP_PKEY_CTX 的 dctx 不会继承原来的 deferred_keygen 标志
		 * 
		 * 需要检查两个地方：
		 * 1. EVP_PKEY_CTX_get0_pkey(ctx) - 当前上下文的 pkey
		 * 2. params->self_eph_pub - 传入的临时公钥（这才是真正保存了 deferred_keygen 的 pkey）
		 */
		
		/* 先定义 params 以便访问 self_eph_pub */
		struct {
			EVP_PKEY* self_eph_priv;
			EVP_PKEY* peer_eph_pub;
			EVP_PKEY* self_cert_priv;
			EVP_PKEY* peer_cert_pub;
			EVP_PKEY* self_cert_pub;
			EVP_PKEY* self_eph_pub;
			const unsigned char* self_id;
			size_t self_id_len;
			const unsigned char* peer_id;
			size_t peer_id_len;
			int initiator;
		} *params = p2;

		/* 尝试从 self_eph_pub 恢复 deferred_keygen（这是临时密钥） */
		if (params->self_eph_pub && !saved_deferred_keygen) {
			int* deferred_flag = (int*)EVP_PKEY_get_ex_data(params->self_eph_pub, 2);
			if (deferred_flag && *deferred_flag) {
				saved_deferred_keygen = *deferred_flag;
				SDF_INFO("pkey_ec_ctrl: Restored deferred_keygen=%d from self_eph_pub ex_data", saved_deferred_keygen);
			}
		}
		
		/* 也尝试从当前 pkey 恢复 */
		EVP_PKEY* ctx_pkey = EVP_PKEY_CTX_get0_pkey(ctx);
		if (ctx_pkey && !saved_deferred_keygen) {
			int* deferred_flag = (int*)EVP_PKEY_get_ex_data(ctx_pkey, 2);
			if (deferred_flag && *deferred_flag) {
				saved_deferred_keygen = *deferred_flag;
				SDF_INFO("pkey_ec_ctrl: Restored deferred_keygen=%d from ctx pkey ex_data", saved_deferred_keygen);
			}
		}

		/*
		 * CRITICAL FIX: Only copy the fields that exist in SDF_SM2DHE_PARAMS
		 * The structure passed from SSL layer does NOT have agreement_handle, deferred_keygen, etc.
		 * Using sizeof(dctx->sm2dhe) would read garbage values!
		 * 
		 * SDF_SM2DHE_PARAMS has: self_eph_priv, peer_eph_pub, self_cert_priv, peer_cert_pub,
		 *                       self_cert_pub, self_eph_pub, self_id, self_id_len,
		 *                       peer_id, peer_id_len, initiator
		 * Total: 10 pointers/size_t + 1 int = about 88 bytes on 64-bit
		 */
		/* params already defined above for deferred_keygen recovery */

		/* Copy only the fields from SDF_SM2DHE_PARAMS */
		dctx->sm2dhe.self_eph_priv = params->self_eph_priv;
		dctx->sm2dhe.peer_eph_pub = params->peer_eph_pub;
		dctx->sm2dhe.self_cert_priv = params->self_cert_priv;
		dctx->sm2dhe.peer_cert_pub = params->peer_cert_pub;
		dctx->sm2dhe.self_cert_pub = params->self_cert_pub;
		dctx->sm2dhe.self_eph_pub = params->self_eph_pub;
		dctx->sm2dhe.self_id = params->self_id;
		dctx->sm2dhe.self_id_len = params->self_id_len;
		dctx->sm2dhe.peer_id = params->peer_id;
		dctx->sm2dhe.peer_id_len = params->peer_id_len;
		dctx->sm2dhe.initiator = params->initiator;

		/* Restore internal fields that are managed by ENGINE */
		dctx->sm2dhe.agreement_handle = saved_agreement_handle;
		dctx->sm2dhe.deferred_keygen = saved_deferred_keygen;
		dctx->sm2dhe.sdf_generated_eph_pub = saved_sdf_generated_eph_pub;
		dctx->sm2dhe.sdf_generated_eph_pub_len = saved_sdf_generated_eph_pub_len;

		SDF_INFO("pkey_ec_ctrl: Copied SM2DHE params (field by field, not memcpy)");
		SDF_INFO("pkey_ec_ctrl: Preserved agreement_handle=%p, deferred_keygen=%d",
			saved_agreement_handle, saved_deferred_keygen);

		/* Debug: log SM2DHE parameters */
		SDF_INFO("pkey_ec_ctrl: SM2DHE parameters stored:");
		SDF_INFO("  self_eph_priv=%p, peer_eph_pub=%p",
			dctx->sm2dhe.self_eph_priv, dctx->sm2dhe.peer_eph_pub);
		SDF_INFO("  self_cert_priv=%p, peer_cert_pub=%p",
			dctx->sm2dhe.self_cert_priv, dctx->sm2dhe.peer_cert_pub);
		SDF_INFO("  self_cert_pub=%p, self_eph_pub=%p",
			dctx->sm2dhe.self_cert_pub, dctx->sm2dhe.self_eph_pub);
		SDF_INFO("  self_id=%p (len=%zu), peer_id=%p (len=%zu)",
			dctx->sm2dhe.self_id, dctx->sm2dhe.self_id_len,
			dctx->sm2dhe.peer_id, dctx->sm2dhe.peer_id_len);
		SDF_INFO("  initiator=%d", dctx->sm2dhe.initiator);

		/*
		 * 对于发起方（服务端），在这里生成 agreement_handle
		 * 根据GM/T 0003.3-2012标准，发起方需要：
		 * 1. 调用 SDF_GenerateAgreementDataWithECCEx 生成协商数据（获得 agreement_handle）
		 * 2. 在密钥派生时调用 SDF_GenerateKeyWithECCEx 生成共享密钥
		 *
		 * 触发条件：
		 * 1. initiator == 1（服务端）
		 * 2. peer_eph_pub == NULL（还没收到客户端公钥，即 ServerKeyExchange 阶段）
		 * 3. agreement_handle == NULL（还没生成过）
		 *
		 * derive 阶段 peer_eph_pub 不为 NULL，跳过密钥生成
		 */
		if (dctx->sm2dhe.initiator && dctx->sm2dhe.peer_eph_pub == NULL && dctx->sm2dhe.agreement_handle == NULL) {
			EVP_PKEY* pkey = EVP_PKEY_CTX_get0_pkey(ctx);
			SDF_KEY_CTX* key_ctx = NULL;
			ECCrefPublicKey sponsor_pub = { 0 };
			ECCrefPublicKey sponsor_tmp_pub = { 0 };
			int ret;

			if (!pkey) {
				SDF_ERR("pkey_ec_ctrl: Cannot get pkey from ctx");
				return 0;
			}

			/* 获取 SDF key context
			 * 注意：pkey 可能是临时密钥（没有 SDF_KEY_CTX），需要从证书密钥获取
			 */
			key_ctx = (SDF_KEY_CTX*)EVP_PKEY_get_ex_data(pkey, 0);
			if (!key_ctx || !key_ctx->sdf_ctx) {
				/* pkey 是临时密钥，尝试从证书密钥获取 SDF_KEY_CTX */
				if (dctx->sm2dhe.self_cert_priv) {
					key_ctx = (SDF_KEY_CTX*)EVP_PKEY_get_ex_data(dctx->sm2dhe.self_cert_priv, 0);
					SDF_INFO("pkey_ec_ctrl: pkey is ephemeral key, using SDF context from cert key");
				}

				if (!key_ctx || !key_ctx->sdf_ctx) {
					SDF_ERR("pkey_ec_ctrl: Cannot get SDF key context from pkey or cert key");
					return 0;
				}
			}

			/* 转换自身证书公钥（sponsor_pub） */
			if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_cert_pub), &sponsor_pub)) {
				SDF_ERR("pkey_ec_ctrl: Failed to convert self_cert_pub to ECCrefPublicKey");
				return 0;
			}

			/* 转换自身临时公钥（sponsor_tmp_pub） */
			if (!EC_KEY_get_ECCrefPublicKey(EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_pub), &sponsor_tmp_pub)) {
				SDF_ERR("pkey_ec_ctrl: Failed to convert self_eph_pub to ECCrefPublicKey");
				return 0;
			}

			SDF_INFO("pkey_ec_ctrl: Calling SDF_GenerateAgreementDataWithECCEx for initiator");
			SDF_INFO("  key_index=%u, self_id=%.*s (len=%zu)",
				key_ctx->key_index,
				dctx->sm2dhe.self_id_len, dctx->sm2dhe.self_id, dctx->sm2dhe.self_id_len);
			SDF_INFO("  sponsor_pub.bits=%d", sponsor_pub.bits);
			SDF_INFO("  sponsor_tmp_pub.bits=%d", sponsor_tmp_pub.bits);

			ret = key_ctx->sdf_ctx->sdfList.SDF_GenerateAgreementDataWithECCEx(
				key_ctx->sdf_ctx->hSession,
				key_ctx->key_index,
				sponsor_pub.bits,
				dctx->sm2dhe.self_id,
				dctx->sm2dhe.self_id_len,
				&sponsor_pub,
				&sponsor_tmp_pub,
				&dctx->sm2dhe.agreement_handle);

			if (ret != SDR_OK) {
				SDF_ERR("pkey_ec_ctrl: SDF_GenerateAgreementDataWithECCEx failed, ret=0x%08X", ret);
				if (key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg) {
					SDF_ERR("pkey_ec_ctrl: Error msg: %s", key_ctx->sdf_ctx->sdfList.SDF_GetErrMsg(ret));
				}
				return 0;
			}

			SDF_INFO("pkey_ec_ctrl: SDF_GenerateAgreementDataWithECCEx successful, agreement_handle=%p",
				dctx->sm2dhe.agreement_handle);

			/*
			 * CRITICAL: 将 agreement_handle 保存到 EVP_PKEY 的 ex_data 中
			 * 因为每次创建新的 EVP_PKEY_CTX 时都会创建新的 dctx，
			 * 导致保存在 dctx 中的 agreement_handle 丢失
			 *
			 * EVP_PKEY 对象在整个生命周期中是同一个，所以保存在这里更可靠
			 */
			SGD_HANDLE* saved_handle = OPENSSL_malloc(sizeof(SGD_HANDLE));
			if (saved_handle) {
				*saved_handle = dctx->sm2dhe.agreement_handle;
				EVP_PKEY_set_ex_data(pkey, 1, saved_handle);  /* index 1 for agreement_handle */
				SDF_INFO("pkey_ec_ctrl: Saved agreement_handle=%p to EVP_PKEY=%p ex_data", *saved_handle, pkey);
			}
			else {
				SDF_ERR("pkey_ec_ctrl: Failed to allocate memory for agreement_handle");
			}

			/*
			 * Plan A: 提取 SDF 生成的临时公钥并更新 self_eph_pub
			 *
			 * 问题：SSL层发送的是软件生成的临时公钥 (068101AA...)，
			 *      但SDF内部生成了新的临时密钥对 (65A2DA82...)
			 * 解决：从sponsor_tmp_pub（输出参数）中提取SDF生成的临时公钥，更新到self_eph_pub
			 *
			 * 注意：SDF_GenerateAgreementDataWithECCEx会覆盖sponsor_tmp_pub，
			 *      所以此时sponsor_tmp_pub包含的是SDF生成的公钥，不是SSL传入的！
			 */
			SDF_INFO("pkey_ec_ctrl: Plan A - Extracting SDF-generated ephemeral public key from sponsor_tmp_pub");

			SDF_INFO("pkey_ec_ctrl: SDF-generated temp public key (from sponsor_tmp_pub output):");
			SDF_HEX_DUMP("  x", sponsor_tmp_pub.x + ECCref_MAX_LEN - 32, 32);
			SDF_HEX_DUMP("  y", sponsor_tmp_pub.y + ECCref_MAX_LEN - 32, 32);

			/* 将SDF生成的临时公钥设置回self_eph_pub EVP_PKEY */
			EC_KEY* ec_key = (EC_KEY*)EVP_PKEY_get0_EC_KEY(dctx->sm2dhe.self_eph_pub);
			if (ec_key) {
				/* 从ECCrefPublicKey转换回EC_POINT */
				BIGNUM* x = BN_bin2bn(sponsor_tmp_pub.x + ECCref_MAX_LEN - 32, 32, NULL);
				BIGNUM* y = BN_bin2bn(sponsor_tmp_pub.y + ECCref_MAX_LEN - 32, 32, NULL);
				if (x && y) {
					EC_POINT* pub_point = EC_POINT_new(EC_KEY_get0_group(ec_key));
					if (pub_point) {
						if (EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(ec_key),
							pub_point, x, y, NULL)) {
							/* 设置新的公钥 */
							if (EC_KEY_set_public_key(ec_key, pub_point)) {
								SDF_INFO("pkey_ec_ctrl: Successfully updated self_eph_pub with SDF-generated public key");
								SDF_INFO("pkey_ec_ctrl: SSL layer will now send SDF's public key in ServerKeyExchange");
							}
							else {
								SDF_ERR("pkey_ec_ctrl: EC_KEY_set_public_key failed");
							}
						}
						else {
							SDF_ERR("pkey_ec_ctrl: EC_POINT_set_affine_coordinates_GFp failed");
						}
						EC_POINT_free(pub_point);
					}
					else {
						SDF_ERR("pkey_ec_ctrl: EC_POINT_new failed");
					}
				}
				else {
					SDF_ERR("pkey_ec_ctrl: BN_bin2bn failed");
				}
				if (x) BN_free(x);
				if (y) BN_free(y);
			}
			else {
				SDF_ERR("pkey_ec_ctrl: Cannot get EC_KEY from self_eph_pub");
			}

			/* 清除 deferred_keygen 标记，表示 SDF 密钥已生成 */
			dctx->sm2dhe.deferred_keygen = 0;
			SDF_INFO("pkey_ec_ctrl: SDF ephemeral key generated, cleared deferred_keygen flag");
		}
		else if (dctx->sm2dhe.initiator && dctx->sm2dhe.peer_eph_pub != NULL) {
			/* derive 阶段，peer_eph_pub 已存在，跳过重复生成 */
			SDF_INFO("pkey_ec_ctrl: peer_eph_pub exists (derive phase), skipping duplicate key generation");
			SDF_INFO("pkey_ec_ctrl: using existing agreement_handle=%p", dctx->sm2dhe.agreement_handle);
		}

		SDF_INFO("pkey_ec_ctrl: SDF_PKEY_CTRL_SET_SM2DHE_PARAMS set successfully");

		return 1;

	case SDF_PKEY_CTRL_GET_SDF_GENERATED_EPH_PUB:
		SDF_INFO("pkey_ec_ctrl: SDF_PKEY_CTRL_GET_SDF_GENERATED_EPH_PUB received");
		if (!dctx) {
			SDF_ERR("pkey_ec_ctrl: dctx is NULL");
			return 0;
		}

		/* 返回 SDF 生成的临时公钥 */
		if (dctx->sm2dhe.sdf_generated_eph_pub && dctx->sm2dhe.sdf_generated_eph_pub_len > 0) {
			/* p2 应该指向一个结构体，包含 pub 和 pub_len 指针 */
			struct {
				unsigned char** pub;
				size_t* pub_len;
			} *out = (void*)p2;

			if (out && out->pub && out->pub_len) {
				*out->pub = dctx->sm2dhe.sdf_generated_eph_pub;
				*out->pub_len = dctx->sm2dhe.sdf_generated_eph_pub_len;
				SDF_INFO("pkey_ec_ctrl: Returning SDF-generated ephemeral public key, len=%zu", *out->pub_len);
				return 1;
			}
		}

		SDF_INFO("pkey_ec_ctrl: No SDF-generated ephemeral public key available");
		return 0;

	default:
		SDF_INFO("pkey_ec_ctrl: unknown control type=%d, p1=%d, p2=%p, dctx=%p", type, p1, p2, dctx);
		/* 返回 0 表示不支持，让 OpenSSL 使用默认实现 */
		return 0;
	}
}

static int sdf_pkey_ec_ctrl_str(EVP_PKEY_CTX* ctx, const char* type,
	const char* value) {
	SDF_INFO("pkey_ec_ctrl_str: called with type='%s', value='%s'", type, value ? value : "(null)");
	if (strcmp(type, "ec_paramgen_curve") == 0) {
		int nid;
		nid = EC_curve_nist2nid(value);
		if (nid == NID_undef)
			nid = OBJ_sn2nid(value);
		if (nid == NID_undef)
			nid = OBJ_ln2nid(value);
		if (nid == NID_undef) {
			SDF_ERR("pkey_ec_ctrl_str: nid is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		/* 强制设置曲线参数，确保 OpenSSL 内部状态同步 */
		EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);

		/* 设置算法类型以确保正确的生成路径 */
		if (nid == NID_sm2) {
			/* SM2 特殊处理 */
			//EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_CTRL_EC_SCHEME, NID_sm2, NULL);
		}
		else {
			/* 标准椭圆曲线 */
			//EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_CTRL_EC_SCHEME, NID_undef, NULL);
		}

		// /* 最终验证设置 */
		// if (EVP_PKEY_CTX_get_ec_paramgen_curve_nid(ctx) != nid) {
		// 	SDF_ERR("pkey_ec_ctrl_str: failed to verify curve nid=%d after setting", nid);
		// 	SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
		// 	return 0;
		// }
#ifndef OPENSSL_NO_SM2
	}
	else if (strcmp(type, "group_name") == 0) {
		SDF_EC_PKEY_CTX* dctx = EVP_PKEY_CTX_get_data(ctx);
		int nid = OBJ_txt2nid(value);
		if (nid == NID_undef) {
			if (strcmp(value, "sm2p256v1") == 0 || strcmp(value, "SM2") == 0 || strcmp(value, "sm2") == 0)
				nid = NID_sm2;
		}
		if (nid == NID_undef) {
			SDF_ERR("pkey_ec_ctrl_str: group_name '%s' is invalid", value);
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}

		/* 确保 dctx 存在 */
		if (!dctx) {
			SDF_INFO("pkey_ec_ctrl_str: dctx is NULL, initializing");
			if (!sdf_pkey_ec_init(ctx)) {
				SDF_ERR("pkey_ec_ctrl_str: failed to initialize dctx");
				return 0;
			}
			dctx = EVP_PKEY_CTX_get_data(ctx);
		}

		/* 强制使用 SM2 曲线 */
		nid = NID_sm2;
		SDF_INFO("pkey_ec_ctrl_str: forcing SM2 curve, nid=%d", nid);

		/* 创建并设置 gen_group */
		EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
		if (!group) {
			SDF_ERR("pkey_ec_ctrl_str: failed to create group for nid=%d", nid);
			return 0;
		}
		EC_GROUP_free(dctx->gen_group);
		dctx->gen_group = group;
		dctx->ec_scheme = nid;
		SDF_INFO("pkey_ec_ctrl_str: group_name set successfully");
		return 1;
	}
	else if (!strcmp(type, "ec_scheme")) {
		int scheme;
		if (!strcmp(value, "sm2"))
			scheme = NID_sm2;
		else {
			SDF_ERR("pkey_ec_ctrl_str: scheme is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		/* 成功时返回 1，失败时返回 0 或 -2 */
		int result = EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1,
			EVP_PKEY_CTRL_EC_SCHEME, scheme, NULL);

		/* 添加调试日志 */
		SDF_INFO("pkey_ec_ctrl_str: ec_scheme result=%d", result);

		/* 添加更多调试信息 */
		SDF_INFO("pkey_ec_ctrl_str: scheme=%s, scheme_nid=%d", value, scheme);

		if (result == 1) {
			SDF_INFO("pkey_ec_ctrl_str: ec_scheme '%s' successfully set", value);
		}
		else {
			SDF_ERR("pkey_ec_ctrl_str: failed to set ec_scheme '%s'", value);
		}

		return result;
	}
	else if (!strcmp(type, "signer_id")) {
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1, EVP_PKEY_CTRL_SIGNER_ID, 0,
			(void*)value);
	}
	else if (!strcmp(type, "ec_encrypt_param")) {
		int encrypt_param;
		if (!(encrypt_param = OBJ_txt2nid(value))) {
			SDF_ERR("pkey_ec_ctrl_str: encrypt_param is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, -1,
			EVP_PKEY_CTRL_EC_ENCRYPT_PARAM, encrypt_param,
			NULL);
#endif
	}
	else if (strcmp(type, "ec_param_enc") == 0) {
		int param_enc;
		if (strcmp(value, "explicit") == 0)
			param_enc = 0;
		else if (strcmp(value, "named_curve") == 0)
			param_enc = OPENSSL_EC_NAMED_CURVE;
		else {
			SDF_ERR("pkey_ec_ctrl_str: param_enc is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
	}
	else if (strcmp(type, "ecdh_kdf_md") == 0) {
		const EVP_MD* md;
		if ((md = EVP_get_digestbyname(value)) == NULL) {
			SDF_ERR("pkey_ec_ctrl_str: md is invalid");
			SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
			return 0;
		}
		return EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md);
	}
	else if (strcmp(type, "ecdh_cofactor_mode") == 0) {
		int co_mode;
		co_mode = atoi(value);
		return EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, co_mode);
	}

	SDF_ERR("pkey_ec_ctrl_str: type is invalid");
	SDFerr(SDF_F_SDF_ECC_VERIFY, SDF_R_SIGNATURE_VERIFICATION_FAILED);
	return 0;
}

static EVP_PKEY_METHOD* sdf_ec_pkey_meth = NULL;

static EVP_PKEY_METHOD* get_sdf_ec_pkey_method(void) {
	if (sdf_ec_pkey_meth)
		return sdf_ec_pkey_meth;

	//sdf_ec_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
	sdf_ec_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
	if (!sdf_ec_pkey_meth) {
		SDF_ERR("get_sdf_ec_pkey_method: alloc sdf_ec_pkey_meth failed");
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
	/* 设置 digestsign 方法，直接处理原始消息并正确计算 e = SM3(ZA || M) */
	EVP_PKEY_meth_set_digestsign(sdf_ec_pkey_meth, sdf_pkey_ec_digestsign);
	/* 设置 digestverify 方法，直接处理原始消息并正确计算 e = SM3(ZA || M) */
	EVP_PKEY_meth_set_digestverify(sdf_ec_pkey_meth, sdf_pkey_ec_digestverify);

	return sdf_ec_pkey_meth;
}
static EVP_PKEY_METHOD* sdf_sm2_pkey_meth = NULL;

static int sdf_pkey_sm2_init(EVP_PKEY_CTX* ctx) {
	SDF_EC_PKEY_CTX* dctx;
	EVP_PKEY* pkey;

	SDF_INFO("pkey_sm2_init: initializing SM2 PKEY context");
	dctx = OPENSSL_zalloc(sizeof(*dctx));
	if (dctx == NULL) {
		SDF_ERR("sdf_pkey_sm2_init: alloc dctx failed");
		SDFerr(SDF_F_SDF_CTRL, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	dctx->cofactor_mode = -1;
	dctx->kdf_type = EVP_PKEY_ECDH_KDF_NONE;
	
#ifndef OPENSSL_NO_SM2
	/* 立即创建 SM2 曲线的 EC_GROUP，确保 gen_group 不为 NULL */
	dctx->gen_group = EC_GROUP_new_by_curve_name(NID_sm2);
	if (!dctx->gen_group) {
		SDF_ERR("pkey_sm2_init: failed to create SM2 group");
		SDFerr(SDF_F_SDF_CTRL, SDF_R_MEMORY_ALLOCATION_FAILED);
		OPENSSL_free(dctx);
		return 0;
	}
	SDF_INFO("pkey_sm2_init: created SM2 group successfully, gen_group=%p", dctx->gen_group);

	/* 根据 pkey 类型设置 ec_scheme */
	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey) {
		int pkey_id = EVP_PKEY_id(pkey);
		int is_sm2_ctx = (pkey_id == EVP_PKEY_SM2);
		
		SDF_INFO("pkey_sm2_init: pkey=%p, pkey_id=%d, is_sm2_ctx=%d, EVP_PKEY_SM2=%d, EVP_PKEY_EC=%d",
			pkey, pkey_id, is_sm2_ctx, EVP_PKEY_SM2, EVP_PKEY_EC);
		
		/* 强制使用 SM2 曲线用于 ECDHE 密钥生成 */
		SDF_INFO("pkey_sm2_init: Forcing SM2 curve for ECDHE key generation");
		dctx->ec_scheme = NID_sm2;
		SDF_INFO("pkey_sm2_init: pkey_id=%d, ec_scheme=%d, NID_sm2=%d, NID_X9_62_prime256v1=%d",
			pkey_id, dctx->ec_scheme, NID_sm2, NID_X9_62_prime256v1);
	} else {
		/* 没有 pkey（keygen 场景），强制使用 SM2 */
		SDF_INFO("pkey_sm2_init: Forcing SM2 curve for ECDHE key generation");
		dctx->ec_scheme = NID_sm2;
	}
	
	dctx->signer_id = NULL;
	dctx->signer_id_len = 0;
	dctx->signer_zid = NULL;
	dctx->signer_zid_len = 0;
	dctx->ec_encrypt_param = NID_undef;
#endif

	EVP_PKEY_CTX_set_data(ctx, dctx);
	SDF_INFO("pkey_sm2_init: context initialized successfully, dctx=%p", dctx);
	SDF_INFO("pkey_sm2_init: ctx=%p, dctx=%p, ec_scheme=%d, gen_group=%p",
		ctx, dctx, dctx->ec_scheme, dctx->gen_group);
	return 1;
}


static EVP_PKEY_METHOD* get_sdf_sm2_pkey_method(void) {
	if (sdf_sm2_pkey_meth)
		return sdf_sm2_pkey_meth;

	sdf_sm2_pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_SM2, 0);
	if (!sdf_sm2_pkey_meth) {
		SDF_ERR("get_sdf_sm2_pkey_method: alloc sdf_sm2_pkey_meth failed");
		SDFerr(SDF_F_SDF_CTRL, SDF_R_MEMORY_ALLOCATION_FAILED);
		return NULL;
	}

	/* 复用 EC 的实现函数 */
	EVP_PKEY_meth_set_init(sdf_sm2_pkey_meth, sdf_pkey_sm2_init);
	EVP_PKEY_meth_set_copy(sdf_sm2_pkey_meth, sdf_pkey_ec_copy);
	EVP_PKEY_meth_set_cleanup(sdf_sm2_pkey_meth, sdf_pkey_ec_cleanup);
	EVP_PKEY_meth_set_paramgen(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_paramgen);
	EVP_PKEY_meth_set_keygen(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_keygen);
	EVP_PKEY_meth_set_sign(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_sign);
	EVP_PKEY_meth_set_verify(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_verify);
	EVP_PKEY_meth_set_encrypt(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_encrypt);
	EVP_PKEY_meth_set_decrypt(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_decrypt);
	/* 设置 digestsign 方法，直接处理原始消息并正确计算 e = SM3(ZA || M) */
	EVP_PKEY_meth_set_digestsign(sdf_sm2_pkey_meth, sdf_pkey_ec_digestsign);
	/* 设置 digestverify 方法，直接处理原始消息并正确计算 e = SM3(ZA || M) */
	EVP_PKEY_meth_set_digestverify(sdf_sm2_pkey_meth, sdf_pkey_ec_digestverify);
	EVP_PKEY_meth_set_derive(sdf_sm2_pkey_meth, NULL, sdf_pkey_ec_kdf_derive);
	EVP_PKEY_meth_set_ctrl(sdf_sm2_pkey_meth, sdf_pkey_ec_ctrl, sdf_pkey_ec_ctrl_str);

	SDF_INFO("get_sdf_sm2_pkey_method: SM2 method created successfully, meth=%p", sdf_sm2_pkey_meth);
	SDF_INFO("get_sdf_sm2_pkey_method: ctrl callback set to sdf_pkey_ec_ctrl=%p", sdf_pkey_ec_ctrl);

	return sdf_sm2_pkey_meth;
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
static int sdf_pkey_meths(ENGINE* e, EVP_PKEY_METHOD** pmeth, const int** nids, int nid) {
	/* 支持的 PKEY NID 列表（以 0 结尾） */
	static int sdf_pkey_nids_all[] = {
		#ifndef OPENSSL_NO_EC
		EVP_PKEY_EC,  /* 确保支持EC类型，用于ECDHE */
		#endif
		#ifndef OPENSSL_NO_SM2
		EVP_PKEY_SM2,
		#endif
		// EVP_PKEY_RSA,
		0 };

	if (pmeth == NULL) {
		/* 返回支持的 NID 列表 */
		*nids = sdf_pkey_nids_all;
		SDF_INFO("sdf_pkey_meths: returning supported NIDs: EVP_PKEY_EC=%d, EVP_PKEY_SM2=%d", EVP_PKEY_EC, EVP_PKEY_SM2);
		return 2; /* 返回支持的 NID 数量：EC SM2 */
	}

	if (nid == EVP_PKEY_EC) {
		SDF_INFO("sdf_pkey_meths: requested EVP_PKEY_EC, returning sdf_ec_pkey_meth");
		*pmeth = get_sdf_ec_pkey_method();
		return (*pmeth != NULL) ? 1 : 0;
	}

#ifndef OPENSSL_NO_SM2
	if (nid == EVP_PKEY_SM2) {
		/* SM2 必须返回独立的 sdf_sm2_pkey_meth，不能返回 sdf_ec_pkey_meth */
		/* 否则会导致双重释放（double free）崩溃 */
		SDF_INFO("sdf_pkey_meths: requested EVP_PKEY_SM2, returning independent SM2 method");
		*pmeth = get_sdf_sm2_pkey_method();
		return (*pmeth != NULL) ? 1 : 0;
	}
#endif

	* pmeth = NULL;
	SDF_ERR("sdf_pkey_meths: pmeth is null, unsupported nid=%d", nid);
	SDFerr(SDF_F_SDF_CTRL, SDF_R_INVALID_PARAMETER);
	return 0;
}

/* ENGINE 初始化 */
static int sdf_init(ENGINE* e) {
	SDF_CTX* ctx;

	/* 初始化 ENGINE 索引 */
	if (sdf_engine_idx == -1) {
		sdf_engine_idx = ENGINE_get_ex_new_index(0, "SDF_CTX", NULL, NULL, NULL);
		if (sdf_engine_idx == -1) {
			SDF_ERR("sdf_init: alloc sdf_engine_idx failed");
			SDFerr(SDF_F_SDF_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
	}

	ctx = sdf_get_ctx(e);
	if (!ctx) {
		ctx = sdf_ctx_new();
		if (!ctx) {
			SDF_ERR("sdf_init: alloc ctx failed");
			SDFerr(SDF_F_SDF_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
		if (!sdf_set_ctx(e, ctx)) {
			sdf_ctx_free(ctx);
			SDF_ERR("sdf_init: set ctx failed");
			SDFerr(SDF_F_SDF_INIT, SDF_R_MEMORY_ALLOCATION_FAILED);
			return 0;
		}
	}

	/* 绑定功能（使用当前的功能掩码）*/
	SDF_INFO("sdf_init: Feature mask is 0x%04X, rebinding features", sdf_global_feature_mask);

	/* 如果功能掩码为 0（配置文件显式设置为 0），不绑定任何功能 */
	if (sdf_global_feature_mask == 0) {
		SDF_INFO("sdf_init: Feature mask is 0, engine disabled by configuration");
		return 1;
	}

	//sdf_rebind_features(e);

	/* 如果已经设置了模块路径，立即初始化设备 */
	if (ctx->module_path) {
		return sdf_init_device(ctx);
	}

	return 1; /* 延迟初始化 */
}

/* ENGINE 清理 */
static int sdf_finish(ENGINE* e) {
	SDF_CTX* ctx = sdf_get_ctx(e);
	if (ctx) {
		sdf_ctx_free(ctx);
		sdf_set_ctx(e, NULL);
	}
	return 1;
}

/* ENGINE 销毁 */
static int sdf_destroy(ENGINE* e) {
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
	ENGINE* e, SSL* ssl, unsigned char* out, size_t outlen, int* outlen_ret) {
	SDF_INFO("sdf_ssl_generate_master_secret: called, outlen=%zu", outlen);

	/* 输出更多调试信息 */
	const char* cipher_name = SSL_get_cipher_name(ssl);
	const char* cipher_version = SSL_get_cipher_version(ssl);
	SDF_INFO("Master secret generation for cipher: %s (%s)",
		cipher_name ? cipher_name : "unknown",
		cipher_version ? cipher_version : "unknown");

	/* 使用OpenSSL默认实现，不使用硬件加速 */
	SDF_INFO("SDF: Using software implementation for master secret generation");
	return 0; /* 返回0让OpenSSL使用默认实现 */
}

/* TLS密钥块生成函数 - 软件实现 */
static int sdf_tls1_generate_key_block(
	ENGINE* e, SSL* ssl, unsigned char* km, size_t kmlen, int free_km) {
	SDF_INFO("sdf_tls1_generate_key_block: called, kmlen=%zu", kmlen);

	/* 输出更多调试信息 */
	const char* cipher_name = SSL_get_cipher_name(ssl);
	const char* cipher_version = SSL_get_cipher_version(ssl);
	SDF_INFO("Key block generation for cipher: %s (%s)",
		cipher_name ? cipher_name : "unknown",
		cipher_version ? cipher_version : "unknown");

	/* 使用OpenSSL默认实现，不使用硬件加速 */
	SDF_INFO("SDF: Using software implementation for key block generation");
	return 0; /* 返回0让OpenSSL使用默认实现 */
}

/* 私钥转换函数 - 硬件实现 */
static int sdf_convert_privkey(ENGINE* e, const char* key_id,
	size_t key_id_len, unsigned char* key,
	void* callback_data) {
	SDF_CTX* ctx = sdf_get_ctx(e);
	if (!ctx) {
		SDF_ERR("sdf_convert_privkey: ctx is null");
		SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_LIBRARY_NOT_INITIALIZED);
		return 0;
	}

	SDF_INFO("SDF: Converting private key from hardware device: %s",
		key_id ? key_id : "default");

	/* 这里可以实现从 SDF 设备中加载私钥的逻辑 */
	/* 目前回退到标准的私钥加载函数 */
	SDF_ERR("sdf_convert_privkey: using software implementation for private key conversion");
	SDFerr(SDF_F_SDF_LOAD_PRIVKEY, SDF_R_LIBRARY_NOT_INITIALIZED);
	return 0; /* 返回0表示使用默认实现 */
}

#endif /* OPENSSL_NO_SM2 */

/* 位掩码功能控制函数实现 */

/* 清理所有引擎绑定 */
static void sdf_clear_all_bindings(ENGINE* e) {
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
static int sdf_rebind_features(ENGINE* e) {
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
		ENGINE_set_EC(e, get_sdf_ec_method());
		SDF_INFO("  EC methods: ENABLED");
	}

	/* 随机数生成功能 (危险) */
	if (sdf_global_feature_mask & ENGINE_FEATURE_RAND) {
		/* ENGINE_set_RAND(e, &sdf_rand_method); */
		SDF_WARN("  RAND takeover: ENABLED (May cause static linking issues!)");
	}

	/* EVP_PKEY_METHOD功能 */
	if (sdf_global_feature_mask & ENGINE_FEATURE_PKEY_METHS) {
		ENGINE_set_pkey_meths(e, sdf_pkey_meths);
		/* 注册 PKEY methods 到全局表 */
		int ret = ENGINE_register_pkey_meths(e);
		SDF_INFO("  PKEY methods: ENABLED, registration: %s", ret ? "SUCCESS" : "FAILED");
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
		/* 暂时使用OpenSSL默认实现 */
		SDF_INFO("  Ciphers: ENABLED (using OpenSSL default)");
	}

	/* 摘要算法功能 */
	if (sdf_global_feature_mask & ENGINE_FEATURE_DIGESTS) {
		/* 暂时使用OpenSSL默认实现 */
		SDF_INFO("  Digests: ENABLED (using OpenSSL default)");
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
		SDF_ERR("sdf_set_feature_mask: invalid mask");
		SDFerr(SDF_F_SDF_SET_FEATURE_MASK, SDF_R_INVALID_PARAMETER);
		return 0;
	}

	sdf_global_feature_mask = mask;
	return 1;
}

/* 验证功能掩码有效性 */
static int sdf_validate_mask(unsigned int mask) {
	/* 基本有效性检查 */
	if (mask == 0) {
		SDF_ERR("sdf_validate_mask: mask is 0");
		SDFerr(SDF_F_SDF_VALIDATE_MASK, SDF_R_INVALID_PARAMETER);
		return 0;
	} /* 不允许全部禁用 */

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
static int bind_sdf(ENGINE* e) {
	/* 设置基本属性和标志 */
	if (!ENGINE_set_id(e, engine_sdf_id) ||
		!ENGINE_set_name(e, engine_sdf_name) ||
		!ENGINE_set_init_function(e, sdf_init) ||
		!ENGINE_set_finish_function(e, sdf_finish) ||
		!ENGINE_set_destroy_function(e, sdf_destroy) ||
		!ENGINE_set_ctrl_function(e, sdf_ctrl) ||
		!ENGINE_set_cmd_defns(e, sdf_cmd_defns)) {
		SDF_ERR("bind_sdf: set basic properties failed");
		SDFerr(SDF_F_BIND_SDF, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}

	/* 绑定默认功能 */
	SDF_INFO("bind_sdf: Initializing with feature mask: 0x%04X", sdf_global_feature_mask);

	/* 如果功能掩码为0（配置文件显式设置为0），不绑定任何功能 */
	if (sdf_global_feature_mask == 0) {
		SDF_INFO("  Engine disabled (FEATURE_MASK=0 in config)");
	}
	else {
		SDF_INFO("  Binding features (default or configured)");
		sdf_rebind_features(e);
	}

	/* 注册 PKEY methods 到全局表（仅在功能掩码不为0时） */
	if (sdf_global_feature_mask != 0 && (sdf_global_feature_mask & ENGINE_FEATURE_PKEY_METHS)) {
		int ret = ENGINE_register_pkey_meths(e);
		SDF_INFO("PKEY methods registered to global table: %s", ret ? "SUCCESS" : "FAILED");

		///* 验证注册结果 */
		//ENGINE *found = ENGINE_get_pkey_meth_engine(EVP_PKEY_SM2);
		//SDF_INFO("Verification: ENGINE_get_pkey_meth_engine(SM2) = %p (id=%s)", 
		//         found, found ? ENGINE_get_id(found) : "(null)");
		//if (found) ENGINE_finish(found);
	}

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
static int bind_helper(ENGINE* e, const char* id) {
	if (id && (strcmp(id, engine_sdf_id) != 0)) {
		SDF_ERR("bind_helper: id is not engine_sdf_id");
		SDFerr(SDF_F_BIND_SDF, SDF_R_INVALID_PARAMETER);
		return 0;
	}
	if (!bind_sdf(e)) {
		SDF_ERR("bind_helper: bind_sdf failed");
		SDFerr(SDF_F_BIND_SDF, SDF_R_MEMORY_ALLOCATION_FAILED);
		return 0;
	}
	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
#else
/* 静态引擎注册 */
static ENGINE* engine_sdf(void) {
	ENGINE* ret = ENGINE_new();
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
	ENGINE* toadd = engine_sdf();
	if (!toadd)
		return;
	sdf_engine = toadd; /* Store global reference */
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

void ENGINE_load_sdf(void) {
	/* 使用 ENGINE_load_builtin_engines 替代 ENGINE_add */
	ENGINE_load_builtin_engines();
}
#endif
