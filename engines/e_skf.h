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
  * Public API
  */

#ifndef OSSL_ENGINES_E_SKF_H
#define OSSL_ENGINES_E_SKF_H

#include <openssl/opensslconf.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

# if defined(__GNUC__) && __GNUC__ >= 4 && \
     (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#  pragma GCC diagnostic ignored "-Wvariadic-macros"
# endif

# ifdef _MSC_VER
#  define SKF_LOG(level, fmt, ...) \
                fprintf(stderr, level ": %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
# else
#  define SKF_LOG(level, fmt, ...) \
                fprintf(stderr, level ": %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
# endif

# ifdef SKF_DEBUG
#  ifdef _MSC_VER
#   define SKF_DGB(fmt, ...)  SKF_LOG("SKF_DBG", fmt, __VA_ARGS__)
#   define SKF_INFO(fmt, ...) SKF_LOG("SKF_INFO", fmt, __VA_ARGS__)
#   define SKF_WARN(fmt, ...) SKF_LOG("SKF_WARN", fmt, __VA_ARGS__)
#  else
#   define SKF_DGB(fmt, ...)  SKF_LOG("SKF_DBG", fmt, ##__VA_ARGS__)
#   define SKF_INFO(fmt, ...) SKF_LOG("SKF_INFO", fmt, ##__VA_ARGS__)
#   define SKF_WARN(fmt, ...) SKF_LOG("SKF_WARN", fmt, ##__VA_ARGS__)
#  endif
# else
#  define SKF_DGB(fmt, ...)
#  define SKF_INFO(fmt, ...)
#  define SKF_WARN(fmt, ...)
# endif

# ifdef _MSC_VER
#  define SKF_ERR(fmt, ...)  SKF_LOG("SKF_ERR", fmt, __VA_ARGS__)
#  define SKF_PERR(fmt, ...) \
                do { \
                    SKF_LOG("SKF_PERR", fmt, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)
#  define SKF_PWARN(fmt, ...) \
                do { \
                    SKF_LOG("SKF_PWARN", fmt, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)
# else
#  define SKF_ERR(fmt, ...)  SKF_LOG("SKF_ERR", fmt, ##__VA_ARGS__)
#  define SKF_PERR(fmt, ...) \
                do { \
                    SKF_LOG("SKF_PERR", fmt, ##__VA_ARGS__); \
                    perror(NULL); \
                } while(0)
#  define SKF_PWARN(fmt, ...) \
                do { \
                    SKF_LOG("SKF_PWARN", fmt, ##__VA_ARGS__); \
                    perror(NULL); \
                } while(0)
# endif

#ifdef __cplusplus
extern "C" {
#endif
#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

	typedef signed char         INT8;          //有符号8位整数
	typedef signed short        INT16;         //有符号16位整数 
	typedef signed int          INT32;         //有符号32位整数
	typedef unsigned char       UINT8;         //无符号8位整数
	typedef unsigned short      UINT16;        //无符号16位整数
	typedef unsigned int        UINT32;        //无符号32位整数
	typedef int                 BOOL;          //布尔类型，取值为TRUE或FALSE

	typedef unsigned char       BYTE;          //字节类型，无符号8位整数
	typedef char                CHAR;          //字符类型，无符号8位整数
	typedef unsigned char       UCHAR;
	typedef short               SHORT;         //短整数，有符号16位
	typedef unsigned short      USHORT;        //无符号16位整数
#if (defined(_WIN32) || defined(_WIN64))
	typedef long                LONG;          //长整数，有符号32位整数
	typedef unsigned long       ULONG;         //长整数，无符号32位整数
	typedef unsigned long       DWORD;         //双字类型，无符号32位整数
#else
	typedef int                LONG;          //长整数，有符号32位整数
	typedef unsigned int       ULONG;         //长整数，无符号32位整数
	typedef unsigned int       DWORD;         //双字类型，无符号32位整数
#endif
	typedef unsigned int        UINT;          //无符号32位整数
	typedef unsigned short      WORD;          //字类型，无符号16位整数

	typedef UINT32              FLAGS;         //标志类型，无符号32位整数
	typedef CHAR* LPSTR;         //8位字符串指针，按照UTF8格式存储及交换
	typedef void* HANDLE;        //句柄，指向任意数据对象的起始地址
	typedef HANDLE              DEVHANDLE;     //设备句柄
	typedef HANDLE              HAPPLICATION;  //应用句柄
	typedef HANDLE              HCONTAINER;    //容器句柄
#if !(defined(_WIN32) || defined(_WIN64))
	typedef void* HMODULE;
#define _stdcall	
#define __stdcall	
#define WINAPI
#define DEVAPI
#define EPSAPI
#else
#define DEVAPI     _stdcall        //_stdcall函数调用方式
#define EPSAPI     _stdcall        //_stdcall函数调用方式
#endif

#ifndef CONST
#define CONST               const
#endif



	//PIN类型
#define ADMIN_TYPE          0              //管理员PIN类型
#define USER_TYPE           1              //用户PIN类型


//分组密码算法标识
#define SGD_SM1_ECB					0x00000101	//SM1算法ECB加密模式
#define SGD_SM1_CBC					0x00000102	//SM1算法CBC加密模式
#define SGD_SM1_CFB					0x00000104	//SM1算法CFB加密模式
#define SGD_SM1_OFB					0x00000108	//SM1算法OFB加密模式
#define SGD_SM1_MAC					0x00000110	//SM1算法MAC加密模式
#define SGD_SSF33_ECB				0x00000201	//SSF33算法ECB加密模式
#define SGD_SSF33_CBC				0x00000202	//SSF33算法CBC加密模式
#define SGD_SSF33_CFB				0x00000204	//SSF33算法CFB加密模式
#define SGD_SSF33_OFB				0x00000208	//SSF33算法OFB加密模式
#define SGD_SSF33_MAC				0x00000210	//SSF33算法MAC加密模式
#define SGD_SMS4_ECB				0x00000401	//SSF33算法ECB加密模式
#define SGD_SMS4_CBC				0x00000402	//SSF33算法CBC加密模式
#define SGD_SMS4_CFB				0x00000404	//SSF33算法CFB加密模式
#define SGD_SMS4_OFB				0x00000408	//SSF33算法OFB加密模式
#define SGD_SMS4_MAC				0x00000410	//SSF33算法MAC加密模式

//非对称密码算法标识
#define SGD_RSA						0x00010000	//RSA算法
#define SGD_SM2_1					0x00020100	//椭圆曲线签名算法
#define SGD_SM2_2					0x00020200	//椭圆曲线密钥交换协议
#define SGD_SM2_3					0x00020400	//椭圆曲线加密算法

//密码杂凑算法标识
#define SGD_SM3						0x00000001	//SM3杂凑算法
#define SGD_SHA1					0x00000002	//SHA1杂凑算法
#define SGD_SHA256					0x00000004	//SHA256杂凑算法

#define MAX_RSA_MODULUS_LEN           256    //RSA模数n = p * q长度(字节)
#define MAX_RSA_MODULUS_LEN_EX        512    //RSA模数n = p * q长度(字节)
#define MAX_RSA_EXPONENT_LEN          4      //RSA公开密钥e长度(字节),一般为00010001

#define ECC_MAX_XCOORDINATE_BITS_LEN  512    //ECC曲线上点的X坐标
#define ECC_MAX_YCOORDINATE_BITS_LEN  512    //ECC曲线上点的Y坐标
#define ECC_MAX_MODULUS_BITS_LEN      512    //ECC算法模数的最大长度 

#define MAX_IV_LEN                    32     //初始化向量的最大长度

//版本:
//主版本号和次版本号以“.”分隔，例如 Version 1.0，主版本号为1，次版本号为0；Version 2.10，主版本号为2，次版本号为10。
	typedef struct Struct_Version
	{
		BYTE major;  //主版本号
		BYTE minor;  //次版本号
	}VERSION;

	// 设备信息结构
	typedef struct Struct_DEVINFO {
		VERSION     Version;                 // 版本号
		CHAR        Manufacturer[64];        // 厂商信息
		CHAR        Issuer[64];              // 发行者信息
		CHAR        Label[32];               // 标签
		CHAR        SerialNumber[32];        // 序列号
		VERSION     HWVersion;               // 硬件版本
		VERSION     FirmwareVersion;         // 固件版本
		ULONG       AlgSymCap;               // 对称算法能力
		ULONG       AlgAsymCap;              // 非对称算法能力
		ULONG       AlgHashCap;              // 杂凑算法能力
		ULONG       DevAuthAlgId;            // 设备认证算法标识
		ULONG       TotalSpace;              // 总空间大小
		ULONG       FreeSpace;               // 剩余空间大小
		ULONG       MaxECCBufferSize;        // 最大ECC缓冲区大小
		ULONG       MaxBufferSize;           // 最大缓冲区大小
		BYTE        Reserved[64];            // 保留
	} DEVINFO, * PDEVINFO;

	// RSA公钥结构
	typedef struct Struct_RSAPUBLICKEYBLOB {
		ULONG       AlgID;                   // 算法标识
		ULONG       BitLen;                  // 模数的位长度
		BYTE        Modulus[MAX_RSA_MODULUS_LEN];            // 模数n
		BYTE        PublicExponent[MAX_RSA_EXPONENT_LEN];       // 公钥指数e
	} RSAPUBLICKEYBLOB, * PRSAPUBLICKEYBLOB;


	// RSA公钥结构
	typedef struct Struct_RSAPUBLICKEYBLOBEX {
		ULONG       AlgID;                   // 算法标识
		ULONG       BitLen;                  // 模数的位长度
		BYTE        Modulus[MAX_RSA_MODULUS_LEN_EX];            // 模数n
		BYTE        PublicExponent[MAX_RSA_EXPONENT_LEN];       // 公钥指数e
	} RSAPUBLICKEYBLOBEX, * PRSAPUBLICKEYBLOBEX;

	// RSA私钥结构
	typedef struct Struct_RSAPRIVATEKEYBLOB {
		ULONG       AlgID;                   // 算法标识
		ULONG       BitLen;                  // 模数的位长度
		BYTE        Modulus[MAX_RSA_MODULUS_LEN];            // 模数n
		BYTE        PublicExponent[MAX_RSA_EXPONENT_LEN];       // 公钥指数e
		BYTE        PrivateExponent[MAX_RSA_MODULUS_LEN];    // 私钥指数d
		BYTE        Prime1[MAX_RSA_MODULUS_LEN / 2];             // 素数p
		BYTE        Prime2[MAX_RSA_MODULUS_LEN / 2];             // 素数q
		BYTE        Prime1Exponent[MAX_RSA_MODULUS_LEN / 2];     // d mod (p-1)
		BYTE        Prime2Exponent[MAX_RSA_MODULUS_LEN / 2];     // d mod (q-1)
		BYTE        Coefficient[MAX_RSA_MODULUS_LEN / 2];        // q^(-1) mod p
	} RSAPRIVATEKEYBLOB, * PRSAPRIVATEKEYBLOB;

	typedef struct Struct_RSAPRIVATEKEYBLOBEX {
		ULONG       AlgID;                   // 算法标识
		ULONG       BitLen;                  // 模数的位长度
		BYTE        Modulus[MAX_RSA_MODULUS_LEN_EX];            // 模数n
		BYTE        PublicExponent[MAX_RSA_EXPONENT_LEN];       // 公钥指数e
		BYTE        PrivateExponent[MAX_RSA_MODULUS_LEN_EX];    // 私钥指数d
		BYTE        Prime1[MAX_RSA_MODULUS_LEN_EX / 2];             // 素数p
		BYTE        Prime2[MAX_RSA_MODULUS_LEN_EX / 2];             // 素数q
		BYTE        Prime1Exponent[MAX_RSA_MODULUS_LEN_EX / 2];     // d mod (p-1)
		BYTE        Prime2Exponent[MAX_RSA_MODULUS_LEN_EX / 2];     // d mod (q-1)
		BYTE        Coefficient[MAX_RSA_MODULUS_LEN_EX / 2];        // q^(-1) mod p
	} RSAPRIVATEKEYBLOBEX, * PRSAPRIVATEKEYBLOBEX;
#ifndef BYZKENVELOPTYPE
#define BYZKENVELOPTYPE 1

	// ECC公钥结构
	typedef struct Struct_ECCPUBLICKEYBLOB {
		ULONG       BitLen;                  // 密钥长度
		BYTE        XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];         // X坐标
		BYTE        YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];         // Y坐标
	} ECCPUBLICKEYBLOB, * PECCPUBLICKEYBLOB;

	// ECC密文结构
	typedef struct Struct_ECCCIPHERBLOB {
		BYTE        XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN / 8];         // X坐标
		BYTE        YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN / 8];         // Y坐标
		BYTE        HASH[32];                // 杂凑值
		ULONG       CipherLen;               // 密文长度
		BYTE        Cipher[256];               // 密文
	} ECCCIPHERBLOB, * PECCCIPHERBLOB;

#endif 

	// ECC私钥结构
	typedef struct Struct_ECCPRIVATEKEYBLOB {
		ULONG       BitLen;                  // 密钥长度
		BYTE        PrivateKey[ECC_MAX_MODULUS_BITS_LEN / 8];          // 私钥
	} ECCPRIVATEKEYBLOB, * PECCPRIVATEKEYBLOB;


	// ECC签名结构
	typedef struct Struct_ECCSIGNATUREBLOB {
		BYTE        r[ECC_MAX_MODULUS_BITS_LEN / 8];                   // 签名r
		BYTE        s[ECC_MAX_MODULUS_BITS_LEN / 8];                   // 签名s
	} ECCSIGNATUREBLOB, * PECCSIGNATUREBLOB;

	typedef struct SKF_ENVELOPEDKEYBLOB {
		ULONG Version;                  // 当前版本为 1
		ULONG ulSymmAlgID;              // 规范中的算法标识，限定ECB模式
		ULONG ulBits;					// 加密密钥对的密钥位长度
		BYTE cbEncryptedPriKey[64];     // 加密保护的加密私钥
		ECCPUBLICKEYBLOB PubKey;        // 加密公钥
		ECCCIPHERBLOB ECCCipherBlob;    // SM2 公钥加密的密钥加密密钥
	}ENVELOPEDKEYBLOB, * PENVELOPEDKEYBLOB;

	// 分组密码参数结构
	typedef struct Struct_BLOCKCIPHERPARAM {
		BYTE        IV[32];                  // 初始向量
		ULONG       IVLen;                   // 初始向量长度
		ULONG       PaddingType;             // 填充方式
		ULONG       FeedBitLen;              // 反馈值长度
	} BLOCKCIPHERPARAM, * PBLOCKCIPHERPARAM;

	// 文件属性结构
	typedef struct Struct_FILEATTRIBUTE {
		CHAR        FileName[32];            // 文件名
		ULONG       FileSize;                // 文件大小
		ULONG       ReadRights;              // 读权限
		ULONG       WriteRights;             // 写权限
	} FILEATTRIBUTE, * PFILEATTRIBUTE;


	//权限类型
#define SECURE_NEVER_ACCOUNT    0x00000000   //不允许
#define SECURE_ADM_ACCOUNT      0x00000001   //管理员权限
#define SECURE_USER_ACCOUNT     0x00000010   //用户权限
#define SECURE_ANYONE_ACCOUNT   0x000000FF   //任何人

//设备状态
#define DEV_ABSENT_STATE        0x00000000 //设备不存在
#define DEV_PRESENT_STATE       0x00000001 //设备存在
#define DEV_UNKNOW_STATE        0x00000002 //设备状态未知

//密码服务接口错误代码定义和说明
#define SAR_OK                        0X00000000 //成功 
#define SAR_FAIL                      0X0A000001 //失败 
#define SAR_UNKNOWNERR                0X0A000002 //异常错误 
#define SAR_NOTSUPPORTYETERR          0X0A000003 //不支持的服务 
#define SAR_FILEERR                   0X0A000004 //文件操作错误 
#define SAR_INVALIDHANDLEERR          0X0A000005 //无效的句柄 
#define SAR_INVALIDPARAMERR           0X0A000006 //无效的参数 
#define SAR_READFILEERR               0X0A000007 //读文件错误 
#define SAR_WRITEFILEERR              0X0A000008 //写文件错误 
#define SAR_NAMELENERR                0X0A000009 //名称长度错误 
#define SAR_KEYUSAGEERR               0X0A00000A //密钥用途错误 
#define SAR_MODULUSLENERR             0X0A00000B //模的长度错误 
#define SAR_NOTINITIALIZEERR          0X0A00000C //未初始化 
#define SAR_OBJERR                    0X0A00000D //对象错误 
#define SAR_MEMORYERR                 0X0A00000E //内存错误 
#define SAR_TIMEOUTERR                0X0A00000F //超时 
#define SAR_INDATALENERR              0X0A000010 //输入数据长度错误 
#define SAR_INDATAERR                 0X0A000011 //输入数据错误 
#define SAR_GENRANDERR                0X0A000012 //生成随机数错误 
#define SAR_HASHOBJERR                0X0A000013 //HASH对象错 
#define SAR_HASHERR                   0X0A000014 //HASH运算错误 
#define SAR_GENRSAKEYERR              0X0A000015 //产生RSA密钥错 
#define SAR_RSAMODULUSLENERR          0X0A000016 //RSA密钥模长错误 
#define SAR_CSPIMPRTPUBKEYERR         0X0A000017 //CSP服务导入公钥错误 
#define SAR_RSAENCERR                 0X0A000018 //RSA加密错误 
#define SAR_RSADECERR                 0X0A000019 //RSA解密错误 
#define SAR_HASHNOTEQUALERR           0X0A00001A //HASH值不相等 
#define SAR_KEYNOTFOUNTERR            0X0A00001B //密钥未发现 
#define SAR_CERTNOTFOUNTERR           0X0A00001C //证书未发现 
#define SAR_NOTEXPORTERR              0X0A00001D //对象未导出 
#define SAR_DECRYPTPADERR             0X0A00001E //解密时做补丁错误 
#define SAR_MACLENERR                 0X0A00001F //MAC长度错误 
#define SAR_BUFFER_TOO_SMALL          0x0A000020 //缓冲区不足 
#define SAR_KEYINFOTYPEERR            0X0A000021 //密钥类型错误 
#define SAR_NOT_EVENTERR              0X0A000022 //无事件错误 
#define SAR_DEVICE_REMOVED            0X0A000023 //设备已移除 
#define SAR_PIN_INCORRECT             0X0A000024 //PIN不正确 
#define SAR_PIN_LOCKED                0X0A000025 //PIN被锁死 
#define SAR_PIN_INVALID               0X0A000026 //PIN无效
#define SAR_PIN_LEN_RANGE             0X0A000027 //PIN长度错误 
#define SAR_USER_ALREADY_LOGGED_IN    0X0A000028 //用户已经登录 
#define SAR_USER_PIN_NOT_INITIALIZED  0X0A000029 //没有初始化用户口令 
#define SAR_USER_TYPE_INVALID         0X0A00002A //PIN类型错误 
#define SAR_APPLICATION_NAME_INVALID  0X0A00002B //应用名称无效 
#define SAR_APPLICATION_EXISTS        0X0A00002C //应用已经存在 
#define SAR_USER_NOT_LOGGED_IN        0X0A00002D //用户没有登录 
#define SAR_APPLICATION_NOT_EXISTS    0X0A00002E //应用不存在 
#define SAR_FILE_ALREADY_EXIST        0X0A00002F //文件已经存在 
#define SAR_NO_ROOM                   0X0A000030 //空间不足 
#define SAR_FILE_NOT_EXIST            0X0A000031 //文件不存在
#define SAR_REACH_MAX_CONTAINER_COUNT 0X0A000032 //已达到最大可管理容器数
#define SAR_CONTAINER_ALREADY_EXIST   0X0A000033 //容器已经存在
#define SAR_CONTAINER_NOT_EXIST       0X0A000034 //容器不存在
//为操作方便，增加自定义类型部分
#define SK_PTR *

	typedef unsigned int UINT4;
	typedef BYTE         SK_BYTE;
	typedef CHAR         SK_CHAR;
	typedef ULONG        SK_ULONG;
	typedef DEVHANDLE    SK_DEVHANDLE;
	typedef HAPPLICATION SK_HAPPLICATION;
	typedef HCONTAINER   SK_HCONTAINER;
	typedef SK_DEVHANDLE SK_PTR   SK_DEVHANDLE_PTR;
	typedef SK_BYTE      SK_PTR   SK_BYTE_PTR;
	typedef SK_CHAR      SK_PTR   SK_CHAR_PTR;
	typedef SK_ULONG     SK_PTR   SK_ULONG_PTR;
	typedef void         SK_PTR   SK_VOID_PTR;

	//=====================================设备管理============================================//
	typedef ULONG DEVAPI _CP_SKF_WaitForDevEvent(LPSTR szDevName, ULONG* pulDevNameLen, ULONG* pulEvent);

	typedef ULONG DEVAPI _CP_SKF_CancelWaitForDevEvent();

	typedef ULONG DEVAPI _CP_SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG* pulSize);

	typedef ULONG DEVAPI _CP_SKF_ConnectDev(LPSTR szName, DEVHANDLE* phDev);

	typedef ULONG DEVAPI _CP_SKF_DisConnectDev(DEVHANDLE hDev);

	typedef ULONG DEVAPI _CP_SKF_GetDevState(LPSTR szDevName, ULONG* pulDevState);

	typedef ULONG DEVAPI _CP_SKF_SetLabel(DEVHANDLE hDev, LPSTR szLabel);

	typedef ULONG DEVAPI _CP_SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO* pDevInfo);

	typedef ULONG DEVAPI _CP_SKF_LockDev(DEVHANDLE hDev, ULONG ulTimeOut);

	typedef ULONG DEVAPI _CP_SKF_UnlockDev(DEVHANDLE hDev);

	typedef ULONG DEVAPI _CP_SKF_Transmit(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen, BYTE* pbData, ULONG* pulDataLen);
	//=====================================访问控制============================================//
	typedef ULONG DEVAPI _CP_SKF_ChangeDevAuthKey(DEVHANDLE hDev, BYTE* pbKeyValue, ULONG ulKeyLen);

	typedef ULONG DEVAPI _CP_SKF_DevAuth(DEVHANDLE hDev, BYTE* pbAuthData, ULONG ulLen);

	typedef ULONG DEVAPI _CP_SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG* pulRetryCount);

	typedef ULONG DEVAPI _CP_SKF_GetPINInfo(HAPPLICATION hApplication, ULONG ulPINType, ULONG* pulMaxRetryCount, ULONG* pulRemainRetryCount, BOOL* pbDefaultPin);

	typedef ULONG DEVAPI _CP_SKF_VerifyPIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szPIN, ULONG* pulRetryCount);

	typedef ULONG DEVAPI _CP_SKF_UnblockPIN(HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN, ULONG* pulRetryCount);

	typedef ULONG DEVAPI _CP_SKF_ClearSecureState(HAPPLICATION hApplication);

	//=====================================应用管理============================================//
	typedef ULONG DEVAPI _CP_SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount, LPSTR szUserPin, DWORD dwUserPinRetryCount, DWORD dwCreateFileRights, HAPPLICATION* phApplication);

	typedef ULONG DEVAPI _CP_SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName, ULONG* pulSize);

	typedef ULONG DEVAPI _CP_SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);

	typedef ULONG DEVAPI _CP_SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION* phApplication);

	typedef ULONG DEVAPI _CP_SKF_CloseApplication(HAPPLICATION hApplication);

	//=====================================文件管理============================================//
	typedef ULONG DEVAPI _CP_SKF_CreateFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);

	typedef ULONG DEVAPI _CP_SKF_DeleteFile(HAPPLICATION hApplication, LPSTR szFileName);

	typedef ULONG DEVAPI _CP_SKF_EnumFiles(HAPPLICATION hApplication, LPSTR szFileList, ULONG* pulSize);

	typedef ULONG DEVAPI _CP_SKF_GetFileInfo(HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE* pFileInfo);

	typedef ULONG DEVAPI _CP_SKF_ReadFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE* pbOutData, ULONG* pulOutLen);

	typedef ULONG DEVAPI _CP_SKF_WriteFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, BYTE* pbData, ULONG ulSize);

	//=====================================容器管理============================================//
	typedef ULONG DEVAPI _CP_SKF_CreateContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER* phContainer);

	typedef ULONG DEVAPI _CP_SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName);

	typedef ULONG DEVAPI _CP_SKF_OpenContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER* phContainer);

	typedef ULONG DEVAPI _CP_SKF_CloseContainer(HCONTAINER hContainer);

	typedef ULONG DEVAPI _CP_SKF_EnumContainer(HAPPLICATION hApplication, LPSTR szContainerName, ULONG* pulSize);

	typedef ULONG DEVAPI _CP_SKF_GetContainerType(HCONTAINER hContainer, ULONG* pulContainerType);

	typedef ULONG DEVAPI _CP_SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG ulCertLen);

	typedef ULONG DEVAPI _CP_SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG* pulCertLen);

	//=====================================密码服务============================================//
	typedef ULONG DEVAPI _CP_SKF_GenRandom(DEVHANDLE hDev, BYTE* pbRandom, ULONG ulRandomLen);

	typedef ULONG DEVAPI _CP_SKF_GenRSAKeyPair(HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB* pBlob);

	typedef ULONG DEVAPI _CP_SKF_ImportRSAKeyPair(HCONTAINER hContainer, ULONG ulSymAlgId, BYTE* pbWrappedKey, ULONG ulWrappedKeyLen, BYTE* pbEncryptedData, ULONG ulEncryptedDataLen);

	typedef ULONG DEVAPI _CP_SKF_RSASignData(HCONTAINER hContainer, BYTE* pbData, ULONG ulDataLen, BYTE* pbSignature, ULONG* pulSignLen);

	typedef ULONG DEVAPI _CP_SKF_RSAVerify(DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE* pbData, ULONG ulDataLen, BYTE* pbSignature, ULONG ulSignLen);

	typedef ULONG DEVAPI _CP_SKF_RSAExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB* pPubKey, BYTE* pbData, ULONG* pulDataLen, HANDLE* phSessionKey);

	typedef ULONG DEVAPI _CP_SKF_GenECCKeyPair(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pBlob);

	typedef ULONG DEVAPI _CP_SKF_ImportECCKeyPair(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	typedef ULONG DEVAPI _CP_SKF_ECCSignData(HCONTAINER hContainer, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	typedef ULONG DEVAPI _CP_SKF_ECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	typedef ULONG DEVAPI _CP_SKF_ECCExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKey, PECCCIPHERBLOB pData, HANDLE* phSessionKey);

	typedef ULONG DEVAPI _CP_SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE* pbPlainText, ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText);

	typedef ULONG DEVAPI _CP_SKF_ExtECCDecrypt(DEVHANDLE hDev, ECCPRIVATEKEYBLOB* pECCPriKeyBlob, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);

	typedef ULONG DEVAPI _CP_SKF_ExtECCSign(DEVHANDLE hDev, ECCPRIVATEKEYBLOB* pECCPriKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	typedef ULONG DEVAPI _CP_SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE* phAgreementHandle);

	typedef ULONG DEVAPI _CP_SKF_GenerateAgreementDataAndKeyWithECC(HANDLE hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB* pSponsorTempECCPubKeyBlob, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, BYTE* pbSponsorID, ULONG ulSponsorIDLen, HANDLE* phKeyHandle);

	typedef ULONG DEVAPI _CP_SKF_GenerateKeyWithECC(HANDLE hAgreementHandle, ECCPUBLICKEYBLOB* pECCPubKeyBlob, ECCPUBLICKEYBLOB* pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE* phKeyHandle);

	typedef ULONG DEVAPI _CP_SKF_ExportPublicKey(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);

	typedef ULONG DEVAPI _CP_SKF_ImportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, BYTE* pbWrapedData, ULONG ulWrapedLen, HANDLE* phKey);

	typedef ULONG DEVAPI _CP_SKF_EncryptInit(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);

	typedef ULONG DEVAPI _CP_SKF_Encrypt(HANDLE hKey, BYTE* pbData, ULONG ulDataLen, BYTE* pbEncryptedData, ULONG* pulEncryptedLen);

	typedef ULONG DEVAPI _CP_SKF_EncryptUpdate(HANDLE hKey, BYTE* pbData, ULONG ulDataLen, BYTE* pbEncryptedData, ULONG* pulEncryptedLen);

	typedef ULONG DEVAPI _CP_SKF_EncryptFinal(HANDLE hKey, BYTE* pbEncryptedData, ULONG* ulEncryptedDataLen);

	typedef ULONG DEVAPI _CP_SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);

	typedef ULONG DEVAPI _CP_SKF_Decrypt(HANDLE hKey, BYTE* pbEncryptedData, ULONG ulEncryptedLen, BYTE* pbData, ULONG* pulDataLen);

	typedef ULONG DEVAPI _CP_SKF_DecryptUpdate(HANDLE hKey, BYTE* pbEncryptedData, ULONG ulEncryptedLen, BYTE* pbData, ULONG* pulDataLen);

	typedef ULONG DEVAPI _CP_SKF_DecryptFinal(HANDLE hKey, BYTE* pbDecryptedData, ULONG* pulDecryptedDataLen);

	typedef ULONG DEVAPI _CP_SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID, ECCPUBLICKEYBLOB* pPubKey, unsigned char* pucID, ULONG ulIDLen, HANDLE* phHash);

	typedef ULONG DEVAPI _CP_SKF_Digest(HANDLE hHash, BYTE* pbData, ULONG ulDataLen, BYTE* pbHashData, ULONG* pulHashLen);

	typedef ULONG DEVAPI _CP_SKF_DigestUpdate(HANDLE hHash, BYTE* pbData, ULONG ulDataLen);

	typedef ULONG DEVAPI _CP_SKF_DigestFinal(HANDLE hHash, BYTE* pHashData, ULONG* pulHashLen);

	typedef ULONG DEVAPI _CP_SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE* phMac);

	typedef ULONG DEVAPI _CP_SKF_Mac(HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE* pbMacData, ULONG* pulMacLen);

	typedef ULONG DEVAPI _CP_SKF_MacUpdate(HANDLE hMac, BYTE* pbData, ULONG ulDataLen);

	typedef ULONG DEVAPI _CP_SKF_MacFinal(HANDLE hMac, BYTE* pbMacData, ULONG* pulMacDataLen);

	typedef ULONG DEVAPI _CP_SKF_CloseHandle(HANDLE hHandle);

	//应用扩展接口
	typedef ULONG DEVAPI _CP_SKF_SetSymmKey(DEVHANDLE hDev, BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey);

	typedef ULONG DEVAPI _CP_SKF_ImportCACertificate(HCONTAINER hContainer, BYTE* pbCert, ULONG ulCertLen);

	typedef ULONG DEVAPI _CP_SKF_ExportCACertificate(HCONTAINER hContainer, BYTE* pbCert, ULONG* pulCertLen);

	typedef ULONG DEVAPI _CP_SKF_RSADecrypt(HCONTAINER hContainer, BYTE* pbCipherText, ULONG ulCipherTextLen, BYTE* pbPlainText, ULONG* pulPlainTextLen);

	typedef ULONG DEVAPI _CP_SKF_RSADecryptA(HCONTAINER hContainer, ULONG ulKeySpec, BYTE* pbCipherText, ULONG ulCipherTextLen, BYTE* pbPlainText, ULONG* pulPlainTextLen);

	typedef ULONG DEVAPI _CP_SKF_RSADecryptB(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCipherText, ULONG ulCipherTextLen, BYTE* pbPlainText, ULONG* pulPlainTextLen);

	typedef ULONG DEVAPI _CP_SKF_ECCDecrypt(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);
	//三未
	typedef ULONG DEVAPI _CP_SKF_ECCDecryptA(HCONTAINER hContainer, ULONG ulKeySpec, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);
	//赢达信
	typedef ULONG DEVAPI _CP_SKF_ECCDecryptB(HCONTAINER hContainer, BOOL bSignFlag, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);

	typedef ULONG DEVAPI _CP_SKF_GenECCKeyPairEx(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB* pPubKeyBlob, ECCPRIVATEKEYBLOB* pPrivKeyBlob);

	typedef ULONG DEVAPI _CP_SKF_ImportECCKeyPair2(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	typedef ULONG DEVAPI _CP_SKF_ECCMultAdd(HCONTAINER hContainer, unsigned int k, ECCPRIVATEKEYBLOB* e, ECCPUBLICKEYBLOB* A, ECCPUBLICKEYBLOB* B, ECCPUBLICKEYBLOB* C);

	typedef ULONG DEVAPI _CP_SKF_ECCModMultAdd(ECCPRIVATEKEYBLOB* k, ECCPRIVATEKEYBLOB* a, ECCPRIVATEKEYBLOB* b, ECCPRIVATEKEYBLOB* c);

	//电子印章接口
	typedef ULONG EPSAPI _CP_EPS_ImportSymmKey(CONST HANDLE hContainer, ULONG ulKeyIndex, CONST BYTE* pbEncData, ULONG ulEncDataLen, ULONG ulFlags);

	typedef ULONG EPSAPI _CP_EPS_WriteESealData(CONST HANDLE hApplication, CONST BYTE* pbData, ULONG ulDataSize, ULONG ulFlags);

	typedef ULONG EPSAPI _CP_EPS_ReadESealData(CONST HANDLE hApplication, ULONG ulKeyIndex, ULONG ulKeyAlgId, BYTE* pbData, ULONG* ulDataLen, ULONG ulFlags);

	typedef ULONG EPSAPI _CP_EPS_Encrypt(CONST HANDLE hApplication, ULONG ulKeyIndex, ULONG ulAlgId, CONST BYTE* pbIVData, ULONG ulIVLen, ULONG DivCount, CONST BYTE* pbDivComponent, ULONG ulDivComponentLen, CONST BYTE* pbInputData, ULONG ulInputLen, BYTE* pbOutputData, ULONG* pulOutputDataLen, ULONG ulFlags);

	typedef ULONG EPSAPI _CP_EPS_Decrypt(CONST HANDLE hContainer, ULONG ulKeyIndex, ULONG ulAlgId, CONST BYTE* pbIVData, ULONG ulIVLen, ULONG DivCount, CONST BYTE* pbDivComponent, ULONG ulDivComponentLen, CONST BYTE* pbInputData, ULONG ulInputLen, BYTE* pbOutputData, ULONG* pulOutputDataLen, ULONG ulFlags);

	typedef ULONG EPSAPI _CP_EPS_Mac(CONST HANDLE hApplication, ULONG ulKeyIndex, ULONG ulAlgId, CONST BYTE* pbIVData, ULONG ulIVLen, ULONG DivCount, CONST BYTE* pbDivComponent, ULONG ulDivComponentLen, CONST BYTE* pbInputData, ULONG ulInputLen, BYTE* pbOutputData, ULONG* pulOutputDataLen, ULONG ulFlags);

	//自定义扩展接口
	typedef ULONG DEVAPI _CP_SLF_Initialize();

	typedef ULONG DEVAPI _CP_SLF_Finalize();

	typedef ULONG DEVAPI _CP_SLF_InitDevToken(HAPPLICATION hApplication, LPSTR pSOpin, LPSTR pInitSOpin, LPSTR pInitUserPin);

	typedef void DEVAPI _CP_SLF_SetInitStyle(char* szDefApplicationName, char* szDefContainerName, ULONG ulContID);

	typedef void DEVAPI _CP_SLF_SetLogFilePath(char* szPath);

	typedef ULONG DEVAPI _CP_SLF_SetSymmSFID(ULONG* pSymAlgID);

	typedef ULONG DEVAPI _CP_SLF_RSASignData(HCONTAINER hContainer, ULONG ulMechDigest, BYTE* pbData, ULONG ulDataLen, BYTE* pbSignature, ULONG* pulSignLen);

	typedef ULONG DEVAPI _CP_SLF_GenRSAKeyPair(HCONTAINER hContainer, LPSTR pLabel, ULONG ulBitsLen, RSAPUBLICKEYBLOB* pBlob);

	typedef ULONG DEVAPI _CP_SLF_UpdateKeyUsage(HCONTAINER hContainer, LPSTR pLabel, ULONG ulKeyTypeID);

	typedef ULONG DEVAPI _CP_SLF_SetKeyIDAttribute(HCONTAINER hContainer, LPSTR pLabel, BYTE* pKeyIDValue, ULONG ulKeyIDValueLen);

	typedef ULONG DEVAPI _CP_SLF_ExportPublicKey(HCONTAINER hContainer, LPSTR pLabel, BYTE* pbBlob, ULONG* pulBlobLen);
#ifdef CLACLIENT
	//CLA扩展接口
	typedef ULONG DEVAPI _CP_CLASKF_GenECCKeyPair(void* vphProv, ULONG ulAlgId, ECCPUBLICKEYBLOB* pBlob);

	typedef ULONG DEVAPI _CP_CLASKF_ImportECCKeyPair(void* vphProv, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	typedef ULONG DEVAPI _CP_CLASKF_ImportECCKeyPair2(void* vphProv, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	typedef ULONG DEVAPI _CP_CLASKF_ExportPublicKey(void* vphProv, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);

	typedef ULONG DEVAPI _CP_CLASKF_ECCSignData(void* vphProv, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	typedef ULONG DEVAPI _CP_CLASKF_ECCDecrypt(void* vphProv, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);
#endif

	typedef struct _SK_FUNCTION_LIST {
		//=====================================设备管理============================================//
		_CP_SKF_WaitForDevEvent* SKF_WaitForDevEvent;
		_CP_SKF_CancelWaitForDevEvent* SKF_CancelWaitForDevEvent;
		_CP_SKF_EnumDev* SKF_EnumDev;
		_CP_SKF_ConnectDev* SKF_ConnectDev;
		_CP_SKF_DisConnectDev* SKF_DisConnectDev;
		_CP_SKF_GetDevState* SKF_GetDevState;
		_CP_SKF_SetLabel* SKF_SetLabel;
		_CP_SKF_GetDevInfo* SKF_GetDevInfo;
		_CP_SKF_LockDev* SKF_LockDev;
		_CP_SKF_UnlockDev* SKF_UnlockDev;
		_CP_SKF_Transmit* SKF_Transmit;
		//=====================================访问控制============================================//
		_CP_SKF_ChangeDevAuthKey* SKF_ChangeDevAuthKey;
		_CP_SKF_DevAuth* SKF_DevAuth;
		_CP_SKF_ChangePIN* SKF_ChangePIN;
		_CP_SKF_GetPINInfo* SKF_GetPINInfo;
		_CP_SKF_VerifyPIN* SKF_VerifyPIN;
		_CP_SKF_UnblockPIN* SKF_UnblockPIN;
		_CP_SKF_ClearSecureState* SKF_ClearSecureState;
		//=====================================应用管理============================================//
		_CP_SKF_CreateApplication* SKF_CreateApplication;
		_CP_SKF_EnumApplication* SKF_EnumApplication;
		_CP_SKF_DeleteApplication* SKF_DeleteApplication;
		_CP_SKF_OpenApplication* SKF_OpenApplication;
		_CP_SKF_CloseApplication* SKF_CloseApplication;
		//=====================================文件管理============================================//
		_CP_SKF_CreateFile* SKF_CreateFile;
		_CP_SKF_DeleteFile* SKF_DeleteFile;
		_CP_SKF_EnumFiles* SKF_EnumFiles;
		_CP_SKF_GetFileInfo* SKF_GetFileInfo;
		_CP_SKF_ReadFile* SKF_ReadFile;
		_CP_SKF_WriteFile* SKF_WriteFile;
		//=====================================容器管理============================================//
		_CP_SKF_CreateContainer* SKF_CreateContainer;
		_CP_SKF_DeleteContainer* SKF_DeleteContainer;
		_CP_SKF_OpenContainer* SKF_OpenContainer;
		_CP_SKF_CloseContainer* SKF_CloseContainer;
		_CP_SKF_EnumContainer* SKF_EnumContainer;
		_CP_SKF_GetContainerType* SKF_GetContainerType;
		_CP_SKF_ImportCertificate* SKF_ImportCertificate;
		_CP_SKF_ExportCertificate* SKF_ExportCertificate;
		//=====================================密码服务============================================//
		_CP_SKF_GenRandom* SKF_GenRandom;
		_CP_SKF_GenRSAKeyPair* SKF_GenRSAKeyPair;
		_CP_SKF_ImportRSAKeyPair* SKF_ImportRSAKeyPair;
		_CP_SKF_RSASignData* SKF_RSASignData;
		_CP_SKF_RSAVerify* SKF_RSAVerify;
		_CP_SKF_RSAExportSessionKey* SKF_RSAExportSessionKey;
		_CP_SKF_GenECCKeyPair* SKF_GenECCKeyPair;
		_CP_SKF_ImportECCKeyPair* SKF_ImportECCKeyPair;
		_CP_SKF_ECCSignData* SKF_ECCSignData;
		_CP_SKF_ECCVerify* SKF_ECCVerify;
		_CP_SKF_ECCExportSessionKey* SKF_ECCExportSessionKey;
		_CP_SKF_ExtECCEncrypt* SKF_ExtECCEncrypt;
		_CP_SKF_ExtECCDecrypt* SKF_ExtECCDecrypt;
		_CP_SKF_GenerateAgreementDataWithECC* SKF_GenerateAgreementDataWithECC;
		_CP_SKF_GenerateAgreementDataAndKeyWithECC* SKF_GenerateAgreementDataAndKeyWithECC;
		_CP_SKF_GenerateKeyWithECC* SKF_GenerateKeyWithECC;
		_CP_SKF_ExtECCSign* SKF_ExtECCSign;
		_CP_SKF_ExportPublicKey* SKF_ExportPublicKey;
		_CP_SKF_ImportSessionKey* SKF_ImportSessionKey;
		_CP_SKF_EncryptInit* SKF_EncryptInit;
		_CP_SKF_Encrypt* SKF_Encrypt;
		_CP_SKF_EncryptUpdate* SKF_EncryptUpdate;
		_CP_SKF_EncryptFinal* SKF_EncryptFinal;
		_CP_SKF_DecryptInit* SKF_DecryptInit;
		_CP_SKF_Decrypt* SKF_Decrypt;
		_CP_SKF_DecryptUpdate* SKF_DecryptUpdate;
		_CP_SKF_DecryptFinal* SKF_DecryptFinal;
		_CP_SKF_DigestInit* SKF_DigestInit;
		_CP_SKF_Digest* SKF_Digest;
		_CP_SKF_DigestUpdate* SKF_DigestUpdate;
		_CP_SKF_DigestFinal* SKF_DigestFinal;
		_CP_SKF_MacInit* SKF_MacInit;
		_CP_SKF_Mac* SKF_Mac;
		_CP_SKF_MacUpdate* SKF_MacUpdate;
		_CP_SKF_MacFinal* SKF_MacFinal;
		_CP_SKF_CloseHandle* SKF_CloseHandle;
		//=================================应用扩展接口=====================================//
		_CP_SKF_SetSymmKey* SKF_SetSymmKey;
		_CP_SKF_ImportCACertificate* SKF_ImportCACertificate;
		_CP_SKF_ExportCACertificate* SKF_ExportCACertificate;
		_CP_SKF_RSADecrypt* SKF_RSADecrypt;
		_CP_SKF_RSADecryptA* SKF_RSADecryptA;
		_CP_SKF_RSADecryptB* SKF_RSADecryptB;
		_CP_SKF_ECCDecrypt* SKF_ECCDecrypt;
		_CP_SKF_ECCDecryptA* SKF_ECCDecryptA;
		_CP_SKF_ECCDecryptB* SKF_ECCDecryptB;
		_CP_SKF_GenECCKeyPairEx* SKF_GenECCKeyPairEx;
		_CP_SKF_ImportECCKeyPair2* SKF_ImportECCKeyPair2;
		_CP_SKF_ECCMultAdd* SKF_ECCMultAdd;
		_CP_SKF_ECCModMultAdd* SKF_ECCModMultAdd;
		//=================================电子印章扩展接口=====================================//
		_CP_EPS_ImportSymmKey* EPS_ImportSymmKey;
		_CP_EPS_WriteESealData* EPS_WriteESealData;
		_CP_EPS_ReadESealData* EPS_ReadESealData;
		_CP_EPS_Encrypt* EPS_Encrypt;
		_CP_EPS_Decrypt* EPS_Decrypt;
		_CP_EPS_Mac* EPS_Mac;
		//=================================自定义扩展接口=====================================//
		_CP_SLF_Initialize* SLF_Initialize;
		_CP_SLF_Finalize* SLF_Finalize;
		_CP_SLF_InitDevToken* SLF_InitDevToken;
		_CP_SLF_SetInitStyle* SLF_SetInitStyle;
		_CP_SLF_SetLogFilePath* SLF_SetLogFilePath;
		_CP_SLF_SetSymmSFID* SLF_SetSymmSFID;
		_CP_SLF_RSASignData* SLF_RSASignData;
		_CP_SLF_GenRSAKeyPair* SLF_GenRSAKeyPair;
		_CP_SLF_UpdateKeyUsage* SLF_UpdateKeyUsage;
		_CP_SLF_SetKeyIDAttribute* SLF_SetKeyIDAttribute;
		_CP_SLF_ExportPublicKey* SLF_ExportPublicKey;
#ifdef CLACLIENT
		_CP_CLASKF_GenECCKeyPair* CLASKF_GenECCKeyPair;
		_CP_CLASKF_ImportECCKeyPair* CLASKF_ImportECCKeyPair;
		_CP_CLASKF_ImportECCKeyPair2* CLASKF_ImportECCKeyPair2;
		_CP_CLASKF_ExportPublicKey* CLASKF_ExportPublicKey;
		_CP_CLASKF_ECCSignData* CLASKF_ECCSignData;
		_CP_CLASKF_ECCDecrypt* CLASKF_ECCDecrypt;
#endif 
	}SK_FUNCTION_LIST;

	typedef SK_FUNCTION_LIST SK_PTR SK_FUNCTION_LIST_PTR;

	typedef SK_FUNCTION_LIST_PTR SK_PTR SK_FUNCTION_LIST_PTR_PTR;

	/* 初始化 SKF 引擎 */
	void ENGINE_load_skf(void);

	/* 为 nginx/angie 设置 SKF 引擎 */
	int skf_engine_setup_for_nginx(const char* lib_path, const char* device_name,
		const char* app_name, const char* pin);

	/* SKF 配置结构体 */
	typedef struct SKF_CONFIG_st SKF_CONFIG;

	/* 创建和释放 SKF 配置 */
	SKF_CONFIG* skf_config_new(void);
	void skf_config_free(SKF_CONFIG* config);

	/* 设置 SKF 配置参数 */
	int skf_config_set_library(SKF_CONFIG* config, const char* lib_path);
	int skf_config_set_device(SKF_CONFIG* config, const char* device_name);
	int skf_config_set_application(SKF_CONFIG* config, const char* app_name);
	int skf_config_set_container(SKF_CONFIG* config, const char* container_name);
	int skf_config_set_pin(SKF_CONFIG* config, const char* pin);

	/* 加载和配置 SKF 引擎 */
	ENGINE* skf_engine_load_and_configure(SKF_CONFIG* config);

	/* 创建和释放带有 SKF 引擎的 SSL 上下文 */
	SSL_CTX* skf_ssl_ctx_new_with_engine(SKF_CONFIG* config, const SSL_METHOD* method);
	void skf_ssl_ctx_free_with_engine(SSL_CTX* ctx);

#ifdef __cplusplus
}
#endif

#endif /* OSSL_ENGINES_E_SKF_H */