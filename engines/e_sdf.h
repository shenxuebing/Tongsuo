/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

 /*
  * SDF Engine for GMT 0018-2012
  * Public API
  */

#ifndef OSSL_ENGINES_E_SDF_H
#define OSSL_ENGINES_E_SDF_H

#include <openssl/opensslconf.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

# if defined(__GNUC__) && __GNUC__ >= 4 && \
     (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#  pragma GCC diagnostic ignored "-Wvariadic-macros"
# endif

# ifdef _MSC_VER
#  define SDF_LOG(level, fmt, ...) \
                fprintf(stderr, level ": %s:%d: " fmt "\n", __FILE__, __LINE__, __VA_ARGS__)
# else
#  define SDF_LOG(level, fmt, ...) \
                fprintf(stderr, level ": %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
# endif

# ifdef SDF_DEBUG
#  ifdef _MSC_VER
#   define SDF_DGB(fmt, ...)  SDF_LOG("SDF_DBG", fmt, __VA_ARGS__)
#   define SDF_INFO(fmt, ...) SDF_LOG("SDF_INFO", fmt, __VA_ARGS__)
#   define SDF_WARN(fmt, ...) SDF_LOG("SDF_WARN", fmt, __VA_ARGS__)
#  else
#   define SDF_DGB(fmt, ...)  SDF_LOG("SDF_DBG", fmt, ##__VA_ARGS__)
#   define SDF_INFO(fmt, ...) SDF_LOG("SDF_INFO", fmt, ##__VA_ARGS__)
#   define SDF_WARN(fmt, ...) SDF_LOG("SDF_WARN", fmt, ##__VA_ARGS__)
#  endif
# else
#  define SDF_DGB(fmt, ...)
#  define SDF_INFO(fmt, ...)
#  define SDF_WARN(fmt, ...)
# endif

# ifdef _MSC_VER
#  define SDF_ERR(fmt, ...)  SDF_LOG("SDF_ERR", fmt, __VA_ARGS__)
#  define SDF_PERR(fmt, ...) \
                do { \
                    SDF_LOG("SDF_PERR", fmt, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)
#  define SDF_PWARN(fmt, ...) \
                do { \
                    SDF_LOG("SDF_PWARN", fmt, __VA_ARGS__); \
                    perror(NULL); \
                } while(0)
# else
#  define SDF_ERR(fmt, ...)  SDF_LOG("SDF_ERR", fmt, ##__VA_ARGS__)
#  define SDF_PERR(fmt, ...) \
                do { \
                    SDF_LOG("SDF_PERR", fmt, ##__VA_ARGS__); \
                    perror(NULL); \
                } while(0)
#  define SDF_PWARN(fmt, ...) \
                do { \
                    SDF_LOG("SDF_PWARN", fmt, ##__VA_ARGS__); \
                    perror(NULL); \
                } while(0)
# endif

#ifdef __cplusplus
extern "C" {
#endif
#define GMT0018_2012		1

	/*数据类型定义*/
	typedef char				SGD_CHAR;
	typedef char				SGD_INT8;
	typedef short				SGD_INT16;
	typedef int					SGD_INT32;
	typedef long long			SGD_INT64;
	typedef unsigned char		SGD_UCHAR;
	typedef unsigned char		SGD_UINT8;
	typedef unsigned short		SGD_UINT16;
	typedef unsigned int		SGD_UINT32;
	typedef unsigned long long	SGD_UINT64;
	typedef unsigned int		SGD_RV;
	typedef void* SGD_OBJ;
	typedef int					SGD_BOOL;
	typedef void* SGD_HANDLE;
#if !(defined(_WIN32) || defined(_WIN64))
	typedef void* HMODULE;
#define _stdcall	
#define __stdcall	
#define WINAPI
#define DEVAPI
#else
#define DEVAPI     _stdcall        //_stdcall函数调用方式
#endif

#ifndef CONST
#define CONST               const
#endif
	/*设备信息*/
	typedef struct DeviceInfo_st {
		unsigned char IssuerName[40];
		unsigned char DeviceName[16];
		unsigned char DeviceSerial[16];
		unsigned int  DeviceVersion;
		unsigned int  StandardVersion;
		unsigned int  AsymSDFAbility[2];
		unsigned int  SymSDFAbility;
		unsigned int  HashSDFAbility;
		unsigned int  BufferSize;
	} DEVICEINFO;

	/*RSA密钥*/
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

	/*RSA密钥,支持3072、4096*/
#define RSAref_MAX_BITS_EX    4096
#define RSAref_MAX_LEN_EX     ((RSAref_MAX_BITS_EX + 7) / 8)
#define RSAref_MAX_PBITS_EX   ((RSAref_MAX_BITS_EX + 1) / 2)
#define RSAref_MAX_PLEN_EX    ((RSAref_MAX_PBITS_EX + 7)/ 8)
	typedef struct RSArefPublicKey_st
	{
		unsigned int  bits;
		unsigned char m[RSAref_MAX_LEN];
		unsigned char e[RSAref_MAX_LEN];
	} RSArefPublicKey;

	typedef struct RSArefPublicKey_st_ex
	{
		unsigned int  bits;
		unsigned char m[RSAref_MAX_LEN_EX];
		unsigned char e[RSAref_MAX_LEN_EX];
	} RSArefPublicKeyEx;

	typedef struct RSArefPrivateKey_st
	{
		unsigned int  bits;
		unsigned char m[RSAref_MAX_LEN];
		unsigned char e[RSAref_MAX_LEN];
		unsigned char d[RSAref_MAX_LEN];
		unsigned char prime[2][RSAref_MAX_PLEN];
		unsigned char pexp[2][RSAref_MAX_PLEN];
		unsigned char coef[RSAref_MAX_PLEN];
	} RSArefPrivateKey;

	typedef struct RSArefPrivateKey_st_ex
	{
		unsigned int  bits;
		unsigned char m[RSAref_MAX_LEN_EX];
		unsigned char e[RSAref_MAX_LEN_EX];
		unsigned char d[RSAref_MAX_LEN_EX];
		unsigned char prime[2][RSAref_MAX_PLEN_EX];
		unsigned char pexp[2][RSAref_MAX_PLEN_EX];
		unsigned char coef[RSAref_MAX_PLEN_EX];
	} RSArefPrivateKeyEx;

#ifndef GMT0018_2012
	/*2008版密码设备应用接口规范ECC密钥数据结构定义*/

#define ECCref_MAX_BITS			256 
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN	136

	typedef struct ECCrefPublicKey_st
	{
		unsigned int  bits;
		unsigned char x[ECCref_MAX_LEN];
		unsigned char y[ECCref_MAX_LEN];
	} ECCrefPublicKey;

	typedef struct ECCrefPrivateKey_st
	{
		unsigned int  bits;
		unsigned char D[ECCref_MAX_LEN];
	} ECCrefPrivateKey;

	/*ECC 密文*/
	typedef struct ECCCipher_st
	{
		unsigned int  clength;  //C的有效长度
		unsigned char x[ECCref_MAX_LEN];
		unsigned char y[ECCref_MAX_LEN];
		unsigned char C[ECCref_MAX_CIPHER_LEN];
		unsigned char M[ECCref_MAX_LEN];
	} ECCCipher;

	/*ECC 签名*/
	typedef struct ECCSignature_st
	{
		unsigned char r[ECCref_MAX_LEN];
		unsigned char s[ECCref_MAX_LEN];
	} ECCSignature;
#else
	/*2012版密码设备应用接口规范ECC密钥数据结构定义*/

#define ECCref_MAX_BITS					512 
#define ECCref_MAX_LEN					((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN			136

	typedef struct ECCrefPublicKey_st
	{
		unsigned int  bits;
		unsigned char x[ECCref_MAX_LEN];
		unsigned char y[ECCref_MAX_LEN];
	} ECCrefPublicKey;

	typedef struct ECCrefPrivateKey_st
	{
		unsigned int  bits;
		unsigned char K[ECCref_MAX_LEN];
	} ECCrefPrivateKey;

	/*ECC 密文*/
	typedef struct ECCCipher_st
	{
		unsigned char x[ECCref_MAX_LEN];
		unsigned char y[ECCref_MAX_LEN];
		unsigned char M[32];
		unsigned int  L;
		unsigned char C[1];
	} ECCCipher;

	/*ECC 签名*/
	typedef struct ECCSignature_st
	{
		unsigned char r[ECCref_MAX_LEN];
		unsigned char s[ECCref_MAX_LEN];
	} ECCSignature;
#endif

#ifndef BYZKENVELOPTYPE
	//总参三部ECC加密密钥对数字信封密文定义
	typedef struct Struct_ECCPUBLICKEYBLOB
	{
		unsigned int BitLen;
		unsigned char XCoordinate[64];
		unsigned char YCoordinate[64];
	} ECCPUBLICKEYBLOB, * PECCPUBLICKEYBLOB;

	typedef struct Struct_ECCCIPHERBLOB
	{
		unsigned char Xcoordinate[64];
		unsigned char Ycoordinate[64];
		unsigned char HASH[32];
		unsigned int CipherLen;
		unsigned char Cipher[1];
	} ECCCIPHERBLOB, * PECCCIPHERBLOB;

	typedef struct SDF_ENVELOPEDKEYBLOB
	{
		unsigned int Version;
		unsigned int ulSymmSDFID;
		unsigned int ulBits;
		unsigned char cbEncryptedPriKey[64];
		ECCPUBLICKEYBLOB PubKey;
		ECCCIPHERBLOB ECCCipherBlob;
	} ENVELOPEDKEYBLOB, * PENVELOPEDKEYBLOB;
#endif

	//SM9
#define SM9ref_MAX_BITS		256
#define SM9ref_MAX_LEN		((SM9ref_MAX_BITS+7) / 8)

#define MAX_SM9_ID_LENGTH					128

	typedef struct SM9refSignMasterPrivateKey_st
	{
		unsigned int bits;
		unsigned char s[SM9ref_MAX_LEN];
	} SM9refSignMasterPrivateKey;

	typedef struct SM9refSignMasterPublicKey_st
	{
		unsigned int bits;
		unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
		unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
		unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
		unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
	} SM9refSignMasterPublicKey;

	typedef struct SM9refSignMasterKeyPair_st
	{
		SM9refSignMasterPrivateKey MasterPrivateKey;
		SM9refSignMasterPublicKey MasterPublicKey;
		unsigned char MasterKeyPairG[1536];
	} SM9refSignMasterKeyPair;

	typedef struct SM9refEncMasterPrivateKey_st
	{
		unsigned int bits;
		unsigned char s[SM9ref_MAX_LEN];
	} SM9refEncMasterPrivateKey;

	typedef struct SM9refEncMasterPublicKey_st
	{
		unsigned int bits;
		unsigned char x[SM9ref_MAX_LEN];
		unsigned char y[SM9ref_MAX_LEN];
	} SM9refEncMasterPublicKey;

	typedef struct SM9refEncMasterKeyPair_st
	{
		SM9refEncMasterPrivateKey MasterPrivateKey;
		SM9refEncMasterPublicKey MasterPublicKey;
		unsigned char MasterKeyPairG[384];
	} SM9refEncMasterKeyPair;

	typedef struct SM9refPublicUserID_st
	{
		unsigned int IDLen;
		unsigned char ID[MAX_SM9_ID_LENGTH];
	} SM9refPublicUserID;

	typedef struct SM9refSignUserPrivateKey_st
	{
		unsigned int bits;
		unsigned char x[SM9ref_MAX_LEN];
		unsigned char y[SM9ref_MAX_LEN];
	} SM9refSignUserPrivateKey;

	typedef struct SM9refSignUserKeyPair_st
	{
		SM9refSignUserPrivateKey PrivateKey;
		SM9refPublicUserID PublicUserID;
	} SM9refSignUserKeyPair;

	typedef struct SM9refEncUserPrivateKey_st
	{
		unsigned int bits;
		unsigned char xa[SM9ref_MAX_LEN]; //X低维坐标
		unsigned char xb[SM9ref_MAX_LEN]; //X高维坐标
		unsigned char ya[SM9ref_MAX_LEN]; //Y低维坐标
		unsigned char yb[SM9ref_MAX_LEN]; //Y高维坐标
	} SM9refEncUserPrivateKey;

	typedef struct SM9refEncUserKeyPair_st
	{
		SM9refEncUserPrivateKey PrivateKey;
		SM9refPublicUserID PublicUserID;
	} SM9refEncUserKeyPair;

	typedef struct SM9Signature_st
	{
		unsigned char h[SM9ref_MAX_LEN];
		unsigned char x[SM9ref_MAX_LEN];
		unsigned char y[SM9ref_MAX_LEN];
	} SM9Signature;

	typedef struct SM9Cipher_st
	{
		unsigned char x[SM9ref_MAX_LEN];
		unsigned char y[SM9ref_MAX_LEN];
		unsigned char h[SM9ref_MAX_LEN];
		unsigned int L;
		unsigned char C[1024];
	} SM9Cipher;

	typedef struct SM9refKeyPackage_st
	{
		unsigned char x[SM9ref_MAX_LEN];
		unsigned char y[SM9ref_MAX_LEN];
	} SM9refKeyPackage;

	typedef struct SM9AgreementParam_st
	{
		SGD_UINT32 nHandleFlag;
		unsigned char pucRandom[32];
		unsigned int uiRandomLength;
		unsigned char pucRA[64];
		unsigned int uiRALength;
	} SM9AgreementParam;

	/*常量定义*/
	//#define MAX_KEK_COUNT					100
//#define MAX_KEK_COUNT					500
//#define MAX_RSA_KEY_PAIR_COUNT		100
//#define MAX_RSA_KEY_PAIR_COUNT			600
//#define MAX_ECC_KEY_PAIR_COUNT		100
//#define MAX_ECC_KEY_PAIR_COUNT			1000

//#define MAX_KEY_INFO_COUNT				500

#define USER_PIN_LENGTH					8    //IC卡PIN口令

#define SGD_TRUE		0x00000001
#define SGD_FALSE		0x00000000

#define IN
#define OUT

#define BUFSIZE1		(1<<0)
#define BUFSIZE2		(1<<1)
#define BUFSIZE4		(1<<2)
#define BUFSIZE8		(1<<3)
#define BUFSIZE16		(1<<4)
#define BUFSIZE32		(1<<5)
#define BUFSIZE64		(1<<6)
#define BUFSIZE128		(1<<7)
#define BUFSIZE256		(1<<8)
#define BUFSIZE512		(1<<9)
#define BUFSIZE1024		(1<<10)
#define BUFSIZE2048		(1<<11)
#define BUFSIZE4096		(1<<12)
#define BUFSIZE8192		(1<<13)

/*算法标识*/

#ifndef GMT0018_2012
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_AES_ECB		0x00000401
#define SGD_AES_CBC		0x00000402
#define SGD_AES_CFB		0x00000404
#define SGD_AES_OFB		0x00000408
#define SGD_AES_MAC		0x00000410
#define SGD_AES_CTR		0x00000420

#define SGD_3DES_ECB	0x00000801
#define SGD_3DES_CBC	0x00000802
#define SGD_3DES_CFB	0x00000804
#define SGD_3DES_OFB	0x00000808
#define SGD_3DES_MAC	0x00000810
#define SGD_3DES_CTR	0x00000820

#define SGD_SMS4_ECB	0x00002001
#define SGD_SMS4_CBC	0x00002002
#define SGD_SMS4_CFB	0x00002004
#define SGD_SMS4_OFB	0x00002008
#define SGD_SMS4_MAC	0x00002010
#define SGD_SMS4_CTR	0x00002020

#define SGD_SM4_ECB		0x00002001
#define SGD_SM4_CBC		0x00002002
#define SGD_SM4_CFB		0x00002004
#define SGD_SM4_OFB		0x00002008
#define SGD_SM4_MAC		0x00002010
#define SGD_SM4_CTR		0x00002020

#define SGD_DES_ECB		0x00004001
#define SGD_DES_CBC		0x00004002
#define SGD_DES_CFB		0x00004004
#define SGD_DES_OFB		0x00004008
#define SGD_DES_MAC		0x00004010
#define SGD_DES_CTR		0x00004020

#define SGD_SM7_ECB		0x00008001
#define SGD_SM7_CBC		0x00008002
#define SGD_SM7_CFB		0x00008004
#define SGD_SM7_OFB		0x00008008
#define SGD_SM7_MAC		0x00008010
#define SGD_SM7_CTR		0x00008020
#else
#define SGD_SM1_ECB		0x00000101
#define SGD_SM1_CBC		0x00000102
#define SGD_SM1_CFB		0x00000104
#define SGD_SM1_OFB		0x00000108
#define SGD_SM1_MAC		0x00000110
#define SGD_SM1_CTR		0x00000120

#define SGD_SSF33_ECB	0x00000201
#define SGD_SSF33_CBC	0x00000202
#define SGD_SSF33_CFB	0x00000204
#define SGD_SSF33_OFB	0x00000208
#define SGD_SSF33_MAC	0x00000210
#define SGD_SSF33_CTR	0x00000220

#define SGD_SMS4_ECB	0x00000401
#define SGD_SMS4_CBC	0x00000402
#define SGD_SMS4_CFB	0x00000404
#define SGD_SMS4_OFB	0x00000408
#define SGD_SMS4_MAC	0x00000410
#define SGD_SMS4_CTR	0x00000420
#define SGD_SMS4_XTS	0x00000440

#define SGD_SM4_ECB		0x00000401
#define SGD_SM4_CBC		0x00000402
#define SGD_SM4_CFB		0x00000404
#define SGD_SM4_OFB		0x00000408
#define SGD_SM4_MAC		0x00000410
#define SGD_SM4_CTR		0x00000420
#define SGD_SM4_XTS		0x00000440

#define SGD_ZUC_EEA3	0x00000801	//ZUC祖冲之机密性算法128-EEA3
#define SGD_ZUC_EIA3	0x00000802	//ZUC祖冲之完整性算法128-EIA3

#define SGD_SM7_ECB		0x00001001
#define SGD_SM7_CBC		0x00001002
#define SGD_SM7_CFB		0x00001004
#define SGD_SM7_OFB		0x00001008
#define SGD_SM7_MAC		0x00001010
#define SGD_SM7_CTR		0x00001020

#define SGD_DES_ECB		0x00002001
#define SGD_DES_CBC		0x00002002
#define SGD_DES_CFB		0x00002004
#define SGD_DES_OFB		0x00002008
#define SGD_DES_MAC		0x00002010
#define SGD_DES_CTR		0x00002020

#define SGD_3DES_ECB	0x00004001
#define SGD_3DES_CBC	0x00004002
#define SGD_3DES_CFB	0x00004004
#define SGD_3DES_OFB	0x00004008
#define SGD_3DES_MAC	0x00004010
#define SGD_3DES_CTR	0x00004020

#define SGD_AES_ECB		0x00008001
#define SGD_AES_CBC		0x00008002
#define SGD_AES_CFB		0x00008004
#define SGD_AES_OFB		0x00008008
#define SGD_AES_MAC		0x00008010
#define SGD_AES_CTR		0x00008020
#endif

#define SGD_RSA			0x00010000
#define SGD_RSA_SIGN	0x00010100
#define SGD_RSA_ENC		0x00010200

#ifndef GMT0018_2012
#define SGD_SM2_1		0x00020100
#define SGD_SM2_2		0x00020200
#define SGD_SM2_3		0x00020400
#else
#define SGD_SM2			0x00020100	//SM2椭圆曲线密码算法
#define SGD_SM2_1		0x00020200	//SM2椭圆曲线签名算法
#define SGD_SM2_2		0x00020400	//SM2椭圆曲线密钥交换协议
#define SGD_SM2_3		0x00020800	//SM2椭圆曲线加密算法
#endif

#define SGD_SM3			0x00000001
#define SGD_SHA1		0x00000002
#define SGD_SHA256		0x00000004
#define SGD_SHA512		0x00000008
#define SGD_SHA384		0x00000010
#define SGD_SHA224		0x00000020
#define SGD_MD5			0x00000080


/*标准错误码定义*/
#define SDR_OK					0x0						   /*成功*/
#define SDR_BASE				0x01000000
#define SDR_UNKNOWERR			(SDR_BASE + 0x00000001)	   /*未知错误*/
#define SDR_NOTSUPPORT			(SDR_BASE + 0x00000002)	   /*不支持的接口调用*/
#define SDR_COMMFAIL			(SDR_BASE + 0x00000003)    /*通信错误*/
#define SDR_HARDFAIL			(SDR_BASE + 0x00000004)    /*硬件错误*/
#define SDR_OPENDEVICE			(SDR_BASE + 0x00000005)    /*打开设备错误*/
#define SDR_OPENSESSION			(SDR_BASE + 0x00000006)    /*打开会话句柄错误*/
#define SDR_PARDENY				(SDR_BASE + 0x00000007)    /*权限不满足*/
#define SDR_KEYNOTEXIST			(SDR_BASE + 0x00000008)    /*密钥不存在*/
#define SDR_SDFNOTSUPPORT		(SDR_BASE + 0x00000009)    /*不支持的算法*/
#define SDR_SDFMODNOTSUPPORT	(SDR_BASE + 0x0000000A)    /*不支持的算法模式*/
#define SDR_PKOPERR				(SDR_BASE + 0x0000000B)    /*公钥运算错误*/
#define SDR_SKOPERR				(SDR_BASE + 0x0000000C)    /*私钥运算错误*/
#define SDR_SIGNERR				(SDR_BASE + 0x0000000D)    /*签名错误*/
#define SDR_VERIFYERR			(SDR_BASE + 0x0000000E)    /*验证错误*/
#define SDR_SYMOPERR			(SDR_BASE + 0x0000000F)    /*对称运算错误*/
#define SDR_STEPERR				(SDR_BASE + 0x00000010)    /*步骤错误*/
#define SDR_FILESIZEERR			(SDR_BASE + 0x00000011)    /*文件大小错误或输入数据长度非法*/
#define SDR_FILENOEXIST			(SDR_BASE + 0x00000012)    /*文件不存在*/
#define SDR_FILEOFSERR			(SDR_BASE + 0x00000013)    /*文件操作偏移量错误*/
#define SDR_KEYTYPEERR			(SDR_BASE + 0x00000014)    /*密钥类型错误*/
#define SDR_KEYERR				(SDR_BASE + 0x00000015)    /*密钥错误*/
#define SDR_ENCDATAERR			(SDR_BASE + 0x00000016)    /*ECC加密数据错误*/
#define SDR_RANDERR				(SDR_BASE + 0x00000017)    /*随机数产生失败*/
#define SDR_PRKRERR				(SDR_BASE + 0x00000018)    /*私钥使用权限获取错误*/
#define SDR_MACERR				(SDR_BASE + 0x00000019)    /*MAC运算失败*/
#define SDR_FILEEXISTSERR		(SDR_BASE + 0x0000001A)    /*指定文件已存在*/
#define SDR_FILEWERR			(SDR_BASE + 0x0000001B)    /*文件写入失败*/
#define SDR_NOBUFFERR			(SDR_BASE + 0x0000001C)    /*存储空间不足*/
#define SDR_INARGERR			(SDR_BASE + 0x0000001D)    /*输入参数错误*/
#define SDR_OUTARGERR			(SDR_BASE + 0x0000001E)    /*输出参数错误*/


/*============================================================*/
/*扩展错误码*/
#define BYR_BASE				(SDR_BASE + 0x00020000)	/*自定义错误码基础值*/
#define BYR_LOGINERR			(BYR_BASE + 0x00000001)	/*未登录*/
#define BYR_EXPIRESERR				(BYR_BASE + 0x00000002)	/*密钥过期*/
#define BYR_LOADERR				(BYR_BASE + 0x00000003)	/*未加载模块*/


/*许可证错误码*/
#define BYR_LIC_BASE				(SDR_BASE + 0x00030000)	/*自定义错误码基础值*/
#define BYR_LIC_EXISTERR			(BYR_LIC_BASE + 0x00000001)	/*未获许可证*/
#define BYR_LIC_AUTHERR				(BYR_LIC_BASE + 0x00000002)	/*许可证错误*/
#define BYR_LIC_TIMEERR				(BYR_LIC_BASE + 0x00000003)	/*许可过期*/
//为操作方便，增加自定义类型部分
#define SD_PTR *

	//=====================================SDF函数指针类型定义============================================//
	//设备管理类函数
	typedef SGD_RV DEVAPI _CP_SDF_OpenDevice(SGD_HANDLE* phDeviceHandle);
	typedef SGD_RV DEVAPI _CP_SDF_CloseDevice(SGD_HANDLE hDeviceHandle);
	typedef SGD_RV DEVAPI _CP_SDF_OpenSession(SGD_HANDLE hDeviceHandle, SGD_HANDLE* phSessionHandle);
	typedef SGD_RV DEVAPI _CP_SDF_CloseSession(SGD_HANDLE hSessionHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GetDeviceInfo(SGD_HANDLE hSessionHandle, DEVICEINFO* pstDeviceInfo);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateRandom(SGD_HANDLE hSessionHandle, SGD_UINT32 uiLength, SGD_UCHAR* pucRandom);
	typedef SGD_RV DEVAPI _CP_SDF_GetPrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR* pucPassword, SGD_UINT32 uiPwdLength);
	typedef SGD_RV DEVAPI _CP_SDF_ReleasePrivateKeyAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex);

	//密钥管理类函数
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyPair_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey* pucPublicKey, RSArefPrivateKey* pucPrivateKey);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyPair_RSAEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKeyEx* pucPublicKey, RSArefPrivateKeyEx* pucPrivateKey);
	typedef SGD_RV DEVAPI _CP_SDF_ExportSignPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey* pucPublicKey);
	typedef SGD_RV DEVAPI _CP_SDF_ExportSignPublicKey_RSAEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKeyEx* pucPublicKey);
	typedef SGD_RV DEVAPI _CP_SDF_ExportEncPublicKey_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey* pucPublicKey);
	typedef SGD_RV DEVAPI _CP_SDF_ExportEncPublicKey_RSAEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKeyEx* pucPublicKey);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithIPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR* pucKey, SGD_UINT32* puiKeyLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithEPK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKey* pucPublicKey, SGD_UCHAR* pucKey, SGD_UINT32* puiKeyLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithEPK_RSAEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, RSArefPublicKeyEx* pucPublicKey, SGD_UCHAR* pucKey, SGD_UINT32* puiKeyLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_ImportKeyWithISK_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR* pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_ExchangeDigitEnvelopeBaseOnRSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKey* pucPublicKey, SGD_UCHAR* pucDEInput, SGD_UINT32 uiDELength, SGD_UCHAR* pucDEOutput, SGD_UINT32* puiDELength);
	typedef SGD_RV DEVAPI _CP_SDF_ExchangeDigitEnvelopeBaseOnRSAEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, RSArefPublicKeyEx* pucPublicKey, SGD_UCHAR* pucDEInput, SGD_UINT32 uiDELength, SGD_UCHAR* pucDEOutput, SGD_UINT32* puiDELength);

	typedef SGD_RV DEVAPI _CP_SDF_ImportKey(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_DestroyKey(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GetSymmKeyHandle(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiSDFID, SGD_UINT32 uiKEKIndex, SGD_UCHAR* pucKey, SGD_UINT32* puiKeyLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_ImportKeyWithKEK(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, SGD_UINT32 uiKEKIndex, SGD_UCHAR* pucKey, SGD_UINT32 uiKeyLength, SGD_HANDLE* phKeyHandle);

	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, SGD_UINT32 uiKeyBits, ECCrefPublicKey* pucPublicKey, ECCrefPrivateKey* pucPrivateKey);
	typedef SGD_RV DEVAPI _CP_SDF_ExportSignPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey* pucPublicKey);
	typedef SGD_RV DEVAPI _CP_SDF_ExportEncPublicKey_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, ECCrefPublicKey* pucPublicKey);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateAgreementDataWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR* pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey* pucSponsorPublicKey, ECCrefPublicKey* pucSponsorTmpPublicKey, SGD_HANDLE* phAgreementHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey* pucResponsePublicKey, ECCrefPublicKey* pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateAgreementDataAndKeyWithECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR* pucResponseID, SGD_UINT32 uiResponseIDLength, SGD_UCHAR* pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey* pucSponsorPublicKey, ECCrefPublicKey* pucSponsorTmpPublicKey, ECCrefPublicKey* pucResponsePublicKey, ECCrefPublicKey* pucResponseTmpPublicKey, SGD_HANDLE* phKeyHandle);
	// 新增：扩展接口，输出原始共享密钥
	// 发起方接口（服务端使用）
	typedef SGD_RV DEVAPI _CP_SDF_GenerateAgreementDataWithECCEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR* pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey* pucSponsorPublicKey, ECCrefPublicKey* pucSponsorTmpPublicKey, SGD_HANDLE* phAgreementHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithECCEx(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucResponseID, SGD_UINT32 uiResponseIDLength, ECCrefPublicKey* pucResponsePublicKey, ECCrefPublicKey* pucResponseTmpPublicKey, SGD_HANDLE hAgreementHandle, SGD_UCHAR* pucSharedSecret, SGD_UINT32* puiSecretLength, SGD_HANDLE* phKeyHandle);
	// 响应方接口（客户端使用）
	typedef SGD_RV DEVAPI _CP_SDF_GenerateAgreementDataAndKeyWithECCEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR* pucResponseID, SGD_UINT32 uiResponseIDLength, SGD_UCHAR* pucSponsorID, SGD_UINT32 uiSponsorIDLength, ECCrefPublicKey* pucSponsorPublicKey, ECCrefPublicKey* pucSponsorTmpPublicKey, ECCrefPublicKey* pucResponsePublicKey, ECCrefPublicKey* pucResponseTmpPublicKey, SGD_UCHAR* pucSharedSecret, SGD_UINT32* puiSecretLength, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithIPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiKeyBits, ECCCipher* pucKey, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_GenerateKeyWithEPK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyBits, SGD_UINT32 uiSDFID, ECCrefPublicKey* pucPublicKey, ECCCipher* pucKey, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_ImportKeyWithISK_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, ECCCipher* pucKey, SGD_HANDLE* phKeyHandle);
	typedef SGD_RV DEVAPI _CP_SDF_ExchangeDigitEnvelopeBaseOnECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiSDFID, ECCrefPublicKey* pucPublicKey, ECCCipher* pucEncDataIn, ECCCipher* pucEncDataOut);

	//非对称密码运算函数
	typedef SGD_RV DEVAPI _CP_SDF_ExternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPublicKey* pucPublicKey, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_ExternalPublicKeyOperation_RSAEx(SGD_HANDLE hSessionHandle, RSArefPublicKeyEx* pucPublicKey, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_ExternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, RSArefPrivateKey* pucPrivateKey, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_ExternalPrivateKeyOperation_RSAEx(SGD_HANDLE hSessionHandle, RSArefPrivateKeyEx* pucPrivateKey, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_InternalPublicKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_InternalPrivateKeyOperation_RSA(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_InternalPublicKeyOperation_RSA_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);
	typedef SGD_RV DEVAPI _CP_SDF_InternalPrivateKeyOperation_RSA_Ex(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiKeyUsage, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, SGD_UCHAR* pucDataOutput, SGD_UINT32* puiOutputLength);

	typedef SGD_RV DEVAPI _CP_SDF_ExternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, ECCrefPrivateKey* pucPrivateKey, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, ECCSignature* pucSignature);
	typedef SGD_RV DEVAPI _CP_SDF_ExternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, ECCrefPublicKey* pucPublicKey, SGD_UCHAR* pucDataInput, SGD_UINT32 uiInputLength, ECCSignature* pucSignature);
	typedef SGD_RV DEVAPI _CP_SDF_InternalSign_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, ECCSignature* pucSignature);
	typedef SGD_RV DEVAPI _CP_SDF_InternalVerify_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, ECCSignature* pucSignature);
	typedef SGD_RV DEVAPI _CP_SDF_ExternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, ECCrefPublicKey* pucPublicKey, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, ECCCipher* pucEncData);
	typedef SGD_RV DEVAPI _CP_SDF_ExternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, ECCrefPrivateKey* pucPrivateKey, ECCCipher* pucEncData, SGD_UCHAR* pucData, SGD_UINT32* puiDataLength);
	typedef SGD_RV DEVAPI _CP_SDF_InternalEncrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiIPKIndex, SGD_UINT32 uiSDFID, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, ECCCipher* pucEncData);
	typedef SGD_RV DEVAPI _CP_SDF_InternalDecrypt_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiISKIndex, SGD_UINT32 uiSDFID, ECCCipher* pucEncData, SGD_UCHAR* pucData, SGD_UINT32* puiDataLength);

	//对称密码运算函数
	typedef SGD_RV DEVAPI _CP_SDF_Encrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiSDFID, SGD_UCHAR* pucIV, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, SGD_UCHAR* pucEncData, SGD_UINT32* puiEncDataLength);
	typedef SGD_RV DEVAPI _CP_SDF_Decrypt(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiSDFID, SGD_UCHAR* pucIV, SGD_UCHAR* pucEncData, SGD_UINT32 uiEncDataLength, SGD_UCHAR* pucData, SGD_UINT32* puiDataLength);
	typedef SGD_RV DEVAPI _CP_SDF_CalculateMAC(SGD_HANDLE hSessionHandle, SGD_HANDLE hKeyHandle, SGD_UINT32 uiSDFID, SGD_UCHAR* pucIV, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength, SGD_UCHAR* pucMAC, SGD_UINT32* puiMACLength);

	//杂凑运算函数
	typedef SGD_RV DEVAPI _CP_SDF_HashInit(SGD_HANDLE hSessionHandle, SGD_UINT32 uiSDFID, ECCrefPublicKey* pucPublicKey, SGD_UCHAR* pucID, SGD_UINT32 uiIDLength);
	typedef SGD_RV DEVAPI _CP_SDF_HashUpdate(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucData, SGD_UINT32 uiDataLength);
	typedef SGD_RV DEVAPI _CP_SDF_HashFinal(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucHash, SGD_UINT32* puiHashLength);

	//用户文件操作函数
	typedef SGD_RV DEVAPI _CP_SDF_CreateFile(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiFileSize);
	typedef SGD_RV DEVAPI _CP_SDF_ReadFile(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32* puiReadLength, SGD_UCHAR* pucBuffer);
	typedef SGD_RV DEVAPI _CP_SDF_WriteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucFileName, SGD_UINT32 uiNameLen, SGD_UINT32 uiOffset, SGD_UINT32 uiWriteLength, SGD_UCHAR* pucBuffer);
	typedef SGD_RV DEVAPI _CP_SDF_DeleteFile(SGD_HANDLE hSessionHandle, SGD_UCHAR* pucFileName, SGD_UINT32 uiNameLen);

	//扩展接口
	typedef SGD_RV DEVAPI _CP_SDF_InputRSAKeyPair(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKey* pucPublicKey, RSArefPrivateKey* pucPrivateKey);
	typedef SGD_RV DEVAPI _CP_SDF_InputRSAKeyPairEx(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, RSArefPublicKeyEx* pucPublicKey, RSArefPrivateKeyEx* pucPrivateKey);
	typedef SGD_RV DEVAPI _CP_SDF_ImportKeyPair_ECC(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex, SGD_UINT32 uiSDFID, SGD_UINT32 uiKeyBits, ENVELOPEDKEYBLOB* pucEncedKeyPair);
	typedef const SGD_CHAR* DEVAPI _CP_SDF_GetErrMsg(SGD_UINT32 code);
	typedef SGD_RV DEVAPI _CP_SDF_GetKekAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, SGD_UCHAR* pucPassword, SGD_UINT32 uiPwdLength);
	typedef SGD_RV DEVAPI _CP_SDF_ReleaseKekAccessRight(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyIndex);
	//管理接口
	typedef SGD_RV DEVAPI _CP_BYCSM_LoadModule(const char* pwd);
	typedef SGD_RV DEVAPI _CP_BYCSM_UninstallModule(const char* pwd);

	typedef struct _SD_FUNCTION_LIST {
		//=====================================设备管理============================================//
		_CP_SDF_OpenDevice* SDF_OpenDevice;
		_CP_SDF_CloseDevice* SDF_CloseDevice;
		_CP_SDF_OpenSession* SDF_OpenSession;
		_CP_SDF_CloseSession* SDF_CloseSession;
		_CP_SDF_GetDeviceInfo* SDF_GetDeviceInfo;
		_CP_SDF_GenerateRandom* SDF_GenerateRandom;
		_CP_SDF_GetPrivateKeyAccessRight* SDF_GetPrivateKeyAccessRight;
		_CP_SDF_ReleasePrivateKeyAccessRight* SDF_ReleasePrivateKeyAccessRight;
		//=====================================密钥管理============================================//
		_CP_SDF_GenerateKeyPair_RSA* SDF_GenerateKeyPair_RSA;
		_CP_SDF_GenerateKeyPair_RSAEx* SDF_GenerateKeyPair_RSAEx;
		_CP_SDF_ExportSignPublicKey_RSA* SDF_ExportSignPublicKey_RSA;
		_CP_SDF_ExportSignPublicKey_RSAEx* SDF_ExportSignPublicKey_RSAEx;
		_CP_SDF_ExportEncPublicKey_RSA* SDF_ExportEncPublicKey_RSA;
		_CP_SDF_ExportEncPublicKey_RSAEx* SDF_ExportEncPublicKey_RSAEx;
		_CP_SDF_GenerateKeyWithIPK_RSA* SDF_GenerateKeyWithIPK_RSA;
		_CP_SDF_GenerateKeyWithEPK_RSA* SDF_GenerateKeyWithEPK_RSA;
		_CP_SDF_GenerateKeyWithEPK_RSAEx* SDF_GenerateKeyWithEPK_RSAEx;
		_CP_SDF_ImportKeyWithISK_RSA* SDF_ImportKeyWithISK_RSA;
		_CP_SDF_ExchangeDigitEnvelopeBaseOnRSA* SDF_ExchangeDigitEnvelopeBaseOnRSA;
		_CP_SDF_ExchangeDigitEnvelopeBaseOnRSAEx* SDF_ExchangeDigitEnvelopeBaseOnRSAEx;
		_CP_SDF_ImportKey* SDF_ImportKey;
		_CP_SDF_DestroyKey* SDF_DestroyKey;
		_CP_SDF_GetSymmKeyHandle* SDF_GetSymmKeyHandle;
		_CP_SDF_GenerateKeyWithKEK* SDF_GenerateKeyWithKEK;
		_CP_SDF_ImportKeyWithKEK* SDF_ImportKeyWithKEK;
		_CP_SDF_GenerateKeyPair_ECC* SDF_GenerateKeyPair_ECC;
		_CP_SDF_ExportSignPublicKey_ECC* SDF_ExportSignPublicKey_ECC;
		_CP_SDF_ExportEncPublicKey_ECC* SDF_ExportEncPublicKey_ECC;
		_CP_SDF_GenerateAgreementDataWithECC* SDF_GenerateAgreementDataWithECC;
		_CP_SDF_GenerateKeyWithECC* SDF_GenerateKeyWithECC;
		_CP_SDF_GenerateAgreementDataAndKeyWithECC* SDF_GenerateAgreementDataAndKeyWithECC;
		// 新增：扩展接口，输出原始共享密钥
		// 发起方接口（服务端使用）
		_CP_SDF_GenerateAgreementDataWithECCEx* SDF_GenerateAgreementDataWithECCEx;
		_CP_SDF_GenerateKeyWithECCEx* SDF_GenerateKeyWithECCEx;
		// 响应方接口（客户端使用）
		_CP_SDF_GenerateAgreementDataAndKeyWithECCEx* SDF_GenerateAgreementDataAndKeyWithECCEx;
		_CP_SDF_GenerateKeyWithIPK_ECC* SDF_GenerateKeyWithIPK_ECC;
		_CP_SDF_GenerateKeyWithEPK_ECC* SDF_GenerateKeyWithEPK_ECC;
		_CP_SDF_ImportKeyWithISK_ECC* SDF_ImportKeyWithISK_ECC;
		_CP_SDF_ExchangeDigitEnvelopeBaseOnECC* SDF_ExchangeDigitEnvelopeBaseOnECC;
		//=====================================非对称密码运算============================================//
		_CP_SDF_ExternalPublicKeyOperation_RSA* SDF_ExternalPublicKeyOperation_RSA;
		_CP_SDF_ExternalPublicKeyOperation_RSAEx* SDF_ExternalPublicKeyOperation_RSAEx;
		_CP_SDF_ExternalPrivateKeyOperation_RSA* SDF_ExternalPrivateKeyOperation_RSA;
		_CP_SDF_ExternalPrivateKeyOperation_RSAEx* SDF_ExternalPrivateKeyOperation_RSAEx;
		_CP_SDF_InternalPublicKeyOperation_RSA* SDF_InternalPublicKeyOperation_RSA;
		_CP_SDF_InternalPrivateKeyOperation_RSA* SDF_InternalPrivateKeyOperation_RSA;
		_CP_SDF_InternalPublicKeyOperation_RSA_Ex* SDF_InternalPublicKeyOperation_RSA_Ex;
		_CP_SDF_InternalPrivateKeyOperation_RSA_Ex* SDF_InternalPrivateKeyOperation_RSA_Ex;
		_CP_SDF_ExternalSign_ECC* SDF_ExternalSign_ECC;
		_CP_SDF_ExternalVerify_ECC* SDF_ExternalVerify_ECC;
		_CP_SDF_InternalSign_ECC* SDF_InternalSign_ECC;
		_CP_SDF_InternalVerify_ECC* SDF_InternalVerify_ECC;
		_CP_SDF_ExternalEncrypt_ECC* SDF_ExternalEncrypt_ECC;
		_CP_SDF_ExternalDecrypt_ECC* SDF_ExternalDecrypt_ECC;
		_CP_SDF_InternalEncrypt_ECC* SDF_InternalEncrypt_ECC;
		_CP_SDF_InternalDecrypt_ECC* SDF_InternalDecrypt_ECC;
		//=====================================对称密码运算============================================//
		_CP_SDF_Encrypt* SDF_Encrypt;
		_CP_SDF_Decrypt* SDF_Decrypt;
		_CP_SDF_CalculateMAC* SDF_CalculateMAC;
		//=====================================杂凑运算============================================//
		_CP_SDF_HashInit* SDF_HashInit;
		_CP_SDF_HashUpdate* SDF_HashUpdate;
		_CP_SDF_HashFinal* SDF_HashFinal;
		//=====================================用户文件操作============================================//
		_CP_SDF_CreateFile* SDF_CreateFile;
		_CP_SDF_ReadFile* SDF_ReadFile;
		_CP_SDF_WriteFile* SDF_WriteFile;
		_CP_SDF_DeleteFile* SDF_DeleteFile;
		//=====================================扩展接口============================================//
		_CP_SDF_InputRSAKeyPair* SDF_InputRSAKeyPair;
		_CP_SDF_InputRSAKeyPairEx* SDF_InputRSAKeyPairEx;
		_CP_SDF_ImportKeyPair_ECC* SDF_ImportKeyPair_ECC;
		_CP_SDF_GetErrMsg* SDF_GetErrMsg;
		_CP_SDF_GetKekAccessRight* SDF_GetKekAccessRight;
		_CP_SDF_ReleaseKekAccessRight* SDF_ReleaseKekAccessRight;
		//=====================================管理接口============================================//
		_CP_BYCSM_LoadModule* BYCSM_LoadModule;
		_CP_BYCSM_UninstallModule* BYCSM_UninstallModule;

	}SD_FUNCTION_LIST;

	typedef SD_FUNCTION_LIST SD_PTR SD_FUNCTION_LIST_PTR;

	typedef SD_FUNCTION_LIST_PTR SD_PTR SD_FUNCTION_LIST_PTR_PTR;

	/* 初始化 SDF 引擎 */
	void ENGINE_load_skf(void);

	/* 为 nginx/angie 设置 SDF 引擎 */
	int skf_engine_setup_for_nginx(const char* lib_path, const char* device_name,
		const char* app_name, const char* pin);

	/* SDF 配置结构体 */
	typedef struct SDF_CONFIG_st SDF_CONFIG;

	/* 创建和释放 SDF 配置 */
	SDF_CONFIG* skf_config_new(void);
	void skf_config_free(SDF_CONFIG* config);

	/* 设置 SDF 配置参数 */
	int skf_config_set_library(SDF_CONFIG* config, const char* lib_path);
	int skf_config_set_device(SDF_CONFIG* config, const char* device_name);
	int skf_config_set_application(SDF_CONFIG* config, const char* app_name);
	int skf_config_set_container(SDF_CONFIG* config, const char* container_name);
	int skf_config_set_pin(SDF_CONFIG* config, const char* pin);

	/* 加载和配置 SDF 引擎 */
	ENGINE* skf_engine_load_and_configure(SDF_CONFIG* config);

	/* 创建和释放带有 SDF 引擎的 SSL 上下文 */
	SSL_CTX* skf_ssl_ctx_new_with_engine(SDF_CONFIG* config, const SSL_METHOD* method);
	void skf_ssl_ctx_free_with_engine(SSL_CTX* ctx);

#ifdef __cplusplus
}
#endif

#endif /* OSSL_ENGINES_E_SDF_H */