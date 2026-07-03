/*
 * SDF GM/T 0018-2012 data type definitions
 *
 * Shared header containing pure data types and constants from GM/T 0018 SDF interface.
 * This file is included by both crypto/sdf/sdf_local.h and providers/sdfprov/sdf_types.h
 * to eliminate duplicate definitions.
 */

#ifndef OSSL_INTERNAL_SDF_GMT_TYPES_H
#define OSSL_INTERNAL_SDF_GMT_TYPES_H

#include <openssl/opensslconf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GMT0018_2012    1

/* Data types */
typedef char               SGD_CHAR;
typedef char               SGD_INT8;
typedef short              SGD_INT16;
typedef int                SGD_INT32;
typedef long long          SGD_INT64;
typedef unsigned char      SGD_UCHAR;
typedef unsigned char      SGD_UINT8;
typedef unsigned short     SGD_UINT16;
typedef unsigned int       SGD_UINT32;
typedef unsigned long long SGD_UINT64;
typedef unsigned int       SGD_RV;
typedef void*              SGD_OBJ;
typedef int                SGD_BOOL;
typedef void*              SGD_HANDLE;

#if !(defined(_WIN32) || defined(_WIN64))
typedef void* HMODULE;
#define _stdcall
#define __stdcall
#define WINAPI
#define DEVAPI
#else
#define DEVAPI     _stdcall
#endif

#ifndef CONST
#define CONST               const
#endif

/* Device info */
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

/* RSA key types (GM/T 0018-2012) */
#define RSAref_MAX_BITS    2048
#define RSAref_MAX_LEN     ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS   ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN    ((RSAref_MAX_PBITS + 7)/ 8)

#define RSAref_MAX_BITS_EX    4096
#define RSAref_MAX_LEN_EX     ((RSAref_MAX_BITS_EX + 7) / 8)
#define RSAref_MAX_PBITS_EX   ((RSAref_MAX_BITS_EX + 1) / 2)
#define RSAref_MAX_PLEN_EX    ((RSAref_MAX_PBITS_EX + 7)/ 8)

typedef struct RSArefPublicKey_st {
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
} RSArefPublicKey;

typedef struct RSArefPublicKey_st_ex {
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN_EX];
    unsigned char e[RSAref_MAX_LEN_EX];
} RSArefPublicKeyEx;

typedef struct RSArefPrivateKey_st {
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN];
    unsigned char e[RSAref_MAX_LEN];
    unsigned char d[RSAref_MAX_LEN];
    unsigned char prime[2][RSAref_MAX_PLEN];
    unsigned char pexp[2][RSAref_MAX_PLEN];
    unsigned char coef[RSAref_MAX_PLEN];
} RSArefPrivateKey;

typedef struct RSArefPrivateKey_st_ex {
    unsigned int  bits;
    unsigned char m[RSAref_MAX_LEN_EX];
    unsigned char e[RSAref_MAX_LEN_EX];
    unsigned char d[RSAref_MAX_LEN_EX];
    unsigned char prime[2][RSAref_MAX_PLEN_EX];
    unsigned char pexp[2][RSAref_MAX_PLEN_EX];
    unsigned char coef[RSAref_MAX_PLEN_EX];
} RSArefPrivateKeyEx;

/* ECC key types (GM/T 0018-2012) */
#define ECCref_MAX_BITS         512
#define ECCref_MAX_LEN          ((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN   136

typedef struct ECCrefPublicKey_st {
    unsigned int  bits;
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
} ECCrefPublicKey;

typedef struct ECCrefPrivateKey_st {
    unsigned int  bits;
    unsigned char K[ECCref_MAX_LEN];
} ECCrefPrivateKey;

typedef struct ECCCipher_st {
    unsigned char x[ECCref_MAX_LEN];
    unsigned char y[ECCref_MAX_LEN];
    unsigned char M[32];
    unsigned int  L;
    unsigned char C[1];
} ECCCipher;

typedef struct ECCSignature_st {
    unsigned char r[ECCref_MAX_LEN];
    unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

/* Constants */
#define SGD_TRUE        0x00000001
#define SGD_FALSE       0x00000000

#define IN
#define OUT

/* Algorithm identifiers (GMT0018_2012) */
#define SGD_SM1_ECB     0x00000101
#define SGD_SM1_CBC     0x00000102
#define SGD_SM1_CFB     0x00000104
#define SGD_SM1_OFB     0x00000108
#define SGD_SM1_MAC     0x00000110
#define SGD_SM1_CTR     0x00000120

#define SGD_SSF33_ECB   0x00000201
#define SGD_SSF33_CBC   0x00000202
#define SGD_SSF33_CFB   0x00000204
#define SGD_SSF33_OFB   0x00000208
#define SGD_SSF33_MAC   0x00000210
#define SGD_SSF33_CTR   0x00000220

#define SGD_SMS4_ECB    0x00000401
#define SGD_SMS4_CBC    0x00000402
#define SGD_SMS4_CFB    0x00000404
#define SGD_SMS4_OFB    0x00000408
#define SGD_SMS4_MAC    0x00000410
#define SGD_SMS4_CTR    0x00000420
#define SGD_SMS4_XTS    0x00000440

#define SGD_SM4_ECB     0x00000401
#define SGD_SM4_CBC     0x00000402
#define SGD_SM4_CFB     0x00000404
#define SGD_SM4_OFB     0x00000408
#define SGD_SM4_MAC     0x00000410
#define SGD_SM4_CTR     0x00000420
#define SGD_SM4_XTS     0x00000440

#define SGD_ZUC_EEA3    0x00000801
#define SGD_ZUC_EIA3    0x00000802

#define SGD_SM7_ECB     0x00001001
#define SGD_SM7_CBC     0x00001002
#define SGD_SM7_CFB     0x00001004
#define SGD_SM7_OFB     0x00001008
#define SGD_SM7_MAC     0x00001010
#define SGD_SM7_CTR     0x00001020

#define SGD_DES_ECB     0x00002001
#define SGD_DES_CBC     0x00002002
#define SGD_DES_CFB     0x00002004
#define SGD_DES_OFB     0x00002008
#define SGD_DES_MAC     0x00002010
#define SGD_DES_CTR     0x00002020

#define SGD_3DES_ECB    0x00004001
#define SGD_3DES_CBC    0x00004002
#define SGD_3DES_CFB    0x00004004
#define SGD_3DES_OFB    0x00004008
#define SGD_3DES_MAC    0x00004010
#define SGD_3DES_CTR    0x00004020

#define SGD_AES_ECB     0x00008001
#define SGD_AES_CBC     0x00008002
#define SGD_AES_CFB     0x00008004
#define SGD_AES_OFB     0x00008008
#define SGD_AES_MAC     0x00008010
#define SGD_AES_CTR     0x00008020

#define SGD_RSA         0x00010000
#define SGD_RSA_SIGN    0x00010100
#define SGD_RSA_ENC     0x00010200

#define SGD_SM2         0x00020100
#define SGD_SM2_1       0x00020200
#define SGD_SM2_2       0x00020400
#define SGD_SM2_3       0x00020800

#define SGD_SM3         0x00000001
#define SGD_SHA1        0x00000002
#define SGD_SHA256      0x00000004
#define SGD_SHA512      0x00000008
#define SGD_SHA384      0x00000010
#define SGD_SHA224      0x00000020
#define SGD_MD5         0x00000080

/* Error codes */
#define SDR_OK                 0x0
#define SDR_BASE               0x01000000
#define SDR_UNKNOWERR          (SDR_BASE + 0x00000001)
#define SDR_NOTSUPPORT         (SDR_BASE + 0x00000002)
#define SDR_COMMFAIL           (SDR_BASE + 0x00000003)
#define SDR_HARDFAIL           (SDR_BASE + 0x00000004)
#define SDR_OPENDEVICE         (SDR_BASE + 0x00000005)
#define SDR_OPENSESSION        (SDR_BASE + 0x00000006)
#define SDR_PARDENY            (SDR_BASE + 0x00000007)
#define SDR_KEYNOTEXIST        (SDR_BASE + 0x00000008)
#define SDR_SDFNOTSUPPORT      (SDR_BASE + 0x00000009)
#define SDR_SDFMODNOTSUPPORT   (SDR_BASE + 0x0000000A)
#define SDR_PKOPERR            (SDR_BASE + 0x0000000B)
#define SDR_SKOPERR            (SDR_BASE + 0x0000000C)
#define SDR_SIGNERR            (SDR_BASE + 0x0000000D)
#define SDR_VERIFYERR          (SDR_BASE + 0x0000000E)
#define SDR_SYMOPERR           (SDR_BASE + 0x0000000F)
#define SDR_STEPERR            (SDR_BASE + 0x00000010)
#define SDR_FILESIZEERR        (SDR_BASE + 0x00000011)
#define SDR_FILENOEXIST        (SDR_BASE + 0x00000012)
#define SDR_FILEOFSERR         (SDR_BASE + 0x00000013)
#define SDR_KEYTYPEERR         (SDR_BASE + 0x00000014)
#define SDR_KEYERR             (SDR_BASE + 0x00000015)
#define SDR_ENCDATAERR         (SDR_BASE + 0x00000016)
#define SDR_RANDERR            (SDR_BASE + 0x00000017)
#define SDR_PRKRERR            (SDR_BASE + 0x00000018)
#define SDR_MACERR             (SDR_BASE + 0x00000019)
#define SDR_FILEEXISTSERR      (SDR_BASE + 0x0000001A)
#define SDR_FILEWERR           (SDR_BASE + 0x0000001B)
#define SDR_NOBUFFERR          (SDR_BASE + 0x0000001C)
#define SDR_INARGERR           (SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR          (SDR_BASE + 0x0000001E)

/* Extended error codes */
#define BYR_BASE              (SDR_BASE + 0x00020000)
#define BYR_LOGINERR          (BYR_BASE + 0x00000001)
#define BYR_EXPIRESERR        (BYR_BASE + 0x00000002)
#define BYR_LOADERR           (BYR_BASE + 0x00000003)

#define BYR_LIC_BASE          (SDR_BASE + 0x00030000)
#define BYR_LIC_EXISTERR      (BYR_LIC_BASE + 0x00000001)
#define BYR_LIC_AUTHERR       (BYR_LIC_BASE + 0x00000002)
#define BYR_LIC_TIMEERR       (BYR_LIC_BASE + 0x00000003)

#define SD_PTR *

#ifdef __cplusplus
}
#endif

#endif /* OSSL_INTERNAL_SDF_GMT_TYPES_H */