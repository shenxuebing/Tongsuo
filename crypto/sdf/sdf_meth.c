/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#include <openssl/types.h>
#include <openssl/sdf.h>
#include "sdf_local.h"

static int x_OpenDevice(void **phDeviceHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_CloseDevice(void *hDeviceHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_OpenSession(void *hDeviceHandle, void **phSessionHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_CloseSession(void *hSessionHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateRandom(void *hSessionHandle, unsigned int uiLength,
                            unsigned char *pucRandom)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GetPrivateKeyAccessRight(void *hSessionHandle,
                                        unsigned int uiKeyIndex,
                                        unsigned char *pucPassword,
                                        unsigned int uiPwdLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ReleasePrivateKeyAccessRight(void *hSessionHandlek,
                                            unsigned int uiKeyIndex)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ImportKeyWithISK_ECC(void *hSessionHandle,
                                    unsigned int uiISKIndex,
                                    OSSL_ECCCipher *pucKey,
                                    void **phKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}


static int x_ImportKeyWithKEK(void *hSessionHandle, unsigned int uiAlgID,
                                unsigned int uiKEKIndex, unsigned char *pucKey,
                                unsigned int puiKeyLength, void **phKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportSignPublicKey_ECC(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_ECCrefPublicKey *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportEncPublicKey_ECC(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_ECCrefPublicKey *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportSignPublicKey_RSA(void *hSessionHandle,
                                     unsigned int uiKeyIndex,
                                     OSSL_RSArefPublicKey *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportSignPublicKey_RSAEx(void *hSessionHandle,
                                       unsigned int uiKeyIndex,
                                       OSSL_RSArefPublicKeyEx *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportEncPublicKey_RSA(void *hSessionHandle,
                                    unsigned int uiKeyIndex,
                                    OSSL_RSArefPublicKey *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_ExportEncPublicKey_RSAEx(void *hSessionHandle,
                                      unsigned int uiKeyIndex,
                                      OSSL_RSArefPublicKeyEx *pucPublicKey)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_DestroyKey(void *hSessionHandle, void *hKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalEncrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned int uiAlgID,
                                  unsigned char *pucData,
                                  unsigned int uiDataLength,
                                  OSSL_ECCCipher *pucEncData)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalDecrypt_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                                  unsigned int uiAlgID,
                                  OSSL_ECCCipher *pucEncData,
                                  unsigned char *pucData,
                                  unsigned int *puiDataLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalSign_ECC(void *hSessionHandle, unsigned int uiISKIndex,
                              unsigned char * pucData,
                              unsigned int uiDataLength,
                              OSSL_ECCSignature *pucSignature)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalPublicKeyOperation_RSA(void *hSessionHandle,
                                            unsigned int uiKeyIndex,
                                            unsigned char *pucDataInput,
                                            unsigned int uiInputLength,
                                            unsigned char *pucDataOutput,
                                            unsigned int *puiOutputLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalPrivateKeyOperation_RSA(void *hSessionHandle,
                                             unsigned int uiKeyIndex,
                                             unsigned char *pucDataInput,
                                             unsigned int uiInputLength,
                                             unsigned char *pucDataOutput,
                                             unsigned int *puiOutputLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalPublicKeyOperation_RSA_Ex(void *hSessionHandle,
                                               unsigned int uiKeyIndex,
                                               unsigned int uiKeyUsage,
                                               unsigned char *pucDataInput,
                                               unsigned int uiInputLength,
                                               unsigned char *pucDataOutput,
                                               unsigned int *puiOutputLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_InternalPrivateKeyOperation_RSA_Ex(void *hSessionHandle,
                                                unsigned int uiKeyIndex,
                                                unsigned int uiKeyUsage,
                                                unsigned char *pucDataInput,
                                                unsigned int uiInputLength,
                                                unsigned char *pucDataOutput,
                                                unsigned int *puiOutputLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_Encrypt(void *hSessionHandle, void *hKeyHandle,
                       unsigned int uiAlgID, unsigned char *pucIV,
                       unsigned char *pucData,
                       unsigned int uiDataLength,
                       unsigned char *pucEncData,
                       unsigned int *puiEncDataLength)
{
    return OSSL_SDR_NOTSUPPORT;
}
    
static int x_Decrypt(void *hSessionHandle, void *hKeyHandle,
                       unsigned int uiAlgID, unsigned char *pucIV,
                       unsigned char *pucEncData, unsigned int uiEncDataLength,
                       unsigned char *pucData,
                       unsigned int *puiDataLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_CalculateMAC(void *hSessionHandle, void *hKeyHandle,
                            unsigned int uiAlgID, unsigned char *pucIV,
                            unsigned char *pucData, unsigned int uiDataLength,
                            unsigned char *pucMac, unsigned int *puiMACLength)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateKey(void *hSessionHandle, uint8_t type, uint8_t no_kek,
                            uint32_t len, void **pkey_handle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateAgreementDataWithECCEx(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateKeyWithECCEx(void *hSessionHandle,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle)
{
    return OSSL_SDR_NOTSUPPORT;
}

static int x_GenerateAgreementDataAndKeyWithECCEx(
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
    return OSSL_SDR_NOTSUPPORT;
}

SDF_METHOD ts_sdf_meth = {
    x_OpenDevice,
    x_CloseDevice,
    x_OpenSession,
    x_CloseSession,
    x_GenerateRandom,
    x_GetPrivateKeyAccessRight,
    x_ReleasePrivateKeyAccessRight,
    x_ImportKeyWithISK_ECC,
    x_ImportKeyWithKEK,
    x_ExportSignPublicKey_ECC,
    x_ExportEncPublicKey_ECC,
    x_ExportSignPublicKey_RSA,
    x_ExportSignPublicKey_RSAEx,
    x_ExportEncPublicKey_RSA,
    x_ExportEncPublicKey_RSAEx,
    x_DestroyKey,
    x_InternalPublicKeyOperation_RSA,
    x_InternalPrivateKeyOperation_RSA,
    x_InternalPublicKeyOperation_RSA_Ex,
    x_InternalPrivateKeyOperation_RSA_Ex,
    x_InternalEncrypt_ECC,
    x_InternalDecrypt_ECC,
    x_InternalSign_ECC,
    x_Encrypt,
    x_Decrypt,
    x_CalculateMAC,

    /* SDF Ext API */
    x_GenerateKey,

    /* SDF Key Agreement API */
    x_GenerateAgreementDataWithECCEx,
    x_GenerateKeyWithECCEx,
    x_GenerateAgreementDataAndKeyWithECCEx,
};
