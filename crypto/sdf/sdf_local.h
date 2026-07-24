/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SDF_LOCAL_H
# define OSSL_CRYPTO_SDF_LOCAL_H

# include <openssl/types.h>
# include <openssl/sdf.h>

typedef int (*SDF_OpenDevice_fn)(void **phDeviceHandle);
typedef int (*SDF_CloseDevice_fn)(void *hDeviceHandle);
typedef int (*SDF_OpenSession_fn)(void *hDeviceHandle, void **phSessionHandle);
typedef int (*SDF_CloseSession_fn)(void *hSessionHandle);
typedef int (*SDF_GenerateRandom_fn)(void *hSessionHandle,
    unsigned int uiLength, unsigned char *pucRandom);

typedef int (*SDF_GetPrivateKeyAccessRight_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucPassword,
    unsigned int uiPwdLength);

typedef int (*SDF_ReleasePrivateKeyAccessRight_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex);

typedef int (*SDF_ImportKeyWithISK_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucKey, void **phKeyHandle);

typedef int (*SDF_ImportKeyWithKEK_fn)(void *hSessionHandle,
    unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle);

typedef int (*SDF_DestroyKey_fn)(void *hSessionHandle, void *hKeyHandle);

typedef int (*SDF_Encrypt_fn)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength);

typedef int (*SDF_Decrypt_fn)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*SDF_CalculateMAC_fn)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength);

typedef int (*SDF_GenerateKey_fn)(void *hSessionHandle, uint8_t type,
    uint8_t no_kek, uint32_t len, void **pkey_handle);

typedef int (*SDF_ExportSignPublicKey_ECC_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);

typedef int (*SDF_ExportEncPublicKey_ECC_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);

typedef int (*SDF_ExportSignPublicKey_RSA_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey);

typedef int (*SDF_ExportSignPublicKey_RSAEx_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKeyEx *pucPublicKey);

typedef int (*SDF_ExportEncPublicKey_RSA_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey);

typedef int (*SDF_ExportEncPublicKey_RSAEx_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKeyEx *pucPublicKey);

typedef int (*SDF_InternalEncrypt_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiAlgID, unsigned char *pucData,
    unsigned int uiDataLength, OSSL_ECCCipher *pucEncData);
typedef int (*SDF_InternalDecrypt_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiAlgID, OSSL_ECCCipher *pucEncData,
    unsigned char *pucData, unsigned int *puiDataLength);

typedef int (*SDF_InternalSign_ECC_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
    OSSL_ECCSignature *pucSignature);

typedef int (*SDF_InternalPublicKeyOperation_RSA_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*SDF_ExternalPublicKeyOperation_RSA_fn)(void *hSessionHandle,
    OSSL_RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*SDF_ExternalPublicKeyOperation_RSAEx_fn)(void *hSessionHandle,
    OSSL_RSArefPublicKeyEx *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*SDF_InternalPrivateKeyOperation_RSA_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*SDF_ExternalPrivateKeyOperation_RSA_fn)(void *hSessionHandle,
    OSSL_RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*SDF_ExternalPrivateKeyOperation_RSAEx_fn)(void *hSessionHandle,
    OSSL_RSArefPrivateKeyEx *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*SDF_InternalPublicKeyOperation_RSA_Ex_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiKeyUsage,
    unsigned char *pucDataInput, unsigned int uiInputLength,
    unsigned char *pucDataOutput, unsigned int *puiOutputLength);

typedef int (*SDF_InternalPrivateKeyOperation_RSA_Ex_fn)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiKeyUsage,
    unsigned char *pucDataInput, unsigned int uiInputLength,
    unsigned char *pucDataOutput, unsigned int *puiOutputLength);

typedef int (*SDF_GenerateAgreementDataWithECCEx_fn)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle);

typedef int (*SDF_GenerateKeyWithECCEx_fn)(void *hSessionHandle,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle);

typedef int (*SDF_GenerateAgreementDataAndKeyWithECCEx_fn)(
    void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle);

typedef int (*SDFE_LoadModule_fn)(const char *password);
typedef int (*SDFE_UninstallModule_fn)(const char *password);

typedef int (*_CP_SDF_OpenDevice)(void **phDeviceHandle);
typedef int (*_CP_SDF_CloseDevice)(void *hDeviceHandle);
typedef int (*_CP_SDF_OpenSession)(void *hDeviceHandle, void **phSessionHandle);
typedef int (*_CP_SDF_CloseSession)(void *hSessionHandle);
typedef int (*_CP_SDF_GenerateRandom)(void *hSessionHandle,
    unsigned int uiLength, unsigned char *pucRandom);

typedef int (*_CP_SDF_GetPrivateKeyAccessRight)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucPassword,
    unsigned int uiPwdLength);

typedef int (*_CP_SDF_ReleasePrivateKeyAccessRight)(void *hSessionHandle,
    unsigned int uiKeyIndex);

typedef int (*_CP_SDF_ImportKeyWithISK_ECC)(void *hSessionHandle,
    unsigned int uiISKIndex, OSSL_ECCCipher *pucKey, void **phKeyHandle);

typedef int (*_CP_SDF_ImportKeyWithKEK)(void *hSessionHandle,
    unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
    unsigned int puiKeyLength, void **phKeyHandle);

typedef int (*_CP_SDF_DestroyKey)(void *hSessionHandle, void *hKeyHandle);

typedef int (*_CP_SDF_Encrypt)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucEncData,
    unsigned int *puiEncDataLength);

typedef int (*_CP_SDF_Decrypt)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucEncData,
    unsigned int uiEncDataLength, unsigned char *pucData,
    unsigned int *puiDataLength);

typedef int (*_CP_SDF_CalculateMAC)(void *hSessionHandle, void *hKeyHandle,
    unsigned int uiAlgID, unsigned char *pucIV, unsigned char *pucData,
    unsigned int uiDataLength, unsigned char *pucMac,
    unsigned int *puiMACLength);

typedef int (*_CP_SDF_ExportSignPublicKey_ECC)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);

typedef int (*_CP_SDF_ExportEncPublicKey_ECC)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_ECCrefPublicKey *pucPublicKey);

typedef int (*_CP_SDF_ExportSignPublicKey_RSA)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey);

typedef int (*_CP_SDF_ExportSignPublicKey_RSAEx)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKeyEx *pucPublicKey);

typedef int (*_CP_SDF_ExportEncPublicKey_RSA)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKey *pucPublicKey);

typedef int (*_CP_SDF_ExportEncPublicKey_RSAEx)(void *hSessionHandle,
    unsigned int uiKeyIndex, OSSL_RSArefPublicKeyEx *pucPublicKey);

typedef int (*_CP_SDF_InternalEncrypt_ECC)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiAlgID, unsigned char *pucData,
    unsigned int uiDataLength, OSSL_ECCCipher *pucEncData);

typedef int (*_CP_SDF_InternalDecrypt_ECC)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiAlgID, OSSL_ECCCipher *pucEncData,
    unsigned char *pucData, unsigned int *puiDataLength);

typedef int (*_CP_SDF_InternalSign_ECC)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned char *pucData, unsigned int uiDataLength,
    OSSL_ECCSignature *pucSignature);

typedef int (*_CP_SDF_InternalPublicKeyOperation_RSA)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*_CP_SDF_ExternalPublicKeyOperation_RSA)(void *hSessionHandle,
    OSSL_RSArefPublicKey *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*_CP_SDF_ExternalPublicKeyOperation_RSAEx)(void *hSessionHandle,
    OSSL_RSArefPublicKeyEx *pucPublicKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*_CP_SDF_InternalPrivateKeyOperation_RSA)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*_CP_SDF_ExternalPrivateKeyOperation_RSA)(void *hSessionHandle,
    OSSL_RSArefPrivateKey *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);
typedef int (*_CP_SDF_ExternalPrivateKeyOperation_RSAEx)(void *hSessionHandle,
    OSSL_RSArefPrivateKeyEx *pucPrivateKey, unsigned char *pucDataInput,
    unsigned int uiInputLength, unsigned char *pucDataOutput,
    unsigned int *puiOutputLength);

typedef int (*_CP_SDF_InternalPublicKeyOperation_RSA_Ex)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiKeyUsage,
    unsigned char *pucDataInput, unsigned int uiInputLength,
    unsigned char *pucDataOutput, unsigned int *puiOutputLength);

typedef int (*_CP_SDF_InternalPrivateKeyOperation_RSA_Ex)(void *hSessionHandle,
    unsigned int uiKeyIndex, unsigned int uiKeyUsage,
    unsigned char *pucDataInput, unsigned int uiInputLength,
    unsigned char *pucDataOutput, unsigned int *puiOutputLength);

typedef int (*_CP_SDF_GenerateAgreementDataWithECCEx)(void *hSessionHandle,
    unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    void **phAgreementHandle);

typedef int (*_CP_SDF_GenerateKeyWithECCEx)(void *hSessionHandle,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    void *hAgreementHandle,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle);

typedef int (*_CP_SDF_GenerateAgreementDataAndKeyWithECCEx)(
    void *hSessionHandle, unsigned int uiISKIndex, unsigned int uiKeyBits,
    unsigned char *pucResponseID, unsigned int uiResponseIDLength,
    unsigned char *pucSponsorID, unsigned int uiSponsorIDLength,
    OSSL_ECCrefPublicKey *pucSponsorPublicKey,
    OSSL_ECCrefPublicKey *pucSponsorTmpPublicKey,
    OSSL_ECCrefPublicKey *pucResponsePublicKey,
    OSSL_ECCrefPublicKey *pucResponseTmpPublicKey,
    unsigned char *pucSharedSecret, unsigned int *puiSecretLength,
    void **phKeyHandle);

typedef int (*_CP_SDFE_LoadModule)(const char *password);

typedef struct _SD_FUNCTION_LIST {
    _CP_SDF_OpenDevice OpenDevice;
    _CP_SDF_CloseDevice CloseDevice;
    _CP_SDF_OpenSession OpenSession;
    _CP_SDF_CloseSession CloseSession;
    _CP_SDF_GenerateRandom GenerateRandom;
    _CP_SDF_GetPrivateKeyAccessRight GetPrivateKeyAccessRight;
    _CP_SDF_ReleasePrivateKeyAccessRight ReleasePrivateKeyAccessRight;
    _CP_SDF_ImportKeyWithISK_ECC ImportKeyWithISK_ECC;
    _CP_SDF_ImportKeyWithKEK ImportKeyWithKEK;
    _CP_SDF_ExportSignPublicKey_ECC ExportSignPublicKey_ECC;
    _CP_SDF_ExportEncPublicKey_ECC ExportEncPublicKey_ECC;
    _CP_SDF_ExportSignPublicKey_RSA ExportSignPublicKey_RSA;
    _CP_SDF_ExportSignPublicKey_RSAEx ExportSignPublicKey_RSAEx;
    _CP_SDF_ExportEncPublicKey_RSA ExportEncPublicKey_RSA;
    _CP_SDF_ExportEncPublicKey_RSAEx ExportEncPublicKey_RSAEx;
    _CP_SDF_DestroyKey DestroyKey;
    _CP_SDF_ExternalPublicKeyOperation_RSA ExternalPublicKeyOperation_RSA;
    _CP_SDF_ExternalPublicKeyOperation_RSAEx ExternalPublicKeyOperation_RSAEx;
    _CP_SDF_InternalPublicKeyOperation_RSA InternalPublicKeyOperation_RSA;
    _CP_SDF_ExternalPrivateKeyOperation_RSA ExternalPrivateKeyOperation_RSA;
    _CP_SDF_ExternalPrivateKeyOperation_RSAEx ExternalPrivateKeyOperation_RSAEx;
    _CP_SDF_InternalPrivateKeyOperation_RSA InternalPrivateKeyOperation_RSA;
    _CP_SDF_InternalPublicKeyOperation_RSA_Ex InternalPublicKeyOperation_RSA_Ex;
    _CP_SDF_InternalPrivateKeyOperation_RSA_Ex InternalPrivateKeyOperation_RSA_Ex;
    _CP_SDF_InternalEncrypt_ECC InternalEncrypt_ECC;
    _CP_SDF_InternalDecrypt_ECC InternalDecrypt_ECC;
    _CP_SDF_InternalSign_ECC InternalSign_ECC;
    _CP_SDF_Encrypt Encrypt;
    _CP_SDF_Decrypt Decrypt;
    _CP_SDF_CalculateMAC CalculateMAC;
    _CP_SDF_GenerateAgreementDataWithECCEx GenerateAgreementDataWithECCEx;
    _CP_SDF_GenerateKeyWithECCEx GenerateKeyWithECCEx;
    _CP_SDF_GenerateAgreementDataAndKeyWithECCEx GenerateAgreementDataAndKeyWithECCEx;
    _CP_SDFE_LoadModule LoadModule;
} SD_FUNCTION_LIST;

struct sdf_method_st {
    SDF_OpenDevice_fn OpenDevice;
    SDF_CloseDevice_fn CloseDevice;
    SDF_OpenSession_fn OpenSession;
    SDF_CloseSession_fn CloseSession;
    SDF_GenerateRandom_fn GenerateRandom;
    SDF_GetPrivateKeyAccessRight_fn GetPrivateKeyAccessRight;
    SDF_ReleasePrivateKeyAccessRight_fn ReleasePrivateKeyAccessRight;
    SDF_ImportKeyWithISK_ECC_fn ImportKeyWithISK_ECC;
    SDF_ImportKeyWithKEK_fn ImportKeyWithKEK;
    SDF_ExportSignPublicKey_ECC_fn ExportSignPublicKey_ECC;
    SDF_ExportEncPublicKey_ECC_fn ExportEncPublicKey_ECC;
    SDF_ExportSignPublicKey_RSA_fn ExportSignPublicKey_RSA;
    SDF_ExportSignPublicKey_RSAEx_fn ExportSignPublicKey_RSAEx;
    SDF_ExportEncPublicKey_RSA_fn ExportEncPublicKey_RSA;
    SDF_ExportEncPublicKey_RSAEx_fn ExportEncPublicKey_RSAEx;
    SDF_DestroyKey_fn DestroyKey;
    SDF_ExternalPublicKeyOperation_RSA_fn ExternalPublicKeyOperation_RSA;
    SDF_ExternalPublicKeyOperation_RSAEx_fn ExternalPublicKeyOperation_RSAEx;
    SDF_InternalPublicKeyOperation_RSA_fn InternalPublicKeyOperation_RSA;
    SDF_ExternalPrivateKeyOperation_RSA_fn ExternalPrivateKeyOperation_RSA;
    SDF_ExternalPrivateKeyOperation_RSAEx_fn ExternalPrivateKeyOperation_RSAEx;
    SDF_InternalPrivateKeyOperation_RSA_fn InternalPrivateKeyOperation_RSA;
    SDF_InternalPublicKeyOperation_RSA_Ex_fn InternalPublicKeyOperation_RSA_Ex;
    SDF_InternalPrivateKeyOperation_RSA_Ex_fn InternalPrivateKeyOperation_RSA_Ex;
    SDF_InternalEncrypt_ECC_fn InternalEncrypt_ECC;
    SDF_InternalDecrypt_ECC_fn InternalDecrypt_ECC;
    SDF_InternalSign_ECC_fn InternalSign_ECC;
    SDF_Encrypt_fn Encrypt;
    SDF_Decrypt_fn Decrypt;
    SDF_CalculateMAC_fn CalculateMAC;

    /* SDF Ext API */
    SDF_GenerateKey_fn GenerateKey;

    /* SDF Key Agreement API */
    SDF_GenerateAgreementDataWithECCEx_fn GenerateAgreementDataWithECCEx;
    SDF_GenerateKeyWithECCEx_fn GenerateKeyWithECCEx;
    SDF_GenerateAgreementDataAndKeyWithECCEx_fn GenerateAgreementDataAndKeyWithECCEx;

    /* Vendor-specific API */
    SDFE_LoadModule_fn LoadModule;
    SDFE_UninstallModule_fn UninstallModule;
};

extern SDF_METHOD ts_sdf_meth;
#endif
