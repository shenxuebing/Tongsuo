/*
 * Test SDF InternalEncrypt/Decrypt_ECC roundtrip
 */
#include <stdio.h>
#include <string.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>
#include <openssl/tsapi.h>
#include <openssl/err.h>
#include "crypto/sdf/sdf_local.h"

int main(void)
{
    void *hDevice = NULL, *hSession = NULL;
    int ret;
    unsigned char plaintext[] = "Hello SM2 Encryption!";
    const char *pwd = "88888888";

    printf("=== SDF Encrypt/Decrypt Roundtrip Test ===\n"); fflush(stdout);

    /* 先加载 SDF 模块 - 通过 Provider 使用的相同方式 */
    /* SDF_LIB 通过 RUN_ONCE 自动加载 byzk0018.dll */

    /* 打开设备 */
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    printf("OpenDevice: ret=0x%08X %s\n", ret, ret == 0 ? "OK" : "FAIL");
    if (ret != 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    /* 打开会话 */
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    printf("OpenSession: ret=0x%08X hSession=%p\n", ret, hSession);
    if (ret != 0) { TSAPI_SDF_CloseDevice(hDevice); return 1; }

    /* Test 1: SDF InternalEncrypt + InternalDecrypt roundtrip */
    printf("\n--- Test 1: SDF InternalEncrypt + InternalDecrypt ---\n"); fflush(stdout);
    {
        size_t cipher_alloc = offsetof(OSSL_ECCCipher, C) + 256;
        OSSL_ECCCipher *cipher = (OSSL_ECCCipher *)OPENSSL_zalloc(cipher_alloc);
        unsigned char dec_out[256];
        unsigned int dec_len;

        ret = TSAPI_SDF_InternalEncrypt_ECC(hSession, 0,
                                             OSSL_SGD_SM2_3,
                                             plaintext, (unsigned int)strlen((char *)plaintext),
                                             cipher);
        printf("InternalEncrypt_ECC(0): ret=0x%08X %s L=%u\n",
               ret, ret == 0 ? "OK" : "FAIL", cipher->L);

        if (ret == 0) {
            dec_len = sizeof(dec_out);
            ret = TSAPI_SDF_InternalDecrypt_ECC(hSession, 0, OSSL_SGD_SM2_3, cipher, dec_out, &dec_len);
            printf("InternalDecrypt_ECC(0): ret=0x%08X %s dec_len=%u\n",
                   ret, ret == 0 ? "OK" : "FAIL", dec_len);
            if (ret == 0) {
                dec_out[dec_len] = 0;
                printf("Decrypted: '%s' MATCH=%s\n", dec_out,
                       strcmp((char *)dec_out, (char *)plaintext) == 0 ? "YES" : "NO");
            }
        }

        OPENSSL_free(cipher);
    }

    /* Test 2: TSAPI high-level SM2Encrypt + SM2Decrypt */
    printf("\n--- Test 2: TSAPI SM2EncryptWithISK + SM2DecryptWithISK ---\n"); fflush(stdout);
    {
        size_t enc_len = 0, dec_len = 0;
        unsigned char *enc = TSAPI_SM2EncryptWithISK(0, plaintext,
                                                       strlen((char *)plaintext), &enc_len);
        printf("SM2EncryptWithISK: %s enc_len=%zu\n", enc ? "OK" : "FAIL", enc_len);
        if (enc) {
            unsigned char *dec = TSAPI_SM2DecryptWithISK(0, enc, enc_len, &dec_len);
            printf("SM2DecryptWithISK: %s dec_len=%zu\n", dec ? "OK" : "FAIL", dec_len);
            if (dec) {
                dec[dec_len] = 0;
                printf("Decrypted: '%s' MATCH=%s\n", dec,
                       strcmp((char *)dec, (char *)plaintext) == 0 ? "YES" : "NO");
                OPENSSL_free(dec);
            }
            OPENSSL_free(enc);
        }
    }

    TSAPI_SDF_CloseSession(hSession);
    TSAPI_SDF_CloseDevice(hDevice);
    printf("\nDone.\n"); fflush(stdout);
    return 0;
}
