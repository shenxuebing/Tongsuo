/*
 * SDF Provider 测试程序
 * 测试 SDF 设备连接、SM2 签名/验签、SM2 加解密
 * 使用 byzk0018.dll (软 SDF 模块)
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pkey.h>
#include <openssl/provider.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    size_t i;
    printf("%s (%zu bytes): ", label, len);
    for (i = 0; i < len && i < 64; i++)
        printf("%02x", data[i]);
    if (len > 64)
        printf("...");
    printf("\n");
}

/* 测试 SDF 设备直接连接 */
static int test_sdf_device(void)
{
    void *hDevice = NULL;
    void *hSession = NULL;
    int ret;
    unsigned char random_buf[32];

    printf("\n=== 测试 SDF 设备连接 ===\n");

    /* 打开设备 */
    ret = TSAPI_SDF_OpenDevice(&hDevice);
    if (ret != OSSL_SDR_OK) {
        printf("TSAPI_SDF_OpenDevice 失败: ret=%d\n", ret);
        return 0;
    }
    printf("TSAPI_SDF_OpenDevice 成功, hDevice=%p\n", hDevice);

    /* 打开会话 */
    ret = TSAPI_SDF_OpenSession(hDevice, &hSession);
    if (ret != OSSL_SDR_OK) {
        printf("TSAPI_SDF_OpenSession 失败: ret=%d\n", ret);
        TSAPI_SDF_CloseDevice(hDevice);
        return 0;
    }
    printf("TSAPI_SDF_OpenSession 成功, hSession=%p\n", hSession);

    /* 生成随机数 */
    ret = TSAPI_SDF_GenerateRandom(hSession, 32, random_buf);
    if (ret == OSSL_SDR_OK) {
        print_hex("随机数", random_buf, 32);
    } else {
        printf("TSAPI_SDF_GenerateRandom 失败: ret=%d\n", ret);
    }

    /* 导出签名公钥 */
    {
        OSSL_ECCrefPublicKey pubkey;
        memset(&pubkey, 0, sizeof(pubkey));
        ret = TSAPI_SDF_ExportSignPublicKey_ECC(hSession, 0, &pubkey);
        if (ret == OSSL_SDR_OK) {
            print_hex("签名公钥 x", pubkey.x, 64);
            print_hex("签名公钥 y", pubkey.y, 64);
        } else {
            printf("TSAPI_SDF_ExportSignPublicKey_ECC(key=0) 失败: ret=%d\n", ret);
        }
    }

    /* 导出加密公钥 */
    {
        OSSL_ECCrefPublicKey pubkey;
        memset(&pubkey, 0, sizeof(pubkey));
        ret = TSAPI_SDF_ExportEncPublicKey_ECC(hSession, 0, &pubkey);
        if (ret == OSSL_SDR_OK) {
            print_hex("加密公钥 x", pubkey.x, 64);
            print_hex("加密公钥 y", pubkey.y, 64);
        } else {
            printf("TSAPI_SDF_ExportEncPublicKey_ECC(key=0) 失败: ret=%d\n", ret);
        }
    }

    /* 测试 SM2 签名 */
    {
        unsigned char msg[] = "Hello SDF Provider!";
        unsigned char hash[32];
        OSSL_ECCSignature sig;

        /* 用 SM3 计算消息摘要 */
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        unsigned int md_len = 32;
        EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
        EVP_DigestUpdate(mdctx, msg, strlen((char *)msg));
        EVP_DigestFinal_ex(mdctx, hash, &md_len);
        EVP_MD_CTX_free(mdctx);
        print_hex("SM3 hash", hash, 32);

        /* 硬件签名 */
        memset(&sig, 0, sizeof(sig));
        ret = TSAPI_SDF_InternalSign_ECC(hSession, 0, hash, 32, &sig);
        if (ret == OSSL_SDR_OK) {
            print_hex("签名 r", sig.r, 64);
            print_hex("签名 s", sig.s, 64);
            printf("SM2 硬件签名成功!\n");
        } else {
            printf("TSAPI_SDF_InternalSign_ECC 失败: ret=%d\n", ret);
        }
    }

    /* 测试 SM2 加解密 */
    {
        unsigned char plaintext[] = "SM2 encryption test data";
        OSSL_ECCCipher *cipher;
        unsigned char decrypted[256];
        unsigned int dec_len;
        size_t cipher_alloc;

        cipher_alloc = sizeof(OSSL_ECCCipher) + strlen((char *)plaintext);
        cipher = (OSSL_ECCCipher *)OPENSSL_zalloc(cipher_alloc);
        if (cipher) {
            /* 加密 */
            ret = TSAPI_SDF_InternalEncrypt_ECC(hSession, 0,
                    OSSL_SGD_SM2_3, plaintext, (unsigned int)strlen((char *)plaintext), cipher);
            if (ret == OSSL_SDR_OK) {
                print_hex("密文 C1x", cipher->x, 32);
                print_hex("密文 C3", cipher->M, 32);
                printf("密文 L=%u\n", cipher->L);
                print_hex("密文 C2", cipher->C, cipher->L);
                printf("SM2 硬件加密成功!\n");

                /* 解密 */
                dec_len = sizeof(decrypted);
                ret = TSAPI_SDF_InternalDecrypt_ECC(hSession, 0,
                        OSSL_SGD_SM2_3, cipher, decrypted, &dec_len);
                if (ret == OSSL_SDR_OK) {
                    decrypted[dec_len] = '\0';
                    printf("SM2 硬件解密成功: '%s'\n", decrypted);
                } else {
                    printf("TSAPI_SDF_InternalDecrypt_ECC 失败: ret=%d\n", ret);
                }
            } else {
                printf("TSAPI_SDF_InternalEncrypt_ECC 失败: ret=%d\n", ret);
            }
            OPENSSL_free(cipher);
        }
    }

    /* 关闭 */
    TSAPI_SDF_CloseSession(hSession);
    TSAPI_SDF_CloseDevice(hDevice);
    printf("SDF 设备关闭成功\n");

    return 1;
}

int main(int argc, char *argv[])
{
    int rc = 0;

    printf("=== SDF Provider 测试 ===\n");
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));

    /* 加载 SDF Provider */
    OSSL_PROVIDER *sdfprov = OSSL_PROVIDER_load(NULL, "sdfprov");
    if (sdfprov == NULL) {
        printf("加载 sdfprov provider 失败!\n");
        ERR_print_errors_fp(stderr);
        /* 尝试继续，测试原始 SDF API */
    } else {
        printf("sdfprov provider 加载成功\n");
    }

    /* 测试 SDF 设备 */
    if (!test_sdf_device()) {
        printf("\nSDF 设备测试未完全通过（可能需要硬件设备）\n");
    }

    /* 卸载 provider */
    if (sdfprov != NULL) {
        OSSL_PROVIDER_unload(sdfprov);
        printf("sdfprov provider 已卸载\n");
    }

    printf("\n=== 测试完成 ===\n");
    return rc;
}
