/*
 * Test both ECC-SM2-SM4-CBC-SM3 and ECDHE-SM2-SM4-CBC-SM3 cipher suites
 * with soft/hard cross-auth combinations on client/server.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/pem.h>

typedef enum {
    KEY_MODE_SOFT = 0,
    KEY_MODE_HARD = 1
} KEY_MODE;

typedef struct {
    const char *name;
    KEY_MODE server_mode;
    KEY_MODE client_mode;
} TEST_SCENARIO;

static const char *mode_name(KEY_MODE mode)
{
    return mode == KEY_MODE_HARD ? "HARD" : "SOFT";
}

static EVP_PKEY *load_sdf_key(const char *uri)
{
    OSSL_STORE_CTX *sctx;
    OSSL_STORE_INFO *info;
    EVP_PKEY *pkey = NULL;

    sctx = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (!sctx) return NULL;
    OSSL_STORE_expect(sctx, OSSL_STORE_INFO_PKEY);
    info = OSSL_STORE_load(sctx);
    if (info) {
        pkey = OSSL_STORE_INFO_get1_PKEY(info);
        OSSL_STORE_INFO_free(info);
    }
    OSSL_STORE_close(sctx);
    return pkey;
}

static EVP_PKEY *load_pem_key(const char *file)
{
    FILE *f = fopen(file, "r");
    EVP_PKEY *pkey = NULL;
    if (f) {
        pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
        fclose(f);
    }
    return pkey;
}

static X509 *load_cert(const char *file)
{
    FILE *f = fopen(file, "r");
    X509 *cert = NULL;
    if (f) {
        cert = PEM_read_X509(f, NULL, NULL, NULL);
        fclose(f);
    }
    return cert;
}

static int load_endpoint_material(KEY_MODE mode, int is_server,
                                  const char *cert_dir,
                                  EVP_PKEY **sign_key, EVP_PKEY **enc_key,
                                  X509 **sign_cert, X509 **enc_cert)
{
    char path[512];

    if (mode == KEY_MODE_HARD) {
        *sign_key = load_sdf_key("sdf:key=0;type=sign");
        *enc_key = load_sdf_key("sdf:key=0;type=enc");
        if (*sign_key == NULL || *enc_key == NULL)
            return 0;

        snprintf(path, sizeof(path), "%s\\server_sign.crt", cert_dir);
        *sign_cert = load_cert(path);
        snprintf(path, sizeof(path), "%s\\server_enc.crt", cert_dir);
        *enc_cert = load_cert(path);
        return *sign_cert != NULL && *enc_cert != NULL;
    }

    snprintf(path, sizeof(path), "%s\\%s_sign.key", cert_dir,
             is_server ? "server" : "client");
    *sign_key = load_pem_key(path);
    snprintf(path, sizeof(path), "%s\\%s_enc.key", cert_dir,
             is_server ? "server" : "client");
    *enc_key = load_pem_key(path);
    if (*sign_key == NULL || *enc_key == NULL)
        return 0;

    snprintf(path, sizeof(path), "%s\\%s_sign.crt", cert_dir,
             is_server ? "server" : "client");
    *sign_cert = load_cert(path);
    snprintf(path, sizeof(path), "%s\\%s_enc.crt", cert_dir,
             is_server ? "server" : "client");
    *enc_cert = load_cert(path);

    return *sign_cert != NULL && *enc_cert != NULL;
}

static int test_cipher_suite(const char *cipher_name,
                             KEY_MODE server_mode, KEY_MODE client_mode)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *ssl_s = NULL, *ssl_c = NULL;
    EVP_PKEY *srv_sign_key = NULL, *srv_enc_key = NULL;
    EVP_PKEY *cli_sign_key = NULL, *cli_enc_key = NULL;
    X509 *srv_sign_cert = NULL, *srv_enc_cert = NULL;
    X509 *cli_sign_cert = NULL, *cli_enc_cert = NULL;
    BIO *s_to_c = NULL, *c_to_s = NULL;
    int ret = 1;
    const char *cert_dir = "E:\\vs2022workspace\\SoftCryptoModule\\softModule\\out\\build\\x86-Debug\\certs\\sm2certs";

    printf("\n========================================\n");
    printf("Testing: %s\n", cipher_name);
    printf("Mode: server=%s client=%s\n",
           mode_name(server_mode), mode_name(client_mode));
    printf("========================================\n");

    if (!load_endpoint_material(server_mode, 1, cert_dir,
                                &srv_sign_key, &srv_enc_key,
                                &srv_sign_cert, &srv_enc_cert)) {
        printf("FAIL: load server materials (mode=%s)\n", mode_name(server_mode));
        goto done;
    }

    if (!load_endpoint_material(client_mode, 0, cert_dir,
                                &cli_sign_key, &cli_enc_key,
                                &cli_sign_cert, &cli_enc_cert)) {
        printf("FAIL: load client materials (mode=%s)\n", mode_name(client_mode));
        goto done;
    }

    /* Server SSL_CTX */
    sctx = SSL_CTX_new(NTLS_server_method());
    if (!sctx) goto done;
    SSL_CTX_enable_ntls(sctx);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(sctx, cipher_name);
    SSL_CTX_use_sign_PrivateKey(sctx, srv_sign_key);
    SSL_CTX_use_sign_certificate(sctx, srv_sign_cert);
    SSL_CTX_use_enc_PrivateKey(sctx, srv_enc_key);
    SSL_CTX_use_enc_certificate(sctx, srv_enc_cert);

    /* Client SSL_CTX */
    cctx = SSL_CTX_new(NTLS_client_method());
    if (!cctx) goto done;
    SSL_CTX_enable_ntls(cctx);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(cctx, cipher_name);
    SSL_CTX_use_sign_PrivateKey(cctx, cli_sign_key);
    SSL_CTX_use_sign_certificate(cctx, cli_sign_cert);
    SSL_CTX_use_enc_PrivateKey(cctx, cli_enc_key);
    SSL_CTX_use_enc_certificate(cctx, cli_enc_cert);

    /* Create SSL objects */
    ssl_s = SSL_new(sctx);
    ssl_c = SSL_new(cctx);
    if (!ssl_s || !ssl_c) goto done;

    /* BIO pair */
    if (!BIO_new_bio_pair(&s_to_c, 0, &c_to_s, 0)) goto done;
    SSL_set_bio(ssl_s, s_to_c, s_to_c);
    SSL_set_bio(ssl_c, c_to_s, c_to_s);
    s_to_c = NULL; c_to_s = NULL;

    SSL_set_connect_state(ssl_c);
    SSL_set_accept_state(ssl_s);

    /* Handshake */
    for (int i = 0; i < 30; i++) {
        int sr = SSL_do_handshake(ssl_s);
        int se = SSL_get_error(ssl_s, sr);
        int cr = SSL_do_handshake(ssl_c);
        int ce = SSL_get_error(ssl_c, cr);

        if (sr == 1 && cr == 1) {
            printf("[PASS] Handshake succeeded!\n");
            printf("  Cipher: %s\n", SSL_get_cipher_name(ssl_s));
            ret = 0;
            goto done;
        }

        if ((se != SSL_ERROR_WANT_READ && se != SSL_ERROR_WANT_WRITE && sr < 0)
            || (ce != SSL_ERROR_WANT_READ && ce != SSL_ERROR_WANT_WRITE && cr < 0)) {
            printf("[FAIL] Handshake failed at iteration %d\n", i);
            printf("  Server: ret=%d err=%d\n", sr, se);
            printf("  Client: ret=%d err=%d\n", cr, ce);
            ERR_print_errors_fp(stdout);
            break;
        }
    }

done:
    SSL_free(ssl_s);
    SSL_free(ssl_c);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    EVP_PKEY_free(srv_sign_key);
    EVP_PKEY_free(srv_enc_key);
    EVP_PKEY_free(cli_sign_key);
    EVP_PKEY_free(cli_enc_key);
    X509_free(srv_sign_cert);
    X509_free(srv_enc_cert);
    X509_free(cli_sign_cert);
    X509_free(cli_enc_cert);
    BIO_free(s_to_c);
    BIO_free(c_to_s);
    return ret;
}

int main(void)
{
    static const TEST_SCENARIO scenarios[] = {
        { "server-hard/client-soft", KEY_MODE_HARD, KEY_MODE_SOFT },
        { "server-soft/client-hard", KEY_MODE_SOFT, KEY_MODE_HARD },
        { "server-hard/client-hard", KEY_MODE_HARD, KEY_MODE_HARD },
        { "server-soft/client-soft", KEY_MODE_SOFT, KEY_MODE_SOFT }
    };
    static const char *ciphers[] = {
        "ECC-SM2-SM4-CBC-SM3",
        "ECDHE-SM2-SM4-CBC-SM3"
    };
    int i, j;
    int failed = 0;

    printf("=== NTLS Cross Auth Matrix Tests ===\n");
    printf("Modes: HARD=SDF provider key, SOFT=PEM key\n");

    OSSL_PROVIDER_load(NULL, "sdfprov");
    OSSL_PROVIDER_load(NULL, "default");

    for (i = 0; i < (int)(sizeof(scenarios) / sizeof(scenarios[0])); i++) {
        printf("\n######## Scenario: %s ########\n", scenarios[i].name);
        for (j = 0; j < (int)(sizeof(ciphers) / sizeof(ciphers[0])); j++) {
            int ret = test_cipher_suite(ciphers[j],
                                        scenarios[i].server_mode,
                                        scenarios[i].client_mode);
            if (ret != 0)
                failed++;
        }
    }

    printf("\n========================================\n");
    printf("SUMMARY: %d/%d cases passed\n",
           (int)(sizeof(scenarios) / sizeof(scenarios[0])
                 * sizeof(ciphers) / sizeof(ciphers[0])) - failed,
           (int)(sizeof(scenarios) / sizeof(scenarios[0])
                 * sizeof(ciphers) / sizeof(ciphers[0])));
    printf("========================================\n");

    return failed == 0 ? 0 : 1;
}
