/*
 * Test NTLS handshake with SDF Provider hardware keys
 * In-process loopback test using two SSL contexts
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/store.h>
#include <openssl/provider.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/sdf.h>
#include <openssl/sgd.h>

/* 加载 SDF 硬件密钥 */
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

/* 加载 PEM 证书 */
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

int main(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *ssl_s = NULL, *ssl_c = NULL;
    EVP_PKEY *srv_sign_key = NULL, *srv_enc_key = NULL;
    EVP_PKEY *cli_sign_key = NULL, *cli_enc_key = NULL;
    X509 *srv_sign_cert = NULL, *srv_enc_cert = NULL;
    X509 *cli_sign_cert = NULL, *cli_enc_cert = NULL;
    int ret = 1;
    BIO *s_to_c = NULL, *c_to_s = NULL; /* memory BIOs for loopback */
    int r;

    printf("=== NTLS + SDF Provider test ===\n"); fflush(stdout);

    OSSL_PROVIDER_load(NULL, "sdfprov");
    OSSL_PROVIDER_load(NULL, "default");

    /* Load SDF hardware keys */
    srv_sign_key = load_sdf_key("sdf:key=0;type=sign");
    srv_enc_key = load_sdf_key("sdf:key=0;type=enc");
    cli_sign_key = load_sdf_key("sdf:key=0;type=sign");
    cli_enc_key = load_sdf_key("sdf:key=0;type=enc");

    if (!srv_sign_key || !srv_enc_key || !cli_sign_key || !cli_enc_key) {
        printf("FAIL: load SDF keys\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    printf("All SDF keys loaded OK\n"); fflush(stdout);

    /* Load certs */
    srv_sign_cert = load_cert("../test/certs/sm2/server_sign.crt");
    srv_enc_cert = load_cert("../test/certs/sm2/server_enc.crt");
    cli_sign_cert = load_cert("../test/certs/sm2/client_sign.crt");
    cli_enc_cert = load_cert("../test/certs/sm2/client_enc.crt");

    if (!srv_sign_cert || !srv_enc_cert || !cli_sign_cert || !cli_enc_cert) {
        printf("FAIL: load certs\n");
        goto done;
    }
    printf("All certs loaded OK\n"); fflush(stdout);

    /* Create server SSL_CTX */
    sctx = SSL_CTX_new(NTLS_server_method());
    if (!sctx) { printf("FAIL: server ctx\n"); goto done; }
    SSL_CTX_enable_ntls(sctx);
    SSL_CTX_set_verify(sctx, SSL_VERIFY_NONE, NULL);
    /* 使用 ECDHE-SM2 密码套件（基于密钥协商，不需要 SM2 加解密） */
    SSL_CTX_set_cipher_list(sctx, "ECDHE-SM2-SM4-CBC-SM3");

    /* Set server sign cert+key */
    if (!SSL_CTX_use_sign_PrivateKey(sctx, srv_sign_key)) {
        printf("FAIL: server sign key\n"); ERR_print_errors_fp(stderr); goto done;
    }
    if (!SSL_CTX_use_sign_certificate(sctx, srv_sign_cert)) {
        printf("FAIL: server sign cert\n"); ERR_print_errors_fp(stderr); goto done;
    }

    /* Set server enc cert+key */
    if (!SSL_CTX_use_enc_PrivateKey(sctx, srv_enc_key)) {
        printf("FAIL: server enc key\n"); ERR_print_errors_fp(stderr); goto done;
    }
    if (!SSL_CTX_use_enc_certificate(sctx, srv_enc_cert)) {
        printf("FAIL: server enc cert\n"); ERR_print_errors_fp(stderr); goto done;
    }

    printf("Server SSL_CTX configured\n"); fflush(stdout);

    /* Create client SSL_CTX */
    cctx = SSL_CTX_new(NTLS_client_method());
    if (!cctx) { printf("FAIL: client ctx\n"); goto done; }
    SSL_CTX_enable_ntls(cctx);
    SSL_CTX_set_verify(cctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_cipher_list(cctx, "ECDHE-SM2-SM4-CBC-SM3");

    /* Set client sign cert+key */
    if (!SSL_CTX_use_sign_PrivateKey(cctx, cli_sign_key)) {
        printf("FAIL: client sign key\n"); ERR_print_errors_fp(stderr); goto done;
    }
    if (!SSL_CTX_use_sign_certificate(cctx, cli_sign_cert)) {
        printf("FAIL: client sign cert\n"); ERR_print_errors_fp(stderr); goto done;
    }

    /* Set client enc cert+key */
    if (!SSL_CTX_use_enc_PrivateKey(cctx, cli_enc_key)) {
        printf("FAIL: client enc key\n"); ERR_print_errors_fp(stderr); goto done;
    }
    if (!SSL_CTX_use_enc_certificate(cctx, cli_enc_cert)) {
        printf("FAIL: client enc cert\n"); ERR_print_errors_fp(stderr); goto done;
    }

    printf("Client SSL_CTX configured\n"); fflush(stdout);

    /* Create SSL objects */
    ssl_s = SSL_new(sctx);
    ssl_c = SSL_new(cctx);
    if (!ssl_s || !ssl_c) { printf("FAIL: SSL_new\n"); goto done; }

    /* Create loopback BIO pair */
    if (!BIO_new_bio_pair(&s_to_c, 0, &c_to_s, 0)) {
        printf("FAIL: BIO pair\n"); goto done;
    }

    SSL_set_bio(ssl_s, s_to_c, s_to_c);
    SSL_set_bio(ssl_c, c_to_s, c_to_s);
    s_to_c = NULL; c_to_s = NULL; /* owned by SSL now */

    SSL_set_connect_state(ssl_c);
    SSL_set_accept_state(ssl_s);

    /* Set certificates first, then keys (order matters for NTLS) */
    SSL_use_sign_certificate(ssl_s, srv_sign_cert);
    SSL_use_enc_certificate(ssl_s, srv_enc_cert);
    SSL_use_sign_certificate(ssl_c, cli_sign_cert);
    SSL_use_enc_certificate(ssl_c, cli_enc_cert);

    SSL_use_sign_PrivateKey(ssl_s, srv_sign_key);
    SSL_use_enc_PrivateKey(ssl_s, srv_enc_key);
    SSL_use_sign_PrivateKey(ssl_c, cli_sign_key);
    SSL_use_enc_PrivateKey(ssl_c, cli_enc_key);

    printf("Starting handshake...\n"); fflush(stdout);

    /* Handshake loop */
    for (int i = 0; i < 20; i++) {
        fprintf(stderr, "  [DBG] iter %d: before server handshake\n", i);
        ERR_clear_error();
        int sr = SSL_do_handshake(ssl_s);
        int se = SSL_get_error(ssl_s, sr);

        /* Capture server errors immediately */
        unsigned long server_err = ERR_peek_error();
        char server_err_buf[256] = {0};
        if (server_err)
            ERR_error_string_n(server_err, server_err_buf, sizeof(server_err_buf));

        fprintf(stderr, "  [DBG] iter %d: before client handshake\n", i);
        ERR_clear_error();
        int cr = SSL_do_handshake(ssl_c);
        int ce = SSL_get_error(ssl_c, cr);

        /* Capture client errors */
        unsigned long client_err = ERR_peek_error();
        char client_err_buf[256] = {0};
        if (client_err)
            ERR_error_string_n(client_err, client_err_buf, sizeof(client_err_buf));

        printf("  [%d] server=%d(err=%d%s%s) client=%d(err=%d%s%s)\n",
               i, sr, se,
               server_err_buf[0] ? " " : "", server_err_buf[0] ? server_err_buf : "",
               cr, ce,
               client_err_buf[0] ? " " : "", client_err_buf[0] ? client_err_buf : "");
        fflush(stdout);

        if (sr == 1 && cr == 1) {
            printf("HANDSHAKE SUCCESS!\n"); fflush(stdout);

            /* Test data transfer */
            const char *msg = "Hello from client!";
            unsigned char buf[256];
            int n;

            n = SSL_write(ssl_c, msg, (int)strlen(msg));
            printf("Client write: %d\n", n); fflush(stdout);

            if (n > 0) {
                /* Transfer data through BIO pair */
                BIO *wb = SSL_get_wbio(ssl_c);
                BIO *rb = SSL_get_rbio(ssl_s);
                /* Data should already be in the BIO pair */
                n = SSL_read(ssl_s, buf, sizeof(buf) - 1);
                if (n > 0) {
                    buf[n] = 0;
                    printf("Server read: '%s'\n", buf);
                } else {
                    printf("Server read failed: %d\n", n);
                }
            }

            ret = 0;
            goto done;
        }

        if ((se != SSL_ERROR_WANT_READ && se != SSL_ERROR_WANT_WRITE && sr < 0)
            || (ce != SSL_ERROR_WANT_READ && ce != SSL_ERROR_WANT_WRITE && cr < 0)) {
            printf("ERRORS:\n");
            if (sr < 0 && se != SSL_ERROR_WANT_READ && se != SSL_ERROR_WANT_WRITE) {
                printf("--- Server errors ---\n");
                ERR_print_errors_fp(stdout);
            }
            if (cr < 0 && ce != SSL_ERROR_WANT_READ && ce != SSL_ERROR_WANT_WRITE) {
                printf("--- Client errors ---\n");
                ERR_print_errors_fp(stdout);
            }
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

    printf("DONE (ret=%d)\n", ret); fflush(stdout);
    return ret;
}
