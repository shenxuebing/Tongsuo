#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/err.h>

static void print_errors(const char *tag)
{
    fprintf(stderr, "[%s] OpenSSL error stack:\n", tag);
    ERR_print_errors_fp(stderr);
}

static EVP_PKEY *load_pkey_from_store(const char *uri)
{
    OSSL_STORE_CTX *store = NULL;
    OSSL_STORE_INFO *info = NULL;
    EVP_PKEY *pkey = NULL;

    store = OSSL_STORE_open(uri, NULL, NULL, NULL, NULL);
    if (store == NULL) {
        print_errors("OSSL_STORE_open");
        return NULL;
    }

    if (!OSSL_STORE_expect(store, OSSL_STORE_INFO_PKEY)) {
        print_errors("OSSL_STORE_expect");
        goto end;
    }

    info = OSSL_STORE_load(store);
    if (info == NULL) {
        print_errors("OSSL_STORE_load");
        goto end;
    }

    pkey = OSSL_STORE_INFO_get1_PKEY(info);
    if (pkey == NULL)
        print_errors("OSSL_STORE_INFO_get1_PKEY");

end:
    OSSL_STORE_INFO_free(info);
    OSSL_STORE_close(store);
    return pkey;
}

static int do_sign_verify(EVP_PKEY *pkey, const char *digest_name,
                          const unsigned char *msg, size_t msg_len)
{
    EVP_MD_CTX *sign_ctx = NULL;
    EVP_MD_CTX *verify_ctx = NULL;
    EVP_MD *md = NULL;
    unsigned char sig[1024];
    size_t sig_len = sizeof(sig);
    int ok = 0;

    md = EVP_MD_fetch(NULL, digest_name, NULL);
    if (md == NULL) {
        print_errors("EVP_MD_fetch");
        goto end;
    }

    sign_ctx = EVP_MD_CTX_new();
    verify_ctx = EVP_MD_CTX_new();
    if (sign_ctx == NULL || verify_ctx == NULL) {
        print_errors("EVP_MD_CTX_new");
        goto end;
    }

    if (EVP_DigestSignInit(sign_ctx, NULL, md, NULL, pkey) != 1) {
        print_errors("EVP_DigestSignInit");
        goto end;
    }
    if (EVP_DigestSignUpdate(sign_ctx, msg, msg_len) != 1) {
        print_errors("EVP_DigestSignUpdate");
        goto end;
    }
    if (EVP_DigestSignFinal(sign_ctx, sig, &sig_len) != 1) {
        print_errors("EVP_DigestSignFinal");
        goto end;
    }

    printf("sign ok: digest=%s sig_len=%zu\n", digest_name, sig_len);

    if (EVP_DigestVerifyInit(verify_ctx, NULL, md, NULL, pkey) != 1) {
        print_errors("EVP_DigestVerifyInit");
        goto end;
    }
    if (EVP_DigestVerifyUpdate(verify_ctx, msg, msg_len) != 1) {
        print_errors("EVP_DigestVerifyUpdate");
        goto end;
    }
    if (EVP_DigestVerifyFinal(verify_ctx, sig, sig_len) != 1) {
        print_errors("EVP_DigestVerifyFinal");
        goto end;
    }

    printf("verify ok: digest=%s\n", digest_name);
    ok = 1;

end:
    EVP_MD_free(md);
    EVP_MD_CTX_free(sign_ctx);
    EVP_MD_CTX_free(verify_ctx);
    return ok;
}

static int do_encrypt_decrypt(EVP_PKEY *pkey, const unsigned char *msg,
                              size_t msg_len)
{
    EVP_PKEY_CTX *enc_ctx = NULL;
    EVP_PKEY_CTX *dec_ctx = NULL;
    unsigned char ciphertext[2048];
    unsigned char plaintext[2048];
    size_t ciphertext_len = sizeof(ciphertext);
    size_t plaintext_len = sizeof(plaintext);
    int ok = 0;

    enc_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    dec_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (enc_ctx == NULL || dec_ctx == NULL) {
        print_errors("EVP_PKEY_CTX_new_from_pkey");
        goto end;
    }

    if (EVP_PKEY_encrypt_init(enc_ctx) <= 0) {
        print_errors("EVP_PKEY_encrypt_init");
        goto end;
    }
    if (EVP_PKEY_encrypt(enc_ctx, ciphertext, &ciphertext_len, msg, msg_len) <= 0) {
        print_errors("EVP_PKEY_encrypt");
        goto end;
    }

    printf("encrypt ok: ciphertext_len=%zu\n", ciphertext_len);

    if (EVP_PKEY_decrypt_init(dec_ctx) <= 0) {
        print_errors("EVP_PKEY_decrypt_init");
        goto end;
    }
    if (EVP_PKEY_decrypt(dec_ctx, plaintext, &plaintext_len,
                         ciphertext, ciphertext_len) <= 0) {
        print_errors("EVP_PKEY_decrypt");
        goto end;
    }

    if (plaintext_len != msg_len || CRYPTO_memcmp(plaintext, msg, msg_len) != 0) {
        fprintf(stderr, "decrypt mismatch: plaintext_len=%zu expected=%zu\n",
                plaintext_len, msg_len);
        goto end;
    }

    printf("decrypt ok: plaintext_len=%zu\n", plaintext_len);
    ok = 1;

end:
    EVP_PKEY_CTX_free(enc_ctx);
    EVP_PKEY_CTX_free(dec_ctx);
    return ok;
}

int main(int argc, char **argv)
{
    OSSL_PROVIDER *sdfprov = NULL;
    OSSL_PROVIDER *defprov = NULL;
    EVP_PKEY *sign_pkey = NULL;
    EVP_PKEY *enc_pkey = NULL;
    const char *sign_uri;
    const char *enc_uri;
    const char *digest_name = "SHA256";
    const unsigned char msg[] = "sdfprov rsa self-test message";
    int ok = 1;

    if (argc < 3 || argc > 4) {
        fprintf(stderr,
                "usage: %s <sign_uri> <enc_uri> [digest]\n"
                "example:\n"
                "  %s \"sdf:key=1;type=sign;algo=rsa;pwd=12345678\" "
                "\"sdf:key=1;type=enc;algo=rsa;pwd=12345678;session=0x1234\"\n",
                argv[0], argv[0]);
        return 2;
    }

    sign_uri = argv[1];
    enc_uri = argv[2];
    if (argc == 4)
        digest_name = argv[3];

    sdfprov = OSSL_PROVIDER_load(NULL, "sdfprov");
    defprov = OSSL_PROVIDER_load(NULL, "default");
    if (sdfprov == NULL || defprov == NULL) {
        print_errors("OSSL_PROVIDER_load");
        ok = 0;
        goto end;
    }

    sign_pkey = load_pkey_from_store(sign_uri);
    if (sign_pkey == NULL) {
        fprintf(stderr, "failed to load sign key from uri: %s\n", sign_uri);
        ok = 0;
        goto end;
    }
    printf("loaded sign key: type=%s bits=%d\n",
           EVP_PKEY_get0_type_name(sign_pkey), EVP_PKEY_get_bits(sign_pkey));

    enc_pkey = load_pkey_from_store(enc_uri);
    if (enc_pkey == NULL) {
        fprintf(stderr, "failed to load enc key from uri: %s\n", enc_uri);
        ok = 0;
        goto end;
    }
    printf("loaded enc key: type=%s bits=%d\n",
           EVP_PKEY_get0_type_name(enc_pkey), EVP_PKEY_get_bits(enc_pkey));

    if (!do_sign_verify(sign_pkey, digest_name, msg, sizeof(msg) - 1))
        ok = 0;
    if (!do_encrypt_decrypt(enc_pkey, msg, sizeof(msg) - 1))
        ok = 0;

end:
    EVP_PKEY_free(sign_pkey);
    EVP_PKEY_free(enc_pkey);
    OSSL_PROVIDER_unload(defprov);
    OSSL_PROVIDER_unload(sdfprov);
    return ok ? 0 : 1;
}
