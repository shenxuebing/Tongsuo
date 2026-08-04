/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */
#include "internal/deprecated.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/sdf.h>
#include <openssl/bio.h>
#include <openssl/tsapi.h>
#include <openssl/ec.h>
#include <openssl/sgd.h>
#include "apps.h"
#include "progs.h"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_HELP,
    OPT_IN,
    OPT_INKEY,
    OPT_INDEX,
    OPT_GENSM2KEY,
    OPT_DELSM2KEY,
    OPT_UPDATESM2KEY,
    OPT_EXPORTSM2PUBKEY,
    OPT_EXPORTRSAPUBKEY,
    OPT_EXPORTSM2KEY,
    OPT_EXPORTSM2KEYWITHEVLP,
    OPT_IMPORTSM2KEY,
    OPT_IMPORTSM2KEYWITHEVLP,
    OPT_IMPORTRSAKEY,
    OPT_LOGIN,
    OPT_ENCRYPT,
    OPT_DECRYPT,
    OPT_PEERKEY,
    OPT_TYPE,
    OPT_OUT,
    OPT_KEYOUT,
    OPT_DEKOUT,
    OPT_INDEK,
    OPT_IV,
    OPT_ISK,
    OPT_ISKTYPE,
    OPT_ALGORITHM,
    OPT_PROV_ENUM,
    OPT_CONFIG,
} OPTION_CHOICE;

/*
 * Usage notes:
 *
 * Provider/config loading:
 *   openssl sdf -config apps/openssl.cnf ...
 *   or set OPENSSL_CONF to the config file before running openssl.
 *
 * The sdfprov section in openssl.cnf provides sdf_lib_path,
 * sdf_module_password and sdf_use_loadmodule.  Environment variables
 * SDF_LIB_PATH, SDF_MODULE_PASSWORD and SDF_USE_LOADMODULE are fallback
 * values only.
 *
 * SM2 key management:
 *   openssl sdf -gensm2key -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -delsm2key -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -updatesm2key -index N [-type sign|enc] [-login user:pass]
 *   openssl sdf -importsm2key -index N -type sign -inkey sm2_sign.key
 *   openssl sdf -importsm2key -index N -type enc  -inkey sm2_enc.key
 *   openssl sdf -exportsm2key -index N -type sign -keyout sm2_sign.key
 *   openssl sdf -exportsm2pubkey -index N -type enc -keyout sm2_enc.pub
 *
 * RSA key import:
 *   openssl sdf -importrsakey -index N -type sign -inkey rsa_sign.key
 *   openssl sdf -importrsakey -index N -type enc  -inkey rsa_enc.key
 *
 * SM2 key import/export with digital envelope:
 *   openssl sdf -importsm2keywithevlp -index N -type enc \
 *       -inkey sm2.keyenc -indek sm4.keyenc
 *   openssl sdf -exportsm2keywithevlp -index N -type sign \
 *       -peerkey peer.pem -keyout sm2.bin -dekout dek.bin
 *
 * Encryption/decryption:
 *   openssl sdf -encrypt -algorithm sm2 -index N -in data.txt -out data.enc
 *   openssl sdf -decrypt -algorithm sm2 -index N -in data.enc -out data.txt
 *   openssl sdf -encrypt -algorithm sm4-cbc -inkey sm4key.enc -isk N \
 *       -isktype sm2 -iv HEX -in data.txt -out data.enc
 *   openssl sdf -decrypt -algorithm sm4-cbc -inkey sm4key.enc -isk N \
 *       -isktype sm2 -iv HEX -in data.enc -out data.txt
 *
 * byzk0018/BYCSM SM2 import index note:
 *   BYCSM_ImportECCKeyPair receives the command index, but the vendor library
 *   stores sign/enc key pairs under a container index.  In local tests,
 *   importing sign index 81 and enc index 82 stored the pair under export
 *   index 40; 83/84 stored under 41; 85/86 stored under 42.
 *   Verify imported public keys with the container index used by the vendor
 *   library, for example:
 *     openssl sdf -exportsm2pubkey -index 40 -type sign -keyout sm2_sign.pub
 *     openssl sdf -exportsm2pubkey -index 40 -type enc  -keyout sm2_enc.pub
 */

const OPTIONS sdf_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},
    {"encrypt", OPT_ENCRYPT, '-', "Encrypt file"},
    {"decrypt", OPT_DECRYPT, '-', "Decrypt file"},
    {"importsm2key", OPT_IMPORTSM2KEY, '-', "Import SM2 key with the index"},
    {"importsm2keywithevlp", OPT_IMPORTSM2KEYWITHEVLP, '-', "Import SM2 key with digital envelope"},
    {"importrsakey", OPT_IMPORTRSAKEY, '-', "Import RSA key with the index (auto 1024-4096)"},
    {"gensm2key", OPT_GENSM2KEY, '-', "Generate SM2 key pair with the index"},
    {"delsm2key", OPT_DELSM2KEY, '-', "Delete SM2 key pair with the index"},
    {"updatesm2key", OPT_UPDATESM2KEY, '-', "Update SM2 key pair with the index"},
    {"exportsm2key", OPT_EXPORTSM2KEY, '-', "Export SM2 key with the index"},
    {"exportsm2pubkey", OPT_EXPORTSM2PUBKEY, '-', "Export SM2 public key with the index"},
    {"exportrsapubkey", OPT_EXPORTRSAPUBKEY, '-', "Export RSA public key with the index"},
    {"exportsm2keywithevlp", OPT_EXPORTSM2KEYWITHEVLP, '-', "Export SM2 key with digital envelope"},
    {"login", OPT_LOGIN, 's', "Login with username:password"},
    OPT_CONFIG_OPTION,
    OPT_PROV_OPTIONS,

    OPT_SECTION("Input"),
    {"inkey", OPT_INKEY, 's', "Input key file"},
    {"index", OPT_INDEX, 's', "Specify the index of key"},
    {"peerkey", OPT_PEERKEY, 's', "Peer public key file used in exporting SM2 key with digital envelope"},
    {"type", OPT_TYPE, 's', "sign: signature key, enc: encryption key"},
    {"indek", OPT_INDEK, '>', "Input digital envelope key"},
    {"isk", OPT_ISK, 's', "Index of ISK key"},
    {"isktype", OPT_ISKTYPE, 's', "ISK type, sm2: SM2 key, rsa: RSA key"},
    {"iv", OPT_IV, 's', "IV in hex format"},
    {"algorithm", OPT_ALGORITHM, 's', "Algorithm to use"},
    {"in", OPT_IN, '>', "Input file"},

    OPT_SECTION("Output"),
    {"out", OPT_OUT, '>', "Output file"},
    {"keyout", OPT_KEYOUT, '>', "Output key file"},
    {"dekout", OPT_DEKOUT, '>', "Output digital envelope key"},

    {NULL}
};

static void sdf_print_usage(void)
{
    BIO_printf(bio_err, "\nCommand usage examples:\n");
    BIO_printf(bio_err, "  Load provider config:\n");
    BIO_printf(bio_err, "    set OPENSSL_CONF=C:\\path\\to\\openssl.cnf\n");
    BIO_printf(bio_err, "    openssl sdf [command options]\n");
    BIO_printf(bio_err, "    # Or pass -config openssl.cnf on the command line.\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Generate SM2 key on device:\n");
    BIO_printf(bio_err, "    openssl sdf -gensm2key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Delete SM2 key on device:\n");
    BIO_printf(bio_err, "    openssl sdf -delsm2key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Update SM2 key on device:\n");
    BIO_printf(bio_err, "    openssl sdf -updatesm2key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Import SM2 private key to device:\n");
    BIO_printf(bio_err, "    openssl sdf -importsm2key -inkey sm2.key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -importsm2key -index 81 -type sign -inkey ..\\test\\certs\\sm2\\server_sign.key\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -importsm2key -index 82 -type enc -inkey ..\\test\\certs\\sm2\\server_enc.key\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Import RSA private key to device:\n");
    BIO_printf(bio_err, "    openssl sdf -importrsakey -inkey rsa.key -index N [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Import SM2 key with digital envelope:\n");
    BIO_printf(bio_err, "    openssl sdf -importsm2keywithevlp -inkey sm2.keyenc -indek sm4.keyenc -index N [-type sign|enc]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Export SM2 private key from device:\n");
    BIO_printf(bio_err, "    openssl sdf -exportsm2key -index N -keyout sm2.key [-type sign|enc] [-login user:pass]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Export SM2 public key from device:\n");
    BIO_printf(bio_err, "    openssl sdf -exportsm2pubkey -index N -keyout sm2.pub [-type sign|enc]\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -exportsm2pubkey -index 40 -type sign -keyout sm2_sign.pub\n");
    BIO_printf(bio_err, "    openssl sdf -config openssl.cnf -exportsm2pubkey -index 40 -type enc -keyout sm2_enc.pub\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Export SM2 key with digital envelope:\n");
    BIO_printf(bio_err, "    openssl sdf -exportsm2keywithevlp -index N -peerkey peer.pem -keyout sm2.bin -dekout dek.bin [-type sign|enc]\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Encrypt/decrypt with SM2 key index:\n");
    BIO_printf(bio_err, "    openssl sdf -encrypt -algorithm sm2 -index N -in plain.bin -out cipher.bin\n");
    BIO_printf(bio_err, "    openssl sdf -decrypt -algorithm sm2 -index N -in cipher.bin -out plain.bin\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "  Encrypt/decrypt with SM4 key encrypted by ISK:\n");
    BIO_printf(bio_err, "    openssl sdf -encrypt -algorithm sm4-cbc -inkey sm4.keyenc -isk N -isktype sm2 -iv HEX -in plain.bin -out cipher.bin\n");
    BIO_printf(bio_err, "    openssl sdf -decrypt -algorithm sm4-cbc -inkey sm4.keyenc -isk N -isktype sm2 -iv HEX -in cipher.bin -out plain.bin\n");
    BIO_printf(bio_err, "\n");
    BIO_printf(bio_err, "Notes:\n");
    BIO_printf(bio_err, "  -type defaults to sign. Use -type enc for encryption-key slots.\n");
    BIO_printf(bio_err, "  -login defaults to admin:123123 if omitted.\n");
    BIO_printf(bio_err, "  Supported -algorithm values are sm2, sm4-ecb, sm4-cbc, sm4-cfb, sm4-ofb.\n");
    BIO_printf(bio_err, "  sdf_lib_path, sdf_module_password and sdf_use_loadmodule are read from openssl.cnf.\n");
    BIO_printf(bio_err, "  SDF_LIB_PATH, SDF_MODULE_PASSWORD and SDF_USE_LOADMODULE are only fallbacks.\n");
    BIO_printf(bio_err, "  Some BYCSM libraries store SM2 sign/enc pairs under a container index.\n");
    BIO_printf(bio_err, "  For byzk0018 tests, import indexes 81/82 export as container index 40.\n");
    BIO_printf(bio_err, "\n");
}

static int sdf_missing_arg(const char *cmd, const char *arg)
{
    BIO_printf(bio_err, "%s requires %s\n", cmd, arg);
    return 0;
}

static int sdf_require_index(const char *cmd, int index)
{
    if (index >= 0)
        return 1;

    BIO_printf(bio_err, "%s requires -index N\n", cmd);
    return 0;
}

int sdf_main(int argc, char **argv)
{
    char *prog;
    OPTION_CHOICE o;
    BIO *outkey = NULL, *outdek = NULL, *key_bio = NULL;
    BIO *in = NULL, *out = NULL;
    int ret = 1, index = -1, sign = 1, keylen = 0, deklen = 0, mode = 0;
    int isk = -1;
    int gensm2 = 0, delsm2 = 0, updatesm2 = 0;
    int exportsm2pubkey = 0, exportsm2keywithevlp = 0, importsm2keywithevlp = 0;
    int exportrsapubkey = 0;
    int exportsm2key = 0, importsm2key = 0, encrypt = 0, decrypt = 0;
    int importrsakey = 0;
    unsigned char *inkey = NULL, *indek = NULL, *inbuf = NULL, *outbuf = NULL;
    char *p = NULL;
    char *login = NULL;
    char *outkeyfile = NULL, *peerkey_file = NULL, *indekfile = NULL;
    char *outdekfile = NULL, *inkeyfile = NULL;
    char *infile = NULL, *outfile = NULL;
    const char *user = "admin", *password = "123123", *hexiv = NULL, *algo = NULL;
    const char *isktype = "sm2";
    unsigned char *iv = NULL;
    long ivlen = 0;
    EVP_PKEY *pkey = NULL, *peer = NULL;
    unsigned char *priv = NULL, *pub = NULL, *outevlp = NULL;
    size_t privlen = 0, publen = 0, outevlplen = 0;
    int inbuflen = -1;
    size_t outbuflen = 0;
    CONF *conf = NULL;

    prog = opt_init(argc, argv, sdf_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(sdf_options);
            sdf_print_usage();
            ret = 0;
            goto end;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_INKEY:
            inkeyfile = opt_arg();
            break;
        case OPT_GENSM2KEY:
            gensm2 = 1;
            break;
        case OPT_DELSM2KEY:
            delsm2 = 1;
            break;
        case OPT_UPDATESM2KEY:
            updatesm2 = 1;
            break;
        case OPT_INDEX:
            if (!opt_int(opt_arg(), &index))
                goto end;
            break;
        case OPT_LOGIN:
            login = opt_arg();
            break;
        case OPT_EXPORTSM2KEY:
            exportsm2key = 1;
            break;
        case OPT_EXPORTSM2PUBKEY:
            exportsm2pubkey = 1;
            break;
        case OPT_EXPORTRSAPUBKEY:
            exportrsapubkey = 1;
            break;
        case OPT_EXPORTSM2KEYWITHEVLP:
            exportsm2keywithevlp = 1;
            break;
        case OPT_IMPORTSM2KEY:
            importsm2key = 1;
            break;
        case OPT_IMPORTSM2KEYWITHEVLP:
            importsm2keywithevlp = 1;
            break;
        case OPT_IMPORTRSAKEY:
            importrsakey = 1;
            break;
        case OPT_PEERKEY:
            peerkey_file = opt_arg();
            break;
        case OPT_TYPE:
            if (strcmp(opt_arg(), "sign") == 0)
                sign = 1;
            else if (strcmp(opt_arg(), "enc") == 0)
                sign = 0;
            else
                goto opthelp;
            break;
        case OPT_KEYOUT:
            outkeyfile = opt_arg();
            break;
        case OPT_INDEK:
            indekfile = opt_arg();
            break;
        case OPT_DEKOUT:
            outdekfile = opt_arg();
            break;
        case OPT_ENCRYPT:
            encrypt = 1;
            break;
        case OPT_DECRYPT:
            decrypt = 1;
            break;
        case OPT_IV:
            hexiv = opt_arg();
            break;
        case OPT_ALGORITHM:
            algo = opt_arg();
            break;
        case OPT_ISK:
            if (!opt_int(opt_arg(), &isk))
                goto end;
            break;
        case OPT_ISKTYPE:
            isktype = opt_arg();
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        case OPT_CONFIG:
            conf = app_load_config_modules(opt_arg());
            if (conf == NULL)
                goto end;
            break;
        }
    }

    argc = opt_num_rest();
    if (argc != 0)
        goto opthelp;

    argc = gensm2 + delsm2 + updatesm2 + exportsm2pubkey + exportrsapubkey
           + exportsm2key + exportsm2keywithevlp + importsm2key
           + importsm2keywithevlp + importrsakey + encrypt + decrypt;
    if (argc == 0) {
        BIO_printf(bio_err, "No sdf command specified\n");
        goto opthelp;
    }
    if (argc > 1) {
        BIO_printf(bio_err, "Only one sdf command can be specified\n");
        goto opthelp;
    }

    if ((gensm2 && !sdf_require_index("-gensm2key", index))
        || (delsm2 && !sdf_require_index("-delsm2key", index))
        || (updatesm2 && !sdf_require_index("-updatesm2key", index))
        || (exportsm2key && (!sdf_require_index("-exportsm2key", index)
                             || (outkeyfile == NULL
                                 && !sdf_missing_arg("-exportsm2key", "-keyout file"))))
        || (exportsm2pubkey && !sdf_require_index("-exportsm2pubkey", index))
        || (exportrsapubkey && !sdf_require_index("-exportrsapubkey", index))
        || (exportsm2keywithevlp
            && (!sdf_require_index("-exportsm2keywithevlp", index)
                || (peerkey_file == NULL
                    && !sdf_missing_arg("-exportsm2keywithevlp", "-peerkey file"))
                || (outkeyfile == NULL
                    && !sdf_missing_arg("-exportsm2keywithevlp", "-keyout file"))
                || (outdekfile == NULL
                    && !sdf_missing_arg("-exportsm2keywithevlp", "-dekout file"))))
        || (importsm2key && (!sdf_require_index("-importsm2key", index)
                             || (inkeyfile == NULL
                                 && !sdf_missing_arg("-importsm2key", "-inkey file"))))
        || (importrsakey && (!sdf_require_index("-importrsakey", index)
                             || (inkeyfile == NULL
                                 && !sdf_missing_arg("-importrsakey", "-inkey file"))))
        || (importsm2keywithevlp
            && (!sdf_require_index("-importsm2keywithevlp", index)
                || (inkeyfile == NULL
                    && !sdf_missing_arg("-importsm2keywithevlp", "-inkey file"))
                || (indekfile == NULL
                    && !sdf_missing_arg("-importsm2keywithevlp", "-indek file")))))
        goto end;

    if (encrypt || decrypt) {
        if (algo == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                             "-algorithm name"))
            goto end;
        if (infile == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                               "-in file"))
            goto end;
        if (outfile == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                                "-out file"))
            goto end;

        if (OPENSSL_strcasecmp(algo, "sm2") == 0) {
            if (!sdf_require_index(encrypt ? "-encrypt" : "-decrypt", index))
                goto end;
        } else if (OPENSSL_strcasecmp(algo, "sm4-ecb") == 0
                   || OPENSSL_strcasecmp(algo, "sm4-cbc") == 0
                   || OPENSSL_strcasecmp(algo, "sm4-cfb") == 0
                   || OPENSSL_strcasecmp(algo, "sm4-ofb") == 0) {
            if (inkeyfile == NULL && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                                      "-inkey file"))
                goto end;
            if (isk < 0 && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt",
                                            "-isk N"))
                goto end;
            if (OPENSSL_strcasecmp(isktype, "sm2") != 0) {
                BIO_printf(bio_err, "Unsupported -isktype %s\n", isktype);
                goto end;
            }
            if (OPENSSL_strcasecmp(algo, "sm4-ecb") != 0 && hexiv == NULL
                && !sdf_missing_arg(encrypt ? "-encrypt" : "-decrypt", "-iv HEX"))
                goto end;
        }
    }

    if (login) {
        user = login;
        p = strchr(login, ':');
        if (p == NULL) {
            BIO_printf(bio_err, "No password found");
            goto end;
        }

        password = p + 1;
        *p = '\0';
    }

    /*
     * 厂商库通常由 sdfprov 从 openssl.cnf 读取配置后预加载。
     * 如果 provider/config 没有先完成预加载，TSAPI 层仍会在首次调用时尝试
     * 用 SDF_LIB_PATH / SDF_MODULE_PASSWORD / SDF_USE_LOADMODULE 作为 fallback。
     */

    if (gensm2) {
        if (!TSAPI_GenerateSM2KeyWithIndex(index, sign, user, password)) {
            BIO_printf(bio_err, "Failed to generate SM2 key pair with index %d\n", index);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (delsm2) {
        if (!TSAPI_DelSm2KeyWithIndex(index, sign, user, password)) {
            BIO_printf(bio_err, "Failed to delete SM2 key pair with index %d\n", index);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (updatesm2) {
        if (!TSAPI_UpdateSm2KeyWithIndex(index, sign, user, password)) {
            BIO_printf(bio_err, "Failed to update SM2 key pair with index %d\n", index);
            goto end;
        }

        ret = 0;
        goto end;
    }

    /*
     * 公钥导出（SM2/RSA）：
     * - 指定 -keyout 时输出 PEM 到文件
     * - 未指定 -keyout 时打印 PEM 到 stdout
     */
    if (exportsm2pubkey || exportrsapubkey) {
        if (outkeyfile != NULL) {
            outkey = bio_open_default(outkeyfile, 'w', FORMAT_PEM);
            if (outkey == NULL)
                goto end;
        } else {
            outkey = BIO_new_fp(stdout, BIO_NOCLOSE);
            if (outkey == NULL)
                goto end;
        }

        if (exportsm2pubkey)
            pkey = TSAPI_ExportSM2PubKeyWithIndex(index, sign);
        else
            pkey = TSAPI_ExportRSAPubKeyWithIndex(index, sign);

        if (pkey == NULL) {
            BIO_printf(bio_err, "Failed to export %s public key with index %d\n",
                       exportsm2pubkey ? "SM2" : "RSA", index);
            goto end;
        }

        if (!PEM_write_bio_PUBKEY(outkey, pkey)) {
            BIO_printf(bio_err, "Failed to write public key\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        ret = 0;
        goto end;
    }

    /* exportsm2key (export private key, requires -keyout) */
    if (outkeyfile) {
        outkey = bio_open_default(outkeyfile, 'w', FORMAT_BINARY);
        if (outkey == NULL)
            goto end;
    }

    if (exportsm2key) {
        pkey = TSAPI_ExportSM2KeyWithIndex(index, sign, user, password);
        if (pkey == NULL) {
            BIO_printf(bio_err, "Failed to export SM2 pubkey with index %d\n", index);
            goto end;
        }

        if (!PEM_write_bio_PrivateKey(outkey, pkey, NULL, NULL, 0, NULL, NULL)) {
            BIO_printf(bio_err, "Failed to write SM2 key\n");
            ERR_print_errors(bio_err);
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (exportsm2keywithevlp) {
        peer = load_pubkey(peerkey_file, FORMAT_PEM, 0, NULL, NULL, "peer key");
        if (peer == NULL) {
            BIO_printf(bio_err, "Error reading peer key %s\n", peerkey_file);
            goto end;
        }

        if (!TSAPI_ExportSM2KeyWithEvlp(index, sign, user, password, peer, &priv,
                                        &privlen, &pub, &publen, &outevlp,
                                        &outevlplen)) {
            BIO_printf(bio_err, "Failed to export SM2 key with digital envelope\n");
            goto end;
        }

        if (BIO_write(outkey, pub, publen) != (int)publen
            || BIO_write(outkey, priv, privlen) != (int)privlen) {
            BIO_printf(bio_err, "Failed to write public or private key\n");
            goto end;
        }

        outdek = bio_open_default(outdekfile, 'w', FORMAT_BINARY);
        if (outdek == NULL)
            goto end;

        if (BIO_write(outdek, outevlp, outevlplen) != (int)outevlplen) {
            BIO_printf(bio_err, "Failed to write digital envelope\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (importsm2key) {
        pkey = load_key(inkeyfile, FORMAT_PEM, 0, NULL, NULL, "key");

        if (pkey == NULL) {
            BIO_printf(bio_err, "Error reading key %s\n", inkeyfile);
            goto end;
        }

        if (!TSAPI_ImportSM2Key(index, sign, user, password, pkey)) {
            BIO_printf(bio_err, "Failed to import SM2 key\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (importrsakey) {
        pkey = load_key(inkeyfile, FORMAT_PEM, 0, NULL, NULL, "key");

        if (pkey == NULL) {
            BIO_printf(bio_err, "Error reading key %s\n", inkeyfile);
            goto end;
        }

        if (!TSAPI_ImportRSAKey(index, sign, user, password, pkey)) {
            BIO_printf(bio_err, "Failed to import RSA key\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (inkeyfile) {
        key_bio = BIO_new(BIO_s_file());
        if (key_bio == NULL) {
            BIO_printf(bio_err, "Error creating key BIO\n");
            goto end;
        }

        if (BIO_read_filename(key_bio, inkeyfile) <= 0) {
            BIO_printf(bio_err, "Error reading key file %s\n", inkeyfile);
            goto end;
        }

        keylen = bio_to_mem(&inkey, 4096, key_bio);
        BIO_free(key_bio);
        key_bio = NULL;

        if (keylen < 0) {
            BIO_printf(bio_err, "Error reading key\n");
            goto end;
        }
    }

    if (indekfile) {
        key_bio = BIO_new(BIO_s_file());
        if (key_bio == NULL) {
            BIO_printf(bio_err, "Error creating key BIO\n");
            goto end;
        }

        if (BIO_read_filename(key_bio, indekfile) <= 0) {
            BIO_printf(bio_err, "Error reading key file %s\n", indekfile);
            goto end;
        }

        deklen = bio_to_mem(&indek, 4096, key_bio);
        BIO_free(key_bio);
        key_bio = NULL;

        if (deklen < 0) {
            BIO_printf(bio_err, "Error reading key\n");
            goto end;
        }
    }

    if (importsm2keywithevlp) {
        if (inkey == NULL || indek == NULL) {
            BIO_printf(bio_err, "No key or digital envelope specified\n");
            goto end;
        }

        if (!TSAPI_ImportSM2KeyWithEvlp(index, sign, user, password, inkey,
                                        keylen, indek, deklen)) {
            BIO_printf(bio_err, "Failed to import SM2 key with digital envelope\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    if (infile) {
        in = bio_open_default(infile, 'r', FORMAT_BINARY);
        if (in == NULL)
            goto end;

        /* Note: Only supports files less than 1GB */
        inbuflen = bio_to_mem(&inbuf, 1024 * 1024 * 1024, in);
        if (inbuflen < 0) {
            BIO_printf(bio_err, "Error reading input\n");
            goto end;
        }
    }

    if (outfile) {
        out = bio_open_default(outfile, 'w', FORMAT_BINARY);
        if (out == NULL)
            goto end;
    }

    if (encrypt || decrypt) {
        if (inbuf == NULL || inbuflen < 0 || out == NULL || algo == NULL) {
            BIO_printf(bio_err, "No input, output or algorithm specified\n");
            goto end;
        }

        if (OPENSSL_strcasecmp(algo, "sm2") == 0) {
            if (index < 0) {
                BIO_printf(bio_err, "No SM2 key index specified\n");
                goto end;
            }

            if (encrypt)
                outbuf = TSAPI_SM2EncryptWithISK(index, inbuf, inbuflen,
                                                 &outbuflen);
            else
                outbuf = TSAPI_SM2DecryptWithISK(index, inbuf, inbuflen,
                                                 &outbuflen);
        } else {
            if (OPENSSL_strcasecmp(algo, "sm4-ecb") == 0)
                mode = OSSL_SGD_SM4_ECB;
            else if (OPENSSL_strcasecmp(algo, "sm4-cbc") == 0)
                mode = OSSL_SGD_SM4_CBC;
            else if (OPENSSL_strcasecmp(algo, "sm4-cfb") == 0)
                mode = OSSL_SGD_SM4_CFB;
            else if (OPENSSL_strcasecmp(algo, "sm4-ofb") == 0)
                mode = OSSL_SGD_SM4_OFB;
            else {
                BIO_printf(bio_err, "Unknown algorithm %s\n", algo);
                goto end;
            }

            if (hexiv) {
                iv = OPENSSL_hexstr2buf(hexiv, &ivlen);
                if (iv == NULL) {
                    BIO_printf(bio_err, "Error reading IV\n");
                    goto end;
                }
                if (ivlen != 16) {
                    BIO_printf(bio_err, "SM4 IV must be 16 bytes\n");
                    goto end;
                }
            }

            if (OPENSSL_strcasecmp(isktype, "sm2") == 0) {
                if (encrypt) {
                    if ((outbuf = TSAPI_SM4Encrypt(mode, inkey, keylen, isk, iv,
                                                   inbuf, inbuflen, &outbuflen))
                                        == NULL) {
                        BIO_printf(bio_err, "Failed to encrypt data\n");
                        goto end;
                    }
                } else {
                    if ((outbuf = TSAPI_SM4Decrypt(mode, inkey, keylen, isk, iv,
                                                   inbuf, inbuflen, &outbuflen))
                                        == NULL) {
                        BIO_printf(bio_err, "Failed to decrypt data\n");
                        goto end;
                    }
                }
            } else {
                BIO_printf(bio_err, "Unknown ISK type %s\n", isktype);
                goto end;
            }
        }

        if (BIO_write(out, outbuf, outbuflen) != (int)outbuflen) {
            BIO_printf(bio_err, "Failed to write output\n");
            goto end;
        }

        ret = 0;
        goto end;
    }

    ret = 0;
end:
    OPENSSL_free(iv);
    OPENSSL_free(inbuf);
    OPENSSL_free(outbuf);
    BIO_free(in);
    BIO_free(out);
    OPENSSL_free(inkey);
    BIO_free(outdek);
    BIO_free(key_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer);
    BIO_free(outkey);
    OPENSSL_free(priv);
    OPENSSL_free(pub);
    OPENSSL_free(outevlp);
    NCONF_free(conf);
    return ret;
}
