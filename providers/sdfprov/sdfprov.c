/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "sdfprov_ctx.h"

/* Forward declarations */
static OSSL_FUNC_provider_gettable_params_fn sdfprov_gettable_params;
static OSSL_FUNC_provider_get_params_fn sdfprov_get_params;
static OSSL_FUNC_provider_query_operation_fn sdfprov_query;
static OSSL_FUNC_provider_teardown_fn sdfprov_teardown;

#ifdef STATIC_SDFPROV
OSSL_provider_init_fn ossl_sdfprov_provider_init;
# define OSSL_provider_init_int ossl_sdfprov_provider_init
#endif

/* Core functions */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
static OSSL_FUNC_core_get_libctx_fn *c_internal_get_libctx = NULL;

/* Global SDF context (single provider instance) */
static SDFPROV_CTX *g_sdfctx = NULL;

SDFPROV_CTX *sdfprov_get_global_ctx(void)
{
    return g_sdfctx;
}

/* External dispatch tables from operation files */
extern const OSSL_DISPATCH sdfprov_sm2_keymgmt_functions[];
extern const OSSL_DISPATCH sdfprov_sm2_signature_functions[];
extern const OSSL_DISPATCH sdfprov_sm2_asym_cipher_functions[];
extern const OSSL_DISPATCH sdfprov_sm2dh_keyexch_functions[];
extern const OSSL_DISPATCH sdfprov_rand_functions[];
extern const OSSL_DISPATCH sdfprov_store_functions[];

/* Provider parameters */
static const OSSL_PARAM sdfprov_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *sdfprov_gettable_params(void *provctx)
{
    return sdfprov_param_types;
}

static int sdfprov_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Tongsuo SDF Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1.0.0"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, ossl_prov_is_running()))
        return 0;
    return 1;
}

/* Algorithm tables */
#define ALG(NAMES, FUNC) { NAMES, "provider=sdfprov", FUNC, NULL }

static const OSSL_ALGORITHM sdfprov_keymgmt[] = {
#ifndef OPENSSL_NO_SM2
    ALG(PROV_NAMES_SM2, sdfprov_sm2_keymgmt_functions),
#endif
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_signature[] = {
#ifndef OPENSSL_NO_SM2
    ALG(PROV_NAMES_SM2, sdfprov_sm2_signature_functions),
#endif
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_asym_cipher[] = {
#ifndef OPENSSL_NO_SM2
    ALG(PROV_NAMES_SM2, sdfprov_sm2_asym_cipher_functions),
#endif
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_keyexch[] = {
#ifndef OPENSSL_NO_SM2
    ALG(PROV_NAMES_SM2DH, sdfprov_sm2dh_keyexch_functions),
#endif
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_rand[] = {
    { "SDF-RAND", "provider=sdfprov", sdfprov_rand_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_store[] = {
    { "sdf", "provider=sdfprov", sdfprov_store_functions, NULL },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *sdfprov_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    *no_cache = 0;

    if (!ossl_prov_is_running())
        return NULL;

    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return sdfprov_keymgmt;
    case OSSL_OP_SIGNATURE:
        return sdfprov_signature;
    case OSSL_OP_ASYM_CIPHER:
        return sdfprov_asym_cipher;
    case OSSL_OP_KEYEXCH:
        return sdfprov_keyexch;
    case OSSL_OP_RAND:
        return sdfprov_rand;
    case OSSL_OP_STORE:
        return sdfprov_store;
    }
    return NULL;
}

static void sdfprov_teardown(void *provctx)
{
    sdfprov_ctx_free(g_sdfctx);
    g_sdfctx = NULL;

    if (provctx != NULL) {
        ossl_prov_ctx_free(provctx);
    }
}

static const OSSL_DISPATCH sdfprov_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))sdfprov_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
      (void (*)(void))sdfprov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))sdfprov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))sdfprov_query },
    { 0, NULL }
};

OSSL_provider_init_fn OSSL_provider_init_int;
int OSSL_provider_init_int(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in,
                            const OSSL_DISPATCH **out,
                            void **provctx)
{
    OSSL_LIB_CTX *libctx = NULL;
    SDFPROV_CTX *sdfctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_internal_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            break;
        }
    }

    if (c_internal_get_libctx == NULL) {
        return 0;
    }

    libctx = (OSSL_LIB_CTX *)c_internal_get_libctx(handle);

    /* Create provider context */
    *provctx = ossl_prov_ctx_new();
    if (*provctx == NULL)
        return 0;

    ossl_prov_ctx_set0_libctx(*provctx, libctx);
    ossl_prov_ctx_set0_handle(*provctx, handle);

    /* Create SDF context (device not yet opened) */
    sdfctx = sdfprov_ctx_new(libctx, handle);
    if (sdfctx == NULL)
        goto err;

    /* Store as global for access by provider operations */
    g_sdfctx = sdfctx;

    /* Read configuration parameters from openssl.cnf provider section */
    if (c_get_params != NULL) {
        char password_buf[256] = {0};
        char lib_path_buf[1024] = {0};
        OSSL_PARAM config_params[] = {
            OSSL_PARAM_utf8_string("sdf_module_password", password_buf, sizeof(password_buf) - 1),
            OSSL_PARAM_utf8_string("sdf_lib_path", lib_path_buf, sizeof(lib_path_buf) - 1),
            OSSL_PARAM_END
        };

        if (c_get_params(handle, config_params)) {
            const OSSL_PARAM *p;
            p = OSSL_PARAM_locate_const(config_params, "sdf_module_password");
            if (p != NULL && password_buf[0] != '\0') {
                sdfctx->password = OPENSSL_strdup(password_buf);
            }
            p = OSSL_PARAM_locate_const(config_params, "sdf_lib_path");
            if (p != NULL && lib_path_buf[0] != '\0') {
                sdfctx->sdf_lib_path = OPENSSL_strdup(lib_path_buf);
            }
        }
    }

    /* Default module password if not configured */
    if (sdfctx->password == NULL)
        sdfctx->password = OPENSSL_strdup("88888888");

    sdfctx->sign_key_index = 0;
    sdfctx->enc_key_index = 0;

    /* Note: device will be opened on first use, not during provider init,
     * so the provider can load even without SDF hardware present */

    *out = sdfprov_dispatch_table;
    return 1;

err:
    ossl_prov_ctx_free(*provctx);
    *provctx = NULL;
    return 0;
}
