/*
 * Copyright 2024-2026 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdlib.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/cryptlib.h"
#include "internal/core.h"
#include "prov/implementations.h"
#include "prov/names.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "internal/tlog.h"
#include "sdfprov_internal.h"
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

static int sdfprov_dup_env_if_unset(char **dst, const char *envname,
                                    const char *logname)
{
    const char *envval;

    if (dst == NULL || *dst != NULL)
        return 1;

    envval = getenv(envname);
    if (envval == NULL || *envval == '\0')
        return 1;

    *dst = OPENSSL_strdup(envval);
    if (*dst == NULL)
        return 0;

    TLOG_DEBUG("Read %s from %s: %s", logname, envname, envval);
    return 1;
}

SDFPROV_CTX *sdfprov_get_global_ctx(void)
{
    return g_sdfctx;
}

/* External dispatch tables from operation files */
extern const OSSL_DISPATCH sdfprov_sm2_keymgmt_functions[];
extern const OSSL_DISPATCH sdfprov_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH sdfprov_sm2_signature_functions[];
extern const OSSL_DISPATCH sdfprov_rsa_signature_functions[];
extern const OSSL_DISPATCH sdfprov_sm2_asym_cipher_functions[];
extern const OSSL_DISPATCH sdfprov_rsa_asym_cipher_functions[];
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
    ALG(PROV_NAMES_RSA, sdfprov_rsa_keymgmt_functions),
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_signature[] = {
#ifndef OPENSSL_NO_SM2
    ALG(PROV_NAMES_SM2, sdfprov_sm2_signature_functions),
#endif
    ALG(PROV_NAMES_RSA, sdfprov_rsa_signature_functions),
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM sdfprov_asym_cipher[] = {
#ifndef OPENSSL_NO_SM2
    ALG(PROV_NAMES_SM2, sdfprov_sm2_asym_cipher_functions),
#endif
    ALG(PROV_NAMES_RSA, sdfprov_rsa_asym_cipher_functions),
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
    if (g_sdfctx != NULL) {
        sdfprov_ctx_free(g_sdfctx);
        g_sdfctx = NULL;
    }

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

    /* Read configuration parameters from openssl.cnf provider section
     *
     * 重要：core 的 OSSL_PROVIDER_get_conf_parameters 始终用
     * OSSL_PARAM_set_utf8_ptr（data_type=6）设置值，因此这里必须用
     * OSSL_PARAM_construct_utf8_ptr（data_type=6）接收指针，
     * 而不能用 OSSL_PARAM_utf8_string（data_type=4）接收 buffer，
     * 否则类型不匹配导致 c_get_params 整体失败（返回 0）。
     */
    const char *password_ptr = NULL;
    const char *lib_path_ptr = NULL;
    const char *use_load_module_ptr = NULL;
    int use_load_module_val = 1;  /* 默认启用 BYCSM_LoadModule（byzk0018 需要） */
    TLOG_DEBUG("Reading config parameters, c_get_params=%p", (void *)c_get_params);
    if (c_get_params != NULL) {
        OSSL_PARAM config_params[] = {
            OSSL_PARAM_construct_utf8_ptr("sdf_module_password", (char **)&password_ptr, 0),
            OSSL_PARAM_construct_utf8_ptr("sdf_lib_path", (char **)&lib_path_ptr, 0),
            OSSL_PARAM_construct_utf8_ptr("sdf_use_loadmodule", (char **)&use_load_module_ptr, 0),
            OSSL_PARAM_END
        };

        TLOG_DEBUG("Calling c_get_params");
        int ret = c_get_params(handle, config_params);
        TLOG_DEBUG("c_get_params returned %d", ret);
        if (ret) {
            if (password_ptr != NULL) {
                sdfctx->password = OPENSSL_strdup(password_ptr);
                TLOG_DEBUG("Read password: %s", password_ptr);
            }
            if (lib_path_ptr != NULL) {
                sdfctx->sdf_lib_path = OPENSSL_strdup(lib_path_ptr);
                TLOG_DEBUG("Read lib_path: %s", lib_path_ptr);
            }
            if (use_load_module_ptr != NULL) {
                use_load_module_val = atoi(use_load_module_ptr);
                sdfctx->use_load_module = use_load_module_val;
                TLOG_DEBUG("Read use_load_module: %d", use_load_module_val);
            }
        } else {
            TLOG_DEBUG("c_get_params failed, using defaults");
        }
    }

    if (!sdfprov_dup_env_if_unset(&sdfctx->password, "SDF_MODULE_PASSWORD",
                                  "password")
            || !sdfprov_dup_env_if_unset(&sdfctx->sdf_lib_path, "SDF_LIB_PATH",
                                         "lib_path")) {
        goto err;
    }

    if (use_load_module_ptr == NULL) {
        const char *env_use_loadmodule = getenv("SDF_USE_LOADMODULE");

        if (env_use_loadmodule != NULL && *env_use_loadmodule != '\0') {
            use_load_module_val = atoi(env_use_loadmodule);
            TLOG_DEBUG("Read use_load_module from SDF_USE_LOADMODULE: %d",
                       use_load_module_val);
        }
    }

    /* Default module password if not configured */
    if (sdfctx->password == NULL)
        sdfctx->password = OPENSSL_strdup("88888888");

    /* Default lib path if not configured */
    if (sdfctx->sdf_lib_path == NULL)
        sdfctx->sdf_lib_path =
#ifdef _WIN32
            OPENSSL_strdup("byzk0018.dll");
#else
            OPENSSL_strdup("./libbyzk0018.so");
#endif
    if (sdfctx->password == NULL || sdfctx->sdf_lib_path == NULL)
        goto err;

    /* 默认启用 BYCSM_LoadModule（兼容博雅等厂商）
     * use_load_module_val 初始为 1，c_get_params 成功时会被配置值覆盖
     * 因此直接使用 use_load_module_val 即可覆盖所有场景 */
    sdfctx->use_load_module = use_load_module_val;

    sdfctx->sign_key_index = 0;
    sdfctx->enc_key_index = 0;

    /* Note: device will be opened on first use, not during provider init,
     * so the provider can load even without SDF hardware present */

    *out = sdfprov_dispatch_table;
    return 1;

err:
    if (sdfctx != NULL) {
        sdfprov_ctx_free(sdfctx);
        if (g_sdfctx == sdfctx)
            g_sdfctx = NULL;
    }
    ossl_prov_ctx_free(*provctx);
    *provctx = NULL;
    return 0;
}
