/*
 * Copyright 2025 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_CRYPTO_SM2DHE_H
# define OSSL_CRYPTO_SM2DHE_H
# pragma once

# include <openssl/evp.h>

/*
 * SM2DHE (SM2 Diffie-Hellman Ephemeral) Key Agreement
 * 
 * This header defines standard interfaces for SM2DHE key agreement,
 * which is used in TLCP (Transport Layer Cryptography Protocol) for
 * ECDHE-SM2 cipher suites.
 * 
 * These interfaces are generic and can be implemented by any ENGINE
 * or provider, not specific to SDF ENGINE.
 */

/* SM2DHE control commands for EVP_PKEY_CTX_ctrl() */
# define EVP_PKEY_CTRL_SM2DHE_SET_PARAMS  (EVP_PKEY_ALG_CTRL + 30)
# define EVP_PKEY_CTRL_SM2DHE_GET_EPH_PUB (EVP_PKEY_ALG_CTRL + 31)

/*
 * SM2DHE parameters structure
 * 
 * This structure is used to pass parameters to ENGINE/provider for
 * SM2DHE key agreement operations.
 */
typedef struct evp_pkey_sm2dhe_params_st {
    /* Role in key agreement: 0=responder (server), 1=initiator (client) */
    int initiator;
    
    /* Ephemeral key pair */
    EVP_PKEY *self_eph_priv;           /* Self ephemeral private key */
    EVP_PKEY *peer_eph_pub;            /* Peer ephemeral public key */
    
    /* Certificate key pair (for SM2DHE agreement) */
    EVP_PKEY *self_cert_priv;          /* Self certificate private key */
    EVP_PKEY *peer_cert_pub;           /* Peer certificate public key */
    
    /* Identity information (for ZA calculation) */
    const unsigned char *self_id;       /* Self identity */
    size_t self_id_len;                 /* Length of self identity */
    const unsigned char *peer_id;       /* Peer identity */
    size_t peer_id_len;                 /* Length of peer identity */
    
    /* Reserved for future extensions */
    void *reserved[4];
} EVP_PKEY_SM2DHE_PARAMS;

/*
 * Helper macros for setting SM2DHE parameters
 */
# define EVP_PKEY_CTX_set_sm2dhe_params(ctx, params) \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_SM2DHE_SET_PARAMS, 0, (void *)(params))

# define EVP_PKEY_CTX_get_sm2dhe_eph_pub(ctx, pub, len) \
    EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_SM2, EVP_PKEY_OP_DERIVE, \
                      EVP_PKEY_CTRL_SM2DHE_GET_EPH_PUB, (int)(len), (void *)(pub))

#endif /* OSSL_CRYPTO_SM2DHE_H */
