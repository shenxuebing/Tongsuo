/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef HEADER_SKF_ERR_H
# define HEADER_SKF_ERR_H

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define SKFerr(f, r) ERR_SKF_error(0, (r), OPENSSL_FILE, OPENSSL_LINE)

/*
 * SKF function codes.
 */
# define SKF_F_SKF_INIT                                   100
# define SKF_F_SKF_FINISH                                 101
# define SKF_F_SKF_CTRL                                   102
# define SKF_F_SKF_LOAD_PRIVKEY                           103
# define SKF_F_SKF_LOAD_PUBKEY                            104
# define SKF_F_SKF_RSA_SIGN                               105
# define SKF_F_SKF_RSA_PRIV_DEC                           106
# define SKF_F_SKF_ECDSA_SIGN                             107
# define SKF_F_SKF_SM2_SIGN                               108
# define SKF_F_SKF_SM2_DECRYPT                            109
# define SKF_F_SKF_RAND_BYTES                             110
# define SKF_F_SKF_LOAD_LIBRARY                           111
# define SKF_F_SKF_INIT_DEVICE                            112
# define SKF_F_SKF_ENUM_DEVICES                           113
# define SKF_F_SKF_ENUM_APPLICATIONS                      114
# define SKF_F_SKF_ENUM_CONTAINERS                        115
# define SKF_F_BIND_SKF                                   116
/* EVP_PKEY EC method function codes */
# define SKF_F_SKF_PKEY_EC_INIT                           117
# define SKF_F_SKF_PKEY_EC_COPY                           118
# define SKF_F_SKF_PKEY_EC_PARAMGEN                       119
# define SKF_F_SKF_PKEY_EC_KEYGEN                         120
# define SKF_F_SKF_PKEY_EC_SIGN                           121
# define SKF_F_SKF_PKEY_EC_VERIFY                         122
# define SKF_F_SKF_PKEY_EC_ENCRYPT                        123
# define SKF_F_SKF_PKEY_EC_DECRYPT                        124
# define SKF_F_SKF_PKEY_EC_DERIVE                         125
# define SKF_F_SKF_PKEY_EC_KDF_DERIVE                     126
# define SKF_F_SKF_PKEY_EC_CTRL                           127
# define SKF_F_SKF_PKEY_EC_CTRL_STR                       128
/* Misc helper function codes */
# define SKF_F_SKF_SET_FEATURE_MASK                       129
# define SKF_F_SKF_VALIDATE_MASK                          130
# define SKF_F_SKF_SSL_GENERATE_MASTER_SECRET             131
# define SKF_F_SKF_TLS1_GENERATE_KEY_BLOCK                132

/*
 * SKF reason codes.
 */
# define SKF_R_ALREADY_LOADED                             100
# define SKF_R_CANT_LOAD_SKF_MODULE                       101
# define SKF_R_CTRL_COMMAND_NOT_IMPLEMENTED               102
# define SKF_R_DSO_FAILURE                                103
# define SKF_R_ENGINE_IS_NOT_INITIALIZED                  104
# define SKF_R_FUNCTION_NOT_SUPPORTED                     105
# define SKF_R_INVALID_ARGUMENT                           106
# define SKF_R_INVALID_KEY_LENGTH                         107
# define SKF_R_INVALID_OPERATION                          108
# define SKF_R_INVALID_PARAMETER                          109
# define SKF_R_INVALID_SIGNATURE_LENGTH                   110
# define SKF_R_KEY_NOT_FOUND                              111
# define SKF_R_NOT_LOADED                                 112
# define SKF_R_OPERATION_NOT_SUPPORTED                    113
# define SKF_R_REQUEST_FAILED                             114
# define SKF_R_UNKNOWN_ALGORITHM_TYPE                     115
# define SKF_R_UNKNOWN_COMMAND                            116
# define SKF_R_UNSUPPORTED_ALGORITHM_NID                  117
# define SKF_R_DEVICE_NOT_FOUND                           118
# define SKF_R_DEVICE_OPEN_FAILED                         119
# define SKF_R_APPLICATION_NOT_FOUND                      120
# define SKF_R_APPLICATION_OPEN_FAILED                    121
# define SKF_R_CONTAINER_NOT_FOUND                        122
# define SKF_R_CONTAINER_OPEN_FAILED                      123
# define SKF_R_AUTHENTICATION_FAILED                      124
# define SKF_R_CERTIFICATE_NOT_FOUND                      125
# define SKF_R_PRIVATE_KEY_NOT_FOUND                      126
# define SKF_R_PUBLIC_KEY_NOT_FOUND                       127
# define SKF_R_SIGNATURE_VERIFICATION_FAILED              128
# define SKF_R_ENCRYPTION_FAILED                          129
# define SKF_R_DECRYPTION_FAILED                          130
# define SKF_R_HASH_CALCULATION_FAILED                    131
# define SKF_R_RANDOM_GENERATION_FAILED                   132
# define SKF_R_MEMORY_ALLOCATION_FAILED                   133
# define SKF_R_BUFFER_TOO_SMALL                           134
# define SKF_R_LIBRARY_NOT_INITIALIZED                    135
# define SKF_R_DEVICE_REMOVED                             136
# define SKF_R_PIN_INCORRECT                              137
# define SKF_R_PIN_LOCKED                                 138
# define SKF_R_USER_NOT_LOGGED_IN                         139
# define SKF_R_OPERATION_TIMEOUT                          140
# define SKF_R_HARDWARE_ERROR                             141
# define SKF_R_COMMUNICATION_ERROR                        142
# define SKF_R_INTERNAL_ERROR                             143
# define SKF_R_EXPORT_KEY_FAILED                          144
# define SKF_R_INIT_FAILED                                145
# define SKF_R_NOT_INITIALIZED                            146
# define SKF_R_ENUMERATION_FAILED                         147
# define SKF_R_NO_DEVICES_FOUND                           148
# define SKF_R_NO_APPLICATIONS_FOUND                      149
# define SKF_R_NO_CONTAINERS_FOUND                        150
# define SKF_R_APPLICATION_NAME_REQUIRED                  151
# define SKF_R_CONTAINER_NAME_REQUIRED                    152
# define SKF_R_MODULE_PATH_REQUIRED                       153
# define SKF_R_NOT_SUPPORTED                              160

# ifdef  __cplusplus
}
# endif
#endif