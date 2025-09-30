/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_E_SDF_ERR_H
# define OSSL_E_SDF_ERR_H

# include <openssl/opensslconf.h>
# include <openssl/symhacks.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define SDFerr(f, r) ERR_SDF_error(0, (r), OPENSSL_FILE, OPENSSL_LINE)

/*
 * SDF function codes.
 */
# define SDF_F_SDF_INIT                                   100
# define SDF_F_SDF_FINISH                                 101
# define SDF_F_SDF_CTRL                                   102
# define SDF_F_SDF_LOAD_PRIVKEY                           103
# define SDF_F_SDF_LOAD_PUBKEY                            104
# define SDF_F_SDF_RSA_PRIV_ENC                           105
# define SDF_F_SDF_RSA_PRIV_DEC                           106
# define SDF_F_SDF_RSA_PUB_ENC                            107
# define SDF_F_SDF_RSA_PUB_DEC                            108
# define SDF_F_SDF_ECC_SIGN                               109
# define SDF_F_SDF_ECC_VERIFY                             110
# define SDF_F_SDF_SM2_SIGN                               111
# define SDF_F_SDF_SM2_VERIFY                             112
# define SDF_F_SDF_SM2_ENCRYPT                            113
# define SDF_F_SDF_SM2_DECRYPT                            114
# define SDF_F_SDF_RAND_BYTES                             115
# define SDF_F_SDF_DIGEST_INIT                            116
# define SDF_F_SDF_DIGEST_UPDATE                          117
# define SDF_F_SDF_DIGEST_FINAL                           118
# define SDF_F_SDF_CIPHER_INIT                            119
# define SDF_F_SDF_CIPHER_UPDATE                          120
# define SDF_F_SDF_CIPHER_FINAL                           121
/* Additional function codes used by implementation */
# define SDF_F_BIND_SDF                                   122
# define SDF_F_CIPHER_SM4_CBC_CIPHER                      123
# define SDF_F_CIPHER_SM4_ECB_CIPHER                      124
# define SDF_F_LOAD_KEY                                   125

/*
 * SDF reason codes.
 */
# define SDF_R_ALREADY_LOADED                             100
# define SDF_R_BN_CTX_FULL                                101
# define SDF_R_BN_EXPAND_FAIL                             102
# define SDF_R_CANT_LOAD_SDF_MODULE                       103
# define SDF_R_CTRL_COMMAND_NOT_IMPLEMENTED               104
# define SDF_R_DSO_FAILURE                                105
# define SDF_R_ENGINE_IS_NOT_INITIALIZED                  106
# define SDF_R_FUNCTION_NOT_SUPPORTED                     107
# define SDF_R_INVALID_ARGUMENT                           108
# define SDF_R_INVALID_DIGEST_LENGTH                      109
# define SDF_R_INVALID_KEY_LENGTH                         110
# define SDF_R_INVALID_OPERATION                          111
# define SDF_R_INVALID_PADDING                            112
# define SDF_R_INVALID_SIGNATURE_LENGTH                   113
# define SDF_R_KEY_NOT_FOUND                              114
# define SDF_R_MISSING_KEY_COMPONENTS                     115
# define SDF_R_NOT_LOADED                                 116
# define SDF_R_NO_MODULUS_OR_NO_EXPONENT                  117
# define SDF_R_OPERATION_NOT_SUPPORTED                    118
# define SDF_R_OUTLEN_TO_LARGE                            119
# define SDF_R_REQUEST_FAILED                             120
# define SDF_R_REQUEST_FALLBACK                           121
# define SDF_R_SIZE_TOO_LARGE_OR_TOO_SMALL                122
# define SDF_R_UNIT_FAILURE                               123
# define SDF_R_UNKNOWN_ALGORITHM_TYPE                     124
# define SDF_R_UNKNOWN_COMMAND                            125
# define SDF_R_UNKNOWN_DIGEST                             126
# define SDF_R_UNKNOWN_PADDING_TYPE                       127
# define SDF_R_UNSUPPORTED_ALGORITHM_NID                  128
# define SDF_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM           129
# define SDF_R_DEVICE_NOT_FOUND                           130
# define SDF_R_DEVICE_OPEN_FAILED                         131
# define SDF_R_SESSION_OPEN_FAILED                        132
# define SDF_R_AUTHENTICATION_FAILED                      133
# define SDF_R_CONTAINER_NOT_FOUND                        134
# define SDF_R_CERTIFICATE_NOT_FOUND                      135
# define SDF_R_PRIVATE_KEY_NOT_FOUND                      136
# define SDF_R_PUBLIC_KEY_NOT_FOUND                       137
# define SDF_R_SIGNATURE_VERIFICATION_FAILED              138
# define SDF_R_ENCRYPTION_FAILED                          139
# define SDF_R_DECRYPTION_FAILED                          140
# define SDF_R_HASH_CALCULATION_FAILED                    141
# define SDF_R_RANDOM_GENERATION_FAILED                   142
# define SDF_R_MEMORY_ALLOCATION_FAILED                   143
# define SDF_R_INVALID_PARAMETER                          144
# define SDF_R_BUFFER_TOO_SMALL                           145
# define SDF_R_LIBRARY_NOT_INITIALIZED                    146
# define SDF_R_DEVICE_REMOVED                             147
# define SDF_R_PIN_INCORRECT                              148
# define SDF_R_PIN_LOCKED                                 149
# define SDF_R_USER_NOT_LOGGED_IN                         150
# define SDF_R_OPERATION_TIMEOUT                          151
# define SDF_R_HARDWARE_ERROR                             152
# define SDF_R_COMMUNICATION_ERROR                        153
# define SDF_R_INTERNAL_ERROR                             154
/* Additional reasons referenced in implementation */
# define SDF_R_EXPORT_KEY_FAILED                          155
# define SDF_R_INIT_FAILED                                156
# define SDF_R_NOT_INITIALIZED                            157
# define SDF_R_OPEN_DEVICE_FAILED                         158
# define SDF_R_OPEN_SESSION_FAILED                        159
/* Not supported operation */
# define SDF_R_NOT_SUPPORTED                               160

# ifdef  __cplusplus
}
# endif
#endif