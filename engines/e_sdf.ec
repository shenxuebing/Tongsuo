# Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt

L SDF        e_sdf_err.h        e_sdf_err.c

# Function codes for SDF engine
F SDF_F_SDF_INIT
F SDF_F_SDF_FINISH
F SDF_F_SDF_CTRL
F SDF_F_SDF_LOAD_PRIVKEY
F SDF_F_SDF_LOAD_PUBKEY
F SDF_F_SDF_RSA_PRIV_ENC
F SDF_F_SDF_RSA_PRIV_DEC
F SDF_F_SDF_RSA_PUB_ENC
F SDF_F_SDF_RSA_PUB_DEC
F SDF_F_SDF_ECC_SIGN
F SDF_F_SDF_ECC_VERIFY
F SDF_F_SDF_SM2_SIGN
F SDF_F_SDF_SM2_VERIFY
F SDF_F_SDF_SM2_ENCRYPT
F SDF_F_SDF_SM2_DECRYPT
F SDF_F_SDF_RAND_BYTES
F SDF_F_SDF_DIGEST_INIT
F SDF_F_SDF_DIGEST_UPDATE
F SDF_F_SDF_DIGEST_FINAL
F SDF_F_SDF_CIPHER_INIT
F SDF_F_SDF_CIPHER_UPDATE
F SDF_F_SDF_CIPHER_FINAL
F SDF_F_BIND_SDF
F SDF_F_CIPHER_SM4_CBC_CIPHER
F SDF_F_CIPHER_SM4_ECB_CIPHER
F SDF_F_LOAD_KEY

# Reason codes for SDF engine
R SDF_R_ALREADY_LOADED                     already loaded
R SDF_R_BN_CTX_FULL                        bn ctx full
R SDF_R_BN_EXPAND_FAIL                     bn expand fail
R SDF_R_CANT_LOAD_SDF_MODULE               can't load sdf module
R SDF_R_CTRL_COMMAND_NOT_IMPLEMENTED       ctrl command not implemented
R SDF_R_DSO_FAILURE                        dso failure
R SDF_R_ENGINE_IS_NOT_INITIALIZED          engine is not initialized
R SDF_R_FUNCTION_NOT_SUPPORTED             function not supported
R SDF_R_INVALID_ARGUMENT                   invalid argument
R SDF_R_INVALID_DIGEST_LENGTH              invalid digest length
R SDF_R_INVALID_KEY_LENGTH                 invalid key length
R SDF_R_INVALID_OPERATION                  invalid operation
R SDF_R_INVALID_PADDING                    invalid padding
R SDF_R_INVALID_SIGNATURE_LENGTH           invalid signature length
R SDF_R_KEY_NOT_FOUND                      key not found
R SDF_R_MISSING_KEY_COMPONENTS             missing key components
R SDF_R_NOT_LOADED                         not loaded
R SDF_R_NO_MODULUS_OR_NO_EXPONENT          no modulus or no exponent
R SDF_R_OPERATION_NOT_SUPPORTED            operation not supported
R SDF_R_OUTLEN_TO_LARGE                    outlen to large
R SDF_R_REQUEST_FAILED                     request failed
R SDF_R_REQUEST_FALLBACK                   request fallback
R SDF_R_SIZE_TOO_LARGE_OR_TOO_SMALL        size too large or too small
R SDF_R_UNIT_FAILURE                       unit failure
R SDF_R_UNKNOWN_ALGORITHM_TYPE             unknown algorithm type
R SDF_R_UNKNOWN_COMMAND                    unknown command
R SDF_R_UNKNOWN_DIGEST                     unknown digest
R SDF_R_UNKNOWN_PADDING_TYPE               unknown padding type
R SDF_R_UNSUPPORTED_ALGORITHM_NID          unsupported algorithm nid
R SDF_R_UNSUPPORTED_PUBLIC_KEY_ALGORITHM   unsupported public key algorithm
R SDF_R_DEVICE_NOT_FOUND                   device not found
R SDF_R_DEVICE_OPEN_FAILED                 device open failed
R SDF_R_SESSION_OPEN_FAILED                session open failed
R SDF_R_AUTHENTICATION_FAILED              authentication failed
R SDF_R_CONTAINER_NOT_FOUND                container not found
R SDF_R_CERTIFICATE_NOT_FOUND              certificate not found
R SDF_R_PRIVATE_KEY_NOT_FOUND              private key not found
R SDF_R_PUBLIC_KEY_NOT_FOUND               public key not found
R SDF_R_SIGNATURE_VERIFICATION_FAILED      signature verification failed
R SDF_R_ENCRYPTION_FAILED                  encryption failed
R SDF_R_DECRYPTION_FAILED                  decryption failed
R SDF_R_HASH_CALCULATION_FAILED            hash calculation failed
R SDF_R_RANDOM_GENERATION_FAILED           random generation failed
R SDF_R_MEMORY_ALLOCATION_FAILED           memory allocation failed
R SDF_R_INVALID_PARAMETER                  invalid parameter
R SDF_R_BUFFER_TOO_SMALL                   buffer too small
R SDF_R_LIBRARY_NOT_INITIALIZED            library not initialized
R SDF_R_DEVICE_REMOVED                     device removed
R SDF_R_PIN_INCORRECT                      pin incorrect
R SDF_R_PIN_LOCKED                         pin locked
R SDF_R_USER_NOT_LOGGED_IN                 user not logged in
R SDF_R_OPERATION_TIMEOUT                  operation timeout
R SDF_R_HARDWARE_ERROR                     hardware error
R SDF_R_COMMUNICATION_ERROR                communication error
R SDF_R_INTERNAL_ERROR                     internal error
R SDF_R_EXPORT_KEY_FAILED                  export key failed
R SDF_R_INIT_FAILED                        init failed
R SDF_R_NOT_INITIALIZED                    not initialized
R SDF_R_OPEN_DEVICE_FAILED                 open device failed
R SDF_R_OPEN_SESSION_FAILED                open session failed