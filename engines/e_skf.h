/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

/*
 * SKF Engine for GMT 0016-2023 Smart Key Interface
 * Public API
 */

#ifndef HEADER_E_SKF_H
#define HEADER_E_SKF_H

#include <openssl/opensslconf.h>
#include <openssl/engine.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 初始化 SKF 引擎 */
void ENGINE_load_skf(void);

/* 为 nginx/angie 设置 SKF 引擎 */
int skf_engine_setup_for_nginx(const char *lib_path, const char *device_name,
                               const char *app_name, const char *pin);

/* SKF 配置结构体 */
typedef struct SKF_CONFIG_st SKF_CONFIG;

/* 创建和释放 SKF 配置 */
SKF_CONFIG *skf_config_new(void);
void skf_config_free(SKF_CONFIG *config);

/* 设置 SKF 配置参数 */
int skf_config_set_library(SKF_CONFIG *config, const char *lib_path);
int skf_config_set_device(SKF_CONFIG *config, const char *device_name);
int skf_config_set_application(SKF_CONFIG *config, const char *app_name);
int skf_config_set_container(SKF_CONFIG *config, const char *container_name);
int skf_config_set_pin(SKF_CONFIG *config, const char *pin);

/* 加载和配置 SKF 引擎 */
ENGINE *skf_engine_load_and_configure(SKF_CONFIG *config);

/* 创建和释放带有 SKF 引擎的 SSL 上下文 */
SSL_CTX *skf_ssl_ctx_new_with_engine(SKF_CONFIG *config, const SSL_METHOD *method);
void skf_ssl_ctx_free_with_engine(SSL_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HEADER_E_SKF_H */