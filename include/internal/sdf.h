/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_INTERNAL_SDF_H
# define OSSL_INTERNAL_SDF_H
# pragma once

int ossl_sdf_lib_preload(const char *path, const char *password,
                         int use_load_module);
void ossl_sdf_lib_cleanup(void);

/*
 * 获取 DSO 动态绑定的 SDF_METHOD 函数指针表。
 * 返回厂商库已加载时的 sdfm（含 SWCSM_ 等扩展接口绑定），
 * 未加载时返回 NULL。供 SDFE_* stub 转发使用（跨翻译单元访问 sdfm）。
 */
const struct sdf_method_st *ossl_sdf_get_method(void);

#endif
