# shenxuebing 代码迁移说明文档

## 概述

本文档仅记录 `shenxuebing` 从 `dev` 分支迁移到 `migration/dev-v2` 分支的代码修改内容，不包含上游 OpenSSL 的其他功能迁移。

## 分支信息

- **源分支**: `dev`
- **目标分支**: `migration/dev-v2`
- **作者**: `shenxuebing`
- **提交数量**: 19 个提交

## shenxuebing 修改内容

### 一、最新迁移（NTLS/SDF Provider 相关）

#### 1.1 EVP Helper API
- **提交**: 6267baa19
- **文件**: `include/openssl/evp.h`, `crypto/evp/pmeth_lib.c`
- **新增**: `EVP_PKEY_CTX_set_sm2_encdata_format` 函数
- **功能**: 设置 SM2 加密数据格式（0=C1C2C3, 1=C1C3C2）
- **验证**: 输入参数验证，通过 EVP_PKEY_CTX_set_params 设置参数
- **代码**:
  ```c
  int EVP_PKEY_CTX_set_sm2_encdata_format(EVP_PKEY_CTX *ctx, int format)
  {
      OSSL_PARAM params[2];

      if (format != 0 && format != 1) {
          ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE);
          return 0;
      }

      params[0] = OSSL_PARAM_construct_int("sm2_encdata_format", &format);
      params[1] = OSSL_PARAM_construct_end();

      return EVP_PKEY_CTX_set_params(ctx, params);
  }
  ```

#### 1.2 软硬交叉认证矩阵测试
- **提交**: c0b3e5d94
- **文件**: `apps/test_both_ciphersuites.c`
- **功能**: 支持 4 种服务器/客户端软硬密钥加载组合的矩阵测试
- **测试套件**: ECC-SM2-SM4-CBC-SM3 和 ECDHE-SM2-SM4-CBC-SM3
- **组合配置**:
  - 服务器软密钥 + 客户端软密钥
  - 服务器软密钥 + 客户端硬密钥
  - 服务器硬密钥 + 客户端软密钥
  - 服务器硬密钥 + 客户端硬密钥

#### 1.3 ECDHE-SM2 客户端临时密钥生成修复
- **提交**: 824bd29ce
- **文件**: `ssl/statem_ntls/ntls_statem_clnt.c`
- **函数**: `tls_construct_cke_sm2dhe_ntls`
- **修复**: 
  - 添加 Provider 检测逻辑
  - 仅在本地加密密钥为软件密钥时生成软件临时密钥
  - 修复软硬交叉认证握手失败问题
- **代码逻辑**:
  ```c
  local_enc = s->cert->pkeys[SSL_PKEY_SM2_ENC].privatekey;
  if (local_enc != NULL) {
      const OSSL_PROVIDER *p = EVP_PKEY_get0_provider(local_enc);
      const char *prov_name = p != NULL ? OSSL_PROVIDER_get0_name(p) : NULL;

      if (prov_name == NULL || OPENSSL_strcasecmp(prov_name, "default") == 0) {
          // 生成软件 SM2 临时密钥
      }
      // 否则使用硬件 Provider 临时密钥
  }
  ```

#### 1.4 SDF Provider ECC-SM2 套件修复
- **提交**: 8aaec4aa5
- **文件**: SDF Provider 相关文件
- **修复**: ECC-SM2-SM4-CBC-SM3 套件
- **新增**: 
  - uiAlgID 参数
  - 私钥访问控制码支持
- **目的**: 完善 SDF Provider 对 ECC-SM2-SM4-CBC-SM3 套件的支持

#### 1.5 SDF Provider 硬件加速模块
- **提交**: de2def58f
- **功能**: 新增 SDF Provider 硬件加速模块
- **目的**: 支持 SDF 硬件加速，提升性能

### 二、SM2/ASN1 代码适配

#### 2.1 SM2/ASN1 API 适配
- **提交**: 081e660d0
- **文件**: SM2/ASN1 相关文件
- **修复**: 更新 SM2/ASN1 代码适配最新 API
- **目的**: 确保代码与最新 OpenSSL API 兼容

#### 2.2 函数签名变更修复
- **提交**: 7d98006c6
- **修复**: 修复函数签名变更导致的编译错误
- **原因**: 上游 API 变更导致函数签名不匹配

### 三、SM2 Provider 完善和补全

#### 3.1 SM2 C1C2C3 格式支持
- **提交**: 24fcac604
- **文件**: SM2 Provider 相关文件
- **补全**: SM2 Provider C1C2C3 格式支持
- **新增**: PKCS7 SM2 加密支持
- **目的**: 支持新的 SM2 加密数据格式

#### 3.2 GM/T 0006 HMAC-SM3 OID
- **提交**: 489a4125f
- **文件**: OID 相关文件
- **补全**: GM/T 0006 HMAC-SM3 OID (sm3 2)
- **目的**: 支持国密标准 GM/T 0006 定义的 HMAC-SM3

#### 3.3 SM1 OID 和国密命令
- **提交**: f9eadb192
- **补全**: 
  - SM1 OID
  - EC PRIVATEKEY INT
  - PKCS7 国密命令
- **目的**: 完善国密算法和协议的 OID 支持

### 四、PKCS7 和 CMS 函数

#### 4.1 CMS 函数补全
- **提交**: eab9fe568
- **修复**: 修复编译链接错误，补全上游缺失的 CMS 函数
- **目的**: 解决编译链接问题，补全缺失的 CMS 函数实现

#### 4.2 PKCS7_dataInit no_hash 参数
- **提交**: 4b646e61c
- **修复**: 修复 TS 签名/验证的 PKCS7_dataInit no_hash 参数值
- **目的**: 正确设置 PKCS7_dataInit 的 no_hash 参数

### 五、NTLS/SDF 集成

#### 5.1 NTLS/SDF 集成核心修改
- **提交**: 9c9ad08d1
- **功能**: 添加 NTLS/SDF 集成核心修改
- **目的**: 实现 NTLS 协议与 SDF Provider 的集成

#### 5.2 SM2DHE 密钥协商模块
- **提交**: 058ce3d15
- **功能**: 添加 SM2DHE 密钥协商模块
- **目的**: 支持 SM2 临时密钥交换（ECDHE-SM2）

#### 5.3 ASN1 签名 SM2 NULL 参数
- **提交**: 5859b07d6
- **修改**: 添加 ASN1 签名 SM2 NULL 参数修改（GM/T 0015-2023）
- **目的**: 遵循国密标准 GM/T 0015-2023

#### 5.4 SM2 算法增强功能
- **提交**: d9c099757
- **功能**: 添加 SM2 算法增强功能
- **目的**: 增强 SM2 算法的功能和性能

### 六、Engine 框架（已迁移到 Provider）

#### 6.1 Engine 框架 SM2 回调扩展
- **提交**: 679dc989e
- **功能**: 添加 Engine 框架 SM2 回调扩展
- **目的**: 支持 Engine 方式的 SM2 回调

#### 6.2 SDF/SKF 引擎
- **提交**: 16bc0c2d7
- **功能**: 添加 SDF/SKF 引擎（Engine 方式）
- **目的**: 支持 SDF/SKF 硬件模块的 Engine 方式

#### 6.3 移除 Engine SM2 回调扩展
- **提交**: 3cec85783
- **重构**: 移除 Engine SM2 回调扩展和 SDF/SKF 引擎
- **原因**: 已迁移到 Provider 架构，Engine 方式不再需要
- **目的**: 清理旧的 Engine 实现，统一使用 Provider

### 七、辅助功能模块

#### 7.1 辅助功能模块
- **提交**: 779a7fd1e
- **新增**: 添加辅助功能模块（tlog.h + OID）
- **目的**: 提供日志和 OID 辅助功能

### 八、RC2 算法

#### 8.1 恢复 RC2 算法支持
- **提交**: 6f006dac4
- **功能**: 恢复 RC2 算法支持
- **原因**: 上游移除了 RC2，但国密应用可能需要
- **目的**: 保持对 RC2 算法的兼容性

## 修改文件清单

### 头文件
- `include/openssl/evp.h` - 新增 EVP_PKEY_CTX_set_sm2_encdata_format 声明

### 源文件
- `crypto/evp/pmeth_lib.c` - 实现 EVP_PKEY_CTX_set_sm2_encdata_format
- `apps/test_both_ciphersuites.c` - 软硬交叉认证矩阵测试
- `ssl/statem_ntls/ntls_statem_clnt.c` - ECDHE-SM2 客户端临时密钥生成修复
- SM2/ASN1 相关文件 - API 适配
- SM2 Provider 相关文件 - C1C2C3 格式支持
- SDF Provider 相关文件 - ECC-SM2 套件修复、硬件加速模块
- PKCS7/CMS 相关文件 - 函数补全和参数修复
- NTLS/SDF 集成相关文件 - 核心集成修改
- OID 相关文件 - SM1、HMAC-SM3 等 OID 补全
- 辅助模块 - tlog.h + OID

## 功能分类总结

### 1. NTLS/SDF 集成（5 个提交）
- NTLS/SDF 集成核心修改
- SM2DHE 密钥协商模块
- ASN1 签名 SM2 NULL 参数修改
- SM2 算法增强功能
- SDF Provider 硬件加速模块
- SDF Provider ECC-SM2 套件修复

### 2. 测试（1 个提交）
- 软硬交叉认证矩阵测试

### 3. SM2 完善（4 个提交）
- SM2/ASN1 API 适配
- SM2 C1C2C3 格式支持
- GM/T 0006 HMAC-SM3 OID
- SM1 OID 和国密命令
- EVP Helper API

### 4. PKCS7/CMS（2 个提交）
- CMS 函数补全
- PKCS7_dataInit no_hash 参数修复

### 5. Engine 到 Provider 迁移（3 个提交）
- Engine 框架 SM2 回调扩展（已移除）
- SDF/SKF 引擎（已移除）
- 移除 Engine 实现

### 6. 辅助功能（1 个提交）
- 辅助功能模块（tlog.h + OID）

### 7. 兼容性（2 个提交）
- 函数签名变更修复
- 恢复 RC2 算法支持

## 测试方法

### 1. 自定义测试程序

#### 测试程序: `apps/test_both_ciphersuites.c`

**编译**:
```bash
cd apps
# 使用现有构建脚本或手动编译
cl test_both_ciphersuites.c /I..\include /I..\apps\include ..\libssl-3.lib ..\libcrypto-3.lib
```

**运行**:
```bash
cd apps
.\test_both_ciphersuites.exe
```

**输出**:
- 测试所有 4 种软硬组合
- 测试两个套件（ECC-SM2-SM4-CBC-SM3 和 ECDHE-SM2-SM4-CBC-SM3）
- 报告每个组合的成功/失败

### 2. s_server/s_client 测试

**注意**: 当前构建可能需要启用 NTLS 支持。使用 `apps/` 目录中的测试脚本。

#### 可用测试脚本:

1. **test_ntls.bat** - 基础 NTLS 软件密钥测试
   - 服务器: PEM 软件密钥
   - 客户端: PEM 软件密钥
   - 端口: 25099

2. **test_ecc_sm2.bat** - ECC-SM2 硬件密钥测试
   - 服务器: SDF 硬件密钥 (byzk0018.dll)
   - 客户端: PEM 软件密钥
   - 端口: 24930
   - 套件: ECC-SM2-SM4-CBC-SM3

3. **test_ecc_sdf_correct.bat** - SDF 硬件密钥测试
   - 服务器: SDF 硬件密钥
   - 客户端: 外部证书目录的 PEM 软件密钥
   - 端口: 24970
   - 套件: ECC-SM2-SM4-CBC-SM3

#### 运行测试:
```bash
cd apps
.\test_ntls.bat
.\test_ecc_sm2.bat
.\test_ecc_sdf_correct.bat
```

### 3. 手动 s_server/s_client 命令

#### 服务器（软件密钥）:
```bash
openssl s_server -ntls -enable_ntls -accept 25099 \
  -sign_cert server_sign.crt -enc_cert server_enc.crt \
  -sign_key server_sign.key -enc_key server_enc.key \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 服务器（SDF 硬件密钥）:
```bash
openssl s_server -ntls -enable_ntls -accept 24930 \
  -sign_cert server_sign.crt -enc_cert server_enc.crt \
  -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" \
  -provider sdfprov -provider default \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 客户端（软件密钥）:
```bash
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25099 \
  -sign_cert client_sign.crt -enc_cert client_enc.crt \
  -sign_key client_sign.key -enc_key client_enc.key \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 客户端（SDF 硬件密钥）:
```bash
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:24930 \
  -sign_cert client_sign.crt -enc_cert client_enc.crt \
  -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" \
  -provider sdfprov -provider default \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

## 构建要求

### 前置条件
- Visual Studio 2022（或兼容版本）
- SDF 硬件模块（用于硬件密钥测试）
- byzk0018.dll（SDF provider DLL）

### 构建命令
```bash
# 配置启用 NTLS 支持
perl Configure VC-WIN64 --enable-ntls

# 构建
nmake
```

## 已知问题

1. **s_server/s_client NTLS 支持**: 当前构建可能默认未启用 NTLS。需要使用 `--enable-ntls` 重新配置。
2. **硬件密钥测试**: 需要 SDF 硬件模块和正确配置。

## 参考资料

- NTLS 协议规范
- SM2 密码标准
- SDF Provider 文档
- OpenSSL Provider 架构
- GM/T 0006 (HMAC-SM3)
- GM/T 0015-2023 (SM2 NULL 参数)

---

**文档版本**: 1.0  
**最后更新**: 2026-05-08  
**迁移分支**: migration/dev-v2  
**作者**: shenxuebing  
**提交数量**: 19 个提交
