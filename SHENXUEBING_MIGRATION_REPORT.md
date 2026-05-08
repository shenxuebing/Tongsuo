# shenxuebing migration/dev-v2 分支迁移说明

---

## 一、概况

| 项目 | 内容 |
|------|------|
| **源分支** | `dev` |
| **目标分支** | `migration/dev-v2`（基于 OpenSSL 3.5.4） |
| **作者** | shenxuebing |
| **提交数量** | 21 个 |
| **迁移周期** | 2026-04-28 ~ 2026-05-08 |
| **新增文件** | 33 个 |
| **修改文件** | 47 个 |
| **代码变更** | +14,235 行 / -524 行（净增约 13,700 行） |

---

## 二、迁移时间线

```
2026-04-28  辅助模块 + Engine 框架 + SM2 增强 + NTLS/SDF 核心（7 个提交）
2026-04-29  RC2 恢复 + OID 补全 + Engine 移除 + API 适配 + PKCS7 修复（9 个提交）
2026-05-07  SDF Provider 实现 + ECC-SM2 修复（2 个提交）
2026-05-08  ECDHE-SM2 修复 + 测试 + EVP API（3 个提交）
```

---

## 三、提交明细

### 3.1 基础设施（04-28）

| # | 时间 | 提交 | 说明 |
|---|------|------|------|
| 1 | 12:41 | `779a7fd1e` | 添加辅助功能模块（tlog.h + OID），为后续迁移做准备 |
| 2 | 12:44 | `679dc989e` | 添加 Engine 框架 SM2 回调扩展（临时，后删除） |
| 3 | 12:46 | `16bc0c2d7` | 添加 SDF/SKF 引擎 Engine 实现（临时，后删除） |
| 4 | 12:56 | `d9c099757` | 添加 SM2 算法增强功能（签名/加密/密钥方法） |
| 5 | 13:02 | `5859b07d6` | 添加 ASN1 签名 SM2 NULL 参数（GM/T 0015-2023） |
| 6 | 13:04 | `058ce3d15` | 添加 SM2DHE 密钥协商模块 + RC2 算法文件 |
| 7 | 13:30 | `9c9ad08d1` | 添加 NTLS/SDF 集成核心修改（SSL 层适配） |

### 3.2 适配修复（04-28 ~ 04-29）

| # | 时间 | 提交 | 说明 |
|---|------|------|------|
| 8 | 14:18 | `7d98006c6` | 修复函数签名变更导致的编译错误 |
| 9 | 13:37 | `6f006dac4` | 恢复 RC2 算法支持（上游 3.x 已移除） |
| 10 | 13:37 | `f9eadb192` | 补全 SM1 OID、EC PRIVATEKEY INT、PKCS7 国密命令 |
| 11 | 13:37 | `3cec85783` | **移除** Engine SM2 回调扩展和 SDF/SKF 引擎（-11,878 行） |
| 12 | 13:37 | `081e660d0` | 更新 SM2/ASN1 代码适配最新 API |
| 13 | 15:35 | `489a4125f` | 补全 GM/T 0006 HMAC-SM3 OID (sm3 2) |
| 14 | 16:03 | `24fcac604` | 补全 SM2 Provider C1C2C3 格式支持和 PKCS7 SM2 加密 |
| 15 | 16:08 | `4b646e61c` | 修复 TS 签名/验证的 PKCS7_dataInit no_hash 参数值 |
| 16 | 22:34 | `eab9fe568` | 修复编译链接错误，补全上游缺失的 CMS 函数 |

### 3.3 SDF Provider 实现（05-07 ~ 05-08）

| # | 时间 | 提交 | 说明 |
|---|------|------|------|
| 17 | 05-07 14:06 | `de2def58f` | **新增 SDF Provider 硬件加速模块**（+2,777 行） |
| 18 | 05-07 15:24 | `8aaec4aa5` | 修复 ECC-SM2-SM4-CBC-SM3 套件 + 测试程序 |
| 19 | 05-08 01:01 | `824bd29ce` | 修复 ECDHE-SM2 crash 和密钥不匹配 |
| 20 | 05-08 01:24 | `c0b3e5d94` | 添加软硬交叉认证矩阵测试程序 |
| 21 | 05-08 09:45 | `6267baa19` | 添加 EVP_PKEY_CTX_set_sm2_encdata_format API |

---

## 四、功能模块详解

### 4.1 SDF Provider 硬件加速模块

**核心功能**：基于 OpenSSL 3.0 Provider 架构，通过 SDF 接口对接硬件加密设备（如 byzk0018.dll），使 NTLS/TLCP 协议的 SM2 密码套件能够使用硬件密钥。

#### Provider 注册算法

| 操作 | 算法名 | 功能 |
|------|--------|------|
| KEYMGMT | SM2 | 密钥管理（加载/导入/导出/生成/DUP） |
| SIGNATURE | SM2 | 硬件签名 + 软件验签 |
| ASYM_CIPHER | SM2 | 硬件加解密 |
| KEYEXCH | SM2DH | 4 密钥协商（2 临时 + 2 长期） |
| RAND | SDF-RAND | 硬件随机数 |
| STORE | sdf | 密钥存储加载 |

#### 新增文件（14 个，providers/sdfprov/）

```
providers/sdfprov/
  build.info                  -- 构建配置
  sdfprov_entry.c             -- OSSL_provider_init 入口
  sdfprov.c                   -- Provider 核心（init/query/teardown）
  sdfprov_ctx.h / sdfprov_ctx.c  -- 全局上下文 + 设备生命周期
  sdfprov_internal.h          -- 内部共享定义
  sdfprov_sm2_keymgmt.c       -- SM2 KEYMGMT（696 行）
  sdfprov_sm2_sig.c           -- SM2 SIGNATURE（465 行）
  sdfprov_sm2_asym_cipher.c   -- SM2 ASYM_CIPHER（247 行）
  sdfprov_sm2dh_exch.c        -- SM2DH KEYEXCH（256 行）
  sdfprov_rand.c              -- 硬件随机数
  sdfprov_store.c             -- STORE（URI 加载）
  sdfprov_utils.c / sdfprov_utils.h  -- ECCref<->EC_KEY 格式转换
```

#### 修改的构建系统文件

| 文件 | 修改内容 |
|------|----------|
| `Configure` | 添加 `enable-sdfprov`、`enable-sdf-lib-dynamic` 选项 |
| `providers/build.info` | 添加 sdfprov 子目录、静态库链接 |
| `crypto/provider_predefined.c` | 注册 sdfprov 为预定义 Provider |

#### SSL 密码套件与 Provider 路由

| SSL 操作 | NTLS 调用链 | SDF Provider 拦截 |
|----------|------------|-------------------|
| 服务器签名 | `ntls_statem_srvr.c` → `EVP_DigestSignInit_ex(propq)` | SIGNATURE 操作 |
| 客户端签名 | `ntls_statem_clnt.c` → `EVP_DigestSignInit_ex(propq)` | SIGNATURE 操作 |
| SM2DHE 密钥交换 | `ssl_derive_ntls()` → `EVP_PKEY_derive_init_ex(propq)` | KEYEXCH 操作 |
| SM2 密钥传输 | `tls_construct_cke_pms_ntls()` → `EVP_PKEY_encrypt()` | ASYM_CIPHER 操作 |

---

### 4.2 SM2 算法增强

#### 4.2.1 SM2 核心功能扩展

| 文件 | 修改 | 行数 |
|------|------|------|
| `crypto/sm2/sm2_crypt.c` | SM2 加密增强，C1C2C3 格式支持 | +1,089 |
| `crypto/sm2/sm2_sign.c` | 签名功能增强 | +291 |
| `crypto/sm2/sm2_kmeth.c` | 密钥方法扩展 | +46 |
| `crypto/sm2/sm2_err.c` | 新增错误码 | +37 |
| `include/crypto/sm2.h` | 新增函数声明 | +62 |
| `include/crypto/sm2err.h` | 错误码定义 | +29 |

#### 4.2.2 sm2_encdata_format 参数

新增 `EVP_PKEY_CTX_set_sm2_encdata_format()` API，控制 SM2 加密密文字节排列：

| 值 | 格式 | 说明 |
|----|------|------|
| 0 | C1C3C2 | 新国密标准格式（默认） |
| 1 | C1C2C3 | 旧格式兼容 |

```c
// include/openssl/evp.h + crypto/evp/pmeth_lib.c
int EVP_PKEY_CTX_set_sm2_encdata_format(EVP_PKEY_CTX *ctx, int format);
```

#### 4.2.3 SM2 Provider 适配

| 文件 | 修改内容 |
|------|----------|
| `providers/implementations/asymciphers/sm2_enc.c` | SM2 加密 Provider 支持 C1C2C3 格式 |
| `crypto/ec/ec_ameth.c` | EC AMETH 适配 SM2 参数 |

---

### 4.3 PKCS7 / CMS 修复

#### 4.3.1 PKCS7 国密命令扩展

| 文件 | 修改 | 行数 |
|------|------|------|
| `crypto/pkcs7/pk7_doit.c` | PKCS7 核心操作重构 | +494 |
| `crypto/pkcs7/pk7_smime.c` | S/MIME 扩展 | +447 |
| `crypto/pkcs7/pk7_lib.c` | 库函数增强 | +136 |
| `crypto/pkcs7/pk7_attr.c` | 属性处理 | +54 |
| `crypto/pkcs7/pkcs7err.c` | 新增错误码 | +60 |
| `crypto/pkcs7/pk7_asn1.c` | ASN1 适配 | +11 |
| `crypto/pkcs7/bio_pk7.c` | BIO 接口 | +5 |
| `crypto/pkcs7/pk7_mime.c` | MIME 适配 | +7 |
| `crypto/pkcs7/pk7_local.h` | 内部头文件 | +3 |
| `crypto/pkcs12/p12_crt.c` | PKCS12 兼容 | +7 |
| `crypto/ts/ts_rsp_sign.c` | TS 签名 no_hash 参数修复 | 2 行 |
| `crypto/ts/ts_rsp_verify.c` | TS 验证 no_hash 参数修复 | 2 行 |

#### 4.3.2 CMS 函数补全

| 文件 | 修改 |
|------|------|
| `crypto/cms/cms_lib.c` | 补全上游 OpenSSL 3.5.4 缺失的 CMS 函数实现（+121 行） |

---

### 4.4 NTLS/SDF 集成

#### 4.4.1 NTLS SSL 层适配

| 文件 | 修改内容 |
|------|----------|
| `ssl/s3_lib.c` | SM2 密码套件注册和 Provider 路由 |
| `ssl/ssl_local.h` | 新增内部字段 |
| `ssl/statem_ntls/ntls_statem_clnt.c` | 客户端：ECDHE-SM2 临时密钥生成修复，Provider 检测逻辑 |
| `ssl/statem_ntls/ntls_statem_lib.c` | 通用：密钥加载和协商辅助函数 |
| `ssl/statem_ntls/ntls_statem_srvr.c` | 服务端：签名和密钥交换 Provider 路由 |
| `apps/s_client.c` | s_client NTLS 适配 |

#### 4.4.2 ASN1 签名 SM2 NULL 参数（GM/T 0015-2023）

| 文件 | 修改 |
|------|------|
| `crypto/asn1/a_sign.c` | ASN1 签名中添加 SM2 NULL 参数，遵循 GM/T 0015-2023 |

---

### 4.5 OID 补全

| 文件 | 新增 OID |
|------|----------|
| `crypto/objects/objects.txt` | SM1 算法、HMAC-SM3 (sm3 2)、EC PRIVATEKEY INT、PKCS7 国密命令等 |
| `crypto/objects/obj_dat.h` | OID 数据表 |
| `crypto/objects/obj_mac.h` | OID 宏定义 |
| `crypto/objects/obj_mac.num` | OID 编号 |

**已验证**：migration/dev-v2 分支包含 dev 分支的所有自定义国密 OID。

---

### 4.6 RC2 算法恢复

上游 OpenSSL 3.x 移除了 RC2 算法，为兼容国密应用重新添加。

#### 新增文件（12 个）

```
crypto/rc2/build.info, rc2_cbc.c, rc2_ecb.c, rc2_skey.c,
  rc2_local.h, rc2cfb64.c, rc2ofb64.c
crypto/evp/e_rc2.c
include/openssl/rc2.h
providers/implementations/ciphers/cipher_rc2.h, cipher_rc2_hw.c
test/rc2test.c, test/recipes/05-test_rc2.t
```

#### 修改文件

```
Configure, crypto/build.info, crypto/evp/build.info,
crypto/evp/c_allc.c, crypto/evp/e_old.c, crypto/evp/evp_enc.c,
crypto/evp/evp_pbe.c, crypto/asn1/p5_pbev2.c, crypto/asn1/p5_scrypt.c,
include/openssl/evp.h, include/openssl/core_names.h.in,
providers/implementations/ciphers/build.info,
test/build.info, util/libcrypto.num
```

---

### 4.7 Engine → Provider 迁移

| 阶段 | 提交 | 说明 |
|------|------|------|
| 添加 Engine | `679dc989e` + `16bc0c2d7` | 临时从 dev 分支迁移 Engine 代码（+11,605 行） |
| **移除 Engine** | `3cec85783` | 删除全部 Engine/SDF/SKF 引擎（-11,878 行） |

最终：Engine 框架已移除，硬件加速统一通过 SDF Provider 实现。

---

### 4.8 辅助模块

| 文件 | 功能 |
|------|------|
| `include/internal/tlog.h` | 日志辅助宏 |

---

## 五、测试方法

### 5.1 构建配置

```bash
perl Configure VC-WIN64A no-shared enable-ntls enable-sdfprov \
  enable-sdf-lib-dynamic --with-sdf-include=./include
nmake
```

**注意**：
- 使用 `C:\Perl64\bin\perl.exe`（MSYS2 Perl 缺少模块）
- NTLS 非默认启用，必须 `enable-ntls`

### 5.2 SDF Provider 加载验证

```bash
openssl list -providers -provider sdfprov
```

**预期输出**：
```
sdfprov
  status: active
```

### 5.3 NTLS 软件密钥握手测试

```bash
# 服务器（新窗口）
start "NTLS Server" /min openssl.exe s_server -ntls -enable_ntls -accept 25099 ^
  -sign_cert server_sign.crt -enc_cert server_enc.crt ^
  -sign_key server_sign.key -enc_key server_enc.key ^
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端
openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:25099 ^
  -sign_cert client_sign.crt -enc_cert client_enc.crt ^
  -sign_key client_sign.key -enc_key client_enc.key ^
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

**预期输出**：`Cipher is ECC-SM2-SM4-GCM-SM3` 或 `Cipher is ECC-SM2-SM4-CBC-SM3`

### 5.4 NTLS SDF 硬件密钥握手测试

#### 前置条件
- byzk0018.dll（64 位）在运行目录或 PATH 中
- yj.db 和 softModule.ini 拷贝到运行目录
- SM2 双证书（签名 + 加密）在运行目录

#### 服务器 SDF 密钥 + 客户端软件密钥

```bash
# 服务器（新窗口，SDF 硬件密钥）
start "NTLS SDF Server" /min openssl.exe s_server -ntls -enable_ntls -accept 24930 ^
  -sign_cert server_sign.crt -enc_cert server_enc.crt ^
  -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" ^
  -provider sdfprov -provider default ^
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端（软件密钥）
openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:24930 ^
  -sign_cert client_sign.crt -enc_cert client_enc.crt ^
  -sign_key client_sign.key -enc_key client_enc.key ^
  -provider sdfprov -provider default ^
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

### 5.5 测试脚本

| 脚本 | 说明 | 套件 | 服务器密钥 | 客户端密钥 |
|------|------|------|------------|------------|
| `apps/test_ntls.bat` | 基础软件握手 | ECC-SM2-SM4-CBC-SM3 | PEM 软件密钥 | PEM 软件密钥 |
| `apps/test_ecc_sdf.bat` | SDF 硬件握手 | ECC-SM2-SM4-CBC-SM3 | SDF 硬件密钥 | PEM 软件密钥 |
| `apps/test_both_ciphersuites.c` | 矩阵测试 | ECC-SM2 + ECDHE-SM2 | 4 种组合 | 4 种组合 |

#### 矩阵测试组合

| # | 服务器密钥 | 客户端密钥 | 套件 |
|---|------------|------------|------|
| 1 | 软件密钥 | 软件密钥 | ECC-SM2-SM4-CBC-SM3 |
| 2 | 软件密钥 | 硬件密钥 | ECC-SM2-SM4-CBC-SM3 |
| 3 | 硬件密钥 | 软件密钥 | ECC-SM2-SM4-CBC-SM3 |
| 4 | 硬件密钥 | 硬件密钥 | ECC-SM2-SM4-CBC-SM3 |
| 5 | 软件密钥 | 软件密钥 | ECDHE-SM2-SM4-CBC-SM3 |
| 6 | 软件密钥 | 硬件密钥 | ECDHE-SM2-SM4-CBC-SM3 |
| 7 | 硬件密钥 | 软件密钥 | ECDHE-SM2-SM4-CBC-SM3 |
| 8 | 硬件密钥 | 硬件密钥 | ECDHE-SM2-SM4-CBC-SM3 |

### 5.6 RC2 算法测试

```bash
openssl enc -rc2-cbc -k test123 -in testfile -out testfile.rc2
openssl enc -rc2-cbc -d -k test123 -in testfile.rc2 -out testfile.dec
```

或运行测试套件：
```bash
nmake test TESTS=test_rc2
```

### 5.7 SM2 C1C2C3 格式测试

```bash
# 使用 C1C2C3 旧格式加密
openssl pkeyutl -encrypt -pubin -inkey sm2_pub.pem -in msg.txt -out msg.enc \
  -pkeyopt sm2_encdata_format:1

# 使用 C1C3C2 新格式加密（默认）
openssl pkeyutl -encrypt -pubin -inkey sm2_pub.pem -in msg.txt -out msg.enc
```

---

## 六、影响文件完整清单

### 6.1 新增文件（33 个）

```
# SDF Provider (14)
providers/sdfprov/build.info
providers/sdfprov/sdfprov.c
providers/sdfprov/sdfprov_ctx.c
providers/sdfprov/sdfprov_ctx.h
providers/sdfprov/sdfprov_entry.c
providers/sdfprov/sdfprov_internal.h
providers/sdfprov/sdfprov_rand.c
providers/sdfprov/sdfprov_sm2_asym_cipher.c
providers/sdfprov/sdfprov_sm2_keymgmt.c
providers/sdfprov/sdfprov_sm2_sig.c
providers/sdfprov/sdfprov_sm2dh_exch.c
providers/sdfprov/sdfprov_store.c
providers/sdfprov/sdfprov_utils.c
providers/sdfprov/sdfprov_utils.h

# RC2 (12)
crypto/rc2/build.info, rc2_cbc.c, rc2_ecb.c, rc2_skey.c,
  rc2_local.h, rc2cfb64.c, rc2ofb64.c
crypto/evp/e_rc2.c
include/openssl/rc2.h
providers/implementations/ciphers/cipher_rc2.h
providers/implementations/ciphers/cipher_rc2_hw.c
test/rc2test.c, test/recipes/05-test_rc2.t

# 辅助
include/internal/tlog.h

# 测试程序
apps/test_both_ciphersuites.c
apps/test_ntls_sdf.c
apps/test_sdf_enc_dec.c
test_sdf_provider.c
```

### 6.2 修改文件（47 个）

```
# SM2 核心 (6)
crypto/sm2/sm2_crypt.c, sm2_sign.c, sm2_kmeth.c, sm2_err.c
include/crypto/sm2.h, include/crypto/sm2err.h

# EVP (5)
crypto/evp/pmeth_lib.c, c_allc.c, e_old.c, evp_enc.c, evp_pbe.c
include/openssl/evp.h

# ASN1 (3)
crypto/asn1/a_sign.c, p5_pbev2.c, p5_scrypt.c

# EC (2)
crypto/ec/ec_ameth.c, ec_asn1.c

# PKCS7/CMS (10)
crypto/pkcs7/pk7_asn1.c, pk7_attr.c, pk7_doit.c, pk7_lib.c,
  pk7_local.h, pk7_mime.c, pk7_smime.c, pkcs7err.c, bio_pk7.c
crypto/cms/cms_lib.c
crypto/pkcs12/p12_crt.c

# 时间戳 (2)
crypto/ts/ts_rsp_sign.c, ts_rsp_verify.c

# SDF 框架 (4)
crypto/sdf/sdf_lib.c, sdf_local.h, sdf_meth.c
include/openssl/sdf.h
crypto/tsapi/tsapi_lib.c

# NTLS SSL (3)
ssl/statem_ntls/ntls_statem_clnt.c, ntls_statem_lib.c, ntls_statem_srvr.c

# SSL 核心 (2)
ssl/s3_lib.c, ssl/ssl_local.h

# Provider (2)
providers/implementations/asymciphers/sm2_enc.c
providers/smtc/self_test_kats.c

# 对象/OID (4)
crypto/objects/obj_dat.h, obj_mac.h, obj_mac.num, objects.txt
include/openssl/pkcs7err.h

# 构建 (2)
Configure, crypto/provider_predefined.c

# 应用 (3)
apps/s_client.c, apps/list.c, apps/pkcs7.c

# 测试 (2)
test/tsapi_test.c, test/sm2_internal_test.c

# 其他
crypto/build.info, crypto/evp/build.info
include/openssl/core_names.h.in
providers/build.info, providers/implementations/ciphers/build.info
crypto/tsapi/build.info, test/build.info
util/libcrypto.num
```

---

## 七、测试状态

| 功能 | 状态 | 说明 |
|------|------|------|
| SDF Provider 加载 | **PASS** | `openssl list -providers` 可见 sdfprov |
| SM2 硬件签名/验签 | **PASS** | 通过 SDF 设备签名，软件验签 |
| SM2 硬件加解密 | **PASS** | C1C3C2 和 C1C2C3 两种格式 |
| SM2 C1C2C3 格式 | **PASS** | sm2_encdata_format 参数 |
| NTLS ECC-SM2 软件握手 | **PASS** | 全软件密钥 |
| NTLS ECC-SM2 SDF 硬件握手 | **PASS** | SDF 服务器 + 软件客户端 |
| NTLS ECDHE-SM2 握手 | **修复中** | 临时密钥跨 Provider 问题 |
| RC2 算法 | **PASS** | CBC/ECB/CFB/OFB 模式 |
| 自定义 OID | **PASS** | 所有 dev 分支 OID 已确认存在 |
| PKCS7 国密命令 | **PASS** | 编译通过 |
| CMS 函数补全 | **PASS** | 编译链接通过 |
| ASN1 SM2 NULL 参数 | **PASS** | GM/T 0015-2023 合规 |

---

## 八、已知问题

1. **ECDHE-SM2 软硬件交叉认证**：KEYMGMT export 函数跨 Provider 调用时存在兼容性问题，正在修复
2. **NTLS 非默认启用**：构建时需显式 `enable-ntls`
3. **硬件密钥测试**：依赖 byzk0018.dll 和 SDF 硬件模块

---

**文档版本**: 1.0
**生成日期**: 2026-05-08
**目标分支**: migration/dev-v2
**作者**: shenxuebing
**提交数量**: 21 个
