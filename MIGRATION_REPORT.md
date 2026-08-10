# Tongsuo migration/dev-v2 分支完整迁移报告

---

## 一、项目概况

| 项目 | 内容 |
|------|------|
| **源分支** | `dev` (Tongsuo 8.x) |
| **目标分支** | `migration/dev-v2` |
| **基础版本** | OpenSSL 3.5.4 (commit 65f8038fc0dbe6816d6a982222e46e53729cb435) |
| **迁移周期** | 2026-01-06 ~ 2026-05-08 |
| **总提交数** | 303 个 |
| **参与人数** | 15 人 |
| **主要贡献者** | Jin Jiu (96), pr000000f (70), K1 (52), Paul Yang (30), shenxuebing (21) |
| **shenxuebing 提交数** | 21 个 (含 2 个后续修复提交) |
| **新增文件** | 33 个 |
| **修改文件** | 47 个 |
| **总代码变更** | +14,235 行 / -524 行 |

---

## 二、迁移时间线

### 阶段一：基础框架导入（2026-01-06 ~ 2026-01-08）

导入 OpenSSL 3.5.4 上游代码，并迁移核心国密算法：

| 日期 | 内容 | 提交者 |
|------|------|--------|
| 2026-01-06 | 导入 OpenSSL 3.5.4 基础代码 | - |
| 2026-01-06 | 添加 ZUC 流密码（zuc-128-eea3） | K1 |
| 2026-01-06 | 支持 EC-ElGamal 同态加密算法 | K1 |
| 2026-01-06 | 移除 SPARC/PA-RISC 架构代码 | K1 |
| 2026-01-06 | 支持 SM2 legacy 选项 | K1 |
| 2026-01-07 | 支持 TLCP 和 GM/T 0024-2014 | Paul Yang |
| 2026-01-07 | 添加 SSL_set_skip_scsv API | Paul Yang |
| 2026-01-08 | 支持 SM3 DRBG (GM/T 0105-2021) | Paul Yang |
| 2026-01-08 | apps/speed 添加 SM3/4、EC-ElGamal 基准测试 | Paul Yang |

### 阶段二：ZKP 算法迁移（2026-01-08 ~ 2026-01-15）

迁移零知识证明相关算法：

| 日期 | 内容 | 提交者 |
|------|------|--------|
| 2026-01-08 | 添加 Bulletproofs 范围证明 | Jin Jiu |
| 2026-01-08 | 添加 NIZKPoK 非交互式零知识证明 | Jin Jiu |
| 2026-01-08 | 添加 Paillier 同态加密 | Jin Jiu |
| 2026-01-08 | 添加 BIGNUM 方法机制 | Jin Jiu |
| 2026-01-09 | 添加 Twisted-EC-ElGamal | Jin Jiu |
| 2026-01-10 | 添加 EC_POINT_from_string | Jin Jiu |
| 2026-01-15 | 添加 ZKP 性能测试和 bug 修复 | Jin Jiu |

### 阶段三：TLS/SSL 功能增强（2026-01-15 ~ 2026-02-06）

迁移 TLS 1.3 RFC 8998、NTLS 修复、证书验证增强等：

| 日期 | 内容 | 提交者 |
|------|------|--------|
| 2026-01-15 | 实现 RFC 8998 TLS 1.3 商密套件 | K1 |
| 2026-01-15 | 使用 ssl3_cbc_digest_record 计算 HMAC_SM3 | K1 |
| 2026-01-15 | 添加 X509 上下文验证接口 | K1 |
| 2026-01-15 | 支持 SSL_CTX_dup | Paul Yang |
| 2026-01-15 | 添加 Delegated Credentials 支持 | K1 |
| 2026-01-16 | 添加 NTLS force-ntls 配置选项 | K1 |
| 2026-01-16 | 修复 NTLS 编译问题 | K1 |
| 2026-01-19 | 添加 SM2 阈值签名和加密 | Jin Jiu |
| 2026-01-19 | 添加白盒 SM4 (wbsm4-xiaolai/baiwu/wsise) | Jin Jiu |
| 2026-02-06 | 使用 Tongsuo 原始 ecp_sm2p256 实现 | pr000000f |
| 2026-02-06 | SM2 快速模约简和 64 位优化 | pr000000f |

### 阶段四：SM2MLKEM768 和优化（2026-02-06 ~ 2026-03-23）

| 日期 | 内容 | 提交者 |
|------|------|--------|
| 2026-02-10 | 实现 SM2MLKEM768 算法 | pr000000f |
| 2026-02-12 | 修复 speed.c bug | pr000000f |
| 2026-03-05 | 添加握手 RTT 打印功能 | pr000000f |
| 2026-03-16 | 准备 8.5.0-pre1 版本 | pr000000f |
| 2026-03-19 | 修复 macOS CI 偶发失败 | pr000000f |
| 2026-03-23 | 更新 CHANGES.md 和 README.md | pr000000f |

### 阶段五：shenxuebing 国密集成迁移（2026-04-28 ~ 2026-05-08）

**shenxuebing 的核心迁移工作**，将 dev 分支的 NTLS/SDF 集成功能迁移到 Provider 架构：

| 日期 | 提交 | 内容 | 分类 |
|------|------|------|------|
| 04-28 12:41 | `779a7fd1e` | 添加辅助功能模块（tlog.h + OID） | 辅助模块 |
| 04-28 12:44 | `679dc989e` | 添加 Engine 框架 SM2 回调扩展 | Engine |
| 04-28 12:46 | `16bc0c2d7` | 添加 SDF/SKF 引擎（Engine 方式） | Engine |
| 04-28 12:56 | `d9c099757` | 添加 SM2 算法增强功能 | SM2 增强 |
| 04-28 13:02 | `5859b07d6` | 添加 ASN1 签名 SM2 NULL 参数（GM/T 0015-2023） | NTLS |
| 04-28 13:04 | `058ce3d15` | 添加 SM2DHE 密钥协商模块 | NTLS |
| 04-28 13:30 | `9c9ad08d1` | 添加 NTLS/SDF 集成核心修改 | NTLS |
| 04-28 14:18 | `7d98006c6` | 修复函数签名变更导致的编译错误 | Bug 修复 |
| 04-29 13:37 | `6f006dac4` | 恢复 RC2 算法支持 | 兼容性 |
| 04-29 13:37 | `f9eadb192` | 补全 SM1 OID、EC PRIVATEKEY INT 和 PKCS7 国密命令 | OID |
| 04-29 13:37 | `3cec85783` | 移除 Engine SM2 回调扩展和 SDF/SKF 引擎 | 重构 |
| 04-29 13:37 | `081e660d0` | 更新 SM2/ASN1 代码适配最新 API | 适配 |
| 04-29 15:35 | `489a4125f` | 补全 GM/T 0006 HMAC-SM3 OID (sm3 2) | OID |
| 04-29 16:03 | `24fcac604` | 补全 SM2 Provider C1C2C3 格式支持和 PKCS7 SM2 加密 | SM2 |
| 04-29 16:08 | `4b646e61c` | 修复 TS 签名/验证的 PKCS7_dataInit no_hash 参数值 | Bug 修复 |
| 04-29 22:34 | `eab9fe568` | 修复编译链接错误，补全上游缺失的 CMS 函数 | Bug 修复 |
| 05-07 14:06 | `de2def58f` | **新增 SDF Provider 硬件加速模块** | SDF Provider |
| 05-07 15:24 | `8aaec4aa5` | 修复 ECC-SM2-SM4-CBC-SM3 套件 (uiAlgID + 控制码) | SDF Provider |
| 05-08 01:01 | `824bd29ce` | 修复 ECDHE-SM2 crash 和密钥不匹配 | SDF Provider |
| 05-08 01:24 | `c0b3e5d94` | 添加软硬交叉认证矩阵测试 | 测试 |
| 05-08 09:45 | `6267baa19` | 添加 EVP_PKEY_CTX_set_sm2_encdata_format API | API |

---

## 三、功能分类详述

### 3.1 SDF Provider 硬件加速（shenxuebing，核心新增）

#### 3.1.1 功能概述

基于 OpenSSL 3.0 Provider 架构，实现 SDF 硬件加密设备的 Provider 接口，使 NTLS（TLCP）协议的 SM2 密码套件能够使用硬件密钥进行 SSL 握手。

#### 3.1.2 Provider 注册算法

| 操作类型 | 算法名称 | 功能说明 |
|----------|----------|----------|
| OSSL_OP_KEYMGMT | SM2 | SM2 密钥管理（导入/导出/生成/DUP） |
| OSSL_OP_SIGNATURE | SM2 | SM2 签名/验签（硬件签名 + 软件验签） |
| OSSL_OP_ASYM_CIPHER | SM2 | SM2 加解密（硬件加解密） |
| OSSL_OP_KEYEXCH | SM2DH | SM2DH 4 密钥协商 |
| OSSL_OP_RAND | SDF-RAND | 硬件随机数生成 |
| OSSL_OP_STORE | sdf | 密钥存储加载（URI: `sdf:key=<idx>;type=<sign\|enc>`） |

#### 3.1.3 新增文件清单（providers/sdfprov/）

| 文件 | 行数 | 功能 |
|------|------|------|
| `sdfprov_entry.c` | ~50 | OSSL_provider_init 入口 |
| `sdfprov.c` | ~300 | Provider 核心: init/query/teardown/get_params |
| `sdfprov_ctx.h` | ~40 | SDFPROV_CTX 全局上下文定义 |
| `sdfprov_ctx.c` | ~200 | 设备/会话生命周期管理 |
| `sdfprov_sm2_keymgmt.c` | ~700 | SM2 KEYMGMT 实现 |
| `sdfprov_sm2_sig.c` | ~350 | SM2 SIGNATURE（硬件签名） |
| `sdfprov_sm2_asym_cipher.c` | ~300 | SM2 ASYM_CIPHER（硬件加解密） |
| `sdfprov_sm2dh_exch.c` | ~260 | SM2DH KEYEXCH（4 密钥协商） |
| `sdfprov_rand.c` | ~100 | 硬件随机数 |
| `sdfprov_store.c` | ~200 | STORE（密钥加载） |
| `sdfprov_utils.c` | ~350 | ECCref<->EC_KEY 格式转换 |
| `sdfprov_utils.h` | ~40 | 工具函数声明 |
| `sdfprov_internal.h` | ~60 | 内部共享定义 |
| `build.info` | ~15 | 构建配置 |

#### 3.1.4 SSL 密码套件支持路由

| SSL 操作 | 调用链 | SDF Provider 拦截点 |
|----------|--------|-------------------|
| 服务器签名 | `ntls_statem_srvr.c` → `EVP_DigestSignInit_ex(propq)` | SIGNATURE 操作 |
| 客户端签名 | `ntls_statem_clnt.c` → `EVP_DigestSignInit_ex(propq)` | SIGNATURE 操作 |
| SM2DHE 密钥交换 | `ssl_derive_ntls()` → `EVP_PKEY_derive_init_ex(propq)` | KEYEXCH 操作 |
| SM2 密钥传输 | `tls_construct_cke_pms_ntls()` → `EVP_PKEY_encrypt()` | ASYM_CIPHER 操作 |

---

### 3.2 NTLS/SDF 集成（shenxuebing）

#### 3.2.1 NTLS 状态机增强

| 文件 | 修改内容 |
|------|----------|
| `ssl/statem_ntls/ntls_statem_clnt.c` | ECDHE-SM2 客户端临时密钥生成修复；添加 Provider 检测逻辑，仅在本地加密密钥为软件密钥时生成软件临时密钥 |
| `ssl/statem_ntls/ntls_statem_srvr.c` | 服务端签名/密钥交换 Provider 路由 |
| `ssl/statem_ntls/ntls_statem_lib.c` | NTLS 通用库函数适配 |

#### 3.2.2 SM2DHE 密钥协商

- **文件**: `providers/implementations/exchange/sm2dh_exch.c`
- **功能**: 4 密钥协商（2 临时 ECDHE + 2 长期加密证书）
- **参数**: SELF_ID, PEER_ID, SELF_ENC_KEY, PEER_ENC_KEY
- **关键修复**: `SM2_compute_key()` 的 `md` 参数必须传 `EVP_sm3()`

#### 3.2.3 ASN1 签名 SM2 NULL 参数（GM/T 0015-2023）

- **文件**: `crypto/asn1/a_sign.c`
- **功能**: 遵循国密标准 GM/T 0015-2023，ASN1 签名中添加 SM2 NULL 参数

---

### 3.3 SM2 算法增强（shenxuebing + 其他贡献者）

#### 3.3.1 shenxuebing 的 SM2 修改

| 文件 | 修改内容 |
|------|----------|
| `crypto/sm2/sm2_crypt.c` | C1C2C3 格式支持 |
| `crypto/sm2/sm2_sign.c` | 签名增强 |
| `crypto/sm2/sm2_kmeth.c` | 密钥方法增强 |
| `crypto/sm2/sm2_err.c` | 错误码更新 |
| `include/crypto/sm2.h` | 头文件更新 |
| `include/crypto/sm2err.h` | 错误码头文件 |
| `providers/implementations/asymciphers/sm2_enc.c` | SM2 加密 Provider 适配 |
| `include/openssl/evp.h` | 新增 `EVP_PKEY_CTX_set_sm2_encdata_format` 声明 |
| `crypto/evp/pmeth_lib.c` | 实现 `EVP_PKEY_CTX_set_sm2_encdata_format` |

#### 3.3.2 `sm2_encdata_format` 参数说明

| 值 | 格式 | 说明 |
|----|------|------|
| 0 | C1C2C3 | 默认格式 |
| 1 | C1C3C2 | GM/T 0009 标准格式 |

控制 SM2 加密密文的字节排列顺序，用于兼容不同国密实现。

#### 3.3.3 其他贡献者的 SM2 优化

| 文件 | 内容 | 提交者 |
|------|------|--------|
| SM2 64 位平台优化 | 快速模约简 | pr000000f |
| `crypto/ec/ecp_sm2p256.c` | 使用 Tongsuo 原始实现 | pr000000f |
| SM2 Za 参数可配置 | 支持 "sm2-za:no" | pr000000f |
| SM2MLKEM768 | 后量子混合密钥交换 | pr000000f |

---

### 3.4 PKCS7/CMS 修复（shenxuebing）

| 文件 | 修改内容 |
|------|----------|
| `crypto/pkcs7/pk7_doit.c` | 修复 PKCS7_dataInit 的 no_hash 参数值 |
| `crypto/pkcs7/pk7_asn1.c` | PKCS7 ASN1 适配 |
| `crypto/pkcs7/pk7_attr.c` | PKCS7 属性处理 |
| `crypto/pkcs7/pk7_lib.c` | PKCS7 库函数 |
| `crypto/pkcs7/pk7_local.h` | 内部头文件 |
| `crypto/pkcs7/pk7_mime.c` | MIME 支持 |
| `crypto/pkcs7/pk7_smime.c` | S/MIME 支持 |
| `crypto/pkcs7/pkcs7err.c` | 错误处理 |
| `crypto/pkcs7/bio_pk7.c` | BIO 接口 |
| `crypto/cms/cms_lib.c` | CMS 函数补全 |
| `crypto/pkcs12/p12_crt.c` | PKCS12 适配 |
| `crypto/ts/ts_rsp_sign.c` | TS 签名修复 |
| `crypto/ts/ts_rsp_verify.c` | TS 验证修复 |

---

### 3.5 OID 补全（shenxuebing）

| 文件 | 新增 OID |
|------|----------|
| `crypto/objects/obj_dat.h` | OID 数据表更新 |
| `include/openssl/obj_mac.h` | OID 宏定义更新 |
| `crypto/objects/objects.txt` | OID 定义文件 |

**新增 OID 列表**:
- SM1 对称加密算法 OID
- GM/T 0006 HMAC-SM3 OID (sm3 2)
- EC PRIVATEKEY INT
- PKCS7 国密命令

**验证状态**: 已确认 migration/dev-v2 分支包含 dev 分支的所有自定义 OID，且额外包含上游 3.5.4 新增的 OID。

---

### 3.6 RC2 算法恢复（shenxuebing）

上游 OpenSSL 3.x 移除了 RC2，但国密应用可能需要兼容。

| 新增文件 | 功能 |
|----------|------|
| `crypto/rc2/rc2_cbc.c` | CBC 模式 |
| `crypto/rc2/rc2_ecb.c` | ECB 模式 |
| `crypto/rc2/rc2_skey.c` | 密钥设置 |
| `crypto/rc2/rc2cfb64.c` | CFB64 模式 |
| `crypto/rc2/rc2ofb64.c` | OFB64 模式 |
| `crypto/rc2/rc2_local.h` | 内部定义 |
| `crypto/rc2/build.info` | 构建配置 |
| `include/openssl/rc2.h` | 公开头文件 |
| `providers/implementations/ciphers/cipher_rc2.h` | Provider 头文件 |
| `providers/implementations/ciphers/cipher_rc2_hw.c` | Provider 硬件加速 |
| `test/rc2test.c` | 测试 |
| `test/recipes/05-test_rc2.t` | 测试脚本 |

---

### 3.7 Engine 到 Provider 迁移（shenxuebing）

| 阶段 | 提交 | 说明 |
|------|------|------|
| 添加 Engine SM2 回调 | `679dc989e` | 临时添加 Engine 框架的 SM2 回调扩展 |
| 添加 SDF/SKF Engine | `16bc0c2d7` | 临时添加 SDF/SKF Engine 实现 |
| **移除 Engine 实现** | `3cec85783` | 清理所有 Engine 代码，统一使用 Provider |

最终架构: Engine 框架已完全移除，所有硬件加速通过 SDF Provider 实现。

---

### 3.8 SDF 框架层适配（shenxuebing）

| 文件 | 修改内容 |
|------|----------|
| `crypto/sdf/sdf_lib.c` | SDF 库函数适配 |
| `crypto/sdf/sdf_local.h` | 内部数据结构更新 |
| `crypto/sdf/sdf_meth.c` | SDF 方法分发 |
| `include/openssl/sdf.h` | SDF API 头文件 |
| `crypto/tsapi/tsapi_lib.c` | TSAPI 库适配 |

---

### 3.9 其他贡献者的主要功能（完整列表）

#### 3.9.1 零知识证明（Jin Jiu）

| 算法 | 文件目录 | 功能 |
|------|----------|------|
| Bulletproofs | `crypto/bn/bp_*.c` | 范围证明、多范围证明 |
| NIZKPoK | `crypto/zkp/` | 非交互式零知识证明 |
| Paillier | `crypto/phe/paillier_*.c` | 同态加密（支持负数、可配置密钥长度） |
| EC-ElGamal | `crypto/phe/ec_elgamal_*.c` | 椭圆曲线同态加密 |
| Twisted-EC-ElGamal | `crypto/phe/` | Twisted 变体 |
| BIGNUM 方法 | `crypto/bn/` | BN 操作支持方法机制 |

#### 3.9.2 白盒 SM4（Jin Jiu）

| 变体 | 配置选项 |
|------|----------|
| wbsm4-xiaolai（小白） | `--enable-wbsm4-xiaolai` |
| wbsm4-baiwu（白雾） | `--enable-wbsm4-baiwu` |
| wbsm4-wsise | `--enable-wbsm4-wsise` |

#### 3.9.3 SM2 阈值密码（Jin Jiu）

- SM2 两方阈值签名
- SM2 两方阈值解密
- speed 命令支持: sm2-threshold-sign, sm2-threshold-decrypt, sm2-crypt

#### 3.9.4 ZUC 算法（K1）

| 算法 | 类型 |
|------|------|
| zuc-128-eea3 | 流密码（加密） |
| zuc-128-eia3 | MAC（消息认证） |

#### 3.9.5 TLS 1.3 RFC 8998（K1）

- TLS_AES_128_SM4_GCM_SHA256
- TLS_SM4_GCM_SM3
- TLS_SM4_CCM_SM3
- SM2 KeyShareEntry 在 ClientHello 中的正确处理

#### 3.9.6 TLCP 协议（Paul Yang）

- 支持 TLCP 和 GM/T 0024-2014
- s_server 支持 TLCP SNI 测试

#### 3.9.7 随机数熵源增强

- 重构 RAND_set_entropy_source 支持多熵源
- 新增 RTC（系统时间）熵源方案

#### 3.9.8 证书验证增强

- X509 添加支持上下文的验证接口
- SSL 握手期间验证证书和 server_name 匹配

#### 3.9.9 SSL 功能增强

- SSL_CTX_dup: SSL 上下文复制
- SSL_set_skip_scsv: 跳过 SCSV
- 异步会话查找
- 握手状态回调
- 获取警报协议消息级别
- 获取会话复用类型
- 握手 RTT 打印

#### 3.9.10 已移除算法

BLAKE2, Blowfish, Whirlpool, RIPEMD, MDC2, MD4, IDEA, GOST, Camellia, MD2, SEED, ARIA, Argon2

#### 3.9.11 已移除架构

VMS, PA-RISC, SPARC

---

## 四、影响文件总览

### 4.1 shenxuebing 新增文件（33 个）

```
providers/sdfprov/
  build.info                     -- 构建配置
  sdfprov.c                      -- Provider 核心
  sdfprov_ctx.c                  -- 设备管理
  sdfprov_ctx.h                  -- 上下文头文件
  sdfprov_entry.c                -- Provider 入口
  sdfprov_internal.h             -- 内部定义
  sdfprov_rand.c                 -- 硬件随机数
  sdfprov_sm2_asym_cipher.c      -- SM2 加解密
  sdfprov_sm2_keymgmt.c          -- SM2 密钥管理
  sdfprov_sm2_sig.c              -- SM2 签名
  sdfprov_sm2dh_exch.c           -- SM2DH 密钥协商
  sdfprov_store.c                -- 密钥存储
  sdfprov_utils.c                -- 工具函数
  sdfprov_utils.h                -- 工具函数头文件

crypto/rc2/
  build.info, rc2_cbc.c, rc2_ecb.c, rc2_skey.c,
  rc2_local.h, rc2cfb64.c, rc2ofb64.c

include/internal/tlog.h          -- 日志辅助
include/openssl/rc2.h            -- RC2 头文件
providers/implementations/ciphers/cipher_rc2.h
providers/implementations/ciphers/cipher_rc2_hw.c

test/rc2test.c, test/recipes/05-test_rc2.t
apps/test_both_ciphersuites.c    -- 软硬交叉认证矩阵测试
apps/test_ntls_sdf.c             -- NTLS SDF 测试
apps/test_sdf_enc_dec.c          -- SDF 加解密测试
test_sdf_provider.c              -- SDF Provider 集成测试
```

### 4.2 shenxuebing 修改文件（47 个）

```
# SM2 核心
crypto/sm2/sm2_crypt.c, sm2_sign.c, sm2_kmeth.c, sm2_err.c
include/crypto/sm2.h, include/crypto/sm2err.h

# Provider
providers/implementations/asymciphers/sm2_enc.c
providers/smtc/self_test_kats.c

# PKCS7/CMS
crypto/pkcs7/pk7_asn1.c, pk7_attr.c, pk7_doit.c, pk7_lib.c,
           pk7_local.h, pk7_mime.c, pk7_smime.c, pkcs7err.c, bio_pk7.c
crypto/cms/cms_lib.c
crypto/pkcs12/p12_crt.c

# 时间戳
crypto/ts/ts_rsp_sign.c, ts_rsp_verify.c
crypto/tsapi/tsapi_lib.c

# ASN1
crypto/asn1/a_sign.c, p5_pbev2.c, p5_scrypt.c

# EVP
crypto/evp/c_allc.c, e_old.c, evp_enc.c, evp_pbe.c, pmeth_lib.c
include/openssl/evp.h

# EC
crypto/ec/ec_ameth.c, ec_asn1.c

# NTLS SSL
ssl/statem_ntls/ntls_statem_clnt.c, ntls_statem_lib.c, ntls_statem_srvr.c

# SDF 框架
crypto/sdf/sdf_lib.c, sdf_local.h, sdf_meth.c
include/openssl/sdf.h

# 对象/OID
crypto/objects/obj_dat.h, include/openssl/obj_mac.h, include/openssl/pkcs7err.h

# 构建系统
crypto/provider_predefined.c

# 应用
apps/list.c, apps/pkcs7.c

# 测试
test/tsapi_test.c
```

---

## 五、构建和测试

### 5.1 构建配置

```bash
# 基础配置（启用 NTLS + SDF Provider）
perl Configure VC-WIN64A no-shared enable-ntls enable-sdfprov enable-sdf-lib-dynamic --with-sdf-include=./include

# 完整配置（含白盒 SM4）
perl Configure VC-WIN64A no-shared enable-ntls enable-sdfprov \
  enable-sdf-lib-dynamic --with-sdf-include=./include \
  --enable-wbsm4-xiaolai --enable-wbsm4-baiwu --enable-wbsm4-wsise

# 构建
nmake
```

**注意**: 必须使用 MSYS2 以外的 Perl（如 Strawberry Perl），推荐 `C:\Perl64\bin\perl.exe`。

### 5.2 SDF Provider 验证

```bash
# 查看 Provider 列表
openssl list -providers -provider sdfprov

# 预期输出包含:
# sdfprov
#   status: active
#   算法: SM2, SM2DH, SDF-RAND, sdf
```

### 5.3 NTLS SSL 握手测试

#### 5.3.1 软件密钥测试

```bash
# 服务器
start "NTLS Server" /min openssl.exe s_server -ntls -enable_ntls -accept 25099 \
  -sign_cert server_sign.crt -enc_cert server_enc.crt \
  -sign_key server_sign.key -enc_key server_enc.key \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端
openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:25099 \
  -sign_cert client_sign.crt -enc_cert client_enc.crt \
  -sign_key client_sign.key -enc_key client_enc.key \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

**预期输出**: `Cipher is ECC-SM2-SM4-GCM-SM3` 或 `Cipher is ECC-SM2-SM4-CBC-SM3`

#### 5.3.2 SDF 硬件密钥测试

```bash
# 服务器（SDF 硬件密钥）
start "NTLS SDF Server" /min openssl.exe s_server -ntls -enable_ntls -accept 24930 \
  -sign_cert server_sign.crt -enc_cert server_enc.crt \
  -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" \
  -provider sdfprov -provider default \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端（软件密钥）
openssl.exe s_client -ntls -enable_ntls -connect 127.0.0.1:24930 \
  -sign_cert client_sign.crt -enc_cert client_enc.crt \
  -sign_key client_sign.key -enc_key client_enc.key \
  -provider sdfprov -provider default \
  -CAfile ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 5.3.3 测试脚本

| 脚本 | 说明 | 端口 |
|------|------|------|
| `apps/test_ntls.bat` | 软件密钥基础测试 | 25099 |
| `apps/test_ecc_sdf.bat` | SDF 硬件密钥测试 | 24970 |
| `apps/test_both_ciphersuites.c` | 4 种软硬组合矩阵测试 | 多端口 |

### 5.4 软硬件要求

| 项目 | 要求 |
|------|------|
| 编译器 | Visual Studio 2022 |
| SDF 模块 | byzk0018.dll（64 位） |
| 配置文件 | yj.db + softModule.ini（运行目录） |
| 证书 | SM2 双证书（签名 + 加密） |
| 密码 | 默认 "88888888"（由 BYCSM_LoadModule 传入） |

---

## 六、已知问题和后续工作

### 6.1 已知问题

1. **ECDHE-SM2 临时密钥**: 软硬件交叉认证时的密钥匹配问题，正在修复中
2. **KEYMGMT export 跨 Provider**: export 函数返回 0 绕过 cb 调用，可能导致跨 Provider 密钥比较失败
3. **NTLS 非默认启用**: 需要显式 `enable-ntls` 配置选项

### 6.2 后续工作（Phase 2）

1. 硬件 SM4 对称加速（密钥导入 SDF 设备）
2. 硬件 SM3 摘要
3. SM2DHE 硬件密钥协商（需厂商扩展 API）
4. 多设备/多会话支持
5. 在默认构建配置中启用 NTLS
6. ZKP 算法的文档和示例完善

---

## 七、测试状态总结

| 功能 | 测试状态 | 备注 |
|------|----------|------|
| SDF Provider 加载 | PASS | `openssl list -providers` 显示 sdfprov |
| SM2 硬件签名/验签 | PASS | 通过 SDF 设备签名，软件验签 |
| SM2 硬件加解密 | PASS | C1C3C2 和 C1C2C3 格式 |
| NTLS ECC-SM2 软件握手 | PASS | 全软件密钥 |
| NTLS ECC-SM2 SDF 硬件握手 | PASS | SDF 服务器 + 软件客户端 |
| NTLS ECDHE-SM2 握手 | 修复中 | 临时密钥跨 Provider 问题 |
| RC2 算法 | PASS | 恢复上游移除的 RC2 |
| SM2 C1C2C3 格式 | PASS | sm2_encdata_format 参数 |
| 自定义 OID | PASS | 所有 dev 分支 OID 已确认存在 |
| TLS 1.3 RFC 8998 | PASS | SM4-GCM-SM3, SM4-CCM-SM3 |
| TLCP 协议 | PASS | GM/T 0024-2014 |
| ZUC 算法 | PASS | zuc-128-eea3, zuc-128-eia3 |
| 白盒 SM4 | PASS | 三种变体 |
| SM2 阈值密码 | PASS | 签名 + 解密 |
| ZKP 算法族 | PASS | Bulletproofs, NIZKPoK, Paillier, EC-ElGamal |

---

## 八、参考资料

| 标准/文档 | 编号 | 内容 |
|-----------|------|------|
| NTLS 协议 | - | 双证书国密 TLS |
| SM2 密码标准 | GM/T 0003 | 椭圆曲线公钥密码 |
| SM3 密码标准 | GM/T 0004 | 密码杂凑算法 |
| SM4 密码标准 | GM/T 0002 | 分组密码 |
| HMAC-SM3 | GM/T 0006 | 消息认证码 |
| SM2 签名参数 | GM/T 0015-2023 | SM2 NULL 参数 |
| SM3 DRBG | GM/T 0105-2021 | 随机数生成器 |
| TLCP | GM/T 0024-2014 | 传输层密码协议 |
| RFC 8998 | - | TLS 1.3 商密套件 |
| SDF 接口 | GM/T 0018 | 密码设备应用接口 |
| OpenSSL 3.x Provider | - | Provider 架构设计 |

---

**报告版本**: 1.0
**生成日期**: 2026-05-08
**目标分支**: migration/dev-v2
**基础版本**: OpenSSL 3.5.4
**总提交数**: 303
**shenxuebing 提交数**: 21
