# Tongsuo migration/dev-v2 分支说明

## 项目概况

| 项目 | 内容 |
|------|------|
| 基础版本 | OpenSSL 3.5.4 |
| 源分支 | dev (Tongsuo 8.x, Engine 架构) |
| 目标分支 | migration/dev-v2 (Provider 架构) |
| 迁移周期 | 2026-01 ~ 2026-05 |

---

## 一、编译

### Windows (Visual Studio 2022)

```bash
# 推荐 Strawberry Perl (C:\Perl64\bin\perl.exe)，MSYS2 Perl 可能缺模块

# 最优编译命令
perl Configure VC-WIN64A no-shared no-module enable-ntls enable-sdfprov enable-sdf-lib-dynamic enable-legacy
nmake
```

### Linux

```bash
# 最优编译命令
./Configure linux-x86_64 \
    --prefix=/usr/local/tongsuo \
    -Wl,-rpath,/usr/local/tongsuo/lib64 \
    no-shared no-module \
    enable-ntls enable-sdfprov enable-sdf-lib-dynamic \
    enable-legacy \
    enable-ec_sm2p_64_gcc_128 \
    -march=native
make -j$(nproc)
```

### 编译选项说明

#### 基础选项

| 选项 | 说明 |
|------|------|
| `no-shared` | 静态编译，生成 .lib/.a 而非 .dll/.so |
| `no-module` | 禁止动态加载 Provider 模块，所有 Provider 编译进 libcrypto（自动定义 STATIC_LEGACY 等宏） |
| `enable-ntls` | 启用 NTLS/TLCP 协议（非默认） |
| `enable-sdfprov` | 编译 SDF Provider（providers/sdfprov/），静态链接到 libcrypto |
| `enable-sdf-lib-dynamic` | 编译 SDF API 桩函数（sdfe_api_stub.c），运行时 DSO 动态加载厂商库 |
| `enable-legacy` | 启用 Legacy Provider（MD5、CAST、Blowfish 等旧算法），PKCS#12 兼容可能需要 |

#### 性能优化选项

| 选项 | 平台 | 说明 |
|------|------|------|
| `enable-ec_sm2p_64_gcc_128` | Linux x86_64 (GCC/Clang) | SM2 快速模约简（64 位优化），显著提升 SM2 性能 |
| `enable-ec_nistp_64_gcc_128` | Linux x86_64 (GCC/Clang) | NIST 曲线（P-256/P-384）快速模约简 |
| `-march=native` | Linux (GCC/Clang) | 针对当前 CPU 指令集优化（AVX2/AES-NI 等） |
| `enable-sm2-precomp` | 通用 | SM2 预计算表加速（增大二进制体积换取速度） |
| `enable-wbsm4-xiaolai` | 通用 | 白盒 SM4 实现（小来方案） |
| `enable-wbsm4-baiwu` | 通用 | 白盒 SM4 实现（百悟方案） |
| `enable-wbsm4-wsise` | 通用 | 白盒 SM4 实现（wsise 方案） |

#### 不需要手动指定的选项

| 选项 | 原因 |
|------|------|
| `enable-rc2` | RC2 默认已编译，无需主动开启 |
| `-DSTATIC_LEGACY` | 使用 `no-module` 时构建系统自动定义，无需手动传 |
| `enable-sdf-lib` | 由 `enable-sdf-lib-dynamic` 自动启用 |
| `--with-sdf-include` | SDF 头文件已在 `./include` 下，不需要 |

> **注意**：`enable-ec_sm2p_64_gcc_128` 和 `enable-ec_nistp_64_gcc_128` 仅在 Linux x86_64 + GCC/Clang 下有效，
> Windows MSVC 不支持（VC-WIN64A 已内置汇编优化）。

### 编译产物

| 文件 | 说明 |
|------|------|
| libcrypto.lib / libcrypto.a | 包含 SDF Provider、Legacy Provider、SDF 框架、SDF API 桩函数 |
| libssl.lib / libssl.a | SSL 库（含 NTLS 支持） |
| openssl.exe | 命令行工具 |

---

## 二、测试

测试证书位于 `test/certs/sm2/`，测试脚本位于 `apps/`。

### 第一阶段：纯软件测试（不需要硬件）

```bash
# NTLS 纯软件握手（ECC + ECDHE 两个密码套件）
apps\test_ntls_soft.bat
```

### 第二阶段：SDF 硬件测试（需要 SDF 设备）

前置条件：byzk0018.dll 在运行目录，openssl.cnf 配置了 sdf_lib_path。

```bash
# Provider 加载 + URI 密钥加载验证
apps\test_store_uri.bat

# SDF 硬件签名测试
apps\test_sdf_sign.bat
```

### 第三阶段：NTLS 全组合测试（需要 SDF 设备）

8 个场景（2 密码套件 x 4 密钥组合）：

```bash
apps\test_ntls_full.bat
```

| # | 密码套件 | 服务端密钥 | 客户端密钥 |
|---|---------|-----------|-----------|
| 1 | ECC-SM2-SM4-CBC-SM3 | 软件(PEM) | 软件(PEM) |
| 2 | ECC-SM2-SM4-CBC-SM3 | 硬件(SDF) | 软件(PEM) |
| 3 | ECC-SM2-SM4-CBC-SM3 | 软件(PEM) | 硬件(SDF) |
| 4 | ECC-SM2-SM4-CBC-SM3 | 硬件(SDF) | 硬件(SDF) |
| 5 | ECDHE-SM2-SM4-CBC-SM3 | 软件(PEM) | 软件(PEM) |
| 6 | ECDHE-SM2-SM4-CBC-SM3 | 硬件(SDF) | 软件(PEM) |
| 7 | ECDHE-SM2-SM4-CBC-SM3 | 软件(PEM) | 硬件(SDF) |
| 8 | ECDHE-SM2-SM4-CBC-SM3 | 硬件(SDF) | 硬件(SDF) |

### 手动测试

```bash
# 查看 Provider
openssl list -providers -provider sdfprov

# SM2 硬件签名
openssl dgst -sm3 -sign "sdf:sm2:0:sign" -provider sdfprov -provider default -out sig.dat data.txt

# NTLS 握手（服务端 SDF + 客户端软件）
openssl s_server -ntls -enable_ntls -accept 25000 ^
  -sign_cert test/certs/sm2/server_sign.crt ^
  -enc_cert test/certs/sm2/server_enc.crt ^
  -sign_key "sdf:sm2:0:sign" -enc_key "sdf:sm2:0:enc" ^
  -provider sdfprov -provider default ^
  -CAfile test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25000 ^
  -sign_cert test/certs/sm2/client_sign.crt ^
  -enc_cert test/certs/sm2/client_enc.crt ^
  -sign_key test/certs/sm2/client_sign.key ^
  -enc_key test/certs/sm2/client_enc.key ^
  -CAfile test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

### 密钥 URI 格式

```
# 兼容老 Engine（推荐）
sdf:sm2:0:sign              # SM2 索引0 签名密钥
sdf:sm2:0:enc:11111111      # SM2 索引0 加密密钥，口令 11111111

# key=value 风格
sdf:key=0;type=sign
sdf:key=0;type=enc;pwd=11111111
```

---

## 三、SDF Provider 配置

在 `openssl.cnf` 中添加：

```ini
[provider_section]
sdfprov = sdfprov_sect

[sdfprov_sect]
activate = 1
sdf_lib_path = byzk0018.dll        # 厂商 DLL 路径
sdf_module_password = 88888888      # 模块加载密码
```

### 指定配置文件路径

默认使用编译时内置的 `openssl.cnf` 路径。可通过环境变量指定自定义配置文件：

```bash
# Windows
set OPENSSL_CONF=C:\path\to\my_openssl.cnf

# Linux/macOS
export OPENSSL_CONF=/path/to/my_openssl.cnf
```

---

## 四、更新记录

### 2026-05-09 代码审查修复 + 测试统一

- 修复线程安全：init_device 加 CRYPTO_RWLOCK 双重检查
- 修复内存泄漏：freedata 释放 agreement_handle、import 释放 pub buffer
- 修复缓冲区溢出：sm2_der_to_ecccipher 增加 cipher_buf_size 边界检查
- 修复 C1C2C3/C1C3C2 格式由自动猜测改为显式 encdata_format 参数
- 修复硬件协商失败静默回退，改用 ERR_raise 报错
- 修复 sign_init/verify_init 中 OPENSSL_memdup 失败未返回错误
- 增强兼容老 Engine URI 格式 (sdf:sm2:0:sign[:pwd])
- 新增 providers/sdfprov/README.md 使用文档
- 新增 8 场景全组合 NTLS 测试脚本 (test_ntls_full.bat)
- 新增 CI sdfprov-compile Job
- 清理调试 fprintf、冗余测试脚本和临时文件
- 测试脚本统一使用 test/certs/sm2/ 自带证书

### 2026-05-08 EVP API + 矩阵测试

- 新增 EVP_PKEY_CTX_set_sm2_encdata_format() API
- 添加软硬交叉认证矩阵测试程序

### 2026-05-07 ~ 05-08 ECDHE-SM2 修复

- 修复 ECDHE-SM2 crash 和密钥不匹配
- 修复 ECC-SM2-SM4-CBC-SM3 套件 uiAlgID 参数和私钥访问控制码支持

### 2026-05-07 SDF Provider 初始实现

- 新增 SDF Provider 硬件加速模块（providers/sdfprov/，14 个文件）
- 注册 SM2 KEYMGMT/SIGNATURE/ASYM_CIPHER/KEYEXCH/RAND/STORE
- 静态链接到 libcrypto，支持 NTLS SM2 密码套件硬件加速

### 2026-04-28 ~ 04-29 国密功能迁移

- SM2 算法增强（C1C2C3 格式、签名/加密/密钥方法）
- ASN1 签名 SM2 NULL 参数（GM/T 0015-2023）
- NTLS/SDF 集成核心修改（SSL 层适配）
- SM2DHE 密钥协商模块
- PKCS7 国密命令扩展
- CMS 函数补全（上游 OpenSSL 3.5.4 缺失）
- OID 补全（SM1、HMAC-SM3、PKCS7 国密命令等）
- RC2 算法恢复
- Engine 框架 SM2 回调 → 最终移除，统一 Provider 架构

### 2026-01 ~ 2026-03 基础迁移（其他贡献者）

- ZUC 流密码（zuc-128-eea3/eia3）
- EC-ElGamal / Twisted-EC-ElGamal / Paillier 同态加密
- Bulletproofs 范围证明 / NIZKPoK 零知识证明
- SM2 阈值签名和加密
- 白盒 SM4（xiaolai/baiwu/wsise）
- TLS 1.3 RFC 8998 商密套件
- TLCP 协议（GM/T 0024-2014）
- SM3 DRBG（GM/T 0105-2021）
- SM2MLKEM768 后量子混合密钥交换
- SM2 快速模约简和 64 位优化

---

## 五、架构说明

### Engine → Provider 迁移

dev 分支使用 Engine 框架实现 SDF 硬件加速，migration/dev-v2 完全迁移到 Provider 架构：

```
旧架构 (dev):  应用 → Engine 回调 → SDF 厂商库
新架构 (v2):   应用 → EVP 框架 → SDF Provider → TSAPI/SDF 框架 → DSO 厂商库
```

### SDF Provider 文件结构

```
providers/sdfprov/
  sdfprov.c                    -- Provider 核心（init/query/teardown）
  sdfprov_ctx.c / sdfprov_ctx.h  -- 设备/会话生命周期管理
  sdfprov_internal.h           -- 内部共享定义
  sdfprov_sm2_keymgmt.c        -- SM2 密钥管理
  sdfprov_sm2_sig.c            -- SM2 签名（硬件签名 + 软件验签）
  sdfprov_sm2_asym_cipher.c    -- SM2 加解密
  sdfprov_sm2dh_exch.c         -- SM2DH 密钥协商
  sdfprov_rand.c               -- 硬件随机数
  sdfprov_store.c              -- 密钥存储（URI 解析）
  sdfprov_utils.c / sdfprov_utils.h  -- ECCref <-> EC_KEY 格式转换
  README.md                    -- 使用文档
```

### 密码套件支持

| 套件 | 密钥交换 | 说明 |
|------|---------|------|
| ECC-SM2-SM4-CBC-SM3 | 静态 SM2 | 长期密钥 |
| ECC-SM2-SM4-GCM-SM3 | 静态 SM2 | GCM 模式 |
| ECDHE-SM2-SM4-CBC-SM3 | 临时 SM2 (ECDHE) | 前向安全 |
| ECDHE-SM2-SM4-GCM-SM3 | 临时 SM2 (ECDHE) | 前向安全 + GCM |

---

**分支**: migration/dev-v2
**基础**: OpenSSL 3.5.4
**最后更新**: 2026-05-09
