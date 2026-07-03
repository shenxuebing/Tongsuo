# SDF Provider 使用说明

## 概述

SDF Provider 是 Tongsuo 项目的一个硬件安全模块（HSM）Provider 实现，基于国密 SDF（Secure Data Facility）规范，提供 SM2 算法的硬件加速支持。

## 功能特性

- **SM2 算法支持**
  - SM2 密钥管理（KEYMGMT）
  - SM2 数字签名（SIGNATURE）
  - SM2 非对称加密（ASYM_CIPHER）
  - SM2DH 密钥交换（KEYEXCH）

- **硬件密钥管理**
  - 支持 SDF 设备硬件密钥
  - 支持软件密钥（兼容性）
  - 自动密钥索引管理

- **随机数生成**
  - SDF-RAND 随机数生成器

- **密钥存储**
  - sdf 存储后端

## 编译

### 编译选项

| 选项 | 默认 | 说明 |
|------|------|------|
| `enable-ntls` | 关闭 | 启用 NTLS/TLCP 协议（SDF Provider 通常配合 NTLS 使用） |
| `enable-sdfprov` | 开启 | 编译 SDF Provider（providers/sdfprov/），静态链接到 libcrypto |
| `enable-sdf-lib-dynamic` | 开启 | 编译 SDF API 桩函数（sdfe_api_stub.c），提供运行时 DSO 动态加载所需符号；自动启用 `sdf-lib` |
| `enable-sdf-lib` | 开启 | 编译 SDF 框架层（crypto/sdf/），通常由 `sdf-lib-dynamic` 自动启用 |
| `--with-sdf-include=<path>` | - | 编译时追加 SDF 头文件搜索路径。若 SDF 头文件已在 `./include` 下则不需要 |

> **`enable-sdf-lib-dynamic` 做什么？**
> 编译 `crypto/tsapi/sdfe_api_stub.c`，这个文件提供 SDF API 函数（如 `SDF_OpenDevice`、
> `SDF_InternalSign_ECC` 等）的桩实现，内部通过 DSO 在运行时加载厂家 DLL/SO 中的真实函数。
> 不启用此选项会导致链接时找不到 SDF 函数符号。

### 编译命令

#### Windows（Visual Studio 2022）

```bash
# SDF 头文件已自带在 ./include 下，无需额外参数
perl Configure VC-WIN64A no-shared enable-ntls enable-sdf-lib-dynamic
nmake
```

#### Linux

```bash
# 基础编译
./Configure linux-x86_64 no-shared enable-ntls enable-sdf-lib-dynamic
make -j$(nproc)

# 生产环境编译（含 SM2 优化加速）
./Configure linux-x86_64 \
    --prefix=/usr/local/tongsuo \
    -Wl,-rpath,/usr/local/tongsuo/lib64 \
    no-shared enable-ntls enable-sdf-lib-dynamic \
    enable-ec_sm2p_64_gcc_128 \
    -march=native
make -j$(nproc)
```

### 性能优化选项

| 选项 | 平台 | 说明 |
|------|------|------|
| `enable-ec_sm2p_64_gcc_128` | Linux x86_64 (GCC/Clang) | SM2 快速模约简（64 位优化），显著提升 SM2 签名/验签/密钥交换性能 |
| `enable-ec_nistp_64_gcc_128` | Linux x86_64 (GCC/Clang) | NIST 曲线（P-256/P-384）快速模约简 |
| `-march=native` | Linux (GCC/Clang) | 针对当前 CPU 指令集优化（AVX2/AES-NI 等） |
| `enable-sm2-precomp` | 通用 | SM2 预计算表加速（增大二进制体积换取速度） |

> **注意**：`ec_sm2p_64_gcc_128` 和 `ec_nistp_64_gcc_128` 仅在 Linux x86_64 + GCC/Clang 下有效，Windows MSVC 不支持。

### 注意事项

1. **Perl 版本**：Windows 下推荐 Strawberry Perl（`C:\Perl64\bin\perl.exe`），MSYS2 Perl 可能缺少模块
2. **静态链接**：`no-shared` 静态编译时，SDF Provider 静态链接到 libcrypto（`STATIC_SDFPROV` 宏）
3. **厂家库不需要编译时链接**：SDF 厂家库（如 byzk0018.dll）在运行时通过 `LoadLibrary`/`dlopen` 动态加载，切换厂家只需修改 `openssl.cnf` 中的 `sdf_lib_path`，无需重新编译

### 编译产物

| 文件 | 说明 |
|------|------|
| `libcrypto.lib` / `libcrypto.a` | 包含 SDF Provider、SDF 框架、SDF API 桩函数的密码库 |
| `libssl.lib` / `libssl.a` | SSL 库（包含 NTLS 支持） |
| `openssl.exe` | 命令行工具 |

## 配置方法

### 1. OpenSSL 配置文件配置

在 `openssl.cnf` 文件中添加 SDF Provider 配置：

```ini
[openssl_init]
providers = provider_section

[provider_section]
default = default_sect
sdfprov = sdfprov_sect

[default_sect]
activate = 1

[sdfprov_sect]
activate = 1
# SDF 厂商库路径（可选，默认: Windows=sdf.dll, Linux=libsdf.so）
# 切换厂家驱动只需修改此路径，无需重新编译
sdf_lib_path = byzk0018.dll
# 是否调用 BYCSM_LoadModule 接口（可选，默认: 1）
# 1=调用（适用于博雅等需要此接口的厂商）
# 0=不调用（适用于不需要此接口的厂商）
sdf_use_loadmodule = 1
# SDF 模块密码（可选，默认: 88888888）
# 这是 SDF 设备模块的加载密码（BYCSM_LoadModule 参数）
# 仅在 sdf_use_loadmodule=1 时使用
# 私钥访问控制码通过 URI 的 pwd 参数传递，不要写在这里
sdf_module_password = 88888888
```

> **静态编译时**：Provider 已内建到 libcrypto 中，不需要 `module` 配置项。`activate = 1` 即可激活。

### 2. 命令行加载 Provider

```bash
# 动态加载（推荐，避免和 default Provider 冲突）
openssl -provider sdfprov -provider default [命令]
```

### 3. 指定配置文件路径

默认使用编译时内置的 `openssl.cnf` 路径。可通过 `OPENSSL_CONF` 环境变量指定自定义配置文件：

```bash
# Windows（临时生效）
set OPENSSL_CONF=C:\path\to\my_openssl.cnf

# Linux/macOS（临时生效）
export OPENSSL_CONF=/path/to/my_openssl.cnf
```

> **注意**：`OPENSSL_CONF` 对所有 `openssl` 子命令生效，包括 `s_server`、`s_client`、`dgst` 等。
> 测试脚本中可在开头添加 `set OPENSSL_CONF=...` 来使用指定配置文件。

## 密钥 URI 格式

SDF Provider 通过 URI 标识硬件密钥，支持两种格式：

### 格式一：兼容老 Engine（推荐）

```
sdf:<algo>:<index>:<type>[:<pwd>]
```

与旧版 Engine 框架格式一致，方便现有应用迁移。

| 参数 | 必填 | 说明 |
|------|------|------|
| `algo` | 是 | 算法：`sm2` 或 `rsa`（rsa 暂未实现） |
| `index` | 是 | SDF 设备密钥索引（从 0 开始） |
| `type` | 是 | 密钥类型：`sign`（签名）或 `enc`（加密） |
| `pwd` | 否 | 私钥访问控制码（GetPrivateKeyAccessRight 参数） |

```bash
# SM2 密钥
sdf:sm2:0:sign                    # 索引0 签名密钥，无口令
sdf:sm2:0:enc:11111111            # 索引0 加密密钥，口令 11111111
sdf:sm2:1:sign:mypassword         # 索引1 签名密钥，自定义口令

# RSA 密钥（未来支持）
# NOTE: RSA is supported in current sdfprov releases.
sdf:rsa:0:sign:password
sdf:rsa:0:enc
```

### 格式二：key=value 风格

```
sdf:key=<index>;type=<sign|enc>[;algo=<sm2|rsa>][;pwd=<password>]
```

```bash
sdf:key=0;type=sign
sdf:key=0;type=enc;algo=sm2;pwd=11111111
sdf:key=1;type=sign;algo=rsa;pwd=mypwd
```

### 设计说明

**为什么 pwd 在 URI 中而不是配置文件中？**

1. **安全性**：不同的密钥索引可能有不同的访问控制码，配置文件只能存一个全局值
2. **灵活性**：与旧版 Engine 框架一致，通过密钥标识直接传递
3. **兼容性**：部分厂家可以关闭私钥访问控制码验证，此时 pwd 参数可省略

> **注意**：`sdf_module_password`（模块加载密码）保留在配置文件中，因为它是
> `BYCSM_LoadModule()` 的设备级初始化参数，与具体密钥无关。

## 使用方法

### 1. 查看已注册的 Provider

```bash
openssl list -providers -provider sdfprov
```

### 2. SM2 签名

```bash
# 使用硬件密钥签名
openssl dgst -provider sdfprov -provider default -sm3 \
  -sign "sdf:sm2:0:sign:11111111" -out sig.dat data.txt
```

### 3. SM2 加解密

```bash
# 使用硬件密钥加密（不需要 pwd，使用公钥）
openssl pkeyutl -provider sdfprov -provider default \
  -encrypt -inkey "sdf:sm2:0:enc" -pubin \
  -in plaintext.txt -out ciphertext.bin

# 使用硬件密钥解密（需要 pwd）
openssl pkeyutl -provider sdfprov -provider default \
  -decrypt -inkey "sdf:sm2:0:enc:11111111" \
  -in ciphertext.bin -out plaintext.txt
```

### 4. NTLS 握手测试

NTLS 使用双证书体系（签名证书 + 加密证书），SDF Provider 支持硬件密钥和软件密钥的任意组合。

#### NTLS 命令行参数

| 参数 | 说明 |
|------|------|
| `-ntls` | 启用 NTLS（TLCP）协议模式 |
| `-enable_ntls` | 在 TLS 基础上启用 NTLS 协商（通常和 `-ntls` 同时使用） |
| `-sign_cert <file>` | 签名证书 |
| `-sign_key <file\|uri>` | 签名私钥（PEM 文件或 SDF URI） |
| `-enc_cert <file>` | 加密证书 |
| `-enc_key <file\|uri>` | 加密私钥（PEM 文件或 SDF URI） |
| `-CAfile <file>` | CA 证书（用于验证对端） |
| `-cipher <suite>` | 指定密码套件 |
| `-provider sdfprov` | 加载 SDF Provider |
| `-provider default` | 同时加载 default Provider |

#### 测试场景一：纯软件密钥（不需要硬件）

用于验证 NTLS 基本功能，不需要 SDF 设备：

```bash
# 设置证书路径（以下示例均假设从项目根目录执行）
CERTS=test/certs/sm2

# 服务端
openssl s_server -ntls -enable_ntls -accept 25099 \
  -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt \
  -sign_key $CERTS/server_sign.key -enc_key $CERTS/server_enc.key \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端（另一个终端）
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25099 \
  -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt \
  -sign_key $CERTS/client_sign.key -enc_key $CERTS/client_enc.key \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 测试场景二：服务端 SDF 硬件密钥 + 客户端软件密钥

最常见的部署场景，服务器使用硬件密钥保护：

```bash
# 服务端 - SDF 硬件密钥
openssl s_server -ntls -enable_ntls -accept 24930 \
  -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt \
  -sign_key "sdf:sm2:0:sign" \
  -enc_key "sdf:sm2:0:enc" \
  -provider sdfprov -provider default \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端 - PEM 软件密钥
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:24930 \
  -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt \
  -sign_key $CERTS/client_sign.key -enc_key $CERTS/client_enc.key \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 测试场景三：服务端 + 客户端均使用 SDF 硬件密钥

最高安全等级，双端密钥均在硬件中：

```bash
# 服务端 - SDF 硬件密钥
openssl s_server -ntls -enable_ntls -accept 24931 \
  -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt \
  -sign_key "sdf:sm2:0:sign" \
  -enc_key "sdf:sm2:0:enc" \
  -provider sdfprov -provider default \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端 - SDF 硬件密钥
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:24931 \
  -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt \
  -sign_key "sdf:sm2:0:sign" \
  -enc_key "sdf:sm2:0:enc" \
  -provider sdfprov -provider default \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

> **注意**：双端使用同一台 SDF 设备时，服务端和客户端密钥索引需错开（如服务端用索引 0/1，客户端用索引 2/3），或者使用不同设备。

#### 测试场景四：ECDHE-SM2 前向安全密钥交换

使用 ECDHE 临时密钥交换，提供前向安全性：

```bash
# 服务端
openssl s_server -ntls -enable_ntls -accept 24932 \
  -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt \
  -sign_key "sdf:sm2:0:sign" \
  -enc_key "sdf:sm2:0:enc" \
  -provider sdfprov -provider default \
  -CAfile $CERTS/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3

# 客户端
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:24932 \
  -sign_cert $CERTS/client_sign.crt -enc_cert $CERTS/client_enc.crt \
  -sign_key $CERTS/client_sign.key -enc_key $CERTS/client_enc.key \
  -CAfile $CERTS/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3
```

#### 测试场景五：带私钥访问控制码

当 SDF 设备启用了私钥访问控制码验证时：

```bash
# 服务端 - 带口令（兼容老 Engine URI 格式）
openssl s_server -ntls -enable_ntls -accept 24933 \
  -sign_cert $CERTS/server_sign.crt -enc_cert $CERTS/server_enc.crt \
  -sign_key "sdf:sm2:0:sign:11111111" \
  -enc_key "sdf:sm2:0:enc:11111111" \
  -provider sdfprov -provider default \
  -CAfile $CERTS/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

#### 验证握手结果

握手成功后，s_client 输出中应显示：

```
SSL-Session:
  Protocol  : TLCPv1.1
  Cipher    : ECC-SM2-SM4-CBC-SM3
```

也可以在 s_client 交互模式中输入文本来验证数据通道：

```bash
# 连接成功后输入文本，服务端应显示收到的内容
hello ntls test
```

#### 测试场景速查表

| 场景 | 服务端密钥 | 客户端密钥 | 密码套件 | 需要硬件 |
|------|-----------|-----------|----------|---------|
| 纯软件 NTLS | PEM 文件 | PEM 文件 | ECC-SM2-SM4-CBC-SM3 | 否 |
| 服务端硬件 | SDF URI | PEM 文件 | ECC-SM2-SM4-CBC-SM3 | 是 |
| 双端硬件 | SDF URI | SDF URI | ECC-SM2-SM4-CBC-SM3 | 是 |
| ECDHE 前向安全 | SDF URI | PEM 文件 | ECDHE-SM2-SM4-CBC-SM3 | 是 |
| GCM 模式 | SDF URI | PEM 文件 | ECC-SM2-SM4-GCM-SM3 | 是 |
| ECDHE+GCM | SDF URI | PEM 文件 | ECDHE-SM2-SM4-GCM-SM3 | 是 |
| 带口令访问 | SDF URI(pwd) | PEM 文件 | ECC-SM2-SM4-CBC-SM3 | 是 |

## 测试指南

### 测试脚本

`apps/` 目录下提供以下测试脚本：

| 脚本 | 测试内容 | 需要硬件 |
|------|---------|---------|
| `test_ntls_soft.bat` | 纯软件 NTLS（ECC + ECDHE，不需要 SDF 设备） | 否 |
| `test_store_uri.bat` | Provider 加载 + SDF URI 密钥加载验证 | 是 |
| `test_sdf_sign.bat` | SDF 硬件密钥签名测试（sign + enc 密钥） | 是 |
| `test_ntls_full.bat` | **全组合测试**（2 密码套件 x 4 密钥组合 = 8 场景） | 是 |

### 第一阶段：环境验证（不需要硬件）

```bash
# 纯软件 NTLS 握手，验证编译和证书是否正确
test_ntls_soft.bat
```

### 第二阶段：SDF 设备验证（需要硬件）

```bash
# 验证 SDF Provider 加载和 URI 密钥读取
test_store_uri.bat

# 验证 SDF 硬件密钥签名
test_sdf_sign.bat
```

### 第三阶段：NTLS 全组合测试（需要硬件）

```bash
# 8 个场景全量测试
test_ntls_full.bat
```

**全组合测试矩阵**：

| # | 密码套件 | 服务端密钥 | 客户端密钥 | 测试点 |
|---|---------|-----------|-----------|--------|
| 1 | ECC-SM2-SM4-CBC-SM3 | 软件(PEM) | 软件(PEM) | 纯软件基线 |
| 2 | ECC-SM2-SM4-CBC-SM3 | 硬件(SDF) | 软件(PEM) | 服务端 SDF 签名 + 解密 |
| 3 | ECC-SM2-SM4-CBC-SM3 | 软件(PEM) | 硬件(SDF) | 客户端 SDF 签名 + 解密 |
| 4 | ECC-SM2-SM4-CBC-SM3 | 硬件(SDF) | 硬件(SDF) | 双端 SDF |
| 5 | ECDHE-SM2-SM4-CBC-SM3 | 软件(PEM) | 软件(PEM) | ECDHE 纯软件基线 |
| 6 | ECDHE-SM2-SM4-CBC-SM3 | 硬件(SDF) | 软件(PEM) | 服务端 SDF + ECDHE 密钥交换 |
| 7 | ECDHE-SM2-SM4-CBC-SM3 | 软件(PEM) | 硬件(SDF) | 客户端 SDF + ECDHE 密钥交换 |
| 8 | ECDHE-SM2-SM4-CBC-SM3 | 硬件(SDF) | 硬件(SDF) | 双端 SDF + ECDHE |

> **注意**：如果双端都使用同一台 SDF 设备测试硬件密钥，通常服务端使用 `key=0`，客户端使用 `key=1` 以避免冲突。以下命令默认使用 `apps/test/certs/sm2` 下的证书，**请在 `Tongsuo/apps` 目录下执行**。

#### 8 种场景手动测试命令速查

**场景 1：[ECC] Svr: SW | Cli: SW**
```bash
# 服务端 (SW)
openssl s_server -ntls -enable_ntls -accept 25101 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key ../test/certs/sm2/server_sign.key -enc_key ../test/certs/sm2/server_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端 (SW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25101 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key ../test/certs/sm2/client_sign.key -enc_key ../test/certs/sm2/client_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

**场景 2：[ECC] Svr: HW | Cli: SW**
```bash
# 服务端 (HW)
openssl s_server -ntls -enable_ntls -accept 25102 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端 (SW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25102 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key ../test/certs/sm2/client_sign.key -enc_key ../test/certs/sm2/client_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

**场景 3：[ECC] Svr: SW | Cli: HW**
```bash
# 服务端 (SW)
openssl s_server -ntls -enable_ntls -accept 25103 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key ../test/certs/sm2/server_sign.key -enc_key ../test/certs/sm2/server_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端 (HW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25103 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key "sdf:key=1;type=sign" -enc_key "sdf:key=1;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

**场景 4：[ECC] Svr: HW | Cli: HW**
```bash
# 服务端 (HW)
openssl s_server -ntls -enable_ntls -accept 25104 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3

# 客户端 (HW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25104 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key "sdf:key=1;type=sign" -enc_key "sdf:key=1;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECC-SM2-SM4-CBC-SM3
```

**场景 5：[ECDHE] Svr: SW | Cli: SW**
```bash
# 服务端 (SW)
openssl s_server -ntls -enable_ntls -accept 25105 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key ../test/certs/sm2/server_sign.key -enc_key ../test/certs/sm2/server_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3

# 客户端 (SW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25105 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key ../test/certs/sm2/client_sign.key -enc_key ../test/certs/sm2/client_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3
```

**场景 6：[ECDHE] Svr: HW | Cli: SW**
```bash
# 服务端 (HW)
openssl s_server -ntls -enable_ntls -accept 25106 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3

# 客户端 (SW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25106 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key ../test/certs/sm2/client_sign.key -enc_key ../test/certs/sm2/client_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3
```

**场景 7：[ECDHE] Svr: SW | Cli: HW**
```bash
# 服务端 (SW)
openssl s_server -ntls -enable_ntls -accept 25107 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key ../test/certs/sm2/server_sign.key -enc_key ../test/certs/sm2/server_enc.key -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3

# 客户端 (HW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25107 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key "sdf:key=1;type=sign" -enc_key "sdf:key=1;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3
```

**场景 8：[ECDHE] Svr: HW | Cli: HW**
```bash
# 服务端 (HW)
openssl s_server -ntls -enable_ntls -accept 25108 -sign_cert ../test/certs/sm2/server_sign.crt -enc_cert ../test/certs/sm2/server_enc.crt -sign_key "sdf:key=0;type=sign" -enc_key "sdf:key=0;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3

# 客户端 (HW)
openssl s_client -ntls -enable_ntls -connect 127.0.0.1:25108 -sign_cert ../test/certs/sm2/client_sign.crt -enc_cert ../test/certs/sm2/client_enc.crt -sign_key "sdf:key=1;type=sign" -enc_key "sdf:key=1;type=enc" -provider sdfprov -provider default -CAfile ../test/certs/sm2/chain-ca.crt -cipher ECDHE-SM2-SM4-CBC-SM3
```

### 测试前准备

1. 确认运行目录包含厂商 DLL（如 `byzk0018.dll`）
2. 确认运行目录包含测试证书（`server_sign.crt` 等）
3. 确认 `openssl.cnf` 已配置 `sdf_lib_path` 和 `sdf_module_password`

## 配置参数说明

### Provider 级别参数（openssl.cnf）

| 参数名 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `sdf_lib_path` | 字符串 | `sdf.dll`(Win) / `libsdf.so`(Linux) | SDF 厂商库路径，切换厂家只需改此配置 |
| `sdf_module_password` | 字符串 | 88888888 | SDF 模块加载密码（BYCSM_LoadModule 参数） |

### 密钥级别参数（URI）

| 参数 | 位置 | 说明 |
|------|------|------|
| `algo` | URI | 算法类型（sm2/rsa），格式一必填，格式二可选（默认 sm2） |
| `key` / `index` | URI | SDF 设备密钥索引 |
| `type` | URI | 密钥类型（sign/enc） |
| `pwd` | URI | 私钥访问控制码（GetPrivateKeyAccessRight 参数），可选 |

## 密码体系说明

SDF Provider 涉及两层密码：

| 密码 | 用途 | 传递方式 | 对应 SDF API |
|------|------|----------|-------------|
| 模块加载密码 | 初始化 SDF 设备模块 | openssl.cnf `sdf_module_password` | `BYCSM_LoadModule(pwd)` |
| 私钥访问控制码 | 访问指定密钥的私钥 | URI `pwd` 参数 | `GetPrivateKeyAccessRight(hSession, keyIndex, pwd, pwdLen)` |

## 密钥类型说明

### 1. 硬件密钥

- 密钥存储在 SDF 设备中，无法导出私钥
- 通过密钥索引和类型访问
- 签名/解密由硬件完成，公钥导出到软件侧用于验签/加密
- URI: `sdf:sm2:0:sign[:pwd]` 或 `sdf:sm2:0:enc[:pwd]`

### 2. 软件密钥

- 密钥以 PEM 格式存储在文件中
- 兼容标准 SM2 密钥格式
- 由 default Provider 处理
- 格式: 标准文件路径

## 硬件要求

### SDF 设备

- 支持国密 SDF 规范（GM/T 0028-2014）的硬件安全模块
- 例如：博雅（byzk0018.dll）等 SDF 设备驱动

### 运行时文件

将以下文件放置在运行目录（或 PATH 可找到的位置）：

| 文件 | 说明 |
|------|------|
| `byzk0018.dll` | SDF 厂商库（64 位） |
| `yj.db` | SDF 设备数据库 |
| `softModule.ini` | SDF 模块配置 |

### 测试证书

NTLS 使用双证书体系（签名 + 加密）。Tongsuo 自带测试证书位于 `test/certs/sm2/`：

| 文件 | 说明 |
|------|------|
| `test/certs/sm2/server_sign.crt` / `server_sign.key` | 服务器签名证书/密钥 |
| `test/certs/sm2/server_enc.crt` / `server_enc.key` | 服务器加密证书/密钥 |
| `test/certs/sm2/client_sign.crt` / `client_sign.key` | 客户端签名证书/密钥 |
| `test/certs/sm2/client_enc.crt` / `client_enc.key` | 客户端加密证书/密钥 |
| `test/certs/sm2/chain-ca.crt` | CA 证书链（根 CA + 中间 CA） |

> 测试脚本已配置为自动使用 `test/certs/sm2/` 下的证书。更新硬件密钥时，请将对应的证书/密钥导入 SDF 设备，并确保证书与硬件密钥匹配。

## 支持的密码套件

SDF Provider 配合 NTLS 支持以下密码套件：

| 套件 | 密钥交换 | 说明 |
|------|----------|------|
| `ECC-SM2-SM4-CBC-SM3` | 静态 SM2 | 使用证书中的长期密钥 |
| `ECC-SM2-SM4-GCM-SM3` | 静态 SM2 | GCM 模式 |
| `ECDHE-SM2-SM4-CBC-SM3` | 临时 SM2 (ECDHE) | 前向安全 |
| `ECDHE-SM2-SM4-GCM-SM3` | 临时 SM2 (ECDHE) | 前向安全 + GCM |

## 架构与调用关系

### 分层架构

```
┌─────────────────────────────────────────────────────────────┐
│                    应用层 (apps / SSL)                        │
│  openssl s_server/s_client, EVP_PKEY, EVP_DigestSign 等     │
└──────────────────────┬──────────────────────────────────────┘
                       │ OpenSSL EVP 框架
                       │ (propq="provider=sdfprov" 路由)
┌──────────────────────▼──────────────────────────────────────┐
│               SDF Provider (providers/sdfprov/)              │
│                                                              │
│  ┌──────────┐ ┌───────────┐ ┌────────────┐ ┌─────────────┐ │
│  │ KEYMGMT  │ │ SIGNATURE │ │ ASYM_CIPHER│ │  KEYEXCH    │ │
│  │ (SM2)    │ │ (SM2)     │ │ (SM2)      │ │ (SM2DH)     │ │
│  └────┬─────┘ └─────┬─────┘ └─────┬──────┘ └──────┬──────┘ │
│       │             │             │                │        │
│  ┌────▼─────┐ ┌─────▼─────┐      │           ┌────▼──────┐ │
│  │  STORE   │ │   RAND    │      │           │           │ │
│  │  (sdf)   │ │ (SDF-RAND)│      │           │           │ │
│  └────┬─────┘ └─────┬─────┘      │           │           │ │
└───────┼──────────────┼────────────┼───────────┼───────────┘
        │              │            │           │
        │  统一调用 TSAPI_SDF_* 接口             │
┌───────▼──────────────▼────────────▼───────────▼───────────┐
│          TSAPI 抽象层 (include/openssl/sdf.h)               │
│   TSAPI_SDF_InternalSign_ECC, TSAPI_SDF_ExportPublicKey...  │
└──────────────────────┬─────────────────────────────────────┘
                       │
┌──────────────────────▼─────────────────────────────────────┐
│           SDF 框架层 (crypto/sdf/sdf_lib.c)                 │
│   SDF_METHOD 函数指针表, DSO 动态加载厂商库                  │
│   DSO_load("sdf") → DSO_bind_func("SDF_InternalSign_ECC")  │
└──────────────────────┬─────────────────────────────────────┘
                       │ 运行时 LoadLibrary / dlopen
┌──────────────────────▼─────────────────────────────────────┐
│           厂商库 (byzk0018.dll / libsdf.so)                 │
│   SDF_OpenDevice, SDF_InternalSign_ECC, BYCSM_LoadModule... │
│                                                             │
│   注意：BYCSM_LoadModule 是厂商特定的初始化函数，             │
│   不属于标准 SDF API，由 SDF Provider 在加载时单独调用       │
└─────────────────────────────────────────────────────────────┘
```

### 各层职责

| 层 | 文件 | 职责 |
|----|------|------|
| **SDF Provider** | `providers/sdfprov/` | OpenSSL 3.0 Provider 接口，向 EVP 框架注册 SM2/SM2DH 算法 |
| **TSAPI 抽象层** | `include/openssl/sdf.h` | 声明 `TSAPI_SDF_*` 函数，统一 SDF API 调用接口 |
| **SDF 框架层** | `crypto/sdf/sdf_lib.c` | `SDF_METHOD` 函数指针表，通过 DSO 运行时加载厂商 DLL 中的真实实现 |
| **SDFE 扩展桩** | `crypto/tsapi/sdfe_api_stub.c` | 厂商扩展函数（`SDFE_*`）的默认桩实现，返回 `NOTSUPPORT`，防止无厂商 SDK 时链接失败 |
| **厂商库** | `byzk0018.dll` 等 | 厂家提供的 SDF 驱动，实现标准 SDF API 和厂商扩展函数 |

### sdfe_api.h 说明

`include/sdfe_api.h`（和 `crypto/tsapi/sdfe_api.h` 是同一文件的副本）定义了厂商扩展 API 的类型和函数声明：

- `SDFE_LoginUsr` — 用户登录
- `SDFE_GenECCKey` / `SDFE_DelECCKey` — ECC 密钥生成/删除
- `SDFE_ImportECCKey` / `SDFE_ExportECCPrivKey` — 密钥导入/导出
- `SDFE_BitmapAsymKey` — 密钥位图查询

这些函数不属于国密 SDF 标准规范（GM/T 0028），而是特定厂商的扩展。`sdfe_api_stub.c` 提供默认的桩实现（全部返回 `NOTSUPPORT`），确保编译时不链接厂商 SDK 也能通过。运行时 DSO 加载厂商库后，如果厂商库实现了这些函数，则使用厂商的真实实现。

### 厂商初始化流程

SDF Provider 加载时的初始化顺序：

```
1. OSSL_provider_init()
   └─ 读取 openssl.cnf: sdf_lib_path, sdf_module_password
   └─ 创建 SDFPROV_CTX（不立即打开设备）

2. 首次使用密钥时（KEYMGMT load / STORE open）
   └─ sdfprov_ctx_init_device()
       ├─ sdfprov_load_module(sdf_lib_path, password)
       │   └─ LoadLibrary(byzk0018.dll)          ← 加载厂商 DLL
       │   └─ BYCSM_LoadModule("88888888")       ← 厂商特定的模块初始化
       ├─ TSAPI_SDF_OpenDevice()                  ← 通过 DSO 调用厂商 SDF_OpenDevice
       └─ TSAPI_SDF_OpenSession()                 ← 通过 DSO 调用厂商 SDF_OpenSession
```

### Provider 注册算法

| 操作类型 | 算法名 | 功能 |
|----------|--------|------|
| KEYMGMT | SM2 | 密钥管理（加载/导入/导出/生成/DUP） |
| SIGNATURE | SM2 | 签名/验签（硬件签名 + 软件验签） |
| ASYM_CIPHER | SM2 | 加解密（硬件加解密） |
| KEYEXCH | SM2DH | SM2DH 4 密钥协商（2 临时 + 2 长期） |
| RAND | SDF-RAND | 硬件随机数生成 |
| STORE | sdf | 密钥存储加载（URI 解析） |

## 调试和日志

SDF Provider 使用 OpenSSL 标准 `ERR_raise` 机制报告错误，可通过以下方式诊断：

```bash
# 查看 Provider 错误队列
openssl errstr 0x10101000

# 启用 OpenSSL 跟踪日志（需编译时启用 trace）
OPENSSL_TRACE=provider openssl list -providers

# 常见错误信息
# PROV_R_FAILED_TO_GET_PARAMETER  -- 配置参数读取失败或 SDF 模块加载失败
# PROV_R_FAILED_TO_SIGN            -- SDF 硬件签名失败
# PROV_R_FAILED_TO_DECRYPT         -- SM2 解密失败或 GetPrivateKeyAccessRight 认证失败
# PROV_R_FAILED_TO_GENERATE_KEY    -- SDF 密钥协商失败
```

## 常见问题

### 1. Provider 加载失败

**解决方案**:
- 检查编译时是否启用了 `enable-sdfprov`
- 静态编译时确认 `activate = 1` 即可，不需要 `module` 配置
- 检查依赖库是否完整

### 2. SDF 设备初始化失败

**解决方案**:
- 检查 SDF 厂商库（byzk0018.dll）是否在运行目录或 PATH 中
- 检查 `yj.db` 和 `softModule.ini` 是否在运行目录
- 检查 `sdf_module_password` 是否正确

### 3. 密钥访问失败

**解决方案**:
- 检查密钥索引是否正确
- 检查密钥类型（sign/enc）是否正确
- 检查 URI 中的 `pwd` 参数是否正确
- 部分厂家可关闭私钥访问控制码，此时省略 `pwd` 即可

### 4. 解密失败（GetPrivateKeyAccessRight 返回错误）

**解决方案**:
- 确认 URI 中包含正确的 `pwd` 参数
- 确认该密钥索引的访问控制码是否正确
- 联系设备厂商确认控制码设置

### 5. 与 default Provider 的 SM2 冲突

SDF Provider 注册了与 default Provider 同名的 SM2 算法。使用 `-provider sdfprov -provider default` 时，sdfprov 会优先处理 SM2 操作。如果只需软件 SM2，不要加载 sdfprov。

## 参考资料

- 国密 SDF 规范 (GM/T 0028-2014)
- SM2 密码标准 (GM/T 0003-2012)
- NTLS 协议规范
- GM/T 0015-2023 (SM2 签名 NULL 参数)
- OpenSSL Provider 架构文档

## 版本信息

- **Provider 名称**: Tongsuo SDF Provider
- **版本**: 1.1.0
- **作者**: Tongsuo Project
- **许可证**: Apache License 2.0

---

**最后更新**: 2026-06-23

## 2026-06 增量说明

### RSA 已支持

当前 `sdfprov` 已支持 RSA 硬件密钥能力，不再是“未来支持”状态：

- KEYMGMT：通过 URI / STORE 加载 RSA 签名密钥和加密密钥
- SIGNATURE：RSA 签名与验签
- ASYM_CIPHER：RSA 公钥加密与私钥解密

当前接入的 SDF RSA 接口包括：

- `SDF_ExportSignPublicKey_RSA`
- `SDF_ExportSignPublicKey_RSAEx`
- `SDF_ExportEncPublicKey_RSA`
- `SDF_ExportEncPublicKey_RSAEx`
- `SDF_InternalPublicKeyOperation_RSA`
- `SDF_InternalPrivateKeyOperation_RSA`
- `SDF_InternalPublicKeyOperation_RSA_Ex`
- `SDF_InternalPrivateKeyOperation_RSA_Ex`

说明：

- 普通 `..._RSA` 接口用于 2048 位及以下 RSA 公私钥运算
- 扩展 `..._RSAEx` / `..._RSA_Ex` 接口用于 3072/4096 位场景
- `_RSA_Ex` 版本额外带 `uiKeyUsage`，用于区分签名密钥和加密密钥用途

### 密钥 URI 扩展

除了原有 URI 写法，现在还支持在 URI 中外送会话句柄地址，直接复用外部 session。

推荐写法：

```bash
sdf:key=1;type=sign;algo=rsa;pwd=12345678
sdf:key=1;type=enc;algo=rsa
sdf:key=1;type=sign;algo=rsa;session=0x12345678
sdf:key=1;type=enc;algo=sm2;session=12345678
```

兼容写法：

```bash
sdf:key=1;type=sign;algo=rsa;session=session:12345678
sdf:rsa:1:sign:mypwd:session:12345678
```

URI 参数说明补充：

- `algo`：支持 `sm2` 和 `rsa`
- `type`：支持 `sign` 和 `enc`
- `pwd`：私钥访问控制码，可选
- `session`：外部会话句柄地址，可选，支持十进制和十六进制字符串

### 外部 Session 使用约定

- 传入 `session` 后，Provider 直接使用外部会话句柄，不再为该密钥自动创建会话
- 外部会话生命周期由调用方负责，Provider 不会关闭该会话
- `pwd` 与 `session` 可以同时使用，适用于“外部会话 + 私钥访问控制码”场景
- 推荐优先使用 `key=value` 风格 URI；旧的 `sdf:<algo>:<index>:<type>[:<pwd>]` 仍兼容

### RSA 示例

RSA 签名：

```bash
openssl dgst -provider sdfprov -provider default -sha256 \
  -sign "sdf:key=1;type=sign;algo=rsa;pwd=12345678" \
  -out sig.bin data.txt
```

RSA 公钥加密：

```bash
openssl pkeyutl -provider sdfprov -provider default \
  -encrypt -pubin \
  -inkey "sdf:key=1;type=enc;algo=rsa" \
  -in plaintext.txt -out ciphertext.bin
```

RSA 私钥解密（复用外部 session）：

```bash
openssl pkeyutl -provider sdfprov -provider default \
  -decrypt \
  -inkey "sdf:key=1;type=enc;algo=rsa;pwd=12345678;session=0x12345678" \
  -in ciphertext.bin -out plaintext.txt
```

RSA 鏈€灏忚仈璋冩祴璇曪細

```bash
test_sdfprov_rsa.exe \
  "sdf:key=1;type=sign;algo=rsa;pwd=12345678" \
  "sdf:key=1;type=enc;algo=rsa;pwd=12345678;session=0x12345678" \
  SHA256
```

## 2026-07 增量说明

### dgst 命令支持 SM2/RSA 硬件签名验签

`openssl dgst` 通过 `sdf:` URI 加载 SDF 硬件私钥完成签名，用证书公钥完成验签。
底层 `load_key()` 走 `OSSL_STORE_open_ex`，自动按 scheme 路由到 SDF Provider，
不需要额外改 apps 代码。

#### SM2 签名 / 验签

```bash
# 签名（SDF 硬件私钥）
openssl dgst -sm3 -provider sdfprov -provider default \
  -sign "sdf:sm2:0:sign" -out sig.bin data.txt

# 验签：先从签名证书提取公钥
openssl x509 -in test/certs/sm2/server_sign.crt -pubkey -noout > sm2pub.pem
openssl dgst -sm3 -provider sdfprov -provider default \
  -verify sm2pub.pem -signature sig.bin data.txt
```

#### RSA 签名 / 验签

```bash
# 签名（SDF 硬件私钥，默认 PKCS1）
openssl dgst -sha256 -provider sdfprov -provider default \
  -sign "sdf:rsa:0:sign" -out sig.bin data.txt

# 验签
openssl x509 -in test/certs/server-rsa-sign.crt -pubkey -noout > rsapub.pem
openssl dgst -sha256 -provider default \
  -verify rsapub.pem -signature sig.bin data.txt
```

### PKCS7 数字信封（封装 / 解封）

`openssl pkcs7 -encrypt/-decrypt` 支持数字信封。`PKCS7_encrypt_ex` 已修复为
纯信封语义——`-encrypt` 默认就是 EnvelopedData，无需 `-nosigs`（与 cms/smime
一致）。SM2 信封使用 `sm2_enveloped` OID（需 `-gmt0010`），标准信封使用
`pkcs7_enveloped` OID。

#### SM2 数字信封

```bash
# 封装：用 SM2 加密证书公钥
openssl pkcs7 -encrypt -provider sdfprov -provider default \
  -in plain.txt -out sm2_env.p7 -outform DER \
  test/certs/sm2/server_enc.crt

# 解封：用 SDF 硬件 SM2 加密私钥
openssl pkcs7 -decrypt -provider sdfprov -provider default \
  -in sm2_env.p7 -inform DER -out plain2.txt \
  -inkey "sdf:sm2:0:enc" -recip test/certs/sm2/server_enc.crt
```

#### RSA 数字信封

```bash
# 封装：用 RSA 加密证书公钥
openssl pkcs7 -encrypt -provider sdfprov -provider default \
  -in plain.txt -out rsa_env.p7 -outform DER \
  test/certs/server-rsa-enc.crt

# 解封：用 SDF 硬件 RSA 加密私钥
openssl pkcs7 -decrypt -provider sdfprov -provider default \
  -in rsa_env.p7 -inform DER -out plain2.txt \
  -inkey "sdf:rsa:0:enc" -recip test/certs/server-rsa-enc.crt
```

> **注意**：RSA 信封解封依赖 SDF 设备的 RSA 加密密钥（`SDF_InternalPrivateKeyOperation_RSA`
> 走 `key_type=enc`）。请确认设备 0 号索引已导入与 `server-rsa-enc.crt` 匹配的
> RSA 加密密钥对，否则解封会因 `RSA_padding_check_PKCS1_type_2` 失败。

### 测试证书路径速查

| 用途 | 证书 / 密钥 |
|------|------------|
| SM2 签名验签 | `test/certs/sm2/server_sign.crt` |
| SM2 信封（解封侧） | `test/certs/sm2/server_enc.crt` |
| RSA 签名验签 | `test/certs/server-rsa-sign.crt` |
| RSA 信封（解封侧） | `test/certs/server-rsa-enc.crt` |

### 常见坑：OPENSSL_CONF 必须指向正确配置

若运行时报 `0x01020003` 等厂商错误码，通常是加载了错误的 `openssl.cnf`。
Tongsuo 默认读取 `OPENSSLDIR/openssl.cnf`（如 `C:\Program Files\Common Files\SSL\openssl.cnf`），
该文件可能未配置 `sdf_use_loadmodule` 或 `sdf_lib_path` 错误。

**解决**：显式设置环境变量指向项目自带的配置：

```bash
# Windows
set OPENSSL_CONF=E:\path\to\Tongsuo\apps\openssl.cnf
# 关键配置项：
#   sdf_lib_path = <绝对路径>\byzk0018.dll
#   sdf_use_loadmodule = 1
#   sdf_module_password = 88888888
```

### 一键测试

```bash
# 在 apps 目录下执行，覆盖 SM2/RSA 签名验签 + SM2 信封 + RSA 信封
test_sdf_sign_envelope.bat
```

## pkeyutl 命令使用说明（SM2/RSA 硬件加解密与签名验签）

`openssl pkeyutl` 是非对称密码运算的基础命令，支持签名、验签、加密、解密和密钥派生。
通过 `sdf:` URI 加载 SDF 硬件密钥，私钥永不出卡，所有私钥操作由硬件完成。

### 前置条件

```bash
# 必须设置 OPENSSL_CONF 指向正确配置（sdf_use_loadmodule=1）
set OPENSSL_CONF=...\apps\openssl.cnf

# 加载 SDF Provider + default Provider
set PROV=-provider sdfprov -provider default
```

### 1. SM2 签名与验签

```bash
# SM2 签名（硬件私钥，-rawin + -digest sm3 走 Provider 的 digest_sign 路径，
# 内部自动完成 SM3 摘要 + Z 值预处理 + 硬件 SM2 签名）
openssl pkeyutl -sign -rawin -digest sm3 %PROV% \
  -inkey "sdf:sm2:0:sign" \
  -in data.txt -out sm2_sig.bin

# SM2 验签（证书公钥，用 default Provider 即可）
openssl pkeyutl -verify -rawin -digest sm3 -provider default \
  -inkey sm2_sign_pub.pem -pubin \
  -sigfile sm2_sig.bin \
  -in data.txt
```

> **提示**：从证书提取公钥：`openssl x509 -in server_sign.crt -pubkey -noout > sm2_sign_pub.pem`

### 2. RSA 签名与验签

```bash
# RSA 签名（硬件私钥，默认 PKCS#1 v1.5 + SHA256）
openssl pkeyutl -sign -rawin -digest sha256 %PROV% \
  -inkey "sdf:rsa:0:sign" \
  -in data.txt -out rsa_sig.bin

# RSA 验签（证书公钥）
openssl pkeyutl -verify -rawin -digest sha256 -provider default \
  -inkey rsa_sign_pub.pem -pubin \
  -sigfile rsa_sig.bin \
  -in data.txt
```

> **注意**：`-rawin` 表示输入是原始数据（未预先哈希），`-digest` 指定摘要算法。
> 不加 `-rawin` 时，输入必须是已计算好的摘要值（裸签模式）。

### 3. SM2 加密与解密（普通加解密，非数字信封）

```bash
# SM2 加密（使用加密证书的公钥，软件加密）
openssl pkeyutl -encrypt -provider default \
  -inkey sm2_enc_pub.pem -pubin \
  -in plaintext.txt -out sm2_ct.bin

# SM2 解密（硬件加密私钥，私钥不出卡）
openssl pkeyutl -decrypt %PROV% \
  -inkey "sdf:sm2:0:enc" \
  -in sm2_ct.bin -out sm2_pt.txt
```

### 4. RSA 加密与解密（普通加解密）

```bash
# RSA 加密（使用加密证书的公钥）
openssl pkeyutl -encrypt -provider default \
  -inkey rsa_enc_pub.pem -pubin \
  -in plaintext.txt -out rsa_ct.bin

# RSA 解密（硬件加密私钥）
openssl pkeyutl -decrypt %PROV% \
  -inkey "sdf:rsa:0:enc" \
  -in rsa_ct.bin -out rsa_pt.txt
```

> **注意**：RSA sign 和 enc 是不同的密钥槽位（由 SDF 设备 `uiKeyUsage` 区分）。
> Provider 会优先走 `_Ex` 扩展接口（带 `uiKeyUsage` 参数），正确路由到对应密钥。

### 5. 直接使用证书做公钥操作（-certin）

```bash
# 用证书直接加密（省去提取公钥步骤）
openssl pkeyutl -encrypt -provider default \
  -certin -inkey server_enc.crt \
  -in plaintext.txt -out ct.bin

# 用证书验签
openssl pkeyutl -verify -rawin -digest sm3 -provider default \
  -certin -inkey server_sign.crt \
  -sigfile sig.bin -in data.txt
```

### URI 参数说明

| URI 格式 | 示例 | 说明 |
|---------|------|------|
| `sdf:sm2:<index>:sign[:<pwd>]` | `sdf:sm2:0:sign` | SM2 签名密钥 |
| `sdf:sm2:<index>:enc[:<pwd>]` | `sdf:sm2:0:enc:11111111` | SM2 加密密钥 |
| `sdf:rsa:<index>:sign[:<pwd>]` | `sdf:rsa:0:sign` | RSA 签名密钥 |
| `sdf:rsa:<index>:enc[:<pwd>]` | `sdf:rsa:0:enc` | RSA 加密密钥 |
| `sdf:key=<i>;type=<t>;algo=<a>[;pwd=<p>]` | `sdf:key=0;type=sign;algo=sm2` | key=value 风格 |

### pkeyutl vs dgst 命令区别

| 特性 | `pkeyutl` | `dgst` |
|------|-----------|--------|
| 签名输入 | 原始数据（`-rawin`）或摘要 | 原始数据（自动哈希） |
| 摘要指定 | `-digest <algo>`（配合 `-rawin`） | `-<algo>`（如 `-sm3`、`-sha256`） |
| 输出格式 | 纯签名值 | 可附加签名者信息 |
| 适用场景 | 底层密码运算 | 文件摘要 + 签名一步完成 |

两个命令都能加载 SDF 硬件密钥（通过 `-inkey "sdf:..."` 或 `-sign "sdf:..."`），
底层走相同的 Provider 路径。推荐：
- **简单签名验签**用 `dgst`（更简洁）
- **需要精确控制（如指定 padding、KDF）**用 `pkeyutl`

### RSA Padding 模式说明

SDF Provider 的 RSA 默认使用 PKCS#1 v1.5 padding。如需指定：

```bash
# PKCS#1 v1.5（默认）
openssl pkeyutl -sign -rawin -digest sha256 %PROV% \
  -inkey "sdf:rsa:0:sign" -pkeyopt rsa_padding_mode:pkcs1 \
  -in data.txt -out sig.bin
```

> **注意**：SDF Provider 当前支持 PKCS#1 v1.5（签名 type 1 / 加密 type 2）。
> OAEP/PSS 等 padding 模式需要厂商 SDF 库支持。

### 常见问题

**Q: pkeyutl 报 "Could not find private key"？**
- 检查 `-provider sdfprov -provider default` 是否都加载
- 检查 `OPENSSL_CONF` 是否指向正确配置（`sdf_use_loadmodule=1`）
- 检查 URI 格式是否正确（`sdf:sm2:0:sign` 而非 `sm2:0:sign`）

**Q: RSA 加密密钥解密报 padding error？**
- 确认使用的是 enc 密钥（`sdf:rsa:0:enc`）而非 sign 密钥
- 确认加密用的证书公钥与解密用的硬件私钥配对

**Q: SM2 签名时摘要如何处理？**
- `-rawin -digest sm3`：输入原始数据，Provider 内部做 SM3 + Z 值预处理 + 硬件签名
- 不加 `-rawin`：输入必须是 32 字节 SM3 摘要值（裸签，不做 Z 值预处理）


