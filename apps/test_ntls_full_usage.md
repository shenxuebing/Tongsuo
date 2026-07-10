# `test_ntls_full` 使用说明

## 1. 脚本用途

`test_ntls_full.bat` / `test_ntls_full.sh` 用于验证 `NTLS + SM2` 的完整握手矩阵，覆盖：

- 密码套件
  - `ECC-SM2-SM4-CBC-SM3`
  - `ECDHE-SM2-SM4-CBC-SM3`
- 端点密钥模式
  - 服务端软件 / 客户端软件
  - 服务端硬件 / 客户端软件
  - 服务端软件 / 客户端硬件
  - 服务端硬件 / 客户端硬件

合计 `2 x 4 = 8` 组场景。

## 2. 脚本位置

- Windows: [test_ntls_full.bat](/abs/path/E:/vs2022workspace/Tongsuo/apps/test_ntls_full.bat:1)
- Linux/WSL: [test_ntls_full.sh](/abs/path/E:/vs2022workspace/Tongsuo/apps/test_ntls_full.sh:1)

## 3. 适用范围

这个脚本只用于 `NTLS SM2` 测试。

当前支持的证书类型：

- `sm2`

当前不支持的 profile：

- `rsa2048`
- `rsa3072`
- `rsa4096`

如果传入 RSA profile，脚本会直接报错退出。RSA 相关能力请使用 `test_sdf_cross`。

## 4. 默认行为

不传参数时，默认配置如下：

- 证书目录：`../test/certs/sm2`
- CA 文件：`../test/certs/sm2/chain-ca.crt`
- 服务端硬件索引
  - 签名：`0`
  - 加密：`0`
- 客户端硬件索引
  - 签名：`1`
  - 加密：`1`

## 5. 基本用法

### Windows

```bat
cd /d E:\vs2022workspace\Tongsuo\apps
test_ntls_full.bat SERVER_HW_SIGN_IDX=0 SERVER_HW_ENC_IDX=0 CLIENT_HW_SIGN_IDX=1 CLIENT_HW_ENC_IDX=1
```

### Linux / WSL

```bash
cd /mnt/e/vs2022workspace/Tongsuo/apps
./test_ntls_full.sh SERVER_HW_SIGN_IDX=0 SERVER_HW_ENC_IDX=0 CLIENT_HW_SIGN_IDX=1 CLIENT_HW_ENC_IDX=1
```

## 6. 支持的参数

### 通用参数

- `OPENSSL_CONF`
- `SDF_LIB_PATH`
- `SDF_MODULE_PASSWORD`
- `SDF_USE_LOADMODULE`
- `CERTS`
- `CAFILE`

### 证书 profile 参数

- `SERVER_CERT_PROFILE`
- `CLIENT_CERT_PROFILE`

当前合法值只有：

- `sm2`

### 服务端软件证书/密钥覆盖参数

- `SERVER_SIGN_CERT`
- `SERVER_ENC_CERT`
- `SERVER_SIGN_KEY`
- `SERVER_ENC_KEY`

### 客户端软件证书/密钥覆盖参数

- `CLIENT_SIGN_CERT`
- `CLIENT_ENC_CERT`
- `CLIENT_SIGN_KEY`
- `CLIENT_ENC_KEY`

### 硬件索引参数

- `SERVER_HW_SIGN_IDX`
- `SERVER_HW_ENC_IDX`
- `CLIENT_HW_SIGN_IDX`
- `CLIENT_HW_ENC_IDX`

## 7. 常用示例

### 标准全量 NTLS 测试

```bat
test_ntls_full.bat SERVER_CERT_PROFILE=sm2 CLIENT_CERT_PROFILE=sm2
```

### 指定硬件索引

```bat
test_ntls_full.bat ^
SERVER_HW_SIGN_IDX=0 ^
SERVER_HW_ENC_IDX=0 ^
CLIENT_HW_SIGN_IDX=1 ^
CLIENT_HW_ENC_IDX=1
```

### 覆盖 SM2 证书路径

```bat
test_ntls_full.bat ^
SERVER_SIGN_CERT=..\test\certs\sm2\server_sign.crt ^
SERVER_ENC_CERT=..\test\certs\sm2\server_enc.crt ^
CLIENT_SIGN_CERT=..\test\certs\sm2\client_sign.crt ^
CLIENT_ENC_CERT=..\test\certs\sm2\client_enc.crt
```

Linux/WSL:

```bash
./test_ntls_full.sh \
SERVER_HW_SIGN_IDX=0 \
SERVER_HW_ENC_IDX=0 \
CLIENT_HW_SIGN_IDX=1 \
CLIENT_HW_ENC_IDX=1 \
SERVER_CERT_PROFILE=sm2 \
CLIENT_CERT_PROFILE=sm2
```

## 8. 输出结果说明

- `PASS`：握手成功
- `FAIL`：握手未成功完成
- `TIMEOUT`：客户端在限定时间内没有结束，被脚本强制终止

## 9. 使用建议

- 建议在 `apps` 目录下运行脚本。
- `openssl.cnf` 需要是启用了 `NTLS` 和 `sdfprov` 的配置。
- 脚本会在每组场景前后清理旧的 `openssl` 进程。
- 硬件场景之间脚本会有等待时间，用于释放设备资源。
- 这个脚本不覆盖 RSA 证书握手测试，RSA 相关验证请走 `test_sdf_cross`。
