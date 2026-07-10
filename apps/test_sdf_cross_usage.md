# `test_sdf_cross` 使用说明

## 1. 脚本用途

`test_sdf_cross.bat` / `test_sdf_cross.sh` 用于验证 `sdfprov` 的软硬件交叉场景，覆盖以下能力：

- `SM2`
  - P1 签名/验签
  - 明文加密/解密
  - `PKCS7` 签名/验签
  - `PKCS7` 信封加密/解密
- `RSA2048 / RSA3072 / RSA4096`
  - P1 签名/验签
  - 明文加密/解密
  - `PKCS7` 签名/验签
  - `S/MIME` 信封加密/解密

这个脚本既能测纯软件，也能测硬件签名/解密，还能测软件证书配合硬件密钥的交叉路径。

## 2. 脚本位置

- Windows: [test_sdf_cross.bat](/abs/path/E:/vs2022workspace/Tongsuo/apps/test_sdf_cross.bat:1)
- Linux/WSL: [test_sdf_cross.sh](/abs/path/E:/vs2022workspace/Tongsuo/apps/test_sdf_cross.sh:1)

## 3. 默认行为

不传参数时，脚本默认使用下面的配置：

- `SM2`
  - 签名索引：`0`
  - 加密索引：`0`
  - 证书/软件密钥：`../test/certs/sm2/server_*`
- `RSA2048`
  - 签名索引：`0`
  - 加密索引：`0`
  - 证书/软件密钥：`../test/certs/server-rsa-*`
- `RSA3072`
  - 默认不启用，只有传入索引后才测试
  - 默认证书/软件密钥：`../test/certs/client_3072_*`
- `RSA4096`
  - 默认不启用，只有传入索引后才测试
  - 默认证书/软件密钥：`../test/certs/client_4096_*`

## 4. 基本用法

### Windows

```bat
cd /d E:\vs2022workspace\Tongsuo\apps
test_sdf_cross.bat RSA2048_IDX=0 RSA3072_IDX=1 RSA4096_IDX=2
```

### Linux / WSL

```bash
cd /mnt/e/vs2022workspace/Tongsuo/apps
./test_sdf_cross.sh RSA2048_IDX=0 RSA3072_IDX=1 RSA4096_IDX=2
```

## 5. 支持的参数

### 通用参数

- `OPENSSL_CONF`
- `SDF_LIB_PATH`
- `SDF_MODULE_PASSWORD`
- `SDF_USE_LOADMODULE`
- `TMP`

### SM2 参数

- `SM2_SIGN_IDX`
- `SM2_ENC_IDX`
- `SM2_SIGN_CERT`
- `SM2_SIGN_KEY`
- `SM2_ENC_CERT`
- `SM2_ENC_KEY`
- `SM2_CAFILE`

### RSA 简写参数

- `RSA2048_IDX`
- `RSA3072_IDX`
- `RSA4096_IDX`

这些是简写形式。传入后会同时作为该算法的签名索引和加密索引。

### RSA 完整参数

- `RSA2048_SIGN_IDX`
- `RSA2048_ENC_IDX`
- `RSA2048_SIGN_CERT`
- `RSA2048_SIGN_KEY`
- `RSA2048_ENC_CERT`
- `RSA2048_ENC_KEY`

- `RSA3072_SIGN_IDX`
- `RSA3072_ENC_IDX`
- `RSA3072_SIGN_CERT`
- `RSA3072_SIGN_KEY`
- `RSA3072_ENC_CERT`
- `RSA3072_ENC_KEY`

- `RSA4096_SIGN_IDX`
- `RSA4096_ENC_IDX`
- `RSA4096_SIGN_CERT`
- `RSA4096_SIGN_KEY`
- `RSA4096_ENC_CERT`
- `RSA4096_ENC_KEY`

## 6. 常用示例

### 仅测试 SM2 和 RSA2048

```bat
test_sdf_cross.bat SM2_SIGN_IDX=0 SM2_ENC_IDX=0 RSA2048_IDX=0
```

### 测试 RSA3072 和 RSA4096

```bat
test_sdf_cross.bat RSA3072_IDX=1 RSA4096_IDX=2
```

### 签名索引和加密索引分开指定

```bat
test_sdf_cross.bat RSA3072_SIGN_IDX=1 RSA3072_ENC_IDX=3
```

### 覆盖证书路径

```bat
test_sdf_cross.bat ^
RSA4096_SIGN_IDX=2 ^
RSA4096_ENC_IDX=2 ^
RSA4096_SIGN_CERT=..\test\certs\client_4096_sign.crt ^
RSA4096_ENC_CERT=..\test\certs\client_4096_enc.crt
```

Linux/WSL:

```bash
./test_sdf_cross.sh \
RSA4096_SIGN_IDX=2 \
RSA4096_ENC_IDX=2 \
RSA4096_SIGN_CERT=../test/certs/client_4096_sign.crt \
RSA4096_ENC_CERT=../test/certs/client_4096_enc.crt
```

### 按你当前导入的索引做完整测试

```bat
test_sdf_cross.bat SM2_SIGN_IDX=0 SM2_ENC_IDX=0 RSA2048_IDX=0 RSA3072_IDX=1 RSA4096_IDX=2
```

## 7. 结果说明

- `OK`：该项测试通过
- `WARN`：通常表示设备里没有对应密钥、证书和索引不匹配，或该项属于可选能力
- `FAIL`：命令执行失败或功能路径失败

## 8. 使用建议

- Windows 下建议先 `cd` 到 `apps` 目录再运行。
- Linux/WSL 下要确保 `OPENSSL_CONF` 指向启用了 provider 的 `openssl.cnf`。
- `RSA3072`、`RSA4096` 测试前，硬件索引中的密钥必须和证书严格匹配。
- RSA 软件侧加密脚本内部使用的是 `pkeyutl -certin`，不依赖单独导出的公钥文件。
