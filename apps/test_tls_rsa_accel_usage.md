# `test_tls_rsa_accel` 使用说明

## 1. 脚本用途

`test_tls_rsa_accel.bat` / `test_tls_rsa_accel.sh` 用于验证 `sdfprov` 的标准 `TLS RSA` 加速能力，当前覆盖两类场景：

- `ECDHE-RSA`：验证服务端硬件 RSA 签名
- `TLS_RSA`：验证服务端硬件 RSA 解密

## 2. 当前支持边界

当前脚本默认验证两类 `ECDHE-RSA` 握手签名：

- `default`：默认协商，当前已验证可走 `RSA-PSS`
- `compat`：固定 `rsa_pkcs1_sha256`，用于兼容性回归

## 3. 脚本位置

- Windows: [test_tls_rsa_accel.bat](/abs/path/E:/vs2022workspace/Tongsuo/apps/test_tls_rsa_accel.bat:1)
- Linux/WSL: [test_tls_rsa_accel.sh](/abs/path/E:/vs2022workspace/Tongsuo/apps/test_tls_rsa_accel.sh:1)

## 4. 默认行为

不传参数时默认使用：

- `RSA_SIGN_IDX=0`
- `RSA_ENC_IDX=0`
- `RSA_SIGN_CERT=../test/certs/server-rsa-sign.crt`
- `RSA_ENC_CERT=../test/certs/server-rsa-enc.crt`
- `TLS_VERSION=-tls1_2`
- `ECDHE_CIPHER=ECDHE-RSA-AES128-GCM-SHA256`
- `RSA_CIPHER=AES128-SHA`
- `RSA_SIGALGS=rsa_pkcs1_sha256`

## 5. 基本用法

### Windows

```bat
cd /d E:\vs2022workspace\Tongsuo\apps
test_tls_rsa_accel.bat RSA_SIGN_IDX=0 RSA_ENC_IDX=0
```

### Linux / WSL

```bash
cd /mnt/e/vs2022workspace/Tongsuo/apps
./test_tls_rsa_accel.sh RSA_SIGN_IDX=0 RSA_ENC_IDX=0
```

## 6. 支持的参数

- `OPENSSL_CONF`
- `RSA_SIGN_IDX`
- `RSA_ENC_IDX`
- `RSA_SIGN_CERT`
- `RSA_ENC_CERT`
- `TLS_VERSION`
- `ECDHE_CIPHER`
- `RSA_CIPHER`
- `RSA_SIGALGS`
- `RSA_SIGALGS_COMPAT`
- `PORT_SIGN`
- `PORT_DEC`

## 7. 常用示例

### 使用 0 号索引测试

```bat
test_tls_rsa_accel.bat RSA_SIGN_IDX=0 RSA_ENC_IDX=0
```

### 使用不同的签名和解密索引

```bat
test_tls_rsa_accel.bat RSA_SIGN_IDX=1 RSA_ENC_IDX=2

### 只测默认协商，不跑兼容项

```bat
test_tls_rsa_accel.bat RSA_SIGN_IDX=0 RSA_ENC_IDX=0 RSA_SIGALGS_COMPAT=
```
```

### 覆盖证书路径

```bat
test_tls_rsa_accel.bat ^
RSA_SIGN_IDX=0 ^
RSA_ENC_IDX=0 ^
RSA_SIGN_CERT=..\test\certs\server-rsa-sign.crt ^
RSA_ENC_CERT=..\test\certs\server-rsa-enc.crt
```

## 8. 结果说明

- `PASS`：该项 TLS 握手通过
- `FAIL`：该项 TLS 握手失败

## 9. 说明

- `ECDHE-RSA default` 成功表示默认协商下的服务端握手签名已走硬件 RSA 签名路径
- `ECDHE-RSA compat` 成功表示 `rsa_pkcs1_sha256` 兼容模式也正常
- `TLS_RSA` 成功表示服务端 premaster secret 解密已走硬件 RSA 解密路径
