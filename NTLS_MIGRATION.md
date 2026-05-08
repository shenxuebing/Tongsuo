# Tongsuo dev-v2 分支迁移说明文档（完整版）

## 概述

本文档详细描述了从 `dev` 分支到 `migration/dev-v2` 分支的所有代码迁移内容，包括新增功能、算法增强、Bug修复、架构优化等各个方面。

## 分支信息

- **源分支**: `dev`
- **目标分支**: `migration/dev-v2`
- **提交数量**: 286 个提交
- **基础版本**: OpenSSL 3.5.4 (commit 65f8038fc0dbe6816d6a982222e46e53729cb435)

## 主要变更分类

### 一、NTLS 和 SDF Provider 相关（最新迁移）

#### 1.1 软硬交叉认证矩阵测试
- **文件**: `apps/test_both_ciphersuites.c`
- **功能**: 支持 4 种服务器/客户端软硬密钥加载组合的矩阵测试
- **测试套件**: ECC-SM2-SM4-CBC-SM3 和 ECDHE-SM2-SM4-CBC-SM3
- **组合配置**:
  - 服务器软密钥 + 客户端软密钥
  - 服务器软密钥 + 客户端硬密钥
  - 服务器硬密钥 + 客户端软密钥
  - 服务器硬密钥 + 客户端硬密钥

#### 1.2 ECDHE-SM2 客户端临时密钥生成修复
- **文件**: `ssl/statem_ntls/ntls_statem_clnt.c`
- **函数**: `tls_construct_cke_sm2dhe_ntls`
- **修复**: 
  - 添加 Provider 检测逻辑
  - 仅在本地加密密钥为软件密钥时生成软件临时密钥
  - 修复软硬交叉认证握手失败问题

#### 1.3 SDF Provider 加速模式
- **功能**: 新增 SDF Provider 加速模式支持
- **修复**: ECC-SM2-SM4-CBC-SM3 套件添加 uiAlgID 参数和服务器间通信控制码支持
- **修复**: 编译链接错误，补全缺失的 CMS 函数

#### 1.4 EVP Helper API
- **文件**: `include/openssl/evp.h`, `crypto/evp/pmeth_lib.c`
- **新增**: `EVP_PKEY_CTX_set_sm2_encdata_format` 函数
- **功能**: 设置 SM2 加密数据格式（0=C1C3C2, 1=C1C2C3）
- **验证**: 输入参数验证，通过 EVP_PKEY_CTX_set_params 设置参数

#### 1.5 SM2 相关完善
- **完善**: GM/T 0006 HMAC-SM3 OID (sm3 2)
- **更新**: SM2/ASN1 编码适配最新 API
- **移除**: Engine SM2 回调扩展和 SDF/SKF 驱动（迁移到 Provider）
- **完善**: SM1 OID、EC PRIVATEKEY INT 和 PKCS7 国密密钥
- **恢复**: RC2 算法支持
- **修复**: 函数签名变更导致的编译错误

#### 1.6 NTLS/SDF 集成基础改造
- **新增**: NTLS/SDF 集成基础改造
- **新增**: SM2DHE 密钥协商模块
- **新增**: ASN1 签名 SM2 NULL 参数修改（GM/T 0015-2023）
- **增强**: SM2 算法增强功能
- **新增**: 辅助功能模块（log.h + OID）

#### 1.7 SM2MLKEM768
- **实现**: SM2MLKEM768 算法
- **修改**: SM2-MLKEM768 群名称改为 curveSM2MLKEM768

### 二、零知识证明（ZKP）算法

#### 2.1 Bulletproofs（范围证明）
- **实现**: Bulletproofs 范围证明算法
- **功能**:
  - 支持 Bulletproofs 参数和证明的编码/解码
  - 多范围证明支持
  - 范围限制为 2 的幂次
  - 添加锁和引用计数
  - 错误处理（ERR_raise）
- **测试**: 添加 Bulletproofs 应用子命令实现和测试用例
- **性能**: 添加 Bulletproofs 算法性能测试

#### 2.2 NIZKPoK（非交互式零知识证明）
- **实现**: NIZKPoK 算法
- **集成**: 集成 TRANSCRIPT 用于 ZKP
- **集成**: 集成 ZKP 工具函数

#### 2.3 Paillier（同态加密）
- **实现**: Paillier 同态加密算法
- **功能**:
  - 支持负数运算
  - 支持指定密钥位大小
  - 支持 Engine 设置，可支持硬件加速
  - 优化加密过程
- **测试**: 添加 Paillier 应用子命令实现和测试用例
- **性能**: 添加 Paillier 算法性能测试，支持其他位长度密钥

#### 2.4 EC-ElGamal
- **实现**: EC-ElGamal 算法
- **实现**: Twisted-EC-ElGamal 算法
- **功能**: 支持 EC_POINT_from_string
- **测试**: 添加 EC-ElGamal 应用子命令实现和测试用例
- **性能**: 添加 EC-ElGamal 算法性能测试
- **优化**: 优化 test_app_ec_elgamal.t 执行时间

#### 2.5 BIGNUM 方法机制
- **实现**: BIGNUM 操作支持方法机制
- **实现**: BN_mul 支持 bn-method

### 三、白盒 SM4（White-box SM4）

#### 3.1 白盒 SM4 算法
- **实现**: 白盒 SM4 算法
- **变体**: 
  - wbsm4-xiaolai（小白）
  - wbsm4-baiwu（白雾）
  - wbsm4-wsise
- **KDF**: wbsm4kdf
- **配置**: 添加配置选项 enable-wbsm4-xiaolai/baiwu/wsise
- **更新**: 更新 evp.h 和 libcrypto.num

### 四、SM2 阈值密码

#### 4.1 SM2 阈值签名
- **实现**: SM2 两方阈值签名
- **性能**: speed 命令添加 sm2-threshold-sign, sm2-threshold-decrypt, sm2-crypt
- **修复**: 修复 SM2_THRESHOLD_sign 资源泄漏

#### 4.2 SM2 阈值加密
- **实现**: SM2 两方阈值解密
- **功能**: 支持阈值加密和解密操作

### 五、SM2 算法增强

#### 5.1 性能优化
- **64位优化**: 添加 SM2 64位平台优化
- **快速模约简**: 添加 SM2 快速模约简算法
- **编译分离**: SM2 和 NIST 优化编译分离
- **条件优化**: AARCH64 仅在启用 ec_sm2p_64_gcc_128 时使用优化的 SM2 实现
- **原始实现**: 使用 Tongsuo 原始的 ecp_sm2p256 实现

#### 5.2 功能增强
- **Za 参数**: 支持通过 "sm2-za:no" 参数禁用 Za
- **测试**: 添加 SM2 without Za 测试用例
- **公钥修复**: 修复过时的 SM2 公钥
- **编码兼容**: 保持 SM2 在 EC 中的封装以兼容常见实现

#### 5.3 API 增强
- **EVP_CIPHER_CTX**: 添加 EVP_CIPHER_CTX_get_buf_len 和 EVP_CIPHER_CTX_get_final_used
- **EC_POINT**: 添加获取 EC_POINT 曲线名称的 API
- **批量计算**: 添加支持椭圆曲线点批量计算的 API（隐私计算场景）

### 六、TLS 1.3 商密套件（RFC 8998）

#### 6.1 RFC 8998 支持
- **实现**: 实现 RFC 8998 支持
- **修复**: 修复 TLS 1.3 使用商密套件时未严格遵循 RFC 8998 问题（#491）
- **修复**: SM2 KeyShareEntry 必须包含在启用 TLS1.3 + SM 时的 ClientHello 中（#522）
- **修复**: 修复 NTLS 设置 TLS 版本范围时的失败问题（#513）
- **调整**: 将 RFC 8998 TLS 1.3 套件移动到正确位置
- **移除**: 从 QUIC 默认套件列表中移除 RFC 8998 套件

#### 6.2 HMAC_SM3 计算
- **实现**: 使用 ssl3_cbc_digest_record 计算 TLS/TLCP CBC 记录的 HMAC_SM3

### 七、NTLS 相关修复

#### 7.1 NTLS 配置
- **新增**: force-ntls 配置选项（#348）
- **修复**: NTLS CI 问题
- **修复**: NTLS 编译问题

#### 7.2 TLCP SNI 测试
- **功能**: s_server 支持 TLCP SNI 测试

### 八、随机数熵源增强

#### 8.1 熵源扩展
- **重构**: 重构 RAND_set_entropy_source，支持传入逗号分隔的多个熵源
- **RTC 方案**: 随机数熵源增加系统时间（RTC）方案
  - 通过反复获取系统时间（real-time clock）来产生不可预测的数据
  - 算法依赖于执行代码或读写内存时，受缓存未命中、系统中断、调度等多个因素影响
  - 导致消耗的时间不确定，从而每次获取的系统时间也不确定

### 九、证书验证增强

#### 9.1 上下文验证
- **新增**: X509 添加支持上下文的验证接口
- **新增**: 允许证书验证使用自定义 vfyopts
- **应用**: apps 使用支持上下文的证书验证接口
- **修改**: ASN1_item_verify_ctx() 不再执行 DigestVerifyInit

#### 9.2 证书匹配验证
- **新增**: 支持在 SSL 握手期间验证证书和 server_name 的匹配

### 十、ZUC 算法

#### 10.1 ZUC 流密码
- **实现**: 添加中国 ZUC 流密码
- **变体**: zuc-128-eea3 流密码
- **优化**: ZUC 算法优化
- **性能**: speed 命令支持 zuc-128-eea3
- **修复**: 修复 zuc-128-eea3 default provider 内存泄漏
- **实现**: 实现 zuc_128_eea3_dupctx

#### 10.2 ZUC MAC
- **实现**: 添加 MAC 算法 zuc-128-eia3
- **性能**: speed 命令支持 zuc-128-eia3
- **动态密码**: 添加支持动态密码的一些 API

### 十一、SM3 DRBG

#### 11.1 SM3 DRBG 实现
- **实现**: 支持 GM/T 0105-2021 定义的 SM3 DRBG
- **功能**: 实现符合国密标准的随机数生成器

### 十二、TLCP 协议

#### 12.1 TLCP 支持
- **实现**: 支持 TLCP 和 GM/T 0024-2014
- **功能**: 实现国密传输层密码协议

### 十三、Delegated Credentials

#### 13.1 Delegated Credentials 支持
- **实现**: 支持 TLS Delegated Credentials
- **修复**: 修复 Delegated Credentials 的编译问题

### 十四、SSL_CTX 复制

#### 14.1 SSL_CTX_dup
- **实现**: 添加支持 SSL_CTX 复制的 API: SSL_CTX_dup
- **修复**: 修复 SSL_CTX_dup 浅拷贝导致的问题
- **修改**: 修改 SSL_set_skip_scsv 的参数为 SSL *

### 十五、其他功能增强

#### 15.1 SSL/TLS 功能
- **SCSV**: 添加支持跳过 SCSV 的 API: SSL_set_skip_scsv
- **异步会话**: 添加异步会话查找支持
- **状态回调**: 添加获取握手状态信息的状态回调
- **会话复用**: 添加获取会话复用类型的新函数
- **警报级别**: 添加获取警报协议消息级别的新函数
- **OCSP**: 支持在 clienthello 回调函数中设置 OCSP 响应消息

#### 15.2 内存管理
- **内存统计**: 添加获取内存使用统计的新函数

#### 15.3 兼容性
- **Lua FFI**: EVP API 兼容 lua ffi
- **批量计算**: 添加支持椭圆曲线点批量计算的 API（隐私计算场景）
- **strcasecmp**: 实现 strcasecmp 和 strncasecmp
- **OPENSSL_strncasecmp**: 使用 OPENSSL_strncasecmp

#### 15.4 配置
- **系统密码套件**: Configure 支持在 unix 系统中配置 system-ciphers-file
- **Engine 方法**: s_server 支持 engine 方法
- **版本命令**: apps 在 openssl version 命令中添加 engines

#### 15.5 性能
- **CHACHA**: CHACHA 算法选择策略优化
- **RSA**: 兼容 7 素数证书，改进多素数 RSA 性能
- **LoongArch**: 添加 LoongArch bn_mont_mul 汇编支持

#### 15.6 编码
- **wrap 模式**: openssl enc 添加 wrap 模式支持

### 十六、算法移除

#### 16.1 已移除算法
- **BLAKE2**: 移除 BLAKE2
- **Blowfish**: 移除 Blowfish
- **Whirlpool**: 移除 Whirlpool
- **RIPEMD**: 移除 RIPEMD
- **MDC2**: 移除 MDC2
- **MD4**: 移除 MD4
- **IDEA**: 移除 IDEA
- **GOST**: 移除 GOST 及相关算法
- **Camellia**: 移除 Camellia 分组密码
- **MD2**: 移除 MD2 算法
- **SEED**: 移除 SEED 密码
- **ARIA**: 移除 ARIA 密码
- **Argon2**: 移除 Argon2

#### 16.2 恢复的算法
- **RC2**: 恢复 RC2 算法支持

### 十七、架构移除

#### 17.1 已移除架构
- **VMS**: 移除 VMS 支持及相关代码和配置
- **PA-RISC**: 移除 PA-RISC 架构代码
- **SPARC**: 移除 SPARC 架构代码
- **ARM**: 移除 ARM 汇编代码中不支持的宏

### 十八、CI/CD 改进

#### 18.1 静态分析
- **新增**: CI 添加静态分析
- **修复**: 修复静态分析下载 coverity 工具失败
- **Coverity**: 修复多个 Coverity 问题（497452, 497428, 497414, 497443, 497438）
- **修复**: 修复 Coverity 未初始化变量使用问题
- **资源泄漏**: 修复资源泄漏问题

#### 18.2 编译器测试
- **新增**: 在 pull request 上运行 compiler-zoo
- **升级**: CI OS 版本从 latest 改为 22.04
- **升级**: compiler-zoo.yml 中升级 runner 到 ubuntu-22.04
- **升级**: CI upgrade upload-artifact to v4
- **扩展**: 修改 ci os-zoo，支持更多操作系统
- **移除**: 从 os-zoo CI 中移除 macos-13
- **更新**: 更新 m68k 交叉编译 CI
- **移除**: 更新 windows.yml，移除 windows 2019 支持

#### 18.3 覆盖率测试
- **扩展**: CI 启用更多覆盖率选项，添加 GCC 11/12, Clang 13/14
- **移除**: 移除同态加密覆盖测试，忽略 lcov 错误

#### 18.4 Fuzz 测试
- **修复**: Fuzz checker CI: 为 fuzzer includes 使用更通用的 include 目录

#### 18.5 其他 CI 改进
- **修复**: 修复 os-zoo CI 错误
- **修复**: 修复 test_ssl_new 偶发失败
- **修复**: 修复 daily CI 失败
- **修复**: 修复 daily checker 问题
- **修复**: 修复 ASLR 在 asan/tsan/ubsan 运行时过大
- **修复**: 修复 Run-checker merge CI: Memleak 测试在没有 ubsan 时不工作
- **改进**: 改进 CI
- **修复**: 修复一些 CI 问题

### 十九、性能优化

#### 19.1 算法优化
- **SM2**: SM2 64位平台优化
- **SM2**: SM2 快速模约简算法
- **ZUC**: ZUC 算法优化
- **CHACHA**: CHACHA 算法选择策略优化
- **RSA**: 兼容 7 素数证书，改进多素数 RSA 性能

#### 19.2 性能测试
- **新增**: 添加性能测试代码
- **新增**: 添加示例性能工具
- **speed**: apps/speed 添加 EC-ElGamal 算法性能测试
- **speed**: apps/speed 添加 SM3/4 算法性能测试
- **speed**: apps/speed 添加 Bulletproofs 算法性能测试
- **speed**: apps/speed 添加 Paillier 算法性能测试
- **speed**: apps/speed 添加 ZUC 和 Paillier 算法到自动化测试脚本
- **speed**: apps/speed 启用 ZUC 和 Paillier 算法到自动化测试脚本
- **修复**: 修复 Speed Test 编译问题
- **修复**: 修复 apps/speed.c 的一些 bug
- **修复**: speed-test.yml bugfix
- **修复**: speed-test 脚本 bug 修复

### 二十、Bug 修复

#### 20.1 资源泄漏
- **修复**: 修复 TSAPI_ImportSM2Key() 内存泄漏
- **修复**: 修复一些资源泄漏问题
- **修复**: 修复资源泄漏问题
- **修复**: 修复 Coverity 资源泄漏问题
- **修复**: 修复一些内存泄漏问题

#### 20.2 编译问题
- **修复**: 修复许多编译问题
- **修复**: 修复一些编译问题
- **修复**: 修复 check-ansi CI 问题
- **修复**: 修复 ec_elgamal 但禁用 twisted elgamal 时的编译失败
- **修复**: 修复 SMTC 的编译问题
- **修复**: 修复 NTLS 的编译问题
- **修复**: 修复 Delegated Credentials 的编译问题
- **修复**: 修复 gcc-4.8.5 编译 paillier bug
- **修复**: 修复函数签名变更导致的编译错误

#### 20.3 测试修复
- **修复**: 修复 test_ssl_new 失败
- **修复**: 修复 test_ca 失败
- **修复**: 修复 test_pkcs12 的测试编号问题
- **修复**: 修复 test_pkeyutl
- **修复**: 修复 ec_test
- **修复**: 修复 ext_internal_test 错误
- **修复**: 修复测试失败，移除 rc2 测试用例
- **修复**: 修复 test_sslapi_data traceref 中的 sm2sig_sm3，修复 test_ssl_new 中 smtc 配置错误
- **修复**: 修复 75-test_quicapi_date/ssltraceref 文件中的 sm2sig_sm3
- **修复**: 修复 test_trace_api 和 test_speed 中的问题
- **修复**: 修复 babasslapitest 中的一些问题
- **修复**: 修复 quic test ssltraceref 文件
- **修复**: 添加测试从多线程访问 X509_STORE
- **修复**: 修复 ec-elgamal 测试用例 bug
- **修复**: 添加 EC_POINT_from_string 测试用例
- **修复**: 添加 paillier_add_plain 测试用例
- **修复**: 修复阈值 SM2 的一些问题
- **修复**: 修复 zkp 的一些问题
- **修复**: 修复 elgamal 和 paillier 的一些问题
- **修复**: 修复 SM2 未启用时的 CI 问题
- **修复**: 修复 use_etm 的问题
- **修复**: 修复 tls1_set_groups
- **修复**: 移动 zkp-test 到 daily-test
- **修复**: 修复 CI 报告的 doc/man3/SSL_set_skip_scsv.pod 错误

#### 20.4 其他 Bug 修复
- **修复**: 修复 Timing Oracle in RSA 解密（已回退）
- **修复**: 修复 babasslapitest.c bug
- **修复**: 修复 Paillier bug
- **修复**: 修复 Paillier engine bug
- **修复**: 修复 zuc-128-eea3 default provider 内存泄漏
- **修复**: 修复错误代码删除
- **修复**: 修复 tongsuo symlink 的 bug
- **修复**: 修复 symbol-prefix bug
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题
- **修复**: 修复一些问题

### 二十一、文档更新

#### 21.1 文档迁移
- **移动**: 将文档移动到 tongsuo-doc 仓库
- **新增**: [docs] 添加英文版 README
- **更新**: 更新 CHANGES.md
- **更新**: 修复 README.md
- **新增**: 添加 SM 示例
- **更新**: 按照 Tongsuo 原始提交修改 examples/sm.c
- **移除**: 移除所有文档

#### 21.2 版权和许可
- **更新**: 更新版权声明
- **更新**: 更新版权检查关键字
- **修复**: 修复许可证链接
- **修复**: 修复许可证链接
- **修改**: 有效期改成 100 年

### 二十二、其他变更

#### 22.1 版本和规范
- **新增**: 添加 Tongsuo 版本
- **新增**: 添加 tongsuo.spec
- **版本**: 更多版本相关内容
- **准备**: 准备 8.5.0-pre1

#### 22.2 符号和链接
- **新增**: 支持新功能：添加导出符号前缀
- **新增**: 添加 tongsuo 软链接到 openssl
- **修复**: 修复 symbol-prefix bug
- **修复**: 使用相对路径作为 tongsuo symlink
- **更新**: 更新 libcrypto.num

#### 22.3 架构支持
- **新增**: 配置 CI 测试 LoongArch
- **新增**: 添加 LoongArch bn_mont_mul 汇编支持
- **新增**: 添加 LoongArch cap.c 中 OPENSSL_cpuid_setup 的头文件
- **保留**: 保留 /include/crypto/riscv_arch.def

#### 22.4 RPM 打包
- **新增**: rpm: 添加 RPM spec 以将 babassl 安装到标准目录以替换 openssl

#### 22.5 BIO 处理
- **修改**: 使用直接读取数据的方式，而不是 peek
  - 可以更好的适应不同的事件处理方式，包括 ET 和 LT
  - 同时不用再适配不同类型的 bio 处理 peek 数据问题
  - 直接使用 BIO_read() 统一处理

#### 22.6 ASYNC
- **修复**: ASYNC: 嵌套作业创建的修复

#### 22.7 配置脚本
- **修改**: 此处的 if 会导致 --prefix 进入编译选项，应当使用 elsif 进行判断
- **修改**: 如果设置 enable-ec_elgamal，自动设置 api 为 1.1.1 并禁用 deprecated

#### 22.8 模块
- **修改**: 启用 SMTC 时禁用模块
- **修改**: 为 liblegacy.a 定义 SMTC_MODULE 以避免多重定义

#### 22.9 清理
- **移除**: 移除更多不必要的文件
- **移除**: 移除更多 VMS 相关代码和配置
- **移除**: 移除临时文件
- **移除**: 移除一堆无用的东西
- **更新**: 更新 objects, 错误号, libcrypto.num 和 libssl.num
- **移除**: 移除 unix-Makefile.tmpl 中的 generate_buildinfo 目标

#### 22.10 头文件
- **修改**: 将 internal/sm3.h 改为 openssl/sm3.h
- **修改**: 在 loongarchcap.c 中添加 OPENSSL_cpuid_setup 的头文件

#### 22.11 其他
- **新增**: 添加辅助功能模块（log.h + OID）
- **新增**: 添加打印握手 RTT 功能给 s_server 和 s_client
- **新增**: 添加同态加密覆盖测试
- **修复**: 修复 EC 参数显式编码问题
- **修复**: 修复 EC_POINT_from_string 移动到 ec_lib.c 使其更通用
- **限制**: Bulletproofs 的范围限制为 2 的幂次
- **更新**: 更新 fuzz/corpora
- **修复**: 修复一些问题
- **解决**: 解决冲突
- **启用**: 启用 ZKP 的 CI 测试
- **更新**: 更新 libcrypto.num
- **移动**: 移动添加的参数到正确的文件
- **更新**: zkp build.info bug 修复
- **更新**: libcrypto.num

### 二十三、测试增强

#### 23.1 测试用例
- **新增**: 添加一些测试用例到 zkp_gadget_test
- **新增**: 添加 SM2 without Za 测试用例
- **新增**: 添加 EC_POINT_from_string 测试用例
- **新增**: 添加 paillier_add_plain 测试用例
- **新增**: 添加从多线程访问 X509_STORE 的测试

#### 23.2 性能测试
- **新增**: 添加性能测试代码
- **新增**: 添加示例性能工具
- **新增**: apps/speed 添加 EC-ElGamal 算法性能测试
- **新增**: apps/speed 添加 SM3/4 算法性能测试
- **新增**: apps/speed 添加 Bulletproofs 算法性能测试
- **新增**: apps/speed 添加 Paillier 算法性能测试
- **新增**: 启用 ZUC 和 Paillier 算法到自动化测试脚本
- **新增**: 添加 ZUC 和 Paillier 算法到自动化测试脚本
- **新增**: speed add sm2-threshold-sign, sm2-threshold-decrypt, sm2-crypt

#### 23.3 测试修复
- **修复**: 修复 test_ssl_new 失败
- **修复**: 修复 test_ca 失败
- **修复**: 修复 test_pkcs12 的测试编号问题
- **修复**: 修复 test_pkeyutl
- **修复**: 修复 ec_test
- **修复**: 修复 ext_internal_test 错误
- **修复**: 修复测试失败，移除 rc2 测试用例
- **修复**: 修复 test_sslapi_data traceref 中的 sm2sig_sm3
- **修复**: 修复 test_ssl_new 中 smtc 配置错误
- **修复**: 修复 75-test_quicapi_date/ssltraceref 文件中的 sm2sig_sm3
- **修复**: 修复 test_trace_api 和 test_speed 中的问题
- **修复**: 修复 babasslapitest 中的一些问题
- **修复**: 修复 quic test ssltraceref 文件
- **修复**: 修复 CI 报告的 doc/man3/SSL_set_skip_scsv.pod 错误

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
- 测试两个套件
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

### 可选配置
```bash
# 启用白盒 SM4
perl Configure VC-WIN64 --enable-ntls --enable-wbsm4-xiaolai --enable-wbsm4-baiwu --enable-wbsm4-wsise

# 启用 EC-ElGamal
perl Configure VC-WIN64 --enable-ec_elgamal
```

## 已知问题

1. **s_server/s_client NTLS 支持**: 当前构建可能默认未启用 NTLS。需要使用 `--enable-ntls` 重新配置。
2. **硬件密钥测试**: 需要 SDF 硬件模块和正确配置。
3. **白盒 SM4**: 需要单独启用配置选项。
4. **EC-ElGamal**: 启用时会自动设置 API 为 1.1.1 并禁用 deprecated。

## 未来工作

1. 在默认构建配置中启用 NTLS 支持
2. 添加更全面的测试用例
3. 文档化 SDF provider 配置详情
4. 添加软密钥 vs 硬密钥操作的性能基准测试
5. 完善 ZKP 算法的文档和示例

## 参考资料

- NTLS 协议规范
- SM2 密码标准
- SDF Provider 文档
- OpenSSL Provider 架构
- RFC 8998 (TLS 1.3 商密套件)
- GM/T 0105-2021 (SM3 DRBG)
- GM/T 0024-2014 (TLCP)
- GM/T 0006 (HMAC-SM3)
- GM/T 0015-2023 (SM2 NULL 参数)

---

**文档版本**: 2.0  
**最后更新**: 2026-05-08  
**迁移分支**: migration/dev-v2  
**基础版本**: OpenSSL 3.5.4  
**提交数量**: 286 个提交
