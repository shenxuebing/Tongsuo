###生成 obj_mac.h 和 obj_dat.h
perl objects.pl objects.txt obj_mac.num obj_mac.h 
perl obj_dat.pl obj_mac.h obj_dat.h

生成最新的后，需要将obj_dat.h拷贝靠include/openssl目录中

###编译Tongsuo
perl Configure enable-ntls VC-WIN32  no-tests --debug   -march=native
perl Configure VC-WIN64A no-shared no-asm no-tests  enable-ec_sm2p_64_gcc_128 enable-ntls  -march=native


./config --prefix=/usr/local/angie/tongsuo -Wl,-rpath,/usr/local/angie/tongsuo/lib64 enable-ec_sm2p_64_gcc_128 enable-ntls  -march=native


20250612
1.测试发现增加SM2签名检查会降低签名性能，在Hygon C86 3250  8-core Processor 8核16线程测试结果如下
测试命令：./openssl speed -multi 20 sm2 

#优化前：
version: 3.0.3
built on: Thu Jun  5 09:34:16 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -O3 -march=native -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG 
CPUINFO: OPENSSL_ia32cap=0x7ed8320b078bffff:0x209c01a9
                              sign    verify    sign/s verify/s
 256 bits SM2 (CurveSM2)   0.0000s   0.0000s  68113.3  33451.5

#优化后：
built on: Thu Jun  5 09:34:16 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -O3 -march=native -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG 
CPUINFO: OPENSSL_ia32cap=0x7ed8320b078bffff:0x209c01a9
                              sign    verify    sign/s verify/s
 256 bits SM2 (CurveSM2)   0.0000s   0.0000s  68008.0  33752.5

 20250616
 1.speed 中测试的性能是一直复用变量，所以性能高，如果每次都重新申请内存，性能会降低很多
 2.增加sm2_sig_verify_fast验签接口，内部使用的变量是上层外送的线程变量，这样在压测时性能会很高





