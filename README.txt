###���� obj_mac.h �� obj_dat.h
perl objects.pl objects.txt obj_mac.num obj_mac.h 
perl obj_dat.pl obj_mac.h obj_dat.h

�������µĺ���Ҫ��obj_dat.h������include/opensslĿ¼��

###����Tongsuo
perl Configure enable-ntls VC-WIN32  no-tests --debug   -march=native
perl Configure VC-WIN64A no-shared no-asm no-tests  enable-ec_sm2p_64_gcc_128 enable-ntls  -march=native


./config --prefix=/usr/local/angie/tongsuo -Wl,-rpath,/usr/local/angie/tongsuo/lib64 enable-ec_sm2p_64_gcc_128 enable-ntls  -march=native


20250612
1.���Է�������SM2ǩ�����ή��ǩ�����ܣ���Hygon C86 3250  8-core Processor 8��16�̲߳��Խ������
�������./openssl speed -multi 20 sm2 

#�Ż�ǰ��
version: 3.0.3
built on: Thu Jun  5 09:34:16 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -O3 -march=native -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG 
CPUINFO: OPENSSL_ia32cap=0x7ed8320b078bffff:0x209c01a9
                              sign    verify    sign/s verify/s
 256 bits SM2 (CurveSM2)   0.0000s   0.0000s  68113.3  33451.5

#�Ż���
built on: Thu Jun  5 09:34:16 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -O3 -march=native -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG 
CPUINFO: OPENSSL_ia32cap=0x7ed8320b078bffff:0x209c01a9
                              sign    verify    sign/s verify/s
 256 bits SM2 (CurveSM2)   0.0000s   0.0000s  68008.0  33752.5

 20250616
 1.speed �в��Ե�������һֱ���ñ������������ܸߣ����ÿ�ζ����������ڴ棬���ܻή�ͺܶ�
 2.����sm2_sig_verify_fast��ǩ�ӿڣ��ڲ�ʹ�õı������ϲ����͵��̱߳�����������ѹ��ʱ���ܻ�ܸ�





