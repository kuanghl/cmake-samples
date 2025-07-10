### overview.

1. 在加解密缓解，公钥用于加密，私钥用于解密；
2. 在签名验签环节，私钥用于签名，公钥用于验签；

    |Algorithm|Sender uses..|Receiver uses…|
    |:--:|:--:|:--:|
    |Encryption|Public key|Private key|
    |Signature|Private key|Public key|

3. mbedtls RSA中的N/E/D/P/Q/DP/DQ/QP参数,公钥由E/N组成,私钥由N/D为核心,E/P/Q/DP/DQ/QP用于加速解密操作或增强算法的安全性;
    - N（Modulus）：模数，是两个大素数P和Q的乘积。N的长度决定了RSA算法的安全性。
    - E（Public Exponent）：公钥指数，通常为65537（0x10001）。E用于加密数据，是公钥的一部分。
    - D（Private Exponent）：私钥指数，用于解密数据或生成数字签名。
    - P（Prime Factor）：素数P，是模数N的一个因子, 用于生成秘钥对。
    - Q（Prime Factor）：素数Q，是模数N的另一个因子, 用于生成秘钥对。
    - DP（D mod (P-1)）：D对(P-1)取模的结果，用于解密数据。
    - DQ（D mod (Q-1)）：D对(Q-1)取模的结果，用于解密数据。
    - Qinv（Q^-1 mod P）：Q的模P的乘法逆元，用于解密数据。

4. 不同哈希函数的摘要值长度不一样;

    |哈希函数|摘要值长度(Len)|
    |:--:|:--:|
    |SHA-1 | 20字节 |
    |SHA-256 | 32字节 |
    |SHA-384 | 48字节 |
    |SHA-512 | 64字节 |

5. 填充方式分为PKCS#V1.5和PKCS#V2.1;
    - 理论上1024bits的密钥可以加密的数据最大长度为1024bits（即1024/8 = 128bytes）。
    - RSA实行分组管理秘钥,若秘钥参数组长度没达到要求,则安装一定的加密标准填充。
    - 填充后的RSA秘钥对用来加密或者签名数据,将更难被攻击解密。
    - 不同长度的秘钥只能加密不同长度的数据块
        - 使用PKCS#1 v1.5填充时需要占用11个bytes,则最大加密数据块长度为128-11。
        - 使用PKCS#1 v2.1填充时采用SHA-256哈希函数占用2*32-2个bytes,则最大加密数据块长度为128-62。

        |填充方式|输入|输出|标准|
        |:--:|:--:|:--:|:--:|
        |RSA_PKCS1_PADDING | <=RSA_size(rsa)–11 | 和秘钥一样长 | PKCS#1 v1.5  |
        |RSA_PKCS1_OAEP_PADDING | <=RSA_size(rsa)–2*Len-2 | 和秘钥一样长 | PKCS#1 v2.0以上 |
        |RSA_NO_PADDING | <=RSA_size(rsa)  | 和秘钥一样长 | 弃用 |

6. SSL(Secure Socket Layer),安全套接字层,包含SSL1.0~3.0;
7. TLS(Transport Layer Security),安全传输层协议,包含TLS1.0~1.3;
8. Base64编码将文本不可见的二进制数据转成文本可见的ASCII字符串;
    
#### samples to used.

```sh
# 生成秘钥对
openssl genrsa -out rsa_private_pkcs1_2048.pem 2048
openssl rsa -in rsa_private_pkcs1_2048.pem  -out rsa_public_pkcs1_2048.pem -pubout -RSAPublicKey_out
# .pfx证书提取私钥
openssl pkcs12 -in your_certificate.pfx -nocerts -nodes -out private_key.pem
# .pfx证书提取公钥
openssl pkcs12 -in your_certificate.pfx -nokeys -out public_key.pem
openssl x509 -in XX.cer -pubkey  -noout > XX.pem
# .pfx证书提取秘钥对
openssl pkcs12 -in acp_test_sign.pfx -nocerts -nodes -out acp_test_sign.key
# 解析秘钥对中的N/E/D/P/Q/DP/DQ/QP参数
openssl asn1parse -in private_key.pem
openssl asn1parse -in public_key.pem

# python环境准备
sudo apt remove dblatex
pip install pycryptodome

# RSA python签名验证
python3 sign_python.py

# RSA python加密解密
python3 encrypt_python.py

# 构建
mkdir build
cd build
cmake ..
make -j8

# RSA c签名验证
./sign_c

# RSA c加密解密
./encrypt_c

# 其他示例都是官方programs示例改编测试
```

#### oqs and openssl.

1. liboqs安装

```sh
# 1. liboqs安装
# https://github.com/open-quantum-safe/liboqs/blob/main/CONFIGURE.md
# https://openquantumsafe.org/liboqs/getting-started.html
sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DOQS_ENABLE_SIG_ML_DSA=ON -DOQS_ENABLE_SIG_STFL_LMS=ON -DOQS_HAZARDOUS_EXPERIMENTAL_ENABLE_SIG_STFL_KEY_SIG_GEN=ON ..  # 启用ML-DSA和LMS算法
make -j$(nproc)
sudo make install
# /usr/local/lib/pkgconfig/liboqs.pc
# Installing: /usr/local/lib/liboqs.a
```
2. oqs-provider安装

```sh
# 2. oqs-provider安装
# oqs配合openssl官方文档: https://github.com/open-quantum-safe/oqs-provider/blob/main/USAGE.md#activation
# oqs配合openssl使用博客: https://blog.csdn.net/Jasmine_xyy/article/details/146690012
# oqs配合openssl使用示例: https://blog.csdn.net/2301_80469065/article/details/147743557
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
git checkout 0.9.0
cmake -S . -B _build && cmake --build _build && ctest --test-dir _build && sudo cmake --install _build
# /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so
# /usr/local/include/oqs-provider/oqs_prov.h
```

3. openssl3.5.0版本安装

```sh
# 3. openssl3.5.0版本安装
curl -L "https://github.com/openssl/openssl/releases/download/openssl-3.5.0/openssl-3.5.0.tar.gz" -o "openssl-3.5.0.tar.gz"
tar -zxf "openssl-3.5.0.tar.gz"
cd openssl-3.5.0 
./config --prefix=/usr/local/openssl
make
make test
sudo make -j4 install
ln -sf /usr/local/openssl/include/openssl /usr/include/openssl
ln -sf /usr/local/openssl/bin/openssl /usr/bin/openssl
ln -sf /usr/local/openssl/lib64/libssl.so.3 /usr/lib/x86_64-linux-gnu//libssl.so.3
ln -sf /usr/local/openssl/lib64/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
openssl version -a
openssl version -d
# /usr/local/openssl/lib64/libcrypto.so.3
```

4. 升级openssh来匹配新版本openssl

```sh
# https://www.wanghaoyu.com.cn/archives/openssh-20250225.html
sudo apt-get install libpam0g-dev
wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p2.tar.gz
tar -zxvf openssh-9.9p2.tar.gz
cd openssh-9.9p2
mkdir build
./configure --prefix=/usr/local/openssh/ --sysconfdir=/etc/ssh/ --with-ssl-dir=/usr/local/openssl/ --without-openssl-header-check  --with-pam --with-md5-passwords
make -j 4 && sudo make install
ln -sf /usr/local/openssh/sbin/sshd /sbin/sshd
ln -sf /usr/local/openssh/bin/ssh /usr/bin/ssh
ln -sf /usr/local/openssh/bin/scp /usr/bin/scp
ln -sf /usr/local/openssh/bin/sftp /usr/bin/sftp
ln -sf /usr/local/openssh/bin/ssh-add /usr/bin/ssh-add
ln -sf /usr/local/openssh/bin/ssh-keygen /usr/bin/ssh-keygen
ln -sf /usr/local/openssh/bin/ssh-keyscan /usr/bin/ssh-keyscan
sshd -V
sshd -t
systemctl restart sshd
systemctl status sshd

# 修复.ssh配置
sudo chmod  600 /home/kuanghl/.ssh/id_rsa
sudo chown kuanghl:kuanghl /home/kuanghl/.ssh/id_rsa
```

5. 配置openssl.cnf来适配openssl3.5.0 + oqs-provider算法

```sh
# 4. 配置openssl.cnf来适配openssl3.5.0 + oqs-provider算法
openssl version
openssl version -d
# OPENSSLDIR: "/usr/local/ssl"
sudo vim /usr/local/ssl/openssl.cnf 
```

- `openssl.cnf`中变更添加以下配置

```ini
[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
```

- 检查openssl3.5.0 + oqs-provider环境配置

```sh
ln -sf /usr/lib/x86_64-linux-gnu/ossl-modules/oqsprovider.so /usr/local/openssl/lib64/ossl-modules/oqsprovider.so
pkg-config --variable pc_path pkg-config
export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:/usr/lib/x86_64-linux-gnu/pkgconfig/
openssl list -providers 
openssl list -providers -verbose
openssl list -signature-algorithms -provider oqsprovider 
openssl list -kem-algorithms -provider oqsprovider

# 混合量子算法
# p256_mldsa44 @ oqsprovider代表: 传统算法ECDSA (P-256) + 抗量子算法CRYSTALS-Dilithium -- mldsas首选方案
# rsa3072_falcon512 @ oqsprovider代表: 传统算法RSA-3072 + 抗量子算法Falcon-512 -- 资源受限场景
# p384_sphincssha2192fsimple @ oqsprovider代表: 传统算法ECDSA (P-384) + 抗量子算法SPHINCS+-SHA2 -- 哈希备份方案
# 独立ML_DSA算法
# https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig/ml_dsa.md
# https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig/dilithium.md
# { 2.16.840.1.101.3.4.3.17, id-ml-dsa-44, ML-DSA-44, MLDSA44 } @ default -- Dilithium 2 -- signature 2420 bytes
# { 2.16.840.1.101.3.4.3.18, id-ml-dsa-65, ML-DSA-65, MLDSA65 } @ default -- Dilithium 3 -- signature 3293 bytes
# { 2.16.840.1.101.3.4.3.19, id-ml-dsa-87, ML-DSA-87, MLDSA87 } @ default -- Dilithium 5 -- signature 4595 bytes
# 独立LMS算法
# https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig_stfl/lms.md
# https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig_stfl/xmss.md
# https://quarkslab.github.io/crypto-condor/devel/method/MLDSA.html
```

6. openssl算法测试验证

```sh
# 美国国家标准与技术研究院(NIST)发布3种后量子密码学(PQC)标准
# ML-KEM - CRYSTALS-Kyber算法作为密钥封装机制(KEM)的标准，(Module-Lattice-Based Key-Encapsulation Mechanism Standard-模块化格基密钥封装机制标准)， 基于“模块格”的数学结构
# ML_DSA - CRYSTALS-Dilithium算法作为数字签名算法的标准，(Module-Lattice-Based Digital Signature Standard-模块化格基的数字签名标准)，基于晶格的数学难题
# SLH-DSA - SPHINCS+ 算法作为数字签名算法的标准， (Stateless Hash-Based Digital Signature Standard-基于哈希的无状态数字签名标准)， 基于哈希函数
# 秘钥格式: ASN.1(算法的参数结构) ------（序列化）------ DER ------（Base64编码）------ PEM
sudo apt-get -y install dumpasn1
mkdir mldsa_test && cd mldsa_test

# ML_KEM秘钥对生成
openssl genpkey -algorithm mlkem1024 -outform DER -out ./prkey.der -outpubkey ./pubkey.der -verbose
dumpasn1 ./pubkey.der
dumpasn1 -a ./pubkey.der

# ML_DSA秘钥对生成
openssl genpkey -h
openssl genpkey -algorithm mldsa44 -outform DER -out ./prkey.der -outpubkey ./pubkey.der -verbose
openssl genpkey -algorithm mldsa44 -outform PEM -out ./prkey.pem -outpubkey ./pubkey.pem -verbose
dumpasn1 -a ./pubkey.der

# DER <--> PEM转换(可选)
openssl pkey -outform DER -in ./prkey.pem -out ./prkey.der
openssl pkey -inform DER -outform DER -in ./prkey.der -pubout > ./pubkey.der
openssl pkey -inform DER -in ./prkey.der -out ./prkey.pem
openssl pkey -in ./prkey.pem -pubout > ./prkey.pem

# 解析秘钥对中的ASN.1参数和提取秘钥
openssl asn1parse -h
openssl pkey -h
openssl asn1parse -inform DER -in ./pubkey.der
openssl asn1parse -in ./pubkey.pem
openssl pkey -in pubkey.pem -pubin -text -noout

# 签名和验证/先计算hash再签名和验签
echo "hello world!" > data.txt
openssl dgst -h 
openssl dgst -sign ./prkey.pem -out data.sig data.txt
openssl dgst -signature data.sig -verify ./pubkey.pem data.txt

# base64编码和解码
openssl base64 -in data.sig -out data.sig.b64
cat data.sig.b64 | base64 -d > data.sig

# LMS算法(属于SLH-DSA类)验证
# 如PQClean或RFC 8554参考实现验证: https://github.com/PQClean/PQClean.git
# 似乎暂时没有实现: https://github.com/open-quantum-safe/oqs-provider/discussions/471
```

7. python算法测试和验证

```sh
# python oqs: https://github.com/mjosaarinen/py-acvp-pqc.git

# ML_DSA
cd mldsa_test
pip install pqcrypto
python3 mldsa44_sign.py

# LMS
pip install hsslms
```

8. c语言接口独立和验证

```sh
# 参考
# https://github.com/PQClean/PQClean.git: 官方PQClean
# https://github.com/pq-crystals/dilithium.git: 基于官方FIPS-204
# https://github.com/Acccrypto/RISC-V-SoC: 一些PQC测试基于RISC-V
# https://github.com/Ji-Peng/PQRV.git: 基于RISC指令的PQC加速
# https://ji-peng.github.io/: PQRV主页论文

# ML_DSA
cd mldsa_test/clib/libdilithium

# 参考仓库
https://github.com/kuanghl/libdilithium.git
https://github.com/kuanghl/libhash.git
```

#### reference.

- [mbedtls sign for 2.15.6](https://blog.csdn.net/anjiyufei/article/details/135355292): mbedTLS 2.16 RSA签名和验签移植。
- [RSA/DSA/ECDSA sign and verify](https://www.codeleading.com/article/41492545289/): 数字签名RSA、DSA、ECDSA。
- [mbedtls rsa](https://hive.blog/python/@yjcps/mbedtls-rsa): 使用mbedtls生成RSA签名和验签, 对比openssl。
- [mbedtls samples](https://github.com/iotwuxi/iot_security.git): 密码技术与物联网安全——mbedtls开发实战代码示例。
- [mbedtls x509](https://blog.51cto.com/u_13640625/4905282): 数字证书及X.509证书标准。
- [mbedtls stm32](https://blog.csdn.net/duapple/article/details/127928082): STM32 Bootloader开发记录3固件签名校验。
- [mbedtls test](https://gitee.com/wangjunhao98/mbedtls_test): 基于mbedtls的rsa验签签名和加密解密，精简库。
- [mbedtls tiny guide](https://github.com/Mbed-TLS/mbedtls/tree/development/configs): mbebtls精简官方指导。
- [mbedtls PKCS#**](https://www.cnblogs.com/SevensNight/p/18766180): 加密算法之PKCS填充。
- [mbedtls N/E/D/P/Q/DP/DQ/QP](https://www.cnblogs.com/sunchukun/p/13690308.html): e n d p q dQ dp invQ八个参数求解参考。
- [ED25519 and RSA](https://blog.csdn.net/orange160/article/details/142856412): ED25519和RSA对比。
- [crypto-condor multi-algo](https://quarkslab.github.io/crypto-condor/devel/index.html): crypto-condor python库及多种算法引用的标准文档。
- [Windows lib](https://blog.csdn.net/pureman_mega/article/details/119857480): windows内核官方使用的加密库。
- [liboqs](https://github.com/open-quantum-safe/liboqs.git): 用于原型制作和量子密码实验的C库。