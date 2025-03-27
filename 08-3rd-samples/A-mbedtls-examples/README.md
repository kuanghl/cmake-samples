### overview.

1. 在加解密缓解，公钥用于加密，私钥用于解密；
2. 在签名验签环节，私钥用于签名，公钥用于验签；

    |Algorithm|Sender uses..|Receiver uses…|
    |:--:|:--:|:--:|
    |Encryption|Public key|Private key|
    |Signature|Private key|Public key|

3. mbedtls RSA中的N/E/D/P/Q/DP/DQ/QP参数,公钥由E/N组成,私钥由N/E/D/P/Q/DP/DQ/QP组成;
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

#### reference.

- [mbedtls sign for 2.15.6](https://blog.csdn.net/anjiyufei/article/details/135355292)
- [mbedtls sign for 3.5.2](https://blog.csdn.net/mickey2007/article/details/143663298)
- [RSA/DSA/ECDSA sign and verify](https://www.codeleading.com/article/41492545289/)
- [mbedtls samples](https://github.com/iotwuxi/iot_security.git)
- [mbedtls x509](https://blog.51cto.com/u_13640625/4905282)
- [mbedtls stm32](https://blog.csdn.net/duapple/article/details/127928082)
- [mbedtls tiny guide](https://github.com/Mbed-TLS/mbedtls/tree/development/configs)
- [mbedtls PKCS#**](https://www.cnblogs.com/SevensNight/p/18766180)