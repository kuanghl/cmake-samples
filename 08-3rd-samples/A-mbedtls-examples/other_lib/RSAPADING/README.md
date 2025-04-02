# RSAES-OAEP-and-RSASSA-PSS

## 问题
实现标准文档IETF RFC 8017中规定的RSA公钥密码体制PKCS#1版本2.2。PKCS#1包含基于Optimal Asymmetric Encryption/Decryption Scheme based the Optimal Asymmetric Encryption Padding（RSAES-OAEP）和基于Probabilistic Signature Scheme的签名方案（RSASSA-PSS）。RSAES-OAEP是密码算法，RSASSA-PSS是概率电子签名算法。RSA的密钥长度为2048位。

## RSAES-OAEP
RSAES-OAEP技术将要加密的消息M（Message）转换为EM（Encoded Message），然后使用公钥（𝑒，𝑒）计算EM^𝑒 mod 𝑛。

![image](https://user-images.githubusercontent.com/70682926/205847708-f1acfad8-ff25-4a24-85e8-e78cf6d08788.png)

- 可以给要加密的消息贴上标签，Hash（L）是该标签的哈希值。
- Padding String是一个值为0x00的字节列。
- “01”和“00”是值分别为0x01和0x00的单字节。 
- 哈希函数使用长度至少为224位的SHA-2系列函数。
- 随机数Seed的长度等于散列函数的长度。
- Encoded Message的长度必须与RSA密钥的长度RSAKEYSIZE（2048位）匹配。

## RSASSA-PSS
RSASSA-PSS技术通过如下过程将要签名的消息M转换为EM，然后使用私钥（𝑑，𝑛）计算EM𝑑 mod 𝑛。

![image](https://user-images.githubusercontent.com/70682926/205847901-450ece1f-04da-41a4-9041-3aab9246d3ff.png)

- 哈希函数使用长度至少为224位的SHA-2系列函数。
- 随机salt的长度等于哈希函数的长度。 
- M’的前8个字节用0x00填充。
- PS按长度填充0x00。 
- TF为1字节，用0xBC填充。
- mHash = Hash(M), H = Hash(M’).  
- EM的长度必须与RSA密钥的长度RSAKEYSIZE（2048位）匹配。
- 如果EM的最左位（MSB）为1，则强制改为0。

## 安装GMP库
GNU GMP库是一个软件包，用于计算整数大小大于2^64的数量。本课题中默认提供的rsa_generate_key（）和rsa_cipher（）函数使用GMP库。要想利用这些函数，必须安装适合各自环境的GMP库。GMP支持Linux、macOS、Windows等大部分环境。先安装GMP，然后进行课题。

- 在Linux环境中，打开终端并执行以下两个命令：

```sh
sudo apt update  
sudo apt install libgmp-dev  
```

- 在MacOS环境中，必须先安装Homebrew（请参阅项目#3）。打开终端，执行以下命令： 

```sh
brew install gmp  
```

在此次课题中，需要安装GMP库，但没有立即使用它进行编码的部分。但在下一个课题中是必要的。要使用GMP函数，必须使用`#include<gmp.h>`，并在gcc链接时使用-lgmp选项。例如，`gcc -o sample sample.c -lgmp`就是其应用。

## 实现函数
使用下面列出的原型实现PKCS#1版本2.2所需的函数。每个函数的要求如下：

- void rsa_generate_key(void *e, void *d, void *n, int mode) – 生成长度为RSAKEYSIZE的e、d、n。如果mode为0，则选择e=65537作为标准模式，如果不是0，则随机选择。这个函数是默认提供的。

- static int rsa_cipher(void *m, const void *k, const void *n) – 计算𝑚 ← 𝑚^𝑘 mod 𝑛如果成功，则为0，否则将传递错误代码。这个只在内部使用的函数是默认提供的。

- void sha224(const unsigned char *m, unsigned int len, unsigned char *digest);  
  void sha256(const unsigned char *m, unsigned int len, unsigned char *digest);  
  void sha384(const unsigned char *m, unsigned int len, unsigned char *digest);  
  void sha512(const unsigned char *m, unsigned int len, unsigned char *digest);  
  void sha512_224(const unsigned char *m, unsigned int len, unsigned char *digest);  
  void sha512_256(const unsigned char *m, unsigned int len, unsigned char *digest);  
  – 将长度为len字节的消息m的SHA-2散列值存储在digest中。这个函数群是开源的。

- int rsaes_oaep_encrypt(const void *m, size_t len, const void *label,  
const void *e, const void *n, void *c, int sha2_ndx) – 将长度为len字节的消息m用公钥（e，n）加密后的结果存储在c中。label可以通过输入NULL作为标识数据的标签字符串来省略。sha2_ndx是要使用的SHA-2哈希函数索引值，从SHA224、SHA256、SHA384、SHA512、SHA512_224、SHA512_256中选择。c的大小应该与RSAKEYSIZE相同。如果成功，则为0，否则将传递错误代码。

- int rsaes_oaep_decrypt(void *m, size_t *len, const void *label,  
const void *d, const void *n, const void *c, int sha2_ndx) – 密文c使用私钥（d，n）恢复原始消息m和长度len。label和sha2_ndx必须与加密时使用的一致。如果成功，则为0，否则将传递错误代码。

- int rsassa_pss_sign(const void *m, size_t len, const void *d, const void *n,  
void *s) – 将长度为len字节的消息m用私钥（d，n）签名的结果保存在s中。s的大小应该等于RSAKEYSIZE。如果成功，则为0，否则将传递错误代码。

- int rsassa_pss_verify(const void *m, size_t len, const void *e,  
const void *n, const void *s) – 用公钥（e，n）验证长度为len字节的消息m的签名是否为s。如果成功，则为0，否则将传递错误代码。

## 错误代码
使用下面列出的代码识别PKCS#1执行过程中发生的错误。
- PKCS_MSG_OUT_OF_RANGE – RSA数据值大于或等于模块化𝑛[内部函数]
- PKCS_MSG_TOO_LONG – 输入消息太长，超过限制[通用]
- PKCS_LABEL_TOO_LONG – 标签长度过长超过限制[RSAES-OAEP]
- PKCS_INITIAL_NONZERO – Encoded Message的第一个字节不是0[RSAES-OAEP] 
- PKCS_HASH_MISMATCH – 哈希值不匹配[通用]  
- PKCS_INVALID_PS – Padding String后面的值不是0x01[RSAES-OAEP]  
- PKCS_HASH_TOO_LONG – 哈希值太长，无法接受[RSASSA-PSS] 
- PKCS_INVALID_LAST – EM的最后一个（LSB）字节不是0xBC[RSASSA-PSS]
- PKCS_INVALID_INIT – EM的第一个（MSB）位不是0[RSASSA-PSS]  
- PKCS_INVALID_PD2 – DB数据库的前半部分与0x0000.00|0x01不匹配[RSASSA-PSS]

## RSAES-OAEP测试示例
以下是RSA密钥长度为1024位，使用SHA-224生成的验证示例：使用以下向量验证程序是否正确运行后，将密钥的长度扩展到2048以实现。

RSA key pairs with size = 1024  

e = 0298c1838a337b4adb8ffce087ee748dd284e41fbcf655698bc803e63d86c9fa  
2aa0863c090a408ea7d612851946acc99f359f3b959e34fa2a6e37d89cc869e3  
2547b5d9a4f2e0d4a6a5be8de889aad703374aa0a454fe2bad307c2f3fab17c7  
ed961e3e30a852a59c3396fe66ab54135b555c787fe5ec35210157ac17d0a385  

d = 01e356b87636214fc4c3f30ad7aea29d305db8143882ceb9e8521e43513cab6c  
8d2065d9b38612962ed1c129a90952893a9a07c9afd232975283e9808adc7a4a  
a39e9f66747f614e84355b229c35ad9163f2003f3b211ac46986f52cb268e6bd  
e3a48f938b0220b0424c42df42a6335c94ad39341d4336f6232cb7d40e3aa2cd  

n = 8d22c4b32917767565ead7c088133ba6b876a945fcd2b0db6b74ca53885ea919  
ce4f7b41e40a43d743fa033617bd42be67a7b9ee955a64496b7cd2e648d51d6a  
7f8cb204178f6f1e9c6e65a14b4302c0099347d6ef5ad414b77c9389d4118796  
b690784663b37089fd596f3fcf8ac43309bd3801ec1b593a574771dddc5d2fc1  

With SHA-224, label = "", message = "sample"  

lHash = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f  

seed = 2010ff31602cf33341383ee7b263583623a0ce5671df22b25013c642  

MGF1 = 8679eccabe80cff717375e8f87235bbe2caca3114f75ce6745c978f33a06cafe  
f0081e6bcf3f28d06bc8232d12851ead1100423bd71995f06a24df0b238e9b50  
00dc623e672afbcb1f2a4a731c776270c4ec230a7ec460d7a0fdd8a6f1ac9eea  
5a75fa  

MGF2 = fe2aff6276137e2aea444234c22f657daba709814e7c9b3048d2ea6f  

EM = 00de3a0053163f8d19ab7c7cd3704c3d4b8807c7d73fa3b98218c12c2d5733ee  
4694bae43e50565c34afa16f7a390e130ecdfb684d807a9cdc3a06cafef0081e  
6bcf3f28d06bc8232d12851ead1100423bd71995f06a24df0b238e9b5000dc62  
3e672afbcb1f2a4a731c776270c4ec230a7ec460d7a0fdd8a6f0dfff872a199f  

c = 704ff5b744789a3e308294e8db60eac4c37910a3e6cb15b70f33fe72fdf3b58a  
63048640133575564d4d4ee834c7e0bd45559d515af48590b99c41ee54996b19  
e4b0f73a76a282b000da1cd49a4df7146b57156c26301692091b02d05f4c6e3a  
10dd2e508ef418760615dfe96e5474f4eae69fb960bdd22b43c6e5b796bd75b2

## RSASSA-PSS测试示例
以下是RSA密钥长度为1024位，使用SHA-224生成的验证示例：使用以下向量验证程序是否正确运行后，将密钥的长度扩展到2048以实现。

RSA key pairs with size = 1024  

e = 0000000000000000000000000000000000000000000000000000000000000000  
0000000000000000000000000000000000000000000000000000000000000000  
0000000000000000000000000000000000000000000000000000000000000000  
0000000000000000000000000000000000000000000000000000000000010001  

d = 06c3eeac459356f743956e0810a0d3f9142943bcce19d111de0e5297aed166b4  
369b3b3e15c9479bf48392b34f71923b3569777e4f05295137518f13e6f48fde  
bd6ebf84a5d8ced584848b8a764ae480506f7d4a5ef7fb7cd5fdf8bf89e5aa45  
e39b99af2beda7fdf43261634ddae38f5beffd0bebf9bd51bfe401d5f6d68671  

n = c7b8ab9cdb83fbb008d80e78b2265aa088cdb5f9c11c0a92948c4c56e138730a  
4c815dc9b096fe4c1f4fb5259c0209c6c330ff8349bd9e0687ee49824f63f551  
414795733bdee587b4d3efecda10b2baaf0666458b5d21fd2b975a1babe9305d  
3ac28bed9037a4dab14ce9c414a96ebb412e8d26d6e69610191b3bed82e42dc1  

With SHA-224, message = "sample"  

mHash = 9003e374bc726550c2c289447fd0533160f875709386dfa377bfd41c  

salt = 6e41978602acca182e8bf511b9acdb04ab324572358c153de6cd3e0a  

M’ = 00000000000000009003e374bc726550c2c289447fd0533160f875709386dfa3  
77bfd41c6e41978602acca182e8bf511b9acdb04ab324572358c153de6cd3e0a  

H = de074849895435205639e196634c62305d6433373f688dd840b07f6b  

DB = 0000000000000000000000000000000000000000000000000000000000000000  
0000000000000000000000000000000000000000000000000000000000000000  
000000000000016e41978602acca182e8bf511b9acdb04ab324572358c153de6  
cd3e0a  

MGF = c93c72a5e3780e32843ab05bfeef5bc18a78688c859081c546bd86ed2895ce14  
028c98ae4df01c28a6d00b29d7bd9d919b2e28fe95ab09bb9db7c688813627ad  
26d0ee008824235a1ab836231651d93b4e3261c925b5a61e2957c54ae44d00d8  
b84f1f  

EM = 493c72a5e3780e32843ab05bfeef5bc18a78688c859081c546bd86ed2895ce14  
028c98ae4df01c28a6d00b29d7bd9d919b2e28fe95ab09bb9db7c688813627ad  
26d0ee00882422345b2fb021ba9bc115c5c77070896ea2b51b12b77f68583d3e  
757115de074849895435205639e196634c62305d6433373f688dd840b07f6bbc  

sig = 80dbbc4987617db7bf5f07f85078bdea501588eca3525dd69023926340e57125  
ec4443d54632acd4c97895394bcf7242fc38a57ce40243783e9a97b3d1eac45f  
8256aa520e44d77120a0585db14c3f4d5195058014e6d924092e57de6237c405  
88b08a6cdc1b73b5fbed022ea12470993dfd3c01480f841863eb23d0383f1b8f

## 骨架文件
与需要实现的框架文件pkcs.skeleton.c一起提供头文件pkcs.h、可验证程序的test.c、SHA-2开源sha2.c、sha2.h和Makefile。其中，除test.c、sha2.c、sha2.h外，其他文件可以根据用途自由修改。
