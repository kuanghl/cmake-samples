# Curve-P-256-and-ECDSA

Using python check [ref](https://mp.weixin.qq.com/s/JHFzB36-8Hc3RTaeP_jcnQ).

## 问题
在椭圆曲线P-256上实现标准文档NIST FIPS186-4中规定的ECDSA（Elliptic Curve Digital Signature Algorithm）电子签名技术。

## Curve P-256
椭圆曲线P-256定义如下：
𝑦^2 = 𝑥^3 − 3𝑥 + 𝑏 (mod 𝑝)  
其中，𝑝是长度为256位的小数，使用以下值：所有的数都用十六进制表示。

𝑝 = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF  

满足上述条件的椭圆曲线上的点构成有限体，在本课题中使用的组的基点（base point）和差数（order）如下：

𝑛 = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  
𝐺𝑥 = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
𝐺𝑦 = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  

小数𝑛是组的次数，𝐺是基点，因此满足𝑛𝐺=𝑂。这里𝑂是无限大点的恒等员。

## ECDSA
当签名者的私钥为𝑑，公钥为𝑄=𝑑𝐺时，针对消息𝑚的ECDSA电子签名算法如下：

- 签名（Signature Generation）
1. 𝑒 = 𝐻(𝑚). 𝐻()是SHA-2哈希函数。
2. 如果𝑒的长度大于𝑛的长度（256位），则剪掉后面的部分。 𝑏𝑖𝑡𝑙𝑒𝑛(𝑒) ≤ 𝑏𝑖𝑡𝑙𝑒𝑛(𝑛)  
3. 随机选择秘密值𝑘。 (0 < 𝑘 < 𝑛)  
4. (𝑥1, 𝑦1) = 𝑘𝐺.  
5. 𝑟 = 𝑥1 mod 𝑛. 如果𝑟=0，就再跳转到step 3.。
6. 𝑠 = 𝑘^−1(𝑒 + 𝑟𝑑) mod 𝑛. 如果𝑠=0，就再跳转到step 3.。
7. (𝑟, 𝑠)是签名值  

- 验证 (Signature Verification)  
1. 如果𝑟和𝑠不在[1，𝑛-1]之间，则签名无效。
2. 𝑒 = 𝐻(𝑚). 𝐻()与签名中使用的哈希函数相同。
3. 如果𝑒的长度大于𝑛的长度（256位），则剪掉后面的部分。𝑏𝑖𝑡𝑙𝑒𝑛(𝑒) ≤ 𝑏𝑖𝑡𝑙𝑒𝑛(𝑛)  
4. 𝑢1 = 𝑒 * 𝑠^−1 mod 𝑛, 𝑢2 = 𝑟 * 𝑠^−1 mod 𝑛.  
5. (𝑥1, 𝑦1) = 𝑢1𝐺 + 𝑢2𝑄. 如果（𝑥1，𝑦1）=𝑂，则签名无效。
6. 𝑟 ≡ 𝑥1 (mod 𝑛)是正确的签名。

## GMP安装
GNU GMP库有多种函数来计算大小大于264的数量。本课题使用长度为256位的大数进行计算。为了完成课题，需要了解这些函数。因为函数的数量很多，所以理解完需要很长时间。幸运的是，计算ECDSA所需的函数数量并没有那么多。参考菜单，熟悉下列函数的使用方法。

- 初始化/删除： mpz_init(), mpz_inits(), mpz_clear(), mpz_clears()  
- 设置值：mpz_set(), mpz_set_ui(), mpz_set_str(), mpz_get_str()  
- 算术运算1：mpz_add(), mpz_add_ui(), mpz_sub(), mpz_sub_ui(), mpz_mul(),  
- 算术运算2：mpz_mul_ui(), mpz_mod(), mpz_mod_ui(), mpz_powm(), mpz_powm_ui()  
- 比较运算：mpz_cmp(), mpz_cmp_ui()  
- 位运算1：mpz_and(), mpz_ior(), mpz_xor(), mpz_com()  
- 位运算2：mpz_setbit(), mpz_clrbit(), mpz_combit(), mpz_tstbit()  
- 整数论：mpz_probab_prime_p(), mpz_gcd(), mpz_lcm(), mpz_invert()  
- I/O：mpz_out_str(), mpz_inp_str()  
- 随机数：mpz_urandomb(), mpz_urandomm(), gmp_randinit_default()  
- 数据转换：mpz_import(), mpz_export()

## 实现函数
下面列出了在椭圆曲线P-256上实现ECDSA电子签名技术所需函数的原型。每个函数的要求如下：

- void ecdsa_p256_init(void) – 为系统参数𝑝、𝑛、𝐺分配空间并初始化值。

- void ecdsa_p256_clear(void) – 返还分配的参数空间。  

- void ecdsa_p256_key(void *d, ecdsa_p256_t *Q) – 随机生成用户的私钥和公钥。 

- int ecdsa_p256_sign(const void *m, size_t len, const void *d, void *r,  
void *s, int sha2_ndx) – 将长度为len字节的消息m作为私钥d存储在r、s中。sha2_ndx是要使用的SHA-2哈希函数索引值，从SHA224、SHA256、SHA384、SHA512、SHA512_224、SHA512_256中选择。r和s的长度必须为256位。成功的话0，否则，将传递错误代码。

- int ecdsa_p256_verify(const void *m, size_t len, const ecdsa_p256_t *Q,  
const void *r, const void *s, int sha2_ndx) – 用公钥Q验证长度为len字节的消息m的签名是否为（r，s）。如果成功，则为0，否则将传递错误代码。

## 错误代码
使用下面列出的代码识别ECDSA执行过程中发生的错误。 
• ECDSA_MSG_TOO_LONG – 输入消息太长，超出限制 
• ECDSA_SIG_INVALID – 验证过程中格式或值无效的签名
• ECDSA_SIG_MISMATCH – 验证最后一步中的值不匹配签名不匹配

## ECDSA测试示例
以下是在椭圆曲线P-256上使用SHA-384哈希函数生成的验证示例。使用以下向量检查程序是否正确运行。 

Curve P-256:  
y^2 = x^3 - 3x + b (mod p)  

Group prime:  
p = FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF 

Group order:  
n = FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  

Group base point:  
Gx = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296  
Gy = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5  

Private key:  
d = C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721  

Signature with SHA-384, message = "sample":  

k = 09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4  
x1 = 0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719  
y1 = BB78F0E6EC1BC1F3DC0900D3C4F2955D1E27865BEE7AC17E57D465E06F981D86  
e = 9A9083505BC92276AEC4BE312696EF7BF3BF603F4BBD381196A029F340585312  
r = 0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719  
s = 4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954  

## 骨架文件
与需要实现的框架文件ecdsa.skeleton.c一起提供头文件ecdsa.h、可验证程序的test.c、SHA-2开源sha2.c、sha2.h和Makefile。其中，除test.c、sha2.c、sha2.h外，其他文件可以根据用途自由修改。
