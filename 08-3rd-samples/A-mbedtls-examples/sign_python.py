from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import HMAC, SHA256
from base64 import b64encode,b64decode

def test_rsa_pkcs1_sign():
    # 生成密钥对
    keyPair = RSA.generate(bits=1024)

    # 私钥
    print("\nprivate key\n")
    print(keyPair.export_key("PEM"))
    # 公钥
    print("\npublic key\n")
    print(keyPair.public_key().export_key("PEM"))

    # 消息
    msg = b'A message for signing'

    # 使用私钥生成加密算子
    print("\ngenerate encryption\n")
    c = pkcs1_15.new(keyPair)
    h = SHA256.new()

    # 计算hash，并打印为16进制字符串
    print("\ncompute hash\n")
    h.update(msg)
    print(h.digest().hex())

    # 对哈希值进行签名，并输出签名数据为16进制字符串
    print("\nsign hash\n")
    sign = c.sign(h)
    print(sign.hex())

    # 最终对签名数据进行base64编码
    print("\nbase64 encode\n")
    print(b64encode(sign))     
    
def rsa_pkcs1v15_sha256_verify():
    print("\nsign verify\n")
    
    msg = b'A message for signing'
    
    sign_b64 = "KYiZF/C18O3wgCZvDptfM8Vh/OPMrcAf6ne9eszSuxgGMK57cKCQuWc33JF8iQmKWrSo+ezzkPJIfXGTj3z3Js9vv1DC2tX3oBh9CdZF+yc5MqZAT5LEEqmwNKWiT4iNwwnbXiJtNSy8/T2PRRN0PBy/TZn3HKc1AMKMYMLUjf8="

    pub_key = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTt8tp4xNp29CMxy6QS0NzpR6t\n8bAcv7ei3NkVM/Nzg3K5wWZRaBTMovbzKCXdXYdC6GutVkG+CEetO3XHM4LhDqW0\nvwISTO65/XrvR3zqXD5ZjrJFmtCAvkCwtMAPjqXZ/RJnd8yrXuoz5cRqVgKmq5TZ\nlGIIiTPIklxGIGof8QIDAQAB\n-----END PUBLIC KEY-----"

    #base64 解码
    sign_data = b64decode(sign_b64)

    # 导入公钥
    pub = RSA.import_key(pub_key)

    c = pkcs1_15.new(pub)
    hashs = SHA256.new()
    hashs.update(msg)

    # 验签
    try:
        c.verify(hashs, sign_data)
        print("verify ok")
    except ValueError:
        print("verify faild")
    
def main():
    test_rsa_pkcs1_sign()
    rsa_pkcs1v15_sha256_verify()

if __name__ == "__main__":
    main()