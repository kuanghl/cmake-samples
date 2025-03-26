from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as pkcs1_15_en
from base64 import b64encode,b64decode

def test_rsa_pkcs1_encrypt():
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

    # 利用公钥生成加密算子,利用私钥生成解密算子
    print("\ngenerate encryption\n")
    en = pkcs1_15_en.new(keyPair.public_key())
    de = pkcs1_15_en.new(keyPair)
    
    # 加密并编码为base64
    print("\nencrypt\n")
    msg_en = en.encrypt(msg)
    msg_en_b64 = b64encode(msg_en)
    print(msg_en_b64)
    
    # base64解码并解密
    print("\ndecrypt\n")
    msg_de = de.decrypt(b64decode(msg_en_b64), None)
    print(msg_de)

def rsa_pkcs1v15_sha256_encrypt():
    print("\nencrypt\n")
    
    msg = b'A message for signing'
    
    pub_key = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnGOkP4vhlzRJP0A/FwwEp48vm\n+2/+S7GXVwWKHU2qzUQqQBjLSkOZvDPdvsFRBfEn0e9fAYi21t3DAd4/pez+N1LA\n8kTIiF9yDS2Zu3dcZ1vu25eAB0Y1unebi5zFcn62CqNL4CmOeqj+PR9N8mPJgbe2\nRNf23KL0bGe2rizU/QIDAQAB\n-----END PUBLIC KEY-----"
    
    # 导入公钥
    pub = RSA.import_key(pub_key)
    
    en = pkcs1_15_en.new(pub)
    msg_en = en.encrypt(msg)
    
    #base64 编码
    msg_en_b64 = b64encode(msg_en)
    print(msg_en_b64)

def rsa_pkcs1v15_sha256_decrypt():
    print("\ndecrypt\n")
    
    en_b64 = "NqDV03/B6Ej8cCMJs8sloXT7kgJ/B7AXx5nRlBZ18T8jvO27M4XV2UccYr4521qAOcpBDbRpISCvCqXuc8IjGLxQYdlabhfpYWk/elnBKPDvELdFX2ueES9eIUNRiWEDEV+Gni3NtRHPFLGqjqAkXQZgqc/vupQE8rZ9z/9hfvk="
    
    priv_key = "-----BEGIN RSA PRIVATE KEY-----\nMIICXgIBAAKBgQDnGOkP4vhlzRJP0A/FwwEp48vm+2/+S7GXVwWKHU2qzUQqQBjL\nSkOZvDPdvsFRBfEn0e9fAYi21t3DAd4/pez+N1LA8kTIiF9yDS2Zu3dcZ1vu25eA\nB0Y1unebi5zFcn62CqNL4CmOeqj+PR9N8mPJgbe2RNf23KL0bGe2rizU/QIDAQAB\nAoGAL9uUyFl0n4BsfmLUIVxU7Vvjah4//yWlzXWUDBotb2W67BUCDXd/sGKtSwqp\n9iGI43oyXDZxHYw5uJy2be/quAXrAeEwsVHhXG4bfV2qPiDVZMAWIOf3mXiMqTUx\nmR/bf9fj1QU4Z5I70j/yytawZKt9qcxNFYu+gmYdlBoqFnECQQDr7pUH5qKsAvVK\nenZpuECGpViENOw4PuSW4Hlt1+NerO3Di30SmN8ETjK5EW5iIoybefig5sTwhrsC\ndFOs75GnAkEA+sENu2PCXq/3YD1fDbLQhW2sWDx06QySP8Sr7W2x/Rjv0yIgkgI4\nzlcWvkgRVQqf5Cj3xl5ClL0eFuGdQbUQuwJBAJtg+ANJEE8Kb7MKLdv4PX6vfDkt\nhXiRawg2c6I0sQhUCQ5kWg2aYh26xkr9wN2edU2bqXOGJ6Nkh9rY85aL/DcCQQCc\nITRRp03Q8zPOIqhauSoIyj7zOcF5kjBFsEl0rkaS1sIM7kTlZKjGIYextuHD17ey\nsqeERhCi2BYyHQxzazAdAkEAoUfZudEnQ3EgKYeTPIuwna6D6O+KovrSZVxpdQI7\n+7lql8EizQgnPLK0GLiJ9EVz4Qqf9NuOm4y1F9rHtXd/ew==\n-----END RSA PRIVATE KEY-----"
    
    #base64 解码
    en = b64decode(en_b64)
    
    # 导入公钥
    priv = RSA.import_key(priv_key)
    
    de = pkcs1_15_en.new(priv)
    msg = de.decrypt(en, None)
    print(msg)
    
    
def main():
    # test_rsa_pkcs1_encrypt()
    rsa_pkcs1v15_sha256_encrypt()
    rsa_pkcs1v15_sha256_decrypt()

if __name__ == "__main__":
    main()