from pqcrypto.sign.ml_dsa_44 import generate_keypair, sign, verify
from base64 import b64encode, b64decode

def test_ml_dsa_44_sign_verify():
    # Alice generates a (public, secret) key pair
    public_key, secret_key = generate_keypair()
    print("\nml_dsa_44 key generate ok\n")
    print("\npublic key, size %d\n" % len(public_key))
    # print(public_key.hex())
    # print("\npublic key base64\n")
    # print(b64encode(public_key))
    print("\nprivate key, size %d\n" % len(secret_key))
    # print(secret_key.hex())
    # print("\nprivate key base64\n")
    # print(b64encode(secret_key))

    # Alice signs her message using her secret key
    signature = sign(secret_key, b"hello world!")
    print("\nml_dsa_44 sign ok size %d\n" % len(signature))
    print(b64encode(signature))
    
    # Bob uses Alice's public key to validate her signature
    assert verify(public_key, b"hello world!", signature)
    print("\nml_dsa_44 verify ok\n")
    
def ml_dsa_44_sign_verify():
    secret_key = b'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'

    public_key = b'MIIFMjALBglghkgBZQMEAxEDggUhAEPgA1FYXgXc3U3YokGuAwjMkGZGw6WIDfQU\
4pjbEut8k+EDSwSX2ZD9fOQVrD0Y297iBuqPpplRu2kfekWLH6XzXLFiHEwzAwOZ\
JmW7FuyLouIFn0OJKIaesg1VmfFvSU1cDJ1FP7uE7r98jIbw+oda74vPkQKItVIT\
gIZZojuNjC1Lkt+pK9MKzUpjc4RBaRQYsIbwc4BFbzSMIfyu3KvONUmwI41mwaJ4\
zmqG1BB/OheRpavKEGG4z9FTSm7foqNvecAHCqelyGRbTJxVmP71wyK2JDOICGmg\
2jVS/vG0ULdjurNo/pmv9Dn4CAFyCT2/zNcl9z1RE9JtcPn4nO4RtsGiutf19yS2\
ncOcOHgOaJWp/Gc4fEv5237X7cvVPdeT8zI1tEwkMTI8bZw+mrTT/uGt5TWVpcVc\
e9dSsuUdqtezMExjV4b80aXBNqMvD2eY/2wVKP8GV2N8KUJq1F1YtTI3+edRLk06\
dIMYCnX4rCAfhdLIN/KYWlOxVq+PWlV7ndVvJzBbcXnP9wrVxbL0eopmQqoVwv/c\
OLJtiyZC0QVnUxs/hYjy8Z1JdjSL4ZlHnlTO4GuHnOr3NzufVnwl5LYOvvIyBCMl\
FJa6RYpPXWlOe3Wy1JlAlTT6a27kQstgFJ3IcGH4uJ/cWJ8OxxVI8a2Icg5ddXw0\
Pg1+FYM8X169BkioSH8v6waa9K+pYtG9Mg2vYwWRyhFI1oKoFH2NFY9nkDZg8+s0\
V+l1fqNrneF3XLEem5wBJYEkGGqGMXtiOXAijRA4JL1uJrtxt9I2EEWhumaMD1ki\
Rr/yW1xkSn4xZUrdj8mR7R3a7Zc5GSiKAq+ZjSJJ3bzzVKs8cI/rqx579tjUW3Sz\
4Xik1hXWfaqRbsYlyUfPUGB0pRLGncqhalQZ8SdvTHmjMS9V5H1aQu/blTEwINV+\
0s41yZ+S/UTbT2jfTWG+OTJ0MOO524lZOPsd7ANqcefULfDhnQWSr3K/wVvfOFCm\
n5iOrP94WLKu5l3IDAh8gwDXYqCx16ZF/VXzSUAxAi68Mik20dbjrh4k9nrZklkA\
e7NMpJIAjcQfG6h4tFiBUxXQ+j6wxEPnfnm9d1aKohU3qhrccHz55zQFMJcSHbbE\
/KuCo7SZe/zfxsyZPHfpKwbm4X7URB00Zu42FhR/eHuMeQmmg0OhXWpCJSCjtx13\
+aQUD67o+BGViCYtsXzc/U2vmJkgssBIFxfcADOQiHTDIF0zHYXqajfJk28CWltt\
+EY0hY9yBrbDTt+WJx1wz+EO14lHvdYcSekqPE1Z0pFc7tL5a3sb0eDUILqjuO+e\
2BhTyL2Or5pTox2/5FWl/pctwz+i4/AwFyGufLBRDOBvvSgjaNImYq44xSf4pD/s\
Lq0zZ3HpeH/XC3tFSAniWO18WFuSNobJ9JW1MHJdi4ibCVlgMk4GnQJfrbnhxw3+\
U38e71AFQdyuxkajmxBY3hktyPu1dwsmMUiFtlJ3uZbXX69p4mnHJnsyX24jsc5T\
/GOvtcLmmXAOTkMUboKbSyL2/pLK2AaP1ClYGGru/ULVFQsrJv0u0Piveoqsr9++\
QIi2eyayGuArLq05+2s86B7Z3iLzyqqYGeJnyhN7eW8C6wFZAFhP0YanVBW9SbWQ\
vBlD7oVnzzc7ZjnSr+mp4Qj3ZLuHcMNbPK6XJZAI4w+VWvSYD6eHYHXhcZYu+J4E\
O7Lb8CcNng6IBvOHD37T4wK7QYJPOUPYqq8k5nsHZJ0Cy+Cs8NI='

    # https://github.com/open-quantum-safe/liboqs/blob/main/docs/algorithms/sig/ml_dsa.md
    # dumpasn1 -a ./pubkey.der 
    # get keysize is different from openssl generate key
    bintmp = b64decode(secret_key)
    secret_key_bin = bintmp[66:]
    bintmp = b64decode(public_key)
    public_key_bin = bintmp[22:]
    print("openssl private key size %d" % len(b64decode(secret_key)))
    print("openssl public key size %d" % len(b64decode(public_key)))
    print("ml_dsa_44 private key size %d" % len(secret_key_bin))
    print("ml_dsa_44 public key size %d" % len(public_key_bin))
    
    signature = sign(secret_key_bin, b"hello world!\n")
    print("\nml_dsa_44 sign ok size %d\n" % len(signature))
    print(b64encode(signature))
    
    assert verify(public_key_bin, b"hello world!\n", signature)
    print("\nml_dsa_44 verify ok\n")

def main():
    test_ml_dsa_44_sign_verify()
    ml_dsa_44_sign_verify()

if __name__ == "__main__":
    main()