from os import urandom
from hsslms import LMS_Priv
from hsslms.utils import LMOTS_ALGORITHM_TYPE, LMS_ALGORITHM_TYPE
from base64 import b64encode, b64decode

# generate a private key
sk = LMS_Priv(LMS_ALGORITHM_TYPE.LMS_SHA256_M32_H10, LMOTS_ALGORITHM_TYPE.LMOTS_SHA256_N32_W8)

# compute the related public key
vk = sk.gen_pub()
print("pk=", b64encode(vk.get_pubkey()))

# sign a message with the private key, in total 2^10 signatures are available
signature = sk.sign(b'abc')
print("sig=", b64encode(signature))

# verify the signature, if invalid an exception will be raised
vk.verify(b'abc', signature)