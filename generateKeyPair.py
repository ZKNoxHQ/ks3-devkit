# Part of ks3-devkit
# MIT license
# Nicolas Bacca, 2024

import binascii
import secp256k1
privateKey = secp256k1.PrivateKey()
publicKey = privateKey.pubkey
print("Private key " + privateKey.serialize())
print("Public key " + binascii.hexlify(publicKey.serialize(compressed=False)).decode('utf-8'))


