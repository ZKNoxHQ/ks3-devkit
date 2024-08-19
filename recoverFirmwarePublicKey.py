# Part of ks3-devkit
# MIT license
# Nicolas Bacca, 2024

import struct
import sys
import json
import secp256k1
import binascii
import hashlib

if len(sys.argv) < 2:
	print("Usage : " + sys.argv[0] + " path_to_keystone3.bin")
	sys.exit(1)

f = open(sys.argv[1], "rb")
data = f.read(4)
headerLen = struct.unpack("<I", data)[0]
headerData = f.read(headerLen)
header = json.loads(headerData.decode('utf-8'))
f.read(1)
data = f.read()
f.close()

for recoveryId in range(4):
	try:
		pubKey = secp256k1.PublicKey()
		recoverableSignature = pubKey.ecdsa_recoverable_deserialize(binascii.unhexlify(header['signature']), recoveryId)
		pubKey = secp256k1.PublicKey(pubKey.ecdsa_recover(data, recoverableSignature))
		print(str(recoveryId) + " : " + binascii.hexlify(pubKey.serialize(compressed=False)).decode('utf-8'))
	except:
		pass

