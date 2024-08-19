# Part of ks3-devkit
# MIT license
# Nicolas Bacca, 2024

import struct
import sys
import json
import binascii
import secp256k1

if len(sys.argv) < 4:
	print("Usage : " + sys.argv[0] + " input_firmware output_firmware hex_private_key")
	sys.exit(1)

try:
        privateKey = binascii.unhexlify(sys.argv[3])
except:
        print("Invalid private key format")
        sys.exit(1)

if len(privateKey) != 32:
        print("Invalid private key size")
        sys.exit(1)


f = open(sys.argv[1], "rb")
data = f.read(4)
headerLen = struct.unpack("<I", data)[0]
headerData = f.read(headerLen)
f.read(1)
firmware = f.read()
f.close()

header = json.loads(headerData.decode('utf-8'))
privateKey = secp256k1.PrivateKey(privateKey, raw=True)
signature = privateKey.ecdsa_sign(firmware)
signature = privateKey.ecdsa_serialize_compact(signature)
signature = binascii.hexlify(signature).decode('utf-8')
header['signature'] = signature
header = json.dumps(header)

f = open(sys.argv[2], "wb")
f.write(struct.pack("<I", len(header))) 
f.write(bytes(header, 'utf-8'))
f.write(b"\x00")
f.write(firmware)
f.close()

