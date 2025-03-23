# Part of ks3-devkit
# MIT license
# Nicolas Bacca, 2025

import struct
import sys
import binascii
import secp256k1
import quicklz
import hashlib

HEADER_MAGIC = b"~fwdata!"

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
compressedFirmware = f.read()
f.close()

signatureBlock = headerData[-256:]
headerData = headerData[:-256]
fileSize = struct.unpack(">I", headerData[len(HEADER_MAGIC) : len(HEADER_MAGIC) + 4])[0]

state = quicklz.QLZStateDecompress()
offset = 0
firmware = b""
while offset < fileSize:
        compressedSize = quicklz.qlz_size_compressed(compressedFirmware[offset:])
        firmware += quicklz.qlz_decompress(compressedFirmware[offset:offset + compressedSize], state)
        offset = offset + compressedSize

privateKey = secp256k1.PrivateKey(privateKey, raw=True)
signature1 = privateKey.ecdsa_sign(compressedFirmware)
signature1 = privateKey.ecdsa_serialize_compact(signature1)
signature1 = binascii.hexlify(signature1).decode('utf-8')
signature2 = privateKey.ecdsa_sign(firmware)
signature2 = privateKey.ecdsa_serialize_compact(signature2)
signature2 = binascii.hexlify(signature2).decode('utf-8')

f = open(sys.argv[2], "wb")
f.write(struct.pack("<I", len(headerData) + 256))
f.write(headerData) 
f.write(bytes(signature1, 'utf-8'))
f.write(bytes(signature2, 'utf-8'))
f.write(b"\x00")
f.write(compressedFirmware)
f.close()
