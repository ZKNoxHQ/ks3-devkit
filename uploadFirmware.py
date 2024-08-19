import usb
import binascii
import struct
import os
import sys

BLOCK_SIZE = 64
TRANSFER_FILE_BLOCK_SIZE = 4096 

HEADER_PROTOCOL = 0x6b
PROTOCOL_VERSION = 0
PROTOCOL_INDEX = 0
PROTOCOL_FLAG = 1
SERVICE_ID_FILE_TRANS = 2
COMMAND_ID_FILE_TRANS_INFO = 1
COMMAND_ID_FILE_TRANS_CONTENT = 2
COMMAND_ID_FILE_TRANS_COMPLETE = 3
TAG_FILE_NAME = 1
TAG_FILE_SIZE = 2
TAG_FILE_MD5 = 3
TAG_FILE_SIGNATURE = 4
TAG_FILE_OFFSET = 1
TAG_FILE_DATA = 2
TAG_ACK = 0xff
TAG_FILE_CONTENT_ACK = 3 

MD5_DUMMY = binascii.unhexlify("997335c1ac2aab2332e8838e57c6715e")
MD5_SIGNATURE_DUMMY = binascii.unhexlify("237b6dd35e1fee70113bbd6919e42f0e551a7508ab141a6fd95e770e9f837050436834b437805bb68787b147cac5abad2e2c995ee0af759119be8f6eba182d11")

def build_tlv(tag, data):
	result = struct.pack("<B", tag)
	if len(data) > 0x7f:
		result = result + struct.pack("<BB", 0x80 | (len(data) >> 8), len(data) & 0xff)
	else:
		result = result + struct.pack("<B", len(data))
	result = result + data
	return result

def send_data(ep_out, serviceId, commandId, data):
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
	checksum = struct.pack("<I", binascii.crc32(wire + data))
	ep_out.write(checksum, 64)

def check_ack_response(response):
	if response[0] != HEADER_PROTOCOL:
		raise Exception("Invalid response")
	dataSize = struct.unpack("<H", response[8 : 8 + 2])[0]
	if dataSize != 6:
		raise Exception("Invalid response size")
	if response[10] == TAG_FILE_CONTENT_ACK:
		return
	if response[10] != TAG_ACK:
		raise Exception("Invalid response ack tag")
	if response[11] != 4:
		raise Exception("Invalid response ack tag size")
	ack = struct.unpack("<I", response[12 : 12 + 4])[0]
	if ack != 0:
		raise Exception("Invalid ack " + str(ack))

if len(sys.argv) < 2:
        print("Usage : " + sys.argv[0] + " path_to_keystone3.bin")
        sys.exit(1)

dev = usb.core.find(idVendor=0x1209)

if dev == None:
        print("Device not found")
        sys.exit(1)

cfg = dev[0]
intf=cfg[(0,0)]
ep_out = intf[0]
ep_in = intf[1]

f = open(sys.argv[1], "rb")
f.seek(0, os.SEEK_END)
fileSize = f.tell()
f.seek(0, os.SEEK_SET)
fileData = f.read()
f.close()

data = build_tlv(TAG_FILE_NAME, b"keystone3.bin")
data += build_tlv(TAG_FILE_SIZE, struct.pack("<I", fileSize))
data += build_tlv(TAG_FILE_MD5, MD5_DUMMY)
data += build_tlv(TAG_FILE_SIGNATURE, MD5_SIGNATURE_DUMMY) 

send_data(ep_out, SERVICE_ID_FILE_TRANS, COMMAND_ID_FILE_TRANS_INFO, data)
data = ep_in.read(64)
check_ack_response(data)

print("Upload in progress ...")

offset = 0
lastPercent = 0
while offset < len(fileData):
	chunkSize = TRANSFER_FILE_BLOCK_SIZE if ((offset + TRANSFER_FILE_BLOCK_SIZE) < len(fileData)) else len(fileData) - offset
	data = build_tlv(TAG_FILE_OFFSET, struct.pack("<I", offset))
	data += build_tlv(TAG_FILE_DATA, fileData[offset : offset + chunkSize])
	send_data(ep_out, SERVICE_ID_FILE_TRANS, COMMAND_ID_FILE_TRANS_CONTENT, data)
	data = ep_in.read(64)
	check_ack_response(data)
	offset += chunkSize 	
	percent = int(offset * 100 / len(fileData))
	if percent > lastPercent + 1:
		print(str(percent) + "% done")
		lastPercent = percent	

input("File uploaded, press return to finalize") 

send_data(ep_out, SERVICE_ID_FILE_TRANS, COMMAND_ID_FILE_TRANS_COMPLETE, b"")


