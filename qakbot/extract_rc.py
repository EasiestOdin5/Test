import pefile
import hashlib
import struct
import sys

def unhex(hex_string):
    import binascii
    if type(hex_string) == str:
        return binascii.unhexlify(hex_string.encode('utf-8'))
    else:
        return binascii.unhexlify(hex_string)

def tohex(data):
    import binascii
    if type(data) == str:
        return binascii.hexlify(data.encode('utf-8'))
    else:
        return binascii.hexlify(data)


def rc4crypt(data, key):
    #If the input is a string convert to byte arrays
    if type(data) == str:
        data = data.encode('utf-8')
    if type(key) == str:
        key = key.encode('utf-8')
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + key[i % len(key)]) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for c in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(c ^ box[(box[x] + box[y]) % 256])
    return bytes(out)




# with raw
key_list_str = [ rb'\System32\WindowsPowerShel1\v1.0\powershel1.exe' ]

# sha1
key_list_sha1 = [ '2fbafdc0451de65322a9aee65f28be319ad9574e' ]


data = open("661_01340000.bin", "rb").read()
pe = pefile.PE(data=data)

rt_string_idx = [
    entry.id for entry in
    pe.DIRECTORY_ENTRY_RESOURCE.entries
].index(pefile.RESOURCE_TYPE['RT_RCDATA'])

rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]



key = b""
config = b""
c2_data = b""

for entry in rt_string_directory.directory.entries:
    data_rva = entry.directory.entries[0].data.struct.OffsetToData
    size = entry.directory.entries[0].data.struct.Size
    rc_data = pe.get_memory_mapped_image()[data_rva:data_rva+size]

    if (len(rc_data) > 700 and len(rc_data) < 1500):
        print("Name:", entry.name, "\tSize:", len(rc_data))

        key_found = False
        for key_str in key_list_str:
            key = hashlib.sha1(key_str).digest()
            config = rc4crypt(rc_data, key)

            checksum = config[0:20]
            c2_data = config[20:]

            if (hashlib.sha1(c2_data).digest() == checksum):
                print("key found:", key_str)
                key_found = True
                break

    if key_found:
        break
        

if not key_found:
    print("key not found: unable to extract c2")
    sys.exit()


if len(c2_data) % 7 != 0:
    print("c2_data length is not mod 7")
    print(tohex(c2_data))
    sys.exit()

for i in range(0, len(c2_data), 7):
    #print(tohex(c2_data[i:i+7]))
    
    ip1 = c2_data[i+1:i+2]
    ip2 = c2_data[i+2:i+3]
    ip3 = c2_data[i+3:i+4]
    ip4 = c2_data[i+4:i+5]
    port = struct.unpack(">H", c2_data[i+5:i+7])[0]

    ip = "%d.%d.%d.%d:%d" % (ord(ip1), ord(ip2), ord(ip3), ord(ip4), port)
    print(ip)
