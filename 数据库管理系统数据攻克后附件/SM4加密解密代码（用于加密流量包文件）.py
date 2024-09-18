from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

MULTIPLIER = 6364136223846793005
ADDEND = 1
MASK = 0xffffffffffffffff
ITERATIONS = 1000

# 从文件中读取seed
def read_seed(file_path):
    with open(file_path, 'r') as file:
        seed = int(file.read().strip(), 16)
        print("seed:", hex(seed))
    return seed

global_seed = read_seed('seed.txt')

def genRandom():
    global global_seed
    # print("global_seed", hex(global_seed))
    for _ in range(ITERATIONS):
        global_seed = (global_seed * MULTIPLIER + ADDEND) & MASK
    return (global_seed >> 32) & 0xffffffff

# 16进制字符串转bytes
def HexStringToBytes(hex_str):
    return bytes.fromhex(hex_str)

# bytes转16进制字符串
def BytesToHexString(byte_seq):
    return byte_seq.hex()

def genSM4KeyOrIV():
    return HexStringToBytes(''.join(f'{genRandom():08x}' for _ in range(4)))

def SM4Encrypt(data_bytes, key_bytes, iv_bytes):
    sm4 = CryptSM4()
    sm4.set_key(key_bytes, SM4_ENCRYPT)
    return sm4.crypt_cbc(iv_bytes, data_bytes)

def SM4Decrypt(cipher_bytes, key_bytes, iv_bytes):
    sm4 = CryptSM4()
    sm4.set_key(key_bytes, SM4_DECRYPT)
    return sm4.crypt_cbc(iv_bytes, cipher_bytes)


print("############ SM4 Cryptographic Services Start... ###################")

iv_bytes = genSM4KeyOrIV()
print("iv hex:", BytesToHexString(iv_bytes))

key_bytes = genSM4KeyOrIV()
print("key hex:", BytesToHexString(key_bytes))

# 从test.pcapng读取数据并加密
with open('test.pcapng', 'rb') as f1:
    plain1_bytes = f1.read()
    cipher1_bytes = SM4Encrypt(plain1_bytes,key_bytes,iv_bytes)

# 写密文数据到cipherText.dat
with open('cipherText.dat', 'wb') as f2:
    f2.write(cipher1_bytes)

# 从cipherText.dat读密文数据
with open('cipherText.dat', 'rb') as f3:
    cipher2_bytes = f3.read()
    plain2_bytes = SM4Decrypt(cipher2_bytes,key_bytes,iv_bytes)

# 解密密文并将明文写入到plainText.pcapng(含flag4)
with open('plainText.pcapng', 'wb') as f4:
    f4.write(plain2_bytes)






