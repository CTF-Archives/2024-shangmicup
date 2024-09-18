from sympy import Mod, Integer
from sympy.core.numbers import mod_inverse

# 模数
N_HEX = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
MODULUS = Integer(int(N_HEX, 16))
MSG_PREFIX = "CryptoCup message:"


# 加密函数
def encrypt_message(message, key):
    # 添加前缀
    message_with_prefix = MSG_PREFIX + message
    message_bytes = message_with_prefix.encode('utf-8')
    message_len = len(message_bytes)
    num_blocks = (message_len + 15) // 16
    blocks = [message_bytes[i * 16:(i + 1) * 16] for i in range(num_blocks)]

    # 进行0填充
    blocks[-1] = blocks[-1].ljust(16, b'\x00')

    encrypted_blocks = []

    k = key

    # 加密每个分组
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        encrypted_block_int = Mod(block_int * k, MODULUS)
        encrypted_blocks.append(encrypted_block_int)
        k += 1  # 密钥自增1

    # 将加密后的分组连接成最终的密文
    encrypted_message = b''.join(
        int(block_int).to_bytes(32, byteorder='big') for block_int in encrypted_blocks
    )

    return encrypted_message


# 解密函数
def decrypt_message(encrypted_message, key):
    num_blocks = len(encrypted_message) // 32
    blocks = [encrypted_message[i * 32:(i + 1) * 32] for i in range(num_blocks)]

    decrypted_blocks = []

    k = key

    # 解密每个分组
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        key_inv = mod_inverse(k, MODULUS)
        decrypted_block_int = Mod(block_int * key_inv, MODULUS)
        decrypted_blocks.append(decrypted_block_int)
        k += 1  # 密钥自增1

    # 将解密后的分组连接成最终的明文
    decrypted_message = b''.join(
        int(block_int).to_bytes(16, byteorder='big') for block_int in decrypted_blocks
    )

    # 去除前缀
    if decrypted_message.startswith(MSG_PREFIX.encode('utf-8')):
        decrypted_message = decrypted_message[len(MSG_PREFIX):]

    return decrypted_message.rstrip(b'\x00').decode('utf-8')


# 测试
initial_key = Integer(0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0)
message = "Hello, this is a test message."
print("Original Message:", message)

# 加密
encrypted_message = encrypt_message(message, initial_key)
print("Encrypted Message (hex):", encrypted_message.hex())

# 解密
decrypted_message = decrypt_message(encrypted_message, initial_key)
print("Decrypted Message:", decrypted_message)






