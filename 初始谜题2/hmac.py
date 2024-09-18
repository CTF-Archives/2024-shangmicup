import binascii
from gmssl import sm3


# 读取HMAC key文件
def read_hmac_key(file_path):
    with open(file_path, 'rb') as f:
        hmac_key = f.read().strip()
    return hmac_key


# 生成token
def generate_token(hmac_key, counter):
    # 如果HMAC_KEY长度不足32字节，则在末尾补0，超过64字节则截断
    if len(hmac_key) < 32:
        hmac_key = hmac_key.ljust(32, b'\x00')
    elif len(hmac_key) > 32:
        hmac_key = hmac_key[:32]

    # 将计数器转换为字节表示
    counter_bytes = counter.to_bytes((counter.bit_length() + 7) // 8, 'big')
    # print("counter_bytes:", binascii.hexlify(counter_bytes))

    tobe_hashed = bytearray(hmac_key + counter_bytes)

    # print("tobe_hashed:", binascii.hexlify(tobe_hashed))

    # 使用SM3算法计算哈希值
    sm3_hash = sm3.sm3_hash(tobe_hashed)

    # 将SM3的哈希值转换为十六进制字符串作为token
    token = sm3_hash

    return token


current_counter = 0


def verify_token(hmac_key, counter, token):
    # 生成token
    generated_token = generate_token(hmac_key, counter)
    global current_counter
    # 比较生成的token和输入的token是否相同
    if generated_token == token:
        if counter & 0xFFFFFFFF > current_counter:
            current_counter = counter & 0xFFFFFFFF
            print("current_counter: ", hex(current_counter))
            return "Success"
        else:
            return "Error: counter must be increasing"
    else:
        return "Error: token not match"


# 假设HMAC key文件路径
hmac_key_file = 'hmac_key.txt'
# 假设计数器值
counter = 0x12345678

# 读取HMAC key
hmac_key = read_hmac_key(hmac_key_file)

# 生成token
token = generate_token(hmac_key, counter)
print("Generated token:", token)
print(verify_token(hmac_key, counter, token))




