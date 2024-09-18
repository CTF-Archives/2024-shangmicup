import sympy as sp
import random

# 设置参数
n = 16  # 向量长度
q = 251  # 模数

# 生成随机噪声向量e
e = sp.Matrix(sp.randMatrix(n, 1, min=0, max=1))  # 噪声向量

# 生成随机n维私钥向量s和n*n矩阵A
s = sp.Matrix(sp.randMatrix(n, 1, min=0, max=q - 1))  # 私钥向量
Temp = sp.Matrix(sp.randMatrix(n, n, min=0, max=q - 1))  # 中间变量矩阵Temp
A = Temp.inv_mod(q)  # 计算矩阵Temp在模 q 下的逆矩阵作为A

# 计算n维公钥向量b
b = (A * s + e) % q  # 公钥向量b = A * s + e


# 加密函数
def encrypt(message, A, b):
    m_bin = bin(message)[2:].zfill(n)  # 将消息转换为16比特的二进制字符串
    m = sp.Matrix([int(bit) for bit in m_bin])  # 转换为SymPy矩阵
    x = sp.Matrix(sp.randMatrix(n, n, min=0, max=q // (n * 4)))  # 随机产生一个n*n的矩阵x
    e1 = sp.Matrix(sp.randMatrix(n, 1, min=0, max=1))  # 随机产生一个n维噪声向量e
    c1 = (x * A) % q  # 密文部分c1 =   x * A
    c2 = (x * b + e1 + m * (q // 2)) % q  # 密文部分c2 = x * b + e1 + m * q/2
    return c1, c2


# 解密函数
def decrypt(c1, c2, s):
    m_dec = (c2 - c1 * s) % q
    m_rec = m_dec.applyfunc(lambda x: round(2 * x / q) % 2)  # 还原消息
    m_bin = ''.join([str(bit) for bit in m_rec])  # 将SymPy矩阵转换为二进制字符串
    m_rec_int = int(m_bin, 2)  # 将二进制字符串转换为整数
    return m_rec_int


# 测试加解密
message = random.randint(0, 2 ** n - 1)  # 要加密的消息，随机生成一个16比特整数
c1, c2 = encrypt(message, A, b)  # 加密

print("原始消息: ", message)
print("公钥A=sp.", A)
print("公钥b=sp.", b)
print("密文c1=sp.", c1)
print("密文c2=sp.", c2)

decrypted_message = decrypt(c1, c2, s)
print("解密后的消息: ", decrypted_message)  # 输出解密后的消息











