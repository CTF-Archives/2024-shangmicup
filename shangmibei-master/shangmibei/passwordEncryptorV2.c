#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define ROUND 16

//S-Box 16x16
int sBox[16] =
        {
                2, 10, 4, 12,
                1, 3, 9, 14,
                7, 11, 8, 6,
                5, 0, 15, 13
        };


// 将十六进制字符串转换为 unsigned char 数组
void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len / 2 > bytes_len) {
        fprintf(stderr, "Invalid hex string length.\n");
        return;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]);
    }
}


// 派生轮密钥
void derive_round_key(unsigned int key, unsigned char *round_key, int length) {

    unsigned int tmp = key;
    for(int i = 0; i < length / 16; i++)
    {
        memcpy(round_key + i * 16,      &tmp, 4);   tmp++;
        memcpy(round_key + i * 16 + 4,  &tmp, 4);   tmp++;
        memcpy(round_key + i * 16 + 8,  &tmp, 4);   tmp++;
        memcpy(round_key + i * 16 + 12, &tmp, 4);   tmp++;
    }
}


// 比特逆序
void reverseBits(unsigned char* state) {
    unsigned char temp[16];
    for (int i = 0; i < 16; i++) {
        unsigned char byte = 0;
        for (int j = 0; j < 8; j++) {
            byte |= ((state[i] >> j) & 1) << (7 - j);
        }
        temp[15 - i] = byte;
    }
    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}


void sBoxTransform(unsigned char* state) {
    for (int i = 0; i < 16; i++) {
        int lo = sBox[state[i] & 0xF];
        int hi = sBox[state[i] >> 4];
        state[i] = (hi << 4) | lo;
    }
}


void leftShiftBytes(unsigned char* state) {
    unsigned char temp[16];
    for (int i = 0; i < 16; i += 4) {
        temp[i + 0] = state[i + 2] >> 5 | (state[i + 1] << 3);
        temp[i + 1] = state[i + 3] >> 5 | (state[i + 2] << 3);
        temp[i + 2] = state[i + 0] >> 5 | (state[i + 3] << 3);
        temp[i + 3] = state[i + 1] >> 5 | (state[i + 0] << 3);
    }
    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[i];
    }
}


// 轮密钥加
void addRoundKey(unsigned char* state, unsigned char* roundKey, unsigned int round) {
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            state[i] ^= ((roundKey[i + round * 16] >> j) & 1) << j;
        }
    }
}

// 加密函数
void encrypt(unsigned char* password, unsigned int key, unsigned char* ciphertext) {
    unsigned char roundKeys[16 * ROUND] = {}; //

    // 生成轮密钥
    derive_round_key(key, roundKeys, 16 * ROUND);

    // 初始状态为16字节的口令
    unsigned char state[16]; // 初始状态为16字节的密码
    memcpy(state, password, 16); // 初始状态为密码的初始值

    // 迭代加密过程
    for (int round = 0; round < ROUND; round++)
    {
        reverseBits(state);
        sBoxTransform(state);
        leftShiftBytes(state);
        addRoundKey(state, roundKeys, round);
    }

    memcpy(ciphertext, state, 16);
}

void main() {
    unsigned char password[] = "pwd:xxxxxxxxxxxx"; // 口令明文固定以pwd:开头，16字节的口令
    unsigned int key = 0xF0FFFFFF; // 4字节的密钥
    unsigned char ciphertext[16]; // 16字节的状态

    printf("Password: \n");
    printf("%s\n", password);

    encrypt(password, key, ciphertext);

    // 输出加密后的结果
    printf("Encrypted password:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");
}















