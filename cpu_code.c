
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <locale.h>
#include <fcntl.h>
#include <time.h>
//#include <openssl/aes.h>

#define AES_BLOCK_SIZE 16
int counterer = 0;

typedef uint8_t state_t[4][4];
uint8_t* gl_chiper_text;

// ������� S-box ��� SubBytes
static const uint8_t sBox[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
};

unsigned char sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; // F

unsigned char Rcon[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
    0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };


uint8_t SubByte(uint8_t byte) {
    uint8_t row = byte >> 4;
    uint8_t col = byte & 0x0F;
    return sBox[row][col];
}

void SubBytes(state_t state) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = SubByte(state[i][j]);
        }
    }
}

void MixColumns(state_t* state);
uint8_t multiply(uint8_t a, uint8_t b);
void keyExpansion(const uint8_t* inputKey, uint8_t* roundKeys);
void SubWord(uint8_t* word);
void RotWord(uint8_t* word);
void XorWords(uint8_t* result, const uint8_t* word1, const uint8_t* word2);
void AddRoundKey(state_t* state, const uint8_t* roundKey);
void PrintState(const state_t* state);
void AES_encrypt(const uint8_t* plaintext, const uint8_t* key, const uint8_t* nonce, uint8_t* ciphertext);
void IncrementCounter(uint8_t* counter);
void aes_ctr_encrypt(const uint8_t* plaintext, size_t length, const uint8_t* key, const uint8_t* nonce, uint8_t* ciphertext);
void SubWord(uint8_t* word);
void RotWord(uint8_t* word);
void expandKey(unsigned char* expandedKey, unsigned char* key, enum keySize, size_t expandedKeySize);
//void Rcon(uint8_t* word, uint8_t round);

void ShiftRows(state_t state) {
    // �������� ������ ������ �� 1 ���� �����
    uint8_t temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // �������� ������ ������ �� 2 ����� �����
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // �������� ��������� ������ �� 3 ����� �����
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}


void aes_encrypt(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext) {
    state_t state;

    // �������� ���� ������ � ���������
    //memcpy(state, plaintext, AES_BLOCK_SIZE);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = plaintext[i + 4 * j];
        }
    }

    // �������� ��������� �����
    uint8_t roundKeys[176];
    expandKey(roundKeys, key, 16, 176);

    // �������� ������ AES
    AddRoundKey(state, roundKeys);

    // ��������� 9 �������
    for (int i = 1; i < 10; ++i) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + i * AES_BLOCK_SIZE);
    }

    // ��������� �����
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 10 * AES_BLOCK_SIZE);

    // �������� ��������� � �������� �����
    //memcpy(ciphertext, state, AES_BLOCK_SIZE);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            ciphertext[i + 4 * j] = state[i][j];
        }
    }
}


int main() {
    //uint8_t* ciphertext = malloc(plaintext_len * sizeof(uint8_t));
    //_setmode(_fileno(stdout), _O_U8TEXT);
    //uint8_t plaintext[] = "890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef7890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789abcdef1234567890abcdef123456789";
    FILE* plaintextFile;
    if (fopen_s(&plaintextFile, "plaintext.txt", "rb") != 0 || plaintextFile == NULL) {
        fprintf(stderr, "Error opening plaintext file.\n");
        return 1;
    }

    fseek(plaintextFile, 0, SEEK_END);
    long plaintextSize = ftell(plaintextFile);
    fseek(plaintextFile, 0, SEEK_SET);

    uint8_t* plaintext = (uint8_t*)calloc(sizeof(char), plaintextSize);
    fread(plaintext, 1, plaintextSize, plaintextFile);
    fclose(plaintextFile);
    size_t length = sizeof(plaintext) - 1; // ��������� ����������� ����
    /*uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x75,
        0x46, 0x20, 0x63, 0xed
    };*/
    char key_str[] = "kkkkeeeeyyyy....";
    uint8_t key[16];

    // ����������� �������� ������ � ������ ������
    for (int i = 0; i < 16; ++i) {
        key[i] = (uint8_t)key_str[i];
    }
    //uint8_t key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x75, 0x46, 0x20, 0x63, 0xed };

    // ����� ������� ������
    //printf("Key in bytes: ");
    /*for (int i = 0; i < 16; ++i) {
        printf("%02x ", key[i]);
    }
    printf("\n");
    printf("Plain in bytes: ");
    for (int i = 0; i < 16; ++i) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");*/

    uint8_t nonce[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t noncer[16] = {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    uint8_t* ciphertext = malloc(plaintextSize * sizeof(uint8_t));


    //uint8_t inputKey[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x75, 0x46, 0x20, 0x63, 0xed };
    uint8_t roundKeys[176]; // 176 ���� (4 ����� �� ������ �� 44 ��������� ������)

    /*keyExpansion(key, roundKeys);

    printf("Round Keys:\n");
    for (int i = 0; i < 176; ++i) {
        printf("%02X ", roundKeys[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }*/
    /*expandKey(roundKeys, key, 16, 176);

    printf("\nExpanded Key (HEX format):\n");

    for (int i = 0; i < 176; i++)
    {
        printf("%2.2x%c", roundKeys[i], ((i + 1) % 16) ? ' ' : '\n');
    }*/
    //uint64_t nonce = 0;
    clock_t start_time = clock();
    aes_ctr_encrypt(plaintext, plaintextSize, key, noncer, ciphertext);
    clock_t end_time = clock();
    // ����� ������������� ������ � ������ CTR
    printf("Ciphertext in CTR mode:\n");
    for (size_t i = 0; i < 100; ++i) {
        printf("%02x ", ciphertext[i]);
    }
    double elapsed_time = ((double)(end_time - start_time) / CLOCKS_PER_SEC) * 1000;

    // Выводим результат
    printf("\nПрограмма выполнилась за: %.2f миллисекунд\n", elapsed_time);
    //printf("\nCiphertext in characters: ");
    /*for (int i = 0; i < 16; ++i) {
        printf("%c", ciphertext[i]);
    }*/
    //printf("\nCiphertext in characters: ");

    //return 0;
    /*uint8_t inputKey[16] = {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x97, 0x75,
        0x46, 0x20, 0x63, 0xed
    };

    // 44 ��������� ��������
    uint8_t roundKeys[176];

    KeyExpansion(inputKey, roundKeys);

    // ����� ��������� ���������
    for (int i = 0; i < 176; ++i) {
        printf("%02x ", roundKeys[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    state_t state = {
        {0xdb, 0xf2, 0x01, 0xc6},
        {0x13, 0x0a, 0x01, 0xc9},
        {0x53, 0x22, 0x01, 0xc0},
        {0x45, 0x5c, 0x01, 0xc3}
    };

    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);

    // ����� ��������� ����� ���������� SubBytes
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }*/

    free(plaintext);
    free(ciphertext);
    //return 0;
}

void generateNonceAndCounter(uint64_t nonce, uint64_t counter, uint8_t* nonceAndCounter) {
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        nonceAndCounter[i] = (nonce >> (8 * i)) & 0xFF;
    }

    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        nonceAndCounter[sizeof(uint64_t) + i] = (counter >> (8 * i)) & 0xFF;
    }
}

void aes_ctr_encrypt(const uint8_t* plaintext, size_t length, const uint8_t* key, const uint8_t* nonce, uint8_t* ciphertext) {
    size_t blocks = length / 16;
    size_t remaining = length % 16;
    //uint64_t noncer = 0;

    for (size_t i = 0; i < blocks; ++i) {
        //uint8_t newNonce[16];
        //generateNonceAndCounter(noncer, blocks, newNonce);
        //IncrementCounter(nonce);
        AES_encrypt(plaintext+i*16, key, nonce, ciphertext+i*16, 1);
        //AES_encrypt(plaintext, key, cipherNonce, ciphertext + i * 16, 1);
        counterer++;
        //IncrementCounter(nonce);
    }

    if (remaining > 0) {
        //IncrementCounter(nonce);
        uint8_t lastBlock[16];
        AES_encrypt(plaintext+blocks*16, key, nonce, ciphertext + blocks * 16, 1);
        //IncrementCounter(nonce);

        //printf("%s\n", ciphertext);
    }
}

void AES_encrypt(const uint8_t* plaintext, const uint8_t* key, const uint8_t* nonce, uint8_t* ciphertext) {
    state_t state;
    uint8_t roundKeys[176];
    uint8_t counter[16];

    for (int i = 0; i < 16; ++i) {
        counter[i] = nonce[i];
    }
    IncrementCounter(counter);
    //KeyExpansion(key, roundKeys);
    expandKey(roundKeys, key, 16, 176);
    for (int block = 0; block < 1; ++block) {  
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                state[i][j] = counter[i + 4 * j];
            }
        }

        
        AddRoundKey(&state, key);
        
        for (int round = 1; round < 10; ++round) {
            SubBytes(&state);
            
            
            ShiftRows(&state);
            
            
            MixColumns(&state);
            
            
            AddRoundKey(&state, roundKeys + round * 16);
            
        }

        // ��������� ����� ��� MixColumns
        SubBytes(&state);
        ShiftRows(&state);
        AddRoundKey(&state, roundKeys + 160);

        // ����������� ������������� ������ � �������� ������
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                ciphertext[i + 4 * j] = state[i][j] ^ plaintext[i + 4 * j];
                //state[i][j] = state[i][j] ^ plaintext[i + 4 * j];
            }
        }
    }
}

void IncrementCounter(uint8_t* counter) {
    // ���������� 128-������� ��������
    for (int i = 15; i >= 0; --i) {
        if (counter[i] == 0xFF) {
            counter[i] = 0x00;
        }
        else {
            counter[i]++;
            break;
        }
    }
}

void AddRoundKey(state_t* state, const uint8_t* roundKey) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            (*state)[i][j] ^= roundKey[i + 4*j];
        }
    }
}


void MixColumns(state_t* state) {
    for (int i = 0; i < 4; ++i) {
        uint8_t a = (*state)[0][i];
        uint8_t b = (*state)[1][i];
        uint8_t c = (*state)[2][i];
        uint8_t d = (*state)[3][i];
        //printf("%02x %02x %02x %02x\n", a, b, c, d);

        (*state)[0][i] = multiply(a, 0x02) ^ multiply(b, 0x03) ^ c ^ d;
        (*state)[1][i] = a ^ multiply(b, 0x02) ^ multiply(c, 0x03) ^ d;
        (*state)[2][i] = a ^ b ^ multiply(c, 0x02) ^ multiply(d, 0x03);
        (*state)[3][i] = multiply(a, 0x03) ^ b ^ c ^ multiply(d, 0x02);
        uint8_t e = multiply(a, 0x02) ^ multiply(b, 0x03) ^ c ^ d;
        uint8_t f = a ^ multiply(b, 0x02) ^ multiply(c, 0x03) ^ d;
        uint8_t g = a ^ b ^ multiply(c, 0x02) ^ multiply(d, 0x03);
        uint8_t h = multiply(a, 0x03) ^ b^ c^ multiply(d, 0x02);
        //printf("%02x %02x %02x %02x\n", e, f, g, h);
    }
}

uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t high_bit_set;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }
        high_bit_set = a & 0x80;
        a <<= 1;
        if (high_bit_set) {
            a ^= 0x1B; // ��������������� ������� x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return result;
}

unsigned char getSBoxValue(unsigned char num)
{
    return sbox[num];
}

unsigned char getRconValue(unsigned char num)
{
    return Rcon[num];
}

void core(unsigned char* word, int iteration)
{
    int i;

    // rotate the 32-bit word 8 bits to the left
    RotWord(word);

    // apply S-Box substitution on all 4 parts of the 32-bit word
    for (i = 0; i < 4; ++i)
    {
        word[i] = getSBoxValue(word[i]);
    }

    // XOR the output of the rcon operation with i to the first part (leftmost) only
    word[0] = word[0] ^ getRconValue(iteration);
}

void expandKey(unsigned char* expandedKey,
    unsigned char* key,
    enum keySize size,
    size_t expandedKeySize)
{
    // current expanded keySize, in bytes
    int currentSize = 0;
    int rconIteration = 1;
    int i;
    unsigned char t[4] = { 0 }; // temporary 4-byte variable

    // set the 16,24,32 bytes of the expanded key to the input key
    for (i = 0; i < size; i++) //записываем в новый массив 
        expandedKey[i] = key[i];
    currentSize += size;

    while (currentSize < expandedKeySize)
    {
        // assign the previous 4 bytes to the temporary value t
        for (i = 0; i < 4; i++)
        {
            t[i] = expandedKey[(currentSize - 4) + i]; //берем последние четвере символа в ключе
        }

        /* every 16,24,32 bytes we apply the core schedule to t
         * and increment rconIteration afterwards
         */
        if (currentSize % size == 0)
        {
            core(t, rconIteration++); // преобразование - разворот, подмена по таблийа, первый элемент на XOR
        }


        /* We XOR t with the four-byte block 16,24,32 bytes before the new expanded key.
         * This becomes the next four bytes in the expanded key.
         */
        for (i = 0; i < 4; i++)
        {
            expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[i];
            currentSize++; //сколько слов сейчас в массиве
        }
    }
}

void SubWord(uint8_t* word) {
    for (int i = 0; i < 4; ++i) {
        word[i] = sBox[word[i] >> 4][word[i] & 0x0F];
    }
}

void RotWord(uint8_t* word) {
    uint8_t temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

void getRcon(uint8_t* word, uint8_t round) {
    word[0] ^= rcon[round];
}

void PrintState(const state_t* state) {
    // ����� ���������
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%02x ", (*state)[i][j]);
        }
        printf("\n");
    }
}