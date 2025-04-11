#include <iostream>
#include <cuda_runtime.h>
#include <iomanip>
#include <fstream>
#include <vector>
#include <iomanip>
#include <time.h>

#define AES_BLOCK_SIZE 16
#define THREADS_PER_BLOCK 128
#define NUM_ROUNDS 10

// AES S-Box
__device__ const unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Round constant array
__device__ const unsigned char Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// SubBytes step of AES encryption
__device__ void SubBytes(unsigned char* state) {
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        state[i] = sbox[state[i]];
    }
}

// ShiftRows step of AES encryption
__device__ void ShiftRows(unsigned char* state) {
    uint8_t temp = state[1 * 4 + 0];
    state[1 * 4 + 0] = state[1 * 4 + 1];
    state[1 * 4 + 1] = state[1 * 4 + 2];
    state[1 * 4 + 2] = state[1 * 4 + 3];
    state[1 * 4 + 3] = temp;

    //                           2            
    temp = state[2 * 4 + 0];
    state[2 * 4 + 0] = state[2 * 4 + 2];
    state[2 * 4 + 2] = temp;
    temp = state[2 * 4 + 1];
    state[2 * 4 + 1] = state[2 * 4 + 3];
    state[2 * 4 + 3] = temp;

    //                              3            
    temp = state[3 * 4 + 3];
    state[3 * 4 + 3] = state[3 * 4 + 2];
    state[3 * 4 + 2] = state[3 * 4 + 1];
    state[3 * 4 + 1] = state[3 * 4 + 0];
    state[3 * 4 + 0] = temp;
}

__device__ uint8_t multiply(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    uint8_t high_bit_set;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }
        high_bit_set = a & 0x80;
        a <<= 1;
        if (high_bit_set) {
            a ^= 0x1B; //                         x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return result;
}
// MixColumns step of AES encryption
__device__ void MixColumns(unsigned char* state) {
    //printf("AAAAAAAAAAAAAAAAAA\n");
    for (size_t i = 0; i < 16; ++i) {
        //printf("%02x ", state[i]);
    }
    //printf("\n");
    //printf("\nAAAAAAAAAAAAAAAAAA\n");
    for (int i = 0; i < 4; ++i) {
        uint8_t a = state[i];
        //printf("%02x ", state[i]);
        uint8_t b = state[4 + i];
        //printf("%02x ", state[i+4]);
        uint8_t c = state[8 + i];
        //printf("%02x ", state[i + 8]);
        uint8_t d = state[12 + i];
        //printf("%02x ", state[i + 12]);
        //printf("%02x %02x %02x %02x\n", a, b, c, d);

        state[i] = (unsigned char)(multiply(a, 0x02) ^ multiply(b, 0x03) ^ c ^ d);
        state[4 + i] = (unsigned char)(a ^ multiply(b, 0x02) ^ multiply(c, 0x03) ^ d);
        state[8 + i] = (unsigned char)(a ^ b ^ multiply(c, 0x02) ^ multiply(d, 0x03));
        state[12 + i] = (unsigned char)(multiply(a, 0x03) ^ b ^ c ^ multiply(d, 0x02));
        uint8_t e = multiply(a, 0x02) ^ multiply(b, 0x03) ^ c ^ d;
        uint8_t f = a ^ multiply(b, 0x02) ^ multiply(c, 0x03) ^ d;
        uint8_t g = a ^ b ^ multiply(c, 0x02) ^ multiply(d, 0x03);
        uint8_t h = multiply(a, 0x03) ^ b ^ c ^ multiply(d, 0x02);
        //printf("%02x %02x %02x %02x\n", e, f, g, h);
    }
    //printf("\nAAAAAAAAAAAAAAAAAA\n");
}

// AddRoundKey step of AES encryption
__device__ void AddRoundKey(unsigned char* state, const unsigned char* roundKey, int mode) {
    //printf("\n---------\n");
    if (mode == 1) {
        for (int i = 0; i < 4; ++i) {
            //printf("%02x ", roundKey[i]);
            //printf();
            for (int j = 0; j < 4; ++j) {
                state[i * 4 + j] ^= roundKey[i + 4 * j];
                //printf("%02x ", roundKey[i*4+j]);
            }
        }
    }
    else {
        for (int i = 0; i < 4; ++i) {
            //printf("%02x ", roundKey[i]);
            //printf();
            for (int j = 0; j < 4; ++j) {
                state[i * 4 + j] ^= roundKey[i * 4 + j];
            }
        }
    }
    //printf("\n---------\n");
}

// KeyExpansion for AES encryption
__device__ void SubWord(unsigned char* word) {
    for (int i = 0; i < 4; ++i) {
        word[i] = sbox[word[i]];
    }
}

__device__ void RotWord(unsigned char* word) {
    unsigned char temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

__device__ void XorWords(unsigned char* word1, const unsigned char* word2) {
    for (int i = 0; i < 4; ++i) {
        word1[i] ^= word2[i];
    }
}

__device__ void KeyExpansion(const unsigned char* key, unsigned char* roundKeys) {
    // Copy the original key to the first round key
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        roundKeys[i] = key[i];
    }

    int roundConstantIndex = 0;
    int currentIndex = AES_BLOCK_SIZE;

    while (currentIndex < AES_BLOCK_SIZE * (NUM_ROUNDS + 1)) {
        unsigned char tempWord[4];
        for (int i = 0; i < 4; ++i) {
            tempWord[i] = roundKeys[currentIndex - 4 + i];
        }

        if (currentIndex % AES_BLOCK_SIZE == 0) {
            RotWord(tempWord);
            SubWord(tempWord);
            tempWord[0] ^= Rcon[roundConstantIndex++];
        }

        XorWords(tempWord, &roundKeys[currentIndex - AES_BLOCK_SIZE]);

        for (int i = 0; i < 4; ++i) {
            roundKeys[currentIndex++] = tempWord[i];
        }
    }
}

__device__ void IncrementCounter(char* counter) {
    //            128-                
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

// AES encryption kernel for CTR mode
__global__ void aesCtrEncryptKernel(const unsigned char* plaintext, const unsigned char* key,
    const unsigned char* nonce, const int numBlocks, unsigned char* ciphertext) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;

    for (int blockIndex = idx; blockIndex < numBlocks; blockIndex += gridDim.x * blockDim.x) {
        // Calculate the counter value (nonce + block index)
        char counter[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            counter[i] = 0x00;
        }
        for (int k = 0; k < 1; k++) {
            IncrementCounter(counter);
        }

        // Generate round keys
        unsigned char roundKeys[176];
        KeyExpansion(key, roundKeys);

        // Encrypt the counter using AES
        unsigned char state[AES_BLOCK_SIZE];
        for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
            state[i] = counter[i];
        }
        AddRoundKey(state, &roundKeys[0 * AES_BLOCK_SIZE], 1);

        for (int round = 0; round < 10; ++round) {
            SubBytes(state);

            ShiftRows(state);

            if (round < 9) {
                MixColumns(state);

            }
            if (round == 0) {
                AddRoundKey(state, &roundKeys[(round + 1) * AES_BLOCK_SIZE], 1);
            }
            else {
                AddRoundKey(state, &roundKeys[(round + 1) * AES_BLOCK_SIZE], 1);
            }

        }

        // XOR the plaintext block with the encrypted counter to get the ciphertext block
        for (int k = 0; k < 1; k++) {
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    ciphertext[blockIndex * AES_BLOCK_SIZE + i + j * 4] = state[i * 4 + j] ^ plaintext[blockIndex * AES_BLOCK_SIZE + i + j * 4];
                    //ciphertext[blockIndex * AES_BLOCK_SIZE + i + j * 4] = '\0';
                    printf("%d - %d - %02x\n", blockIndex * AES_BLOCK_SIZE + i + j * 4, blockIndex, state[i * 4 + j] ^ plaintext[blockIndex * AES_BLOCK_SIZE + i + j * 4]);
                    //printf("%02x\n", ciphertext[blockIndex * AES_BLOCK_SIZE + i + j * 4]);
                }


            }
        }
    }
}

// Wrapper function for AES encryption in CTR mode
void aesCtrEncrypt(const uint8_t* plaintext, const char* key, const char* nonce,
    const int numBlocksCUDA, unsigned char* ciphertext) {
    clock_t start_time = clock();

    // Allocate device memory
    unsigned char* d_plaintext, * d_key, * d_nonce, * d_ciphertext;
    cudaMalloc((void**)&d_plaintext, numBlocksCUDA * AES_BLOCK_SIZE);
    cudaMalloc((void**)&d_key, AES_BLOCK_SIZE);
    cudaMalloc((void**)&d_nonce, AES_BLOCK_SIZE);
    cudaMalloc((void**)&d_ciphertext, numBlocksCUDA * AES_BLOCK_SIZE);
    clock_t test1_time = clock();
    double elapsed_time = ((double)(test1_time - start_time) / CLOCKS_PER_SEC) * 1000;
    //printf("\nПрограмма выполнилась за: %.2f миллисекунд\n", elapsed_time);
    // Copy data from host to device
    cudaMemcpyAsync(d_plaintext, plaintext, numBlocksCUDA * AES_BLOCK_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpyAsync(d_key, key, AES_BLOCK_SIZE, cudaMemcpyHostToDevice);
    cudaMemcpyAsync(d_nonce, nonce, AES_BLOCK_SIZE, cudaMemcpyHostToDevice);
    cudaDeviceSynchronize();
    clock_t test2_time = clock();
    elapsed_time = ((double)(test2_time - start_time) / CLOCKS_PER_SEC) * 1000;
    //printf("\nПрограмма выполнилась за: %.2f миллисекунд\n", elapsed_time);
    // Launch the CUDA kernel
    //unsigned int num_states = size_bytes >> 4;
    int numThreads = THREADS_PER_BLOCK;
    int numBlocks = (numBlocksCUDA + numThreads - 1) / numThreads;
    //int blocksPerGrid = (num_states + threadsPerBlock - 1) / threadsPerBlock;
    aesCtrEncryptKernel << <numBlocks, numThreads >> > (d_plaintext, d_key, d_nonce, numBlocksCUDA, d_ciphertext);
    clock_t test3_time = clock();
    elapsed_time = ((double)(test3_time - start_time) / CLOCKS_PER_SEC) * 1000;
    //printf("ANSWER:\n");
    //printf("\nПрограмма выполнилась за: %.2f миллисекунд\n", elapsed_time);
    //std::vector<uint8_t> ciphertext(AES_BLOCK_SIZE * numBlocks);
    //unsigned char* h_ciphertext = new unsigned char[AES_BLOCK_SIZE * numBlocks];
    cudaMemcpyAsync(ciphertext, d_ciphertext, AES_BLOCK_SIZE * numBlocks, cudaMemcpyDeviceToHost);
    cudaDeviceSynchronize();
    // Write ciphertext to a file

    // Copy the result back to the host
    //cudaMemcpyAsync(cipherFinal.data(), d_ciphertext, numBlocksCUDA * AES_BLOCK_SIZE, cudaMemcpyDeviceToHost);
    //cudaDeviceSynchronize();
    // Free device memory
    cudaFree(d_plaintext);
    //cudaFree(d_key);
    //cudaFree(d_nonce);
    cudaFree(d_ciphertext);
    clock_t test4_time = clock();
    elapsed_time = ((double)(test4_time - start_time) / CLOCKS_PER_SEC) * 1000;
    //printf("\nПрограмма выполнилась за: %.2f миллисекунд\n", elapsed_time);
}

int main() {
    // Example usage
    //uint8_t plaintext[] = "abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789abcdef123456789xabcdef123456789";
    //clock_t start_time = clock();
    //unsigned char ciphertext[AES_BLOCK_SIZE * numBlocks];
    std::ifstream plaintextFile("plaintext.txt", std::ios::binary);
    if (!plaintextFile.is_open()) {
        std::cerr << "Error opening plaintext file.\n";
        return 1;
    }

    plaintextFile.seekg(0, std::ios::end);
    size_t plaintextSize = plaintextFile.tellg();
    plaintextFile.seekg(0, std::ios::beg);

    std::vector<uint8_t> plaintext(plaintextSize);
    plaintextFile.read(reinterpret_cast<char*>(plaintext.data()), plaintextSize);
    plaintextFile.close();
    //plaintext[15] = '0';
    //plaintext[31] = '0';

    char key[] = "kkkkeeeeyyyy....";
    char nonce[] = "abcdefgh12345678";

    int numBlocks = (plaintextSize + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    //unsigned char ciphertext[AES_BLOCK_SIZE * numBlocks];
    unsigned char* ciphertext = new unsigned char[AES_BLOCK_SIZE * numBlocks];
    //cudaMalloc((void**)&d_ciphertext, AES_BLOCK_SIZE * numBlocks);
    //std::vector<uint8_t> ciphertext(AES_BLOCK_SIZE * numBlocks);
    clock_t start_time = clock();
    aesCtrEncrypt(plaintext.data(), key, nonce, numBlocks, ciphertext);
    clock_t end_time = clock();
    std::cout << "Encrypted Message: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)ciphertext[i];
    }
    std::cout << std::endl;
    int length = sizeof(plaintext) - 1;
    // Display the encrypted message

    //clock_t end_time = clock();

    // Вычисляем время в миллисекундах
    double elapsed_time = ((double)(end_time - start_time) / CLOCKS_PER_SEC) * 1000;

    // Выводим результат
    printf("\nПрограмма выполнилась за: %.2f миллисекунд\n", elapsed_time);



    return 0;
}
