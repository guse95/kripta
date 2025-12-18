#include "AESKeyExpantion.h"


void AESKeyExpantion::expandKey(const uint8_t* key, uint8_t* new_keys, uint32_t key_len) {
    const uint32_t Nk = key_len / 4;
    const uint32_t Nb = block_size / 4;
    const uint32_t Nr = Nk + 6;

    const uint32_t total_words = Nb * (Nr + 1);
    auto* w = reinterpret_cast<uint32_t*>(new_keys);

    for (uint32_t i = 0; i < Nk; ++i) {
        w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3];
    }

    constexpr uint32_t rcon[10] = {0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                         0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000};

    for (uint32_t i = Nk; i < total_words; ++i) {
        uint32_t temp = w[i - 1];
        if (i % Nk == 0) {
            uint8_t bytes[4] = { 0 };

            bytes[0] = (temp >> 24) & 0xFF;  // MSB
            bytes[1] = (temp >> 16) & 0xFF;
            bytes[2] = (temp >> 8) & 0xFF;
            bytes[3] = temp & 0xFF;

            // RotWord
            uint8_t t = bytes[0];
            bytes[0] = bytes[1];
            bytes[1] = bytes[2];
            bytes[2] = bytes[3];
            bytes[3] = t;

            // SubWord
            bytes[0] = S_box[bytes[0]];
            bytes[1] = S_box[bytes[1]];
            bytes[2] = S_box[bytes[2]];
            bytes[3] = S_box[bytes[3]];

            // bytes[0] = S_box[(temp >> 16) & 0xFF];
            // bytes[1] = S_box[(temp >> 8) & 0xFF];
            // bytes[2] = S_box[temp & 0xFF];
            // bytes[3] = S_box[(temp >> 24) & 0xFF];

            temp = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            temp ^= rcon[(i / Nk) - 1];
        }
        else if (Nk > 6 && i % Nk == 4) {

            uint8_t bytes[4] = {(uint8_t)((temp >> 24) & 0xFF), (uint8_t)((temp >> 16) & 0xFF), (uint8_t)((temp >> 8) & 0xFF), (uint8_t)(temp & 0xFF)};
            bytes[0] = S_box[bytes[0]];
            bytes[1] = S_box[bytes[1]];
            bytes[2] = S_box[bytes[2]];
            bytes[3] = S_box[bytes[3]];

            // uint8_t bytes[4] = { 0 };
            // bytes[0] = S_box[(temp >> 24) & 0xFF];
            // bytes[1] = S_box[(temp >> 16) & 0xFF];
            // bytes[2] = S_box[(temp >> 8) & 0xFF];
            // bytes[3] = S_box[temp & 0xFF];

            temp = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        }
        w[i] = w[i - Nk] ^ temp;
    }
}