#pragma once

#include "KeyExpansion.h"
#include "DES.h"


uint64_t R = 0x0123456789ABCDEF;
uint8_t iv[8] = {0, 0, 0, 0, 0, 0, 0, 0};


class DEALKeyExpansion final : public IKeyExpansion
{
    void expandKey(const uint8_t* key, uint8_t* new_keys, uint32_t key_len) override
    {
        const auto K_1 = reinterpret_cast<const uint64_t*>(key);
        const auto K_2 = K_1 + 1;

        auto des_encryptor = new DES();

        uint8_t* des_key = reinterpret_cast<uint8_t*>(&R);
        uint64_t t = 0;

        if (key_len == 128) {

            t = *K_1 ^ *reinterpret_cast<uint64_t*>(iv);
            des_encryptor->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys, des_key);

            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys);
            des_encryptor->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 8, des_key);

            uint64_t i = 0;
            i |= (1ULL << 63);
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(new_keys + 8) ^ i;
            des_encryptor->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 16, des_key);

            i = 0;
            i |= (1ULL << 62);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 16) ^ i;
            des_encryptor->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 24, des_key);

            i = 0;
            i |= (1ULL << 60);
            t = *K_1 ^ *reinterpret_cast<uint64_t*>(new_keys + 24) ^ i;
            des_encryptor->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 32, des_key);

            i = 0;
            i |= (1ULL << 56);
            t = *K_2 ^ *reinterpret_cast<uint64_t*>(new_keys + 32) ^ i;
            des_encryptor->encrypt(reinterpret_cast<uint8_t*>(&t), new_keys + 40, des_key);
        }

        delete des_encryptor;
    }
};
