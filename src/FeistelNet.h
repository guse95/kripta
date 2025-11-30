#pragma once
#include<cstdint>
#include <cstring>

#include "KeyExpansion.h"

class FeistelNet {
    IKeyExpansion *keyExpansion;
    IRoundFunction *roundFunction;
    uint32_t key_size;
    uint32_t rounds;
    uint32_t round_key_size;
    uint32_t block_size;

public:
    FeistelNet(IKeyExpansion *_keyExpansion, IRoundFunction *_roundFunction, const uint32_t _key_size, const uint32_t _block_size) :
    keyExpansion(_keyExpansion), roundFunction(_roundFunction), key_size(_key_size), block_size(_block_size)
    {
        if (key_size == 256)
        {
            rounds = 8;
            round_key_size = 8;
        } else if (key_size == 64)
        {
            rounds = 16;
            round_key_size = 6;
        } else
        {
            rounds = 6;
            round_key_size = 8;
        }
    }
    FeistelNet(const FeistelNet &other) = default;

    void encryptBlock(uint8_t* text, const uint8_t* key) const
    {
        auto* keys = new uint8_t[round_key_size * rounds]();
        keyExpansion->expandKey(key, keys, key_size);

        uint64_t l = (*reinterpret_cast<uint64_t*>(text));
        uint64_t r = (*reinterpret_cast<uint64_t*>(text + (block_size / 2)));

        for (size_t i = 0; i < rounds; i++) {

            uint64_t F = 0;
            auto* tmp = reinterpret_cast<uint8_t*>(&r);
            roundFunction->roundFun(tmp, reinterpret_cast<uint8_t*>(&F),
                keys + i * round_key_size);
            uint64_t XOR = F ^ l;

            l = r;
            r = XOR;
        }
        memcpy(text, &r, block_size / 2);
        memcpy(text + block_size / 2, &l, block_size / 2);

        delete[] keys;
    }

    void decryptBlock(uint8_t* text, const uint8_t* key) const
    {
        auto* keys = new uint8_t[round_key_size * rounds]();
        keyExpansion->expandKey(key, keys, key_size);

        uint64_t l = (*reinterpret_cast<uint64_t*>(text));
        uint64_t r = (*reinterpret_cast<uint64_t*>(text + (block_size / 2)));

        for (size_t i = 0; i < rounds; i++) {
            uint64_t F = 0;

            auto* tmp = reinterpret_cast<uint8_t*>(&r);
            roundFunction->roundFun(tmp, reinterpret_cast<uint8_t*>(&F),
                keys + (rounds - i - 1) * round_key_size);
            uint64_t XOR = F ^ l;

            l = r;
            r = XOR;
        }
        memcpy(text, &r, block_size / 2);
        memcpy(text + block_size / 2, &l, block_size / 2);

        delete[] keys;
    }
};
