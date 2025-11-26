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
        // auto* keys = new uint8_t[round_key_size * rounds](); // 16 x 6 bytes
        // keyExpansion->expandKey(key, keys, key_size);
        //
        // auto l = *reinterpret_cast<uint64_t*>(text);
        // auto r = *reinterpret_cast<uint64_t*>(text + block_size / 2);
        //
        // for (size_t i = 0; i < rounds; ++i)
        // {
        //     const auto tmp = r;
        //     uint64_t FunRes = 0;
        //     roundFunction->roundFun(reinterpret_cast<uint8_t*>(&r),
        //         reinterpret_cast<uint8_t*>(&FunRes), (keys + i * round_key_size));
        //
        //     r = l ^ FunRes;
        //     l = tmp;
        //
        // }
        // // const auto tmp = reinterpret_cast<uint64_t*>(text);
        // // *tmp = (*tmp << 32) | (*tmp >> 32); //TODO: поменять на скока двигать
        // delete[] keys;

        auto* keys = new uint8_t[round_key_size * rounds]();
        keyExpansion->expandKey(key, keys, key_size);

        uint64_t l = (*reinterpret_cast<uint64_t*>(text));
        uint64_t r = (*reinterpret_cast<uint64_t*>(text + (block_size / 2)));

        for (size_t i = 0; i < rounds; i++) {

            uint64_t round_F_result = 0;
            auto* r_ptr = reinterpret_cast<uint8_t*>(&r);
            roundFunction->roundFun(r_ptr, reinterpret_cast<uint8_t*>(&round_F_result),
                keys + i * round_key_size);
            uint64_t xor_result = round_F_result ^ l;

            l = r;
            r = xor_result;
        }
        memcpy(text, &r, block_size / 2);
        memcpy(text + block_size / 2, &l, block_size / 2);

        delete[] keys;
    }

    void decryptBlock(uint8_t* text, const uint8_t* key) const
    {
        // auto* keys = new uint8_t[round_key_size * rounds](); // 16 x 48 bit
        // keyExpansion->expandKey(key, keys, key_size);
        //
        // auto l = *reinterpret_cast<uint64_t*>(text);
        // auto r = *reinterpret_cast<uint64_t*>(text + block_size / 2);
        // for (size_t i = 0; i < rounds; ++i)
        // {
        //     const auto tmp = r;
        //     uint64_t FunRes = 0;
        //     roundFunction->roundFun(reinterpret_cast<uint8_t*>(&r),
        //         reinterpret_cast<uint8_t*>(&FunRes), (keys + (rounds - 1 - i) * round_key_size));
        //
        //
        //     // uint64_t XOR = *l ^ FunRes;
        //     // *l = *r;
        //     // *r = XOR;
        //     r = l ^ FunRes;
        //     l = tmp;
        // }
        // // const auto tmp = reinterpret_cast<uint64_t*>(text);
        // // *tmp = (*tmp << 32) | (*tmp >> 32);
        //
        // delete[] keys;




        auto* keys = new uint8_t[round_key_size * rounds]();
        keyExpansion->expandKey(key, keys, key_size);

        uint64_t l = (*reinterpret_cast<uint64_t*>(text));
        uint64_t r = (*reinterpret_cast<uint64_t*>(text + (block_size / 2)));

        for (size_t i = 0; i < rounds; i++) {
            uint64_t round_F_result = 0;

            auto* r_ptr = reinterpret_cast<uint8_t*>(&r);
            roundFunction->roundFun(r_ptr, reinterpret_cast<uint8_t*>(&round_F_result),
                keys + (rounds - i - 1) * round_key_size);
            uint64_t xor_result = round_F_result ^ l;

            l = r;
            r = xor_result;
        }
        memcpy(text, &r, block_size / 2);
        memcpy(text + block_size / 2, &l, block_size / 2);

        delete[] keys;
    }
};
