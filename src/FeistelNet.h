#pragma once
#include<cstdint>

#include "KeyExpansion.h"

class FeistelNet {
    IKeyExpansion *keyExpansion;
    IRoundFunction *roundFunction;

public:
    FeistelNet(IKeyExpansion *_keyExpansion, IRoundFunction *_roundFunction) :
    keyExpansion(_keyExpansion), roundFunction(_roundFunction) {}
    FeistelNet(const FeistelNet &other) = default;

    void encryptBlock(uint8_t* text, const uint8_t* key) const
    {
        uint8_t keys[96] = {0}; // 16 x 48 bit
        keyExpansion->expandKey(key, keys);

        auto *l = reinterpret_cast<uint32_t*>(text);
        auto *r = l + 1;

        for (size_t i = 0; i < 16; ++i)
        {

            const auto tmp = *r;
            uint32_t FunRes = 0;
            roundFunction->roundFun(reinterpret_cast<uint8_t*>(r),
                reinterpret_cast<uint8_t*>(&FunRes), (keys + i * 6));

            *r = *l ^ FunRes;
            *l = tmp;
        }
        const auto tmp = reinterpret_cast<uint64_t*>(text);
        *tmp = (*tmp << 32) | (*tmp >> 32);
    }

    void decryptBlock(uint8_t* text, const uint8_t* key) const
    {
        uint8_t keys[96] = {0}; // 16 x 48 bit
        keyExpansion->expandKey(key, keys);

        auto *l = reinterpret_cast<uint32_t*>(text);
        auto *r = l + 1;

        for (size_t i = 0; i < 16; ++i)
        {
            const auto tmp = *r;
            uint32_t FunRes = 0;
            roundFunction->roundFun(reinterpret_cast<uint8_t*>(r),
                reinterpret_cast<uint8_t*>(&FunRes), (keys + (15 - i) * 6));

            *r = *l ^ FunRes;
            *l = tmp;
        }
        const auto tmp = reinterpret_cast<uint64_t*>(text);
        *tmp = (*tmp << 32) | (*tmp >> 32);
    }
};
