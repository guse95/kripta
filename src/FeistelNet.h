#pragma once
#include<cstdint>

#include "KeyExpansion.h"

class FeistelNet {
    IKeyExpansion *keyExpansion;
    IRoundFunction *roundFunction;

public:
    FeistelNet(IKeyExpansion *_keyExpansion, IRoundFunction *_roundFunction) :
    keyExpansion(_keyExpansion), roundFunction(_roundFunction) {}

    void encryptBlock(uint8_t* text, const uint8_t* key) const
    {
        uint8_t keys[96]; // 16 x 48 bit
        keyExpansion->expandKey(key, keys);
        for (size_t i = 0; i < 16; ++i)
        {
            auto *l = reinterpret_cast<uint32_t*>(text);
            auto *r = l + 1;
            const auto tmp = *l;

            uint32_t FunRes;
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
        uint8_t keys[96]; // 16 x 48 bit
        keyExpansion->expandKey(key, keys);
        for (size_t i = 0; i < 16; ++i)
        {
            auto *r = reinterpret_cast<uint32_t*>(text);
            auto *l = r + 1;
            const auto tmp = *l;

            uint32_t FunRes;
            roundFunction->roundFun(reinterpret_cast<uint8_t*>(l),
                reinterpret_cast<uint8_t*>(&FunRes), keys + i * 6);

            *l = *r ^ FunRes;
            *r = tmp;
        }
        const auto tmp = reinterpret_cast<uint64_t*>(text);
        *tmp = (*tmp << 32) | (*tmp >> 32);
    }
};
