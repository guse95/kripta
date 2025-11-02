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
        const auto keys = keyExpansion->expandKey(key);
        for (size_t i = 0; i < 16; ++i)
        {
            auto *l = reinterpret_cast<uint32_t*>(text);
            auto *r = l + 1;
            const auto tmp = *l;
            *r = *l ^ *reinterpret_cast<uint32_t*>(
                roundFunction->roundFun(reinterpret_cast<uint8_t*>(r), keys[i]));
            *l = tmp;
        }
        const auto tmp = reinterpret_cast<uint64_t*>(text);
        *tmp = (*tmp << 32) | (*tmp >> 32);
    }

    void decryptBlock(uint8_t* text, const uint8_t* key) const
    {
        const auto keys = keyExpansion->expandKey(key);
        for (size_t i = 0; i < 16; ++i)
        {
            auto *r = reinterpret_cast<uint32_t*>(text);
            auto *l = r + 1;
            const auto tmp = *l;
            *l = *r ^ *reinterpret_cast<uint32_t*>(
                roundFunction->roundFun(reinterpret_cast<uint8_t*>(l), keys[i]));
            *r = tmp;
        }
        const auto tmp = reinterpret_cast<uint64_t*>(text);
        *tmp = (*tmp << 32) | (*tmp >> 32);
    }
};
