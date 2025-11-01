#pragma once
#include<cstdint>

#include "KeyExpansion.h"

class FeistelNetwork {
    IKeyExpansion *keyExpansion;
    IRoundFunction *roundFunction;
public:
    FeistelNetwork(IKeyExpansion *_keyExpansion, IRoundFunction *_roundFunction) :
    keyExpansion(_keyExpansion), roundFunction(_roundFunction) {}

    uint8_t* encryptBlock(uint8_t* text, uint8_t* key);
    uint8_t* decryptBlock(uint8_t* text, uint8_t* key);
};
