#pragma once
#include "DEALKeyExpantion.h"
#include "DEALRoundFunction.h"
#include "FeistelNet.h"
#include "ISymmetricCypher.h"
#include <cstring>



class DEAL : public ISymmetricCypher
{
    FeistelNet net;
public:

    DEAL(uint32_t key_size) : net(FeistelNet(new DEALKeyExpansion(), new DEALRoundFunction(), key_size, 16)) {}
    ~DEAL() override = default;

    void encrypt(uint8_t* text, uint8_t* encrText, uint8_t* key) override
    {
        memcpy(encrText, text, 16);
        net.encryptBlock(encrText, key);
    }

    void decrypt(uint8_t* text, uint8_t* decrText, uint8_t* key) override
    {
        memcpy(decrText, text, 16);
        net.decryptBlock(decrText, key);
    }
};
