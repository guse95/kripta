#pragma once

#include <any>
#include <iostream>
#include <vector>

#include "ISymmetricCypher.h"

class CipherContext
{
    ISymmetricCypher* algorithm;
    uint8_t* key;
    enum class Mode {ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta} mode;
    enum Padding {Zeros, ANSI_X923, PKCS7, ISO10126} padding;
    uint8_t* iv = nullptr;
    std::vector<std::any> additional = {};

public:
    CipherContext(ISymmetricCypher* _algorithm,
        uint8_t* _key,
        Mode _mode, Padding _padding,
        uint8_t* _iv = nullptr,
        std::initializer_list<std::any> _additional = {}) :
    algorithm(_algorithm), key(_key), mode(_mode), padding(_padding), iv(_iv), additional(_additional)
    {
        //TODO: обработка дополнительных параметров
    }

    void encrypt(uint8_t* data, uint8_t* output);
    void decrypt(uint8_t* data, uint8_t* output);

    void encrypt(uint8_t* data, const std::string& outputPath);
    void decrypt(uint8_t* data, const std::string& outputPath);
};
