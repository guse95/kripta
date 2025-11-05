#pragma once

#include <any>
#include <iostream>
#include <vector>
#include <cstring>

#include "P_Block.h"
#include "ISymmetricCypher.h"

enum class Mode { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };

enum class Padding { Zeros, ANSI_X923, PKCS7, ISO10126 };

class CipherContext
{
    ISymmetricCypher* algorithm;
    uint8_t* key;
    Mode mode;
    Padding padding;

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

    void encrypt(uint8_t* data, uint64_t size, uint8_t* output)
    {
        switch (mode)
        {
        case Mode::ECB:
            {
                //TODO: потоки
                const uint64_t block_size = 8;
                uint64_t block_count = size / block_size;
                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(data + i * block_size,
                                       output + i * block_size, key);
                    printf("encrypting end");
                }

                uint64_t rest;
                if ((rest = size % block_size) != 0)
                {
                    uint8_t last_block[block_size];
                    memcpy(last_block, data + size - rest, rest);
                    algorithm->encrypt(last_block, output + size - rest, key);
                    //TODO: функция с "добивкой" последнего блока
                }
                break;
            }
        case Mode::CBC:
            {
                break;
            }
        case Mode::PCBC:
            {
                break;
            }
        case Mode::CFB:
            {
                break;
            }
        case Mode::OFB:
            {
                break;
            }
        case Mode::CTR:
            {
                break;
            }
        case Mode::RandomDelta:
            {
                break;
            }

        default:
            printf("Something went wrong (decryption)");
            break;
        }
    }

    void decrypt(uint8_t* data, uint64_t size, uint8_t* output)
    {
        switch (mode)
        {
        case Mode::ECB:
            {
                //TODO: потоки
                uint64_t block_size = 8;
                for (uint64_t i = 0; i < size / block_size; i++)
                {
                    algorithm->decrypt(data + i * block_size,
                                       output + i * block_size, key);
                }
            }
        case Mode::CBC:
            {
                break;
            }
        case Mode::PCBC:
            {
                break;
            }
        case Mode::CFB:
            {
                break;
            }
        case Mode::OFB:
            {
                break;
            }
        case Mode::CTR:
            {
                break;
            }
        case Mode::RandomDelta:
            {
                break;
            }

        default:
            printf("Something went wrong (decryption)");
            break;
        }
    }

    void encrypt(uint8_t* data, const std::string& outputPath);
    void decrypt(uint8_t* data, const std::string& outputPath);
};
