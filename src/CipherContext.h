#pragma once

#include <any>
#include <iostream>
#include <vector>
#include <cstring>
#include <thread>

#include "P_Block.h"
#include "ISymmetricCypher.h"

enum class Mode { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };

enum class Padding { Zeros, ANSI_X923, PKCS7, ISO10126 };

class   CipherContext
{
    ISymmetricCypher* algorithm;
    uint8_t* key;
    Mode mode;
    Padding padding;

    uint8_t* iv = nullptr;
    std::vector<std::any> additional = {};

public:
    const uint64_t block_size = 8;

    CipherContext(ISymmetricCypher* _algorithm,
                  uint8_t* _key,
                  Mode _mode, Padding _padding,
                  uint8_t* _iv = nullptr,
                  std::initializer_list<std::any> _additional = {}) :
        algorithm(_algorithm), key(_key), mode(_mode), padding(_padding), iv(_iv), additional(_additional)
    {
        //TODO: обработка дополнительных параметров
        if (mode == Mode::ECB)
        {
            // additional[0].isNumb();
        }
    }

    static void threas_encr(const CipherContext* context, uint8_t* data,
        const uint64_t ind_thread, const uint64_t num_of_threads, const uint64_t num_of_blocks, uint8_t* output)
    {
        for (uint64_t i = 0; i * num_of_threads + ind_thread < num_of_blocks; ++i)
        {
            uint64_t ind_of_block = i * num_of_threads + ind_thread;

            context->algorithm->encrypt(data + ind_of_block * context->block_size,
                               output + ind_of_block * context->block_size, context->key);
            printf("encrypting end");
        }
    }

    void encrypt(uint8_t* data, uint64_t size, uint8_t* output)
    {
        switch (mode)
        {
        case Mode::ECB:
            {
                //потоки
                const uint64_t block_count = size / block_size;
                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(threas_encr,
                        this, data, i, num_of_threads, block_count, output); // [start, end)
                }
                for (auto& t : threads)
                {
                    t.join();
                }


                uint64_t rest;
                if ((rest = size % block_size) != 0)
                {
                    uint8_t last_block[block_size] = {0};
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
