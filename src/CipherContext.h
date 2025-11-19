#pragma once

#include <any>
#include <iostream>
#include <vector>
#include <cstring>
#include <thread>

#include "P_Block.h"
#include "ISymmetricCypher.h"

enum class Mode { ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta };

enum class Padding { ZEROS, ANSI_X923, PKCS7, ISO10126 };

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

    void paddingLastBlock(const uint8_t* data, const uint64_t size, uint8_t* last_block) const
    {
        const uint64_t rest = size % block_size;

        if (padding != Padding::ISO10126){
            last_block[block_size] = {0};
        }
        memcpy(last_block, data + size - rest, rest);

        switch (padding)
        {
            case Padding::ZEROS:
                {
                    break;
                }
            case Padding::PKCS7:
                {
                    for (auto i = rest; i < block_size; i++)
                    {
                        last_block[i] = block_size - rest;
                    }
                    break;
                }
            case Padding::ANSI_X923:
                {
                    last_block[block_size - 1] = block_size - rest;
                    break;
                }
            case Padding::ISO10126:
                {
                    last_block[block_size - 1] = block_size - rest;
                    break;
                }
        default:
            printf("Something went wrong (padding last block)");
            break;
        }

    }

    void unpaddingLastBlock(const uint8_t* last_block, const uint64_t rest, uint8_t* output) const
    {
        if (padding != Padding::ZEROS && last_block[block_size - 1] != block_size - rest)
        {
            std::cerr << "padding last block does not match(kod govno)" << std::endl;
        }
        memcpy(output, last_block, rest);
    }

    static void threadEncr(const CipherContext* context, uint8_t* data,
        const uint64_t ind_thread, const uint64_t num_of_threads, const uint64_t num_of_blocks, uint8_t* output)
    {
        for (uint64_t i = 0; i * num_of_threads + ind_thread < num_of_blocks; ++i)
        {
            uint64_t ind_of_block = i * num_of_threads + ind_thread;

            context->algorithm->encrypt(data + ind_of_block * context->block_size,
                               output + ind_of_block * context->block_size, context->key);
        }
        printf("encrypting end %lu\n", ind_thread);
    }

    uint8_t* encrypt(uint8_t* data, const uint64_t size, uint64_t& output_len)
    {
        switch (mode)
        {
        case Mode::ECB:
            {
                //потоки
                uint64_t block_count = size / block_size;
                const uint64_t rest = size % block_size;

                output_len = (block_count + 1 + (rest != 0)) * block_size;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(threadEncr,
                        this, data, i, num_of_threads, block_count, output);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);
                    algorithm->encrypt(last_block, output + block_count * block_size, key);
                    ++block_count;
                }

                uint8_t service_block[block_size] = {0};
                service_block[0] = rest;
                algorithm->encrypt(service_block, output + block_count * block_size, key);

                return output;
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
        return nullptr;
    }

    uint8_t* decrypt(uint8_t* data, const uint64_t size, uint64_t& output_len) const
    {
        switch (mode)
        {
        case Mode::ECB:
            {
                //TODO: потоки
                uint64_t block_count = size / block_size;
                uint8_t service_block[block_size] = {0};
                algorithm->decrypt(data + (block_count - 1) * block_size, service_block, key);
                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[block_count * block_size + rest]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                threads.emplace_back([this, data, i, num_of_threads, block_count, output]
                    {
                    for (uint64_t j = 0; j * num_of_threads + i < block_count; ++j)
                    {
                        uint64_t ind_of_block = j * num_of_threads + i;

                        this->algorithm->decrypt(data + ind_of_block * this->block_size,
                                           output + ind_of_block * this->block_size, this->key);
                    }
                    printf("decrypting end %lu\n", i);
                    });
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest) {
                    uint8_t last_block[block_size] = {0};
                    algorithm->decrypt(data + block_count * block_size, last_block, key);

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
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
        return nullptr;
    }

    void encrypt(uint8_t* data, const std::string& outputPath);
    void decrypt(uint8_t* data, const std::string& outputPath);
};
