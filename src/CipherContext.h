#pragma once

#include <any>
#include <iostream>
#include <vector>
#include <cstring>
#include <random>
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
    const uint64_t block_size;
    uint8_t* iv = nullptr;
    std::vector<std::any> additional = {};

public:

    CipherContext(ISymmetricCypher* _algorithm,
                  uint8_t* _key,
                  Mode _mode, Padding _padding,
                  uint64_t _block_size,
                  uint8_t* _iv = nullptr,
                  std::initializer_list<std::any> _additional = {}) :
        algorithm(_algorithm), key(_key), mode(_mode), padding(_padding), block_size(_block_size), iv(_iv), additional(_additional)
    {
        //TODO: обработка дополнительных параметров
        if (mode == Mode::ECB || mode == Mode::CBC)
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

    static void thread_delta_encr(const CipherContext* context, uint8_t* data, uint8_t* output, const uint8_t* iv,
        const uint64_t ind_thread, const uint64_t num_of_threads, const uint64_t num_of_blocks, const uint32_t delta)
    {
        for (uint64_t j = 0; j * num_of_threads + ind_thread < num_of_blocks; ++j)
        {
            const uint64_t ind_of_block = j * num_of_threads + ind_thread;

            auto tmp_iv = *(uint64_t*)(iv) + ind_of_block * delta;
            context->algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                output + ind_of_block * context->block_size, context->key);
            auto tmp_text = reinterpret_cast<uint64_t*>(data + ind_of_block * context->block_size);
            auto tmp_out = reinterpret_cast<uint64_t*>(output + ind_of_block * context->block_size);
            *tmp_out ^= *tmp_text;
        }
    }

    static void thread_delta_decr(const CipherContext* context, uint8_t* data, uint8_t* output, const uint8_t* iv,
        const uint64_t ind_thread, const uint64_t num_of_threads, const uint64_t num_of_blocks, const uint32_t delta)
    {
        for (uint64_t j = 0; j * num_of_threads + ind_thread < num_of_blocks; ++j)
        {
            const uint64_t ind_of_block = j * num_of_threads + ind_thread;

            auto tmp_iv = *(uint64_t*)(iv) + ind_of_block * delta;
            context->algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                output + ind_of_block * context->block_size, context->key);
            auto tmp_text = reinterpret_cast<uint64_t*>(data + ind_of_block * context->block_size);
            auto tmp_out = reinterpret_cast<uint64_t*>(output + ind_of_block * context->block_size);
            *tmp_out ^= *tmp_text;
        }
    }

    uint8_t* encrypt(uint8_t* data, const uint64_t size, uint64_t& output_len) const
    {
        uint64_t block_count = size / block_size;
        const uint64_t rest = size % block_size;

        output_len = (block_count + 1 + (rest != 0) + (mode == Mode::RandomDelta)) * block_size;
        auto output = new uint8_t[output_len]();

        uint8_t service_block[block_size] = {0};
        service_block[0] = rest;

        switch (mode)
        {
        case Mode::ECB:
            {
                //потоки
                algorithm->encrypt(service_block, output + (block_count + 1) * block_size, key);

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
                }

                return output;
            }
        case Mode::CBC:
            {
                auto tmp_iv = reinterpret_cast<uint64_t*>(iv);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                *tmp_text ^= *tmp_iv;
                algorithm->encrypt(service_block, output, key);


                for (uint64_t i = 0; i < block_count; ++i)
                {
                    tmp_text = reinterpret_cast<uint64_t*>(data + i * block_size);
                    tmp_iv = reinterpret_cast<uint64_t*>(output + i * block_size);
                    *tmp_text ^= *tmp_iv;
                    algorithm->encrypt(data + i * block_size,
                                       output + (i + 1) * block_size, key);
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    tmp_iv = reinterpret_cast<uint64_t*>(output + block_count * block_size);
                    *tmp_text ^= *tmp_iv;
                    algorithm->encrypt(last_block, output + (block_count + 1) * block_size, key);
                }

                return output;
            }
        case Mode::PCBC:
            {
                auto tmp_iv = reinterpret_cast<uint64_t*>(iv);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                uint64_t tmp_prev_text = *tmp_text;
                *tmp_text ^= *tmp_iv;
                algorithm->encrypt(service_block, output, key);


                for (uint64_t i = 0; i < block_count; ++i)
                {
                    tmp_text = reinterpret_cast<uint64_t*>(data + i * block_size);
                    tmp_iv = reinterpret_cast<uint64_t*>(output + i * block_size);

                    tmp_prev_text ^= *tmp_iv;
                    tmp_prev_text ^= *tmp_text;
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_prev_text),
                                       output + (i + 1) * block_size, key);
                    tmp_prev_text = *tmp_text; // копирование блока ((
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    tmp_iv = reinterpret_cast<uint64_t*>(output + block_count * block_size);

                    *tmp_text ^= *tmp_iv;
                    *tmp_text ^= tmp_prev_text;
                    algorithm->encrypt(last_block, output + (block_count + 1) * block_size, key);
                }

                return output;
                break;
            }
        case Mode::CFB:
            {
                auto tmp_iv = *reinterpret_cast<uint64_t*>(iv);
                algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv), output, key);
                auto tmp_out = reinterpret_cast<uint64_t*>(output);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                *tmp_out ^= *tmp_text;


                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(output + i * block_size,
                                       output + (i + 1) * block_size, key);
                    tmp_text = reinterpret_cast<uint64_t*>(data + i * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(output + (i + 1) * block_size);
                    *tmp_out ^= *tmp_text;
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);
                    algorithm->encrypt(output + block_count * block_size,
                        output + (block_count + 1) * block_size, key);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    tmp_out = reinterpret_cast<uint64_t*>(output + (block_count + 1) * block_size);
                    *tmp_out ^= *tmp_text;
                }

                return output;
            }
        case Mode::OFB: // нет смысла в параллельности
            {
                auto tmp_iv = *reinterpret_cast<uint64_t*>(iv);
                algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv), output, key);
                tmp_iv = *reinterpret_cast<uint64_t*>(output);
                auto tmp_out = reinterpret_cast<uint64_t*>(output);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                *tmp_out ^= *tmp_text;


                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                       output + (i + 1) * block_size, key);
                    tmp_iv = *reinterpret_cast<uint64_t*>(output + (i + 1) * block_size);
                    tmp_text = reinterpret_cast<uint64_t*>(data + i * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(output + (i + 1) * block_size);
                    *tmp_out ^= *tmp_text;
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);

                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                        output + (block_count + 1) * block_size, key);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    tmp_out = reinterpret_cast<uint64_t*>(output + (block_count + 1) * block_size);
                    *tmp_out ^= *tmp_text;
                }

                return output;
            }
        case Mode::CTR:
            {
                auto tmp_iv = *reinterpret_cast<uint64_t*>(iv) + block_count + 1;
                algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                    output + (block_count + 1) * block_size, key);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                auto tmp_out = reinterpret_cast<uint64_t*>(output + (block_count + 1) * block_size);
                *tmp_out ^= *tmp_text;

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_encr, this, data, output, iv,
                        i, num_of_threads, block_count, 1);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);

                    tmp_iv = *reinterpret_cast<uint64_t*>(this->iv) + block_count;
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                    output + block_count * block_size, key);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    tmp_out = reinterpret_cast<uint64_t*>(output + block_count * block_size);
                    *tmp_out ^= *tmp_text;
                }

                return output;
            }
        case Mode::RandomDelta:
            {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<uint8_t> dist(0, 255);

                uint8_t rnd_iv[block_size];

                for (size_t i = 0; i < block_size; ++i) {
                    rnd_iv[i] = dist(gen);
                }
                uint32_t delta = *reinterpret_cast<uint32_t*>(rnd_iv);

                algorithm->encrypt(rnd_iv, output, key);

                auto tmp_iv = *reinterpret_cast<uint64_t*>(rnd_iv) + (block_count + 1) * delta;
                algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                    output + (block_count + 2) * block_size, key);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                auto tmp_out = reinterpret_cast<uint64_t*>(output + (block_count + 2) * block_size);
                *tmp_out ^= *tmp_text;

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_encr, this, data, output + block_size, static_cast<uint8_t*>(rnd_iv),
                        i, num_of_threads, block_count, delta);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    uint8_t last_block[block_size];
                    paddingLastBlock(data, size, last_block);

                    tmp_iv = *reinterpret_cast<uint64_t*>(rnd_iv) + block_count * delta;
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                    output + (block_count + 1) * block_size, key);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    tmp_out = reinterpret_cast<uint64_t*>(output + (block_count + 1) * block_size);
                    *tmp_out ^= *tmp_text;
                }

                return output;
            }

        default:
            printf("Something went wrong (encryption)");
            break;
        }
        return nullptr;
    }

    uint8_t* decrypt(uint8_t* data, const uint64_t size, uint64_t& output_len) const
    {
        uint64_t block_count = size / block_size;
        uint8_t service_block[block_size] = {0};

        switch (mode)
        {
        case Mode::ECB:
            {
                //потоки
                algorithm->decrypt(data + (block_count - 1) * block_size, service_block, key);

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

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
                algorithm->decrypt(data, service_block, key);
                auto tmp_iv = reinterpret_cast<uint64_t*>(iv);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                *tmp_text ^= *tmp_iv;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back([this, data, i, num_of_threads, block_count, output]
                        {
                        for (uint64_t j = 0; j * num_of_threads + i < block_count; ++j)
                        {
                            uint64_t ind_of_block = j * num_of_threads + i;

                            this->algorithm->decrypt(data + (ind_of_block + 1) * this->block_size,
                                       output + ind_of_block * this->block_size, this->key);

                            const auto tmp_iv_loc = reinterpret_cast<uint64_t*>(data + ind_of_block * this->block_size);
                            const auto tmp_text_loc = reinterpret_cast<uint64_t*>(output + ind_of_block * this->block_size);
                            *tmp_text_loc = (*tmp_text_loc) ^ (*tmp_iv_loc);
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
                    algorithm->decrypt(data + (block_count + 1) * block_size, last_block, key);
                    tmp_iv = reinterpret_cast<uint64_t*>(data + block_count * block_size);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    *tmp_text ^= *tmp_iv;

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
            }
        case Mode::PCBC:
            {
                algorithm->decrypt(data, service_block, key);
                auto tmp_iv = reinterpret_cast<uint64_t*>(iv);
                auto tmp_text = reinterpret_cast<uint64_t*>(service_block);
                *tmp_text ^= *tmp_iv;
                auto tmp_prev_text = tmp_text;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->decrypt(data + (i + 1) * block_size,
                                       output + i * block_size, key);
                    tmp_iv = reinterpret_cast<uint64_t*>(data + i * block_size);
                    tmp_text = reinterpret_cast<uint64_t*>(output + i * block_size);
                    *tmp_text ^= *tmp_iv;
                    *tmp_text ^= *tmp_prev_text;
                    tmp_prev_text = tmp_text;
                }

                if (rest) {
                    uint8_t last_block[block_size] = {0};
                    algorithm->decrypt(data + (block_count + 1) * block_size, last_block, key);
                    tmp_iv = reinterpret_cast<uint64_t*>(data + block_count * block_size);
                    tmp_text = reinterpret_cast<uint64_t*>(last_block);
                    *tmp_text ^= *tmp_iv;
                    *tmp_text ^= *tmp_prev_text;
                    tmp_prev_text = tmp_text;

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
                break;
            }
        case Mode::CFB:
            {
                algorithm->encrypt(iv, service_block, key);
                auto tmp_out = reinterpret_cast<uint64_t*>(service_block);
                auto tmp_text = reinterpret_cast<uint64_t*>(data);
                *tmp_out ^= *tmp_text;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back([this, data, i, num_of_threads, block_count, output]
                        {
                        for (uint64_t j = 0; j * num_of_threads + i < block_count; ++j)
                        {
                            uint64_t ind_of_block = j * num_of_threads + i;

                            this->algorithm->encrypt(data + ind_of_block * this->block_size,
                                       output + ind_of_block * this->block_size, this->key);
                            auto tmp_text = reinterpret_cast<uint64_t*>(data + (ind_of_block + 1) * this->block_size);
                            auto tmp_out = reinterpret_cast<uint64_t*>(output + ind_of_block * this->block_size);
                            *tmp_out ^= *tmp_text;
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

                    algorithm->encrypt(data + block_count * block_size,
                        last_block, key);
                    tmp_text = reinterpret_cast<uint64_t*>(data + (block_count + 1) * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(last_block);
                    *tmp_out ^= *tmp_text;

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
            }
        case Mode::OFB:
            {
                algorithm->encrypt(iv, service_block, key);
                auto tmp_iv = *reinterpret_cast<uint64_t*>(service_block);
                auto tmp_out = reinterpret_cast<uint64_t*>(service_block);
                auto tmp_text = reinterpret_cast<uint64_t*>(data);
                *tmp_out ^= *tmp_text;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                for (uint64_t i = 0; i < block_count; ++i)
                {
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                       output + i * block_size, key);
                    tmp_iv = *reinterpret_cast<uint64_t*>(output + i * block_size);
                    tmp_text = reinterpret_cast<uint64_t*>(data + (i + 1) * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(output + i * block_size);
                    *tmp_out ^= *tmp_text;
                }

                if (rest) {
                    uint8_t last_block[block_size] = {0};

                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                        last_block, key);
                    tmp_text = reinterpret_cast<uint64_t*>(data + (block_count + 1) * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(last_block);
                    *tmp_out ^= *tmp_text;

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
            }
        case Mode::CTR:
            {
                auto tmp_iv = *reinterpret_cast<uint64_t*>(this->iv) + block_count - 1;
                algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                    service_block, key);
                auto tmp_text = reinterpret_cast<uint64_t*>(data + (block_count - 1) * block_size);
                auto tmp_out = reinterpret_cast<uint64_t*>(service_block);
                *tmp_out ^= *tmp_text;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_decr, this, data, output, iv,
                        i, num_of_threads, block_count, 1);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    uint8_t last_block[block_size] = {0};

                    tmp_iv = *reinterpret_cast<uint64_t*>(this->iv) + block_count;
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                    last_block, key);
                    tmp_text = reinterpret_cast<uint64_t*>(data + block_count * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(last_block);
                    *tmp_out ^= *tmp_text;

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
            }
        case Mode::RandomDelta:
            {
                uint8_t rnd_iv[block_size] = {0};
                algorithm->decrypt(data, rnd_iv, key);

                uint32_t delta = *reinterpret_cast<uint32_t*>(rnd_iv);
                --block_count;

                auto tmp_iv = *reinterpret_cast<uint64_t*>(rnd_iv) + (block_count - 1) * delta;
                algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                    service_block, key);
                auto tmp_text = reinterpret_cast<uint64_t*>(data + block_count * block_size);
                auto tmp_out = reinterpret_cast<uint64_t*>(service_block);
                *tmp_out ^= *tmp_text;

                const uint64_t rest = service_block[0];
                block_count -= 1 + (rest != 0);

                output_len = block_count * block_size + rest;
                auto output = new uint8_t[output_len]();

                std::vector<std::thread> threads;
                const int num_of_threads = std::any_cast<int>(additional[0]);

                for (uint64_t i = 0; i < num_of_threads; i++)
                {
                    threads.emplace_back(thread_delta_decr, this, data + block_size, output, static_cast<uint8_t*>(rnd_iv),
                        i, num_of_threads, block_count, delta);
                }
                for (auto& t : threads)
                {
                    t.join();
                }

                if (rest != 0) {
                    uint8_t last_block[block_size] = {0};

                    tmp_iv = *reinterpret_cast<uint64_t*>(rnd_iv) + block_count * delta;
                    algorithm->encrypt(reinterpret_cast<uint8_t*>(&tmp_iv),
                                    last_block, key);
                    tmp_text = reinterpret_cast<uint64_t*>(data + (block_count + 1) * block_size);
                    tmp_out = reinterpret_cast<uint64_t*>(last_block);
                    *tmp_out ^= *tmp_text;

                    unpaddingLastBlock(last_block, rest, output + block_count * block_size);
                }

                return output;
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
