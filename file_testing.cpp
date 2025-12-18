#include <iostream>

#include "CipherContext.h"
#include "AES/AES.h"
#include "DES/DES.h"
#include "DEAL/DEAL.h"
#include "TripleDES/TripleDES.h"


int main()
{
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t key_des[8] = {'a', 's', 'd', 'f', 'e', 'd', 'c', 'b'};
    uint8_t key_deal_128[16] = {
        'z', 'x', 'c', 'v', 'b', 'n', 'm', ',',
        '.', '/', 'a', 's', 'd', 'f', 'g', 'h'
    };
    uint8_t key_deal_192[24] = {
        'j', 'u', 'g', '1', '2', 'n', 'a', 's',
        'd', 'f', 'e', 'd', 'c', 'b', 'm', ',',
        '.', '/', 'a', 's', 'd', 'f', 'g', 'h'
    };
    uint8_t key_deal_256[32] = {
        'p', 'o', 'i', 'u', '9', '8', '7', '6',
        '5', '4', 'a', 's', 'd', 'f', 'g', 'h',
        'z', 'x', 'c', 'v', 'b', 'n', 'm', 's',
        'd', 'k', 'l', 'h', 'n', 'm', 'g', 'h'
    };

    uint8_t iv_des[8] = {'q', 'w', 'e', 'r', 't', 'y', 'u', 'i'};
    uint8_t iv_deal[16] = {
        '1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'g', 'f', 'e', 'd', 'c', 'b', 'a'
    };
    uint8_t iv_aes_192[24] = {
        'l', 'k', 'j', 'h', 'g', 'v', 'x', 'p',
        'f', 'f', 'f', 'f', 'a', 'b', 'm', 'd',
        '.', '/', 'a', 's', 'Z', 'Z', 'Z', 'Z'
    };
    uint8_t iv_aes_256[32] = {
        '0', '9', '8', '7', '6', '5', '4', '3',
        '2', '1', '1', '1', '1', 'f', 'g', 'h',
        'z', 'x', 'c', 'v', 'b', 'n', 'm', 's',
        'd', 'k', 'l', 'h', '1', '1', '1', '1'
    };

    auto alg_des = DES();
    auto alg_tripleDES = TripleDES();
    auto alg_deal_128 = DEAL(128);
    auto alg_deal_192 = DEAL(192);
    auto alg_deal_256 = DEAL(256);

    auto alg_aes_128_128 = AES(16, 16, key_deal_128);
    auto alg_aes_128_192 = AES(16, 24, key_deal_192);
    auto alg_aes_128_256 = AES(16, 32, key_deal_256);

    auto alg_aes_192_128 = AES(24, 16, key_deal_128);
    auto alg_aes_192_192 = AES(24, 24, key_deal_192);
    auto alg_aes_192_256 = AES(24, 32, key_deal_256);

    auto alg_aes_256_128 = AES(32, 16, key_deal_128);
    auto alg_aes_256_192 = AES(32, 24, key_deal_192);
    auto alg_aes_256_256 = AES(32, 32, key_deal_256);

    // CipherContext Cont(&alg_aes_192_192, key_deal_192, Mode::ECB, Padding::PKCS7, 24, iv_aes_192, {8});

    // Cont.encrypt("vid.mp4", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.mp4");

    // Cont.encrypt("33.png", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.png");
    //
    // Cont.encrypt("text.txt", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.txt");

    // ISymmetricCypher* algs[] = {&alg_des, &alg_deal_128, &alg_deal_192, &alg_deal_256};
    // uint8_t* keys[] = {key_des, key_deal_128, key_deal_192, key_deal_256};
    // uint8_t* ivs[] = {iv_des, iv_deal, iv_deal, iv_deal};


    // ISymmetricCypher* algs[] = {
    //     &alg_aes_128_128, &alg_aes_128_192, &alg_aes_128_256,
    //     &alg_aes_192_128, &alg_aes_192_192, &alg_aes_192_256,
    //     &alg_aes_256_128, &alg_aes_256_192, &alg_aes_256_256,
    // };
    // uint8_t* keys[] = {key_deal_128, key_deal_192, key_deal_256};
    // uint8_t* ivs[] = {iv_deal, iv_aes_192, iv_aes_256};
    //
    constexpr Mode modes[] = {Mode::ECB, Mode::CBC, Mode::PCBC, Mode::CFB, Mode::OFB, Mode::CTR, Mode::RandomDelta };
    // constexpr Padding paddings[] = {Padding::ZEROS, Padding::PKCS7, Padding::ANSI_X923, Padding::ISO10126};
    // uint64_t block_sz[] = {16, 24, 32};
    //
    //
    // for (int iv = 0; iv < 3; iv++)
    // {
    //     for (int k = 0; k < 3; k++)
    //     {
    //         for (int j = 0; j < 7; j++)
    //         {
    //             CipherContext Cont(algs[iv * 3 + k], keys[k], modes[j], Padding::ZEROS, block_sz[iv], ivs[iv], {8});
    //
    //             std::string ind = std::to_string(iv) + "_" + std::to_string(k) + "_" + std::to_string(j);
    //             std::string encr_file_name = "EncrRes/encr_" + ind + ".txt";
    //             std::string decr_file_name = "DecrRes/decr_" + ind + ".png";
    //
    //             Cont.encrypt("33.png", encr_file_name);
    //             Cont.decrypt(encr_file_name, decr_file_name);
    //         }
    //     }
    // }



    for (int i = 0; i < 7; i++)
    {
        CipherContext Cont(&alg_tripleDES, key_deal_192, modes[i], Padding::ZEROS, 8, iv_des, {8});

        std::string ind = std::to_string(i);
        std::string encr_file_name = "EncrRes/encr_" + ind + ".txt";
        std::string decr_file_name = "DecrRes/decr_" + ind + ".png";

        Cont.encrypt("33.png", encr_file_name);
        Cont.decrypt(encr_file_name, decr_file_name);
    }
}
