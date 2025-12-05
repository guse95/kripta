#include <iostream>

#include "CipherContext.h"
#include "DES/DES.h"
#include "DEAL/DEAL.h"


int main()
{
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t key_des[8] = {'a', 's', 'd', 'f', 'e', 'd', 'c', 'b'};
    uint8_t key_deal_128[16] = {'z', 'x', 'c', 'v', 'b', 'n', 'm',
        ',', '.', '/', 'a', 's', 'd', 'f', 'g', 'h'};
    uint8_t key_deal_192[24] = {'j', 'u', 'g', '1', '2', 'n', 'a',
        's', 'd', 'f', 'e', 'd', 'c', 'b', 'm', ',',
        '.', '/', 'a', 's', 'd', 'f', 'g', 'h'};
    uint8_t key_deal_256[32] = {'p', 'o', 'i', 'u', '9', '8', '7',
        '6', '5', '4', 'a', 's', 'd', 'f', 'g', 'h',
        'z', 'x', 'c', 'v', 'b', 'n', 'm', 's', 'd',
        'k', 'l', 'h', 'n', 'm', 'g', 'h'};

    uint8_t iv_des[8] = {'q', 'w', 'e', 'r', 't', 'y', 'u', 'i'};
    uint8_t iv_deal[16] = {'1', '2', '3', '4', '5', '6', '7', '8',
        '9', 'g', 'f', 'e', 'd', 'c', 'b', 'a'};

    auto alg_des = DES();
    auto alg_deal_128 = DEAL(128);
    auto alg_deal_192 = DEAL(192);
    auto alg_deal_256 = DEAL(256);

    // CipherContext Cont(&alg_deal_192, key_deal_192, Mode::ECB, Padding::PKCS7, 16, iv_deal, {8});

    // Cont.encrypt("vid.mp4", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.mp4");

    // Cont.encrypt("33.png", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.png");
    //
    // Cont.encrypt("text.txt", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.txt");

    ISymmetricCypher* algs[] = {&alg_des, &alg_deal_128, &alg_deal_192, &alg_deal_256};
    uint8_t* keys[] = {key_des, key_deal_128, key_deal_192, key_deal_256};
    uint8_t* ivs[] = {iv_des, iv_deal, iv_deal, iv_deal};
    constexpr Mode modes[] = {Mode::ECB, Mode::CBC, Mode::PCBC, Mode::CFB, Mode::OFB, Mode::CTR, Mode::RandomDelta };
    constexpr Padding paddings[] = {Padding::ZEROS, Padding::PKCS7, Padding::ANSI_X923, Padding::ISO10126};
    uint64_t block_sz[] = {8, 16, 16, 16};

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 7; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                CipherContext Cont(algs[i], keys[i], modes[j], paddings[k], block_sz[i], ivs[i], {8});

                std::string ind = std::to_string(i) + "_" + std::to_string(j) + "_" + std::to_string(k);
                std::string encr_file_name = "EncrRes/encr_" + ind + ".txt";
                std::string decr_file_name = "DecrRes/decr_" + ind + ".png";

                Cont.encrypt("33.png", encr_file_name);
                Cont.decrypt(encr_file_name, decr_file_name);
            }
        }
    }
}
