#include <iostream>

#include "CipherContext.h"
#include "MillerRabin.h"
#include "RSA.h"
#include "SoloveiStrassen.h"
#include "DES/DES.h"
#include "DEAL/DEAL.h"
#include "RSA/ServiceGCD.h"
#include "RSA/Ferma.h"
#include "RSA/SoloveiStrassen.h"
#include <gmpxx.h>

#include "WienerAttack.h"
#include "AES/AES.h"
#include "TripleDES/TripleDES.h"


int main()
{
    // uint8_t text[] = "Some text to check DES.\nSome more text.";
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t text[] = "Some text to check if DES works.\nIf you see this, I half won!";
    uint8_t key[8] = {10, 23, 54, 3, 124, 43, 76, 255};
    uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    uint8_t iv2[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'g', 'f', 'e', 'd', 'c', 'b', 'a'};
    uint8_t key2[16] = {'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 'a', 's', 'd', 'f', 'g', 'h'};


    uint8_t iv_aes_192[24] = {
        'n', 'm', ',', '.', '/', 'a', 's', '1',
        '2', '3', '4', '5', '6', '7', '8', '9',
        'g', 'f', 'e', 'd', 'c', 'b', 'a', 'o'};
    uint8_t key_aes_192[24] = {
        'j', 'u', 'g', '1', '2', 'n', 'a', 's',
        'd', 'f', 'e', 'd', 'c', 'b', 'm', ',',
        '.', '/', 'a', 's', 'd', 'f', 'g', 'h'};

    uint8_t iv_aes_256[32] = {
        '5', '6', '7', '8', '9', 'g', 'f', 'e',
        'n', 'm', ',', '.', '/', 'a', 's', '1',
        '2', '3', '4', '5', '6', '7', '8', '9',
        'g', 'f', 'e', 'd', 'c', 'b', 'a', 'Z'};
    uint8_t key_aes_256[32] = {'p', 'o', 'i', 'u', '9', '8', '7',
        '6', '5', '4', 'a', 's', 'd', 'f', 'g', 'h',
        'z', 'x', 'c', 'v', 'b', 'n', 'm', 's', 'd',
        'k', 'l', 'h', 'n', 'm', 'g', 'h'};

    // auto alg = DES();
    // auto alg2 = DEAL(128);
    // auto alg3 = AES(24, 16, key2);
    auto alg4 = TripleDES();
    const CipherContext Cont(&alg4, key_aes_192, Mode::ECB, Padding::ZEROS, 8, iv, {2});

    // uint8_t text_deal[16] = "Some text to ch";
    // uint8_t encr_text[16] = {0};
    // uint8_t decr_text[16] = {0};
    //
    // alg3.encrypt(text_deal, encr_text, key2);
    //
    // std::cout << "Encrypted text: " << std::endl;
    // for (int i = 0; i < 16; i++)
    // {
    //     std::cout << encr_text[i] << " ";
    // }
    // std::cout << std::endl;
    //
    // alg3.decrypt(encr_text, decr_text, key2);
    //
    // std::cout << "Decrypted text: " << std::endl;
    // for (uint64_t i = 0; i < 16; i++)
    // {
    //     std::cout << decr_text[i];
    //     // printf("%c", decrtext[i]);
    // }
    // std::cout << std::endl;


    uint64_t encr_sz;
    uint8_t* encrtext = Cont.encrypt(text, sizeof(text) / sizeof(uint8_t), encr_sz);

    if (encrtext == nullptr)
    {
        std::cerr << "Encrypt failed" << std::endl;
    }
    std::cout << "Encrypted text: " << std::endl;
    for (int i = 0; i < encr_sz; i++)
    {
        std::cout << encrtext[i] << " ";
    }
    std::cout << std::endl;

    uint64_t decr_sz;
    uint8_t* decrtext = Cont.decrypt(encrtext, encr_sz, decr_sz);

    std::cout << "Decrypted text: " << std::endl;
    for (uint64_t i = 0; i < decr_sz - 1; i++)
    {
        std::cout << decrtext[i];
    }
    std::cout << std::endl;

    delete[] encrtext;
    delete[] decrtext;





    // MillerRabin s;
    // std::cout << "RESULT: " << s.isPrime(mpz_class("17"), 0.5) << std::endl;


    // RSA rsa_alg(RSA::MILLER_RABIN, 0.99, 4096);
    // rsa_alg.generateWeakKeys();
    // mpz_class mess("12345678901234567890");
    // mpz_class encr_res = rsa_alg.encrypt(mess);
    // std::cout << "Encrypted: " << encr_res << '\n';
    //
    // mpz_class decr_res = rsa_alg.decrypt(encr_res);
    // std::cout << "Decrypted: " << decr_res << '\n';
    //
    // WienerAttack wa;
    // // auto res = wa.chainFraction(706, 1124);
    // // for (auto i : res)
    // // {
    // //     std::cout << i << '\n';
    // // }
    //
    // auto d = wa.predictKeyPriv(rsa_alg.key_pub.first, rsa_alg.key_pub.second);
    //
    // std::cout << "Predicted d: " << d << '\n';
    // std::cout << "Predicted: " << ServiceGCD::mod_pow(encr_res, d, rsa_alg.key_pub.second) << '\n';
}
