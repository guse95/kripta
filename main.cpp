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


int main()
{
    // uint8_t text[] = "Some text to check DES.\nSome more text.";
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t text[] = "Some text to check if DES works.\nIf you see this, I half won!";
    uint8_t key[8] = {10, 23, 54, 3, 124, 43, 76, 255};
    uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    uint8_t iv2[16] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 'g', 'f', 'e', 'd', 'c', 'b', 'a'};
    uint8_t key2[16] = {'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 'a', 's', 'd', 'f', 'g', 'h'};

    // auto alg = DES();
    // auto alg2 = DEAL(128);
    // const CipherContext Cont(&alg2, key2, Mode::RandomDelta, Padding::ZEROS, 16, iv2, {2});

    // uint8_t text_deal[16] = "Some text to ch";
    // uint8_t encr_text[16] = {0};
    // uint8_t decr_text[16] = {0};
    //
    // alg2->encrypt(text_deal, encr_text, key2);
    //
    // std::cout << "Encrypted text: " << std::endl;
    // for (int i = 0; i < 16; i++)
    // {
    //     std::cout << encr_text[i] << " ";
    // }
    // std::cout << std::endl;
    //
    // alg2->decrypt(encr_text, decr_text, key2);
    //
    // std::cout << "Decrypted text: " << std::endl;
    // for (uint64_t i = 0; i < 16; i++)
    // {
    //     std::cout << decr_text[i];
    //     // printf("%c", decrtext[i]);
    // }
    // std::cout << std::endl;


    // uint64_t encr_sz;
    // uint8_t* encrtext = Cont.encrypt(text, sizeof(text) / sizeof(uint8_t), encr_sz);
    //
    // if (encrtext == nullptr)
    // {
    //     std::cerr << "Encrypt failed" << std::endl;
    // }
    // std::cout << "Encrypted text: " << std::endl;
    // for (int i = 0; i < encr_sz; i++)
    // {
    //     std::cout << encrtext[i] << " ";
    // }
    // std::cout << std::endl;
    //
    // uint64_t decr_sz;
    // uint8_t* decrtext = Cont.decrypt(encrtext, encr_sz, decr_sz);
    //
    // std::cout << "Decrypted text: " << std::endl;
    // for (uint64_t i = 0; i < decr_sz - 1; i++)
    // {
    //     std::cout << decrtext[i];
    // }
    // std::cout << std::endl;
    //
    // delete[] encrtext;
    // delete[] decrtext;

    // MillerRabin s;
    // std::cout << "RESULT: " << s.isPrime(mpz_class("17"), 0.5) << std::endl;


    RSA rsa_alg(RSA::MILLER_RABIN, 0.99, 4096);
    rsa_alg.generateKeys();
    mpz_class mess("12345678901234567890");
    mpz_class encr_res = rsa_alg.encrypt(mess);
    std::cout << "Encrypted: " << encr_res << '\n';

    mpz_class decr_res = rsa_alg.decrypt(encr_res);
    std::cout << "Decrypted: " << decr_res << '\n';

}
