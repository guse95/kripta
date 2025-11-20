#include <iostream>

#include "CipherContext.h"
#include "DES.h"


int main()
{
    // uint8_t text[] = "Some text to check DES.\nSome more text.";
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t text[] = "Some text to check if DES works.\nIf you see this, I half won!";
    uint8_t key[8] = {10, 23, 54, 3, 124, 43, 76, 255};
    uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    auto alg = new DES();
    CipherContext Cont(alg, key, Mode::OFB, Padding::ZEROS, iv, {2});

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
        // printf("%c", decrtext[i]);
    }
    std::cout << std::endl;

    delete[] encrtext;
    delete[] decrtext;
}
