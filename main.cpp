#include <iostream>

#include "CipherContext.h"
#include "DES.h"


int main()
{
    uint8_t text[] = "Some text to check DES.\nSome more text.";
    uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};

    auto alg = new DES();
    CipherContext Cont(alg, key, Mode::ECB, Padding::Zeros);

    const uint64_t blocks = (sizeof(text) + sizeof(uint8_t) - 1) / sizeof(uint8_t);

    uint8_t encrtext[blocks];

    Cont.encrypt(text, sizeof(text) / sizeof(uint8_t), encrtext);

    std::cout << "Encrypted text: " << std::endl;
    for (uint64_t i = 0; i < blocks; i++)
    {
        std::cout << encrtext[i] << " ";
    }
    std::cout << std::endl;

    uint8_t decrtext[blocks];
    Cont.decrypt(encrtext, blocks, decrtext);

    std::cout << "Decrypted text: " << std::endl;
    for (uint64_t i = 0; i < blocks; i++)
    {
        std::cout << decrtext[i] << " ";
    }
    std::cout << std::endl;
}
