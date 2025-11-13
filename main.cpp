#include <iostream>

#include "CipherContext.h"
#include "DES.h"


int main()
{
    // uint8_t text[] = "Some text to check DES.\nSome more text.";
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t text[] = "Some text to check if DES works.\nIf you see this, I half won!";
    uint8_t key[8] = {10, 23, 54, 3, 124, 43, 76, 255};

    auto alg = new DES();
    CipherContext Cont(alg, key, Mode::ECB, Padding::Zeros, nullptr, {2});

    constexpr uint64_t blocks = ((sizeof(text) + 7) / 8) * 8;

    uint8_t encrtext[blocks] = {0};

    Cont.encrypt(text, sizeof(text) / sizeof(uint8_t), encrtext);

    std::cout << "Encrypted text: " << std::endl;
    for (const unsigned char i : encrtext)
    {
        std::cout << i << " ";
    }
    std::cout << std::endl;

    uint8_t decrtext[blocks] = {0};
    Cont.decrypt(encrtext, blocks, decrtext);

    std::cout << "Decrypted text: " << std::endl;
    for (uint64_t i = 0; i < sizeof(text) - 1; i++)
    {
        std::cout << decrtext[i];
        // printf("%c", decrtext[i]);
    }
    std::cout << std::endl;
}
