#include <iostream>

#include "CipherContext.h"
#include "DES.h"
#include "DEAL.h"


int main()
{
    // uint8_t key[8] = {0, 124, 2, 0, 12, 0, 0, 132};
    uint8_t key[8] = {10, 23, 54, 3, 124, 43, 76, 255};
    uint8_t key2[16] = {10, 23, 54, 3, 124, 43, 76, 255, 10, 23, 54, 3, 124, 43, 76, 255};
    uint8_t iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    auto alg = new DES();
    auto alg2 = new DEAL(128);

    CipherContext Cont(alg2, key2, Mode::ECB, Padding::ZEROS, 16, iv, {8});

    // Cont.encrypt("vid.mp4", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.mp4");
    //
    // Cont.encrypt("img.png", "encrypted.txt");
    // Cont.decrypt("encrypted.txt", "decrypted.png");
    //
    Cont.encrypt("text.txt", "encrypted.txt");
    Cont.decrypt("encrypted.txt", "decrypted.txt");

    delete alg;
    delete alg2;
}
