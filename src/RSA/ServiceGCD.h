#ifndef SERVICEGCD_H
#define SERVICEGCD_H

#include <cstdint>
#include <iostream>

#include "my_BigInt.h"

class ServiceGCD {

public:
    ServiceGCD() = default;
    ~ServiceGCD() = default;

    static BigInt gcd(BigInt x, BigInt y);

    static BigInt exp_gcd(BigInt a, BigInt b, BigInt &x, BigInt &y);

    static BigInt mod_pow(BigInt a, BigInt pow, BigInt mod);

    static BigInt Legendre(BigInt a, BigInt p);

    static BigInt Jacobi(BigInt a, BigInt p);
};



#endif
