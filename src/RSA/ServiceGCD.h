#ifndef SERVICEGCD_H
#define SERVICEGCD_H

#include <cstdint>
#include <iostream>
#include <gmpxx.h>

class ServiceGCD {

public:
    ServiceGCD() = default;
    ~ServiceGCD() = default;

    static mpz_class gcd(mpz_class x, mpz_class y);

    static mpz_class exp_gcd(mpz_class a, mpz_class b, mpz_class &x, mpz_class &y);

    static mpz_class mod_pow(const mpz_class& a, const mpz_class& pow, const mpz_class& mod);

    static mpz_class Legendre(mpz_class a, mpz_class p);

    static mpz_class Jacobi(mpz_class a, mpz_class p);
};



#endif
