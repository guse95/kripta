#include "ServiceGCD.h"


mpz_class ServiceGCD::gcd(mpz_class x, mpz_class y)
{
    while (x != 0)
    {
        if (x <= y)
        {
            y = y % x;
        }
        std::swap(x ,y);
    }
    return y;
}

mpz_class ServiceGCD::exp_gcd(mpz_class a, mpz_class b, mpz_class &x, mpz_class &y)
{
    if (a == 0)
    {
        x = 0;
        y = 1;
        return b;
    }
    mpz_class x1, y1;
    mpz_class g = exp_gcd(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

mpz_class ServiceGCD::mod_pow(const mpz_class& a, const mpz_class& pow, const mpz_class& mod)
{
    if (pow < 2) {
        if (pow == 1) {
            return a % mod;
        }
        return 1;
    }
    mpz_class res = mod_pow(a, pow/2, mod);
    res = (res * res) % mod;
    if (pow % 2 == 1) {
        res = (res * a) % mod;
    }
    return res;
}

mpz_class ServiceGCD::Legendre(mpz_class a, mpz_class p)
{
    if (a % p == 0)
    {
        return 0;
    }
    if (mod_pow(a, (p - 1) / 2, p) == 1)
    {
        return 1;
    }
    return -1;
}

mpz_class sign_Jacobi(mpz_class p)
{
    mpz_class tmp = p % 8;
    if (tmp == 1 || tmp == 7)
        return 1;
    return -1;
}

mpz_class ServiceGCD::Jacobi(mpz_class a, mpz_class p)
{
    mpz_class res = 1;
    a %= p;
    if (a == 1 || a == 0)
    {
        return a;
    }
    if (a % 2 == 0)
    {
        while (a % 2 == 0)
        {
            res *= sign_Jacobi(p);
            a /= 2;
        }
        return res * Jacobi(a, p);
    }
    res *= Jacobi(p, a) * (((a - 1) % 4 == 0
        || (p - 1) % 4 == 0) ? 1 : -1);
    return res;
}
