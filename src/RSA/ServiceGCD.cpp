#include "ServiceGCD.h"


BigInt ServiceGCD::gcd(BigInt x, BigInt y)
{
    while (x != BigInt(0))
    {
        if (x <= y)
        {
            y = y % x;
        }
        std::swap(x ,y);
    }
    return y;
}

BigInt ServiceGCD::exp_gcd(BigInt a, BigInt b, BigInt &x, BigInt &y)
{
    if (a == BigInt(0))
    {
        x = BigInt(0);
        y = BigInt(1);
        return b;
    }
    BigInt x1, y1;
    BigInt g = exp_gcd(b % a, a, x1, y1);
    x = y1 - (b % a) * x1;
    y = x1;
    return g;
}

BigInt ServiceGCD::mod_pow(BigInt a, BigInt pow, const BigInt mod)
{
    return a.mod_exp(pow, mod);
}

BigInt ServiceGCD::Legendre(BigInt a, BigInt p)
{
    if (a % p == BigInt(0))
    {
        return BigInt(0);
    }
    if (mod_pow(a, (p - BigInt(1)) / BigInt(2), p) == BigInt(1))
    {
        return BigInt(1);
    }
    return BigInt(-1);
}

BigInt sign_Jacobi(BigInt p)
{
    BigInt tmp = p % BigInt(8);
    if (tmp == BigInt(1) || tmp == BigInt(7))
        return BigInt(1);
    return BigInt(-1);
}

BigInt ServiceGCD::Jacobi(BigInt a, BigInt p)
{
    auto res = BigInt(1);
    a %= p;
    if (a == BigInt(1) || a == BigInt(0))
    {
        return a;
    }
    if (a % BigInt(2) == BigInt(1))
    {
        while (a % BigInt(2) == BigInt(0))
        {
            res *= sign_Jacobi(p);
            a /= BigInt(2);
        }
        return res * Jacobi(a, p);
    }
    res *= Jacobi(p, a) * BigInt(((a - BigInt(1)) % BigInt(4) == BigInt(0)
        || (p - BigInt(1)) % BigInt(4) == BigInt(0)) ? 1 : -1);
    return res;
}
