#include "MillerRabin.h"

#include "ServiceGCD.h"

[[nodiscard]] double MillerRabin::getProbForOneIter() const
{
    return 0.25;
}

[[nodiscard]] bool MillerRabin::testIteration(const BigInt& a, const BigInt& n) const
{
    BigInt pow = n - BigInt(1);
    BigInt s(0);
    const BigInt n_uno(n - BigInt(1));
    while (pow % BigInt(2) == BigInt(0))
    {
        pow /= BigInt(2);
        ++s;
    }
    BigInt x = ServiceGCD::mod_pow(a, pow, n);

    if (x == BigInt(1) || x == n_uno)
    {
        return true;
    }
    for (BigInt i(0); i < s; ++i)
    {
        x = x * x % n;
        if (x == n_uno)
        {
            return true;
        }
    }
    return false;
}