#include "SoloveiStrassen.h"
#include "ServiceGCD.h"

[[nodiscard]] double SoloveiStrassen::getProbForOneIter() const
{
    return 0.5;
}

[[nodiscard]] bool SoloveiStrassen::testIteration(const BigInt& a, const BigInt& n) const
{
    BigInt Jacobi_val = ServiceGCD::Jacobi(a, n);
    if (Jacobi_val == BigInt(-1))
    {
        Jacobi_val += n;
    }
    return (ServiceGCD::mod_pow(a, (n - BigInt(1)) / BigInt(2), n) == Jacobi_val);
}