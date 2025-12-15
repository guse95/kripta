#include "SoloveiStrassen.h"
#include "ServiceGCD.h"

[[nodiscard]] double SoloveiStrassen::getProbForOneIter() const
{
    return 0.5;
}

[[nodiscard]] bool SoloveiStrassen::testIteration(const mpz_class& a, const mpz_class& n) const
{
    mpz_class Jacobi_val = ServiceGCD::Jacobi(a, n);
    if (Jacobi_val == -1)
    {
        Jacobi_val += n;
    }
    return (ServiceGCD::mod_pow(a, (n - mpz_class(1)) / mpz_class(2), n) == Jacobi_val);
}