#include "Ferma.h"
#include "ServiceGCD.h"

[[nodiscard]] double Ferma::getProbForOneIter() const
{
    return 0.5;
}

[[nodiscard]] bool Ferma::testIteration(const BigInt& a, const BigInt& n) const
{
    return (ServiceGCD::mod_pow(a, n - BigInt(1), n) == BigInt(1));
}
