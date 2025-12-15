#include "Ferma.h"
#include "ServiceGCD.h"

[[nodiscard]] double Ferma::getProbForOneIter() const
{
    return 0.5;
}

[[nodiscard]] bool Ferma::testIteration(const mpz_class& a, const mpz_class& n) const
{
    return (ServiceGCD::mod_pow(a, n - mpz_class(1), n) == mpz_class(1));
}
