#ifndef MILLERRABIN_H
#define MILLERRABIN_H
#include "PrimeTestBase.h"


class MillerRabin : public PrimeTestBase {
public:
    ~MillerRabin() final = default;

    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const mpz_class& a, const mpz_class& n) const final;
};


#endif
