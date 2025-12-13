#ifndef MILLERRABIN_H
#define MILLERRABIN_H
#include "PrimeTestBase.h"


class MillerRabin : public PrimeTestBase {
public:
    ~MillerRabin() final = default;

    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const BigInt& a, const BigInt& n) const final;
};


#endif
