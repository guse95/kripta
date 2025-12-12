#ifndef FERMA_H
#define FERMA_H
#include "PrimeTestBase.h"
#include "my_BigInt.h"

class Ferma : public PrimeTestBase {
    public:
    ~Ferma() final = default;

    [[nodiscard]] double getProbForOneIter() const final;

    [[nodiscard]] bool testIteration(const BigInt& a, const BigInt& n) const final;
};



#endif
