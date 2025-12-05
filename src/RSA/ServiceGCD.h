#ifndef SERVICEGCD_H
#define SERVICEGCD_H

#include <cstdint>
#include <iostream>

using ll = long long;

class ServiceGCD {

public:
    ServiceGCD() = default;
    ~ServiceGCD() = default;

    static ll gcd(ll x, ll y);

    static ll exp_gcd(ll a, ll b, ll &x, ll &y);

    static ll mod_pow(ll a, ll pow, ll mod);

    static ll Legendre(ll a, ll p);

    static ll Jacobi(ll a, ll p);
};



#endif
