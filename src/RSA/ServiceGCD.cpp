#include "ServiceGCD.h"


ll ServiceGCD::gcd(ll x, ll y)
{
    while (x)
    {
        if (x <= y)
        {
            y = y % x;
        }
        std::swap(x ,y);
    }
    return y;
}

ll ServiceGCD::exp_gcd(ll a, ll b, ll &x, ll &y)
{
    if (a == 0)
    {
        x = 0;
        y = 1;
        return b;
    }
    ll x1, y1;
    ll g = exp_gcd(b % a, a, x1, y1);
    x = y1 - (b % a) * x1;
    y = x1;
    return g;
}

ll ServiceGCD::mod_pow(ll a, ll pow, const ll mod)
{
    if (a == 1 || a == 0)
    {
        return a;
    }
    ll res = 1;
    a %= mod;
    while (pow) {
        if (pow % 2 == 1)
        {
            res *= a;
            res %= mod;
            pow--;
        } else
        {
            res *= res;
            res %= mod;
            pow /= 2;
        }
    }
    return res;
}

ll ServiceGCD::Legendre(ll a, ll p)
{
    if (a % p == 0)
    {
        return 0;
    }
    if (mod_pow(a, (p - 1) / 2, p) == 1)
    {
        return 1;
    }
    return -1;
}

ll sign_Jacobi(ll p)
{
    ll tmp = p % 8;
    if (tmp == 1 || tmp == 7)
        return 1;
    return -1;
}

ll ServiceGCD::Jacobi(ll a, ll p)
{
    ll res = 1;
    a %= p;
    if (a == 1 || a == 0)
    {
        return a;
    }
    if (a % 2 == 0)
    {
        ll tmp = a & (-a);
        if (tmp % 2 == 0)
        {
            res *= sign_Jacobi(p);
            a <<= tmp;
        }
    }
    res *= Jacobi(p, a) * (((a - 1) / 2 % 2 == 0 || (p - 1) / 2 % 2 == 0) ? 1 : -1);
    return res;
}
