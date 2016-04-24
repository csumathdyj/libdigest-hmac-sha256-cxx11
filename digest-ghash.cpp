#include <cstdint>
#include <array>
#include <string>
#include <algorithm>
#include <utility>
#include "digest.hpp"
#include "digest-ghash.hpp"

namespace digest {

// GF(2**128) pack
template<class ITER>
static void
gfpack (ITER a, std::array<std::uint32_t,4>& b)
{
    for (int i = 0; i < 4; ++i, a += 4) {
        std::uint32_t const a0 = static_cast<std::uint8_t> (a[0]);
        std::uint32_t const a1 = static_cast<std::uint8_t> (a[1]);
        std::uint32_t const a2 = static_cast<std::uint8_t> (a[2]);
        std::uint32_t const a3 = static_cast<std::uint8_t> (a[3]);
        b[i] = (a0 << 24) | (a1 << 16) | (a2 << 8) | a3;
    }
}

// GF(2**128) unpack
template<class ITER>
static void
gfunpack (std::array<std::uint32_t,4> const& a, ITER b)
{
    for (int i = 0; i < 4; ++i, b += 4) {
        b[0] = (a[i] >> 24) & 0xff;
        b[1] = (a[i] >> 16) & 0xff;
        b[2] = (a[i] >>  8) & 0xff;
        b[3] =  a[i]        & 0xff;
    }
}

// C = A + B in GF(2**128)
static void
gfadd (std::array<std::uint32_t,4> const& a,
    std::array<std::uint32_t,4> const& b, std::array<std::uint32_t,4>& c)
{
    c[3] = a[3] ^ b[3];
    c[2] = a[2] ^ b[2];
    c[1] = a[1] ^ b[1];
    c[0] = a[0] ^ b[0];
}

// A = A >> 1 in GF(2**128) polymonial 1+x+x**2+x**7+x**128
static void
gftwice (std::array<std::uint32_t,4>& a)
{
    bool const overflow = (a[3] & 0x01) != 0;
    a[3] = (a[2] << 31) | (a[3] >> 1);
    a[2] = (a[1] << 31) | (a[2] >> 1);
    a[1] = (a[0] << 31) | (a[1] >> 1);
    a[0] = (a[0] >> 1) ^ (overflow ? 0xe1000000 : 0);
}

// C = A * B in GF(2**128), precomputed A[i] = H * i for i in 0 ... 16
static void
gfmul (std::array<std::array<std::uint32_t,4>,16> const& a,
    std::array<std::uint32_t,4> const& b, std::array<std::uint32_t,4>& c)
{
    static const std::uint32_t reduction[16] = {
        0x00000000, 0x1c200000, 0x38400000, 0x24600000,
        0x70800000, 0x6ca00000, 0x48c00000, 0x54e00000,
        0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
        0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000,
    };
    std::array<std::uint32_t,4> v = {{0}};
    for (int k = 3; k >= 0; --k) {
        std::uint32_t w = b[k];
        for (int j = 0; j < 32; j += 4) {
            std::uint32_t overflow = v[3] & 0x0f;
            v[3] = (v[2] << 28) | (v[3] >> 4);
            v[2] = (v[1] << 28) | (v[2] >> 4);
            v[1] = (v[0] << 28) | (v[1] >> 4);
            v[0] = (v[0] >>  4) ^ reduction[overflow];
            v[3] ^= a[w & 0xf][3];
            v[2] ^= a[w & 0xf][2];
            v[1] ^= a[w & 0xf][1];
            v[0] ^= a[w & 0xf][0];
            w >>= 4;
        }
    }
    std::swap (c, v);
}

GHASH::GHASH () : hash_key (), authdata (), sum ()
{
}

GHASH&
GHASH::set_key128 (std::array<std::uint8_t,16> const& key)
{
    static const int revbit[16] {
        0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
    std::array<std::uint32_t,4> h;
    gfpack (key.begin (), h);
    hash_key[0].fill(0);
    hash_key[revbit[1]] = h;
    for (int i = 2; i < 16; i += 2) {
        hash_key[revbit[i]] = hash_key[revbit[i / 2]];
        gftwice (hash_key[revbit[i]]);
        gfadd (h, hash_key[revbit[i]], hash_key[revbit[i + 1]]);
    }
    return *this;
}

GHASH&
GHASH::set_authdata (std::string const& ad)
{
    authdata = ad;
    return *this;
}

std::string
GHASH::digest ()
{
    finish ();
    std::string t (16, 0);
    gfunpack (sum, t.begin ());
    return std::move (t);
}

void
GHASH::init_sum ()
{
    sum.fill (0);
    update_sum_with_data (authdata);
}

void
GHASH::update_sum_with_data (std::string const& data)
{
    int const q = data.size () / 16;
    int const r = data.size () - q * 16;
    std::string::const_iterator s = data.cbegin ();
    for (int i = 0; i < q; ++i, s += 16) {
        update_sum (s);
    }
    if (r > 0) {
        std::string padding (s, data.cend ());
        padding.resize (16, 0);
        update_sum (padding.cbegin ());
    }
}

void
GHASH::update_sum (std::string::const_iterator s)
{
    std::array<std::uint32_t,4> y;
    gfpack (s, y);
    gfadd (y, sum, sum);
    gfmul (hash_key, sum, sum);
}

void
GHASH::last_sum ()
{
    update_sum_with_data (mbuf);
    std::array<std::uint32_t,4> y;
    std::uint64_t const bitlen_authdata = 8LLU * authdata.size ();
    std::uint64_t const bitlen_textdata = 8LLU * mlen;
    y[0] = bitlen_authdata >> 32;
    y[1] = bitlen_authdata & 0xffffffff;
    y[2] = bitlen_textdata >> 32;
    y[3] = bitlen_textdata & 0xffffffff;
    gfadd (y, sum, sum);
    gfmul (hash_key, sum, sum);
}

}//namespace digest
