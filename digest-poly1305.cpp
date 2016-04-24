#include <cstdint>
#include <array>
#include <string>
#include <utility>
#include <algorithm>
#include "digest.hpp"
#include "digest-poly1305.hpp"

namespace digest {

// poly1305 sum[i+1] == (sum[i] + (message_block|[0x01])) * r mod prime
// prime == 130**2 - 5
//
// sum == a[0] + a[1] * B + a[2] * B**2 + a[3] * B**3 + a[4] * B**4
// B == 2**26

static const std::uint32_t MASK26 = (1U << 26) - 1U;

static inline std::uint32_t
ord (char const c)
{
    return static_cast<std::uint8_t> (c);
}

template<class ITER>
static inline std::uint32_t
unpack32 (ITER const s)
{
    return ord (s[0])
        | (ord (s[1]) << 8)
        | (ord (s[2]) << 16)
        | (ord (s[3]) << 24);
}

static inline void
pack32 (std::uint32_t const x, std::string::iterator const s)
{
    s[0] = x & 0xff;
    s[1] = (x >> 8) & 0xff;
    s[2] = (x >> 16) & 0xff;
    s[3] = (x >> 24) & 0xff;
}

static inline void
pack64 (std::uint64_t const x, std::string::iterator const s)
{
    s[0] = x & 0xff;
    s[1] = (x >> 8) & 0xff;
    s[2] = (x >> 16) & 0xff;
    s[3] = (x >> 24) & 0xff;
    s[4] = (x >> 32) & 0xff;
    s[5] = (x >> 40) & 0xff;
    s[6] = (x >> 48) & 0xff;
    s[7] = (x >> 56) & 0xff;
}

static inline void
add128 (std::uint32_t const n0, std::uint32_t const n1,
    std::uint32_t const n2, std::uint32_t const n3,
    std::array<std::uint32_t,5>& a)
{
    a[0] += n0 & MASK26;
    a[1] += ((n1 << 6) | (n0 >> 26)) & MASK26;
    a[2] += ((n2 << 12) | (n1 >> 20)) & MASK26;
    a[3] += ((n3 << 18) | (n2 >> 14)) & MASK26;
    a[4] += n3 >> 8;
}

static inline void
pack128 (std::array<std::uint32_t,5> const& a, std::string::iterator t)
{
    std::array<std::uint32_t,5> b;
    for (int i = 0; i < 5; ++i)
        b[i] = a[i] & MASK26;
    pack32 ((b[1] << 26) | b[0], t);
    pack32 ((b[2] << 20) | (b[1] >> 6), t + 4);
    pack32 ((b[3] << 14) | (b[2] >> 12), t + 8);
    pack32 ((b[4] << 8) | (b[3] >> 18), t + 12);
}

static inline std::uint32_t
full_carry (std::array<std::uint32_t,5>& a)
{
    std::uint32_t carry = 0;
    for (int i = 0; i < 5; ++i) {
        std::uint32_t const x = a[i] + carry;
        carry = x >> 26;
        a[i] = x & MASK26;
    }
    return carry;
}

static inline std::uint64_t
full_carry (std::array<std::uint64_t,5> const& c, std::array<std::uint32_t,5>& a)
{
    std::uint64_t carry = 0;
    for (int i = 0; i < 5; ++i) {
        std::uint64_t const x = c[i] + carry;
        carry = x >> 26;
        a[i] = static_cast<std::uint32_t> (x) & MASK26;
    }
    return carry;
}

static inline std::uint64_t
mul64 (std::uint32_t const a, std::uint32_t const b)
{
    return static_cast<std::uint64_t> (a) * b;
}

static inline void
mul_mod (std::array<std::uint32_t,5> const& r,
    std::array<std::uint32_t,5> const& f, std::array<std::uint32_t,5>& a, 
    std::array<std::uint64_t,5>& c)
{
    c[0] = mul64 (a[0], r[0]) + mul64 (a[4], f[1]) + mul64 (a[3], f[2])
         + mul64 (a[2], f[3]) + mul64 (a[1], f[4]);
    c[1] = mul64 (a[1], r[0]) + mul64 (a[0], r[1]) + mul64 (a[4], f[2])
         + mul64 (a[3], f[3]) + mul64 (a[2], f[4]);
    c[2] = mul64 (a[2], r[0]) + mul64 (a[1], r[1]) + mul64 (a[0], r[2])
         + mul64 (a[4], f[3]) + mul64 (a[3], f[4]);
    c[3] = mul64 (a[3], r[0]) + mul64 (a[2], r[1]) + mul64 (a[1], r[2])
         + mul64 (a[0], r[3]) + mul64 (a[4], f[4]);
    c[4] = mul64 (a[4], r[0]) + mul64 (a[3], r[1]) + mul64 (a[2], r[2])
         + mul64 (a[1], r[3]) + mul64 (a[0], r[4]);

    std::uint64_t overflow = full_carry (c, a) * 5 + a[0];
    a[1] += overflow >> 26;
    a[0] = static_cast<std::uint32_t> (overflow) & MASK26;
}

static inline void
complete_mul_mod (std::array<std::uint32_t,5>& a)
{
    // full carry from a[1] (may be 27 bit)
    std::uint32_t const overflow = full_carry (a);
    a[0] += overflow * 5;
    full_carry (a);

    // if (a >= prime) a -= prime
    std::array<std::uint32_t,5> w {{a[0] + 5, a[1], a[2], a[3], a[4]}};
    if (full_carry (w) > 0) {
        std::swap (a, w);
    }
}

POLY1305::POLY1305 (void)
{
    authdata.clear ();
    aead_construction = false;
}

POLY1305&
POLY1305::set_key256 (std::array<std::uint8_t,32> const& key)
{
    std::array<std::uint8_t,32>::const_iterator const r = key.cbegin ();
    std::array<std::uint8_t,32>::const_iterator const s = key.cbegin () + 16U;
    sum.fill (0);
    add128 (unpack32 (r), unpack32 (r + 4), unpack32 (r + 8), unpack32 (r + 12), sum);
    scale[0] = sum[0] & 0x03ffffffUL;
    scale[1] = sum[1] & 0x03ffff03UL;
    scale[2] = sum[2] & 0x03ffc0ffUL;
    scale[3] = sum[3] & 0x03f03fffUL;
    scale[4] = sum[4] & 0x000fffffUL;
    scale5[0] = scale[0] * 5UL;
    scale5[1] = scale[1] * 5UL;
    scale5[2] = scale[2] * 5UL;
    scale5[3] = scale[3] * 5UL;
    scale5[4] = scale[4] * 5UL;
    std::copy (s, s + 16U, termination.begin ());
    return *this;
}

POLY1305&
POLY1305::set_authdata (std::string const& a)
{
    authdata = a;
    return *this;
}

POLY1305&
POLY1305::set_aead_construction (bool const a)
{
    aead_construction = a;
    return *this;
}

void
POLY1305::init_sum ()
{
    sum.fill (0);
    if (aead_construction && ! authdata.empty ())
        update_sum_with_data (authdata);
}

void
POLY1305::update_sum_with_data (std::string const& data)
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
POLY1305::update_sum (std::string::const_iterator s)
{
    add128 (unpack32 (s), unpack32 (s + 4), unpack32 (s + 8), unpack32 (s + 12), sum);
    sum[4] += 1U << 24;
    mul_mod (scale, scale5, sum, poly);
}

void
POLY1305::last_sum ()
{
    if (mbuf.size () == blocksize () || aead_construction) {
        update_sum_with_data (mbuf);
    }
    else if (! mbuf.empty ()) {
        mbuf.push_back (0x01);
        mbuf.resize (16, 0);
        std::string::const_iterator const p = mbuf.cbegin ();
        add128 (unpack32 (p), unpack32 (p + 4), unpack32 (p + 8), unpack32 (p + 12), sum);
        mul_mod (scale, scale5, sum, poly);
    }
    if (aead_construction) {
        std::string blk (16, 0);
        pack64 (authdata.size (), blk.begin ());
        pack64 (mlen, blk.begin () + 8);
        update_sum (blk.cbegin ());
    }
    complete_mul_mod (sum);
    std::array<std::uint8_t,16>::const_iterator const s = termination.cbegin ();
    add128 (unpack32 (s), unpack32 (s + 4), unpack32 (s + 8), unpack32 (s + 12), sum);
    full_carry (sum);
}

std::string
POLY1305::digest ()
{
    finish ();
    std::string mac (16, 0);
    pack128 (sum, mac.begin ());
    return std::move (mac);
}

}//namespace digest
