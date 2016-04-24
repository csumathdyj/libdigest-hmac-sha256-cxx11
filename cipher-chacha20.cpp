#include <array>
#include <cstdint>
#include <string>
#include <algorithm>
#include <utility>
#include <stdexcept>
#include "cipher-chacha20.hpp"
#include "digest-poly1305.hpp"

namespace cipher {

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
pack32 (std::uint32_t const x, std::array<std::uint8_t,64>::iterator const s)
{
    s[0] = x & 0xff;
    s[1] = (x >> 8) & 0xff;
    s[2] = (x >> 16) & 0xff;
    s[3] = (x >> 24) & 0xff;
}

static inline void
qround (std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d)
{
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d <<  8) | (d >> 24);
    c += d; b ^= c; b = (b <<  7) | (b >> 25);
}

void
CHACHA20::chacha20_block (std::uint32_t count, std::array<std::uint8_t,64>& block)
{
    std::array<std::uint32_t,16> state {{
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0],     key[1],     key[2],     key[3],
        key[4],     key[5],     key[6],     key[7],
        count,      nonce[0],   nonce[1],   nonce[2],
    }};
    std::array<std::uint32_t,16> w = state;
    for (int i = 0; i < 10; ++i) {
        qround (w[0], w[4],  w[8], w[12]);
        qround (w[1], w[5],  w[9], w[13]);
        qround (w[2], w[6], w[10], w[14]);
        qround (w[3], w[7], w[11], w[15]);
        qround (w[0], w[5], w[10], w[15]);
        qround (w[1], w[6], w[11], w[12]);
        qround (w[2], w[7],  w[8], w[13]);
        qround (w[3], w[4],  w[9], w[14]);
    }
    for (int i = 0; i < 16; ++i)
        w[i] += state[i];
    std::array<std::uint8_t,64>::iterator b = block.begin ();
    for (int i = 0; i < 16; ++i, b += 4)
        pack32 (w[i], b);
}

CHACHA20::CHACHA20 (void) : poly1305 ()
{
    clear ();
}

CHACHA20&
CHACHA20::set_key256 (std::array<std::uint8_t,32> const& a)
{
    std::array<std::uint8_t,32>::const_iterator s = a.cbegin ();
    for (int i = 0; i < 8; ++i, s += 4) {
        key[i] = unpack32 (s);
    }
    return *this;
}

CHACHA20&
CHACHA20::clear (void)
{
    authdata.clear ();
    nonce.fill (0);
    iv = 1U;
    expected_tag.clear ();
    tag.clear ();
    state = INIT;
    pos = 0;
    return *this;
}

CHACHA20&
CHACHA20::set_counter (std::uint32_t const x)
{
    iv = x;
    return *this;
}

CHACHA20&
CHACHA20::add_authdata (std::string const& a)
{
    authdata = a;
    return *this;
}

CHACHA20&
CHACHA20::set_nonce (std::string const& a)
{
    if (a.size () != 12U)
        throw std::runtime_error ("chacha20 nonce size must be 12.");
    std::string::const_iterator s = a.cbegin ();
    for (int i = 0; i < 3; ++i, s += 4) {
        nonce[i] = unpack32 (s);
    }
    return *this;
}

CHACHA20&
CHACHA20::set_authtag (std::string const& a)
{
    expected_tag = a;
    return *this;
}

void
CHACHA20::poly1305_key_gen (std::array<std::uint8_t,32>& one_time_key)
{
    std::array<std::uint8_t,64> block;
    chacha20_block (0, block);
    std::copy (block.cbegin (), block.cbegin () + 32, one_time_key.begin ());
}

CHACHA20&
CHACHA20::encrypt (void)
{
    std::array<std::uint8_t,32> one_time_key;
    poly1305_key_gen (one_time_key);
    poly1305.set_key256 (one_time_key);
    poly1305.set_authdata (authdata);
    poly1305.set_aead_construction (true);
    counter = iv;
    chacha20_block (counter, key_stream);
    state = ENCRYPT;
    pos = 0;
    return *this;
}

CHACHA20&
CHACHA20::decrypt (void)
{
    encrypt ();
    state = DECRYPT;
    return *this;
}

std::string
CHACHA20::update (std::string::const_iterator s, std::string::const_iterator e)
{
    if (ENCRYPT != state && DECRYPT != state)
        throw std::runtime_error ("update() decends encrypt() or decrypt().");
    if (s >= e)
        return "";
    if (DECRYPT == state)
        poly1305.add (s, e);
    std::string dst;
    while (s < e) {
        dst.push_back (static_cast<std::uint8_t> (*s++) ^ key_stream[pos]);
        if (++pos >= key_stream.size ()) {
            if (++counter == iv)
                throw std::runtime_error ("chacha20 counter overflow");
            chacha20_block (counter, key_stream);
            pos = 0;
        }
    }
    if (ENCRYPT == state)
        poly1305.add (dst);
    return std::move (dst);    
}

std::string
CHACHA20::update (std::string const& data)
{
    return update (data.cbegin (), data.cend ());
}

std::string
CHACHA20::authtag (void)
{
    if (ENCRYPT == state || DECRYPT == state) {
        tag = poly1305.digest ();
        state = FINAL;
    }
    return tag;
}

bool
CHACHA20::good (void)
{
    // constant-time comparison while tag == expected_tag
    authtag ();
    bool ok = true;
    for (int i = 0; i < tag.size (); ++i) {
        volatile bool const prev_ok = ok;
        volatile bool const not_ok = false;
        int const expected_c = i >= expected_tag.size () ? 0 : expected_tag[i];
        ok = tag[i] == expected_c ? prev_ok : not_ok;
    }
    return ok;
}

}//namespace cipher
