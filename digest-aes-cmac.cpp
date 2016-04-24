#include <cstdint>
#include <array>
#include <string>
#include <algorithm>
#include <utility>
#include "digest.hpp"
#include "cipher-aes.hpp"
#include "digest-aes-cmac.hpp"

namespace digest {

// JH. Song, R. Poovendran, J. Lee, T. Iwata, "RFC 4493 The AES-CMAC Algorithm" (2006)
// https://tools.ietf.org/html/rfc4493

using BLOCK = typename cipher::AES::BLOCK;

AES_CMAC::AES_CMAC () : base (), cipher (), sum ()
{
}

AES_CMAC&
AES_CMAC::set_key128 (std::array<std::uint8_t,16> const& key)
{
    cipher.set_key128 (key);
    return *this;
}

AES_CMAC&
AES_CMAC::set_key192 (std::array<std::uint8_t,24> const& key)
{
    cipher.set_key192 (key);
    return *this;
}

AES_CMAC&
AES_CMAC::set_key256 (std::array<std::uint8_t,32> const& key)
{
    cipher.set_key256 (key);
    return *this;
}

std::string
AES_CMAC::digest ()
{
    finish ();
    return std::string (sum.begin (), sum.end ());
}

void
AES_CMAC::init_sum ()
{
    sum.fill (0);
}

void
AES_CMAC::update_sum (std::string::const_iterator s)
{
    BLOCK w;
    for (int i = 0; i < 16; ++i) {
        std::uint8_t const x = static_cast<std::uint8_t> (*s++);
        w[i] = sum[i] ^ x;
    }
    cipher.encrypt (w, sum);
}

void
AES_CMAC::last_sum ()
{
    
    BLOCK const zero {{0}};
    BLOCK el;
    cipher.encrypt (zero, el);
    BLOCK key1 = generate_key (el);
    BLOCK key2 = generate_key (key1);
    if (mbuf.size () == 16U) {
        BLOCK w;
        for (int i = 0; i < 16; ++i) {
            std::uint8_t const x = static_cast<std::uint8_t> (mbuf[i]);
            w[i] = sum[i] ^ key1[i] ^ x;
        }
        cipher.encrypt (w, sum);
    }
    else {
        BLOCK w;
        mbuf.push_back (0x80);
        mbuf.resize (16, 0);
        for (int i = 0; i < 16; ++i) {
            std::uint8_t const x = static_cast<std::uint8_t> (mbuf[i]);
            w[i] = sum[i] ^ key2[i] ^ x;
        }
        cipher.encrypt (w, sum);
    }
}

BLOCK
AES_CMAC::generate_key (BLOCK const& el)
{
    static const std::uint8_t Rb = 0x87;
    BLOCK key;
    bool const lsb = (el[0] & 0x80) != 0;
    for (int i = 0; i < 15; ++i) {
        key[i] = (el[i] << 1) | (el[i + 1] >> 7);
    }
    key[15] = (el[15] << 1) ^ (lsb ? Rb : 0);
    return std::move (key);
}

}//namespace digest
