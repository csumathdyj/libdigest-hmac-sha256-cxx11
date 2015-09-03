#include <iostream>
#include <algorithm>
#include <string>
#include <cctype>
#include <random>
#include "pbkdf2-sha256.hpp"
#include "digest.hpp"
#include "mime-base64.hpp"

namespace pbkdf2_sha256 {

static const std::string IDENT = "$pbkdf2-sha256$";
static const std::size_t ROUNDS_DEFAULT = 6400U;
static const std::size_t SALT_SIZE_DEFAULT = 16U;
static const std::size_t KEYLEN_DEFAULT = 32U;

std::string
encrypt (std::string const& password)
{
    return encrypt (password, ROUNDS_DEFAULT, SALT_SIZE_DEFAULT);
}

std::string
encrypt (std::string const& password, std::size_t const rounds)
{
    return encrypt (password, rounds, SALT_SIZE_DEFAULT);
}

std::string
encrypt (std::string const& password, std::string const& salt)
{
    return encrypt (password, ROUNDS_DEFAULT, salt);
}

std::string
encrypt (std::string const& password, std::size_t const rounds, std::size_t const salt_size)
{
    std::string salt;
    std::random_device randev;
    std::mt19937 gen (randev ());
    std::uniform_int_distribution<uint8_t> dist (0, 255);
    for (std::size_t i = 0; i < salt_size; ++i)
        salt.push_back (dist (gen));
    return encrypt (password, rounds, salt);
}

std::string
encrypt (std::string const& password, std::size_t const rounds, std::string const& salt)
{
    std::string dk;
    pbkdf2_sha256 (password, salt, rounds, KEYLEN_DEFAULT, dk);
    return IDENT + std::to_string (rounds)
           + "$" + mime::encode_base64crypt (salt)
           + "$" + mime::encode_base64crypt (dk);
}

bool
verify (std::string const& password, std::string const& pubkey)
{
    if (pubkey.compare (0, IDENT.size (), IDENT) != 0)
        return false;
    auto s = pubkey.cbegin () + IDENT.size ();
    auto const e = pubkey.cend ();
    std::size_t rounds = 0;
    if (s >= e || ! std::isdigit (*s))
        return false;
    while (s < e && std::isdigit (*s))
        rounds = rounds * 10 + *s++ - '0';
    if (s >= e || '$' != *s)
        return false;
    auto const s1 = ++s;
    s = std::find (s, e, '$');
    std::string salt64 (s1, s);
    std::string salt;
    mime::decode_base64crypt (salt64, salt);
    return pubkey == encrypt (password, rounds, salt);
}

// Password-Based Key Derivation Function 2 (PBKDF2)
// see RFC 2898 PKCS#5 version 2.0
void
pbkdf2_sha256 (std::string const& secret, std::string const& salt, std::size_t const rounds, std::size_t keylen, std::string& dkout)
{
    digest::HMAC<digest::SHA256> prf (secret);
    std::string dk;
    uint32_t i = 0;
    while (keylen > 0) {
        ++i;
        std::string block_number;
        block_number.push_back ((i >> 24) & 0xff);
        block_number.push_back ((i >> 16) & 0xff);
        block_number.push_back ((i >>  8) & 0xff);
        block_number.push_back (i & 0xff);
        std::string u = prf.add (salt).add (block_number).digest ();
        std::string t = u;
        for (std::size_t j = 1; j < rounds; ++j) {
            u = prf.add (u).digest ();
            for (std::size_t k = 0; k < u.size (); ++k)
                t[k] ^= u[k];
        }
        std::size_t n = std::min (keylen, t.size ());
        dk.append (t.begin (), t.begin () + n);
        keylen -= n;
    }
    std::swap (dkout, dk);
}

}//namespace pbkdf2_sha256
