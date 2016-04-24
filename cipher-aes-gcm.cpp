#include <cstdint>
#include <string>
#include <array>
#include <algorithm>
#include <utility>
#include <stdexcept>
#include "cipher-aes-gcm.hpp"
#include "cipher-aes.hpp"
#include "digest-ghash.hpp"

namespace cipher {

AES_GCM::AES_GCM (void) : ghash (), aes ()
{
    clear ();
}

AES_GCM&
AES_GCM::set_key128 (std::array<std::uint8_t,16> const& key128)
{
    AES::BLOCK zero {{0}};
    AES::BLOCK hash_key;
    aes.set_key128 (key128);
    aes.encrypt (zero, hash_key);
    ghash.set_key128 (hash_key);
    return *this;
}

AES_GCM&
AES_GCM::clear (void)
{
    authdata.clear ();
    nonce.clear ();
    expected_tag.clear ();
    state = INIT;
    pos = 0;
    return *this;
}

AES_GCM&
AES_GCM::add_authdata (std::string const& a)
{
    authdata = a;
    return *this;
}

AES_GCM&
AES_GCM::set_nonce (std::string const& a)
{
    nonce = a;
    return *this;
}

AES_GCM&
AES_GCM::set_authtag (std::string const& a)
{
    expected_tag = a;
    return *this;
}

AES_GCM&
AES_GCM::encrypt (void)
{
    reset_counter ();
    tag.clear ();
    ghash.set_authdata (authdata);
    state = ENCRYPT;
    return *this;
}

std::string
AES_GCM::authtag (void)
{
    if (ENCRYPT == state || DECRYPT == state) {
        tag = ghash.digest ();
        for (int i = 0; i < tag.size (); ++i)
            tag[i] = static_cast<std::uint8_t> (tag[i]) ^ key_stream0[i];
        state = FINAL;
    }
    return tag;
}

AES_GCM&
AES_GCM::decrypt (void)
{
    encrypt ();
    state = DECRYPT;
    return *this;
}

bool
AES_GCM::good (void)
{
    // constant-time comparison while tag == expected_tag
    authtag ();
    bool ok = true;
    for (int i = 0; i < tag.size (); ++i)
        if (i >= expected_tag.size () || tag[i] != expected_tag[i])
            ok = false;
    return ok;
}

std::string
AES_GCM::update (std::string::const_iterator s, std::string::const_iterator e)
{
    if (ENCRYPT != state && DECRYPT != state)
        throw std::runtime_error ("update() decends encrypt() or decrypt().");
    if (s >= e)
        return "";
    std::string dst;
    while (s < e) {
        dst.push_back (static_cast<std::uint8_t> (*s++) ^ key_stream[pos]);
        if (++pos >= key_stream.size ()) {
            increment_counter ();
            pos = 0;
        }
    }
    if (ENCRYPT == state)
        ghash.add (dst.cbegin (), dst.cend ());
    else
        ghash.add (s, e);
    return std::move (dst);
}

std::string
AES_GCM::update (std::string const& src)
{
    return update (src.cbegin (), src.cend ());
}

void
AES_GCM::reset_counter (void)
{
    if (nonce.size () == 12) {
        std::copy (nonce.cbegin (), nonce.cend (), counter.begin ());
        counter[12] = 0;
        counter[13] = 0;
        counter[14] = 0;
        counter[15] = 1;
    }
    else {
        ghash.set_authdata ("");
        std::string h = ghash.add (nonce).digest ();
        std::copy (h.cbegin (), h.cend (), counter.begin ());
    }
    aes.encrypt (counter, key_stream0);
    increment_counter ();
}

void
AES_GCM::increment_counter (void)
{
    // constant-time increment
    AES::BLOCK::value_type carry = 1U;
    for (int i = counter.size () - 1; i >= 0; --i) {
        counter[i] += carry;
        carry = counter[i] < carry ? 1U : 0;
    }
    aes.encrypt (counter, key_stream);
}

}//namespace cipher
