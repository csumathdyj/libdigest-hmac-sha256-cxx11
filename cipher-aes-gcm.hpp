#pragma once

#include <cstdint>
#include <list>
#include <string>
#include <array>
#include "digest-ghash.hpp"
#include "cipher-aes.hpp"

namespace cipher {

class AES_GCM {
public:
    explicit AES_GCM (void);
    AES_GCM& set_key128 (std::array<std::uint8_t,16> const& key128);
    AES_GCM& set_key192 (std::array<std::uint8_t,24> const& key192);
    AES_GCM& set_key256 (std::array<std::uint8_t,32> const& key256);
    AES_GCM& clear (void);
    AES_GCM& add_authdata (std::string const& a);
    AES_GCM& set_nonce (std::string const& a);
    AES_GCM& set_authtag (std::string const& a);

    AES_GCM& encrypt (void);
    std::string authtag (void);

    AES_GCM& decrypt (void);
    bool good (void);

    std::string update (std::string::const_iterator s, std::string::const_iterator e);
    std::string update (std::string const& src);

private:
    enum { INIT, DECRYPT, ENCRYPT, FINAL };
    digest::GHASH ghash;
    cipher::AES aes;
    std::string authdata;
    std::string nonce;
    std::string expected_tag;
    std::string tag;
    AES::BLOCK counter;
    AES::BLOCK key_stream0;
    AES::BLOCK key_stream;
    int state;
    int pos;

    void set_ghash_key (void);
    void reset_counter (void);
    void increment_counter (void);
};

}//namespace cipher
