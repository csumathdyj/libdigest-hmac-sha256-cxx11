#pragma once

#include <cstdint>
#include <string>
#include <array>
#include "digest-poly1305.hpp"

namespace cipher {

class CHACHA20 {
public:
    explicit CHACHA20 (void);
    CHACHA20& set_key256 (std::array<std::uint8_t,32> const& a);
    CHACHA20& clear (void);
    CHACHA20& add_authdata (std::string const& a);
    CHACHA20& set_counter (std::uint32_t const x);
    CHACHA20& set_nonce (std::string const& a);
    CHACHA20& set_authtag (std::string const& a);
    void poly1305_key_gen (std::array<std::uint8_t,32>& one_time_key);

    CHACHA20& encrypt (void);
    std::string authtag (void);

    CHACHA20& decrypt (void);
    bool good (void);

    std::string update (std::string::const_iterator s, std::string::const_iterator e);
    std::string update (std::string const& data);

private:
    enum { INIT, DECRYPT, ENCRYPT, FINAL };
    digest::POLY1305 poly1305;
    std::array<std::uint32_t,8> key;
    std::string authdata;
    std::array<std::uint32_t,3> nonce;
    std::string expected_tag;
    std::string tag;
    std::uint32_t iv;
    std::uint32_t counter;
    int state;
    int pos;
    std::array<std::uint8_t,64> key_stream;

    void chacha20_block (std::uint32_t count, std::array<std::uint8_t,64>& block);
};

}//namespace cipher
