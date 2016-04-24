#pragma once

#include <cstdint>
#include <list>
#include <string>
#include <array>
#include "digest-aes-cmac.hpp"
#include "cipher-aes.hpp"

namespace cipher {

class AES_SIV {
public:
    explicit AES_SIV (void);
    AES_SIV& set_key256 (std::array<std::uint8_t,32> const& key256);
    AES_SIV& clear (void);
    AES_SIV& add_authdata (std::string const& a);
    AES_SIV& set_nonce (std::string const& a);

    AES_SIV& add (std::string const& a);
    AES_SIV& add (std::string::const_iterator s, std::string::const_iterator e);
    AES_SIV& encrypt (void);
    std::string authtag (void);

    AES_SIV& set_authtag (std::string const& a);
    AES_SIV& decrypt (void);
    bool good (void);

    std::string update (std::string::const_iterator s, std::string::const_iterator e);
    std::string update (std::string const& src);

private:
    enum { INIT, UPDATECMAC, DECRYPT, ENCRYPT, FINAL };
    digest::AES_CMAC aes_cmac;
    AES aes;
    std::list<std::string> authdata;
    std::string nonce;
    bool deterministic;
    std::string tail;
    std::size_t tailcount;
    std::string expected_tag;
    std::string tag;
    AES::BLOCK counter;
    AES::BLOCK key_stream;
    int state;
    int pos;

    void init_tag (void);
    void splice_tail (std::string::const_iterator s, std::string::const_iterator e);
    void replace_tail (std::string::const_iterator s, std::string::const_iterator e);
    void update_cmac (std::string::const_iterator s, std::string::const_iterator e);
    void final_tag (void);
    void gfadd (std::string& d, std::string& a, int j, int const n);
    void gftwice (std::string& s);
    void preset_counter (std::string const& v);
    void increment_counter (void);
};

}//namespace cipher
