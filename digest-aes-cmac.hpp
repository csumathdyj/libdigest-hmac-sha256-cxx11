#pragma once

#include <cstdint>
#include <array>
#include <string>
#include "digest.hpp"
#include "cipher-aes.hpp"

namespace digest {

class AES_CMAC : public base {
public:
    using BLOCK = typename cipher::AES::BLOCK;

    AES_CMAC ();
    AES_CMAC& set_key128 (std::array<std::uint8_t,16> const& key);
    AES_CMAC& set_key192 (std::array<std::uint8_t,24> const& key);
    AES_CMAC& set_key256 (std::array<std::uint8_t,32> const& key);
    std::size_t blocksize () const { return sum.size (); }
    std::string digest ();
protected:
    void init_sum ();
    void update_sum (std::string::const_iterator s);
    void last_sum ();
private:
    cipher::AES cipher;
    BLOCK sum;
    BLOCK generate_key (BLOCK const& el);
};

}//namespace digest
