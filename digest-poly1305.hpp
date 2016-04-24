#pragma once

#include <cstdint>
#include <array>
#include <string>
#include "digest.hpp"

namespace digest {

class POLY1305 : public base {
public:
    explicit POLY1305 (void);
    POLY1305& set_key256 (std::array<std::uint8_t,32> const& key);
    POLY1305& set_authdata (std::string const& a);
    POLY1305& set_aead_construction (bool const a);
    std::size_t blocksize () const { return 16U; }
    std::string digest ();
protected:
    std::string authdata;
    bool aead_construction;
    std::array<std::uint64_t,5> poly;
    std::array<std::uint32_t,5> sum;
    std::array<std::uint32_t,5> scale;
    std::array<std::uint32_t,5> scale5;
    std::array<std::uint8_t,16> termination;
    void init_sum ();
    void update_sum_with_data (std::string const& data);
    void update_sum (std::string::const_iterator s);
    void last_sum ();
};

}//namespace digest
