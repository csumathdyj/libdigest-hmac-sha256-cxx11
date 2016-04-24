#pragma once

#include <cstdint>
#include <array>
#include <string>
#include "digest.hpp"

namespace digest {

class GHASH : public base {
public:
    GHASH ();
    GHASH& set_key128 (std::array<std::uint8_t,16> const& key);
    GHASH& set_authdata (std::string const& ad);
    std::size_t blocksize () const { return 16U; }
    std::string digest ();
protected:
    void init_sum ();
    void update_sum (std::string::const_iterator s);
    void last_sum ();
private:
    std::array<std::array<std::uint32_t,4>,16> hash_key;
    std::string authdata;
    std::array<std::uint32_t,4> sum;
    void update_sum_with_data (std::string const& data);
};

}//namespace digest
