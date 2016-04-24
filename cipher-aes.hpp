#pragma once

#include <cstdint>
#include <array>

namespace cipher {

class AES {
    int nrounds;
    std::uint32_t keys[60];
    std::uint32_t ikeys[60];
public:
    enum { BLOCKSIZE = 16 };
    using BLOCK = std::array<std::uint8_t,16>;
    AES () {}
    void set_key128 (std::array<std::uint8_t,16> const& key);
    void set_key192 (std::array<std::uint8_t,24> const& key);
    void set_key256 (std::array<std::uint8_t,32> const& key);
    void encrypt (BLOCK const& plain, BLOCK& secret);
    void decrypt (BLOCK const& secret, BLOCK& plain);
private:
    void schedule_keys (int const nk, int const nr);
};

}//namespace cipher

