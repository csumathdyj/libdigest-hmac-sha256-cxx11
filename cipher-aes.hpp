#pragma once

#include <cstdint>
#include <array>

namespace cipher {

class aes_type {
    int nrounds;
    uint32_t keys[60];
    uint32_t ikeys[60];
public:
    enum { BLOCKSIZE = 16 };
    aes_type () {}
    void set_key128 (std::array<uint8_t,16> const& key);
    void set_key192 (std::array<uint8_t,24> const& key);
    void set_key256 (std::array<uint8_t,32> const& key);
    void encrypt (std::array<uint8_t,16> const& plain, std::array<uint8_t,16>& secret);
    void decrypt (std::array<uint8_t,16> const& secret, std::array<uint8_t,16>& plain);
private:
    void schedule_keys (int const nk, int const nr);
};

}//namespace cipher

