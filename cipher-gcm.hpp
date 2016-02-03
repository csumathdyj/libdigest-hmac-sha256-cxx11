#pragma once

#include <string>
#include <cstdint>
#include <array>
#include <utility>

namespace cipher {

// BlockCipher object must have a member function:
//
// void BlockCipher::encrypt (std::array<uint8_t,16>, std::array<uint8_t,16>);
//
template<class BlockCipher>
class gcm_type {
public:
    gcm_type () : cipher ()
    {
        nonce.clear ();
        authdata.clear ();
        authtag.clear ();
    }

    // set 128 bits key before encrypt/decrypt
    void set_key128 (std::array<std::uint8_t,16> const& a)
    {
        cipher.set_key128 (a);
    }

    // set 192 bits key before encrypt/decrypt
    void set_key192 (std::array<std::uint8_t,24> const& a)
    {
        cipher.set_key192 (a);
    }

    // set 256 bits key before encrypt/decrypt
    void set_key256 (std::array<std::uint8_t,32> const& a)
    {
        cipher.set_key256 (a);
    }

    // set nonce of IV before encrypt/decrypt
    void set_nonce (std::string const& a)
    {
        nonce = a;
    }

    // set additional authenticated data before encrypt/decrypt
    void set_authdata (std::string const& a)
    {
        authdata = a;
    }

    // get calculated authentication tag after encrypt
    void get_authtag (std::string& a)
    {
        a = authtag;
    }

    // set authentication tag before decrypt to verify tag
    void set_authtag (std::string const& a)
    {
        authtag = a;
    }

    // encrypt plain text to secret text and authtag
    void encrypt (std::string const& plain, std::string& secret)
    {
        std::array<std::array<std::uint32_t,4>,16> hash_key;
        std::array<std::uint8_t,16> counter;
        crypt_hash_key (hash_key);
        reset_counter (hash_key, counter);
        crypt_and_ghash (hash_key, counter, plain, secret, secret, authtag);
        encrypt_counter_mode (counter, authtag, authtag, 0, 16);
    }

    // decrypt secret text to plain text with authtag
    bool decrypt (std::string const& secret, std::string& plain)
    {
        std::array<std::array<std::uint32_t,4>,16> hash_key;
        std::array<std::uint8_t,16> counter;
        std::string tag;
        crypt_hash_key (hash_key);
        reset_counter (hash_key, counter);
        crypt_and_ghash (hash_key, counter, secret, plain, secret, tag);
        encrypt_counter_mode (counter, tag, tag, 0, 16);
        if (tag != authtag) {
            plain.clear ();
            return false;
        }
    }

private:
    BlockCipher cipher;
    std::string nonce;
    std::string authdata;
    std::string authtag;

    // hash_key = CIPH(K,0**128) * i for i in 0 ... 16
    void crypt_hash_key (std::array<std::array<std::uint32_t,4>,16>& hash_key)
    {
        static const int revbit[16] {
            0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};

        std::array<std::uint8_t,16> null_block {{0}};
        std::array<std::uint8_t,16> x;
        std::array<std::uint32_t,4> h;
        cipher.encrypt (null_block, x);

        gfpack (x.begin (), h);
        hash_key[0].fill(0);
        hash_key[revbit[1]] = h;
        for (int i = 2; i < 16; i += 2) {
            hash_key[revbit[i]] = hash_key[revbit[i / 2]];
            gftwice (hash_key[revbit[i]]);
            gfadd (h, hash_key[revbit[i]], hash_key[revbit[i + 1]]);
        }
    }

    // J[0] = IV||0**31||1      if len(IV) == 96
    // J[0] = GHASH(H,{},IV)    otherwise
    void reset_counter (std::array<std::array<std::uint32_t,4>,16> const& hash_key,
        std::array<std::uint8_t,16>& counter)
    {
        if (nonce.size () == 12) {
            for (int i = 0; i < 12; ++i) {
                counter[i] = nonce[i];
            }
            counter[12] = 0;
            counter[13] = 0;
            counter[14] = 0;
            counter[15] = 1;
        }
        else {
            std::array<std::uint32_t,4> hash = {{0}};
            ghash_text (hash_key, nonce, hash);
            ghash_len (hash_key, 0, nonce.size (), hash);
            gfunpack (hash, counter.begin ());
        }
    }

    // B=GCTR(J[i],A) where i in 1 ... n
    // GHASH(H,A||0**v||C||0**u)
    void crypt_and_ghash (std::array<std::array<std::uint32_t,4>,16> const& hash_key,
        std::array<std::uint8_t,16> counter, std::string const& src,
        std::string& dst, std::string const& secret,
        std::string& tag)
    {
        std::array<std::uint32_t,4> secret_block;
        std::array<std::uint32_t,4> hash = {{0}};

        ghash_text (hash_key, authdata, hash);
        dst.resize (src.size (), 0);
        increment_counter (counter);
        auto s = secret.cbegin ();
        int const n = src.size ();
        int const m = n / 16 * 16;
        for (int i = 0; i < m; i += 16, s += 16) {
            encrypt_counter_mode (counter, src, dst, i, 16);
            gfpack (s, secret_block);
            gfadd (secret_block, hash, hash);
            gfmul (hash_key, hash, hash);
            increment_counter (counter);
        }
        if (m < n) {
            encrypt_counter_mode (counter, src, dst, m, n - m);
            ghash_text_end (hash_key, secret, hash);
        }
        ghash_len (hash_key, authdata.size (), secret.size (), hash);
        tag.resize (16, 0);
        gfunpack (hash, tag.begin ());
    }

    // T=GCTR(J[0],S)
    template<class SEQ>
    void encrypt_counter_mode (std::array<uint8_t,16> counter,
        SEQ const& src, SEQ& dst, int const pos, int const n)
    {
        std::array<std::uint8_t,16> pad;
        cipher.encrypt (counter, pad);
        for (int i = 0; i < n; ++i) {
            dst[pos + i] = static_cast<uint8_t> (src[pos + i]) ^ pad[i];
        }
    }

    // J[i] = inc(J[i-1])
    void increment_counter (std::array<uint8_t,16>& counter)
    {
        for (int i = 15; i >= 0; --i) {
            if (++counter[i])
                break;
        }
    }

    // GF(2**128) pack
    template<class ITER>
    void gfpack (ITER a, std::array<std::uint32_t,4>& b)
    {
        for (int i = 0; i < 4; ++i, a += 4) {
            std::uint32_t const a0 = static_cast<std::uint8_t> (a[0]);
            std::uint32_t const a1 = static_cast<std::uint8_t> (a[1]);
            std::uint32_t const a2 = static_cast<std::uint8_t> (a[2]);
            std::uint32_t const a3 = static_cast<std::uint8_t> (a[3]);
            b[i] = (a0 << 24) | (a1 << 16) | (a2 << 8) | a3;
        }
    }

    // GF(2**128) unpack
    template<class ITER>
    void gfunpack (std::array<std::uint32_t,4> const& a, ITER b)
    {
        for (int i = 0; i < 4; ++i, b += 4) {
            b[0] = (a[i] >> 24) & 0xff;
            b[1] = (a[i] >> 16) & 0xff;
            b[2] = (a[i] >>  8) & 0xff;
            b[3] =  a[i]        & 0xff;
        }
    }

    // C = A + B in GF(2**128)
    void gfadd (std::array<std::uint32_t,4> const& a,
        std::array<std::uint32_t,4> const& b, std::array<std::uint32_t,4>& c)
    {
        c[3] = a[3] ^ b[3];
        c[2] = a[2] ^ b[2];
        c[1] = a[1] ^ b[1];
        c[0] = a[0] ^ b[0];
    }

    // A = A >> 1 in GF(2**128) polymonial 1+x+x**2+x**7+x**128
    void gftwice (std::array<std::uint32_t,4>& a)
    {
        bool const overflow = (a[3] & 0x01) != 0;
        a[3] = (a[2] << 31) | (a[3] >> 1);
        a[2] = (a[1] << 31) | (a[2] >> 1);
        a[1] = (a[0] << 31) | (a[1] >> 1);
        a[0] = (a[0] >> 1) ^ (overflow ? 0xe1000000 : 0);
    }

    // C = A * B in GF(2**128), precomputed A[i] = H * i for i in 0 ... 16
    void gfmul (std::array<std::array<std::uint32_t,4>,16> const& a,
        std::array<std::uint32_t,4> const& b, std::array<std::uint32_t,4>& c)
    {
        static const std::uint32_t reduction[16] = {
            0x00000000, 0x1c200000, 0x38400000, 0x24600000,
            0x70800000, 0x6ca00000, 0x48c00000, 0x54e00000,
            0xe1000000, 0xfd200000, 0xd9400000, 0xc5600000,
            0x91800000, 0x8da00000, 0xa9c00000, 0xb5e00000,
        };
        std::array<std::uint32_t,4> v = {{0}};
        for (int k = 3; k >= 0; --k) {
            std::uint32_t w = b[k];
            for (int j = 0; j < 32; j += 4) {
                std::uint32_t overflow = v[3] & 0x0f;
                v[3] = (v[2] << 28) | (v[3] >> 4);
                v[2] = (v[1] << 28) | (v[2] >> 4);
                v[1] = (v[0] << 28) | (v[1] >> 4);
                v[0] = (v[0] >>  4) ^ reduction[overflow];
                v[3] ^= a[w & 0xf][3];
                v[2] ^= a[w & 0xf][2];
                v[1] ^= a[w & 0xf][1];
                v[0] ^= a[w & 0xf][0];
                w >>= 4;
            }
        }
        std::swap (c, v);
    }

    // GHASH(H, X[1] || X[1] || .. || X[m] || 0**v)
    void ghash_text (std::array<std::array<std::uint32_t,4>,16> const& hash_key,
        std::string const& src, std::array<std::uint32_t,4>& hash)
    {
        int const n = src.size ();
        int const m = n / 16 * 16;
        auto s = src.cbegin ();
        std::array<std::uint32_t,4> y;
        for (int i = 0; i < m; i += 16, s += 16) {
            gfpack (s, y);
            gfadd (y, hash, hash);
            gfmul (hash_key, hash, hash);
        }
        if (m < n) {
            ghash_text_end (hash_key, src, hash);
        }
    }

    // GHASH(H, X[m] || 0**v)
    void ghash_text_end (std::array<std::array<std::uint32_t,4>,16> const& hash_key,
        std::string const& src, std::array<std::uint32_t,4>& hash)
    {
        std::array<std::uint32_t,4> y;
        gfpack_last_block (src, y);
        gfadd (y, hash, hash);
        gfmul (hash_key, hash, hash);
    }

    // GF(2**128) pack(S[m]||..||S[n-1]||0**v) last block with zero paddings
    void gfpack_last_block (std::string const& src, std::array<std::uint32_t,4>& y)
    {
        std::array<std::uint8_t,16> x = {{0}};
        int const n = src.size ();
        int const m = n / 16 * 16;
        for (int i = m, j = 0; i < n; ++i, ++j) {
            x[j] = src[i];
        }
        gfpack (x.cbegin (), y);
    }

    // GHASH(H,[len(A)]_64||[len(C)]_64)
    void ghash_len (std::array<std::array<std::uint32_t,4>,16> const& hash_key,
        std::size_t const alen, std::size_t const blen,
        std::array<std::uint32_t,4>& x)
    {
        std::array<std::uint32_t,4> len_block;
        std::uint64_t const len_a = 8LLU * alen;
        std::uint64_t const len_b = 8LLU * blen;
        len_block[0] = len_a >> 32;
        len_block[1] = len_a & 0xffffffff;
        len_block[2] = len_b >> 32;
        len_block[3] = len_b & 0xffffffff;
        gfadd (len_block, x, x);
        gfmul (hash_key, x, x);
    }
};

}//namespace cipher

// gcm - Galois/Counter Mode
//
// see http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
// Morris Dworkin, ``Recommendation for Cipher Modes of Operation:
// Galois/Counter Mode (GCM) and GMAC'', 2007
//
// License: The BSD 3-Clause
//
// Copyright (c) 2016, MIZUTANI Tociyuki
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
