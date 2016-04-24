#include <cstdint>
#include <list>
#include <string>
#include <array>
#include <algorithm>
#include <utility>
#include <stdexcept>
#include "digest-aes-cmac.hpp"
#include "cipher-aes.hpp"
#include "cipher-aes-siv.hpp"

namespace cipher {

// encryption synopsis
//
//      cipher::AES_SIV siv;
//      siv.set_key256 (key256);
//      siv.add_authdata (authdata[i]); // i = 0 ... n
//      siv.add_nonce (nonce); // for ! deterministic
//      siv.add (plain_text[i]); // i = 0 ... n
//      siv.encrypt ();
//      cipher_text[i] = siv.update (plain_text[i]); // i = 0 ... n
//      authtag = siv.authtag ();
//
// decryption synopsis
//
//      cipher::AES_SIV siv;
//      siv.set_key256 (key256);
//      siv.add_authdata (authdata[i]); // i = 0 ... n
//      siv.add_nonce (nonce); // for ! deterministic
//      siv.set_iv (authtag);
//      siv.decrypt ();
//      plain_text[i] = siv.update (cipher_text[i]); // i = 0 ... n
//      if (siv.good ()) { ... }

AES_SIV::AES_SIV (void) : aes_cmac (), aes ()
{
    tail.resize (aes_cmac.blocksize (), 0);
    clear ();
}

AES_SIV&
AES_SIV::set_key256 (std::array<std::uint8_t,32> const& key256)
{
    std::array<std::uint8_t,16> key1;
    std::copy (key256.cbegin (), key256.cbegin () + 16, key1.begin ());
    aes_cmac.set_key128 (key1);

    std::array<std::uint8_t,16> key2;
    std::copy (key256.cbegin () + 16, key256.cend (), key2.begin ());
    aes.set_key128 (key2);
    return *this;
}

AES_SIV&
AES_SIV::clear (void)
{
    authdata.clear ();
    nonce.clear ();
    deterministic = true;
    tailcount = 0;
    expected_tag.clear ();
    tag.clear ();
    state = INIT;
    pos = 0;
    return *this;
}

AES_SIV&
AES_SIV::set_authtag (std::string const& a)
{
    expected_tag = a;
    return *this;
}

AES_SIV&
AES_SIV::set_nonce (std::string const& a)
{
    nonce = a;
    deterministic = false;
    return *this;
}

AES_SIV&
AES_SIV::add_authdata (std::string const& a)
{
    authdata.push_back (a);
    return *this;
}

AES_SIV&
AES_SIV::add (std::string const& a)
{
    return add (a.cbegin (), a.cend ());
}

AES_SIV&
AES_SIV::add (std::string::const_iterator s, std::string::const_iterator e)
{
    if (INIT == state || FINAL == state)
        init_tag ();
    else if (ENCRYPT == state || DECRYPT == state)
        throw std::runtime_error ("cannot add () at update ().");
    state = UPDATECMAC;
    update_cmac (s, e);
    return *this;
}

AES_SIV&
AES_SIV::encrypt (void)
{
    if (UPDATECMAC != state)
        throw std::runtime_error ("encrypt() decends add().");
    final_tag ();
    preset_counter (tag);
    pos = 0;
    state = ENCRYPT;
    return *this;
}

AES_SIV&
AES_SIV::decrypt (void)
{
    init_tag ();
    preset_counter (expected_tag);
    pos = 0;
    state = DECRYPT;
    return *this;
}

std::string
AES_SIV::update (std::string::const_iterator s, std::string::const_iterator e)
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
    if (DECRYPT == state) {
        update_cmac (dst.cbegin (), dst.cend ());
    }
    return std::move (dst);
}

std::string
AES_SIV::update (std::string const& src)
{
    return update (src.cbegin (), src.cend ());
}

std::string
AES_SIV::authtag (void)
{
    if (INIT == state) {
        init_tag ();
        state = UPDATECMAC;
    }
    if (UPDATECMAC == state || DECRYPT == state) {
        final_tag ();
        state = FINAL;
    }
    return tag;
}

bool
AES_SIV::good (void)
{
    authtag ();
    // constant-time comparison while tag == expected_tag
    bool ok = true;
    for (int i = 0; i < tag.size (); ++i) {
        volatile bool const prev_ok = ok;
        volatile bool const not_ok = false;
        int const expected_c = i >= expected_tag.size () ? 0 : expected_tag[i];
        ok = tag[i] == expected_c ? prev_ok : not_ok;
    }
    return ok;
}

// authtag calculation
//
//      tag0 == cmac (zero);
//      tag1 == (tag0 (gaolis*) 2) (galois+) cmac (authdata[0])
//      tag2 == (tag1 (gaolis*) 2) (galois+) cmac (authdata[1])
//          ...
//      tagI == (tagH (gaolis*) 2) (galois+) cmac (authdata[n])
//      tagJ == (tagI (gaolis*) 2) (galois+) cmac (nonce)
//
//      authtag ==
//        if N < m
//          cmac ((tagJ (gaolis*) 2) (galois+) pad (plain_text))
//        else
//          cmac (plain_text.substr (0, N - m)
//                  (string+) (tagJ (galois+) plain_text.substr (N - m, m)))
//        where N == plain_text.size () and m == blocksize

// tail is the ring buffer
//
//      let m = tail.size ();
//      if (tailcount < m)
//          return tail.substr (0, tailcount);
//      else if (tailcount == m)
//          return tail;
//      else if (m < tailcount && tailcount < m * 2) {
//          let i = tailcount - m;
//          return tail.substr (i, m - i) + tail.substr (0, i);
//      }
//      else
//          throw std::runtime_error ("cannot happen");

void
AES_SIV::init_tag (void)
{
    std::string const zero (16, 0);
    tag = aes_cmac.add (zero).digest ();
    for (std::string const& ad : authdata) {
        std::string sum = aes_cmac.add (ad).digest ();
        gftwice (tag);
        gfadd (tag, sum, 0, sum.size ());
    }
    if (! deterministic) {
        std::string sum = aes_cmac.add (nonce).digest ();
        gftwice (tag);
        gfadd (tag, sum, 0, sum.size ());
    }
    tailcount = 0;
}

// splice tail when e - s < m.
//      e - s is the length of plain_text between s and e.
//      m is the size of block.
// pop front of e - s size from tail and update cmac with it.
// push back s ... e.
// ensure: the tail is filled. the its size is m. 
void
AES_SIV::splice_tail (std::string::const_iterator s, std::string::const_iterator e)
{
    std::size_t const m = tail.size ();
    std::size_t const n1 = tailcount < m ? tailcount : m;
    std::size_t const n2 = e - s;
    std::size_t const i = tailcount < m ? 0 : tailcount - m;

    std::size_t const n0 = n1 + n2 - m;
    if (n1 < m || i + n2 <= n1) {
        // pop{tail[i...i+n0]} tail[i+n0...m] tail[0...i] push{str(s...e)}
        if (n0 > 0)
            aes_cmac.add (tail.cbegin () + i, tail.cbegin () + i + n0);
        std::copy (s, e, tail.begin () + i);
    }
    else {
        // pop{tail[i...m] tail[0...n0-(m-i)]} tail[n0-(m-i)...i] push{str(s...e)}
        if (n0 > 0) {
            if (i < m)
                aes_cmac.add (tail.cbegin () + i, tail.cbegin () + m);
            aes_cmac.add (tail.cbegin (), tail.cbegin () + n0 - (m - i));
        }
        if (i < m)
            std::copy (s, s + (m - i), tail.begin () + i);
        std::copy (s + (m - i), e, tail.begin ());
    }
    tailcount += n2;
    if (tailcount > m * 2)
        tailcount -= m;
}

// replace tail when e - s >= m
//      see splice_tail.
// update cmac with entires of tail.
// update cmac with s ... e - m.
// assign tail with e - m ... e.
// ensure: the tail is filled. the its size is m. 
void
AES_SIV::replace_tail (std::string::const_iterator s, std::string::const_iterator e)
{
    std::size_t const m = tail.size ();
    std::size_t const n1 = tailcount < m ? tailcount : m;
    std::size_t const n2 = e - s;
    std::size_t const i = tailcount < m ? 0 : tailcount - m;

    if (0 < n1 && n1 < m)
        aes_cmac.add (tail.cbegin (), tail.cbegin () + n1);
    else if (tailcount == m)
        aes_cmac.add (tail);
    else if (m < tailcount) {
        aes_cmac.add (tail.cbegin () + i, tail.cbegin () + m);
        aes_cmac.add (tail.cbegin (), tail.cbegin () + i);
    }
    if (m < n2)
        aes_cmac.add (s, e - m);
    tail.assign (e - m, e);
    tailcount = m;
}

void
AES_SIV::update_cmac (std::string::const_iterator s, std::string::const_iterator e)
{
    if (s >= e)
        return;
    
    std::size_t const m = tail.size ();
    std::size_t const n1 = tailcount < m ? tailcount : m;
    std::size_t const n2 = e - s;
    if (n1 + n2 < m) {
        std::copy (s, e, tail.begin () + n1);
        tailcount += n2;
    }
    else if (n2 < m) {
        splice_tail (s, e);
    }
    else {
        replace_tail (s, e);
    }
}

void
AES_SIV::final_tag (void)
{
    std::size_t const m = tail.size ();
    if (tailcount > m) {
        // tail is operated as the ring buffer and rotate it.
        std::size_t const i = tailcount - m;
        tail = tail.substr (i, m - i) + tail.substr (0, i);
        tailcount = m;
    }
    std::size_t const n = tailcount;
    if (n == m) {
        // V = AES-CMAC (K1, Sn xorend D);
        // A xorend B == leftmost(A,len(A)-len(B))||(rightmost(A,len(B))^B)
        gfadd (tag, tail, 0, m);
    }
    else {
        // V = AES-CMAC (K1, dbl(D) xor pad(Sn))
        gftwice (tag);
        gfadd (tag, tail, 0, n);
        tag[n] = 0x80 ^ static_cast <std::uint8_t> (tag[n]);
    }
    tag = aes_cmac.add (tag).digest ();
}

void
AES_SIV::gfadd (std::string& d, std::string& a, int j, int const n)
{
    for (int i = 0; i < n; ++i, ++j) {
        d[i] = static_cast<std::uint8_t> (d[i])
            ^ static_cast<std::uint8_t> (a[j]);
    }
}

void
AES_SIV::gftwice (std::string& s)
{
    static const std::uint8_t Rb = 0x87;
    int n = s.size () - 1;
    std::string t (n + 1, 0);
    std::uint8_t const u0 = static_cast <std::uint8_t> (s[0]);
    bool const lsb = (u0 & 0x80) != 0;
    for (int i = 0; i < n; ++i) {
        std::uint8_t const u1 = static_cast <std::uint8_t> (s[i]);
        std::uint8_t const u2 = static_cast <std::uint8_t> (s[i + 1]);
        t[i] = (u1 << 1) | (u2 >> 7);
    }
    std::uint8_t const u3 = static_cast <std::uint8_t> (s[n]);
    t[n] = (u3 << 1) ^ (lsb ? Rb : 0);
    std::swap (s, t);
}

void
AES_SIV::preset_counter (std::string const& v)
{
    //Q = V bitand (1^64 || 0^1 || 1^31 || 0^1 || 1^31)
    for (int i = 0; i < 16; ++i) {
        counter[i] = static_cast<std::uint8_t> (v[i]);
    }
    counter[8] &= 0x7f;
    counter[12] &= 0x7f;
    aes.encrypt (counter, key_stream);
}

void
AES_SIV::increment_counter (void)
{
    // 64-bit constant-time increment
    int const d = counter.size () - 8;
    AES::BLOCK::value_type carry = 1U;
    for (int i = d + 7; i >= d; --i) {
        counter[i] += carry;
        carry = counter[i] < carry ? 1U : 0;
    }
    aes.encrypt (counter, key_stream);
}

}//namespace cipher
