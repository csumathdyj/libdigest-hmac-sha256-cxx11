#include <string>
#include <array>
#include <cstdint>
#include <algorithm>
#include "digest-poly1305.hpp"
#include "mime-base16.hpp"
#include "taptests.hpp"

std::string
decode_hex (std::string const& s)
{
    std::string t;
    mime::decode_hex (s, t);
    return std::move (t);
}

std::array<std::uint8_t,32>
decode_key256 (std::string const& s)
{
    std::array<std::uint8_t,32> key;
    std::string t (decode_hex (s));
    std::copy (t.begin (), t.end (), key.begin ());
    return std::move (key);
}

void
test_poly1305_auth (test::simple& ts)
{
    // 2.5.2.  Poly1305 Example and Test Vector
    std::string key_hex (
        "85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:"
        "01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
    std::string msg_hex (
        "43 72 79 70 74 6f 67 72 61 70 68 69 63 20 46 6f"
        "72 75 6d 20 52 65 73 65 61 72 63 68 20 47 72 6f"
        "75 70");
    std::string expected_mac_hex (
        "a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "2.5.2 poly1305 test vector");
}

void
test_poly1305_aead_construction (test::simple& ts)
{
    // 2.8.2.  Example and Test Vector for AEAD_CHACHA20_POLY1305
    std::string key_hex (
        "7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84"
        "0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff");
    std::string authdata_hex (
        "50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7");
    std::string cipher_text_hex (
        "d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2"
        "a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6"
        "3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b"
        "1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36"
        "92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58"
        "fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc"
        "3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b"
        "61 16");
    std::string expected_tag_hex (
        "1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const authdata = decode_hex (authdata_hex);
    std::string const cipher_text = decode_hex (cipher_text_hex);
    std::string const expected_tag = decode_hex (expected_tag_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    poly1305.set_aead_construction (true);
    poly1305.set_authdata (authdata);
    std::string got_tag = poly1305.add (cipher_text).digest ();
    ts.ok (expected_tag == got_tag, "2.8.2 chacha20-poly1305 test vector");
}

// A.3. Poly1305 Message Authentication Code
void
poly1305_mac_test_vector_1 (test::simple& ts)
{
    std::string key_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_mac_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-1");
}

void
poly1305_mac_test_vector_2 (test::simple& ts)
{
    std::string key_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e");
    std::string msg_hex (
        "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74"
        "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e"
        "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72"
        "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69"
        "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72"
        "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46"
        "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20"
        "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73"
        "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69"
        "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74"
        "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69"
        "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72"
        "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74"
        "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20"
        "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75"
        "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e"
        "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69"
        "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20"
        "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63"
        "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61"
        "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e"
        "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c"
        "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65"
        "73 73 65 64 20 74 6f");
    std::string expected_mac_hex (
        "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-2");
}

void
poly1305_mac_test_vector_3 (test::simple& ts)
{
    std::string key_hex (
        "36 e5 f6 b5 c5 e0 60 70 f0 ef ca 96 22 7a 86 3e"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "41 6e 79 20 73 75 62 6d 69 73 73 69 6f 6e 20 74"
        "6f 20 74 68 65 20 49 45 54 46 20 69 6e 74 65 6e"
        "64 65 64 20 62 79 20 74 68 65 20 43 6f 6e 74 72"
        "69 62 75 74 6f 72 20 66 6f 72 20 70 75 62 6c 69"
        "63 61 74 69 6f 6e 20 61 73 20 61 6c 6c 20 6f 72"
        "20 70 61 72 74 20 6f 66 20 61 6e 20 49 45 54 46"
        "20 49 6e 74 65 72 6e 65 74 2d 44 72 61 66 74 20"
        "6f 72 20 52 46 43 20 61 6e 64 20 61 6e 79 20 73"
        "74 61 74 65 6d 65 6e 74 20 6d 61 64 65 20 77 69"
        "74 68 69 6e 20 74 68 65 20 63 6f 6e 74 65 78 74"
        "20 6f 66 20 61 6e 20 49 45 54 46 20 61 63 74 69"
        "76 69 74 79 20 69 73 20 63 6f 6e 73 69 64 65 72"
        "65 64 20 61 6e 20 22 49 45 54 46 20 43 6f 6e 74"
        "72 69 62 75 74 69 6f 6e 22 2e 20 53 75 63 68 20"
        "73 74 61 74 65 6d 65 6e 74 73 20 69 6e 63 6c 75"
        "64 65 20 6f 72 61 6c 20 73 74 61 74 65 6d 65 6e"
        "74 73 20 69 6e 20 49 45 54 46 20 73 65 73 73 69"
        "6f 6e 73 2c 20 61 73 20 77 65 6c 6c 20 61 73 20"
        "77 72 69 74 74 65 6e 20 61 6e 64 20 65 6c 65 63"
        "74 72 6f 6e 69 63 20 63 6f 6d 6d 75 6e 69 63 61"
        "74 69 6f 6e 73 20 6d 61 64 65 20 61 74 20 61 6e"
        "79 20 74 69 6d 65 20 6f 72 20 70 6c 61 63 65 2c"
        "20 77 68 69 63 68 20 61 72 65 20 61 64 64 72 65"
        "73 73 65 64 20 74 6f");
    std::string expected_mac_hex (
        "f3 47 7e 7c d9 54 17 af 89 a6 b8 79 4c 31 0c f0");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-3");
}

void
poly1305_mac_test_vector_4 (test::simple& ts)
{
    std::string key_hex (
        "1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0"
        "47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0");
    std::string msg_hex (
        "27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61"
        "6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f"
        "76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64"
        "20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77"
        "61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77"
        "65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65"
        "73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20"
        "72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e");
    std::string expected_mac_hex (
        "45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-4");
}

void
poly1305_mac_test_vector_5 (test::simple& ts)
{
    std::string key_hex (
        "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
    std::string expected_mac_hex (
        "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-5");
}

void
poly1305_mac_test_vector_6 (test::simple& ts)
{
    std::string key_hex (
        "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
    std::string msg_hex (
        "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_mac_hex (
        "03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-6");
}

void
poly1305_mac_test_vector_7 (test::simple& ts)
{
    std::string key_hex (
        "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
        "f0 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
        "11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_mac_hex (
        "05 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-7");
}

void
poly1305_mac_test_vector_8 (test::simple& ts)
{
    std::string key_hex (
        "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff"
        "fb fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe"
        "01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01");
    std::string expected_mac_hex (
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-8");
}

void
poly1305_mac_test_vector_9 (test::simple& ts)
{
    std::string key_hex (
        "02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "fd ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
    std::string expected_mac_hex (
        "fa ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-9");
}

void
poly1305_mac_test_vector_10 (test::simple& ts)
{
    std::string key_hex (
        "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "e3 35 94 d7 50 5e 43 b9 00 00 00 00 00 00 00 00"
        "33 94 d7 50 5e 43 79 cd 01 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_mac_hex (
        "14 00 00 00 00 00 00 00 55 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-10");
}

void
poly1305_mac_test_vector_11 (test::simple& ts)
{
    std::string key_hex (
        "01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string msg_hex (
        "e3 35 94 d7 50 5e 43 b9 00 00 00 00 00 00 00 00"
        "33 94 d7 50 5e 43 79 cd 01 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::string expected_mac_hex (
        "13 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
    std::array<std::uint8_t,32> const key = decode_key256 (key_hex);
    std::string const msg = decode_hex (msg_hex);
    std::string const expected_mac = decode_hex (expected_mac_hex);
    digest::POLY1305 poly1305;
    poly1305.set_key256 (key);
    std::string got_mac = poly1305.add (msg).digest ();
    ts.ok (expected_mac == got_mac, "A.3 poly1305-11");
}

int
main ()
{
    test::simple ts (13);

    test_poly1305_auth (ts);
    test_poly1305_aead_construction (ts);

    poly1305_mac_test_vector_1 (ts);
    poly1305_mac_test_vector_2 (ts);
    poly1305_mac_test_vector_3 (ts);
    poly1305_mac_test_vector_4 (ts);
    poly1305_mac_test_vector_5 (ts);
    poly1305_mac_test_vector_6 (ts);
    poly1305_mac_test_vector_7 (ts);
    poly1305_mac_test_vector_8 (ts);
    poly1305_mac_test_vector_9 (ts);
    poly1305_mac_test_vector_10 (ts);
    poly1305_mac_test_vector_11 (ts);

    return ts.done_testing ();
}
