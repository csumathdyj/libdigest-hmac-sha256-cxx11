#include <cstdint>
#include <string>
#include "digest.hpp"
#include "mime-base64.hpp"
#include "mime-base16.hpp"
#include "pbkdf2-sha256.hpp"
#include "taptests.hpp"

void
test_sha256 (test::simple& t)
{
    digest::SHA256 sha256;
    t.ok (sha256.add ("").hexdigest () ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha-256 empty data");

    t.ok (sha256.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        "sha-256 quick brown...");

    digest::base& h = sha256;
    h.add ("The quick brown fox jumps over the lazy dog.");
    t.ok (h.hexdigest () ==
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        "sha-256 c");
    h.reset ();
    h.add ("The quick brown fox ");
    h.add ("jumps over the lazy dog.");
    t.ok (h.hexdigest () ==
        "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        "sha-256 d");
}

void
test_sha256_more (test::simple& t)
{
    // Authorization: Digest algorithm=SHA-256,qop=auth,...
    digest::SHA256 h1;
    digest::SHA256 h2;
    digest::SHA256 hr;
    std::string a1     = "Mufasa:http-auth@example.org:Circle of Life";
    std::string a2     = "GET:/dir/index.html";
    std::string nonce  = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
    std::string nc     = "00000001";
    std::string cnonce = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
    std::string got = hr.add (h1.add (a1).hexdigest ())
                        .add (":").add (nonce)
                        .add (":").add (nc)
                        .add (":").add (cnonce)
                        .add (":auth:").add (h2.add (a2).hexdigest ())
                        .hexdigest ();
    t.ok (got == "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
        "http digest authorization");
}

void
test_sha512 (test::simple& t)
{
    digest::SHA512 sha512;
    t.ok (sha512.add ("").hexdigest () ==
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "sha-512 empty data");

    t.ok (sha512.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb"
        "c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
        "sha-512 quick brown...");

    digest::base& h = sha512;
    h.add ("The quick brown fox jumps over the lazy dog.");
    t.ok (h.hexdigest () ==
        "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb"
        "c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
        "sha-512 c");
    h.reset ();
    h.add ("The quick brown fox ");
    h.add ("jumps over the lazy dog.");
    t.ok (h.hexdigest () ==
        "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb"
        "c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
        "sha-512 d");
}

void
test_sha224 (test::simple& t)
{
    digest::SHA224 sha224;
    t.ok (sha224.add ("").hexdigest () ==
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "sha-224 empty data");

    t.ok (sha224.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "619cba8e8e05826e9b8c519c0a5c68f4fb653e8a3d8aa04bb2c8cd4c",
        "sha-224 quick brown...");
}

void
test_sha384 (test::simple& t)
{
    digest::SHA384 sha384;
    t.ok (sha384.add ("").hexdigest () ==
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
        "274edebfe76f65fbd51ad2f14898b95b",
        "sha-384 empty data");

    t.ok (sha384.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "ed892481d8272ca6df370bf706e4d7bc1b5739fa2177aae6c50e946678718fc6"
        "7a7af2819a021c2fc34e91bdb63409d7",
        "sha-384 quick brown...");
}

void
test_sha512_224 (test::simple& t)
{
    digest::SHA512_224 sha;
    t.ok (sha.add ("").hexdigest () ==
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921",
        "sha-512/224 empty data");

    t.ok (sha.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890c",
        "sha-512/224 quick brown...");
}

void
test_sha512_256 (test::simple& t)
{
    digest::SHA512_256 sha;
    t.ok (sha.add ("").hexdigest () ==
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce",
        "sha-512/256 empty data");

    t.ok (sha.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb",
        "sha-512/256 quick brown...");
}

void
test_sha1 (test::simple& t)
{
    digest::SHA1 sha;
    t.ok (sha.add ("").hexdigest () ==
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "sha-1 empty data");

    t.ok (sha.add ("The quick brown fox jumps over the lazy dog.").hexdigest () ==
        "408d94384216f890ff7a0c3528e8bed1e0b01621",
        "sha-1 quick brown...");
}

void
test_hmac_1 (test::simple& t)
{
    std::string const key16 =
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        "0b0b0b0b";
    std::string const data16 =
        "4869205468657265";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest () ==
        "896fb1128abbdf196832107cd49df33f"
        "47b4b1169912ba4f53684b22",
        "hmac-sha-224 rfc 4231 test case 1");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest () ==
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7",
        "hmac-sha-256 rfc 4231 test case 1");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest () ==
        "afd03944d84895626b0825f4ab46907f"
        "15f9dadbe4101ec682aa034c7cebc59c"
        "faea9ea9076ede7f4af152e8b2fa9cb6",
        "hmac-sha-384 rfc 4231 test case 1");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest () ==
        "87aa7cdea5ef619d4ff0b4241a1d6cb0"
        "2379f4e2ce4ec2787ad0b30545e17cde"
        "daa833b7d6b8a702038b274eaea3f4e4"
        "be9d914eeb61f1702e696c203a126854",
        "hmac-sha-512 rfc 4231 test case 1");
}

void
test_hmac_2 (test::simple& t)
{
    std::string const key16 =
        "4a656665";
    std::string const data16 =
        "7768617420646f2079612077616e7420"
        "666f72206e6f7468696e673f";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest () ==
        "a30e01098bc6dbbf45690f3a7e9e6d0f"
        "8bbea2a39e6148008fd05e44",
        "hmac-sha-224 rfc 4231 test case 2");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest () ==
        "5bdcc146bf60754e6a042426089575c7"
        "5a003f089d2739839dec58b964ec3843",
        "hmac-sha-256 rfc 4231 test case 2");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest () ==
        "af45d2e376484031617f78d2b58a6b1b"
        "9c7ef464f5a01b47e42ec3736322445e"
        "8e2240ca5e69e2c78b3239ecfab21649",
        "hmac-sha-384 rfc 4231 test case 2");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest () ==
        "164b7a7bfcf819e2e395fbe73b56e0a3"
        "87bd64222e831fd610270cd7ea250554"
        "9758bf75c05a994a6d034f65f8f0e6fd"
        "caeab1a34d4a6b4b636e070a38bce737",
        "hmac-sha-512 rfc 4231 test case 2");
}

void
test_hmac_3 (test::simple& t)
{
    std::string const key16 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaa";
    std::string const data16 =
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd"
        "dddddddddddddddddddddddddddddddd"
        "dddd";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest () ==
        "7fb3cb3588c6c1f6ffa9694d7d6ad264"
        "9365b0c1f65d69d1ec8333ea",
        "hmac-sha-224 rfc 4231 test case 3");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest () ==
        "773ea91e36800e46854db8ebd09181a7"
        "2959098b3ef8c122d9635514ced565fe",
        "hmac-sha-256 rfc 4231 test case 3");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest () ==
        "88062608d3e6ad8a0aa2ace014c8a86f"
        "0aa635d947ac9febe83ef4e55966144b"
        "2a5ab39dc13814b94e3ab6e101a34f27",
        "hmac-sha-384 rfc 4231 test case 3");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest () ==
        "fa73b0089d56a284efb0f0756c890be9"
        "b1b5dbdd8ee81a3655f83e33b2279d39"
        "bf3e848279a722c806b485a47e67c807"
        "b946a337bee8942674278859e13292fb",
        "hmac-sha-512 rfc 4231 test case 3");
}

void
test_hmac_4 (test::simple& t)
{
    std::string const key16 =
        "0102030405060708090a0b0c0d0e0f10"
        "111213141516171819";
    std::string const data16 =
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
        "cdcd";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest () ==
        "6c11506874013cac6a2abc1bb382627c"
        "ec6a90d86efc012de7afec5a",
        "hmac-sha-224 rfc 4231 test case 4");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest () ==
        "82558a389a443c0ea4cc819899f2083a"
        "85f0faa3e578f8077a2e3ff46729665b",
        "hmac-sha-256 rfc 4231 test case 4");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest () ==
        "3e8a69b7783c25851933ab6290af6ca7"
        "7a9981480850009cc5577c6e1f573b4e"
        "6801dd23c4a7d679ccf8a386c674cffb",
        "hmac-sha-384 rfc 4231 test case 4");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest () ==
        "b0ba465637458c6990e5a8c5f61d4af7"
        "e576d97ff94b872de76f8050361ee3db"
        "a91ca5c11aa25eb4d679275cc5788063"
        "a5f19741120c4f2de2adebeb10a298dd",
        "hmac-sha-512 rfc 4231 test case 4");
}

void
test_hmac_5 (test::simple& t)
{
    std::string const key16 =
        "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
        "0c0c0c0c";
    std::string const data16 =
        "546573742057697468205472756e6361"
        "74696f6e";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest ().substr (0, 128 / 4) ==
        "0e2aea68a90c8d37c988bcdb9fca6fa8",
        "hmac-sha-224 rfc 4231 test case 5");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest ().substr (0, 128 / 4) ==
        "a3b6167473100ee06e0c796c2955552b",
        "hmac-sha-256 rfc 4231 test case 5");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest ().substr (0, 128 / 4) ==
        "3abf34c3503b2a23a46efc619baef897",
        "hmac-sha-384 rfc 4231 test case 5");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest ().substr (0, 128 / 4) ==
        "415fad6271580a531d4179bc891d87a6",
        "hmac-sha-512 rfc 4231 test case 5");
}

void
test_hmac_6 (test::simple& t)
{
    std::string const key16 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa";
    std::string const data16 =
        "54657374205573696e67204c61726765"
        "72205468616e20426c6f636b2d53697a"
        "65204b6579202d2048617368204b6579"
        "204669727374";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest () ==
        "95e9a0db962095adaebe9b2d6f0dbce2"
        "d499f112f2d2b7273fa6870e",
        "hmac-sha-224 rfc 4231 test case 6");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest () ==
        "60e431591ee0b67f0d8a26aacbf5b77f"
        "8e0bc6213728c5140546040f0ee37f54",
        "hmac-sha-256 rfc 4231 test case 6");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest () ==
        "4ece084485813e9088d2c63a041bc5b4"
        "4f9ef1012a2b588f3cd11f05033ac4c6"
        "0c2ef6ab4030fe8296248df163f44952",
        "hmac-sha-384 rfc 4231 test case 6");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest () ==
        "80b24263c7c1a3ebb71493c1dd7be8b4"
        "9b46d1f41b4aeec1121b013783f8f352"
        "6b56d037e05f2598bd0fd2215d6a1e52"
        "95e64f73f63f0aec8b915a985d786598",
        "hmac-sha-512 rfc 4231 test case 6");
}

void
test_hmac_7 (test::simple& t)
{
    std::string const key16 =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaa";
    std::string const data16 =
        "54686973206973206120746573742075"
        "73696e672061206c6172676572207468"
        "616e20626c6f636b2d73697a65206b65"
        "7920616e642061206c61726765722074"
        "68616e20626c6f636b2d73697a652064"
        "6174612e20546865206b6579206e6565"
        "647320746f2062652068617368656420"
        "6265666f7265206265696e6720757365"
        "642062792074686520484d414320616c"
        "676f726974686d2e";

    std::string key, data;
    mime::decode_hex (key16, key);
    mime::decode_hex (data16, data);

    digest::HMAC<digest::SHA224> hmac_sha_224 (key);
    t.ok (hmac_sha_224.add (data).hexdigest () ==
        "3a854166ac5d9f023f54d517d0b39dbd"
        "946770db9c2b95c9f6f565d1",
        "hmac-sha-224 rfc 4231 test case 7");

    digest::HMAC<digest::SHA256> hmac_sha_256 (key);
    t.ok (hmac_sha_256.add (data).hexdigest () ==
        "9b09ffa71b942fcb27635fbcd5b0e944"
        "bfdc63644f0713938a7f51535c3a35e2",
        "hmac-sha-256 rfc 4231 test case 7");

    digest::HMAC<digest::SHA384> hmac_sha_384 (key);
    t.ok (hmac_sha_384.add (data).hexdigest () ==
        "6617178e941f020d351e2f254e8fd32c"
        "602420feb0b8fb9adccebb82461e99c5"
        "a678cc31e799176d3860e6110c46523e",
        "hmac-sha-384 rfc 4231 test case 7");

    digest::HMAC<digest::SHA512> hmac_sha_512 (key);
    t.ok (hmac_sha_512.add (data).hexdigest () ==
        "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
        "debd71f8867289865df5a32d20cdc944"
        "b6022cac3c4982b10d5eeb55c3e4de15"
        "134676fb6de0446065c97440fa8c6a58",
        "hmac-sha-512 rfc 4231 test case 7");
}

// RFC 6238 TOTP: Time-Based One-Time Password Algorithm
static std::uint32_t
totp (digest::base& hfunc, std::string const& secret, std::uint64_t const epoch)
{
    std::uint64_t const t = epoch / 30U;
    std::string data (8, 0);
    for (int i = 0; i < 8; ++i) {
        data[i] = (t >> (56 - (i * 8))) & 0xff;
    }
    std::string const hs = hfunc.add (data).digest ();
    int off = static_cast<std::uint8_t> (hs[hs.size () - 1]) & 0x0f;
    std::uint32_t bin = (static_cast<std::uint8_t> (hs[off + 0]) << 24)
                       | (static_cast<std::uint8_t> (hs[off + 1]) << 16)
                       | (static_cast<std::uint8_t> (hs[off + 2]) <<  8)
                       |  static_cast<std::uint8_t> (hs[off + 3]);
    return (bin & 0x7fffffff) % 100000000U;
}

// RFC 6238 TOTP, Appendix B. Test Vectors
void
test_rfc6238_totp (test::simple& t)
{
    std::string const secret1 = "12345678901234567890";
    std::string const secret2 = "12345678901234567890123456789012";
    std::string const secret5 = "12345678901234567890123456789012"
                                 "34567890123456789012345678901234";
    digest::HMAC<digest::SHA1>   hf1 (secret1);
    digest::HMAC<digest::SHA256> hf2 (secret2);
    digest::HMAC<digest::SHA512> hf5 (secret5);

    t.ok (totp (hf1, secret1,          59ULL) == 94287082, "totp SHA-1 59");
    t.ok (totp (hf2, secret2,          59ULL) == 46119246, "totp SHA-256 59");
    t.ok (totp (hf5, secret5,          59ULL) == 90693936, "totp SHA-512 59");

    t.ok (totp (hf1, secret1,  1111111109ULL) ==  7081804, "totp SHA-1 1111111109");
    t.ok (totp (hf2, secret2,  1111111109ULL) == 68084774, "totp SHA-256 1111111109");
    t.ok (totp (hf5, secret5,  1111111109ULL) == 25091201, "totp SHA-512 1111111109");

    t.ok (totp (hf1, secret1,  1111111111ULL) == 14050471, "totp SHA-1 1111111111");
    t.ok (totp (hf2, secret2,  1111111111ULL) == 67062674, "totp SHA-256 1111111111");
    t.ok (totp (hf5, secret5,  1111111111ULL) == 99943326, "totp SHA-512 1111111111");

    t.ok (totp (hf1, secret1,  1234567890ULL) == 89005924, "totp SHA-1 1234567890");
    t.ok (totp (hf2, secret2,  1234567890ULL) == 91819424, "totp SHA-256 1234567890");
    t.ok (totp (hf5, secret5,  1234567890ULL) == 93441116, "totp SHA-512 1234567890");

    t.ok (totp (hf1, secret1,  2000000000ULL) == 69279037, "totp SHA-1 2000000000");
    t.ok (totp (hf2, secret2,  2000000000ULL) == 90698825, "totp SHA-256 2000000000");
    t.ok (totp (hf5, secret5,  2000000000ULL) == 38618901, "totp SHA-512 2000000000");

    t.ok (totp (hf1, secret1, 20000000000ULL) == 65353130, "totp SHA-1 20000000000");
    t.ok (totp (hf2, secret2, 20000000000ULL) == 77737706, "totp SHA-256 20000000000");
    t.ok (totp (hf5, secret5, 20000000000ULL) == 47863826, "totp SHA-512 20000000000");
}

void
test_encode_base64_foobar (test::simple& t)
{
    t.ok (mime::encode_base64 ("", "") == "", "encode_base64 empty");
    t.ok (mime::encode_base64 ("f", "") == "Zg==", "encode_base64 f");
    t.ok (mime::encode_base64 ("fo", "") == "Zm8=", "encode_base64 fo");
    t.ok (mime::encode_base64 ("foo", "") == "Zm9v", "encode_base64 foo");
    t.ok (mime::encode_base64 ("foob", "") == "Zm9vYg==", "encode_base64 foob");
    t.ok (mime::encode_base64 ("fooba", "") == "Zm9vYmE=", "encode_base64 fooba");
    t.ok (mime::encode_base64 ("foobar", "") == "Zm9vYmFy", "encode_base64 foobar");
}

void
test_decode_base64_foobar (test::simple& t)
{
    std::string got;
    t.ok (mime::decode_base64 ("", got), "decode_base64 empty");
    t.ok (got == "", "decode_base64 got empty");

    t.ok (mime::decode_base64 ("Zg==", got), "decode_base64 Zg==");
    t.ok (got == "f", "decode_base64 got f");

    t.ok (mime::decode_base64 ("Zm8=", got), "decode_base64 Zm8=");
    t.ok (got == "fo", "decode_base64 got fo");

    t.ok (mime::decode_base64 ("Zm9v", got), "decode_base64 Zm9v");
    t.ok (got == "foo", "decode_base64 got foo");

    t.ok (mime::decode_base64 ("Zm9vYg==", got), "decode_base64 Zm9vYg==");
    t.ok (got == "foob", "decode_base64 got foob");

    t.ok (mime::decode_base64 ("Zm9vYmE=", got), "decode_base64 Zm9vYmE=");
    t.ok (got == "fooba", "decode_base64 got fooba");

    t.ok (mime::decode_base64 ("Zm9vYmFy", got), "decode_base64 Zm9vYmFy");
    t.ok (got == "foobar", "decode_base64 got foobar");
}

void
test_encode_base64 (test::simple& t)
{
    static const std::basic_string<std::uint8_t> xinput {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
        0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
        0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55, 0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
        0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97, 0xaa, 0x63,
        0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
        0x86, 0x35, 0xfb, 0x6c, 0x75, 0x39, 0x27, 0xfa, 0x0e, 0x85,
        0xd1, 0x55, 0x56, 0x4e, 0x2e, 0x27, 0x2a, 0x28, 0xd1, 0x80,
        0x2c, 0xa1, 0x0d, 0xaf, 0x44, 0x96, 0x79, 0x46, 0x97, 0xcf,
        0x8d, 0xb5, 0x85, 0x6c, 0xb6, 0xc1, 0xb0, 0x34, 0x4c, 0x61,
        0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
        0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    std::string octets (xinput.cbegin (), xinput.cend ());

    static const std::string expected1 =
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW/p4JSZSmptj2XqmMVZNXXicK3\n"
        "ZUSMhjX7bHU5J/oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK/OrwvxK4gd\n"
        "wgDJgz2nJuk3bC4yz/c=\n";
    t.ok (mime::encode_base64 (octets) == expected1, "encode_base64/1");

    static const std::string expected2 =
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW/p4JSZSmptj2XqmMVZNXXicK3"
        "ZUSMhjX7bHU5J/oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK/OrwvxK4gd"
        "wgDJgz2nJuk3bC4yz/c=";
    t.ok (mime::encode_base64 (octets, "") == expected2, "encode_base64/2");

    static const std::string expected3 =
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW_p4JSZSmptj2XqmMVZNXXicK3"
        "ZUSMhjX7bHU5J_oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK_OrwvxK4gd"
        "wgDJgz2nJuk3bC4yz_c=";
    t.ok (mime::encode_base64url (octets) == expected3, "encode_base64url");

    static const std::string expected4 =
        "47DEQpj8HBSa./TImW.5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW/p4JSZSmptj2XqmMVZNXXicK3"
        "ZUSMhjX7bHU5J/oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK/OrwvxK4gd"
        "wgDJgz2nJuk3bC4yz/c";
    t.ok (mime::encode_base64crypt (octets) == expected4, "encode_base64crypt");

    octets.clear ();
    for (std::size_t i = 0; i < 54; ++i)
        octets.push_back (i + 40);
    static const std::string expected5 =
        "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RF"
        "RkdISUpLTE1OT1BRUlNUVVZXWFlaW1xd\n";
    t.ok (mime::encode_base64 (octets) == expected5, "encode_base64/1 72 column");

    for (std::size_t i = 54; i < 57; ++i)
        octets.push_back (i + 40);
    static const std::string expected6 =
        "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RF"
        "RkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9g\n";
    t.ok (mime::encode_base64 (octets) == expected6, "encode_base64/1 76 column");

    for (std::size_t i = 57; i < 60; ++i)
        octets.push_back (i + 40);
    static const std::string expected7 =
        "KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RF"
        "RkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9g\n"
        "YWJj\n";
    t.ok (mime::encode_base64 (octets) == expected7, "encode_base64/1 80 column");
}

void
test_decode_base64 (test::simple& t)
{
    static const std::basic_string<std::uint8_t> xinput {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
        0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
        0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55, 0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
        0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97, 0xaa, 0x63,
        0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
        0x86, 0x35, 0xfb, 0x6c, 0x75, 0x39, 0x27, 0xfa, 0x0e, 0x85,
        0xd1, 0x55, 0x56, 0x4e, 0x2e, 0x27, 0x2a, 0x28, 0xd1, 0x80,
        0x2c, 0xa1, 0x0d, 0xaf, 0x44, 0x96, 0x79, 0x46, 0x97, 0xcf,
        0x8d, 0xb5, 0x85, 0x6c, 0xb6, 0xc1, 0xb0, 0x34, 0x4c, 0x61,
        0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
        0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    std::string expected (xinput.cbegin (), xinput.cend ());
    std::string got;

    static const std::string b64_1 =
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW/p4JSZSmptj2XqmMVZNXXicK3\n"
        "ZUSMhjX7bHU5J/oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK/OrwvxK4gd\n"
        "wgDJgz2nJuk3bC4yz/c=\n";
    t.ok (mime::decode_base64 (b64_1, got), "decode_base64 wrap");
    t.ok (got == expected, "decode_base64 wrap got");

    static const std::string b64_2 =
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW/p4JSZSmptj2XqmMVZNXXicK3"
        "ZUSMhjX7bHU5J/oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK/OrwvxK4gd"
        "wgDJgz2nJuk3bC4yz/c=";
    t.ok (mime::decode_base64 (b64_2, got), "decode_base64");
    t.ok (got == expected, "decode_base64 got");

    static const std::string b64_3 =
        "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW_p4JSZSmptj2XqmMVZNXXicK3"
        "ZUSMhjX7bHU5J_oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK_OrwvxK4gd"
        "wgDJgz2nJuk3bC4yz_c=";
    t.ok (mime::decode_base64url (b64_3, got), "decode_base64url");
    t.ok (got == expected, "decode_base64url got");

    static const std::string b64_4 =
        "47DEQpj8HBSa./TImW.5JCeuQeRkm5NMpJWZG3hS"
        "uFXvU38lyJW/p4JSZSmptj2XqmMVZNXXicK3"
        "ZUSMhjX7bHU5J/oOhdFVVk4uJyoo0YAsoQ2vRJZ5"
        "RpfPjbWFbLbBsDRMYdjbOFNcqK/OrwvxK4gd"
        "wgDJgz2nJuk3bC4yz/c";
    t.ok (mime::decode_base64crypt (b64_4, got), "decode_base64crypt");
    t.ok (got == expected, "decode_base64crypt got");
}

void
test_base64_more (test::simple& t)
{
    std::string plain = "Aladdin:open sesame";
    std::string b64 = "QWxhZGRpbjpvcGVuIHNlc2FtZQ==";
    t.ok (mime::encode_base64 (plain, "") == b64, "http basic www-authenticate");
    std::string got;
    mime::decode_base64 (b64, got);
    t.ok (got == plain, "http basic authorization");
}

void
test_encode_base16 (test::simple& t)
{
    static const std::basic_string<std::uint8_t> xinput {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
        0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
        0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55, 0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
        0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97, 0xaa, 0x63,
        0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
        0x86, 0x35, 0xfb, 0x6c, 0x75, 0x39, 0x27, 0xfa, 0x0e, 0x85,
        0xd1, 0x55, 0x56, 0x4e, 0x2e, 0x27, 0x2a, 0x28, 0xd1, 0x80,
        0x2c, 0xa1, 0x0d, 0xaf, 0x44, 0x96, 0x79, 0x46, 0x97, 0xcf,
        0x8d, 0xb5, 0x85, 0x6c, 0xb6, 0xc1, 0xb0, 0x34, 0x4c, 0x61,
        0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
        0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    std::string octets (xinput.cbegin (), xinput.cend ());

    static const std::string expected1 =
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4"
        "649B934CA495991B7852B855EF537F25C895\n"
        "BFA782526529A9B63D97AA631564D5D789C2B765"
        "448C8635FB6C753927FA0E85D155564E2E27\n"
        "2A28D1802CA10DAF4496794697CF8DB5856CB6C1"
        "B0344C61D8DB38535CA8AFCEAF0BF12B881D\n"
        "C200C9833DA726E9376C2E32CFF7\n";
    t.ok (mime::encode_base16 (octets) == expected1, "encode_base16/1");

    static const std::string expected2 =
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4"
        "649B934CA495991B7852B855EF537F25C895"
        "BFA782526529A9B63D97AA631564D5D789C2B765"
        "448C8635FB6C753927FA0E85D155564E2E27"
        "2A28D1802CA10DAF4496794697CF8DB5856CB6C1"
        "B0344C61D8DB38535CA8AFCEAF0BF12B881D"
        "C200C9833DA726E9376C2E32CFF7";
    t.ok (mime::encode_base16 (octets, "") == expected2, "encode_base16/2");

    static const std::string expected3 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        "649b934ca495991b7852b855ef537f25c895"
        "bfa782526529a9b63d97aa631564d5d789c2b765"
        "448c8635fb6c753927fa0e85d155564e2e27"
        "2a28d1802ca10daf4496794697cf8db5856cb6c1"
        "b0344c61d8db38535ca8afceaf0bf12b881d"
        "c200c9833da726e9376c2e32cff7";
    t.ok (mime::encode_hex (octets) == expected3, "encode_hex/1");

    static const std::string expected4 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        "649b934ca495991b7852b855ef537f25c895\n"
        "bfa782526529a9b63d97aa631564d5d789c2b765"
        "448c8635fb6c753927fa0e85d155564e2e27\n"
        "2a28d1802ca10daf4496794697cf8db5856cb6c1"
        "b0344c61d8db38535ca8afceaf0bf12b881d\n"
        "c200c9833da726e9376c2e32cff7\n";
    t.ok (mime::encode_hex (octets, "\n") == expected4, "encode_hex/2");

    octets.clear ();
    for (std::size_t i = 0; i < 36; ++i)
        octets.push_back (i + 40);
    static const std::string expected5 =
        "28292A2B2C2D2E2F303132333435363738393A3B"
        "3C3D3E3F404142434445464748494A4B\n";
    t.ok (mime::encode_base16 (octets) == expected5, "encode_base16/1 72 column");

    for (std::size_t i = 36; i < 38; ++i)
        octets.push_back (i + 40);
    static const std::string expected6 =
        "28292A2B2C2D2E2F303132333435363738393A3B"
        "3C3D3E3F404142434445464748494A4B4C4D\n";
    t.ok (mime::encode_base16 (octets) == expected6, "encode_base16/1 76 column");

    for (std::size_t i = 38; i < 40; ++i)
        octets.push_back (i + 40);
    static const std::string expected7 =
        "28292A2B2C2D2E2F303132333435363738393A3B"
        "3C3D3E3F404142434445464748494A4B4C4D\n"
        "4E4F\n";
    t.ok (mime::encode_base16 (octets) == expected7, "encode_base16/1 80 column");
}

void
test_decode_base16 (test::simple& t)
{
    static const std::basic_string<std::uint8_t> xinput {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb,
        0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4,
        0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55, 0xef, 0x53, 0x7f, 0x25, 0xc8, 0x95, 0xbf, 0xa7,
        0x82, 0x52, 0x65, 0x29, 0xa9, 0xb6, 0x3d, 0x97, 0xaa, 0x63,
        0x15, 0x64, 0xd5, 0xd7, 0x89, 0xc2, 0xb7, 0x65, 0x44, 0x8c,
        0x86, 0x35, 0xfb, 0x6c, 0x75, 0x39, 0x27, 0xfa, 0x0e, 0x85,
        0xd1, 0x55, 0x56, 0x4e, 0x2e, 0x27, 0x2a, 0x28, 0xd1, 0x80,
        0x2c, 0xa1, 0x0d, 0xaf, 0x44, 0x96, 0x79, 0x46, 0x97, 0xcf,
        0x8d, 0xb5, 0x85, 0x6c, 0xb6, 0xc1, 0xb0, 0x34, 0x4c, 0x61,
        0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
        0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7};
    std::string expected (xinput.cbegin (), xinput.cend ());
    std::string got;

    static const std::string b16_1 =
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4"
        "649B934CA495991B7852B855EF537F25C895\n"
        "BFA782526529A9B63D97AA631564D5D789C2B765"
        "448C8635FB6C753927FA0E85D155564E2E27\n"
        "2A28D1802CA10DAF4496794697CF8DB5856CB6C1"
        "B0344C61D8DB38535CA8AFCEAF0BF12B881D\n"
        "C200C9833DA726E9376C2E32CFF7\n";
    t.ok (mime::decode_base16 (b16_1, got), "decode_base16 wrap");
    t.ok (got == expected, "decode_base16 wrap got");

    static const std::string b16_2 =
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4"
        "649B934CA495991B7852B855EF537F25C895"
        "BFA782526529A9B63D97AA631564D5D789C2B765"
        "448C8635FB6C753927FA0E85D155564E2E27"
        "2A28D1802CA10DAF4496794697CF8DB5856CB6C1"
        "B0344C61D8DB38535CA8AFCEAF0BF12B881D"
        "C200C9833DA726E9376C2E32CFF7";
    t.ok (mime::decode_base16 (b16_2, got), "decode_base16");
    t.ok (got == expected, "decode_base16 got");

    static const std::string b16_3 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        "649b934ca495991b7852b855ef537f25c895"
        "bfa782526529a9b63d97aa631564d5d789c2b765"
        "448c8635fb6c753927fa0e85d155564e2e27"
        "2a28d1802ca10daf4496794697cf8db5856cb6c1"
        "b0344c61d8db38535ca8afceaf0bf12b881d"
        "c200c9833da726e9376c2e32cff7";
    t.ok (mime::decode_hex (b16_3, got), "decode_hex");
    t.ok (got == expected, "decode_hex got");

    static const std::string b16_4 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
        "649b934ca495991b7852b855ef537f25c895\n"
        "bfa782526529a9b63d97aa631564d5d789c2b765"
        "448c8635fb6c753927fa0e85d155564e2e27\n"
        "2a28d1802ca10daf4496794697cf8db5856cb6c1"
        "b0344c61d8db38535ca8afceaf0bf12b881d\n"
        "c200c9833da726e9376c2e32cff7\n";
    t.ok (mime::decode_hex (b16_4, got), "decode_hex");
    t.ok (got == expected, "decode_hex got wrap");
}

void
test_pbkdf2_sha256 (test::simple& t)
{
    // https://pythonhosted.org/passlib/lib/passlib.hash.pbkdf2_digest.html

    static const std::basic_string<std::uint8_t> xsalt {
        0xd1, 0x9a, 0xf3, 0x5e, 0x2b, 0x45, 0x48, 0x69, 0x6d, 0x4d,
        0x09, 0xc1, 0x58, 0xeb, 0x1d, 0x03};
    std::string salt (xsalt.cbegin (), xsalt.cend ());

    t.ok (mime::encode_base64crypt (salt) == "0ZrzXitFSGltTQnBWOsdAw",
        "pbkdf2-sha256 salt");

    std::string got = pbkdf2_sha256::encrypt ("password", salt);
    std::string expected
        = "$pbkdf2-sha256$6400$0ZrzXitFSGltTQnBWOsdAw$"
          "Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M";
    t.ok (got == expected, "pbkdf2-sha256 encrypt salt");
    t.ok (pbkdf2_sha256::verify ("password", got), "pbkdf2-sha256 verify");
}

int
main ()
{
    test::simple t (121);
    test_sha256 (t);
    test_sha256_more (t);
    test_sha512 (t);
    test_sha224 (t);
    test_sha384 (t);
    test_sha512_224 (t);
    test_sha512_256 (t);
    test_sha1 (t);
    test_hmac_1 (t);
    test_hmac_2 (t);
    test_hmac_3 (t);
    test_hmac_4 (t);
    test_hmac_5 (t);
    test_hmac_6 (t);
    test_hmac_7 (t);
    test_rfc6238_totp (t);
    test_encode_base64_foobar (t);
    test_decode_base64_foobar (t);
    test_encode_base64 (t);
    test_decode_base64 (t);
    test_encode_base16 (t);
    test_decode_base16 (t);
    test_base64_more (t);
    test_pbkdf2_sha256 (t);
    return t.done_testing ();
}
