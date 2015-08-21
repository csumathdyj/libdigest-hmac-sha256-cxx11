#include "digest.hpp"
#include "taptests.hpp"

void
test_md5 (test::simple& t)
{
    digest::MD5 md5;
    t.ok (md5.hexdigest ()
        == "d41d8cd98f00b204e9800998ecf8427e", "md5 empty data");
    t.ok (md5.add ("abc").hexdigest ()
        == "900150983cd24fb0d6963f7d28e17f72", "md5 a");
    t.ok (md5.add ("abcdbcdecdefdefgefghfghighijhijkijkl").hexdigest ()
        == "1abfcd9645d94ffc9f14286a365988d6", "md5 b");
    t.ok (md5.add ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
             .hexdigest ()
        == "8215ef0796a20bcaaae116d3876c664a", "md5 c");

    digest::base& h = md5;
    h.add ("abc");
    t.ok (h.hexdigest ()
        == "900150983cd24fb0d6963f7d28e17f72", "md5 d");
}

void
test_sha256 (test::simple& t)
{
    digest::SHA256 sha256;
    t.ok (sha256.add ("").hexdigest ()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256 empty data");

    t.ok (sha256.add ("The quick brown fox jumps over the lazy dog.").hexdigest ()
        == "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        "sha256 quick brown...");

    digest::base& h = sha256;
    h.add ("The quick brown fox jumps over the lazy dog.");
    t.ok (h.hexdigest ()
        == "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        "sha256 c");
    h.reset ();
    h.add ("The quick brown fox ");
    h.add ("jumps over the lazy dog.");
    t.ok (h.hexdigest ()
        == "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
        "sha256 d");
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
        "http sha-256 digest response");
}

void
test_hmac_sha256 (test::simple& t)
{
    digest::HMAC<digest::SHA256> hmac1 (
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"
        "\x0b\x0b\x0b\x0b");
    t.ok (hmac1.add ("Hi There").hexdigest ()
        == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "hmac-sha256 rfc 4231 test case 1");

    digest::HMAC<digest::SHA256> hmac2 ("Jefe");
    t.ok (hmac2.add ("what do ya want for nothing?").hexdigest ()
        == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "hmac-sha256 rfc 4231 test case 2");

    digest::HMAC<digest::SHA256> hmac3 (
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        "\xaa\xaa\xaa");
    t.ok (hmac3.add ("Test Using Larger Than Block-Size Key - Hash Key First")
               .hexdigest ()
        == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "hmac-sha256 rfc 4231 test case 6");

    digest::base& h = hmac3;
    t.ok (h.add ("This is a test using a larger than block-size ke"
                 "y and a larger than block-size data. The key nee"
                 "ds to be hashed before being used by the HMAC al"
                 "gorithm.")
               .hexdigest ()
        == "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        "hmac-sha256 rfc 4231 test case 7");
}

int
main ()
{
    test::simple t (14);
    test_md5 (t);
    test_sha256 (t);
    test_sha256_more (t);
    test_hmac_sha256 (t);
    return t.done_testing ();
}
