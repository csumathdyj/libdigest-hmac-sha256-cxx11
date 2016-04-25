SHA-2, HMAC, PBKDF2
=================

SHA-256, SHA-384, SHA-512, SHA-512/256 classes,
HMAC class template,
PKCS#5 PBKDF2 template function,
MIME BASE 64/32/16 encoding and decoding functions,
CMAC and AES-SIV class,
GHASH and AES-GCM class,
POLY1305 and CHACHA20 class,
for C++11.

SYNOPSIS
--------

    #include "digest.hpp"
    digest::SHA256 digest_object;
    digest::HMAC<digest::SHA256> digest_object (std::string const& key);
    digest::base& digest_object.add (std::string const& data);
    std::string octets = digest_object.digest ();
    std::string hexlower = digest_object.hexdigest ();
    digest::base& digest_object.reset ();
    digest::base& digest_object.finish ();

    #include "mime-base64.hpp"
    std::string base64 = encode_base64 (std::string const& octets,
        std::string const& endline = "\n", int const width = 76);
    std::string b64url = mime::encode_base64url (std::string const& octets);
    std::string b64crypt = mime::encode_base64crypt (std::string const& octets);
    bool mime::decode_base64 (std::string const& base64, std::string& octets);
    bool mime::decode_base64url (std::string const& b64url, std::string& octets);
    bool mime::decode_base64crypt (std::string const& b64crype, std::string& octets);

    #include "mime-base32.hpp"
    std::string base32 = mime::encode_base32 (std::string const& octets,
        std::string const& endline = "\n", int const width = 76);
    std::string b32hex = mime::encode_base32hex (std::string const& octets,
        std::string const& endline = "\n", int const width = 76);
    bool mime::decode_base32 (std::string const& base32, std::string& octets);
    bool mime::decode_base32hex (std::string const& b32hex, std::string& octets);

    #include "mime-base16.hpp"
    std::string base16 = mime::encode_base16 (std::string const& octets,
        std::string const& endline = "\n", int const width = 76);
    std::string hex = mime::encode_hex (std::string const& octets,
        std::string const& endline = "", int const width = 76);
    bool mime::decode_base16 (std::string const& base16, std::string& octets);
    bool mime::decode_hex (std::string const& hex, std::string& octets);

    #include "pkcs5-pbkdf2.hpp"
    std::string key_octets = pkcs5::pbkdf2<digest::HMAC<digest::SHA256>> (
        std::string const& password, std::string const& salt,
        std::size_t const rounds, std::size_t keylen);

DESCRIPTION
-----------

To calculate a SHA-1 message digest, use SHA1 class.

To calculate a SHA-224 message digest, use SHA224 class.

To calculate a SHA-256 message digest, use SHA256 class.

To calculate a SHA-384 message digest, use SHA384 class.

To calculate a SHA-512 message digest, use SHA512 class.

To calculate a SHA-512/224 message digest, use SHA512_224 class.

To calculate a SHA-512/256 message digest, use SHA512_256 class.

To calculate a HMAC message authentication code, use HMAC class
template. Its constructor creates the digest object with
a key argument as a std::string. It uses the key over the
object life time. Currently, there is no method changing key
settings.

To calculate a PKCS#5 PBKDF2 key derivation code,
use pkcs5::pbkdf2 template function.

They calculate from the sequences of byte-oriented input data
as a std::string to call add member function repeatedly.
After the sequences, call hexdigest or digest member function
to get a message digest or a message authuncitation code
as a std::string. Once after calling digest or hexdigest member
function, the digest object teminates the previous input data
sequences. So that calling add member function on termination
starts new sequences of input data to calculate another code.
To terminate input sequences explicitly, call finish member
function. It calls automatically before digest or hexdigest
member function. To discard data input sequences, call reset
member function. It initialises the digest object as same as
the situation just creating it.

Current version accepts only byte-oriented input data.
Bit-oriented data are not available.

The representation of the output vector is octets by digest
member function. One is lowercase hexdecimals by hexdigest
member function. To get uppercase hexdecimals, use mime-base16
functions. To get Base 64 text, use mime-base64 functions.

SHA-256 AND HMAC-SHA-256 EXAMPLE
----------------------------

    #include "digest.hpp"
    #include <string>
    
    void
    example_sha256 ()
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
        //=> 753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1
    }

    void
    example_hmac_sha256 ()
    {
        // RFC 4231 HMAC-SHA256 test case 2
        std::string key = "Jefe";
        std::string data = "what do ya want for nothing?";
        digest::HMAC<digest::SHA256> hmac (key);
        std::string got = hmac.add (data).hexdigest ();
        //=> 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    }

COPYRIGHT AND LICENSE
---------------------

Copyright (c) 2016, MIZUTANI Tociyuki  
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.
 3. Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
