DIGEST_TEST=digest-test
DIGEST_TESTOBJ=digest-base.o digest-sha-256.o digest-sha-512.o \
	       digest-sha-1.o \
	       mime-base64.o mime-base32.o mime-base16.o

AES_TEST=cipher-aes-test
AES_TESTOBJ=cipher-aes.o

GHASH_TEST=digest-ghash-test
GHASH_TESTOBJ=digest-ghash.o digest-base.o mime-base16.o

AES_GCM_TEST=cipher-aes-gcm-test
AES_GCM_TESTOBJ=cipher-aes-gcm.o cipher-aes.o digest-ghash.o digest-base.o mime-base16.o

AES_CMAC_TEST=digest-aes-cmac-test
AES_CMAC_TESTOBJ=digest-base.o cipher-aes.o digest-aes-cmac.o mime-base16.o

AES_SIV_TEST=cipher-aes-siv-test
AES_SIV_TESTOBJ=cipher-aes-siv.o digest-base.o cipher-aes.o digest-aes-cmac.o mime-base16.o

POLY1305_TEST=digest-poly1305-test
POLY1305_TESTOBJ=digest-base.o digest-poly1305.o mime-base16.o

CHACHA20_TEST=cipher-chacha20-test
CHACHA20_TESTOBJ=cipher-chacha20.o digest-base.o digest-poly1305.o mime-base16.o

PROGS=$(DIGEST_TEST) $(AES_TEST) $(GHASH_TEST) $(AES_GCM_TEST) \
      $(AES_CMAC_TEST) $(AES_SIV_TEST) \
      $(POLY1305_TEST) $(CHACHA20_TEST)
OBJS=$(DIGEST_TESTOBJ) $(AES_TESTOBJ) $(GHASH_TESTOBJ) $(AES_GCM_TESTOBJ) \
     $(AES_CMAC_TESTOBJ) $(AES_SIV_TESTOBJ) \
     $(POLY1305_TESTOBJ) $(CHACHA20_TESTOBJ)

CXX=clang++ -std=c++11
#CXX=g++ -std=c++11
CXXFLAGS=-Wall -O3

PROVE=
#PROVE=prove

all : $(PROGS)

digest-base.o : digest.hpp digest-base.cpp
	$(CXX) $(CXXFLAGS) -c digest-base.cpp -o $@

digest-sha-256.o : digest.hpp digest-sha-256.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-256.cpp -o $@

digest-sha-512.o : digest.hpp digest-sha-512.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-512.cpp -o $@

digest-sha-1.o : digest.hpp digest-sha-1.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-1.cpp -o $@

digest-ghash.o : digest-ghash.hpp digest-ghash.cpp
	$(CXX) $(CXXFLAGS) -c digest-ghash.cpp -o $@

digest-aes-cmac.o : digest-aes-cmac.hpp digest-aes-cmac.cpp
	$(CXX) $(CXXFLAGS) -c digest-aes-cmac.cpp -o $@

digest-poly1305.o : digest-poly1305.hpp digest-poly1305.cpp
	$(CXX) $(CXXFLAGS) -c digest-poly1305.cpp -o $@

mime-base64.o : mime-base64.hpp mime-base64.cpp
	$(CXX) $(CXXFLAGS) -c mime-base64.cpp -o $@

mime-base32.o : mime-base32.hpp mime-base32.cpp
	$(CXX) $(CXXFLAGS) -c mime-base32.cpp -o $@

mime-base16.o : mime-base16.hpp mime-base16.cpp
	$(CXX) $(CXXFLAGS) -c mime-base16.cpp -o $@

cipher-aes.o : cipher-aes.hpp cipher-aes.cpp
	$(CXX) $(CXXFLAGS) -c cipher-aes.cpp -o $@

cipher-chacha20.o : cipher-chacha20.hpp cipher-chacha20.cpp
	$(CXX) $(CXXFLAGS) -c cipher-chacha20.cpp -o $@

cipher-aes-siv.o : cipher-aes-siv.hpp cipher-aes-siv.cpp
	$(CXX) $(CXXFLAGS) -c cipher-aes-siv.cpp -o $@

cipher-aes-gcm.o : cipher-aes-gcm.hpp cipher-aes-gcm.cpp
	$(CXX) $(CXXFLAGS) -c cipher-aes-gcm.cpp -o $@

test : $(DIGEST_TEST) $(AES_TEST) $(AES_GCM_TEST) $(AES_CMAC_TEST) $(AES_SIV_TEST) $(POLY1305_TEST) $(CHACHA20_TEST)
	$(PROVE) ./$(DIGEST_TEST)
	$(PROVE) ./$(AES_TEST)
	$(PROVE) ./$(AES_GCM_TEST)
	$(PROVE) ./$(AES_CMAC_TEST)
	$(PROVE) ./$(AES_SIV_TEST)
	$(PROVE) ./$(POLY1305_TEST)
	$(PROVE) ./$(CHACHA20_TEST)

$(DIGEST_TEST) : digest.hpp pkcs5-pbkdf2.hpp taptests.hpp digest-test.cpp $(DIGEST_TESTOBJ)
	$(CXX) $(CXXFLAGS) digest-test.cpp $(DIGEST_TESTOBJ) -o $@

$(AES_TEST) : cipher-aes.hpp taptests.hpp cipher-aes-test.cpp $(AES_TESTOBJ)
	$(CXX) $(CXXFLAGS) cipher-aes-test.cpp $(AES_TESTOBJ) -o $@

$(GHASH_TEST) : taptests.hpp digest-ghash-test.cpp $(GHASH_TESTOBJ)
	$(CXX) $(CXXFLAGS) digest-ghash-test.cpp $(GHASH_TESTOBJ) -o $@

$(AES_GCM_TEST) : cipher-aes.hpp cipher-aes-gcm.hpp taptests.hpp cipher-aes-gcm-test.cpp $(AES_GCM_TESTOBJ)
	$(CXX) $(CXXFLAGS) cipher-aes-gcm-test.cpp $(AES_GCM_TESTOBJ) -o $@

$(AES_CMAC_TEST) : cipher-aes.hpp taptests.hpp digest-aes-cmac-test.cpp $(AES_CMAC_TESTOBJ)
	$(CXX) $(CXXFLAGS) digest-aes-cmac-test.cpp $(AES_CMAC_TESTOBJ) -o $@

$(AES_SIV_TEST) : cipher-aes.hpp cipher-aes-siv.hpp taptests.hpp cipher-aes-siv-test.cpp $(AES_SIV_TESTOBJ)
	$(CXX) $(CXXFLAGS) cipher-aes-siv-test.cpp $(AES_SIV_TESTOBJ) -o $@

$(POLY1305_TEST) : digest-poly1305.hpp taptests.hpp digest-poly1305-test.cpp $(POLY1305_TESTOBJ)
	$(CXX) $(CXXFLAGS) digest-poly1305-test.cpp $(POLY1305_TESTOBJ) -o $@

$(CHACHA20_TEST) : cipher-chacha20.hpp digest-poly1305.hpp taptests.hpp cipher-chacha20-test.cpp $(CHACHA20_TESTOBJ)
	$(CXX) $(CXXFLAGS) cipher-chacha20-test.cpp $(CHACHA20_TESTOBJ) -o $@

clean :
	rm -f $(PROGS) $(OBJS)
