DIGEST_TEST=digest-test
DIGEST_TESTOBJ=digest-base.o digest-md5.o digest-sha-256.o \
	mime-base64.o mime-base16.o \
	pbkdf2-sha256.o

AES_TEST=cipher-aes-test
AES_TESTOBJ=cipher-aes.o

GCM_TEST=cipher-gcm-test
GCM_TESTOBJ=cipher-aes.o mime-base16.o

PROGS=$(DIGEST_TEST) $(AES_TEST) $(GCM_TEST)
OBJS=$(DIGEST_TESTOBJ) $(AES_TESTOBJ) $(GCM_TESTOBJ)

CXX=clang++ -std=c++11
#CXX=g++ -std=c++11
CXXFLAGS=-Wall -O2

#PROVE=
PROVE=prove

all : $(PROGS)

digest-base.o : digest.hpp digest-base.cpp
	$(CXX) $(CXXFLAGS) -c digest-base.cpp

digest-md5.o : digest.hpp digest-md5.cpp
	$(CXX) $(CXXFLAGS) -c digest-md5.cpp

digest-sha-256.o : digest.hpp digest-sha-256.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-256.cpp

mime-base64.o : mime-base64.hpp mime-base64.cpp
	$(CXX) $(CXXFLAGS) -c mime-base64.cpp

mime-base16.o : mime-base16.hpp mime-base16.cpp
	$(CXX) $(CXXFLAGS) -c mime-base16.cpp

pbkdf2-sha256.o : pbkdf2-sha256.hpp pbkdf2-sha256.cpp
	$(CXX) $(CXXFLAGS) -c pbkdf2-sha256.cpp

cipher-aes.o : cipher-aes.hpp cipher-aes.cpp
	$(CXX) $(CXXFLAGS) -c cipher-aes.cpp

test : $(DIGEST_TEST) $(AES_TEST) $(GCM_TEST)
	$(PROVE) ./$(DIGEST_TEST)
	$(PROVE) ./$(AES_TEST)
	$(PROVE) ./$(GCM_TEST)

$(DIGEST_TEST) : digest.hpp taptests.hpp digest-test.cpp $(DIGEST_TESTOBJ)
	$(CXX) $(CXXFLAGS) -o $(DIGEST_TEST) digest-test.cpp $(DIGEST_TESTOBJ)

$(AES_TEST) : cipher-aes.hpp taptests.hpp cipher-aes-test.cpp $(AES_TESTOBJ)
	$(CXX) $(CXXFLAGS) -o $(AES_TEST) cipher-aes-test.cpp $(AES_TESTOBJ)

$(GCM_TEST) : cipher-aes.hpp cipher-gcm.hpp taptests.hpp cipher-gcm-test.cpp $(GCM_TESTOBJ)
	$(CXX) $(CXXFLAGS) -o $(GCM_TEST) cipher-gcm-test.cpp $(GCM_TESTOBJ)

clean :
	rm -f $(PROGS) $(OBJS)
