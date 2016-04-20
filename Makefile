DIGEST_TEST=digest-test
DIGEST_TESTOBJ=digest-base.o digest-sha-256.o digest-sha-512.o \
	       digest-sha-1.o \
	       mime-base64.o mime-base32.o mime-base16.o

PROGS=$(DIGEST_TEST)
OBJS=$(DIGEST_TESTOBJ)

CXX=clang++ -std=c++11
#CXX=g++ -std=c++11
CXXFLAGS=-Wall -O3

PROVE=
#PROVE=prove

all : $(PROGS)

digest-base.o : digest.hpp digest-base.cpp
	$(CXX) $(CXXFLAGS) -c digest-base.cpp

digest-sha-256.o : digest.hpp digest-sha-256.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-256.cpp

digest-sha-512.o : digest.hpp digest-sha-512.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-512.cpp

digest-sha-1.o : digest.hpp digest-sha-1.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-1.cpp

mime-base64.o : mime-base64.hpp mime-base64.cpp
	$(CXX) $(CXXFLAGS) -c mime-base64.cpp

mime-base32.o : mime-base32.hpp mime-base32.cpp
	$(CXX) $(CXXFLAGS) -c mime-base32.cpp

mime-base16.o : mime-base16.hpp mime-base16.cpp
	$(CXX) $(CXXFLAGS) -c mime-base16.cpp

test : $(DIGEST_TEST)
	$(PROVE) ./$(DIGEST_TEST)

$(DIGEST_TEST) : digest.hpp pkcs5-pbkdf2.hpp taptests.hpp digest-test.cpp $(DIGEST_TESTOBJ)
	$(CXX) $(CXXFLAGS) -o $(DIGEST_TEST) digest-test.cpp $(DIGEST_TESTOBJ)

clean :
	rm -f $(PROGS) $(OBJS)
