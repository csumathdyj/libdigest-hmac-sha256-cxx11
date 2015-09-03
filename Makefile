TESTEXEC=test-digest
OBJECTS=digest-base.o digest-md5.o digest-sha-256.o \
	mime-base64.o \
	pbkdf2-sha256.o

CXX=clang++ -std=c++11
#CXX=g++ -std=c++11
CXXFLAGS=-Wall -O2

all : $(OBJECTS)

digest-base.o : digest.hpp digest-base.cpp
	$(CXX) $(CXXFLAGS) -c digest-base.cpp

digest-md5.o : digest.hpp digest-md5.cpp
	$(CXX) $(CXXFLAGS) -c digest-md5.cpp

digest-sha-256.o : digest.hpp digest-sha-256.cpp
	$(CXX) $(CXXFLAGS) -c digest-sha-256.cpp

mime-base64.o : mime-base64.hpp mime-base64.cpp
	$(CXX) $(CXXFLAGS) -c mime-base64.cpp

pbkdf2-sha256.o : pbkdf2-sha256.hpp pbkdf2-sha256.cpp
	$(CXX) $(CXXFLAGS) -c pbkdf2-sha256.cpp

test : $(TESTEXEC)
	./$(TESTEXEC)

$(TESTEXEC) : digest.hpp taptests.hpp test.cpp $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TESTEXEC) test.cpp $(OBJECTS)

clean :
	rm -f $(TESTEXEC) $(OBJECTS)
