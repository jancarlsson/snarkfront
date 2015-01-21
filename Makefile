CXX = g++
CXXFLAGS = -O2 -g3 -std=c++11

AR = ar
RANLIB = ranlib

LIBRARY_HPP = \
	Alg_BigInt.hpp \
	Alg_bool.hpp \
	Alg.hpp \
	Alg_uint.hpp \
	AST.hpp \
	BigIntOps.hpp \
	BitwiseOps.hpp \
	Counter.hpp \
	DataBuffer.hpp \
	DSL_base.hpp \
	DSL_bless.hpp \
	DSL_identity.hpp \
	DSL_ppzk.hpp \
	DSL_utility.hpp \
	EnumOps.hpp \
	EvalAST.hpp \
	GenericProgressBar.hpp \
	HexUtil.hpp \
	InitPairing.hpp \
	Lazy.hpp \
	MerkleTree.hpp \
	PowersOf2.hpp \
	R1C.hpp \
	Rank1Ops.hpp \
	SecureHashStd.hpp \
	SHA_1.hpp \
	SHA_224.hpp \
	SHA_256.hpp \
	SHA_384.hpp \
	SHA_512_224.hpp \
	SHA_512_256.hpp \
	SHA_512.hpp \
	snarkfront.hpp \
	TLsingleton.hpp

default :
	@echo Build options:
	@echo make lib SNARKLIB_PREFIX=\<path\>
	@echo make archive SNARKLIB_PREFIX=\<path\>
	@echo make tests SNARKLIB_PREFIX=\<path\>
	@echo make install PREFIX=\<path\>
	@echo make doc
	@echo make clean

README.html : README.md
	markdown_py -f README.html README.md -x toc -x extra --noisy

doc : README.html

ifeq ($(PREFIX),)
install :
	$(error Please provide PREFIX, e.g. make install PREFIX=/usr/local)
else
install :
	mkdir -p $(PREFIX)/include/snarkfront $(PREFIX)/lib
	cp libsnarkfront.* $(PREFIX)/lib
	cp $(LIBRARY_HPP) $(PREFIX)/include/snarkfront
endif

CLEAN_FILES = \
	libsnarkfront.so \
	libsnarkfront.a \
	test_merkle \
	test_proof \
	test_sha \
	test_SHAVS \
	README.html \
	input.txt \
	keygen.txt \
	proof.txt

clean :
	rm -f *.o $(CLEAN_FILES)


################################################################################
# SNARKLIB_PREFIX
#

ifeq ($(SNARKLIB_PREFIX),)
lib :
	$(error Please provide SNARKLIB_PREFIX, e.g. make lib SNARKLIB_PREFIX=/usr/local)

archive :
	$(error Please provide SNARKLIB_PREFIX, e.g. make archive SNARKLIB_PREFIX=/usr/local)

test_merkle :
	$(error Please provide SNARKLIB_PREFIX, e.g. make test_merkle SNARKLIB_PREFIX=/usr/local)

test_proof :
	$(error Please provide SNARKLIB_PREFIX, e.g. make test_proof SNARKLIB_PREFIX=/usr/local)

test_sha :
	$(error Please provide SNARKLIB_PREFIX, e.g. make test_sha SNARKLIB_PREFIX=/usr/local)

test_SHAVS :
	$(error Please provide SNARKLIB_PREFIX, e.g. make test_SHAVS SNARKLIB_PREFIX=/usr/local)

tests :
	$(error Please provide SNARKLIB_PREFIX, e.g. make tests SNARKLIB_PREFIX=/usr/local)
else
CXXFLAGS_SNARKLIB = -I$(SNARKLIB_PREFIX)/include/snarklib -DUSE_ASM -DUSE_ADD_SPECIAL -DUSE_ASSERT
LDFLAGS_SNARKLIB = -lgmpxx -lgmp

SO_FLAGS = $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) -fPIC
AR_FLAGS = $(CXXFLAGS) $(CXXFLAGS_SNARKLIB)

LIBRARY_CPP = \
	EnumOps.cpp \
	DataBuffer.cpp \
	DSL_base.cpp \
	DSL_bless.cpp \
	DSL_identity.cpp \
	DSL_utility.cpp \
	GenericProgressBar.cpp \
	HexUtil.cpp \
	InitPairing.cpp \
	PowersOf2.cpp

libsnarkfront.so : $(LIBRARY_HPP) $(LIBRARY_CPP)
	$(CXX) -c $(SO_FLAGS) -o EnumOps.o EnumOps.cpp
	$(CXX) -c $(SO_FLAGS) -o DataBuffer.o DataBuffer.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_base.o DSL_base.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_bless.o DSL_bless.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_identity.o DSL_identity.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_utility.o DSL_utility.cpp
	$(CXX) -c $(SO_FLAGS) -o GenericProgressBar.o GenericProgressBar.cpp
	$(CXX) -c $(SO_FLAGS) -o HexUtil.o HexUtil.cpp
	$(CXX) -c $(SO_FLAGS) -o InitPairing.o InitPairing.cpp
	$(CXX) -c $(SO_FLAGS) -o PowersOf2.o PowersOf2.cpp
	$(CXX) -o libsnarkfront.so -shared $(LIBRARY_CPP:.cpp=.o)

libsnarkfront.a : $(LIBRARY_HPP) $(LIBRARY_CPP)
	$(CXX) -c $(AR_FLAGS) -o EnumOps.o EnumOps.cpp
	$(CXX) -c $(AR_FLAGS) -o DataBuffer.o DataBuffer.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_base.o DSL_base.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_bless.o DSL_bless.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_identity.o DSL_identity.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_utility.o DSL_utility.cpp
	$(CXX) -c $(AR_FLAGS) -o GenericProgressBar.o GenericProgressBar.cpp
	$(CXX) -c $(AR_FLAGS) -o HexUtil.o HexUtil.cpp
	$(CXX) -c $(AR_FLAGS) -o InitPairing.o InitPairing.cpp
	$(CXX) -c $(AR_FLAGS) -o PowersOf2.o PowersOf2.cpp
	$(AR) qc libsnarkfront.a $(LIBRARY_CPP:.cpp=.o)
	$(RANLIB) libsnarkfront.a

lib : libsnarkfront.so

archive : libsnarkfront.a

test_merkle : test_merkle.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_merkle.o
	$(CXX) -o $@ test_merkle.o $(LDFLAGS_SNARKLIB) libsnarkfront.a

test_proof : test_proof.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_proof.o
	$(CXX) -o $@ test_proof.o $(LDFLAGS_SNARKLIB) libsnarkfront.a

test_sha : test_sha.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_sha.o
	$(CXX) -o $@ test_sha.o $(LDFLAGS_SNARKLIB) libsnarkfront.a

test_SHAVS : test_SHAVS.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_SHAVS.o
	$(CXX) -o $@ test_SHAVS.o $(LDFLAGS_SNARKLIB) libsnarkfront.a

tests : test_merkle test_proof test_sha test_SHAVS
endif
