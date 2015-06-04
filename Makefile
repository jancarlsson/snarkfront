CXX = g++
CXXFLAGS = -O2 -g3 -std=c++11 -I.

RM = rm
LN = ln
AR = ar
RANLIB = ranlib

LIBRARY_BACK_HPP = \
	AdvancedEncryptionStd.hpp \
	AES_Cipher.hpp \
	AES_InvCipher.hpp \
	AES_InvSBox.hpp \
	AES_KeyExpansion.hpp \
	AES_SBox.hpp \
	Alg_BigInt.hpp \
	Alg_bool.hpp \
	Alg_Field.hpp \
	Alg.hpp \
	Alg_internal.hpp \
	Alg_uint.hpp \
	AST.hpp \
	BigIntOps.hpp \
	BitwiseAST.hpp \
	BitwiseINT.hpp \
	CompilePPZK_query.hpp \
	CompilePPZK_witness.hpp \
	CompileQAP.hpp \
	Counter.hpp \
	DataBuffer.hpp \
	DSL_algo.hpp \
	DSL_base.hpp \
	DSL_bless.hpp \
	DSL_identity.hpp \
	DSL_ppzk.hpp \
	DSL_utility.hpp \
	EnumOps.hpp \
	EvalAST.hpp \
	GenericProgressBar.hpp \
	Getopt.hpp \
	HexUtil.hpp \
	InitPairing.hpp \
	Lazy.hpp \
	MerkleAuthPath.hpp \
	MerkleBundle.hpp \
	MerkleTree.hpp \
	PowersOf2.hpp \
	R1C.hpp \
	Rank1Ops.hpp \
	SecureHashStd.hpp \
	Serialize.hpp \
	SHA_1.hpp \
	SHA_224.hpp \
	SHA_256.hpp \
	SHA_384.hpp \
	SHA_512_224.hpp \
	SHA_512_256.hpp \
	SHA_512.hpp \
	TLsingleton.hpp

LIBRARY_FRONT_HPP = \
	snarkfront.hpp

LIBRARY_HPP = \
	$(LIBRARY_BACK_HPP) \
	$(LIBRARY_FRONT_HPP)

LIBRARY_BIN = \
	hodur \
	randomness \
	qap \
	ppzk \
	verify

LIBRARY_TESTS = \
	test_aes \
	test_bundle \
	test_merkle \
	test_proof \
	test_sha \
	test_SHAVS

default :
	@echo Build options:
	@echo make lib SNARKLIB_PREFIX=\<path\>
	@echo make archive SNARKLIB_PREFIX=\<path\>
	@echo make tests SNARKLIB_PREFIX=\<path\>
	@echo make tools SNARKLIB_PREFIX=\<path\>
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
	mkdir -p $(PREFIX)/include/snarkfront $(PREFIX)/lib $(PREFIX)/bin
	cp libsnarkfront.* $(PREFIX)/lib
	cp $(LIBRARY_BACK_HPP) $(PREFIX)/include/snarkfront
	cp $(LIBRARY_FRONT_HPP) $(PREFIX)/include
	cp $(LIBRARY_BIN) $(PREFIX)/bin
endif

CLEAN_FILES = \
	libsnarkfront.so \
	libsnarkfront.a \
	$(LIBRARY_TESTS) \
	$(LIBRARY_BIN) \
	README.html \
	input.txt \
	keygen.txt \
	proof.txt

clean :
	rm -f *.o $(CLEAN_FILES) tmp_test_cli.* snarkfront


################################################################################
# SNARKLIB_PREFIX
#

ifeq ($(SNARKLIB_PREFIX),)
lib :
	$(error Please provide SNARKLIB_PREFIX, e.g. make lib SNARKLIB_PREFIX=/usr/local)

archive :
	$(error Please provide SNARKLIB_PREFIX, e.g. make archive SNARKLIB_PREFIX=/usr/local)

hodur :
	$(error Please provide SNARKLIB_PREFIX, e.g. make hodur SNARKLIB_PREFIX=/usr/local)

ppzk :
	$(error Please provide SNARKLIB_PREFIX, e.g. make ppzk SNARKLIB_PREFIX=/usr/local)

qap :
	$(error Please provide SNARKLIB_PREFIX, e.g. make qap SNARKLIB_PREFIX=/usr/local)

randomness :
	$(error Please provide SNARKLIB_PREFIX, e.g. make randomness SNARKLIB_PREFIX=/usr/local)

test_aes :
	$(error Please provide SNARKLIB_PREFIX, e.g. make test_aes SNARKLIB_PREFIX=/usr/local)

test_bundle :
	$(error Please provide SNARKLIB_PREFIX, e.g. make test_bundle SNARKLIB_PREFIX=/usr/local)

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

tools :
	$(error Please provide SNARKLIB_PREFIX, e.g. make tools SNARKLIB_PREFIX=/usr/local)

verify :
	$(error Please provide SNARKLIB_PREFIX, e.g. make verify SNARKLIB_PREFIX=/usr/local)
else
CXXFLAGS_SNARKLIB = \
	-I$(SNARKLIB_PREFIX)/include \
	-DUSE_ASM -DUSE_ADD_SPECIAL -DUSE_ASSERT -DPARNO_SOUNDNESS_FIX

LDFLAGS_SNARKLIB = -lgmpxx -lgmp
LDFLAGS = -L. -lsnarkfront

SO_FLAGS = $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) -fPIC
AR_FLAGS = $(CXXFLAGS) $(CXXFLAGS_SNARKLIB)

LIBRARY_CPP = \
	Alg.cpp \
	DataBuffer.cpp \
	DSL_base.cpp \
	DSL_bless.cpp \
	DSL_identity.cpp \
	DSL_utility.cpp \
	EnumOps.cpp \
	GenericProgressBar.cpp \
	Getopt.cpp \
	HexUtil.cpp \
	InitPairing.cpp \
	PowersOf2.cpp \
	Serialize.cpp

libsnarkfront.so : $(LIBRARY_HPP) $(LIBRARY_CPP)
	$(RM) -f snarkfront
	$(LN) -s . snarkfront
	$(CXX) -c $(SO_FLAGS) -o Alg.o Alg.cpp
	$(CXX) -c $(SO_FLAGS) -o DataBuffer.o DataBuffer.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_base.o DSL_base.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_bless.o DSL_bless.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_identity.o DSL_identity.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_utility.o DSL_utility.cpp
	$(CXX) -c $(SO_FLAGS) -o EnumOps.o EnumOps.cpp
	$(CXX) -c $(SO_FLAGS) -o GenericProgressBar.o GenericProgressBar.cpp
	$(CXX) -c $(SO_FLAGS) -o Getopt.o Getopt.cpp
	$(CXX) -c $(SO_FLAGS) -o HexUtil.o HexUtil.cpp
	$(CXX) -c $(SO_FLAGS) -o InitPairing.o InitPairing.cpp
	$(CXX) -c $(SO_FLAGS) -o PowersOf2.o PowersOf2.cpp
	$(CXX) -c $(SO_FLAGS) -o Serialize.o Serialize.cpp
	$(RM) -f libsnarkfront.so
	$(CXX) -o libsnarkfront.so -shared $(LIBRARY_CPP:.cpp=.o)

libsnarkfront.a : $(LIBRARY_HPP) $(LIBRARY_CPP)
	$(RM) -f snarkfront
	$(LN) -s . snarkfront
	$(CXX) -c $(AR_FLAGS) -o Alg.o Alg.cpp
	$(CXX) -c $(AR_FLAGS) -o DataBuffer.o DataBuffer.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_base.o DSL_base.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_bless.o DSL_bless.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_identity.o DSL_identity.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_utility.o DSL_utility.cpp
	$(CXX) -c $(AR_FLAGS) -o EnumOps.o EnumOps.cpp
	$(CXX) -c $(AR_FLAGS) -o GenericProgressBar.o GenericProgressBar.cpp
	$(CXX) -c $(AR_FLAGS) -o Getopt.o Getopt.cpp
	$(CXX) -c $(AR_FLAGS) -o HexUtil.o HexUtil.cpp
	$(CXX) -c $(AR_FLAGS) -o InitPairing.o InitPairing.cpp
	$(CXX) -c $(AR_FLAGS) -o PowersOf2.o PowersOf2.cpp
	$(CXX) -c $(AR_FLAGS) -o Serialize.o Serialize.cpp
	$(RM) -f libsnarkfront.a
	$(AR) qc libsnarkfront.a $(LIBRARY_CPP:.cpp=.o)
	$(RANLIB) libsnarkfront.a

lib : libsnarkfront.so

archive : libsnarkfront.a

hodur : hodur.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o hodur.o
	$(CXX) -o $@ hodur.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

ppzk : ppzk.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o ppzk.o
	$(CXX) -o $@ ppzk.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

qap : qap.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o qap.o
	$(CXX) -o $@ qap.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

randomness : randomness.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o randomness.o
	$(CXX) -o $@ randomness.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

test_aes : test_aes.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_aes.o
	$(CXX) -o $@ test_aes.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

test_bundle : test_bundle.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_bundle.o
	$(CXX) -o $@ test_bundle.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

test_merkle : test_merkle.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_merkle.o
	$(CXX) -o $@ test_merkle.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

test_proof : test_proof.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_proof.o
	$(CXX) -o $@ test_proof.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

test_sha : test_sha.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_sha.o
	$(CXX) -o $@ test_sha.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

test_SHAVS : test_SHAVS.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o test_SHAVS.o
	$(CXX) -o $@ test_SHAVS.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)

tests : $(LIBRARY_TESTS)

tools : $(LIBRARY_BIN)

verify : verify.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_SNARKLIB) $< -o verify.o
	$(CXX) -o $@ verify.o $(LDFLAGS) $(LDFLAGS_SNARKLIB)
endif
