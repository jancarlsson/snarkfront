CXX = g++
CXXFLAGS = -O2 -g3 -std=c++11 -I.

RM = rm
LN = ln
AR = ar
RANLIB = ranlib

LIBRARY_BACK_HPP = \
	Alg_BigInt.hpp \
	Alg_bool.hpp \
	Alg_Field.hpp \
	Alg.hpp \
	Alg_internal.hpp \
	Alg_uint.hpp \
	AST.hpp \
	BigIntOps.hpp \
	BitwiseAST.hpp \
	CompilePPZK_query.hpp \
	CompilePPZK_witness.hpp \
	CompileQAP.hpp \
	Counter.hpp \
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
	HexDumper.hpp \
	InitPairing.hpp \
	Lazy.hpp \
	MerkleAuthPath.hpp \
	MerkleBundle.hpp \
	MerkleTree.hpp \
	PowersOf2.hpp \
	R1C.hpp \
	Rank1Ops.hpp \
	Serialize.hpp \
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
	test_sha

default :
	@echo Build options:
	@echo make lib PREFIX=\<path\>
	@echo make archive PREFIX=\<path\>
	@echo make tests PREFIX=\<path\>
	@echo make tools PREFIX=\<path\>
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
# PREFIX
#

ifeq ($(PREFIX),)
lib :
	$(error Please provide PREFIX, e.g. make lib PREFIX=/usr/local)

archive :
	$(error Please provide PREFIX, e.g. make archive PREFIX=/usr/local)

hodur :
	$(error Please provide PREFIX, e.g. make hodur PREFIX=/usr/local)

ppzk :
	$(error Please provide PREFIX, e.g. make ppzk PREFIX=/usr/local)

qap :
	$(error Please provide PREFIX, e.g. make qap PREFIX=/usr/local)

randomness :
	$(error Please provide PREFIX, e.g. make randomness PREFIX=/usr/local)

test_aes :
	$(error Please provide PREFIX, e.g. make test_aes PREFIX=/usr/local)

test_bundle :
	$(error Please provide PREFIX, e.g. make test_bundle PREFIX=/usr/local)

test_merkle :
	$(error Please provide PREFIX, e.g. make test_merkle PREFIX=/usr/local)

test_proof :
	$(error Please provide PREFIX, e.g. make test_proof PREFIX=/usr/local)

test_sha :
	$(error Please provide PREFIX, e.g. make test_sha PREFIX=/usr/local)

tests :
	$(error Please provide PREFIX, e.g. make tests PREFIX=/usr/local)

tools :
	$(error Please provide PREFIX, e.g. make tools PREFIX=/usr/local)

verify :
	$(error Please provide PREFIX, e.g. make verify PREFIX=/usr/local)
else
CXXFLAGS_EXTRA = \
	-I$(PREFIX)/include \
	-DUSE_ASM -DUSE_ADD_SPECIAL -DUSE_ASSERT -DPARNO_SOUNDNESS_FIX

LDFLAGS_EXTRA = -lgmpxx -lgmp
LDFLAGS = -L. -lsnarkfront

SO_FLAGS = $(CXXFLAGS) $(CXXFLAGS_EXTRA) -fPIC
AR_FLAGS = $(CXXFLAGS) $(CXXFLAGS_EXTRA)

LIBRARY_CPP = \
	Alg.cpp \
	DSL_algo.cpp \
	DSL_base.cpp \
	DSL_identity.cpp \
	DSL_utility.cpp \
	EnumOps.cpp \
	GenericProgressBar.cpp \
	Getopt.cpp \
	HexDumper.cpp \
	InitPairing.cpp \
	PowersOf2.cpp \
	Serialize.cpp

libsnarkfront.so : $(LIBRARY_HPP) $(LIBRARY_CPP)
	$(RM) -f snarkfront
	$(LN) -s . snarkfront
	$(CXX) -c $(SO_FLAGS) -o Alg.o Alg.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_algo.o DSL_algo.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_base.o DSL_base.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_identity.o DSL_identity.cpp
	$(CXX) -c $(SO_FLAGS) -o DSL_utility.o DSL_utility.cpp
	$(CXX) -c $(SO_FLAGS) -o EnumOps.o EnumOps.cpp
	$(CXX) -c $(SO_FLAGS) -o GenericProgressBar.o GenericProgressBar.cpp
	$(CXX) -c $(SO_FLAGS) -o Getopt.o Getopt.cpp
	$(CXX) -c $(SO_FLAGS) -o HexDumper.o HexDumper.cpp
	$(CXX) -c $(SO_FLAGS) -o InitPairing.o InitPairing.cpp
	$(CXX) -c $(SO_FLAGS) -o PowersOf2.o PowersOf2.cpp
	$(CXX) -c $(SO_FLAGS) -o Serialize.o Serialize.cpp
	$(RM) -f libsnarkfront.so
	$(CXX) -o libsnarkfront.so -shared $(LIBRARY_CPP:.cpp=.o)

libsnarkfront.a : $(LIBRARY_HPP) $(LIBRARY_CPP)
	$(RM) -f snarkfront
	$(LN) -s . snarkfront
	$(CXX) -c $(AR_FLAGS) -o Alg.o Alg.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_algo.o DSL_algo.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_base.o DSL_base.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_identity.o DSL_identity.cpp
	$(CXX) -c $(AR_FLAGS) -o DSL_utility.o DSL_utility.cpp
	$(CXX) -c $(AR_FLAGS) -o EnumOps.o EnumOps.cpp
	$(CXX) -c $(AR_FLAGS) -o GenericProgressBar.o GenericProgressBar.cpp
	$(CXX) -c $(AR_FLAGS) -o Getopt.o Getopt.cpp
	$(CXX) -c $(AR_FLAGS) -o HexDumper.o HexDumper.cpp
	$(CXX) -c $(AR_FLAGS) -o InitPairing.o InitPairing.cpp
	$(CXX) -c $(AR_FLAGS) -o PowersOf2.o PowersOf2.cpp
	$(CXX) -c $(AR_FLAGS) -o Serialize.o Serialize.cpp
	$(RM) -f libsnarkfront.a
	$(AR) qc libsnarkfront.a $(LIBRARY_CPP:.cpp=.o)
	$(RANLIB) libsnarkfront.a

lib : libsnarkfront.so

archive : libsnarkfront.a

hodur : hodur.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o hodur.o
	$(CXX) -o $@ hodur.o $(LDFLAGS) $(LDFLAGS_EXTRA)

ppzk : ppzk.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o ppzk.o
	$(CXX) -o $@ ppzk.o $(LDFLAGS) $(LDFLAGS_EXTRA)

qap : qap.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o qap.o
	$(CXX) -o $@ qap.o $(LDFLAGS) $(LDFLAGS_EXTRA)

randomness : randomness.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o randomness.o
	$(CXX) -o $@ randomness.o $(LDFLAGS) $(LDFLAGS_EXTRA)

test_aes : test_aes.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o test_aes.o
	$(CXX) -o $@ test_aes.o $(LDFLAGS) $(LDFLAGS_EXTRA)

test_bundle : test_bundle.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o test_bundle.o
	$(CXX) -o $@ test_bundle.o $(LDFLAGS) $(LDFLAGS_EXTRA)

test_merkle : test_merkle.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o test_merkle.o
	$(CXX) -o $@ test_merkle.o $(LDFLAGS) $(LDFLAGS_EXTRA)

test_proof : test_proof.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o test_proof.o
	$(CXX) -o $@ test_proof.o $(LDFLAGS) $(LDFLAGS_EXTRA)

test_sha : test_sha.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o test_sha.o
	$(CXX) -o $@ test_sha.o $(LDFLAGS) $(LDFLAGS_EXTRA)

tests : $(LIBRARY_TESTS)

tools : $(LIBRARY_BIN)

verify : verify.cpp libsnarkfront.a
	$(CXX) -c $(CXXFLAGS) $(CXXFLAGS_EXTRA) $< -o verify.o
	$(CXX) -o $@ verify.o $(LDFLAGS) $(LDFLAGS_EXTRA)
endif
