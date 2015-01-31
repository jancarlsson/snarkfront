snarkfront: a C++ embedded domain specific language for zero knowledge proofs
================================================================================

--------------------------------------------------------------------------------
Introduction
--------------------------------------------------------------------------------

The name "snarkfront" is homage to Cfront - the original C++ compiler
implementation developed at AT&T Bell Laboratories through the 1980s. Cfront
was a front-end over the native C toolchain, literally a source translator.
Somewhat analogously, snarkfront is a C++ embedded domain specific language
(EDSL) over the underlying snarklib template library.

The author suspects zero knowledge cryptography may be the new public-key, a
technology that opens up entirely new classes of applications and systems.
Public-key cryptography makes asymmetric trust relationships possible.
Zero knowledge proofs make anonymous trust relationships possible.

The author is grateful to the [SCIPR Lab] for the [GitHub libsnark project].
This project is built on top of the [GitHub snarklib project] which was made
possible by the libsnark source code release.

--------------------------------------------------------------------------------
[TOC]

<!---
  NOTE: the file you are reading is in Markdown format, which is is fairly readable
  directly, but can be converted into an HTML file with much nicer formatting.
  To do so, run "make doc" (this requires the python-markdown package) and view
  the resulting file README.html.
-->

--------------------------------------------------------------------------------
Language summary
--------------------------------------------------------------------------------

Four types:

- Boolean
- 128-bit unsigned integer scalars
- 32-bit unsigned integer words
- 64-bit unsigned integer words

The usual operators:

- logical and bitwise complement
- AND, OR, XOR, addition, subtraction, multiplication, modulo addition
- shift and rotate
- comparisons: == != < <= > >=
- ternary conditional
- type conversion between Boolean, 32-bit, 64-bit, and 128-bit

Cryptographic one-wayness:

- FIPS PUB 180-4: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- binary Merkle tree

Elliptic curve pairings:

- Barreto-Naehrig at 128 bits of security
- Edwards at 80 bits of security

Use both API and CLI toolchain:

- programmatic API with cryptographic structures in C++ templates (done)
- map-reduce cryptographic structures in files from command line (work in progress)

*The CLI allows optimizing memory locality by trading time for space.*

--------------------------------------------------------------------------------
Alice and Bob need a zero knowledge proof
--------------------------------------------------------------------------------

Alice:

    Bob, do you know the combination to this lock?

Bob:

    Yes, I do.

Alice:

    Please give me the combination.

Bob:

    If I give you the combination, you will not need me.
    The combination is my secret.

Alice:

    Bob, I need to be sure you are honest.
    A proof that you know the combination is enough.
    The actual combination may remain your secret.

One-way hash functions are the cryptographic analogue to combination locks.
The secret combination is the message input, the pre-image. The state of the
lock, either locked or unlocked, corresponds to the message digest output.

The message digest output is public knowledge just like the state of the lock.
Anyone can test the lock to see if it opens.

The message input is secret just like the combination to the lock. Only one
who knows the secret can unlock the lock.

Zero knowledge cryptography is a way for Bob to dial in the combination to
the lock without revealing it. He can hand the lock to Alice who can test the
lock and see it open. However, if she disassembles the lock, Alice learns
nothing about the combination to the lock.

--------------------------------------------------------------------------------
Honest Charles helps Alice and Bob trust each other with snarkfront
--------------------------------------------------------------------------------

- The lock is SHA-256. The problem is digest == SHA256(message).

- Alice and Bob both agree on a digest.

- Only Bob knows the message.

- Bob must prove this knowledge to Alice without revealing the secret.

- Alice and Bob trust Honest Charles who will help.

The code fragments below are incomplete to illustrate the EDSL more clearly.
However, the code is real and not pseudocode. It is almost identical to code
from the file test_proof.cpp.

Honest Charles generates a key pair for y == SHA256(x)

    // blessing allocates the variables
    array<uint32_x<FR>, 8> pubVars;
    bless(pubVars);

    // private witness variables after this
    end_input<PAIRING>();

    // prove this: pubVars == SHA256(message)
    assert_true(pubVars == digest(zk::SHA256<FR>(), ""));

    keyFile << keypair<PAIRING>();

Public input is y = pubHash

    // bless variables with values this time
    array<uint32_x<FR>, 8> pubVars;
    bless(pubVars, pubHash);

    end_input<PAIRING>();

    inputFile << input<PAIRING>();

Bob proves he knows x = secretMsg

    // key pair never changes, read in once and keep it
    Keypair<PAIRING> keypair;
    keyFile >> keypair;

    // public common knowledge
    Input<PAIRING> input;
    inputFile >> input;

    // bless variables with the message digest from public common knowledge
    array<uint32_x<FR>, 8> pubVars;
    bless(pubVars, input);

    end_input<PAIRING>();

    // this is true: pubVars == SHA256(secretMsg)
    assert_true(pubVars == digest(zk::SHA256<FR>(), secretMsg));

    proofFile << proof(keypair);

Alice verifies the proof from Bob that pubHash == SHA256(secretMsg)

    Keypair<PAIRING> keypair;
    keyFile >> keypair;

    Input<PAIRING> input;
    inputFile >> input;

    Proof<PAIRING> proof;
    proofFile >> proof;

    // check if the proof is satisfied
    const bool ok = verify(keypair, input, proof);

If ok is true, then Alice knows that Bob knows a secretMsg which SHA-256 hashes
to pubHash. Only Bob knows the value of secretMsg. No one else does, not even
Honest Charles. Bob generates a proof that he knows secretMsg without revealing
what this is.

--------------------------------------------------------------------------------
Build instructions
--------------------------------------------------------------------------------

The snarklib C++ template library is required.
It may be found here: [GitHub snarklib project]

The [GNU Multiple Precision Arithmetic Library] is also required.

The relationship between snarkfront and snarklib is symbiotic. They are two
levels of the same idea. It is convenient to install them into the same PREFIX
location.

First, install snarklib: (nothing to build because all header files)

    $ cd ~/snarklib
    $ make install PREFIX=/usr/local

Second, build and install snarkfront:

    $ cd ~/snarkfront
    $ make tools SNARKLIB_PREFIX=/usr/local
    $ make install PREFIX=/usr/local

To build the testing applications: (as statically linked)

    $ cd ~/snarkfront
    $ make tests SNARKLIB_PREFIX=/usr/local

This generates:

1. test_SHAVS  - implements NIST SHA validation suite
2. test_proof  - isolated stages for: key generation, input, proof, verify
3. test_sha    - play with zero knowledge SHA-2
4. test_merkle - play with zero knowledge Merkle trees
5. make_merkle - Merkle tree constraint system in files

--------------------------------------------------------------------------------
test_SHAVS (Secure Hash Algorithm and Verification System)
--------------------------------------------------------------------------------

This tests the zero knowledge implementation of SHA-2 included in snarkfront.
The snarkfront implementation is derived directly from the NIST standards
document [FIPS PUB 180-4]. To run these tests, download the [SHAVS] test cases
using the [SHA byte test vectors] provided as a courtesy by NIST.

If the test vectors are in directory ~/SHA_byte_test_vectors:

    $ ./test_SHAVS.sh ~/SHA_byte_test_vectors

    SHA1 Monte Carlo
    OK 0 dd4df644eaf3d85bace2b21accaa22b28821f5cd 11f5c38b4479d4ad55cb69fadf62de0b036d5163
    OK 1 11f5c38b4479d4ad55cb69fadf62de0b036d5163 5c26de848c21586bec36995809cb02d3677423d9
    OK 2 5c26de848c21586bec36995809cb02d3677423d9 453b5fcf263d01c891d7897d4013990f7c1fb0ab
    OK 3 453b5fcf263d01c891d7897d4013990f7c1fb0ab 36d0273ae363f992bbc313aa4ff602e95c207be3
    ...lots of output...

The validation tests are processed in order:

1. Monte Carlo
2. Short messages
3. Long messages

Note the Monte Carlo tests are quite fast. The short messages tests take
longer but are still reasonable. The long messages tests require much more
time.

The test_SHAVS binary has additional modes not exposed by the shell script.

    $ ./test_SHAVS
    usage: cat NIST_SHAVS_byte_test_vector_file | ./test_SHAVS -p BN128|Edwards -b 1|224|256|384|512 [-i Len|COUNT] [-p]

    example: SHA1 short messages
    cat SHA1ShortMsg.rsp | ./test_SHAVS -p BN128 -b 1

    example: SHA256 long messages with proof
    cat SHA256LongMsg.rsp | ./test_SHAVS -p Edwards -b 256 -p

    example: SHA512 Monte Carlo mode
    cat SHA512Monte.txt | ./test_SHAVS -p BN128 -b 512

    example: SHA224 short messages, only Len = 464 test case
    cat SHA224ShortMsg.rsp | ./test_SHAVS -p Edwards -b 224 -i 464

    example: SHA384 Monte Carlo mode, only COUNT = 75 test case
    cat SHA384Monte.txt | ./test_SHAVS -p BN128 -b 384 -i 75

The "-p" switch enables zero knowledge proofs. This is very expensive if run
for hundreds or thousands of test cases. For this reason, the shell script
leaves proofs disabled. (Note the snarkfront SHA-2 implementation uses the
same templates for both proof and non-proof modes. So testing in non-proof
mode does exercise the same code.)

--------------------------------------------------------------------------------
test_proof (zero knowledge proof for SHA-256)
--------------------------------------------------------------------------------

This tests the "Alice and Bob" example above where:

- the lock is SHA-256
- the secret combination is message: "abc"
- the state is unlocked if the message digest matches: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

Just run the shell script:

    $ ./test_proof.sh 

    generate key pair
    (8) ..................................................
    (7) ..................................................
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................

    real    0m37.271s
    user    0m33.105s
    sys     0m3.970s
    -rw-rw-r--. 1 jcarlsson jcarlsson 169178776 Jan 21 01:13 keygen.txt


    real    0m0.006s
    user    0m0.002s
    sys     0m0.004s
    -rw-rw-r--. 1 jcarlsson jcarlsson 10044 Jan 21 01:13 input.txt

    generate proof
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................

    real    0m15.744s
    user    0m15.593s
    sys     0m0.534s
    -rw-rw-r--. 1 jcarlsson jcarlsson 2092 Jan 21 01:13 proof.txt

    verify proof ......
    proof is verified

    real    0m8.566s
    user    0m8.467s
    sys     0m0.404s

Equivalently:

(generate the proving and verification keys)

    $ ./test_proof -m keygen > keygen.txt

(public input)

    $ ./test_proof -m input > input.txt

(generate a proof using the secret)

    $ cat keygen.txt input.txt | ./test_proof -m proof > proof.txt

(verify the proof)

    $ cat keygen.txt input.txt proof.txt | ./test_proof -m verify

Note how expensive key pair generation is in comparison with the proof and
verification. This is typical. The proving key will be very large and take a
long time to generate. However, it only has to be done once at the very
beginning and then is reused forever by all parties.

*The entity or multi-party protocol generating the key pair is trusted!*

This test is realistic in the sense that each stage is properly blinded to
inadvertant knowledge which it can not know. Each of the four stages only
has the information it should possess.

--------------------------------------------------------------------------------
test_sha (zero knowledge SHA-2)
--------------------------------------------------------------------------------

The usage message explains how to run this.

    $ ./test_sha 
    usage: ./test_sha -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256 [-r]

    text from standard input:
    echo "abc" | ./test_sha -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256

    random data:
    ./test_sha -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256 -r

Two elliptic curves are supported.

- Barreto-Naehrig at 128 bits, use option: "-p BN128"
- Edwards at 80 bits, use option: "-p Edwards"

All SHA-2 variants are supported, use option: "-b number" which selects algorithm
SHA-number.

The "-r" switch fills the message with random bytes drawn from /dev/urandom.
Otherwise, the message input is read from standard input. Note the random data
fills the entire message block and is intentionally not padded. It is often useful
to use the SHA-2 compression function without padding in zero knowledge proofs.

Some examples:

(SHA-256 hash of "abc" using Barreto-Naehrig elliptic curve)

    $ echo "abc" | ./test_sha -p BN128 -b 256
    0       61 62 63 80 00 00 00 00  00 00 00 00 00 00 00 00  |abc.............|
    16      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    32      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    48      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 18  |................|
    digest ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    variable count 100810
    generate key pair
    (8) ..................................................
    (7) ..................................................
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    generate proof
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    verify proof ......
    test passed

(SHA-512 hash of random data using Edwards elliptic curve)

    $ ./test_sha -p Edwards -b 512 -r
    0       f9 b2 0c a7 be 7c 4a 63  e4 2c e9 d0 73 63 6a 21  |.....|Jc.,..scj!|
    16      97 fc 09 7f e5 e6 07 4d  09 f8 03 9b 06 7c 0a 57  |.......M.....|.W|
    32      f5 dc 13 dc b9 86 57 14  15 6c c8 39 6d a2 81 85  |......W..l.9m...|
    48      cb 2f c6 9e 44 d9 55 74  6b d0 e4 37 77 ea 4f 9e  |./..D.Utk..7w.O.|
    64      2a 85 f8 b2 ab ff 65 32  f8 35 e1 2e cb b7 4d 64  |*.....e2.5....Md|
    80      6d e1 37 0b 8e 4e d0 94  47 8f 72 8f 56 ff 99 b9  |m.7..N..G.r.V...|
    96      f5 15 42 9d 39 4c a1 66  fb 35 7c 48 bd 7a 26 99  |..B.9L.f.5|H.z&.|
    112     93 ad a5 2f ab bd d0 d1  77 5d b2 ce 66 f1 df 81  |.../....w]..f...|
    digest b5116da07a8505f0 c368fbeaafd325cd fcadc90843dd73c6 2b66c252e1c624fa dcefd966e88ec168 f9d42ebea62cd76c 44e2b3df8a50695b 4f4de3202f866192
    variable count 254367
    generate key pair
    (8) ..................................................
    (7) ..................................................
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    generate proof
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    verify proof ......
    test passed

Note the "variable count" is shown. This is not the same as the number of gates
in the circuit. There are always more variables than gates. For instance, a
binary AND gate has two input wires and one output. Each wire has an associated
variable. In this case, there are three variables and one gate.

--------------------------------------------------------------------------------
test_merkle (zero knowledge Merkle tree)
--------------------------------------------------------------------------------

The usage message explains how to run this.

    $ ./test_merkle 
    usage: ./test_merkle -p BN128|Edwards -b 256|512 -d tree_depth -i leaf_number

The binary Merkle tree uses either SHA-256 or SHA-512. The test fills the tree
while maintaining all authentication paths from leaves to the root. When the
tree is full, a zero knowledge proof is generated for the authentication path
corresponding to leaf_number (zero indexed so the first leaf is 0). This proves
membership of the leaf in the Merkle tree without revealing the path. The leaf
remains secret, known only to the entity which generates the proof.

Here is an example:

    $ ./test_merkle -p Edwards -b 256 -d 8 -i 123
    leaf 123 child bits 01111011
    root path
    [7] 151a93fe 4455c504 4f344030 4f4faf9b c256b138 521fd887 6b284d63 2c0282a4
    [6] 92bad7a9 50b87c3d 3a257c87 013f093e f21a4bc7 d9683c52 e65b8b7b 1635517b
    [5] 316eaa86 d4ed553e 951f87b1 84ca4feb bc99a605 3510130a 1f1ae614 31ca1373
    [4] ba7d8f7e 2d5650a4 874550d8 5fa14800 128de086 9e4d3c8a 0b55c8f7 1b1dae61
    [3] 99a9b31e b94bec08 0f29d016 d42535d8 44273afb 6ed3b090 d27231d4 376b861e
    [2] 45ba2418 be207b0c 7e84f275 064c4651 118a8666 13846b0a 75983d94 32588a4f
    [1] c2f67261 bc4d70bf 131f1892 0f93cb24 3e736ff5 4ec9b139 9c989a43 fe887b66
    [0] 4cc129ba 32e7de1d 6b0197b7 213f5dc2 65c57387 09407efc afde16fb a3def3c1
    siblings
    [7] bc1bc5b6 46c57e7b 417d49c6 8e056bfe 6128f578 91ebaff1 de941ba5 d03e4574
    [6] f97179d2 a7482340 e2139c8d cb03e373 e169b3fb ae4e0fee f221f5f7 00da45d2
    [5] d7054248 15e083c7 e8bd4137 1c7cfc49 ea65e98b 37f996fd c716a4b2 bccd1eab
    [4] a5214c55 b4f36acc 24d04d36 964b608a 97e9ce98 416f0191 44045bc3 1ec6dd18
    [3] 1d96398d e8d40516 450a3f64 e8dea4a8 eba4552d b7dda6e5 99509ffd 0a564684
    [2] 13344341 e6483de4 db0f7581 533fe253 e52f2e72 8fcf07e4 4b6b05cf cfe5da6d
    [1] 0c622966 e292b4d8 d8f068cf b4cc5eae 5b5fb59d 6c431637 9c63a062 8a6a96c8
    [0] 0000007a 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    variable count 821581
    generate key pair
    (8) ....................................................................................................
    (7) ....................................................................................................
    (6) ....................................................................................................
    (5) ....................................................................................................
    (4) ....................................................................................................
    (3) ....................................................................................................
    (2) ....................................................................................................
    (1) ....................................................................................................
    generate proof
    (5) ....................................................................................................
    (4) ....................................................................................................
    (3) ....................................................................................................
    (2) ....................................................................................................
    (1) ....................................................................................................
    verify proof ......
    proof verification OK

Note the index convention runs in the opposite direction of tree depth. The
root element at the top of the tree is index 7. The index 0 is at the leaves
of the tree. This reversed indexing is consistent with how the proof works.
The proof follows the path from the leaf upwards to the root.

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

[SCIPR Lab]: http://www.scipr-lab.org/ (Succinct Computational Integrity and Privacy Research Lab)

[GitHub libsnark project]: https://github.com/scipr-lab/libsnark

[GitHub snarklib project]: https://github.com/jancarlsson/snarklib

[GNU Multiple Precision Arithmetic Library]: https://gmplib.org/

[FIPS PUB 180-4]: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf

[SHAVS]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

[SHA byte test vectors]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip
