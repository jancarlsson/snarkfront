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

Five types:

- Boolean
- 128-bit unsigned integer scalars
- 8-bit unsigned integer octets
- 32-bit unsigned integer words
- 64-bit unsigned integer words

The usual operators:

- logical and bitwise complement
- AND, OR, XOR, addition, subtraction, multiplication, modulo addition
- shift and rotate
- comparisons: == != < <= > >=
- ternary conditional
- array subscript (look up tables)
- type conversion between Boolean, 8-bit, 32-bit, 64-bit, and 128-bit

Cryptographic algorithms:

- FIPS PUB 180-4: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- FIPS PUB 197: AES-128, AES-192, AES-256
- binary Merkle tree using SHA-256 or SHA-512
- key pair generation with cleartext (done) or blinded (work in progress) entropy

Elliptic curve pairings:

- Barreto-Naehrig at 128 bits of security
- Edwards at 80 bits of security

Use both API and CLI toolchain:

- programmatic API with cryptographic structures in C++ templates
- map-reduce cryptographic structures in files from command line

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
Honest Charles helps Alice and Bob trust each other with the snarkfront API
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
API versus CLI
--------------------------------------------------------------------------------

The API will give better single-core performance on computers with enough RAM.
In practice, that means 16 GB to 32 GB at a minimum.
The API trades off space to buy time.

The CLI is the only option for computers with less RAM. That is true for almost
all mass market consumer laptops and desktops (as of 2015).
The CLI trades off time to buy space.

RAM can dominate implementation choices. The zero knowledge cryptographic
structures are large. For example, the proving key for an authentication path
in a Merkle tree of depth 64 is 6 GB. The windowed exponentiation lookup tables
used in calculating the proving key are over 5 GB.

Note the API does not use OpenMP. The API is single threaded and runs on one
core only. There is no technical reason it must work this way. SMP and MT
concurrency should be supported. The author has not had time to work on this.

The CLI scales well to multi-core (concurrent running processes, not threads)
and distributed fleets. The directed acyclic graph of cryptographic arithmetic
possesses natural concurrency and parallelism. The toolchain transformations
correspond to this graph.

In summary:

    if (RAM < 16GB) {
        Must use the CLI
    } else if (RAM < 32GB) {
        Might be able to use the API, otherwise use the CLI
    } else {
        if (single_core) {
            Use the API, it will be faster
        } else {
            Use the CLI, it can be faster
        }
    }

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
5. test_bundle - CLI testing with Merkle trees
6. test_aes    - play with zero knowledge AES

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
- the state is "unlocked" if the message digest matches: ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad

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

    real    0m37.947s
    user    0m33.792s
    sys     0m4.097s
    -rw-rw-r--. 1 jcarlsson jcarlsson 169178113 Feb 17 15:19 keygen.txt


    real    0m0.004s
    user    0m0.001s
    sys     0m0.003s
    -rw-rw-r--. 1 jcarlsson jcarlsson 10044 Feb 17 15:19 input.txt

    generate proof
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................

    real    0m15.636s
    user    0m15.499s
    sys     0m0.686s
    -rw-rw-r--. 1 jcarlsson jcarlsson 2095 Feb 17 15:19 proof.txt

    verify proof ......
    proof is verified

    real    0m8.507s
    user    0m8.435s
    sys     0m0.563s

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
test_aes (zero knowledge AES)
--------------------------------------------------------------------------------

This tests the zero knowledge implementation of AES included in snarkfront.
The snarkfront implementation is derived directly from the NIST standards
document [FIPS PUB 197].

The usage message explains how to run this.

    $ ./test_aes 
    encrypt: ./test_aes -p BN128|Edwards -b 128|192|256 -k key_in_hex -e -i hex_text
    decrypt: ./test_aes -p BN128|Edwards -b 128|192|256 -k key_in_hex -d -i hex_text

Examples from the NIST standards document:

(AES-128 encrypt with Edwards curve)

    $ ./test_aes -p Edwards -b 128 -e -k 2b7e151628aed2a6abf7158809cf4f3c -i 3243f6a8885a308d313198a2e0370734
    output: 3925841d02dc09fbdc118597196a0b32
    variable count 1609976
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
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    verify proof ......
    test passed

(AES-128 encrypt with Barreto-Naehrig curve)

    $ ./test_aes -p BN128 -b 128 -e -k 000102030405060708090a0b0c0d0e0f -i 00112233445566778899aabbccddeeff
    output: 69c4e0d86a7b0430d8cdb78070b4c55a
    variable count 1609976
    ...
    test passed

(AES-128 decrypt with Edwards curve)

    $ ./test_aes -p Edwards -b 128 -d -k 000102030405060708090a0b0c0d0e0f -i 69c4e0d86a7b0430d8cdb78070b4c55a
    output: 00112233445566778899aabbccddeeff
    variable count 1610264
    ...
    test passed

(AES-192 encrypt with Barreto-Naehrig curve)

    $ ./test_aes -p BN128 -b 192 -e -k 000102030405060708090a0b0c0d0e0f1011121314151617 -i 00112233445566778899aabbccddeeff
    output: dda97ca4864cdfe06eaf70a0ec0d7191
    variable count 1804760
    ...
    test passed

(AES-192 decrypt with Barreto-Naehrig curve)

    $ ./test_aes -p BN128 -b 192 -d -k 000102030405060708090a0b0c0d0e0f1011121314151617 -i dda97ca4864cdfe06eaf70a0ec0d7191
    output: 00112233445566778899aabbccddeeff
    variable count 1805112
    ...
    test passed

(AES-256 encrypt with Edwards curve)

    $ ./test_aes -p Edwards -b 256 -e -k 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f -i 00112233445566778899aabbccddeeff
    output: 8ea2b7ca516745bfeafc49904b496089
    variable count 2222515
    ...
    test passed

(AES-256 decrypt with Barreto-Naehrig curve)

    $ ./test_aes -p BN128 -b 256 -d -k 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f -i 8ea2b7ca516745bfeafc49904b496089
    output: 00112233445566778899aabbccddeeff
    variable count 2222931
    ...
    test passed

The test_aes process uses about 5.5 GB for the AES-256 examples during key pair
generation. Memory requirements could be lower if the CLI were used instead of
the API (which holds all cryptographic structures in RAM).

--------------------------------------------------------------------------------
test_sha (zero knowledge SHA-2)
--------------------------------------------------------------------------------

The usage message explains how to run this.

    $ ./test_sha 
    usage: ./test_sha -b 1|224|256|384|512|512_224|512_256 [-p BN128|Edwards] [-r] [-d hex_digest] [-e equal_pattern] [-n not_equal_pattern]

    text from standard input:
    echo "abc" | ./test_sha -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256

    pre-image pattern and hash:
    echo "abc" | ./test_sha -p BN128|Edwards -b 1|224|256|384|512|512_224|512_256 -d digest -e pattern -n pattern

    hash only, skip zero knowledge proof:
    echo "abc" | ./test_sha -b 1|224|256|384|512|512_224|512_256

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

The "-d hex_digest" option sets the message digest hash value.
The "-e equal_pattern" and "-n not_equal_pattern" apply constraints on the preimage.
See the example below for details.

Some examples:

(SHA-256 hash of "abc" using Barreto-Naehrig elliptic curve)

    $ echo "abc" | ./test_sha -p BN128 -b 256
    0       61 62 63 0a 80 00 00 00  00 00 00 00 00 00 00 00  |abc.............|
    16      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    32      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    48      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 20  |................|
    digest edeaaff3 f1774ad2 88867377 0c6d6409 7e391bc3 62d7d6fb 34982ddf 0efd18cb
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
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    verify proof ......
    test passed

(SHA-512 hash of random data using Edwards elliptic curve)

    $ ./test_sha -p Edwards -b 512 -r
    0       ed 63 41 a6 41 1f 90 a1  94 57 4f a2 a2 fb 56 8e  |.cA.A....WO...V.|
    16      1b da 86 c9 4a 56 65 6e  47 09 4e aa 99 10 b3 d4  |....JVenG.N.....|
    32      1d 81 44 1d ca 47 76 de  b1 e7 b8 b6 33 dc 50 aa  |..D..Gv.....3.P.|
    48      60 53 57 e4 58 36 1c 59  9a c7 45 f9 8e 4b f7 10  |`SW.X6.Y..E..K..|
    64      d0 54 11 a5 45 5a 62 56  0f e0 92 0f 5b 4a b2 a9  |.T..EZbV....[J..|
    80      dd 46 09 af 74 3e 2b 46  15 9b 31 1a f9 3b 2f f8  |.F..t>+F..1..;/.|
    96      06 e2 60 b5 40 20 89 cb  96 1f f5 2c 78 3c b3 60  |..`.@......,x<.`|
    112     99 9e b5 af 04 34 86 d6  3e 71 f1 0e ce 8e c6 c2  |.....4..>q......|
    digest d243920075e8e576 aa3fd2cfa3d6f9e5 ce020a6e81a70918 1f1d45dec43d7951 2fe82b594e800358 b05fbed726dfee6f bcc70b92231cd3c2 afaec5a8d481047a
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
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    verify proof ......
    test passed

(SHA-1 hash with specified digest and preimage constraints)

    1. calculate message digest
    $ echo "hello" | ./test_sha -b 1
    f572d396fae9206628714fb2ce00f72e94f2258f

    2. zero knowledge proof with satisfied constraints (should pass)
    $ echo "hello" | ./test_sha -b 1 -p BN128 -d f572d396fae9206628714fb2ce00f72e94f2258f -e ??ll -n a?a
    0       68 65 6c 6c 6f 0a 80 00  00 00 00 00 00 00 00 00  |hello...........|
    16      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    32      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
    48      00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 30  |...............0|
    constrain preimage[0] != 61
    constrain preimage[2] == 6c
    constrain preimage[2] != 61
    constrain preimage[3] == 6c
    digest f572d396 fae92066 28714fb2 ce00f72e 94f2258f
    variable count 25644
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
    (6) ..................................................
    (5) ..................................................
    (4) ..................................................
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................
    verify proof ......
    test passed

    3. zero knowledge proof with violated constraints (should fail)
    $ echo "hello" | ./test_sha -b 1 -p BN128 -d f572d396fae9206628714fb2ce00f72e94f2258f -e ??ll -n h?a
    ...
    constrain preimage[0] != 68
    constrain preimage[2] == 6c
    constrain preimage[2] != 61
    constrain preimage[3] == 6c
    ...
    test failed

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
    (6) ....................................................................................................
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
test_cli.sh
--------------------------------------------------------------------------------

An example script exercises the command line toolchain end-to-end.

    $ ./test_cli.sh
    usage: ./test_cli.sh BN128|Edwards 256|512 <tree_depth> <vector_blocks> <window_blocks> [clearonly]

It uses test_bundle to generate a Merkle tree, add a commitment leaf, then
write the constraint system, input, and witness to files.

    $ ./test_bundle 
    new tree:      ./test_bundle -p BN128|Edwards -b 256|512 -t merkle_tree_file -d tree_depth
    add leaf:      ./test_bundle -p BN128|Edwards -b 256|512 -t merkle_tree_file -c hex_digest [-k]
    constraints:   ./test_bundle -p BN128|Edwards -b 256|512 -t merkle_tree_file -s constraint_system_file -n constraints_per_file
    proof input:   ./test_bundle -p BN128|Edwards -b 256|512 -t merkle_tree_file -i proof_input_file
    proof witness: ./test_bundle -p BN128|Edwards -b 256|512 -t merkle_tree_file -w proof_witness_file

These files are inputs to the four toolchain executables which perform the
zero knowledge cryptographic calculations.

1. randomness - sample entropy from /dev/urandom and save in files (dangerous!)
2. qap - map constraint system to query vectors
3. ppzk - map query vectors and randomness to generate key pair, reduce proving key and witness to generate proof
4. verify - check that verification key, input, and proof are consistent

Here is an easy example. This creates a Merkle tree of depth one using the
80 bit Edwards curve and SHA-256. The map-reduce index space is trivial with
a single partition for the query vectors and windowed exponentiation table.

    $ ./test_cli.sh Edwards 256 1 1 1
    create merkle tree
    add commitment leaf
    generate constraint system (may take a while)
    generate proof inputs
    generate proof witness
    key randomness ***destroy tmp_test_cli.keyrand after use***
    key randomness (mostly blinded)
    qap query A
    qap query B
    qap query C
    qap query H
    g1_exp_count 606516
    g2_exp_count 75705
    qap query K
    qap query input consistency

    ***** PROVING KEY *****

    ppzk query A
    tmp_test_cli.pkqueryA0
    (1) ..................................................

    ppzk query A (mostly blinded)
    tmp_test_cli.pkqueryA.blind0
    (1) ..................................................

    ppzk query B
    tmp_test_cli.pkqueryB0
    (1) ..................................................

    ppzk query B (mostly blinded)
    tmp_test_cli.pkqueryB.blind0
    (1) ..................................................

    ppzk query C
    tmp_test_cli.pkqueryC0
    (1) ..................................................

    ppzk query C (mostly blinded)
    tmp_test_cli.pkqueryC.blind0
    (1) ..................................................

    ppzk query H
    tmp_test_cli.pkqueryH0
    (1) ..................................................

    ppzk query K
    tmp_test_cli.pkqueryK0
    (1) ..................................................

    ppzk query K (mostly blinded)
    tmp_test_cli.pkqueryK.blind0
    (3) ..................................................
    (2) ..................................................
    (1) ..................................................

    ***** VERIFICATION KEY *****

    ppzk query IC
    (1) ..................................................

    ppzk query IC (mostly blinded)
    (1) ..................................................

    ***tmp_test_cli.keyrand no longer needed***

    ***** PROOF *****

    proof randomness ***destroy tmp_test_cli.proofrand after use***

    qap witness

    ppzk witness A
    tmp_test_cli.pkqueryA0
    (1) ..................................................

    ppzk witness A (mostly blinded)
    tmp_test_cli.pkqueryA.blind0
    (1) ..................................................

    ppzk witness B
    tmp_test_cli.pkqueryB0
    (1) ..................................................

    ppzk witness B (mostly blinded)
    tmp_test_cli.pkqueryB.blind0
    (1) ..................................................

    ppzk witness C
    tmp_test_cli.pkqueryC0
    (1) ..................................................

    ppzk witness C (mostly blinded)
    tmp_test_cli.pkqueryC.blind0
    (1) ..................................................

    ppzk witness H
    tmp_test_cli.pkqueryH0
    (1) ..................................................

    ppzk witness K
    tmp_test_cli.pkqueryK0
    (1) ..................................................

    ppzk witness K (mostly blinded)
    tmp_test_cli.pkqueryK.blind0
    (1) ..................................................

    ***tmp_test_cli.proofrand no longer needed***

    ***** VERIFY *****

    PASS key pair entropy in clear
    PASS mostly blinded key pair entropy

Many files are left behind by the script.

    $ du -k -c tmp_test_cli.*
    8       tmp_test_cli.input
    4       tmp_test_cli.keyrand
    12      tmp_test_cli.keyrand.blind
    4       tmp_test_cli.merkle
    32204   tmp_test_cli.pkqueryA0
    32204   tmp_test_cli.pkqueryA.blind0
    42104   tmp_test_cli.pkqueryB0
    42104   tmp_test_cli.pkqueryB.blind0
    17360   tmp_test_cli.pkqueryC0
    17360   tmp_test_cli.pkqueryC.blind0
    21436   tmp_test_cli.pkqueryH0
    48      tmp_test_cli.pkqueryIC
    48      tmp_test_cli.pkqueryIC.blind
    16884   tmp_test_cli.pkqueryK0
    16884   tmp_test_cli.pkqueryK.blind0
    4       tmp_test_cli.pkwitnessA
    4       tmp_test_cli.pkwitnessA.blind
    4       tmp_test_cli.pkwitnessB
    4       tmp_test_cli.pkwitnessB.blind
    4       tmp_test_cli.pkwitnessC
    4       tmp_test_cli.pkwitnessC.blind
    4       tmp_test_cli.pkwitnessH
    4       tmp_test_cli.pkwitnessK
    4       tmp_test_cli.pkwitnessK.blind
    4       tmp_test_cli.proofrand
    4       tmp_test_cli.qapqueryA
    5232    tmp_test_cli.qapqueryA0
    4       tmp_test_cli.qapqueryA.afterIC
    5216    tmp_test_cli.qapqueryA.afterIC0
    4       tmp_test_cli.qapqueryB
    4144    tmp_test_cli.qapqueryB0
    4       tmp_test_cli.qapqueryC
    2908    tmp_test_cli.qapqueryC0
    4       tmp_test_cli.qapqueryH
    7080    tmp_test_cli.qapqueryH0
    4       tmp_test_cli.qapqueryIC
    16      tmp_test_cli.qapqueryIC0
    4       tmp_test_cli.qapqueryK
    5568    tmp_test_cli.qapqueryK0
    7080    tmp_test_cli.qapwitness0
    4       tmp_test_cli.system
    26752   tmp_test_cli.system0
    2172    tmp_test_cli.witness
    304904  total

A more realistic example is a Merkle tree of depth 64 using the 128 bit
Barreto-Naehrig curve. As before, the SHA-256 compression function is used.
Query vectors are partitioned into 16 blocks. The windowed exponentiation
table is partitioned into 8 blocks.

    $ ./test_cli.sh BN128 256 64 16 8 clearonly

Note this may take hours to run and writes 16 GB of files to disk. However,
RAM use remains between 500 MB and 2 GB. A laptop with 4 GB RAM and a slow
x86-64 bit CPU running at 1 GHz can generate the key pair in under eight hours
using a single core without stressing itself (getting hot or thrashing disk).

Note also the test_cli.sh script and partitioning chosen in these examples is
not optimal. The blocks of the partitioned problem may be mapped and reduced
concurrently according to interdependencies between them. Optimal partitioning
would be tuned to the RAM and CPU cores available. This test script is just to
verify end-to-end functionality in a transparent way.

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

[SCIPR Lab]: http://www.scipr-lab.org/ (Succinct Computational Integrity and Privacy Research Lab)

[GitHub libsnark project]: https://github.com/scipr-lab/libsnark

[GitHub snarklib project]: https://github.com/jancarlsson/snarklib

[GNU Multiple Precision Arithmetic Library]: https://gmplib.org/

[FIPS PUB 180-4]: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf

[FIPS PUB 197]: https://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

[SHAVS]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf

[SHA byte test vectors]: http://csrc.nist.gov/groups/STM/cavp/documents/shs/shabytetestvectors.zip
