#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>
#include "FoundationDSL.hpp"
#include "GenericProgressBar.hpp"
#include "HexUtil.hpp"
#include "MainEC.hpp"
#include "MerkleTree.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: " << exeName
         << " -c BN128|Edwards"
            " -b 256|512"
            " -d tree_depth"
            " -i leaf_number"
         << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING, typename EVAL, typename EVAL_PATH, typename ZK_PATH>
void runTest(const size_t treeDepth,
             const size_t leafNumber)
{
    EVAL evalTree(treeDepth);

    vector<typename EVAL::DigType> oldLeafs;
    vector<EVAL_PATH> oldPaths;

    typename EVAL::HashType::WordType count = 0;

    while (! evalTree.isFull()) {
        const typename EVAL::DigType leaf{count};
        evalTree.updatePath(leaf, oldPaths);

        // save an old authentication path
        oldLeafs.emplace_back(leaf);
        oldPaths.emplace_back(evalTree.authPath());

        evalTree.updateSiblings(leaf);
        ++count;
    }

    if (leafNumber >= oldLeafs.size()) {
        cout << "leaf number " << leafNumber
             << " is larger than " << oldLeafs.size()
             << endl;

        exit(EXIT_FAILURE);
    }

    const auto& leaf = oldLeafs[leafNumber];
    const auto& authPath = oldPaths[leafNumber];

    cout << "leaf " << leafNumber << " child bits ";
    for (int i = authPath.childBits().size() - 1; i >= 0; --i) {
        cout << authPath.childBits()[i];
    }
    cout << endl;

    cout << "root path" << endl;
    for (int i = authPath.rootPath().size() - 1; i >= 0; --i) {
        cout << "[" << i << "] "
             << asciiHex(authPath.rootPath()[i], true) << endl;
    }

    cout << "siblings" << endl;
    for (int i = authPath.siblings().size() - 1; i >= 0; --i) {
        cout << "[" << i << "] "
             << asciiHex(authPath.siblings()[i], true) << endl;
    }

    typename ZK_PATH::DigType rt;
    bless(rt, authPath.rootHash());

    end_input<PAIRING>();

    typename ZK_PATH::DigType zkLeaf;
    bless(zkLeaf, leaf);

    ZK_PATH zkAuthPath(authPath);
    zkAuthPath.updatePath(zkLeaf);

    assert_true(rt == zkAuthPath.rootHash());

    cout << "variable count " << variable_count<PAIRING>() << endl;
}

template <typename PAIRING>
bool runTest(const string& shaBits,
             const size_t treeDepth,
             const size_t leafNumber)
{
    typedef typename PAIRING::Fr FR;

    if ("256" == shaBits) {
        runTest<PAIRING,
                eval::MerkleTree_SHA256,
                eval::MerkleAuthPath_SHA256,
                zk::MerkleAuthPath_SHA256<FR>>(
            treeDepth,
            leafNumber);

    } else if ("512" == shaBits) {
        runTest<PAIRING,
                eval::MerkleTree_SHA512,
                eval::MerkleAuthPath_SHA512,
                zk::MerkleAuthPath_SHA512<FR>>(
            treeDepth,
            leafNumber);
    }

    GenericProgressBar progress1(cerr), progress2(cerr, 100);

    cerr << "generate key pair";
    const auto key = keypair<PAIRING>(progress2);
    cerr << endl;

    const auto in = input<PAIRING>();

    cerr << "generate proof";
    const auto p = proof(key, progress2);
    cerr << endl;

    cerr << "verify proof ";
    const bool proofOK = verify(key, in, p, progress1);
    cerr << endl;

    return proofOK;
}

int main(int argc, char *argv[])
{
    // command line switches
    string ellipticCurve, shaBits;
    size_t treeDepth = -1, leafNumber = -1;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "c:b:d:i:"))) {
        switch (opt) {
        case ('c') :
            ellipticCurve = optarg;
            break;
        case ('b') :
            shaBits = optarg;
            break;
        case('d') :
            {
                stringstream ss(optarg);
                ss >> treeDepth;
                if (!ss) printUsage(argv[0]);
            }
            break;
        case('i') :
            {
                stringstream ss(optarg);
                ss >> leafNumber;
                if (!ss) printUsage(argv[0]);
            }
            break;
        }
    }

    if (shaBits.empty() || -1 == treeDepth || -1 == leafNumber) {
        printUsage(argv[0]);
    }

    bool result;

    if ("BN128" == ellipticCurve) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        result = runTest<BN128_PAIRING>(shaBits, treeDepth, leafNumber);

    } else if ("Edwards" == ellipticCurve) {
        // Edwards 80 bits
        init_Edwards();
        result = runTest<EDWARDS_PAIRING>(shaBits, treeDepth, leafNumber);

    } else {
        // no elliptic curve specified
        printUsage(argv[0]);
    }

    cout << "proof verification " << (result ? "OK" : "FAIL") << endl;

    exit(EXIT_SUCCESS);
}
