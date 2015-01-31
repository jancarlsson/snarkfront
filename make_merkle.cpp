#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <unistd.h>
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    cout << "usage: " << exeName
         << " -p BN128|Edwards"
            " -b 256|512"
            " -d tree_depth"
            " -o file_prefix"
            " -n constraints_per_file"
         << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING, typename BUNDLE, typename ZK_PATH>
void makeMerkle(const size_t treeDepth)
{
    BUNDLE bundle(treeDepth);

    const typename BUNDLE::DigType leaf{0};
    bundle.addLeaf(leaf);
    const auto& authPath = bundle.authPath().front();

    typename ZK_PATH::DigType zkRT;
    bless(zkRT, authPath.rootHash());

    end_input<PAIRING>();

    typename ZK_PATH::DigType zkLeaf;
    bless(zkLeaf, leaf);

    ZK_PATH zkAuthPath(authPath);
    zkAuthPath.updatePath(zkLeaf);

    assert_true(zkRT == zkAuthPath.rootHash());

    cout << "variable count " << variable_count<PAIRING>() << endl;
}

template <typename PAIRING>
void makeMerkle(const string& shaBits,
                const size_t treeDepth,
                const string& filePrefix,
                const size_t maxSize)
{
    typedef typename PAIRING::Fr FR;

    write_files<PAIRING>(filePrefix, maxSize);

    if (nameSHA256(shaBits)) {
        makeMerkle<PAIRING,
                   MerkleBundle_SHA256<size_t>,
                   zk::MerkleAuthPath_SHA256<FR>>(treeDepth);

    } else if (nameSHA512(shaBits)) {
        makeMerkle<PAIRING,
                   MerkleBundle_SHA512<size_t>,
                   zk::MerkleAuthPath_SHA512<FR>>(treeDepth);
    }

    finalize_files<PAIRING>();
}

int main(int argc, char *argv[])
{
    // command line switches
    string pairing, shaBits, filePrefix;
    size_t treeDepth = -1, maxSize = -1;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "p:b:o:d:n:"))) {
        switch (opt) {
        case ('p') :
            pairing = optarg;
            break;
        case ('b') :
            shaBits = optarg;
            break;
        case ('o') :
            filePrefix = optarg;
            break;
        case ('d') : {
                stringstream ss(optarg);
                if (!(ss >> treeDepth)) {
                    cerr << "error: tree depth " << optarg << endl;
                    exit(EXIT_FAILURE);
                }
            }
            break;
        case ('n') : {
                stringstream ss(optarg);
                if (!(ss >> maxSize)) {
                    cerr << "error: number of constraints per file " << optarg << endl;
                    exit(EXIT_FAILURE);
                }
            }
            break;
        }
    }

    if (!validPairingName(pairing) ||
        !(nameSHA256(shaBits) || nameSHA512(shaBits)) ||
        filePrefix.empty() ||
        -1 == treeDepth ||
        -1 == maxSize)
        printUsage(argv[0]);

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        makeMerkle<BN128_PAIRING>(shaBits, treeDepth, filePrefix, maxSize);

    } else if (pairingEdwards(pairing)){
        // Edwards 80 bits
        init_Edwards();
        makeMerkle<EDWARDS_PAIRING>(shaBits, treeDepth, filePrefix, maxSize);
    }

    exit(EXIT_SUCCESS);
}
