#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "Getopt.hpp"
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace std;

void printUsage(const char* exeName) {
    const string
        PAIR = " -p BN128|Edwards",
        BITS = " -b 256|512",
        D = " -d tree_depth",
        T = " -t merkle_tree_file",
        LEAF = " -c hex_digest",
        KEEP = " [-k]",
        SYS = " -s constraint_system_file",
        N = " -n constraints_per_file",
        IN = " -i proof_input_file",
        WIT = " -w proof_witness_file";

    cout << "new tree:      " << exeName << PAIR << BITS << T << D << endl
         << "add leaf:      " << exeName << PAIR << BITS << T << LEAF << KEEP << endl
         << "constraints:   " << exeName << PAIR << BITS << T << SYS << N << endl
         << "proof input:   " << exeName << PAIR << BITS << T << IN << endl
         << "proof witness: " << exeName << PAIR << BITS << T << WIT << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING, typename BUNDLE>
bool newTree(const string& treefile,
             const size_t depth)
{
    if (0 == depth) return false;

    BUNDLE bund(depth);

    ofstream ofs(treefile);
    if (!ofs)
        return false;
    else
        bund.marshal_out(ofs);

    return true;
}

template <typename PAIRING, typename BUNDLE>
bool addLeaf(const string& treefile,
             const string& cmtext,
             const bool keep)
{
    BUNDLE bund;
    {
        ifstream ifs(treefile);
        if (!ifs || !bund.marshal_in(ifs))
            return false;
    }

    typename BUNDLE::DigType cm;
    if (!asciiHexToArray(cmtext, cm))
        return false;

    bund.addLeaf(cm, keep);
    {
        ofstream ofs(treefile);
        if (!ofs)
            return false;
        else
            bund.marshal_out(ofs);
    }

    return true;
}

template <typename PAIRING, typename BUNDLE, typename ZK_PATH>
bool proofFiles(const string& treefile,
                const string& sysfile,
                const size_t sysnum,
                const string& pinfile,
                const string& witfile)
{
    BUNDLE bund;
    {
        ifstream ifs(treefile);
        if (!ifs || !bund.marshal_in(ifs))
            return false;
    }

    if (1 != bund.authLeaf().size() || 1 != bund.authPath().size())
        return false;

    const auto& authLeaf = bund.authLeaf().front();
    const auto& authPath = bund.authPath().front();

    if (!sysfile.empty()) write_files<PAIRING>(sysfile, sysnum);

    typename ZK_PATH::DigType zkRT;
    bless(zkRT, authPath.rootHash());

    end_input<PAIRING>();

    if (!pinfile.empty()) {
        ofstream ofs(pinfile);
        if (!ofs) return false;
        ofs << input<PAIRING>();
        return true;
    }

    typename ZK_PATH::DigType zkLeaf;
    bless(zkLeaf, authLeaf);

    ZK_PATH zkAuthPath(authPath);
    zkAuthPath.updatePath(zkLeaf);

    assert_true(zkRT == zkAuthPath.rootHash());

    if (!sysfile.empty()) finalize_files<PAIRING>();

    if (!witfile.empty()) {
        ofstream ofs(witfile);
        if (!ofs) return false;
        ofs << witness<PAIRING>();
        return true;
    }

    return true;
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "ptcsiw", "bdn", "k");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto
        pairing = cmdLine.getString('p'),
        treefile = cmdLine.getString('t'),
        cmtext = cmdLine.getString('c'),
        sysfile = cmdLine.getString('s'),
        pinfile = cmdLine.getString('i'),
        witfile = cmdLine.getString('w');

    const auto
        numbits = cmdLine.getNumber('b'),
        depth = cmdLine.getNumber('d'),
        sysnum = cmdLine.getNumber('n');

    const auto keep = cmdLine.getFlag('k');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    if (256 != numbits && 512 != numbits) {
        cerr << "error: number SHA-2 bits " << numbits << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        typedef BN128_PAIRING PAIR;
        typedef PAIR::Fr FR;

        if (256 == numbits) {
            typedef MerkleBundle_SHA256<size_t> BUNDLE;
            typedef zk::MerkleAuthPath_SHA256<FR> ZK_PATH;

            if (-1 != depth)
                ok = newTree<PAIR, BUNDLE>(treefile, depth);
            else if (! cmtext.empty())
                ok = addLeaf<PAIR, BUNDLE>(treefile, cmtext, keep);
            else
                ok = proofFiles<PAIR, BUNDLE, ZK_PATH>(treefile,
                                                       sysfile,
                                                       sysnum,
                                                       pinfile,
                                                       witfile);

        } else if (512 == numbits) {
            typedef MerkleBundle_SHA512<size_t> BUNDLE;
            typedef zk::MerkleAuthPath_SHA512<FR> ZK_PATH;

            if (-1 != depth)
                ok = newTree<PAIR, BUNDLE>(treefile, depth);
            else if (! cmtext.empty())
                ok = addLeaf<PAIR, BUNDLE>(treefile, cmtext, keep);
            else
                ok = proofFiles<PAIR, BUNDLE, ZK_PATH>(treefile,
                                                       sysfile,
                                                       sysnum,
                                                       pinfile,
                                                       witfile);
        }

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        typedef EDWARDS_PAIRING PAIR;
        typedef PAIR::Fr FR;

        if (256 == numbits) {
            typedef MerkleBundle_SHA256<size_t> BUNDLE;
            typedef zk::MerkleAuthPath_SHA256<FR> ZK_PATH;

            if (-1 != depth)
                ok = newTree<PAIR, BUNDLE>(treefile, depth);
            else if (! cmtext.empty())
                ok = addLeaf<PAIR, BUNDLE>(treefile, cmtext, keep);
            else
                ok = proofFiles<PAIR, BUNDLE, ZK_PATH>(treefile,
                                                       sysfile,
                                                       sysnum,
                                                       pinfile,
                                                       witfile);

        } else if (512 == numbits) {
            typedef MerkleBundle_SHA512<size_t> BUNDLE;
            typedef zk::MerkleAuthPath_SHA512<FR> ZK_PATH;

            if (-1 != depth)
                ok = newTree<PAIR, BUNDLE>(treefile, depth);
            else if (! cmtext.empty())
                ok = addLeaf<PAIR, BUNDLE>(treefile, cmtext, keep);
            else
                ok = proofFiles<PAIR, BUNDLE, ZK_PATH>(treefile,
                                                       sysfile,
                                                       sysnum,
                                                       pinfile,
                                                       witfile);
        }
    }

    if (!ok) {
        cerr << "ERROR" << endl;
        exit(EXIT_FAILURE);
    }

    exit(EXIT_SUCCESS);
}
