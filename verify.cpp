#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string>
#include "Getopt.hpp"
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace snarklib;
using namespace std;

void printUsage(const char* exeName) {
    const string
        PAIR = " -p BN128|Edwards",
        VKEY = " -v key_file",
        IN = " -i proof_input_file",
        A = " -a file",
        B = " -b file",
        C = " -c file",
        H = " -h file",
        K = " -k file";

    cout << "usage: " << exeName << PAIR << VKEY << IN << A << B << C << H << K << endl;

    exit(EXIT_FAILURE);
}

template <typename T>
bool marshal_in(T& a, const string& filename) {
    ifstream ifs(filename);
    return !!ifs && a.marshal_in(ifs);
}

template <typename T>
bool marshal_in_raw(T& a, const string& filename) {
    ifstream ifs(filename);
    return !!ifs && a.marshal_in_raw(ifs);
}

template <typename PAIRING>
bool verifyProof(const string& keyfile,
                 const string& pinfile,
                 const string& afile,
                 const string& bfile,
                 const string& cfile,
                 const string& hfile,
                 const string& kfile)
{
    PPZK_VerificationKey<PAIRING> vk;
    R1Witness<typename PAIRING::Fr> input;
    typename PPZK_WitnessA<PAIRING>::Val pA;
    typename PPZK_WitnessB<PAIRING>::Val pB;
    typename PPZK_WitnessC<PAIRING>::Val pC;
    typename PAIRING::G1 pH, pK;

    return
        marshal_in_raw(vk, keyfile) &&
        marshal_in(input, pinfile) &&
        marshal_in_raw(pA, afile) &&
        marshal_in_raw(pB, bfile) &&
        marshal_in_raw(pC, cfile) &&
        marshal_in_raw(pH, hfile) &&
        marshal_in_raw(pK, kfile) &&
        strongVerify(vk, input, PPZK_Proof<PAIRING>(pA, pB, pC, pH, pK));
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "pviabchk", "", "");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto
        pairing = cmdLine.getString('p'),
        keyfile = cmdLine.getString('v'),
        pinfile = cmdLine.getString('i'),
        afile = cmdLine.getString('a'),
        bfile = cmdLine.getString('b'),
        cfile = cmdLine.getString('c'),
        hfile = cmdLine.getString('h'),
        kfile = cmdLine.getString('k');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    bool ok = false;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        ok = verifyProof<BN128_PAIRING>(keyfile, pinfile, afile, bfile, cfile, hfile, kfile);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        ok = verifyProof<EDWARDS_PAIRING>(keyfile, pinfile, afile, bfile, cfile, hfile, kfile);
    }

    cout << ok << endl;

    exit(EXIT_SUCCESS);
}
