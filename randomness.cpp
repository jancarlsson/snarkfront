#include <cstdlib>
#include <fstream>
#include <iostream>
#include <ostream>
#include <string>
#include "Getopt.hpp"
#include "snarkfront.hpp"

using namespace snarkfront;
using namespace snarklib;
using namespace std;

void printUsage(const char* exeName) {
    const string
        PAIR = " -p BN128|Edwards",
        KEY = " -k",
        OUT = " [-o output_file]";

    cout << "key pair entropy: " << exeName << PAIR << KEY << OUT << endl
         << "proof entropy:    " << exeName << PAIR << OUT << endl;

    exit(EXIT_FAILURE);
}

template <typename PAIRING>
void writeEntropy(ostream& os, const bool is_keypair) {
    if (is_keypair) {
        PPZK_KeypairRandomness<typename PAIRING::Fr> entropy(0);
        os << entropy;

    } else {
        PPZK_ProofRandomness<typename PAIRING::Fr> entropy(0);
        os << entropy;
    }
}

int main(int argc, char *argv[])
{
    Getopt cmdLine(argc, argv, "po", "", "k");
    if (!cmdLine || cmdLine.empty()) printUsage(argv[0]);

    const auto pairing = cmdLine.getString('p');
    const auto outfile = cmdLine.getString('o');
    const auto is_keypair = cmdLine.getFlag('k');

    if (!validPairingName(pairing)) {
        cerr << "error: elliptic curve pairing " << pairing << endl;
        exit(EXIT_FAILURE);
    }

    ofstream ofs(outfile);
    if (!outfile.empty() && !ofs) {
        cerr << "error: output file " << outfile << endl;
        exit(EXIT_FAILURE);
    }

    ostream& os = outfile.empty() ? cout : ofs;

    if (pairingBN128(pairing)) {
        // Barreto-Naehrig 128 bits
        init_BN128();
        writeEntropy<BN128_PAIRING>(os, is_keypair);

    } else if (pairingEdwards(pairing)) {
        // Edwards 80 bits
        init_Edwards();
        writeEntropy<EDWARDS_PAIRING>(os, is_keypair);
    }

    exit(EXIT_SUCCESS);
}
