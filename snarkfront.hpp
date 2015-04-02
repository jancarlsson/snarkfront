#ifndef _SNARKFRONT_HPP_
#define _SNARKFRONT_HPP_

////////////////////////////////////////////////////////////////////////////////
// this header file includes everything applications need
//

// not part of the EDSL but convenient for command line applications
#include "CompilePPZK_query.hpp"
#include "CompilePPZK_witness.hpp"
#include "CompileQAP.hpp"
#include "Getopt.hpp"

// the basic language
#include "DSL_base.hpp"
#include "DSL_bless.hpp"
#include "DSL_identity.hpp"
#include "DSL_ppzk.hpp"
#include "DSL_utility.hpp"

// progress bar for proof generation and verification
#include "GenericProgressBar.hpp"

// input and printing of hexadecimal text
#include "HexUtil.hpp"

// initialize elliptic curves
#include "InitPairing.hpp"

// Merkle tree
#include "MerkleAuthPath.hpp"
#include "MerkleBundle.hpp"
#include "MerkleForest.hpp"
#include "MerkleTree.hpp"

// Secure Hash Algorithms
#include "SHA_1.hpp"
#include "SHA_224.hpp"
#include "SHA_256.hpp"
#include "SHA_384.hpp"
#include "SHA_512.hpp"
#include "SHA_512_224.hpp"
#include "SHA_512_256.hpp"

// Advanced Encryption Algorithm
#include "AES_Cipher.hpp"
#include "AES_InvCipher.hpp"
#include "AES_InvSBox.hpp"
#include "AES_KeyExpansion.hpp"
#include "AES_SBox.hpp"

#endif
