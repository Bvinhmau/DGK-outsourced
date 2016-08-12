#ifndef DGKOPERATIONS_H
#define DGKOPERATIONS_H
#include "DGKPublicKey.h"
#include "DGKPrivateKey.h"
#include <iostream>
#include <map>
#include <vector>


/*
author: Baptiste VINH MAU, baptiste.vinhmau@epfl.ch

This class provide all the operations used by the DGk Cryptosystem.
In a general rule, always try to access to the key by reference, as some of their variables (the LUT) may take a lot
of memories for a plaintext space of raisonnable size.
Please also note that this implementation does NOT provide any way to prevent or detect overflow when multiplying two large plaintext for exemple.
The result will be expressed modulus the plaintext space.

The plaintext is garanted supported up to 31 bits (going over this value will cause problem as long are used to store plaintexts, and as the real plaintext space will be Zu with u a l+1 bits prime number)
Plaintexts are represented by unsigned long (as there are limited up to 32 bits)
Ciphertexts are reprsented by ZZ
*/
class DGKOperations
{
    public:

        DGKOperations();
        virtual ~DGKOperations();
static void testKey();

/*
Function used to generate a pair of Public/Private keys for the DGk cryptosystem.
int l : used to precise the size of the plaintext, it will ensure that the plaintext pace will be larger than l bits
int t : first security parameter, must garanty t/2 bits of computational security (so t >=160 )
int k : secnd security paremeter, a number of k bits must be hard to factorize
*/
static std::tuple<DGKPrivateKey, DGKPublicKey>  DGKOperations::GenerateKeys(int l , int t , int k);
/*

/*
Function use for a standard encryption using the DGk cryptosystem.It also use some precomputed LUT to speed up
the process.
DGKPubicKey pubkey
unsigned long plaintext
*/
static ZZ DGKOperations::encrypt(DGKPublicKey &pubKey, unsigned long plaintext );

/*
Generate one the LUT of  pow(g,i), with i defined over the plaintext space, that is use for the encryption
with precomputation.
*/
static std::map<unsigned long, ZZ> DGKOperations::generatePreCompLut(DGKPublicKey pubKey);
/*
Generate one the LUT of  pow(g,pow(2,i), with i defined over 0...2t-1, that is use for the encryption
with precomputation.
*/
static std::map<unsigned long, ZZ> DGKOperations::generatePreCompLutSG(DGKPublicKey pubKey);
/*
Generate the LUT that is used for the decryption of DGK.
*/
static std::map<ZZ, unsigned long> DGKOperations::generateLUT(DGKPublicKey pubKey , DGKPrivateKey privKey);

/*
Function used for the standard decryption using the DGk cryptosystem.
DGKPublicKey pubkey : A valid DGK Public Key.
DGKPrivateKey privkey : A valid DGK Private Key.
ZZ ciphertext
std::map<ZZ, unsigned long> LUT : LUT used to establish a one to one correspondance with a plaintext.
*/
static unsigned long DGKOperations::decrypt(DGKPublicKey &pubKey ,DGKPrivateKey &privKey , ZZ ciphertext);

/*
Homomorphic Add operation between two ciphers for DGK
*/
static ZZ DGKOperations::DGKAdd(DGKPublicKey &pubKey, ZZ a, ZZ b);
/*
Homomorphic Multiplication between a plain and a ciphetext for DGK
*/
static ZZ DGKOperations::DGKMultiply(DGKPublicKey &pubKey, ZZ cipher, unsigned long plaintext);

/*
Multiplication of two ciphertexts using BetterTime in the malicuious model, offline version, return <x*y,d> with d
*/
static std::tuple<ZZ, ZZ> DGKOperations::CipherMultiplication(DGKPublicKey &pubKey,int sock, ZZ x, ZZ y);
static std::tuple<ZZ, ZZ>  DGKOperations::CipherMultiplication(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ x, ZZ y);

/*
Multiplication of two ciphertexts using BetterTime in the honnest but curious model, offline version, return <x*y,d> with d
*/
static ZZ CipherMultiplicationHonnest(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ x , ZZ y);
/*
Multiplication of two ciphertexts using BetterTime in the malicious model, offline version, return <x*y,d> with d
*/
static ZZ DGKOperations::CipherMultiplicationHonnest(DGKPublicKey &pubKey,int sock, ZZ x, ZZ y);

/*
 Set of operations that may be used to conduce a Cipher Multiplication on online version , in the malicious model
*/
static std::tuple<ZZ, ZZ, ZZ> DGKOperations::RequestOutSourcedMultiplication(unsigned long (&secrets)[5], DGKPublicKey &pubKey, ZZ x , ZZ y);
static std::tuple<ZZ, ZZ> DGKOperations::PerfomOutSourcedMultiplication(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ xBlinded , ZZ yBlinded, ZZ challenge);
static std::tuple<ZZ, ZZ>  DGKOperations::CompleteOutSourcedMultiplication(DGKPublicKey &pubKey,  ZZ x, ZZ y, ZZ product, ZZ response, unsigned long (&secrets)[5], ZZ xBlinded, ZZ yBlinded);

/*
Corrected version of the Veugen comparison algorithm. It can be used to compare encrypted version of numbers up to l-2 bits, and return an encrypted result.
*/
static ZZ DGKOperations::isSuperiorTo(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ x , ZZ y);
static inline ZZ DGKOperations::PowerModSG(ZZ g , ZZ e , ZZ n ,std::map<unsigned long, ZZ> &lut );

static ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey, int sock,ZZ a, ZZ b, ZZ replaceAbyB);
static ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey, int sock,ZZ a, long b, ZZ replaceAbyB);


/*
Convert a ZZ Big Integer to a (base 255) string, and vice versa
*/
static ZZ DGKOperations::stringToZZ(string str);
static string DGKOperations::ZZToString( ZZ z);

/*
Set of function to send a given type to a destination socket
*/
static void DGKOperations::sendZZ( int sock,ZZ cipher);
static void DGKOperations::sendInt(int sock , int op);

static ZZ DGKOperations::isSuperiorTo(DGKPublicKey &pubKey,int sock, ZZ x, ZZ y);


static vector<int> DGKOperations::topKMaxVanilla(DGKPublicKey &pubKey , DGKPrivateKey &privKey ,vector<ZZ> finputs,int k);
static vector<int> DGKOperations::topKMaxTournament(DGKPublicKey &pubKey , DGKPrivateKey &privKey ,vector<ZZ> finputs,int k);
static vector<int> DGKOperations::topKMaxTournament(DGKPublicKey &pubKey, DGKPrivateKey &privKey, int sock,vector<ZZ> completeInputs,int k);
static vector<ZZ> DGKOperations::topKMaxSwap(DGKPublicKey &pubKey, DGKPrivateKey &privKey, int sock,vector<ZZ> completeInputs,int k);

static ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey , DGKPrivateKey &privKey ,ZZ a , ZZ b , ZZ replaceAbyB);
static ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey , DGKPrivateKey &privKey ,ZZ a , long b , ZZ replaceAbyB);

/*
Set of function used by the Client when he needed to perform some outsourced operations
*/
static void DGKOperations::PerformMultiplicationOutsourced(DGKPublicKey pubkKey, DGKPrivateKey privKey, int stocking);
static void DGKOperations::PerformMultiplicationOutsourcedHonnest(DGKPublicKey pubKey, DGKPrivateKey privKey, int stocking);
static void DGKOperations::isSuperiorToFirstOutsourcedPart(DGKPublicKey pubKey, DGKPrivateKey privKey, int sock);

protected:

    private:
        static int DGKOperations::path(int i, int n);
};

#endif // DGKOPERATIONS_H
