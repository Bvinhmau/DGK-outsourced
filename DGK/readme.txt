The following project implements the DGK cryptosystem and the offline version of some outsourced operations.

The public and private key are implemented as DGKPublicKey and DGKPrivateKey objects, that can be stored in plaintext files with the save/load methods.

Plaintexts are represented as long object (as they are rather small) and ciphertexts use the ZZ class provided by the NTL library.

Important implemented operation are DGKAdd, DGKMultiply, the two vanilla operation of an additive homomorphic cryptosystem. 

CipherMultiplication and CipherMultiplicationHonnest implements an offline version of the outsourced multiplication of two ciphertexts (see BetterTime) in the malicious and the honnest but curious model. In the malicious model, the result and a control value are returned, while the honnest version return only the result.

isInferiorTo implements the (corrected version of) the DGK comparison proposed by Veugen. It can be use to compare encrypted version of numbers up to l-2 bits, and return an encrypted result.

The key generation has been tested with the standard security parameters (160,1024) for plaintexts up to 21 bits. In this case, the key generation took 2h30, and the keys weight a few hundreds of megabytes.
