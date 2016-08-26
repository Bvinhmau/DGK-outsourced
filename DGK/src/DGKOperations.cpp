#include <DGKOperations.h>
#include "DGKPublicKey.h"
#include "DGKPrivateKey.h"
#include "DGKOutSourcedOperationsID.h"
#include "comm.h"

#include <iostream>
#include <tuple>
#include <chrono>
#include <math.h>

#define POSMOD(x,n) ((x % n + n) % n)
using namespace std;
using namespace std::chrono;


// The following method will generate a key pair for the DGK cryptosystem
std::tuple<DGKPrivateKey, DGKPublicKey>  DGKOperations::GenerateKeys(int l, int t, int k)
{
    cout << "Generating Keys..." << endl;
    // First check that all the parameters of the KeyPair are coherent throw an exception otherwise
    if (0 > l || 32 <= l )
    {
        throw std::runtime_error("DGK Keygen Invalid parameters : plaintext space must be less than 32 bits");
    }

    if (l > t ||  t > k )
    {
        throw std::runtime_error("DGK Keygen Invalid parameters: we must have l < k < t");
    }
    if ( k/2 < t + l + 1 )
    {
        throw std::runtime_error("DGK Keygen Invalid parameters: we must have k > k/2 < t + l ");
    }

    if ( t%2 != 0 )
    {
        throw std::runtime_error("DGK Keygen Invalid parameters: t must be divisible by 2 ");
    }
    ZZ p,rp;
    ZZ q,rq;
    ZZ g, h ;
    ZZ n, r ;
    unsigned long u;
    ZZ vp,vq, vpvq,tmp;

    while(true)
    {
        // Generate some of the requiered prime nuber
        ZZ zU  = NTL::NextPrime(NTL::power(ZZ(2),l) + ZZ(2),10);
        conv(u,zU);
        vp = NTL::RandomPrime_ZZ(t,10);
        vq = NTL::RandomPrime_ZZ(t,10);
        vpvq = vp * vq ;
        tmp = u * vp;

        int needed_bits = k/2 - NTL::NumBits(tmp);


        // Generate rp until p is prime such that uvp divde p-1
        do
        {

            rp = NTL::RandomBits_ZZ(needed_bits);
            NTL::SetBit(rp,needed_bits -1);
            p = rp * tmp +1;

        }
        while(!ProbPrime(p,10));  // Thus we ensure that p is a prime, with p-1 dividable by prime numbers vp and u

        tmp = u * vq;
        needed_bits = k/2 - NTL::NumBits(tmp);

// Same method for q than for p

        do
        {

            rq = NTL::RandomBits_ZZ(needed_bits);
            NTL::SetBit(rq,needed_bits -1);

            q = rq * tmp +1;

        }
        while(!ProbPrime(q,10));  // Thus we ensure that q is a prime, with p-1 dividable by prime numbers vq and u
        if(POSMOD(rq,u)!= 0 && POSMOD(rp,u)!= 0 )
        {
            break;
        }

    }
    n = p*q;
    tmp = rp * rq * u ;

    while(true)
    {

        r = NTL::RandomBnd(n);
        h = NTL::PowerMod(r,tmp,n);
        if (h == ZZ(1))
        {
            continue;

        }
        if (NTL::PowerMod(h,vp,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(h,vq,n) == ZZ(1))
        {

            continue;
        }
        if (NTL::PowerMod(h,u,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(h,u*vq,n) == ZZ(1))
        {

            continue;
        }
        if (NTL::PowerMod(h,u*vp,n) == ZZ(1))
        {

            continue;
        }


        if (NTL::GCD(h,n) == ZZ(1))
        {
            break;
        }

    }

    ZZ rprq = rp*rq;

    while(true)
    {

        r = NTL::RandomBnd(n);
        g = NTL::PowerMod(r,rprq,n);

        if (g == ZZ(1))
        {

            continue;
        }

        if (NTL::GCD(g,n) != ZZ(1))
        {

            continue;
        } // Then h can still be of order u,vp, vq , or a combinaison of them different that uvpvq

        if (NTL::PowerMod(g,u,n) == ZZ(1))
        {

            continue;
        }
        if (NTL::PowerMod(g,u*u,n) == ZZ(1))
        {

            continue;
        }
        if (NTL::PowerMod(g,u*u*vp,n) == ZZ(1))
        {

            continue;
        }
        if (NTL::PowerMod(g,u*u*vq,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(g,vp,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(g,vq,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(g,u*vq,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(g,u*vp,n) == ZZ(1))
        {

            continue;
        }

        if (NTL::PowerMod(g,vpvq,n) == ZZ(1))
        {

            continue;
        }
        if (NTL::PowerMod(POSMOD(g,p),vp,p) == ZZ(1))
        {
            // Temporary fix
            continue;
        }
        if (NTL::PowerMod(POSMOD(g,p),u,p) == ZZ(1))
        {
            // Temporary fix
            continue;
        }
        if (NTL::PowerMod(POSMOD(g,q),vq,q) == ZZ(1))
        {
            // Temporary fix
            continue;
        }
        if (NTL::PowerMod(POSMOD(g,q),u,q) == ZZ(1))
        {
            // Temporary fix
            continue;
        }
        break;

    }



    std::map<ZZ, unsigned long> lut;
    /*
        ZZ gvp = PowerMod(POSMOD(g,n),vp*vq,n);
        for (int i=0; i<u; ++i){
            ZZ decipher = PowerMod(gvp,POSMOD(ZZ(i),n),n);
            lut[decipher] = i;
        }
    */
    ZZ gvp = PowerMod(POSMOD(g,p),vp,p);
    for (int i=0; i<u; ++i)
    {
        ZZ decipher = PowerMod(gvp,POSMOD(ZZ(i),p),p);
        lut[decipher] = i;
    }

    std::map<unsigned long, ZZ> hLUT;
    for (int i=0; i<2*t; ++i)
    {
        ZZ e = PowerMod(ZZ(2),i,n);
        ZZ out = PowerMod(h,e,n);
        hLUT[i] = out;
    }

    std::map<unsigned long, ZZ> gLUT;
    for (int i=0; i<u; ++i)
    {
        ZZ out = PowerMod(g,i,n);
        gLUT[i] = out;
    }

    //DGKOperations::GenerateKeys();
    DGKPublicKey pubkey(n,g,h, u, gLUT,hLUT,l,t,k);
    DGKPrivateKey privkey(p,q,vp,vq,lut,u);

    return  std::make_tuple(privkey,pubkey);
}

std::map<unsigned long, ZZ> DGKOperations::generatePreCompLut(DGKPublicKey pubKey)
{
    std::map<unsigned long, ZZ> gLUT;

    ZZ n, g, h,u ;
    n = pubKey.GetN();
    g = pubKey.GetG();
    h = pubKey.GetH();
    u = pubKey.GetU();


    for (int i=0; i<u; ++i)
    {
        ZZ out = PowerMod(g,i,n);
        gLUT[i] = out;
    }
    return gLUT;
}
std::map<unsigned long, ZZ> DGKOperations::generatePreCompLutSG(DGKPublicKey pubKey)
{
    std::map<unsigned long, ZZ> hLUT;
    unsigned long t = 160;
    ZZ n, g, h,u ;
    n = pubKey.GetN();
    g = pubKey.GetG();
    h = pubKey.GetH();
    u = pubKey.GetU();


    for (int i=0; i<2*t; ++i)
    {
        ZZ e = PowerMod(ZZ(2),i,n);
        ZZ out = PowerMod(h,e,n);
        hLUT[i] = out;
    }
    return hLUT;
}
inline ZZ DGKOperations::PowerModSG(ZZ g, ZZ e, ZZ n,std::map<unsigned long, ZZ> &lut )
{
    if (g== 0)
    {
        return ZZ(0) ;
    }
    ZZ result = ZZ(1);
    for(int i = 0; i < NTL::NumBits(e); ++i)
    {
        if(bit(e,i) == 1)
        {
            result = result * lut[i];
        }
    }
    return result;
}
ZZ DGKOperations::encrypt(DGKPublicKey &pubKey, unsigned long plaintext)
{
    int t = pubKey.getT();
    ZZ n, h, u;

    n = pubKey.GetN();
    h = pubKey.GetH();
    u = pubKey.GetU();

    // TODO Thro error is paintext not in Zu
    ZZ ciphertext,r;

    if (0 > plaintext || u <= plaintext )
    {
        throw std::runtime_error("Encryption Invalid Parameter : the plaintext is not in Zu");
    }
    r = NTL::RandomBnd(t*2);
    SetBit(r,t*2-1);
    ZZ firstpart = pubKey.getGLUT(plaintext);
    ZZ secondpart = ZZ(0);
    if (h== 0)
    {
        secondpart = ZZ(0) ;
    }
    secondpart = ZZ(1);
    for(int i = 0; i < NTL::NumBits(r); ++i)
    {
        if(bit(r,i) == 1)
        {
            secondpart = secondpart * pubKey.getHLUT()[i];
        }
    }

    // ZZ secondpart = NTL::PowerMod(h,r,n) ;

    ciphertext = POSMOD(firstpart * secondpart, n);
    return ciphertext;

}


std::map<ZZ, unsigned long> DGKOperations::generateLUT(DGKPublicKey pubKey, DGKPrivateKey privKey)
{
    ZZ n,g,h,u, vp,p ;
    std::map<ZZ, unsigned long> LUT;
    n = pubKey.GetN();
    g = pubKey.GetG();
    h = pubKey.GetH();
    u = pubKey.GetU();
    p = privKey.GetP();
    vp = privKey.GetVP() ;
    ZZ gvp = PowerMod(POSMOD(g,p),vp,p);
    for (int i=0; i<u; ++i)
    {
        ZZ decipher = PowerMod(gvp,POSMOD(ZZ(i),p),p);
        LUT[decipher] = i;
    }
    return LUT;

}
unsigned long DGKOperations::decrypt(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ ciphertext)
{

    //high_resolution_clock::time_point t1 = high_resolution_clock::now();
    ZZ vp,p,n;
// std::map<ZZ, unsigned long> LUT = privKey.GetLUT();
    unsigned long u = pubKey.GetU();
    vp = privKey.GetVP();
    p = privKey.GetP();
    n = pubKey.GetN();

    if (0 > ciphertext || n <= ciphertext )
    {
        throw std::runtime_error("Decryption Invalid Parameter : the ciphertext is not in Zn");
    }

    ZZ decipher = PowerMod(POSMOD(ciphertext,p),vp,p);

    unsigned long plain = privKey.GetLUT(decipher);

    return plain;
}
ZZ DGKOperations::DGKAdd(DGKPublicKey &pubKey, ZZ a, ZZ b)
{

    ZZ n ;
    n = pubKey.GetN();
    if (0 > a || n <= a || 0 >b || n <= b )
    {
        throw std::runtime_error("DGKAdd Invalid Parameter : at least one of the ciphertext is not in Zn");
    }
    ZZ result = MulMod(a,b,n);
    return result;
};

ZZ DGKOperations::DGKMultiply(DGKPublicKey &pubKey, ZZ cipher, unsigned long plaintext)
{
    ZZ n ;
    unsigned long u;
    n = pubKey.GetN();
    u = pubKey.GetU();
    if (0 > cipher || n <= cipher )
    {
        throw std::runtime_error("DGKMultiply Invalid Parameter :  the ciphertext is not in Zn");
    }
    if (0 > plaintext || u <= plaintext )
    {
        throw std::runtime_error("DGKMultiply Invalid Parameter :  the plaintext is not in Zu");
    }
    ZZ result = PowerMod(cipher,plaintext,n);
    return result;
};

std::tuple<ZZ, ZZ> DGKOperations::CipherMultiplication(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ x, ZZ y)
{
    unsigned long u = pubKey.GetU();
    // Generate all the blinding/challenge values
    unsigned long ca = NTL::RandomBnd(u);
    unsigned long cm = NTL::RandomBnd(u-1) +1;
    unsigned long bx = NTL::RandomBnd(u);
    unsigned long by = NTL::RandomBnd(u);
    unsigned long p = NTL::RandomBnd(u-1) +1;

    unsigned long secrets[]= {ca, cm, bx, by,p};
    ZZ caEncrypted = DGKOperations::encrypt(pubKey, ca);
    ZZ bxEncrypted = DGKOperations::encrypt(pubKey, bx);
    ZZ byEncrypted = DGKOperations::encrypt(pubKey, by);
    ZZ pEncrypted  = DGKOperations::encrypt(pubKey, p);

    ZZ xBlinded  = DGKOperations::DGKAdd(pubKey, x, bxEncrypted);
    ZZ yBlinded  = DGKOperations::DGKAdd(pubKey, y, byEncrypted);
    ZZ challenge = DGKOperations::DGKAdd(pubKey, xBlinded, caEncrypted);
    challenge = DGKOperations::DGKMultiply(pubKey, challenge,cm);

    // Send blinded operands and challenge to the key owner
    // Below Owner part
    ZZ product = DGKOperations::encrypt(pubKey,
                                        POSMOD(
                                            ZZ(DGKOperations::decrypt(pubKey,privKey,xBlinded))
                                            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded)),u)
                                       );

    ZZ response = DGKOperations::encrypt(pubKey, POSMOD(
            ZZ(DGKOperations::decrypt(pubKey,privKey,challenge))
            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded )),u));
    // The owner send product + responsefpow

    //Unblind the challegen
    ZZ associated = DGKMultiply(pubKey,
                                DGKAdd(pubKey,
                                       response,
                                       DGKMultiply(pubKey,
                                               DGKAdd(pubKey,
                                                       DGKOperations::DGKMultiply(pubKey,
                                                               product,
                                                               POSMOD(cm,u)),
                                                       DGKOperations::DGKMultiply(pubKey,
                                                               yBlinded,
                                                               POSMOD(ZZ(ca)*ZZ(cm),u))
                                                     ),
                                               long(u-1)
                                                  )
                                      ),
                                p
                               )
                    ;

    // Unblind the Result
    ZZ result = DGKOperations::DGKAdd(pubKey,
                                      product,
                                      DGKOperations::DGKMultiply(pubKey,
                                              DGKOperations::DGKAdd( pubKey,
                                                      DGKOperations::DGKAdd( pubKey,
                                                              DGKOperations::DGKMultiply(pubKey, x, by),
                                                              DGKOperations::DGKMultiply(pubKey, y, bx)),
                                                      DGKOperations::encrypt(pubKey, POSMOD(ZZ(bx)*ZZ(by),u))
                                                                   ),
                                              long(-1 + u)
                                                                )
                                     );
    return  std::make_tuple(result,associated);
    ;
};


ZZ DGKOperations::CipherMultiplicationHonnest(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ x, ZZ y)
{
    unsigned long u = pubKey.GetU();
    // Generate all the blinding/challenge values
    unsigned long ca = NTL::RandomBnd(u);
    unsigned long cm = NTL::RandomBnd(u-1) +1;
    unsigned long bx = NTL::RandomBnd(u);
    unsigned long by = NTL::RandomBnd(u);
    unsigned long p = NTL::RandomBnd(u-1) +1;

    unsigned long secrets[]= {ca, cm, bx, by,p};
    ZZ caEncrypted = DGKOperations::encrypt(pubKey, ca);
    ZZ bxEncrypted = DGKOperations::encrypt(pubKey, bx);
    ZZ byEncrypted = DGKOperations::encrypt(pubKey, by);
    ZZ pEncrypted  = DGKOperations::encrypt(pubKey, p);

    ZZ xBlinded  = DGKOperations::DGKAdd(pubKey, x, bxEncrypted);
    ZZ yBlinded  = DGKOperations::DGKAdd(pubKey, y, byEncrypted);
    ZZ challenge = DGKOperations::DGKAdd(pubKey, xBlinded, caEncrypted);
    challenge = DGKOperations::DGKMultiply(pubKey, challenge,cm);

    // Send blinded operands and challenge to the key owner
    // Below Owner part
    ZZ product = DGKOperations::encrypt(pubKey,
                                        POSMOD(
                                            ZZ(DGKOperations::decrypt(pubKey,privKey,xBlinded))
                                            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded)),u)
                                       );
    // The owner send product



    // Unblind the Result
    ZZ result = DGKOperations::DGKAdd(pubKey,
                                      product,
                                      DGKOperations::DGKMultiply(pubKey,
                                              DGKOperations::DGKAdd( pubKey,
                                                      DGKOperations::DGKAdd( pubKey,
                                                              DGKOperations::DGKMultiply(pubKey, x, by),
                                                              DGKOperations::DGKMultiply(pubKey, y, bx)),
                                                      DGKOperations::encrypt(pubKey, POSMOD(ZZ(bx)*ZZ(by),u))
                                                                   ),
                                              long(-1 + u)
                                                                )
                                     );
    return  result;
    ;
};


std::tuple<ZZ, ZZ, ZZ> DGKOperations::RequestOutSourcedMultiplication(unsigned long (&secrets)[5],DGKPublicKey &pubKey, ZZ x, ZZ y)
{

    unsigned long u = pubKey.GetU();
    // Generate all the blinding/challenge values
    unsigned long ca = NTL::RandomBnd(u);
    unsigned long cm = NTL::RandomBnd(u-1) +1;
    unsigned long bx = NTL::RandomBnd(u);
    unsigned long by = NTL::RandomBnd(u);
    unsigned long p = NTL::RandomBnd(u-1) +1;

    ZZ caEncrypted = DGKOperations::encrypt(pubKey, ca);
    ZZ bxEncrypted = DGKOperations::encrypt(pubKey, bx);
    ZZ byEncrypted = DGKOperations::encrypt(pubKey, by);
    ZZ pEncrypted  = DGKOperations::encrypt(pubKey, p);

    ZZ xBlinded  = DGKOperations::DGKAdd(pubKey, x, bxEncrypted);
    ZZ yBlinded  = DGKOperations::DGKAdd(pubKey, y, byEncrypted);
    ZZ challenge = DGKOperations::DGKAdd(pubKey, xBlinded, caEncrypted);
    challenge = DGKOperations::DGKMultiply(pubKey, challenge,cm);

    //secrets= {ca, cm, bx, by,p,xBlinded,yBlinded};
    (secrets)[0] = ca;
    (secrets)[1] = cm;
    (secrets)[2] = bx;
    (secrets)[3] = by;
    (secrets)[4] = p;

    //TODO add a way to perform the reauest to the server, and send to him the both blinded cipher and the challenge
    return  std::make_tuple(challenge, xBlinded,yBlinded);

}
std::tuple<ZZ, ZZ> DGKOperations::PerfomOutSourcedMultiplication(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ xBlinded, ZZ yBlinded, ZZ challenge)
{
    unsigned long u = pubKey.GetU();

    ZZ product = DGKOperations::encrypt(pubKey,
                                        POSMOD(
                                            ZZ(DGKOperations::decrypt(pubKey,privKey,xBlinded))
                                            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded)),u)
                                       );

    ZZ response = DGKOperations::encrypt(pubKey, POSMOD(
            ZZ(DGKOperations::decrypt(pubKey,privKey,challenge))
            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded )),u));

    return  std::make_tuple(product,response);

}
std::vector<int> DGKOperations::topKMaxVanilla(DGKPublicKey &pubKey, DGKPrivateKey &privKey, vector<ZZ> inputs, int k)
{
// vector<ZZ> results(ZZ(0),k);


    vector<int> results;
    vector<int> ids;
    for (int i = 0; i < inputs.size(); i++)
    {
        ids.push_back(i);
    }
    for (int i = 0 ; i < k ; ++i)
    {
        ZZ maxelem = inputs[0];
        ZZ maxId = DGKOperations::encrypt(pubKey,0);



        for (int j = 0 ; j < inputs.size();  ++j)
        {
            ZZ repl = DGKOperations::isSuperiorTo( pubKey, privKey, maxelem, inputs[j] );
            maxelem =replaceIf(pubKey,privKey,maxelem,inputs[j],repl);
            maxId =replaceIf(pubKey,privKey,maxId,j,repl);

        }
        int idtodelete = DGKOperations::decrypt(pubKey,privKey, maxId); // need an other pairof keys.
        results.push_back(ids[idtodelete]);
        inputs.erase(inputs.begin() + idtodelete);
        ids.erase(ids.begin() + idtodelete);

    }
    return results;
}

vector<int> DGKOperations::topKMaxTournament(DGKPublicKey &pubKey, DGKPrivateKey &privKey,vector<ZZ> completeInputs,int k)
{
    if (k<2)
    {
        return topKMaxVanilla(pubKey,privKey,completeInputs,k);
    }
    vector<ZZ> inputs(completeInputs.size() - k +2);

    for(int i = 0 ; i < (completeInputs.size() - k +2) ; ++i)
    {
        inputs[i] = completeInputs[i];
    }
    vector<int> results;

    ZZ n = ZZ(inputs.size());
    int numbcomp = 0;

    ZZ temp = n ;
    //Compute the number of comparison needed,  required to initialize the parents/childrens vectors

    while(temp > 1)
    {
        ZZ newtemp = ZZ(0);
        for(int i = 0; i < NumBits(temp); ++i)
        {

            if(bit(temp,i))
            {
                numbcomp = numbcomp + pow(2,i) -1;
                newtemp = newtemp + ZZ(1);

            }
        }
        temp =newtemp;

    }
    temp = n ;

    // int id = path(5,20);
    vector<ZZ> cipherlist_(inputs);
    vector<vector<int>> parents(numbcomp+inputs.size());
    vector<int> children(numbcomp+inputs.size(),-1);
    vector<int> inputsid;
    vector<int> newIds;
    vector<int> temparents;

    vector<ZZ> resultscipher;
    vector<int> resultsId;
    temparents.push_back(-1);
    temparents.push_back(-1);

    for(int i = 0; i < inputs.size() + numbcomp; ++i)
    {
        vector<int> newVector(2,-1);
        parents[i]=newVector; // The original inputs possess no parents
        inputsid.push_back(i);
    }
    int iterindex = inputs.size();
    int currentN = inputs.size();

    temp = n ;
    //Build the "tournament tree"
    while(temp > 1)
    {
        ZZ newtemp = ZZ(0);
        vector<int> newinputsId;
        int indexinputs = 0;
        for(int i = NumBits(temp) -1; i >= 0 ; --i)
        {
            if(bit(temp,i) )
            {
                // Subtree of size pow(2,l)
                newtemp = newtemp + ZZ(1);

                if(i != 0 )
                {
                    // "Sub" tree of size pow(2,i)
                    vector<int> treeNodeId;
                    int treeNodeIndex = 0;
                    for(int j = 0 ; j < pow(2,i) ; ++j)
                    {

                        if(j ==  pow(2,i) -1)
                        {
                            newinputsId.push_back(iterindex-1);
                            //  iterindex = iterindex +1;

                        }
                        //Basis of the tree, where the parents of the nodes are the currents inputs

                        else  if(j <pow(2,i-1) )
                        {
                            children[inputsid[indexinputs]] = iterindex;
                            children[inputsid[indexinputs+1]] = iterindex;

                            vector<int> temparents;

                            temparents.push_back(inputsid[indexinputs]);
                            temparents.push_back(inputsid[indexinputs+1]);

                            parents[iterindex] = temparents ;
                            treeNodeId.push_back(iterindex);
                            iterindex = iterindex +1;
                            indexinputs = indexinputs+2;

                        }
                        else
                        {
                            children[treeNodeId[treeNodeIndex]] = iterindex;
                            children[treeNodeId[treeNodeIndex+1]] = iterindex;

                            vector<int> temparents;

                            temparents.push_back(treeNodeId[treeNodeIndex]);
                            temparents.push_back(treeNodeId[treeNodeIndex+1]);
                            parents[iterindex] = temparents ;
                            treeNodeId.push_back(iterindex);
                            iterindex = iterindex +1;
                            treeNodeIndex= treeNodeIndex+2;

                        }
                    }
                }
                else
                {
                    newinputsId.push_back(inputsid[indexinputs]);
                    indexinputs = indexinputs+1;
                }


            }
        }
        temp =newtemp;
        inputsid = newinputsId;



    }

    vector<ZZ> cipherTournam(numbcomp+inputs.size());
    vector<ZZ> iDTournam(numbcomp+inputs.size());

    for(int i = 0 ; i < inputs.size(); ++i)
    {
        cipherTournam[i] = inputs[i];
        iDTournam[i] = encrypt(pubKey,i);
    }
    // Filling the first instance of the tournament
    for(int i = inputs.size(); i< numbcomp+inputs.size() ; i++ )
    {
        vector<int>parentsids = parents[i];
        ZZ compResult = isSuperiorTo(pubKey,privKey,cipherTournam[parentsids[0]],cipherTournam[parentsids[1]]);

        cipherTournam[i] = replaceIf(pubKey,privKey,cipherTournam[parentsids[0]],cipherTournam[parentsids[1]],compResult );
        iDTournam[i] = replaceIf(pubKey,privKey,iDTournam[parentsids[0]],iDTournam[parentsids[1]],compResult );

    }
    resultsId.push_back(decrypt(pubKey,privKey,iDTournam[iDTournam.size()-1])); // break securty assumptation ? do it with vector


    for(int w = 0 ; w < k-1; ++w)
    {

        int idToReplace = resultsId[w];
        int idNewelement = inputs.size() + w;

        if(w == k -2)
        {
            cipherTournam[idToReplace] = encrypt(pubKey,0);
            iDTournam[idToReplace] =   encrypt(pubKey,0);

        }
        else
        {
            cipherTournam[idToReplace] = completeInputs[idNewelement];
            iDTournam[idToReplace] =  encrypt(pubKey,idNewelement);
        }
        int currentIdIndex = idToReplace;

        while(children[currentIdIndex] != -1)
        {
            currentIdIndex = children[currentIdIndex];
            vector<int> currentParents = parents[currentIdIndex];

            ZZ compResult = isSuperiorTo(pubKey,privKey,cipherTournam[currentParents[0]],cipherTournam[currentParents[1]]);


            cipherTournam[currentIdIndex] = replaceIf(pubKey,privKey,cipherTournam[currentParents[0]],cipherTournam[currentParents[1]],compResult );

            iDTournam[currentIdIndex] = replaceIf(pubKey,privKey,iDTournam[currentParents[0]],iDTournam[currentParents[1]],compResult );
        }

        resultsId.push_back(decrypt(pubKey,privKey,iDTournam[iDTournam.size()-1])); // break secu assumption again ??

    }
    return resultsId;
}
int DGKOperations::path(int i, int n)
{
    vector<int> positions;
    ZZ zzN = ZZ(n);
    int numBits = NumBits(zzN);
    int startposition = 0;
    for(int j = 0; j < numBits; ++j)
    {
        if(bit(zzN,numBits-j))
        {

            if(i <= startposition + pow(2,numBits-j)  )
            {
                break;
            }
            else
            {
                startposition = startposition+ pow(2,numBits-j);

            }
        }
    }

    return i;
}
ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey, DGKPrivateKey &privKey,ZZ a, ZZ b, ZZ replaceAbyB)
{
    unsigned long u = pubKey.GetU();

    ZZ result = DGKAdd(pubKey,
                       DGKOperations::CipherMultiplicationHonnest(pubKey,privKey,a,replaceAbyB),
                       DGKOperations::CipherMultiplicationHonnest(pubKey,privKey,b,
                               DGKAdd(pubKey,
                                      DGKOperations::encrypt(pubKey,1),
                                      DGKOperations::DGKMultiply(pubKey,replaceAbyB,long(u-1)) )
                                                                 ));
    return result;
}
ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey, DGKPrivateKey &privKey,ZZ a, long b, ZZ replaceAbyB)
{
    unsigned long u = pubKey.GetU();

    ZZ result = DGKAdd(pubKey,
                       DGKOperations::CipherMultiplicationHonnest(pubKey,privKey,a,replaceAbyB),
                       DGKOperations::DGKMultiply(pubKey,
                               DGKAdd(pubKey,
                                      DGKOperations::encrypt(pubKey,1),
                                      DGKOperations::DGKMultiply(pubKey,replaceAbyB,long(u-1)) )
                               ,b));
    return result;
}

std::tuple<ZZ, ZZ>  DGKOperations::CompleteOutSourcedMultiplication(DGKPublicKey &pubKey,  ZZ x, ZZ y, ZZ product, ZZ response, unsigned long (&secrets)[5], ZZ xBlinded, ZZ yBlinded)
{
    unsigned long ca =(secrets)[0];
    unsigned long cm =(secrets)[1];
    unsigned long bx = (secrets)[2];
    unsigned long by = (secrets)[3];
    unsigned long p  =(secrets)[4] ;
    unsigned long u = pubKey.GetU();
    ZZ associated = DGKMultiply(pubKey,
                                DGKAdd(pubKey,
                                       response,
                                       DGKMultiply(pubKey,
                                               DGKAdd(pubKey,
                                                       DGKOperations::DGKMultiply(pubKey,
                                                               product,
                                                               POSMOD(cm,u)),
                                                       DGKOperations::DGKMultiply(pubKey,
                                                               yBlinded,
                                                               POSMOD(ZZ(ca)*ZZ(cm),u))
                                                     ),
                                               long(u-1)
                                                  )
                                      ),
                                p
                               )
                    ;

    // Unblind the Result
    ZZ result = DGKOperations::DGKAdd(pubKey,
                                      product,
                                      DGKOperations::DGKMultiply(pubKey,
                                              DGKOperations::DGKAdd( pubKey,
                                                      DGKOperations::DGKAdd( pubKey,
                                                              DGKOperations::DGKMultiply(pubKey, x, by),
                                                              DGKOperations::DGKMultiply(pubKey, y, bx)),
                                                      DGKOperations::encrypt(pubKey, POSMOD(ZZ(bx)*ZZ(by),u))
                                                                   ),
                                              long(-1 + u)
                                                                )
                                     );
    return  std::make_tuple(result,associated);


}

ZZ DGKOperations::stringToZZ(string str)
{
    ZZ result = ZZ();
    int l = str.length();
    for (int i = 0 ; i < l ; i++)
    {
        ZZ incr = ZZ((( unsigned char) str[i] ))* NTL::power(ZZ(256),l-1-i);
        result = result + incr;

    }
    return result;

}


string DGKOperations::ZZToString( ZZ z)
{
    string result ;
    int  l = NumBits(z);
    if(l == 0)
    {
        return "0";
    }
    int lBase255 = ceil((l-1)/8) + 1;

    for (int i = 0 ; i < lBase255; i++)
    {
        ZZ expo = NTL::power(ZZ(256), lBase255 -1 - i) ;
        ZZ quotient = z / expo;
        POSMOD(z,expo);
        //   z = z %  pow(256, lBase255 -1 - i);
        unsigned int asInt = conv<unsigned int>(quotient);

        unsigned char c = (unsigned char) asInt;
        result += c;
    }
    return result;

}
ZZ DGKOperations::isSuperiorTo(DGKPublicKey &pubKey,DGKPrivateKey &privKey, ZZ x, ZZ y )
{
    // A & B
    int l = pubKey.getL() -2 ; // see constraints in the veugen paper
    int N = pubKey.GetU();
    int u = pubKey.GetU();
    int powL = pow(2,l);

    // A
    unsigned long r = NTL::RandomBnd(N);//

    //r = 5; //TODO remove this heresy
    ZZ encR = encrypt(pubKey,r);
    long alpha = POSMOD(r,powL);
    ZZ alphaZZ = ZZ(alpha);
    ZZ z = DGKAdd(pubKey,
                  encrypt(pubKey,powL),
                  DGKAdd(pubKey,
                         encR,
                         DGKAdd(pubKey, x, DGKMultiply(pubKey,y,u-1))));
    // B
    long plainZ = decrypt(pubKey,privKey,z);

    long beta = POSMOD(plainZ,powL);
    ZZ encBetaMayOverflow = encrypt(pubKey,(beta >= (powL - POSMOD(N,powL))));
    ZZ d ;
    if ( plainZ < (N-1)/2)
    {
        d = encrypt(pubKey,1);
    }
    else
    {
        d = encrypt(pubKey,0);
    }
    long betaTab [l];
    ZZ encBetaTab [l];

    for(int i = 0 ; i < l ; i++)
    {
        betaTab[i] = bit(beta,i);
        encBetaTab[i] = encrypt(pubKey, betaTab[i]);
    }
    //A
    if (r < (N-1)/2)
    {
        d = encrypt(pubKey,0);

    }
    ZZ encAlphaXORBetaTab [l];
    ZZ W [l];
    ZZ c [l+1];


    long alphaHat = POSMOD(r-N,powL);
    ZZ xorBitsSum = encrypt(pubKey,0);
    ZZ alphaHatZZ = ZZ(alphaHat);
    for(int i = 0 ; i < l ; i++)
    {
        if(bit(alpha,i) == 0)
        {
            encAlphaXORBetaTab[i] = encBetaTab[i];
        }
        else
        {
            encAlphaXORBetaTab[i] = DGKAdd(pubKey,  encrypt(pubKey,1), DGKMultiply(pubKey,encBetaTab[i],u-1));
        }
        if(bit(alphaZZ,i) == bit(alphaHatZZ,i))
        {
            W[i] = encAlphaXORBetaTab[i];
            //  xorBitsSum = DGKAdd(pubKey,xorBitsSum,encAlphaXORBetaTab[i] );

        }
        else
        {
            W[i] = DGKAdd(pubKey,  encAlphaXORBetaTab[i], DGKMultiply(pubKey,d,u-1));
            // W[i] = encAlphaXORBetaTab[i];

            // xorBitsSum = DGKAdd(pubKey,xorBitsSum,DGKAdd(pubKey,encrypt(pubKey,1),DGKMultiply(pubKey,encAlphaXORBetaTab[i],u-1)) );

        }

        W[i] = DGKMultiply(pubKey, W[i],pow(2,i));
        xorBitsSum = DGKAdd(pubKey,xorBitsSum,DGKMultiply(pubKey,W[i],2 ));
    }
    long da = RandomBnd(2);
    long s = 1 -2*da;
    ZZ wProduct = encrypt(pubKey,0);
    for(int i = 0 ; i < l ; i++)
    {


        long alphaexp = POSMOD( bit(alphaHatZZ,l-1-i) -  bit(alphaZZ,l-1-i), u);
        c[l-1-i] =  DGKAdd(pubKey,
                           wProduct,
                           DGKAdd(pubKey, DGKAdd(pubKey,DGKMultiply(pubKey,encBetaTab[l-1-i],u-1),encrypt(pubKey, POSMOD(s + bit(alphaZZ, l-1-i), N) )), DGKMultiply(pubKey,d,alphaexp)));

        ZZ rBlind = NTL::RandomBits_ZZ(pubKey.getT() * 2);
        NTL::SetBit(rBlind,pubKey.getT() * 2 -1);
        //TODO BLIND
        wProduct = DGKAdd(pubKey,wProduct,DGKMultiply(pubKey, W[l-1-i],3));

    }
    c[l] = DGKAdd(pubKey, encrypt(pubKey,da),xorBitsSum);
    // A shuffle C

    // B
    ZZ db =  encrypt(pubKey,0);
    for(int i = 0 ; i < l+1 ; i++)
    {
        if(decrypt(pubKey, privKey,c[i]) == 0)
        {
            db= encrypt(pubKey,1);
            break;
        }
    }
    ZZ divZ = encrypt(pubKey,plainZ/powL);


    //A
    ZZ betaInfAlpha;
    if (da == 1)
    {
        betaInfAlpha = db;
    }
    else
    {
        betaInfAlpha = DGKAdd(pubKey,encrypt(pubKey,1),DGKMultiply(pubKey, db, u -1));
    }



    ZZ overflow = DGKMultiply(pubKey,d,1+N/powL);
    ZZ doubleBucketGap ;
    if (beta >= powL - POSMOD(N,powL))
    {
        doubleBucketGap = encrypt(pubKey,0);


    }
    else
    {
        doubleBucketGap = DGKMultiply(pubKey, d, u -1);

    }
    overflow = DGKAdd(pubKey,overflow,doubleBucketGap);
    ZZ result = DGKAdd(pubKey,
                       DGKAdd(pubKey,
                              divZ,
                              DGKMultiply(pubKey,DGKAdd(pubKey, encrypt(pubKey,r/powL),betaInfAlpha), u-1))
                       , overflow);
    long lastpush = 0;

    lastpush = decrypt(pubKey,privKey,d) *(
                   (1 -decrypt(pubKey,privKey,betaInfAlpha))*(1 - (alpha < POSMOD(N,powL)))* (beta >= (powL - POSMOD(N,powL)))
                   +(decrypt(pubKey,privKey,betaInfAlpha))*(0 - (alpha < POSMOD(N,powL)))* (1-(beta >= (powL - POSMOD(N,powL))))
               );


    ZZ effectOfAlphaBetaOverflow = std::get<0>((CipherMultiplication(pubKey,privKey,betaInfAlpha,encBetaMayOverflow )));
    effectOfAlphaBetaOverflow = DGKMultiply(pubKey,effectOfAlphaBetaOverflow, POSMOD(2 * (alpha < POSMOD(N,powL)) - 1,N));
    effectOfAlphaBetaOverflow = DGKAdd(pubKey,effectOfAlphaBetaOverflow,DGKMultiply(pubKey,DGKAdd(pubKey, encBetaMayOverflow, betaInfAlpha),POSMOD(N-(alpha < POSMOD(N,powL)),N)));
    effectOfAlphaBetaOverflow = DGKAdd(pubKey, effectOfAlphaBetaOverflow,encBetaMayOverflow );
    effectOfAlphaBetaOverflow = std::get<0>(CipherMultiplication(pubKey,privKey,effectOfAlphaBetaOverflow,d));
    // encBetaMayOverflow
    result = DGKAdd(pubKey,result,DGKMultiply(pubKey,effectOfAlphaBetaOverflow,u-1));

    return result;
}


ZZ rcvZZ(int sock)
{
    std::string  tempciph  = "tempZZ";
    recvFile(sock, (char *)tempciph.c_str());

    //std::string cipherString;
    ZZ cipher;
    std::ifstream myfile2;

    myfile2.open("tempZZ");
    myfile2 >> cipher;
    // cipherString =  sstr.str();
    myfile2.close();
    return cipher;
}
void DGKOperations::sendInt(int sock, int op)
{
    std::ofstream myfile;
    myfile.open ("temp.txt");
    myfile << op;

    myfile.close();
    std::string tmp = "temp.txt";
    sendFile(sock, (char *)tmp.c_str());
}
void DGKOperations::sendZZ( int sock,ZZ cipher)
{

    std::ofstream myfile;
    myfile.open ("tempZZ.txt");
    myfile << cipher;

    myfile.close();

    std::string tmp = "tempZZ.txt";
    sendFile(sock, (char *)tmp.c_str());
}

void DGKOperations::PerformMultiplicationOutsourced(DGKPublicKey pubKey, DGKPrivateKey privKey, int stocking)
{
    ZZ xBlinded = rcvZZ(stocking);
    ZZ yBlinded = rcvZZ(stocking);
    ZZ challenge = rcvZZ(stocking);

    long u = pubKey.GetU();
    ZZ product = DGKOperations::encrypt(pubKey,
                                        POSMOD(
                                            ZZ(DGKOperations::decrypt(pubKey,privKey,xBlinded))
                                            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded)),u)
                                       );

    ZZ response = DGKOperations::encrypt(pubKey, POSMOD(
            ZZ(DGKOperations::decrypt(pubKey,privKey,challenge))
            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded )),u));
    DGKOperations::sendZZ(stocking,product);
    DGKOperations::sendZZ(stocking,response);
    // The owner send product + responsefpow
}


std::tuple<ZZ, ZZ> DGKOperations::CipherMultiplication(DGKPublicKey &pubKey,int sock, ZZ x, ZZ y)
{
    unsigned long u = pubKey.GetU();
    // Generate all the blinding/challenge values
    unsigned long ca = NTL::RandomBnd(u);
    unsigned long cm = NTL::RandomBnd(u-1) +1;
    unsigned long bx = NTL::RandomBnd(u);
    unsigned long by = NTL::RandomBnd(u);
    unsigned long p = NTL::RandomBnd(u-1) +1;

    unsigned long secrets[]= {ca, cm, bx, by,p};
    ZZ caEncrypted = DGKOperations::encrypt(pubKey, ca);
    ZZ bxEncrypted = DGKOperations::encrypt(pubKey, bx);
    ZZ byEncrypted = DGKOperations::encrypt(pubKey, by);
    ZZ pEncrypted  = DGKOperations::encrypt(pubKey, p);

    ZZ xBlinded  = DGKOperations::DGKAdd(pubKey, x, bxEncrypted);
    ZZ yBlinded  = DGKOperations::DGKAdd(pubKey, y, byEncrypted);
    ZZ challenge = DGKOperations::DGKAdd(pubKey, xBlinded, caEncrypted);
    challenge = DGKOperations::DGKMultiply(pubKey, challenge,cm);

    DGKOperations::sendInt(sock,DO_OUTSOURCEDMULTIPLICATION);



    // Send blinded operands and challenge to the key owner

    DGKOperations::sendZZ(sock,xBlinded);
    DGKOperations::sendZZ(sock,yBlinded);
    DGKOperations::sendZZ(sock,challenge);
    ZZ product = rcvZZ(sock);
    ZZ response = rcvZZ(sock);




    //Unblind the challegen
    ZZ associated = DGKMultiply(pubKey,
                                DGKAdd(pubKey,
                                       response,
                                       DGKMultiply(pubKey,
                                               DGKAdd(pubKey,
                                                       DGKOperations::DGKMultiply(pubKey,
                                                               product,
                                                               POSMOD(cm,u)),
                                                       DGKOperations::DGKMultiply(pubKey,
                                                               yBlinded,
                                                               POSMOD(ZZ(ca)*ZZ(cm),u))
                                                     ),
                                               long(u-1)
                                                  )
                                      ),
                                p
                               )
                    ;

    // Unblind the Result
    ZZ result = DGKOperations::DGKAdd(pubKey,
                                      product,
                                      DGKOperations::DGKMultiply(pubKey,
                                              DGKOperations::DGKAdd( pubKey,
                                                      DGKOperations::DGKAdd( pubKey,
                                                              DGKOperations::DGKMultiply(pubKey, x, by),
                                                              DGKOperations::DGKMultiply(pubKey, y, bx)),
                                                      DGKOperations::encrypt(pubKey, POSMOD(ZZ(bx)*ZZ(by),u))
                                                                   ),
                                              long(-1 + u)
                                                                )
                                     );
    return  std::make_tuple(result,associated);
    ;
}

void DGKOperations::PerformMultiplicationOutsourcedHonnest(DGKPublicKey pubKey, DGKPrivateKey privKey, int stocking)
{
    ZZ xBlinded = rcvZZ(stocking);
    ZZ yBlinded = rcvZZ(stocking);


    long u = pubKey.GetU();
    ZZ product = DGKOperations::encrypt(pubKey,
                                        POSMOD(
                                            ZZ(DGKOperations::decrypt(pubKey,privKey,xBlinded))
                                            * ZZ(DGKOperations::decrypt(pubKey,privKey,yBlinded)),u)
                                       );

    DGKOperations::sendZZ(stocking,product);

    // The owner send product + responsefpow
}



ZZ DGKOperations::CipherMultiplicationHonnest(DGKPublicKey &pubKey,int sock, ZZ x, ZZ y)
{
    unsigned long u = pubKey.GetU();
    // Generate all the blinding/challenge values
    unsigned long bx = NTL::RandomBnd(u);
    unsigned long by = NTL::RandomBnd(u);
    ZZ bxEncrypted = DGKOperations::encrypt(pubKey, bx);
    ZZ byEncrypted = DGKOperations::encrypt(pubKey, by);

    ZZ xBlinded  = DGKOperations::DGKAdd(pubKey, x, bxEncrypted);
    ZZ yBlinded  = DGKOperations::DGKAdd(pubKey, y, byEncrypted);
    DGKOperations::sendInt(sock,DO_OUTSOURCEDHONNESTMULTIPLICATION);




    DGKOperations::sendZZ(sock,xBlinded);
    DGKOperations::sendZZ(sock,yBlinded);

    ZZ product = rcvZZ(sock);






    // Unblind the Result
    ZZ result = DGKOperations::DGKAdd(pubKey,
                                      product,
                                      DGKOperations::DGKMultiply(pubKey,
                                              DGKOperations::DGKAdd( pubKey,
                                                      DGKOperations::DGKAdd( pubKey,
                                                              DGKOperations::DGKMultiply(pubKey, x, by),
                                                              DGKOperations::DGKMultiply(pubKey, y, bx)),
                                                      DGKOperations::encrypt(pubKey, POSMOD(ZZ(bx)*ZZ(by),u))
                                                                   ),
                                              long(-1 + u)
                                                                )
                                     );
    return  result;
    ;
}

ZZ DGKOperations::isSuperiorTo(DGKPublicKey &pubKey,int sock, ZZ x, ZZ y)
{
    // A & B
    int l = pubKey.getL() -2 ; // see constraints in the veugen paper
    int N = pubKey.GetU();
    int u = pubKey.GetU();
    int powL = pow(2,l);

    // A
    unsigned long r = NTL::RandomBnd(N);//
    ZZ encR = encrypt(pubKey,r);
    long alpha = POSMOD(r,powL);
    ZZ alphaZZ = ZZ(alpha);
    ZZ z = DGKAdd(pubKey,
                  encrypt(pubKey,powL),
                  DGKAdd(pubKey,
                         encR,
                         DGKAdd(pubKey, x, DGKMultiply(pubKey,y,u-1))));
    // SEND TO B
    sendInt(sock,DO_COMPARISONFIRSTPART);
    sendZZ(sock,z);
    ZZ encBetaTab [l];
    ZZ d = rcvZZ(sock);

    for(int i = 0 ; i < l ; i++)
    {
        encBetaTab[i] = rcvZZ(sock);
    }
    //A
    if (r < (N-1)/2)
    {
        d = encrypt(pubKey,0);

    }
    ZZ encAlphaXORBetaTab [l];
    ZZ W [l];
    ZZ c [l+1];


    long alphaHat = POSMOD(r-N,powL);
    ZZ xorBitsSum = encrypt(pubKey,0);
    ZZ alphaHatZZ = ZZ(alphaHat);
    for(int i = 0 ; i < l ; i++)
    {
        if(bit(alpha,i) == 0)
        {
            encAlphaXORBetaTab[i] = encBetaTab[i];
        }
        else
        {
            encAlphaXORBetaTab[i] = DGKAdd(pubKey,  encrypt(pubKey,1), DGKMultiply(pubKey,encBetaTab[i],u-1));
        }
        if(bit(alphaZZ,i) == bit(alphaHatZZ,i))
        {
            W[i] = encAlphaXORBetaTab[i];
            //  xorBitsSum = DGKAdd(pubKey,xorBitsSum,encAlphaXORBetaTab[i] );

        }
        else
        {
            W[i] = DGKAdd(pubKey,  encAlphaXORBetaTab[i], DGKMultiply(pubKey,d,u-1));
            // W[i] = encAlphaXORBetaTab[i];

            // xorBitsSum = DGKAdd(pubKey,xorBitsSum,DGKAdd(pubKey,encrypt(pubKey,1),DGKMultiply(pubKey,encAlphaXORBetaTab[i],u-1)) );

        }

        W[i] = DGKMultiply(pubKey, W[i],pow(2,i));
        xorBitsSum = DGKAdd(pubKey,xorBitsSum,DGKMultiply(pubKey,W[i],2 ));
    }
    long da = RandomBnd(2);
    long s = 1 -2*da;
    ZZ wProduct = encrypt(pubKey,0);
    for(int i = 0 ; i < l ; i++)
    {


        long alphaexp = POSMOD( bit(alphaHatZZ,l-1-i) -  bit(alphaZZ,l-1-i), u);
        c[l-1-i] =  DGKAdd(pubKey,
                           wProduct,
                           DGKAdd(pubKey, DGKAdd(pubKey,DGKMultiply(pubKey,encBetaTab[l-1-i],u-1),encrypt(pubKey, POSMOD(s + bit(alphaZZ, l-1-i), N) )), DGKMultiply(pubKey,d,alphaexp)));

        sendZZ(sock,c[l-1-i] );
        ZZ rBlind = NTL::RandomBits_ZZ(pubKey.getT() * 2);
        NTL::SetBit(rBlind,pubKey.getT() * 2 -1);
        //TODO BLIND
        wProduct = DGKAdd(pubKey,wProduct,DGKMultiply(pubKey, W[l-1-i],3));

    }


    c[l] = DGKAdd(pubKey, encrypt(pubKey,da),xorBitsSum);
    sendZZ(sock,c[l] );

    // TODO A shuffle C

    // B , A send C


    //A

    ZZ db = rcvZZ(sock);
    ZZ divZ = rcvZZ(sock);
    ZZ betaInfAlpha;
    if (da == 1)
    {
        betaInfAlpha = db;
    }
    else
    {
        betaInfAlpha = DGKAdd(pubKey,encrypt(pubKey,1),DGKMultiply(pubKey, db, u -1));
    }



    ZZ overflow = DGKMultiply(pubKey,d,1+N/powL);
    ZZ doubleBucketGap ;
    ZZ betaToosmall = rcvZZ(sock);
    ZZ betaToosmall2 = rcvZZ(sock);

    ZZ result = DGKAdd(pubKey,
                       divZ,
                       DGKMultiply(pubKey,DGKAdd(pubKey, encrypt(pubKey,r/powL),betaInfAlpha), u-1))
                ;


    ZZ correctionincrement = DGKOperations::encrypt(pubKey,1+N/powL);
    correctionincrement = DGKOperations::DGKAdd(pubKey,
                          correctionincrement,
                          DGKOperations::DGKMultiply(pubKey,betaToosmall,u-1));

    ZZ correctionincrementSecondPart = DGKOperations::DGKMultiply(pubKey,betaToosmall2, 1 - (alpha < POSMOD(N,powL) ));
    correctionincrementSecondPart = DGKOperations::CipherMultiplicationHonnest(pubKey,sock,
                                    DGKAdd(pubKey,
                                           DGKOperations::encrypt(pubKey,1),
                                           DGKOperations::DGKMultiply(pubKey,betaInfAlpha,u-1)),
                                    correctionincrementSecondPart);


    ZZ correctionincrementThirdPart   = DGKOperations::DGKMultiply(pubKey,
                                        DGKOperations::DGKAdd(pubKey,
                                                DGKOperations::encrypt(pubKey,1),
                                                DGKOperations::DGKMultiply(pubKey,betaToosmall2,u-1)),
                                        POSMOD( - (alpha < POSMOD(N,powL)),u));




    correctionincrementThirdPart = DGKOperations::CipherMultiplicationHonnest(pubKey,sock,
                                   betaInfAlpha,
                                   correctionincrementThirdPart);
    correctionincrementSecondPart = DGKOperations::DGKMultiply(pubKey,correctionincrementSecondPart, u-1);

    correctionincrementThirdPart = DGKOperations::DGKMultiply(pubKey,correctionincrementThirdPart, u-1);

    correctionincrement = DGKAdd(pubKey,correctionincrement,correctionincrementSecondPart);
    correctionincrement = DGKAdd(pubKey,correctionincrement,correctionincrementThirdPart);

    correctionincrement = DGKOperations::CipherMultiplicationHonnest(pubKey,sock,d,correctionincrement);






    result = DGKAdd(pubKey,result,correctionincrement);

    return result;
}

void DGKOperations::isSuperiorToFirstOutsourcedPart(DGKPublicKey pubKey, DGKPrivateKey privKey, int sock)
{




    int l = pubKey.getL() -2 ; // see constraints in the veugen paper
    int N = pubKey.GetU();
    int u = pubKey.GetU();
    int powL = pow(2,l);

    ZZ z = rcvZZ(sock);
    long plainZ = DGKOperations::decrypt(pubKey,privKey,z);

    long beta = POSMOD(plainZ,powL);
    ZZ encBetaMayOverflow = DGKOperations::encrypt(pubKey,(beta >= (powL - POSMOD(N,powL))));
    ZZ d ;
    if ( plainZ < (N-1)/2)
    {
        d = DGKOperations::encrypt(pubKey,1);
    }
    else
    {
        d = DGKOperations::encrypt(pubKey,0);
    }
    DGKOperations::sendZZ(sock, d);

    long betaTab [l];
    ZZ encBetaTab [l];

    for(int i = 0 ; i < l ; i++)
    {
        betaTab[i] = bit(beta,i);
        encBetaTab[i] = DGKOperations::encrypt(pubKey, betaTab[i]);
        DGKOperations::sendZZ(sock, encBetaTab[i]);
    }
    ZZ db = DGKOperations::encrypt(pubKey,0);
    for(int i = 0 ; i < l+1 ; i++)
    {
        ZZ c = rcvZZ(sock);
        if(DGKOperations::decrypt(pubKey, privKey,c) == 0)
        {
            db= DGKOperations::encrypt(pubKey,1);
            //break;
        }
    }
    ZZ divZ = DGKOperations::encrypt(pubKey,plainZ/powL);

    DGKOperations::sendZZ(sock,db);
    DGKOperations::sendZZ(sock,divZ);

    int betaTooSmall = 1;
    if (beta > powL - POSMOD(N,powL))
    {
        betaTooSmall = 0;
    }

    int betaTooSmall2 = 0;
    if (beta > powL - POSMOD(N,powL))
    {
        betaTooSmall = 1;
    }


    DGKOperations::sendZZ(sock, DGKOperations::encrypt(pubKey,betaTooSmall));
    DGKOperations::sendZZ(sock, DGKOperations::encrypt(pubKey,betaTooSmall2));



}
ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey, int sock,ZZ a, ZZ b, ZZ replaceAbyB)
{
    unsigned long u = pubKey.GetU();

    ZZ result = DGKAdd(pubKey,
                       DGKOperations::CipherMultiplicationHonnest(pubKey,sock,a,replaceAbyB),
                       DGKOperations::CipherMultiplicationHonnest(pubKey,sock,b,
                               DGKAdd(pubKey,
                                      DGKOperations::encrypt(pubKey,1),
                                      DGKOperations::DGKMultiply(pubKey,replaceAbyB,long(u-1)) )
                                                                 ));
    return result;
}
ZZ DGKOperations::replaceIf(DGKPublicKey &pubKey, int sock,ZZ a, long b, ZZ replaceAbyB)
{
    unsigned long u = pubKey.GetU();

    ZZ result = DGKAdd(pubKey,
                       DGKOperations::CipherMultiplicationHonnest(pubKey,sock,a,replaceAbyB),
                       DGKOperations::DGKMultiply(pubKey,
                               DGKAdd(pubKey,
                                      DGKOperations::encrypt(pubKey,1),
                                      DGKOperations::DGKMultiply(pubKey,replaceAbyB,long(u-1)) )
                               ,b));
    return result;
}

vector<int> DGKOperations::topKMaxTournament(DGKPublicKey &pubKey, DGKPrivateKey &privKey, int sock,vector<ZZ> completeInputs,int k)
{
    if (k<2)
    {
        return topKMaxVanilla(pubKey,privKey,completeInputs,k);
    }
    vector<ZZ> inputs(completeInputs.size() - k +2);

    for(int i = 0 ; i < (completeInputs.size() - k +2) ; ++i)
    {
        inputs[i] = completeInputs[i];
    }
    vector<int> results;

    ZZ n = ZZ(inputs.size());
    int numbcomp = 0;

    ZZ temp = n ;
    //Compute the number of comparison needed,  required to initialize the parents/childrens vectors

    while(temp > 1)
    {
        ZZ newtemp = ZZ(0);
        for(int i = 0; i < NumBits(temp); ++i)
        {

            if(bit(temp,i))
            {
                numbcomp = numbcomp + pow(2,i) -1;
                newtemp = newtemp + ZZ(1);

            }
        }
        temp =newtemp;

    }
    temp = n ;

    // int id = path(5,20);
    vector<ZZ> cipherlist_(inputs);
    vector<vector<int>> parents(numbcomp+inputs.size());
    vector<int> children(numbcomp+inputs.size(),-1);
    vector<int> inputsid;
    vector<int> newIds;
    vector<int> temparents;

    vector<ZZ> resultscipher;
    vector<int> resultsId;
    temparents.push_back(-1);
    temparents.push_back(-1);

    for(int i = 0; i < inputs.size() + numbcomp; ++i)
    {
        vector<int> newVector(2,-1);
        parents[i]=newVector; // The original inputs possess no parents
        inputsid.push_back(i);
    }
    int iterindex = inputs.size();
    int currentN = inputs.size();

    temp = n ;
    //Build the "tournament tree"
    while(temp > 1)
    {
        ZZ newtemp = ZZ(0);
        vector<int> newinputsId;
        int indexinputs = 0;
        for(int i = NumBits(temp) -1; i >= 0 ; --i)
        {
            if(bit(temp,i) )
            {
                // Subtree of size pow(2,l)
                newtemp = newtemp + ZZ(1);

                if(i != 0 )
                {
                    // "Sub" tree of size pow(2,i)
                    vector<int> treeNodeId;
                    int treeNodeIndex = 0;
                    for(int j = 0 ; j < pow(2,i) ; ++j)
                    {

                        if(j ==  pow(2,i) -1)
                        {
                            newinputsId.push_back(iterindex-1);
                            //  iterindex = iterindex +1;

                        }
                        //Basis of the tree, where the parents of the nodes are the currents inputs

                        else  if(j <pow(2,i-1) )
                        {
                            children[inputsid[indexinputs]] = iterindex;
                            children[inputsid[indexinputs+1]] = iterindex;
                            vector<int> temparents;

                            temparents.push_back(inputsid[indexinputs]);
                            temparents.push_back(inputsid[indexinputs+1]);

                            parents[iterindex] = temparents ;
                            treeNodeId.push_back(iterindex);
                            iterindex = iterindex +1;
                            indexinputs = indexinputs+2;

                        }
                        else
                        {
                            children[treeNodeId[treeNodeIndex]] = iterindex;
                            children[treeNodeId[treeNodeIndex+1]] = iterindex;


                            vector<int> temparents;

                            temparents.push_back(treeNodeId[treeNodeIndex]);
                            temparents.push_back(treeNodeId[treeNodeIndex+1]);
                            parents[iterindex] = temparents ;
                            treeNodeId.push_back(iterindex);
                            iterindex = iterindex +1;
                            treeNodeIndex= treeNodeIndex+2;

                        }
                    }
                }
                else
                {
                    newinputsId.push_back(inputsid[indexinputs]);
                    indexinputs = indexinputs+1;
                }


            }
        }
        temp =newtemp;
        inputsid = newinputsId;



    }

    vector<ZZ> cipherTournam(numbcomp+inputs.size());
    vector<ZZ> iDTournam(numbcomp+inputs.size());

    for(int i = 0 ; i < inputs.size(); ++i)
    {
        cipherTournam[i] = inputs[i];
        iDTournam[i] = encrypt(pubKey,i);
    }
    // Filling the first instance of the tournament
    for(int i = inputs.size(); i< numbcomp+inputs.size() ; i++ )
    {
        vector<int>parentsids = parents[i];

        ZZ compResult = isSuperiorTo(pubKey,sock,cipherTournam[parentsids[0]],cipherTournam[parentsids[1]]);

        cipherTournam[i] = replaceIf(pubKey,sock,cipherTournam[parentsids[0]],cipherTournam[parentsids[1]],compResult );
        iDTournam[i] = replaceIf(pubKey,sock,iDTournam[parentsids[0]],iDTournam[parentsids[1]],compResult );

    }

    resultsId.push_back(decrypt(pubKey,privKey,iDTournam[iDTournam.size()-1])); // break securty assumptation ? do it with vector

    for(int w = 0 ; w < k-1; ++w)
    {

        int idToReplace = resultsId[w];
        int idNewelement = inputs.size() + w;

        if(w == k -2)
        {
            cipherTournam[idToReplace] = encrypt(pubKey,0);
            iDTournam[idToReplace] =   encrypt(pubKey,0);

        }
        else
        {
            cipherTournam[idToReplace] = completeInputs[idNewelement];
            iDTournam[idToReplace] =  encrypt(pubKey,idNewelement);
        }
        int currentIdIndex = idToReplace;

        while(children[currentIdIndex] != -1)
        {
            currentIdIndex = children[currentIdIndex];
            vector<int> currentParents = parents[currentIdIndex];

            ZZ compResult = isSuperiorTo(pubKey,sock,cipherTournam[currentParents[0]],cipherTournam[currentParents[1]]);


            cipherTournam[currentIdIndex] = replaceIf(pubKey,sock,cipherTournam[currentParents[0]],cipherTournam[currentParents[1]],compResult );

            iDTournam[currentIdIndex] = replaceIf(pubKey,sock,iDTournam[currentParents[0]],iDTournam[currentParents[1]],compResult );
        }

        resultsId.push_back(decrypt(pubKey,privKey,iDTournam[iDTournam.size()-1])); // break secu assumption again ??

    }
    return resultsId;
}

static vector<ZZ> DGKOperations::topKMaxSwap(DGKPublicKey &pubKey, int sock,vector<ZZ> completeInputs,int k)
{
    int u = pubKey.GetU();

    int n = completeInputs.size() - k +2;
    int treesize = ceil(log2(n));
    int bigN = pow(2,treesize);

        vector<ZZ> swappableInputs(bigN);
    vector<ZZ> swappableId(bigN);
    for(int i = 0 ; i < bigN ; ++i)
    {
        if (i < n){
        swappableInputs[i] = completeInputs[i];
        }
        else{
            swappableInputs[i] = DGKOperations::encrypt(pubKey,pow(2,pubKey.getL() - 2)-1);
        }
        swappableId[i] = DGKOperations::encrypt(pubKey,i);
    }

    vector<ZZ> results;



    for(int currentround = 0; currentround < k; ++currentround )
    {

    if(currentround == 0){ // initialize the array
        for (int currentdepth = 0 ; currentdepth < treesize ; currentdepth++)
        {

            int firstId = 0;
            int secondId = firstId + pow(2,currentdepth);
            while(secondId < bigN){
                ZZ shallswap =DGKOperations::DGKAdd(pubKey,
                                                    DGKOperations::encrypt(pubKey,1),
                                                    DGKOperations::DGKMultiply(pubKey,
                                                                                   DGKOperations::isSuperiorTo(pubKey,sock,swappableInputs[firstId],swappableInputs[secondId])
                                                                               ,u-1));


                //Perform the Swap..
                if(secondId + pow(2,currentdepth) -1 < bigN && firstId-1 < bigN)
                {

                    for(int i = 0; i < pow(2,currentdepth); ++i)
                    {
                        ZZ replaceValue = DGKOperations::replaceIf(pubKey,sock,swappableInputs[firstId+i],swappableInputs[secondId+i],shallswap);
                        ZZ replaceId    = DGKOperations::replaceIf(pubKey,sock,swappableId[firstId+i],swappableId[secondId+i],shallswap);

                        ZZ totalValue = DGKOperations::DGKAdd(pubKey,swappableInputs[firstId+i],swappableInputs[secondId+i]);
                        ZZ totalId = DGKOperations::DGKAdd(pubKey,swappableId[firstId+i],swappableId[secondId+i]);

                        swappableInputs[firstId+i] =replaceValue;
                        swappableId[firstId+i] =replaceId;
                        swappableInputs[secondId+i] = DGKOperations::DGKAdd(pubKey,totalValue,DGKOperations::DGKMultiply(pubKey,replaceValue,u-1));
                        swappableId[secondId+i] = DGKOperations::DGKAdd(pubKey,totalId,DGKOperations::DGKMultiply(pubKey,replaceId,u-1));


                    }

                }
                else
                {
                    // Shall not happens now TODO delete this else



                }

                 firstId = secondId+pow(2,currentdepth);
                 secondId = firstId + pow(2,currentdepth);


            }
        }

    }
    else {
              for (int currentdepth = 0 ; currentdepth < treesize ; currentdepth++)
        {

            int firstId = 0;;
            int secondId = firstId + pow(2,currentdepth);


                ZZ shallswap =DGKOperations::DGKAdd(pubKey,
                                                    DGKOperations::encrypt(pubKey,1),
                                                    DGKOperations::DGKMultiply(pubKey,
                                                                                   DGKOperations::isSuperiorTo(pubKey,sock,swappableInputs[firstId],swappableInputs[secondId])
                                                                               ,u-1));


                //Perform the Swap..

                    for(int i = 0; i < pow(2,currentdepth); ++i)
                    {
                        ZZ replaceValue = DGKOperations::replaceIf(pubKey,sock,swappableInputs[firstId+i],swappableInputs[secondId+i],shallswap);
                        ZZ replaceId    = DGKOperations::replaceIf(pubKey,sock,swappableId[firstId+i],swappableId[secondId+i],shallswap);

                        ZZ totalValue = DGKOperations::DGKAdd(pubKey,swappableInputs[firstId+i],swappableInputs[secondId+i]);
                        ZZ totalId = DGKOperations::DGKAdd(pubKey,swappableId[firstId+i],swappableId[secondId+i]);

                        swappableInputs[firstId+i] =replaceValue;
                        swappableId[firstId+i] =replaceId;
                        swappableInputs[secondId+i] = DGKOperations::DGKAdd(pubKey,totalValue,DGKOperations::DGKMultiply(pubKey,replaceValue,u-1));
                        swappableId[secondId+i] = DGKOperations::DGKAdd(pubKey,totalId,DGKOperations::DGKMultiply(pubKey,replaceId,u-1));


                    }

        }

    }
     //Save and replace the local maximum
     results.push_back(swappableId[0]);
     if(currentround < k-2){
        swappableId[0] = DGKOperations::encrypt(pubKey,completeInputs.size() - k +2+currentround);
        swappableInputs[0] = completeInputs[completeInputs.size() - k +2+currentround];

     }
     else if (currentround == k-2){

        swappableId[0] = DGKOperations::encrypt(pubKey,completeInputs.size() - k +2+currentround);
        swappableInputs[0] = DGKOperations::encrypt(pubKey,pow(2,pubKey.getL() - 2)-1); // maximum possible value without overflow
     }
    }
    return results;
}

