#ifndef DGKPRIVATEKEY_H
#define DGKPRIVATEKEY_H
#include <NTL/ZZ.h>
#include <map>



#include <sstream>
#include <iostream>
#include <fstream>
#include <chrono>
#include <stdlib.h>
//#include <inttypes.h>
#include <windows.h>
#define POSMOD(x,n) ((x % n + n) % n)

using namespace NTL;
using namespace std;

/*
author: Baptiste VINH MAU, baptiste.vinhmau@epfl.ch

This class provide the representation of a Public Key used by the DGK cryptosystem.
*/

class DGKPrivateKey
{
public:
    DGKPrivateKey();
    DGKPrivateKey(ZZ p, ZZ q, ZZ vp, ZZ vq,  std::map<ZZ, unsigned long> LUT, unsigned long u);
    NTL::ZZ  GetP()
    {
        return p;
    }
    NTL::ZZ  GetQ()
    {
        return q;
    }
    NTL::ZZ  GetVP()
    {
        return vp;
    }
    NTL::ZZ  GetVQ()
    {
        return vq;
    }
    NTL::ZZ  GetN()
    {
        return p*q;
    }

    long GetLUT(ZZ key)
    {
        if( LUT.count(key) == 0)
        {
            throw std::runtime_error("Error during Decryption: you tried to decipher and invalid ciphertext");

        }
        return LUT[key];
    }

    friend inline std::ostream& operator<<(std::ostream& os, const DGKPrivateKey& self)
    {
        std::ios_base::fmtflags flags = os.flags();
        os << std::dec << self.p << " " << self.q << " " << self.vp <<" " << self.vq << " " << self.u << " ";

        //for (unsigned long i=0; i<self.u; ++i)     {
        for(auto i = self.LUT.begin(); i != self.LUT.end(); i++)
        {
            os << std::dec << i->first << " " << i->second <<" ";
        }
        os << " ";

        os.flags(flags);
        return os;
    }

    friend inline std::istream& operator>>(std::istream& is,  DGKPrivateKey& self)
    {
        std::ios_base::fmtflags flags = is.flags();
        is >> std::dec >>  self.p  >> self.q >> self.vp >> self.vq >> self.u ;

        // ZZ temp = ZZ();

        std::map<ZZ,unsigned long> LUT2;
        for(int i = 0 ; i < self.u ; i++)
        {
            ZZ key;
            unsigned long value;
            is >> key >> value;
            LUT2[key]=value;
        }
        self.LUT = LUT2;

        is.flags(flags);
        return is;
    }



    /** Will save the key at the given path as a plain text file
    **/
    friend inline void save(const DGKPrivateKey &self, string const path)
    {

        std::ofstream myfile;
        myfile.open (path);
        myfile << self;
        myfile.close();
    }
       /** Will save the key at the given path as a plain text file, but will not include any LUT
    **/
friend inline void partialSave(const DGKPrivateKey &self, string const path)
    {

        std::ofstream myfile;
        myfile.open (path);
        std::ios_base::fmtflags flags = myfile.flags();
    //    os << std::dec << self.n << " " << self.g << " " << self.h <<" " << self.u << " " << self.l << " " << self.t << " " << self.k << " ";
        myfile << std::dec << self.p << " " << self.q << " " << self.vp <<" " << self.vq << " " << self.u << " ";


        myfile.flags(flags);

        myfile.close();
    }
   /** Will load the Key stored at a given path, and recompute its LUT.
    **/
 friend inline void partialLoad(DGKPrivateKey &self, string const path, ZZ g)
    {

        std::ifstream myfile;
        myfile.open (path);

			std::ios_base::fmtflags flags = myfile.flags();
        myfile >> std::dec >>  self.p  >> self.q >> self.vp >> self.vq >> self.u ;

   // ZZ temp = ZZ();
			myfile.flags(flags);
        myfile.close();

        std::map<ZZ,unsigned long> LUT2;
     ZZ gvp = PowerMod(POSMOD(g,self.p),self.vp,self.p);
    for (int i=0; i<self.u; ++i){
        ZZ decipher = PowerMod(gvp,POSMOD(ZZ(i),self.p),self.p);
        LUT2[decipher] = i;
    }

        self.LUT = LUT2;

    }
       /** Will load the Key stored at a given path, the content of the LUT will also be read from the file.
    **/

    friend inline void load(DGKPrivateKey &self, string const path)
    {
        DGKPrivateKey privKey = DGKPrivateKey();
        std::ifstream myfile;
        myfile.open (path);
        myfile >> self;

        myfile.close();
    }



protected:

private:
    ZZ p;
    ZZ q;
    ZZ vp;
    ZZ vq;
    unsigned long u;
    std::map<ZZ, unsigned long> LUT ;


};

#endif // DGKPRIVATEKEY_H
