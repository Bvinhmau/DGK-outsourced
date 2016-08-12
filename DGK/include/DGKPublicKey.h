#ifndef DGKPUBLICKEY_H
#define DGKPUBLICKEY_H
#include <NTL/ZZ.h>
#include <map>

#include <sstream>
#include <iostream>
#include <fstream>
#include <chrono>
#include <stdlib.h>
//#include <inttypes.h>
#include <windows.h>
using namespace std;
using namespace std::chrono;

using namespace NTL;
/*
author: Baptiste VINH MAU, baptiste.vinhmau@epfl.ch

This class provide the representation of a Public Key used by the DGK cryptosystem.
*/
class DGKPublicKey
{
public:
    DGKPublicKey();
    DGKPublicKey(ZZ N, ZZ G, ZZ H, unsigned long U,  std::map<unsigned long, ZZ> gLUT,  std::map<unsigned long, ZZ> hLUT, int l, int t, int k);
    NTL::ZZ  GetN()
    {
        return n;
    }
    NTL::ZZ  GetG()
    {
        return g;
    }
    NTL::ZZ  GetH()
    {
        return h;
    }
    long  GetU()
    {
        return u;
    }
    ZZ getGLUT(unsigned long key)
    {
        return gLUT[key];
    }
    std::map<unsigned long, ZZ> getHLUT()
    {
        return hLUT;
    }
    int getL()
    {
        return l;
    }
    int getT()
    {
        return t;
    }
    int getK()
    {
        return k;
    }
    friend inline std::ostream& operator<<(std::ostream& os, const DGKPublicKey& self)
    {
        std::ios_base::fmtflags flags = os.flags();
        //    os << std::dec << self.n << " " << self.g << " " << self.h <<" " << self.u << " " << self.l << " " << self.t << " " << self.k << " ";
        os  << std::hex  << self.n << " " << self.g << " " << self.h <<" " << self.u << " " << self.l << " " << self.t << " " << self.k << " ";

        //for (unsigned long i=0; i<self.u; ++i)     {
        for(auto i = self.gLUT.begin(); i != self.gLUT.end(); i++)
        {
            //os << std::hex << i << "=" << self.gLUT[i] <<"\n";
            os << std::hex  << i->first << " " << i->second <<" ";
        }
        os << " ";
        for(auto i = self.hLUT.begin(); i != self.hLUT.end(); i++)
        {
            //os << std::hex << i << "=" << self.gLUT[i] <<"\n";
            os << std::hex  << i->first << " " << i->second <<" ";
        }
        os.flags(flags);
        return os;
    }

    friend inline std::istream& operator>>(std::istream& is,  DGKPublicKey& self)
    {
        std::ios_base::fmtflags flags = is.flags();
        std::string tempn;
        is >> std::hex >>  self.n  >> self.g >> self.h >> self.u >> self.l >> self.t >> self.k ;

        // ZZ temp = ZZ();

        std::map<unsigned long, ZZ> gLUT2;
        for(int i = 0 ; i < self.u ; i++)
        {
            unsigned long key;
            ZZ value;
            is >> std::hex >>  key >> value;
            gLUT2[key]=value;
        }
        std::map<unsigned long, ZZ> hLUT2;
        for(int i = 0 ; i < 2*self.t ; i++)
        {
            unsigned long key;
            ZZ value;
            is >> std::hex >>  key >> value;
            hLUT2[key]=value;
        }
        self.hLUT = hLUT2;
        self.gLUT = gLUT2;

        is.flags(flags);
        return is;
    }

    /** Will save the key at the given path as a plain text file
    **/
    friend inline void save(const DGKPublicKey &self, string const path)
    {

        std::ofstream myfile;
        myfile.open (path);
        myfile << self;

        myfile.close();
    }
    /** Will save the key at the given path as a plain text file, but will not include any LUT
     **/

    friend inline void partialSave(const DGKPublicKey &self, string const path)
    {

        std::ofstream myfile;
        myfile.open (path);
        std::ios_base::fmtflags flags = myfile.flags();
        //    os << std::dec << self.n << " " << self.g << " " << self.h <<" " << self.u << " " << self.l << " " << self.t << " " << self.k << " ";
        myfile  << std::hex  << self.n << " " << self.g << " " << self.h <<" " << self.u << " " << self.l << " " << self.t << " " << self.k << " ";


        myfile.flags(flags);

        myfile.close();
    }

    /** Will load the Key stored at a given path, the content of the LUT will also be read from the file.
    **/
    friend inline void load(DGKPublicKey &self, string const path)
    {
        DGKPublicKey pubKey = DGKPublicKey();
        std::ifstream myfile;
        myfile.open (path);
        myfile >> self;

        myfile.close();
    }
    /** Will load the Key stored at a given path, and recompute its LUT.
     **/
    friend inline void partialLoad(DGKPublicKey &self, string const path)
    {

        DGKPublicKey pubKey = DGKPublicKey();
        std::ifstream myfile;
        myfile.open (path);

        std::ios_base::fmtflags flags = myfile.flags();
        myfile >> std::hex >>  self.n  >> self.g >> self.h >> self.u >> self.l >> self.t >> self.k ;

        // ZZ temp = ZZ();
        myfile.flags(flags);
        myfile.close();
        std::map<unsigned long, ZZ> hLUT2;
        for (int i=0; i<2*self.t; ++i)
        {
            ZZ e = PowerMod(ZZ(2),i,self.n);
            ZZ out = PowerMod(self.h,e,self.n);
            hLUT2[i] = out;
        }

        std::map<unsigned long, ZZ> gLUT2;
        for (int i=0; i<self.u; ++i)
        {
            ZZ out = PowerMod(self.g,i,self.n);
            gLUT2[i] = out;
        }
        self.hLUT = hLUT2;
        self.gLUT = gLUT2;


    }
protected:


private:
    ZZ n;
    ZZ g;
    ZZ h;
    unsigned long u;

    int k;
    int t;
    int l;
    std::map<unsigned long, ZZ> gLUT;
    std::map<unsigned long, ZZ> hLUT;
};


#endif // DGKPUBLICKEY_H



