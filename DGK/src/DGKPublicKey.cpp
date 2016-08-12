#include "DGKPublicKey.h"
   #include <NTL/ZZ.h>

DGKPublicKey::DGKPublicKey(){

};
DGKPublicKey::DGKPublicKey(ZZ m_n, ZZ m_g, ZZ m_h, unsigned long m_u, std::map<unsigned long, ZZ> m_gLUT , std::map<unsigned long, ZZ> m_hLUT , int m_l, int m_t , int m_k ):
    n(m_n), g(m_g),h(m_h), u(m_u), gLUT(m_gLUT), hLUT(m_hLUT), l(m_l), t(m_t),k(m_k)
{
}


