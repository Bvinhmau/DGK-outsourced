#include "DGKPrivateKey.h"



DGKPrivateKey::DGKPrivateKey(){
};
DGKPrivateKey::DGKPrivateKey(ZZ m_p, ZZ m_q, ZZ m_vp, ZZ m_vq,  std::map<ZZ, unsigned long> m_lut, unsigned long m_u) : p(m_p),
q(m_q),vp(m_vp), vq(m_vq), LUT(m_lut), u(m_u)
{
}
