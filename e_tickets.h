#ifndef E_TICKETS_H
#define E_TICKETS_H

#include"pairing_3.h"
#include "zzn.h"
#include <stdlib.h>
#include <stdio.h>
#include <list>
typedef unsigned char u8;
typedef unsigned int u32;

#define AES_SECURITY 128 //lamda
#define ATTRIBUTES_NUM 30 //n
#define DIS_ATTRIBUTES_NUM 5 //m
struct ET_MPK
{
    G2 X_,Y_,Z_;
    G2 A_[ATTRIBUTES_NUM],B_[ATTRIBUTES_NUM];
    G1 C,D0,D1,D2,D3;
};
struct ET_MSK
{
    Big x,y,z;
    Big a[ATTRIBUTES_NUM],b[ATTRIBUTES_NUM];
    Big c;
    Big d0,d1,d2,d3;
};

struct ET_SSK
{
    Big e;
    Big f1,f2,f3;
};
struct ET_PI_1
{
    Big c;
    Big se,s1,s2,s3;

};
struct ET_SPK
{
    G1 F1,F2,F3;
    G2 E_,F1_,F2_,F3_;
    ET_PI_1 pi_1;
};

struct ET_CRED_S
{
   G2 sigma1,sigma2;
};
struct ET_ATT
{
    Big id;
    Big a[ATTRIBUTES_NUM];
};
struct ET_USK
{
    Big rou,miu;
    Big sn,t;


};
struct ET_PI_2
{
    Big c;
    Big s;
};
struct ET_UPK
{
    G1 U1,U2,U3;
    ET_PI_2 pi_2;
};

struct ET_CRED_U
{
   G1 sig[ATTRIBUTES_NUM];
};
struct ET_PI_3
{
    Big c;
    Big s0,s1,s2;
};
struct ET_PROOF
{
    Big att[DIS_ATTRIBUTES_NUM];
    ET_UPK upk;
    G1 Sigma;
    G1 T;
    ET_PI_3 pi_3;

};
struct ET_TKT
{
  G1 T1,T2;
  Big VP,sn;
};
struct ET_TKT_V
{
  G1 T1,T2;
  G2 T_;
};
struct ET_PI_4
{
    Big c;
    Big s1,s2;
};
struct ET_TOK
{
    ET_TKT tkt;
    G1 K;
    G2 V;
    ET_PI_4 pi_4;
};

class e_tickets
{
private:
    PFC *pfc;
    G1 g,g1;
    G2 g_,g_1;
    GT gt,gt_1;

public:
    e_tickets(PFC *p);
    ~e_tickets();
    int Setup(ET_MPK &mpk,ET_MSK &msk);
    int SReg_S(ET_SSK &ssk,ET_SPK &spk);
    int SReg_CA(ET_MPK &mpk,ET_MSK &msk,ET_SPK &spk,ET_CRED_S &cred_s);
    int SReg_R(ET_MPK &mpk,ET_SSK &ssk,ET_SPK &spk,ET_CRED_S &cred_s);
    int UReg_S_SmartCard(ET_ATT &att,ET_USK &usk, ET_UPK &upk);
    int UReg_CA(ET_MPK &mpk, ET_MSK &msk, ET_ATT &att, ET_UPK &upk, ET_CRED_U &cred_u);
    int UReg_R_Smartphone(ET_MPK &mpk, ET_ATT &att,ET_UPK &upk,ET_CRED_U &cred_u);
    int Obtain_S_SmartCard(ET_MPK &mpk, ET_SPK &spk,ET_USK &usk,ET_ATT &att,ET_UPK &upk,ET_CRED_U &cred_u,Big &nounce,ET_PROOF &proof);
    int Issue(ET_MPK &mpk,ET_SSK &ssk, ET_SPK &spk,ET_PROOF &proof,Big &nounce,ET_TKT &tkt);
    int Obtain_R_SmartCard(ET_MPK &mpk,ET_SPK &spk,ET_USK &usk,ET_TKT &tkt,ET_TKT_V &tkt_v);
    int Obtain_R_Smartphone(ET_TKT_V &tkt_v);
    int Show_SmartCard(ET_MPK &mpk,ET_SPK &spk,ET_USK &usk,ET_TKT &tkt,ET_TOK &tok);
    int Verify(ET_SPK &spk,ET_TOK &tok);
};

#endif // E_TICKETS_H
