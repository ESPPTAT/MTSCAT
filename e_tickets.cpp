#include "e_tickets.h"

e_tickets::e_tickets(PFC *p)
{
    pfc=p;
    pfc->random(g);
    pfc->random(g_);
    gt=pfc->pairing(g_,g);
    g1=pfc->mult(g,0);
    g_1=pfc->mult(g_1,0);
    gt_1=pfc->power(gt,0);
}
e_tickets::~e_tickets()
{

}

int e_tickets::Setup(ET_MPK &mpk,ET_MSK &msk)
{
    int ret =0;
    //generate msk
    pfc->random(msk.x);
    pfc->random(msk.y);
    pfc->random(msk.z);

    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        pfc->random(msk.a[i]);
        pfc->random(msk.b[i]);
    }
    pfc->random(msk.c);
    pfc->random(msk.d0);
    pfc->random(msk.d1);
    pfc->random(msk.d2);
    pfc->random(msk.d3);

    //compute mpk
    mpk.X_=pfc->mult(g_,msk.x);
    mpk.Y_=pfc->mult(g_,msk.y);
    mpk.Z_=pfc->mult(g_,msk.z);

    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        mpk.A_[i]=pfc->mult(g_,msk.a[i]);
        mpk.B_[i]=pfc->mult(g_,msk.b[i]);
    }

    mpk.C=pfc->mult(g,msk.c);
    mpk.D0=pfc->mult(g,msk.d0);
    mpk.D1=pfc->mult(g,msk.d1);
    mpk.D2=pfc->mult(g,msk.d2);
    mpk.D3=pfc->mult(g,msk.d3);

    return ret;
}
int e_tickets::SReg_S(ET_SSK &ssk,ET_SPK &spk)
{
    int ret =0;
    //generate ssk
    pfc->random(ssk.e);
    pfc->random(ssk.f1);
    pfc->random(ssk.f2);
    pfc->random(ssk.f3);
    //compute spk
    spk.E_=pfc->mult(g_,ssk.e);
    spk.F1_=pfc->mult(g_,ssk.f1);
    spk.F2_=pfc->mult(g_,ssk.f2);
    spk.F3_=pfc->mult(g_,ssk.f3);
    spk.F1=pfc->mult(g,ssk.f1);
    spk.F2=pfc->mult(g,ssk.f2);
    spk.F3=pfc->mult(g,ssk.f3);
    //sign pi_1
    Big r0,r1,r2,r3;

    pfc->random(r0);
    pfc->random(r1);
    pfc->random(r2);
    pfc->random(r3);
    G2 K_;
    G1 R1,R2,R3;

    K_=pfc->mult(g_,r0);
    R1=pfc->mult(g,r1);
    R2=pfc->mult(g,r2);
    R3=pfc->mult(g,r3);

    pfc->start_hash();
    pfc->add_to_hash(spk.E_);
    pfc->add_to_hash(spk.F1);
    pfc->add_to_hash(spk.F2);
    pfc->add_to_hash(spk.F3);
    pfc->add_to_hash(K_);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    spk.pi_1.c=pfc->finish_hash_to_group();

    Big t;
    t=pfc->Zpmulti(ssk.e,spk.pi_1.c);
    spk.pi_1.se=pfc->Zpsub(r0,t);
    t=pfc->Zpmulti(ssk.f1,spk.pi_1.c);
    spk.pi_1.s1=pfc->Zpsub(r1,t);
    t=pfc->Zpmulti(ssk.f2,spk.pi_1.c);
    spk.pi_1.s2=pfc->Zpsub(r2,t);
    t=pfc->Zpmulti(ssk.f3,spk.pi_1.c);
    spk.pi_1.s3=pfc->Zpsub(r3,t);
    return ret;
}
int e_tickets::SReg_CA(ET_MPK &mpk,ET_MSK &msk,ET_SPK &spk,ET_CRED_S &cred_s)
{
    int ret=0;
    //verify Pi1

    G2 K_;
    G1 R1,R2,R3;

    K_=pfc->mult(g_,spk.pi_1.se)+pfc->mult(spk.E_,spk.pi_1.c);
    R1=pfc->mult(g,spk.pi_1.s1)+pfc->mult(spk.F1,spk.pi_1.c);
    R2=pfc->mult(g,spk.pi_1.s2)+pfc->mult(spk.F2,spk.pi_1.c);
    R3=pfc->mult(g,spk.pi_1.s3)+pfc->mult(spk.F3,spk.pi_1.c);

    pfc->start_hash();
    pfc->add_to_hash(spk.E_);
    pfc->add_to_hash(spk.F1);
    pfc->add_to_hash(spk.F2);
    pfc->add_to_hash(spk.F3);
    pfc->add_to_hash(K_);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    Big c=pfc->finish_hash_to_group();
    if(c!= spk.pi_1.c) return -1;

    //verify spk
    GT E1,E2;
    E1=pfc->pairing(g_,spk.F1);
    E2=pfc->pairing(spk.F1_,g);
    if(E1 != E2) return -2;
    E1=pfc->pairing(g_,spk.F2);
    E2=pfc->pairing(spk.F2_,g);
    if(E1 != E2) return -3;
    E1=pfc->pairing(g_,spk.F3);
    E2=pfc->pairing(spk.F3_,g);
    if(E1 != E2) return -4;

    //sign PS
    Big r;
    pfc->random(r);
    cred_s.sigma1=pfc->mult(g_,r);
    cred_s.sigma2=pfc->mult(g_,msk.c)+pfc->mult(spk.E_,msk.d0)+pfc->mult(spk.F1_,msk.d1)+pfc->mult(spk.F2_,msk.d2)+pfc->mult(spk.F3_,msk.d3);
    cred_s.sigma2=pfc->mult(cred_s.sigma2,r);
    return ret;
}

int e_tickets::SReg_R(ET_MPK &mpk,ET_SSK &ssk,ET_SPK &spk,ET_CRED_S &cred_s)
{
    int ret =0;
    GT E1,E2;
    E1=pfc->pairing(cred_s.sigma2,g);
    G1 T=mpk.C+pfc->mult(mpk.D0,ssk.e)+pfc->mult(mpk.D1,ssk.f1)+pfc->mult(mpk.D2,ssk.f2)+pfc->mult(mpk.D3,ssk.f3);
    E2=pfc->pairing(cred_s.sigma1,T);
    if (E1 != E2) return -1;
    return ret;
}
int e_tickets::UReg_S_SmartCard(ET_ATT &att,ET_USK &usk, ET_UPK &upk)
{
    int ret =0;
    pfc->random(usk.rou);
    pfc->random(att.id);
    for(int i=0;i<ATTRIBUTES_NUM;i++)
        pfc->random(att.a[i]);
    pfc->random(usk.miu);
    pfc->start_hash();
    pfc->add_to_hash(att.id);
    Big h=pfc->finish_hash_to_group();
    upk.U1=pfc->mult(g,h);
    upk.U2=pfc->mult(upk.U1,usk.miu);
    upk.U3=pfc->mult(upk.U2,usk.miu);
    //sign pi2
    Big r;
    pfc->random(r);
    G1 R1,R2;
    R1=pfc->mult(upk.U1,r);
    R2=pfc->mult(upk.U2,r);
    pfc->start_hash();
    pfc->add_to_hash(upk.U1);
    pfc->add_to_hash(upk.U2);
    pfc->add_to_hash(upk.U3);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    upk.pi_2.c=pfc->finish_hash_to_group();

    Big t;
    t=pfc->Zpmulti(usk.miu,upk.pi_2.c);
    upk.pi_2.s=pfc->Zpsub(r,t);
    return ret;

}
int e_tickets::UReg_CA(ET_MPK &mpk,ET_MSK &msk,ET_ATT &att,ET_UPK &upk,ET_CRED_U &cred_u)
{
    int ret=0;
    //verify pi2

    G1 R1,R2;
    R1=pfc->mult(upk.U1,upk.pi_2.s)+pfc->mult(upk.U2,upk.pi_2.c);
    R2=pfc->mult(upk.U2,upk.pi_2.s)+pfc->mult(upk.U3,upk.pi_2.c);
    pfc->start_hash();
    pfc->add_to_hash(upk.U1);
    pfc->add_to_hash(upk.U2);
    pfc->add_to_hash(upk.U3);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    Big c=pfc->finish_hash_to_group();
    if(c!= upk.pi_2.c) return -1;

    //sign ARTS

    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        Big t1=pfc->Zpadd(msk.x,msk.a[i]);
        Big t2=pfc->Zpmulti(msk.b[i],att.a[i]);
        Big t3=pfc->Zpadd(t2,t1);
        cred_u.sig[i]=pfc->mult(upk.U1,t3)+pfc->mult(upk.U2,msk.y)+pfc->mult(upk.U3,msk.z);
    }

    return ret;
}
int e_tickets::UReg_R_Smartphone(ET_MPK &mpk, ET_ATT &att,ET_UPK &upk,ET_CRED_U &cred_u)
{
    int ret=0;
    GT E1, E2,E3,E4;
    G2 S;
    for(int i=0;i<ATTRIBUTES_NUM;i++)
    {
        E1=pfc->pairing(g_,cred_u.sig[i]);
        S=mpk.X_+mpk.A_[i]+pfc->mult(mpk.B_[i],att.a[i]);
        E2=pfc->pairing(S,upk.U1);
        E3=pfc->pairing(mpk.Y_,upk.U2);
        E4=pfc->pairing(mpk.Z_,upk.U3);
        if (E1 != E2*E3*E4) return -1;
    }
    return ret;
}
int e_tickets::Obtain_S_SmartCard(ET_MPK &mpk, ET_SPK &spk, ET_USK &usk, ET_ATT &att, ET_UPK &upk, ET_CRED_U &cred_u, Big &nounce, ET_PROOF &proof)
{
    int ret =0;
    Big r;
    //randomize
    pfc->random(r);
    proof.upk.U1=pfc->mult(upk.U1,r);
    proof.upk.U2=pfc->mult(upk.U2,r);
    proof.upk.U3=pfc->mult(upk.U3,r);
    //agg cred
    proof.Sigma=cred_u.sig[0];
    proof.att[0]=att.a[0];
    for(int i=1;i<DIS_ATTRIBUTES_NUM;i++)
    {

        proof.Sigma=proof.Sigma+cred_u.sig[i];
        proof.att[i]=att.a[i];

    }
    proof.Sigma=pfc->mult(proof.Sigma,r);

    //t,sn
    pfc->start_hash();
    pfc->add_to_hash(usk.rou);
    pfc->add_to_hash(nounce);
    pfc->add_to_hash((Big)1);
    usk.sn=pfc->finish_hash_to_group();
    pfc->start_hash();
    pfc->add_to_hash(usk.rou);
    pfc->add_to_hash(nounce);
    pfc->add_to_hash((Big)2);
    usk.t=pfc->finish_hash_to_group();
    proof.T=pfc->mult(g,usk.t)+pfc->mult(spk.F1,usk.miu)+pfc->mult(spk.F2,usk.sn);
    //sign pi_3
    Big r0,r1,r2;
    pfc->random(r0);
    pfc->random(r1);
    pfc->random(r2);
    G1 R1,R2,R3;
    R1=pfc->mult(proof.upk.U1,r0);
    R2=pfc->mult(proof.upk.U2,r0);
    R3=pfc->mult(g,r1)+pfc->mult(spk.F1,r0)+pfc->mult(spk.F2,r2);
    pfc->start_hash();
    pfc->add_to_hash(proof.upk.U1);
    pfc->add_to_hash(proof.upk.U2);
    pfc->add_to_hash(proof.upk.U3);
    pfc->add_to_hash(proof.T);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    pfc->add_to_hash(nounce);
    proof.pi_3.c=pfc->finish_hash_to_group();

    Big t;
    t=pfc->Zpmulti(usk.miu,proof.pi_3.c);
    proof.pi_3.s0=pfc->Zpsub(r0,t);
    t=pfc->Zpmulti(usk.t,proof.pi_3.c);
    proof.pi_3.s1=pfc->Zpsub(r1,t);
    t=pfc->Zpmulti(usk.sn,proof.pi_3.c);
    proof.pi_3.s2=pfc->Zpsub(r2,t);

    return ret;
}
int e_tickets::Issue(ET_MPK &mpk,ET_SSK &ssk, ET_SPK &spk,ET_PROOF &proof,Big &nounce,ET_TKT &tkt)
{
    int ret =0;

    //verify pi_3
    G1 R1,R2,R3;
    R1=pfc->mult(proof.upk.U1,proof.pi_3.s0)+pfc->mult(proof.upk.U2,proof.pi_3.c);
    R2=pfc->mult(proof.upk.U2,proof.pi_3.s0)+pfc->mult(proof.upk.U3,proof.pi_3.c);
    R3=pfc->mult(g,proof.pi_3.s1)+pfc->mult(spk.F1,proof.pi_3.s0)+pfc->mult(spk.F2,proof.pi_3.s2)+pfc->mult(proof.T,proof.pi_3.c);
    pfc->start_hash();
    pfc->add_to_hash(proof.upk.U1);
    pfc->add_to_hash(proof.upk.U2);
    pfc->add_to_hash(proof.upk.U3);
    pfc->add_to_hash(proof.T);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    pfc->add_to_hash(R3);
    pfc->add_to_hash(nounce);
    Big c=pfc->finish_hash_to_group();
    if(c!= proof.pi_3.c) return -1;

    //verify cred
    GT E1, E2,E3,E4;
    G2 S;
    E1=pfc->pairing(g_,proof.Sigma);
    E3=pfc->pairing(mpk.Y_,pfc->mult(proof.upk.U2,DIS_ATTRIBUTES_NUM));
    E4=pfc->pairing(mpk.Z_,pfc->mult(proof.upk.U3,DIS_ATTRIBUTES_NUM));
    S=mpk.X_+mpk.A_[0]+pfc->mult(mpk.B_[0],proof.att[0]);
    for(int i=1;i<DIS_ATTRIBUTES_NUM;i++)
    {
        S=S+mpk.X_+mpk.A_[i]+pfc->mult(mpk.B_[i],proof.att[i]);
    }
    E2=pfc->pairing(S,proof.upk.U1);
    if (E1 != E2*E3*E4) return -2;

    //sign tkt
    Big k;
    pfc->random(k);
    pfc->random(tkt.VP);
    tkt.T1=pfc->mult(g,k);
    tkt.T2=proof.T+pfc->mult(g,ssk.e)+pfc->mult(spk.F3,tkt.VP);
    tkt.T2=pfc->mult(tkt.T2,k);

    return ret;

}
int e_tickets::Obtain_R_SmartCard(ET_MPK &mpk, ET_SPK &spk, ET_USK &usk, ET_TKT &tkt, ET_TKT_V &tkt_v)
{
    int ret=0;

    tkt.T2=tkt.T2+pfc->mult(tkt.T1,-usk.t);
    tkt_v.T1=tkt.T1;
    tkt_v.T2=tkt.T2;
    tkt_v.T_=spk.E_+pfc->mult(spk.F1_,usk.miu)+pfc->mult(spk.F2_,usk.sn)+pfc->mult(spk.F3_,tkt.VP);
    return ret;

}
int e_tickets::Obtain_R_Smartphone(ET_TKT_V &tkt_v)
{
    int ret=0;
    GT E1,E2;
    E1=pfc->pairing(g_,tkt_v.T2);
    E2=pfc->pairing(tkt_v.T_,tkt_v.T1);
    if(E1 != E2) return -1;
    return ret;
}
int e_tickets::Show_SmartCard(ET_MPK &mpk,ET_SPK &spk,ET_USK &usk,ET_TKT &tkt,ET_TOK &tok)
{
    int ret=0;
    Big r,k;
    pfc->random(r);
    tok.tkt.T1=pfc->mult(tkt.T1,r);
    tok.tkt.T2=pfc->mult(tkt.T2,r);
    tok.K=pfc->mult(g,k)+pfc->mult(tok.tkt.T1,usk.miu);
    tok.V=pfc->mult(spk.F1_,k);

    //sign pi_4;
    Big r1,r2;
    pfc->random(r1);
    pfc->random(r2);
    G1 R1;
    G2 R2;
    R1=pfc->mult(g,r2)+pfc->mult(tok.tkt.T1,r1);
    R2=pfc->mult(spk.F1_,r2);
    pfc->start_hash();
    pfc->add_to_hash(tok.K);
    pfc->add_to_hash(tok.V);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    tok.pi_4.c=pfc->finish_hash_to_group();
    Big t;
    t=pfc->Zpmulti(usk.miu,tok.pi_4.c);
    tok.pi_4.s1=pfc->Zpsub(r1,t);
    t=pfc->Zpmulti(k,tok.pi_4.c);
    tok.pi_4.s2=pfc->Zpsub(r2,t);

    tok.tkt.VP=tkt.VP;
    tok.tkt.sn=usk.sn;
    return ret;

}
int e_tickets::Verify(ET_SPK &spk,ET_TOK &tok)
{
    int ret=0;

    //verify pi_4
    G1 R1;
    G2 R2;
    R1=pfc->mult(g,tok.pi_4.s2)+pfc->mult(tok.tkt.T1,tok.pi_4.s1)+pfc->mult(tok.K,tok.pi_4.c);
    G2 R3=pfc->mult(tok.V,tok.pi_4.c);
    R2=R3+pfc->mult(spk.F1_,tok.pi_4.s2);

    //R2=R2+R3;
    pfc->start_hash();
    pfc->add_to_hash(tok.K);
    pfc->add_to_hash(tok.V);
    pfc->add_to_hash(R1);
    pfc->add_to_hash(R2);
    Big c=pfc->finish_hash_to_group();
    //if(c!=tok.pi_4.c) return -1;

    //verify ps
    GT E1,E2,E3,E4;
    G2 S;
    E1=pfc->pairing(spk.F1_,tok.K);
    S=spk.E_+pfc->mult(spk.F2_,tok.tkt.sn)+pfc->mult(spk.F3_,tok.tkt.VP);
    E2=pfc->pairing(S,tok.tkt.T1);
    E3=pfc->pairing(g_,tok.tkt.T2);
    E4=pfc->pairing(tok.V,g);
    if(E1*E2!=E3*E4) return -2;
    return ret;
}
