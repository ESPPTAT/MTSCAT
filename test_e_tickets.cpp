#include"e_tickets.h"
#include "pairing_3.h"
#include <ctime>
#include <time.h>
#define TEST_TIME 1
int correct_test()
{
    PFC pfc(AES_SECURITY);

    e_tickets e_tickets_inst(&pfc);
    int ret =0;
    ET_MPK mpk;
    ET_MSK msk;
    ret = e_tickets_inst.Setup(mpk,msk);
    if(ret != 0)
    {
        printf("e_tickets_inst.Setup Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Setup pass\n");
    ET_SSK ssk;
    ET_SPK spk;
    ret = e_tickets_inst.SReg_S(ssk,spk);
    if(ret != 0)
    {
        printf("e_tickets_inst.SReg_S Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.SReg_S pass\n");
    ET_CRED_S cred_s;
    ret = e_tickets_inst.SReg_CA(mpk,msk,spk,cred_s);
    if(ret != 0)
    {
        printf("e_tickets_inst.SReg_CA Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.SReg_CA pass\n");

    ret = e_tickets_inst.SReg_R(mpk,ssk,spk,cred_s);
    if(ret != 0)
    {
        printf("e_tickets_inst.SReg_R Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.SReg_R pass\n");
    ET_ATT att;
    ET_USK usk;
    ET_UPK upk;
    ret = e_tickets_inst.UReg_S_SmartCard(att,usk, upk);
    if(ret != 0)
    {
        printf("e_tickets_inst.UReg_S_SmartCard Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.UReg_S_SmartCard pass\n");
    ET_CRED_U cred_u;
    ret = e_tickets_inst.UReg_CA(mpk,msk,att,upk,cred_u);
    if(ret != 0)
    {
        printf("e_tickets_inst.UReg_CA Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.UReg_CA pass\n");

    ret = e_tickets_inst.UReg_R_Smartphone(mpk, att,upk,cred_u);
    if(ret != 0)
    {
        printf("e_tickets_inst.UReg_R_Smartphone Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.UReg_R_Smartphone pass\n");
    Big nounce;
    pfc.random(nounce);
    ET_PROOF proof;
    ret = e_tickets_inst.Obtain_S_SmartCard(mpk, spk, usk, att, upk, cred_u, nounce, proof);
    if(ret != 0)
    {
        printf("e_tickets_inst.Obtain_S_SmartCard Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Obtain_S_SmartCard pass\n");
    ET_TKT tkt;
    ret = e_tickets_inst.Issue(mpk,ssk, spk,proof,nounce,tkt);
    if(ret != 0)
    {
        printf("e_tickets_inst.Issue Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Issue pass\n");
    ET_TKT_V tkt_v;
    ret = e_tickets_inst.Obtain_R_SmartCard(mpk,spk,usk,tkt, tkt_v);
    if(ret != 0)
    {
        printf("e_tickets_inst.Obtain_R_SmartCard Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Obtain_R_SmartCard pass\n");

    ret = e_tickets_inst.Obtain_R_Smartphone(tkt_v);
    if(ret != 0)
    {
        printf("e_tickets_inst.Obtain_R_Smartphone Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Obtain_R_Smartphone pass\n");
    ET_TOK tok;
    ret = e_tickets_inst.Show_SmartCard(mpk,spk,usk,tkt,tok);
    if(ret != 0)
    {
        printf("e_tickets_inst.Show_SmartCard Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Show_SmartCard pass\n");

    ret = e_tickets_inst.Verify(spk,tok);
    if(ret != 0)
    {
        printf("e_tickets_inst.Verify Erro ret =%d\n",ret);
        return 1;
    }
    else
        printf("e_tickets_inst.Verify pass\n");
    return ret;
}
int speed_test()
{
    int k;
    clock_t start,finish;
    double sum;
    PFC pfc(AES_SECURITY);
    int ret =0;
    //1. basic
    //G1
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        G1 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G1 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_1 ret : %d time =%f sec\n",ret,sum);

    //G2
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        G2 G;
        pfc.random(G);
        Big r;
        pfc.random(r);
        G2 T=pfc.mult(G,r);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_2 ret : %d time =%f sec\n",ret,sum);

    //e
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        G1 G;
        G2 H;
        pfc.random(G);
        pfc.random(H);
        GT T=pfc.pairing(H,G);
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("BN256.e_p ret : %d time =%f sec\n",ret,sum);
    ///////////////////////////////////////////////////////////
    e_tickets e_tickets_inst(&pfc);

    ET_MPK mpk;
    ET_MSK msk;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Setup(mpk,msk);
        if(ret != 0)
        {
            printf("e_tickets_inst.Setup Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Setup ret : %d time =%f sec\n",ret,sum);

    ET_SSK ssk;
    ET_SPK spk;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.SReg_S(ssk,spk);
        if(ret != 0)
        {
            printf("e_tickets_inst.SReg_S Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.SReg_S ret : %d time =%f sec\n",ret,sum);
    ET_CRED_S cred_s;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.SReg_CA(mpk,msk,spk,cred_s);
        if(ret != 0)
        {
            printf("e_tickets_inst.SReg_CA Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.SReg_CA ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.SReg_R(mpk,ssk,spk,cred_s);
        if(ret != 0)
        {
            printf("e_tickets_inst.SReg_R Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.SReg_R ret : %d time =%f sec\n",ret,sum);
    ET_ATT att;
    ET_USK usk;
    ET_UPK upk;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.UReg_S_SmartCard(att,usk, upk);
        if(ret != 0)
        {
            printf("e_tickets_inst.UReg_S_SmartCard Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.UReg_S_SmartCard ret : %d time =%f sec\n",ret,sum);
    ET_CRED_U cred_u;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.UReg_CA(mpk,msk,att,upk,cred_u);
        if(ret != 0)
        {
            printf("e_tickets_inst.UReg_CA Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.UReg_CA ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.UReg_R_Smartphone(mpk, att,upk,cred_u);
        if(ret != 0)
        {
            printf("e_tickets_inst.UReg_R_Smartphone Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.UReg_R_Smartphone ret : %d time =%f sec\n",ret,sum);
    Big nounce;
    pfc.random(nounce);
    ET_PROOF proof;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Obtain_S_SmartCard(mpk, spk, usk, att, upk, cred_u, nounce, proof);
        if(ret != 0)
        {
            printf("e_tickets_inst.Obtain_S_SmartCard Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Obtain_S_SmartCard ret : %d time =%f sec\n",ret,sum);
    ET_TKT tkt;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Issue(mpk,ssk, spk,proof,nounce,tkt);
        if(ret != 0)
        {
            printf("e_tickets_inst.Issue Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Issue ret : %d time =%f sec\n",ret,sum);
    ET_TKT_V tkt_v;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Obtain_R_SmartCard(mpk,spk,usk,tkt, tkt_v);
        if(ret != 0)
        {
            printf("e_tickets_inst.Obtain_R_SmartCard Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Obtain_R_SmartCard ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Obtain_R_Smartphone(tkt_v);
        if(ret != 0)
        {
            printf("e_tickets_inst.Obtain_R_Smartphone Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Obtain_R_Smartphone ret : %d time =%f sec\n",ret,sum);
    ET_TOK tok;
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Show_SmartCard(mpk,spk,usk,tkt,tok);
        if(ret != 0)
        {
            printf("e_tickets_inst.Show_SmartCard Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Show_SmartCard ret : %d time =%f sec\n",ret,sum);
    start=clock();
    for(k=0;k<TEST_TIME;k++)
    {
        ret = e_tickets_inst.Verify(spk,tok);
        if(ret != 0)
        {
            printf("e_tickets_inst.Verify Erro ret =%d\n",ret);
            return 1;
        }
    }
    finish=clock();
    sum = (double)(finish-start)/(CLOCKS_PER_SEC*TEST_TIME);
    printf("e_tickets_inst.Verify ret : %d time =%f sec\n",ret,sum);
    return ret;
}
int main()
{

    int ret=0;

    ret =correct_test();
    if(ret ==0)
    {
        printf("e_tickets is correct!\n");
    }

    ret =speed_test();
    if(ret ==0)
    {
        printf("speed test of e_tickets is completed!\n");
    }

    return ret;
}
