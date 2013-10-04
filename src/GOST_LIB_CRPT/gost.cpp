#include "stdlib.h"
#include "gost.h"

//GOST basic Simple Step
void GOST_Crypt_Step(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key )
{
    typedef  union
    {
        uint32_t full;
        uint8_t parts[4];
    } GOST_Data_Part_sum;
    GOST_Data_Part_sum S;

    //N1=Lo(DATA); N2=Hi(DATA)
    S.full = (*DATA).half[_GOST_Data_Part_LoHalf]+*GOST_Key;//S=(N1+X)mod2^32

    for(uint8_t m=0; m<(_GOST_TABLE_NODES/2); m++)
    {
        //S(m)=H(m,S)
        S.parts[m] = *(GOST_Table+(S.parts[m]&0x0F));//Low value
        GOST_Table+= _GOST_TABLE_MAX_NODE_VALUE;//next line in table
        S.parts[m] |= (*(GOST_Table+((S.parts[m]&0xF0)>>4)))<<4;//Hi value
        GOST_Table+= _GOST_TABLE_MAX_NODE_VALUE;//next line in table

    }

    S.full = _rotl(S.full,11);//S=Rl(11,S); rol S,11
    S.full = S.full^(*DATA).half[_GOST_Data_Part_HiHalf];//S XOR N2

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];//N2=N1
    (*DATA).half[_GOST_Data_Part_LoHalf] = S.full;//N1=S
}

//"Magic" numbers 3 and 8 from GOST
#define _GOST_32_3P_CICLE_ITERS_K 3
#define _GOST_32_3P_CICLE_ITERS_J 8
//Basic 32-3 encryption algorithm of GOST
void GOST_Crypt_32_3_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    uint8_t k,j;
    GOST_Data_Part TMP;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K7,K6,K5,K4,K3,K2,K1,K0
    for(k=0;k<_GOST_32_3P_CICLE_ITERS_K;k++)
    {
        for (j=0;j<_GOST_32_3P_CICLE_ITERS_J;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
            GOST_Key++;
        }
        GOST_Key-=_GOST_32_3P_CICLE_ITERS_J;
    }

    GOST_Key+=_GOST_32_3P_CICLE_ITERS_J;

    for (j=0;j<_GOST_32_3P_CICLE_ITERS_J;j++)
    {
        GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
        GOST_Key--;
    }
//SWAP N1 <-> N2
    TMP=*DATA;

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];
    (*DATA).half[_GOST_Data_Part_LoHalf] = TMP.half[_GOST_Data_Part_HiHalf];

}

//Basic 32-P decryption algorithm of GOST
void GOST_Crypt_32_P_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    uint8_t k,j;
    GOST_Data_Part TMP;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0
    for (j=0;j<_GOST_32_3P_CICLE_ITERS_J;j++)
    {
        GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
        GOST_Key++;
    }
//GOST_Key offset =  GOST_Key + _GOST_32_3P_CICLE_ITERS_J
    for(k=0;k<_GOST_32_3P_CICLE_ITERS_K;k++)
    {
        for (j=0;j<_GOST_32_3P_CICLE_ITERS_J;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
            GOST_Key--;
        }
        GOST_Key+=_GOST_32_3P_CICLE_ITERS_J;
    }

//SWAP N1 <-> N2
    TMP=*DATA;

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];
    (*DATA).half[_GOST_Data_Part_LoHalf] = TMP.half[_GOST_Data_Part_HiHalf];

}

//Imitta
void GOST_Imitta_16_3_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    //"Magic" numbers 2 and 8 from GOST
    #define _GOST_16_3_CICLE_ITERS_K 2
    #define _GOST_16_3_CICLE_ITERS_J 8
    uint8_t k,j;
    for(k=0;k<_GOST_16_3_CICLE_ITERS_K;k++)
    {
        for (j=0;j<_GOST_16_3_CICLE_ITERS_J;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
            GOST_Key++;
        }
        GOST_Key-=_GOST_16_3_CICLE_ITERS_J;
    }

}
