#include "stdlib.h"
#include "gost.h"



typedef union
{
    uint32_t full;
    uint8_t parts[4];
} GOST_Data_Part_sum;



//GOST Simple Step
void GOST_Crypt_Step(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key )
{
#define _GOST_GetTable(x,t) (*(t+(x&0x0f)) | (*(t+(x&0xF0>>4))))
    //N1=Lo(DATA); N2=Hi(DATA)
    GOST_Data_Part_sum S;
    S.full = (*DATA).half[_GOST_Data_Part_LoHalf]+*GOST_Key;//S=(N1+X)mod2^32

    for(uint8_t m=0; m<(_GOST_TABLE_NODES/2); m++)
    {
        S.parts[m] = _GOST_GetTable(S.parts[m],GOST_Table);//S(m)=H(m,S)
    }

    S.full = _rotl(S.full,11);//S=Rl(11,S); rol S,11
    S.full = S.full^(*DATA).half[_GOST_Data_Part_HiHalf];//S XOR N2

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];//N2=N1
    (*DATA).half[_GOST_Data_Part_LoHalf] = S.full;//N1=S
}


void GOST_Crypt_32_3_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
//Magic numbers 3 and 8 from GOST algorithm
#define _GOST_32_3_CICLE_ITERS_K 3
#define _GOST_32_3_CICLE_ITERS_J 8
    uint8_t k,j;
    GOST_Data_Part TMP;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K7,K6,K5,K4,K3,K2,K1,K0
    for(k=0;k<_GOST_32_3_CICLE_ITERS_K;k++)
    {
        for (j=0;j<_GOST_32_3_CICLE_ITERS_J;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
            GOST_Key++;
            GOST_Table++;
        }
        GOST_Key-=j;
        GOST_Table-=j;
    }

    GOST_Key+=_GOST_32_3_CICLE_ITERS_J;

    for (j=0;j<_GOST_32_3_CICLE_ITERS_J;j++)
    {
        GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
        GOST_Key--;
        GOST_Table++;
    }
//SWAP N1 <-> N2
    TMP=*DATA;

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];
    (*DATA).half[_GOST_Data_Part_LoHalf] = TMP.half[_GOST_Data_Part_HiHalf];

}
