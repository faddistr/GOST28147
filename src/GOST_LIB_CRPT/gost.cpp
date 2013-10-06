#include <stdlib.h>
#include <String.h>
#include "gost.h"

#define min(x,y) (x>y?y:x)
//GOST basic Simple Step
void GOST_Crypt_Step(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key )
{
    typedef  union
    {
        uint32_t full;
        uint8_t parts[4];
    } GOST_Data_Part_sum;
    GOST_Data_Part_sum S;
    uint8_t tmp;
    //N1=Lo(DATA); N2=Hi(DATA)
    S.full = (uint32_t)((*DATA).half[_GOST_Data_Part_LoHalf]+*GOST_Key) ;//S=(N1+X)mod2^32

    for(uint8_t m=0; m<(_GOST_TABLE_NODES/2); m++)
    {
        //S(m)=H(m,S)
        tmp=S.parts[m];
        S.parts[m] = *(GOST_Table+(tmp&0x0F));//Low value
        GOST_Table+= _GOST_TABLE_MAX_NODE_VALUE;//next line in table
        S.parts[m] |= (*(GOST_Table+((tmp&0xF0)>>4)))<<4;//Hi value
        GOST_Table+= _GOST_TABLE_MAX_NODE_VALUE;//next line in table

    }

    S.full = _lrotl(S.full,11);//S=Rl(11,S); rol S,11
    S.full = S.full^(*DATA).half[_GOST_Data_Part_HiHalf];//S XOR N2

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];//N2=N1
    (*DATA).half[_GOST_Data_Part_LoHalf] = S.full;//N1=S
}


//Basic 32-3 encryption algorithm of GOST
void GOST_Crypt_32_E_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    uint8_t k,j;
    uint32_t TMP;
    uint32_t *GOST_Key_tmp=GOST_Key;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K0,K1,K2,K3,K4,K5,K6,K7,K7,K6,K5,K4,K3,K2,K1,K0
    for(k=0;k<3;k++)
    {
        for (j=0;j<8;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
            GOST_Key++;
        }
        GOST_Key=GOST_Key_tmp;
    }

    GOST_Key=GOST_Key_tmp+8;

    for (j=0;j<8;j++)
    {
        GOST_Key--;
        GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
    }
//SWAP N1 <-> N2
    TMP=(*DATA).half[_GOST_Data_Part_HiHalf];

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];
    (*DATA).half[_GOST_Data_Part_LoHalf] = TMP;

}

//Basic 32-P decryption algorithm of GOST, usefull only in SR mode
void GOST_Crypt_32_D_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    uint8_t k,j;
    uint32_t TMP;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0
    for (j=0;j<8;j++)
    {
        GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
        GOST_Key++;
    }
//GOST_Key offset =  GOST_Key + _GOST_32_3P_CICLE_ITERS_J
    for(k=0;k<3;k++)
    {
        for (j=0;j<8;j++)
        {
            GOST_Key--;
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
        }
        GOST_Key+=8;
    }

//SWAP N1 <-> N2
    TMP=(*DATA).half[_GOST_Data_Part_HiHalf];

    (*DATA).half[_GOST_Data_Part_HiHalf] = (*DATA).half[_GOST_Data_Part_LoHalf];
    (*DATA).half[_GOST_Data_Part_LoHalf] = TMP;

}

//Imitta
void GOST_Imitta_16_E_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
//K0,K1,K2,K3,K4,K5,K6,K7, K0,K1,K2,K3,K4,K5,K6,K7.
    uint8_t k,j;
    for(k=0;k<2;k++)
    {
        for (j=0;j<8;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, GOST_Key ) ;
            GOST_Key++;
        }
        GOST_Key-=8;
    }

}



//for first round Imitta must set to _GOST_Def_Byte
void GOST_Imitta(uint8_t *Open_Data,  uint8_t *Imitta, uint32_t Size, uint8_t *GOST_Table, uint8_t *GOST_Key )
{
    uint8_t i;
    while(Size!=0)
    {
         for (i=0;i<min(_GOST_Part_Size,Size);i++)
         {
              *Imitta=(*Imitta)^(*Open_Data);
              Open_Data++;
              Imitta++;
         }
         Size-=i;
         Imitta-=i;
         GOST_Imitta_16_E_Cicle((GOST_Data_Part *)Imitta,GOST_Table,(uint32_t *)GOST_Key);
    }
}

void GOST_Encrypt_SR(uint8_t *Data, uint32_t Size, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key )
{
    uint8_t Cur_Part_Size;
    uint8_t Tmp[_GOST_Part_Size];
    while (Size!=0)
    {
        Cur_Part_Size=min(_GOST_Part_Size,Size);
       // memset(Tmp, _GOST_Def_Byte, sizeof(Tmp));//have no sense in this mode
        memcpy(Tmp, Data,Cur_Part_Size);//align by _GOST_Part_Size bytes
        if (Mode==_GOST_Mode_Encrypt)
        {
            GOST_Crypt_32_E_Cicle((GOST_Data_Part *) Tmp,GOST_Table,(uint32_t *) GOST_Key);
        } else
        {
            GOST_Crypt_32_D_Cicle((GOST_Data_Part *) Tmp,GOST_Table,(uint32_t *) GOST_Key);
        }
        memcpy(Data,Tmp, Cur_Part_Size);
        Data+=Cur_Part_Size;
        Size-=Cur_Part_Size;
    }

}

void GOST_Crypt_G_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key )
{
//"magic" consts from GOST for pseudorandom generator of gamma
#define _GOST_C0 (uint32_t)(0x1010101)
#define _GOST_C1 (uint32_t)(0x1010104)
#define _GOST_ADC32(x,y,c) c=(uint32_t)(x+y); c+=( ( c<x ) | ( c<y ) )
    GOST_Data_Part *S=(GOST_Data_Part *)Synchro;
    GOST_Data_Part Tmp;
    uint8_t i;
    while(Size!=0)
    {
        (*S).half[_GOST_Data_Part_LoHalf]+=_GOST_C0;//_GOST_Data_Part_LoHalf
        _GOST_ADC32((*S).half[_GOST_Data_Part_HiHalf],_GOST_C1,(*S).half[_GOST_Data_Part_HiHalf]);//_GOST_Data_Part_HiHalf
        Tmp=*S;
        GOST_Crypt_32_E_Cicle(&Tmp,GOST_Table,(uint32_t *)GOST_Key);
        for (i=0;i<min(_GOST_Part_Size,Size);i++)
        {
            *Data^=Tmp.parts[i];
            Data++;
        }
        Size-=i;
    }
}

void GOST_Crypt_GF_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key )
{
    GOST_Data_Part S;
    uint8_t i,Tmp;
    memcpy(&S,Synchro,_GOST_Synchro_Size);
    while(Size!=0)
    {
        GOST_Crypt_32_E_Cicle(&S,GOST_Table,(uint32_t *)GOST_Key);//C32(S)
        for (i=0;i<min(_GOST_Part_Size,Size);i++)//Data XOR S; S=Data;
        {
            if (Mode==_GOST_Mode_Encrypt)
            {
                *Data^=S.parts[i];
                S.parts[i]=*Data;
            } else
            {
                Tmp=*Data;
                *Data^=S.parts[i];
                S.parts[i]=Tmp;
            }
            Data++;
        }
        Size-=i;
    }

}
