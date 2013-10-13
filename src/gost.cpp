/**
@file gost.cpp
Реализация функций шифрования ГОСТ28147-89.
*/
#include <stdlib.h>
#include <String.h>
#include "gost.h"
/**
  @def _SWAPW32(W)
  Задает обратный порядок байт в 4х байтном числе. Для совместимости архитектур.
*/
#define _SWAPW32(W) ((W>>24) | (W<<24) | ((W>>8)&0xFF00) | ((W<<8)&0xFF0000))
/**
  @def _Min(W)
  Ищет минимальное значение между x и у
*/
#define _Min(x,y) (x>y?y:x)
/**
    @def _GOST_C0
    Константа С0 для задания начального значения псевдослучайного генератора гаммы.
*/
#define _GOST_C0 (uint32_t)(0x1010101)
/**
   @def _GOST_C1
   Константа С1 для задания начального значения псевдослучайного генератора гаммы.
*/
#define _GOST_C1 (uint32_t)(0x1010104)

/**
    @def _GOST_ADC32(x,y,c)
    Выполняет операцию c=(x+y)mod(2^32-1), т.е. с=x+y, если x+y<2^32 с=(uint32_t)(x+y)+1, если х+y>2^32
*/
#define _GOST_ADC32(x,y,c) c=(uint32_t)(x+y); c+=( ( c<x ) | ( c<y ) )

/**
@details GOST_Crypt_Step
Выполняет простейший шаг криптопреобразования(шифрования и расшифрования) ГОСТ28147-89
@param *DATA - Указатель на данные для зашифрования в формате GOST_Data_Part
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param GOST_Key - 32хбитная часть ключа(СК).
@param Last - Является ли шаг криптопреобразования последним? Если да(true)-
результат будет занесен в 32х битный накопитель  N2, в противном случае предыдущие значение N1
сохраняется в N2, а результат работы будет занесен в накопитель N1.
*/
//GOST basic Simple Step
void GOST_Crypt_Step(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t GOST_Key, bool Last )
{
    typedef  union
    {
        uint32_t full;
        uint8_t parts[_GOST_TABLE_NODES/2];
    } GOST_Data_Part_sum;
    GOST_Data_Part_sum S;
    uint8_t m;
    uint8_t tmp;
    //N1=Lo(DATA); N2=Hi(DATA)

    S.full = (uint32_t)((*DATA).half[_GOST_Data_Part_N1_Half]+GOST_Key) ;//S=(N1+X)mod2^32

    for(m=0; m<(_GOST_TABLE_NODES/2); m++)
    {
        //S(m)=H(m,S)
        tmp=S.parts[m];
        S.parts[m] = *(GOST_Table+(tmp&0x0F));//Low value
        GOST_Table+= _GOST_TABLE_MAX_NODE_VALUE;//next line in table
        S.parts[m] |= (*(GOST_Table+((tmp&0xF0)>>4)))<<4;//Hi value
        GOST_Table+= _GOST_TABLE_MAX_NODE_VALUE;//next line in table

    }
    S.full = (*DATA).half[_GOST_Data_Part_N2_Half]^_lrotl(S.full,11);//S=Rl(11,S); rol S,11 //S XOR N2
    if (Last)
    {
        (*DATA).half[_GOST_Data_Part_N2_Half] = S.full; //N2=S
    }else
    {
        (*DATA).half[_GOST_Data_Part_N2_Half] = (*DATA).half[_GOST_Data_Part_N1_Half];//N2=N1
        (*DATA).half[_GOST_Data_Part_N1_Half] = S.full;//N1=S
    }
}

/**
@details GOST_Crypt_32_E_Cicle
Базовый алгоритм выполняющий 32шага шифрования для 64-битной порции данных
(в номенклатуре документа ГОСТ28147-89 алгоритм 32-З), обратный алгоритму 32-Р.
@param *DATA - Указатель на данные для зашифрования в формате GOST_Data_Part
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param GOST_Key - 32хбитная часть ключа(СК).
*/
void GOST_Crypt_32_E_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    uint8_t k,j;
    uint32_t *GOST_Key_tmp=GOST_Key;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K0,K1,K2,K3,K4,K5,K6,K7, K0,K1,K2,K3,K4,K5,K6,K7, K7,K6,K5,K4,K3,K2,K1,K0

    for(k=0;k<3;k++)
    {
        for (j=0;j<8;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Next_Step ) ;
            GOST_Key++;
        }
        GOST_Key=GOST_Key_tmp;
    }

    GOST_Key+=7;//K7

    for (j=0;j<7;j++)
    {
        GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Next_Step ) ;
        GOST_Key--;
    }
    GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Last_Step ) ;
}

/**
@details GOST_Crypt_32_D_Cicle
Базовый алгоритм выполняющий 32шага расшифрования для 64-битной порции данных
(в номенклатуре документа ГОСТ28147-89 алгоритм 32-Р), обратный алгоритму 32-З.
Применяется только в режиме простой замены.
@param *DATA - Указатель на данные для зашифрования в формате GOST_Data_Part
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param GOST_Key - 32хбитная часть ключа(СК).
*/
//Basic 32-P decryption algorithm of GOST, usefull only in SR mode
void GOST_Crypt_32_D_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
    uint8_t k,j;
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0, K7,K6,K5,K4,K3,K2,K1,K0
    for (j=0;j<8;j++)
    {
        GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Next_Step ) ;
        GOST_Key++;
    }
//GOST_Key offset =  GOST_Key + _GOST_32_3P_CICLE_ITERS_J
    for(k=0;k<2;k++)
    {
        for (j=0;j<8;j++)
        {
            GOST_Key--;
            GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Next_Step ) ;
        }
        GOST_Key+=8;
    }
    for (j=0;j<7;j++)
    {
        GOST_Key--;
        GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Next_Step ) ;
    }
    GOST_Key--;
    GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key,_GOST_Last_Step ) ;

}

/**
@details GOST_Imitta_16_E_Cicle
Базовый алгоритм выполняющий 16 шагов расчета 64х битной имитовставки(в номенклатуре документа
ГОСТ28147-89 алгоритм 16-З).
@param *DATA - Указатель на данные для зашифрования в формате GOST_Data_Part
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param GOST_Key - 32хбитная часть ключа(СК).
*/
//Imitta
void GOST_Imitta_16_E_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key)
{
//Key rotation:
//K0,K1,K2,K3,K4,K5,K6,K7, K0,K1,K2,K3,K4,K5,K6,K7.
    uint8_t k,j;
    uint32_t *GOST_Key_Beg=GOST_Key;
    for(k=0;k<2;k++)
    {
        for (j=0;j<8;j++)
        {
            GOST_Crypt_Step(DATA, GOST_Table, *GOST_Key, _GOST_Next_Step) ;
            GOST_Key++;
        }
        GOST_Key=GOST_Key_Beg;
    }


}

/**
@details GOST_Imitta
Подпрограма расчета имитовставки
@param *Open_Data - Указатель на данные для которых требуется расчитать имитовстаку.
@param *Imitta - Указатель на массив размером _GOST_Imitta_Size(64 бита), куда будет занесен результат
расчета имитовставки.
@param Size - Размер данных
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param *GOST_Key - Указатель на 256 битный массив ключа(СК).
@attention  Для первого раунда массив Imitta должен быть заполнен _GOST_Def_Byte!
*/
//for first round Imitta must set to _GOST_Def_Byte
void GOST_Imitta(uint8_t *Open_Data,  uint8_t *Imitta, uint32_t Size, uint8_t *GOST_Table, uint8_t *GOST_Key )
{

    uint8_t Cur_Part_Size;
    GOST_Data_Part *Imitta_Prep=(GOST_Data_Part *) Imitta;
    GOST_Data_Part Open_Data_Prep;
    while(Size!=0)
    {
        Cur_Part_Size=_Min(_GOST_Part_Size,Size);
        Open_Data_Prep.half[_GOST_Data_Part_N2_Half]=0;
        Open_Data_Prep.half[_GOST_Data_Part_N1_Half]=0;
        memcpy(&Open_Data_Prep,Open_Data,Cur_Part_Size);
        (*Imitta_Prep).half[_GOST_Data_Part_N1_Half]^=Open_Data_Prep.half[_GOST_Data_Part_N1_Half];
        (*Imitta_Prep).half[_GOST_Data_Part_N2_Half]^=Open_Data_Prep.half[_GOST_Data_Part_N2_Half];
        Size-=Cur_Part_Size;
        Open_Data+=Cur_Part_Size;
        GOST_Imitta_16_E_Cicle(Imitta_Prep,GOST_Table,(uint32_t *)GOST_Key);
    }
#if _GOST_ROT==1
    (*Imitta_Prep).half[_GOST_Data_Part_N1_Half]=_SWAPW32((*Imitta_Prep).half[_GOST_Data_Part_N1_Half]);
    (*Imitta_Prep).half[_GOST_Data_Part_N2_Half]=_SWAPW32((*Imitta_Prep).half[_GOST_Data_Part_N2_Half]);
#endif
}

/**
@details GOST_Encrypt_SR
Функция шифрования/расшифрования в режиме простой замены.
@param *Data - Указатель на данные для шифрования, также сюда заносится результат.
@param Size - Размер данных
@param Mode - Если _GOST_Mode_Encrypt шифрования, _GOST_Mode_Decrypt - расшифрование
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param *GOST_Key - Указатель на 256 битный массив ключа(СК).
*/
void GOST_Encrypt_SR(uint8_t *Data, uint32_t Size, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key )
{
    uint8_t Cur_Part_Size;
    GOST_Data_Part Data_prep;
    uint32_t *GOST_Key_pt=(uint32_t *) GOST_Key;

    while (Size!=0)
    {
        Cur_Part_Size=_Min(_GOST_Part_Size,Size);
        memset(&Data_prep,_GOST_Def_Byte,sizeof(Data_prep));
        memcpy(&Data_prep,Data,Cur_Part_Size);
#if _GOST_ROT==1
        Data_prep.half[_GOST_Data_Part_N2_Half]=_SWAPW32(Data_prep.half[_GOST_Data_Part_N2_Half]);
        Data_prep.half[_GOST_Data_Part_N1_Half]=_SWAPW32(Data_prep.half[_GOST_Data_Part_N1_Half]);
#endif
        if (Mode==_GOST_Mode_Encrypt)
        {
            GOST_Crypt_32_E_Cicle(&Data_prep,GOST_Table,GOST_Key_pt);
        } else
        {
            GOST_Crypt_32_D_Cicle(&Data_prep,GOST_Table,GOST_Key_pt);
        }
#if _GOST_ROT==1
        Data_prep.half[_GOST_Data_Part_N2_Half]=_SWAPW32(Data_prep.half[_GOST_Data_Part_N2_Half]);
        Data_prep.half[_GOST_Data_Part_N1_Half]=_SWAPW32(Data_prep.half[_GOST_Data_Part_N1_Half]);
#endif
        memcpy(Data,&Data_prep, Cur_Part_Size);
        Data+=Cur_Part_Size;
        Size-=Cur_Part_Size;
   }

}

#if _GOST_ROT_Synchro_GAMMA==1
/**
@details GOST_Crypt_G_PS
Функция подготовки Синхропосылки для режима гаммирования. Должна быть вызвана до первого вызова
GOST_Crypt_G_Data. Если хранить синхропосылку в уже "развернутом" виде (поменять местами 32битные части), то функцию можно свести
к макросу вызова единичного шага криптопреобразования, для чего в файле gost.h установить
константу _GOST_ROT_Synchro_GAMMA=0. Синхропосылка это случайные данные, так что смысл функции
только в совместимости с входами еталонного шифратора.
@param *Synchro - Указатель на данные для шифрования, также сюда заносится результат.
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0)
@param *GOST_Key - Указатель на 256 битный массив ключа(СК).
*/
void GOST_Crypt_G_PS(uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key)
{
   uint32_t Tmp;
   GOST_Data_Part *GOST_Synchro_prep= (GOST_Data_Part *) Synchro;
   Tmp=(*GOST_Synchro_prep).half[_GOST_Data_Part_N2_Half];
   (*GOST_Synchro_prep).half[_GOST_Data_Part_N2_Half]=(*GOST_Synchro_prep).half[_GOST_Data_Part_N1_Half];
   (*GOST_Synchro_prep).half[_GOST_Data_Part_N1_Half]=Tmp;

   GOST_Crypt_32_E_Cicle(GOST_Synchro_prep, GOST_Table, (uint32_t *) GOST_Key);
}
#endif

/**
@details GOST_Crypt_G_Data
Шифрование\Расшифрования блока данных в режиме гаммирования.
@param *Data - Указатель на данные для шифрования\расшифрования, также сюда заносится результат работы.
@param Size - Размер данных
@param *Synchro - Указатель на синхопросылку, также сюда заносится текущее значение синхропосылки.
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате(вместо старшого полубайта 0).
@param *GOST_Key - Указатель на 256 битный массив ключа(СК).
@attention Синхропосылка Synchro для первого вызова должна быть подготовлена функцией/макросом GOST_Crypt_G_PS.
*/
void GOST_Crypt_G_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key )
{

    GOST_Data_Part *S=(GOST_Data_Part *)Synchro;
    GOST_Data_Part Tmp;
    uint8_t i;
    while(Size!=0)
    {
        (*S).half[_GOST_Data_Part_N1_Half]+=_GOST_C0;
        _GOST_ADC32((*S).half[_GOST_Data_Part_N2_Half],_GOST_C1,(*S).half[_GOST_Data_Part_N2_Half]);//_GOST_Data_Part_HiHalf

        Tmp=*S;
        GOST_Crypt_32_E_Cicle(&Tmp,GOST_Table,(uint32_t *)GOST_Key);
#if _GOST_ROT==1
        Tmp.half[_GOST_Data_Part_N2_Half]=_SWAPW32(Tmp.half[_GOST_Data_Part_N2_Half]);
        Tmp.half[_GOST_Data_Part_N1_Half]=_SWAPW32(Tmp.half[_GOST_Data_Part_N1_Half]);
#endif
        for (i=0;i<_Min(_GOST_Part_Size,Size);i++)
        {
            *Data^=Tmp.parts[i];
            Data++;
        }
        Size-=i;
    }
}

#if _GOST_ROT_Synchro_GAMMA==1
/**
@details GOST_Crypt_GF_Prepare_S
Функция подготовки Синхропосылки для режима гаммирования с обратной связью.
Меняет местами 32битные части синхропосылки. Аналогично режиму гаммирования, если синхропосылка
хранится в "развернутом" виде(32х битные части поменяны местами) то функцию можно опустить.
Синхропосылка это случайные данные, так что смысл функции только в совместимости с
входами еталонного шифратора. Для упрощения жизни компилятору необходимо выставить константу
_GOST_ROT_Synchro_GAMMA=0 в gost.h.
@param *Synchro - Указатель на данные для шифрования, также сюда заносится результат.
*/
void GOST_Crypt_GF_Prepare_S(uint8_t *Synchro)
{
    GOST_Data_Part *S=(GOST_Data_Part *)Synchro;
    uint32_t Tmp=(*S).half[_GOST_Data_Part_N1_Half];
    (*S).half[_GOST_Data_Part_N1_Half]=(*S).half[_GOST_Data_Part_N2_Half];
    (*S).half[_GOST_Data_Part_N2_Half]=Tmp;
}
#endif

/**
@details GOST_Crypt_GF_Data
Функция шифрования в режиме гаммирования с обратной связью.
@param *Data - указатель на данные для шифрования/расшифрования.
@param Size - Размер данных
@param *Synchro - Указатель на синхопросылку,
также сюда заносится текущее значение синхропосылки.
@param Mode - Если _GOST_Mode_Encrypt будет выполнено шифрование данных,
если _GOST_Mode_Decrypt расшифрование
@param *GOST_Table - Указатель на таблицу замены ГОСТ(ДК) в 128 байтном формате
(вместо старшого полубайта 0).
@param *GOST_Key - Указатель на 256 битный массив ключа(СК).
@attention Если используется режим совместимости с входами еталонного шифратора, то синхропосылка
Synchro для первого вызова должна быть подготовлена функцией GOST_Crypt_GF_Prepare_S.
*/
void GOST_Crypt_GF_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key )
{
    GOST_Data_Part *S=(GOST_Data_Part *)Synchro;
    uint8_t i,Tmp;
    while(Size!=0)
    {

        GOST_Crypt_32_E_Cicle(S,GOST_Table,(uint32_t *)GOST_Key);//C32(S)
#if _GOST_ROT==1
        (*S).half[_GOST_Data_Part_N2_Half]=_SWAPW32((*S).half[_GOST_Data_Part_N2_Half]);
        (*S).half[_GOST_Data_Part_N1_Half]=_SWAPW32((*S).half[_GOST_Data_Part_N1_Half]);
#endif
        for (i=0;i<_Min(_GOST_Part_Size,Size);i++)//Data XOR S; S=Data;
        {
            if (Mode==_GOST_Mode_Encrypt)
            {
                *Data^=(*S).parts[i];
                (*S).parts[i]=*Data;
            } else
            {
                Tmp=*Data;
                *Data^=(*S).parts[i];
                (*S).parts[i]=Tmp;
            }
            Data++;
        }
#if _GOST_ROT==1
        (*S).half[_GOST_Data_Part_N2_Half]=_SWAPW32((*S).half[_GOST_Data_Part_N2_Half]);
        (*S).half[_GOST_Data_Part_N1_Half]=_SWAPW32((*S).half[_GOST_Data_Part_N1_Half]);
#endif
        Size-=i;
    }

}
