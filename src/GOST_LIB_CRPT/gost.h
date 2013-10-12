#ifndef GOST_H
#define GOST_H
#include "stdint.h"

#define _GOST_TABLE_NODES 8
#define _GOST_TABLE_MAX_NODE_VALUE 16
#define _GOST_TABLE_SIZE _GOST_TABLE_NODES*_GOST_TABLE_MAX_NODE_VALUE//128(in orig 64) to optimize code

#define _GOST_Data_Part_N1_Half 1
#define _GOST_Data_Part_N2_Half 0
#define _GOST_Def_Byte 0
//to make code understandable
typedef union
{
    uint8_t  parts[8];
    uint32_t half[2];
   // uint64_t full;
} GOST_Data_Part;

#define _GOST_Part_Size sizeof(GOST_Data_Part)
#define _GOST_Imitta_Size   _GOST_Part_Size
#define _GOST_Synchro_Size  _GOST_Part_Size
#define _GOST_Key_Size   32

#define _GOST_Next_Step false
#define _GOST_Last_Step true

#define _GOST_ROT 1 // comptaible with etalon encryptor

void GOST_Imitta(uint8_t *Open_Data, uint8_t *Imitta, uint32_t Size,  uint8_t *GOST_Table, uint8_t *GOST_Key );

#define _GOST_Mode_Encrypt true
#define _GOST_Mode_Decrypt false

void GOST_Encrypt_SR(uint8_t *Data, uint32_t Size, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key );

void GOST_Crypt_32_E_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key);

#if _GOST_ROT==1
void GOST_Crypt_G_PS(uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key);
#else
#define GOST_Crypt_G_PS(GOST_Synchro, GOST_Table, GOST_Key) GOST_Crypt_32_E_Cicle((GOST_Data_Part *) GOST_Synchro, GOST_Table, (uint32_t *) GOST_Key)
#endif
void GOST_Crypt_G_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key );


void GOST_Crypt_GF_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key );




#endif // GOST_H
