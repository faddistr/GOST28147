#ifndef GOST_H
#define GOST_H
#include "stdint.h"

#define _GOST_TABLE_NODES 8
#define _GOST_TABLE_MAX_NODE_VALUE 16
#define _GOST_TABLE_SIZE _GOST_TABLE_NODES*_GOST_TABLE_MAX_NODE_VALUE//128
//? mb etalon cryptor have errors
#define _GOST_Data_Part_LoHalf 1
#define _GOST_Data_Part_HiHalf 0

#define _GOST_Part_Size 8
#define _GOST_Def_Byte 0
#define _GOST_Imitta_Size _GOST_Part_Size
//to make code understandable
typedef union
{
    uint32_t half[2];
   // uint64_t full;
} GOST_Data_Part;

void GOST_Imitta(uint8_t *Open_Data, uint8_t *Imitta, uint32_t Size,  uint8_t *GOST_Table, uint8_t *GOST_Key );

#define _GOST_Crypt_SR_Encrypt true
#define _GOST_Crypt_SR_Decrypt false

void GOST_Encrypt_SR(uint8_t *Data, uint32_t Size, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key );

#endif // GOST_H
