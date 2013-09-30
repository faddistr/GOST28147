#ifndef GOST_H
#define GOST_H
#include "stdint.h"
#define _GOST_TABLE_NODES 8
#define _GOST_TABLE_MAX_NODE_VALUE 16
#define _GOST_TABLE_SIZE _GOST_TABLE_NODES*_GOST_TABLE_MAX_NODE_VALUE//128

#define _GOST_Data_Part_LoHalf 0
#define _GOST_Data_Part_HiHalf 1

typedef union
{
    uint32_t half[2];
    uint64_t full;
} GOST_Data_Part;


void GOST_Crypt_Step(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key );
#endif // GOST_H
