#include <QCoreApplication>
#include "gost.h"
uint8_t gost_table[_GOST_TABLE_SIZE];
uint32_t GOST_Key;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    GOST_Key=0xAA;
    GOST_Data_Part DATA;
    DATA.full=0x55555555AAAAAAAA;
    for(uint8_t i=0;i<_GOST_TABLE_NODES;i++)
    {
     for(uint8_t j=0;j<_GOST_TABLE_MAX_NODE_VALUE;j++)
     {
         gost_table[i*_GOST_TABLE_MAX_NODE_VALUE+j]=j;
     }
    }
    GOST_Crypt_Step(&DATA,gost_table,&GOST_Key);
    GOST_Key++;
    GOST_Crypt_Step(&DATA,gost_table,&GOST_Key);
    return a.exec();
}
