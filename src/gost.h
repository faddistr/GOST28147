/**
@file gost.h
Прототипы функций шифрования ГОСТ28147-89
*/
/**
@mainpage Библиотека ГОСТ28147-89
@details Реализует функции шифрования, расшифрования
во всех режимах: "Выработка имитовставки", "Простая замена",
"Гаммирование","Гаммирование с обратной связью".
Все, что надо знать для начала работы с библиотекой описано в файле gost.h
@author Д.О. Федорченко (mailto: faddistr@gmail.com)
*/
#ifndef GOST_H
#define GOST_H
#include "stdint.h"
/**
  Количество узлов замены
*/
#define _GOST_TABLE_NODES 8
/**
  Количество елементов в узле замены, для упрощения используется 128 байтная таблица замены,
  в каждом елементе старший полубайт 0.
*/
#define _GOST_TABLE_MAX_NODE_VALUE 16
/**
  Размер таблицы замен(ДК) в байтах
*/
#define _GOST_TABLE_SIZE _GOST_TABLE_NODES*_GOST_TABLE_MAX_NODE_VALUE//128(in orig 64) to optimize code
/**
  Положение накопителя N1 в объедененние данных GOST_Data_Part
*/
#define _GOST_Data_Part_N1_Half 1
/**
  Положение накопителя N2 в объедененние данных GOST_Data_Part
*/
#define _GOST_Data_Part_N2_Half 0
/**
  Байт по умолчанию.
*/
#define _GOST_Def_Byte 0
/**
@union GOST_Data_Part
Объеденение данных для лучше читаемости кода, описываем единичную 64битную порцию данных
*/
//to make code understandable
typedef union
{
    /**
     * @brief parts 8битное представление порции данных для криптообработки
    */
    uint8_t  parts[8];
    /**
     * @brief half 32байтное представление порции данных для криптообработки
    */
    uint32_t half[2];
   // uint64_t full; //Нет в с51
} GOST_Data_Part;
/**
  Размер порции данных для криптообработки
*/
#define _GOST_Part_Size sizeof(GOST_Data_Part)
/**
  Размер имитовставки
*/
#define _GOST_Imitta_Size   _GOST_Part_Size
/**
  Размер синхропосылки
*/
#define _GOST_Synchro_Size  _GOST_Part_Size
/**
  Размер ключа(СК) в байтах(256 бит)
*/
#define _GOST_Key_Size   32
/**
  Следующий шаг криптопреобразования
*/
#define _GOST_Next_Step false
/**
  Последний шаг криптопреобразования
*/
#define _GOST_Last_Step true
/**
  Cовместимость с архитектурой еталонного шифратора
*/
#define _GOST_ROT 1
/**
  Совместимость с входами синхропосылки еталонного шифратора
*/
#define _GOST_ROT_Synchro_GAMMA 1
/**
  Режим шифрования
*/
#define _GOST_Mode_Encrypt true
/**
  Режим расшифрования
*/
#define _GOST_Mode_Decrypt false

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
void GOST_Imitta(uint8_t *Open_Data, uint8_t *Imitta, uint32_t Size,  uint8_t *GOST_Table, uint8_t *GOST_Key );

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
void GOST_Encrypt_SR(uint8_t *Data, uint32_t Size, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key );



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
void GOST_Crypt_G_PS(uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key);
#else
void GOST_Crypt_32_E_Cicle(GOST_Data_Part *DATA, uint8_t *GOST_Table, uint32_t *GOST_Key);
/**
  Подготовка синхропосылки. См. функцию GOST_Crypt_G_PS
*/
#define GOST_Crypt_G_PS(GOST_Synchro, GOST_Table, GOST_Key) GOST_Crypt_32_E_Cicle((GOST_Data_Part *) GOST_Synchro, GOST_Table, (uint32_t *) GOST_Key)
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
void GOST_Crypt_G_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, uint8_t *GOST_Table, uint8_t *GOST_Key );

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
void GOST_Crypt_GF_Prepare_S(uint8_t *Synchro);
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
void GOST_Crypt_GF_Data(uint8_t *Data, uint32_t Size, uint8_t *Synchro, bool Mode, uint8_t *GOST_Table, uint8_t *GOST_Key );




#endif // GOST_H
