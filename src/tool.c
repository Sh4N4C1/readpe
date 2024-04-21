#include "../include/Tool.h"
#include <stdio.h>
#include <windows.h>

VOID PrintBuffer(PBYTE pBuffer, SIZE_T sBufferSize)
{
        for (size_t i = 0; i < sBufferSize; i++)
        {
                if (i % 16 == 0)
                {
                        if (i != 0)
                        {
                                printf("  ");
                                for (size_t j = i - 16; j < i; j++)
                                {
                                        printf("%c", (pBuffer[j] >= 32 && pBuffer[j] <= 126) ? pBuffer[j] : '.');
                                }
                                printf("\n");
                        }
                        printf("%08x: ", (unsigned int)i);
                }

                printf("%02x ", pBuffer[i]);

                if (i == sBufferSize - 1)
                {
                        for (size_t j = 0; j < (15 - i % 16) * 3; j++)
                        {
                                printf(" ");
                        }
                        printf("  ");
                        for (size_t j = (i / 16) * 16; j < sBufferSize; j++)
                        {
                                printf("%c", (pBuffer[j] >= 32 && pBuffer[j] <= 126) ? pBuffer[j] : '.');
                        }
                        printf("\n");
                }
        }
}
