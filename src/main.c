#include "../include/Parse.h"
#include "../include/Read.h"
#include "../include/Tool.h"
#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[])
{
        if (argc != 2)
        {
                printf("Usage: %s <PE File>\n", argv[0]);
                return EXIT_FAILURE;
        }

        PBYTE pPeBuffer = NULL;
        DWORD dwPeSize = 0;
        READ_STATUS rs = ReadPeFile(argv[1], &pPeBuffer, &dwPeSize);
        if (rs != READ_OK)
        {
                printf("[!] ReadPeFile failed with error: %d\n", rs);
                return EXIT_FAILURE;
        }

        // HANDLE hHandle = GetModuleHandleA("ntdll.dll");
        // PARSE_STATUS ps = ParsePeFile((PBYTE)hHandle);
        PARSE_STATUS ps = ParsePeFile(pPeBuffer);
        if (ps != PARSE_OK)
        {
                printf("[!] ParsePeFile failed with error: %d\n", ps);
                return EXIT_FAILURE;
        }

        free(pPeBuffer);

        return EXIT_SUCCESS;
}
