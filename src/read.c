#include "../include/Read.h"
#include <stdio.h>
#include <windows.h>

READ_STATUS ReadPeFile(_In_ LPCSTR FilePath, _Out_ PBYTE *Buffer, _Out_ PDWORD Size)
{

        HANDLE hFile = NULL;
        PBYTE pFileBuffer = NULL;
        DWORD dwFileSize = 0;

        hFile = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
                printf("[!] CreateFileA failed with error: %d\n", GetLastError());
                return READ_FILE_NOT_FOUND;
        }

        dwFileSize = GetFileSize(hFile, NULL);
        if (dwFileSize == 0)
        {
                printf("[!] GetFileSize failed with error: %d\n", GetLastError());
                CloseHandle(hFile);
                return READ_ERROR;
        }

        pFileBuffer = (PBYTE)malloc(dwFileSize);
        if (pFileBuffer == NULL)
        {
                printf("[!] malloc failed with error: %d\n", GetLastError());
                CloseHandle(hFile);
                return READ_ERROR;
        }

        DWORD dwBytesRead = 0;
        if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwBytesRead, NULL))
        {
                printf("[!] ReadFile failed with error: %d\n", GetLastError());
                CloseHandle(hFile);
                free(pFileBuffer);
                return READ_ERROR;
                ;
        }

        CloseHandle(hFile);

        *Buffer = pFileBuffer;
        *Size = dwFileSize;

        return READ_OK;
}
