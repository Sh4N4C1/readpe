#pragma once

#include <windows.h>

typedef enum {
    READ_OK,
    READ_ERROR,
    READ_EOF,
    READ_FILE_NOT_FOUND,
} READ_STATUS;

READ_STATUS ReadPeFile(
    _In_ LPCSTR FilePath,
    _Out_ PBYTE* Buffer,
    _Out_ PDWORD Size
);
