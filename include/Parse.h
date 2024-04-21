#pragma once

#include <windows.h>

typedef enum {
    PARSE_OK,
    PARSE_ERROR,
    PARSE_INVALID_PE,
} PARSE_STATUS;


PARSE_STATUS ParsePeFile(
    _In_ PBYTE pPeBuffer
);
