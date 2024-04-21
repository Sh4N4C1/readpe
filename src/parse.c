#include "../include/Parse.h"
#include "../include/Tool.h"
#include <stdio.h>
#include <windows.h>

PARSE_STATUS ParsePeFile(_In_ PBYTE pPeBuffer)
{

        PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)pPeBuffer;
        if (pDosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
        {
                printf("[!] Invalid DOS signature\n");
                return PARSE_INVALID_PE;
        }

        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pPeBuffer + pDosHeaders->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
                printf("[!] Invalid NT signature\n");
                return PARSE_INVALID_PE;
        }

        IMAGE_FILE_HEADER NtFileHeader = pNtHeaders->FileHeader;
        printf("[+] File Type: ");
        if (NtFileHeader.Characteristics & IMAGE_FILE_DLL)
        {
                printf("DLL\n");
        }
        else if (NtFileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        {
                printf("EXE\n");
        }
        else
        {
                printf("\n[!] File is not a DLL or EXE\n");
                return PARSE_ERROR;
        }
        printf("[+] File Arch: %s\n", NtFileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "x64");

        printf("[+] Section Count: %d\n", NtFileHeader.NumberOfSections);

        IMAGE_OPTIONAL_HEADER NtOptionalHeader = pNtHeaders->OptionalHeader;
        printf("[+] Entry Point: 0x%08x\n", NtOptionalHeader.AddressOfEntryPoint);
        printf("[+] Image Base: 0x%08x\n", NtOptionalHeader.ImageBase);
        printf("[+] Section Alignment: 0x%08x\n", NtOptionalHeader.SectionAlignment);
        printf("[+] File Alignment: 0x%08x\n", NtOptionalHeader.FileAlignment);
        printf("[+] Image Size: 0x%08x\n", NtOptionalHeader.SizeOfImage);
        printf("[+] Headers Size: 0x%08x\n", NtOptionalHeader.SizeOfHeaders);
        printf("[+] Subsystem: %s\n", NtOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ? "GUI" : "CUI");

        // print sections buffer
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < NtFileHeader.NumberOfSections; i++)
        {
                printf("[+] Section Name: %s\n", pSectionHeader->Name);
                printf("\t\\_Virtual Address: 0x%08x\n", pSectionHeader->VirtualAddress);
                printf("\t\\_Virtual Size: 0x%08x\n", pSectionHeader->Misc.VirtualSize);
                printf("\t\\_Raw Size: 0x%08x\n", pSectionHeader->SizeOfRawData);
                printf("\t\\_Raw Offset: 0x%08x\n", pSectionHeader->PointerToRawData);
                printf("\t\\_Characteristics: 0x%08x\n", pSectionHeader->Characteristics);
                pSectionHeader++;
        }
        // those code only work on dll load into current process
        //
        // if (NtFileHeader.Characteristics & IMAGE_FILE_DLL)
        // {
        //         PIMAGE_DATA_DIRECTORY pExportDir = &NtOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        //         if (pExportDir->VirtualAddress != 0)
        //         {
        //                 PIMAGE_EXPORT_DIRECTORY pExportDesc =
        //                     (PIMAGE_EXPORT_DIRECTORY)(pPeBuffer + pExportDir->VirtualAddress);
        //                 printf("[+] Export Directory:\n");
        //                 printf("  [+] Export Flags: 0x%08x\n", pExportDesc->Characteristics);
        //                 printf("  [+] Export Time: 0x%08x\n", pExportDesc->TimeDateStamp);
        //                 printf("  [+] Major Version: %d\n", pExportDesc->MajorVersion);
        //                 printf("  [+] Minor Version: %d\n", pExportDesc->MinorVersion);
        //                 printf("  [+] Name RVA: 0x%08x\n", pExportDesc->Name);
        //                 printf("  [+] Ordinal Base: %d\n", pExportDesc->Base);
        //                 printf("  [+] Function Count: %d\n", pExportDesc->NumberOfFunctions);
        //                 printf("  [+] Name Count: %d\n", pExportDesc->NumberOfNames);
        //                 PDWORD pFunctions = (PDWORD)(pPeBuffer + pExportDesc->AddressOfFunctions);
        //                 PDWORD pNames = (PDWORD)(pPeBuffer + pExportDesc->AddressOfNames);
        //                 PWORD pNameOrdinals = (PWORD)(pPeBuffer + pExportDesc->AddressOfNameOrdinals);
        //                 for (DWORD i = 0; i < pExportDesc->NumberOfNames; i++)
        //                 {
        //                         printf("    %s\n", (PCHAR)(pPeBuffer + pNames[i]));
        //                         printf("      Ordinal: %d\n", pNameOrdinals[i] + pExportDesc->Base);
        //                         printf("      RVA: 0x%08x\n", pFunctions[pNameOrdinals[i]]);
        //                 }
        //         }
        // }
        // if file type is exe, print importdir and show functions
        // if (NtFileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        // {
        //         PIMAGE_DATA_DIRECTORY pImportDir = &NtOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        //         if (pImportDir->VirtualAddress != 0)
        //         {
        //                 PIMAGE_IMPORT_DESCRIPTOR pImportDesc =
        //                     (PIMAGE_IMPORT_DESCRIPTOR)(pPeBuffer + pImportDir->VirtualAddress);
        //                 printf("[+] Import Directory:\n");
        //                 while (pImportDesc->Name != 0)
        //                 {
        //                         printf("  %s\n", (PCHAR)(pPeBuffer + pImportDesc->Name));
        //                         PIMAGE_THUNK_DATA pThunk =
        //                             (PIMAGE_THUNK_DATA)(pPeBuffer + pImportDesc->OriginalFirstThunk);
        //                         while (pThunk->u1.AddressOfData != 0)
        //                         {
        //                                 if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
        //                                 {
        //                                         printf("    %d\n", IMAGE_ORDINAL(pThunk->u1.Ordinal));
        //                                 }
        //                                 else
        //                                 {
        //                                         PIMAGE_IMPORT_BY_NAME pImport =
        //                                             (PIMAGE_IMPORT_BY_NAME)(pPeBuffer + pThunk->u1.AddressOfData);
        //                                         printf("    %s\n", pImport->Name);
        //                                 }
        //                                 pThunk++;
        //                         }
        //                         pImportDesc++;
        //                 }
        //         }
        // }

        return PARSE_OK;
}
