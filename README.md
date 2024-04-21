# readpe

```
+-----------+   pDosHeaders->e_lfanew   +---------------+
|           |   -------------------->   |  Nt Headers   | ------+
|Dos Headers|                           |---------------|       | pNtHeaders->FileHeader
|           |                           |  Nt Signature |       | To Read PE Type(exe,dll)
+-----------+                           |---------------|       | To Read PE Arch(x86,x64)
                                        |  File Header  | <-----+
            IMAGE_DIRECTORY_ENTRY_IMPORT|---------------|       | pNtHeaders->OptionalHeader
Import Function  <-----OR EXPORT------- |Optional Header| <-----+
                                        +---------------+
```
