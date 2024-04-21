# readpe

```
+-----------+   pDosHeaders->e_lfanew   +---------------+
|           |   -------------------->   |  Nt Headers   | ------+
|Dos Headers|                           |---------------|       |
|           |                           |  Nt Signature |       | pNtHeaders->FileHeader
+-----------+                           |---------------|       |
                                        |  File Header  | <-----+
                                        |---------------|
    import/export function<------------ |Optional Header|
                                        +---------------+

```
