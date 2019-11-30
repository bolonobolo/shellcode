global _start

section .text
_start:

    ;lea ebp, [findSymbolByHash]
    ;lea edi, [hashString]
    mov ebp, findSymbolByHash
    mov edi, hashString

getKernel32Base:
    xor ecx, ecx                ; zeroing register ECX
    mul ecx                     ; zeroing register EAX EDX
    mov eax, [fs:ecx + 0x030]   ; PEB loaded in eax
    mov eax, [eax + 0x00c]      ; LDR loaded in eax
    mov esi, [eax + 0x014]      ; InMemoryOrderModuleList loaded in esi
    lodsd                       ; program.exe address loaded in eax (1st module)
    xchg esi, eax               
    lodsd                       ; ntdll.dll address loaded (2nd module)
    mov ebx, [eax + 0x10]       ; kernel32.dll address loaded in ebx (3rd module)
    mov eax, ebx
    ; EBX = base of kernel32.dll address

    ; EAX 76140000 kernel32.76140000
    ; ECX 00000000
    ; EDX 00000000
    ; EBX 76140000 kernel32.76140000
    ; ESP 0022FF8C
    ; EBP 0022FF94
    ; ESI 0026190C
    ; EDI 00000000
    ; EIP 00401005 getMessa.00401005

    push 0xec0e4e8e             ; LoadLibraryA hash
    push eax
    call ebp                    ; findSymbolByHash
    
    ; EAX 76192864 kernel32.LoadLibraryA
    ; ECX 00000000
    ; EDX 00000000
    ; EBX 76140000 kernel32.76140000
    ; ESP 0022FF8C
    ; EBP 0022FF94
    ; ESI 0026190C
    ; EDI 00000000
    ; EIP 00401015 getMessa.00401015

getUser32:
    push 0x61616c6c                 ;
    sub word [esp + 0x2], 0x6161    ; aalld.23resU
    push 0x642e3233                 ; 
    push 0x72657355                 ; 
    push esp
    call eax                        ; call LoadlibraryA and find User32.dll

    ; EAX 76200000 OFFSET User32.#2499
    ; ECX 7759316F ntdll.7759316F
    ; EDX 00530174
    ; EBX 760C0000 kernel32.760C0000
    ; ESP 0022FF60 ASCII "User32.dll"
    ; EBP 0022FF8C
    ; ESI 0053190C
    ; EDI 00000000
    ; EIP 00401037 getMessa.00401037
    
getFunctions:
    push 0xbc4da2a8          ; MessageBoxA hash
    push eax                 ; user32.dll address
    call ebp                 ; findSymbolByHash
    add sp, 8
    push eax
    lea esi, [esp]

    mov [esi+0x4], eax     ; store Messagebox in esi+4

    push 0x73e2d87e          ; ExitProcess hash
    push ebx                 ; kernel32 dll location
    call ebp                 ; findSymbolByHash
    mov [esi+0x8], eax     ; store ExitProcess in esi+8

callMessageBox:
    xor edx, edx
    xor ecx, ecx
    push edx                        
    push 'Pwnd'
    mov edi, esp
    push edx
    push 'Yess'
    mov ecx, esp
    push edx                        ; uType = NULL
    push edi                        ; the title "dnwP"
    push ecx                        ; the message "sseY"
    push edx                        ; hWnd = NULL
    call dword [esi+0x4]            ; MessageBoxA(windowhandle,msg,title,type)

callExitProcess:
    xor  edx, edx
    push edx                 ; uExitCode
    call dword [esi+0x8]   ; call ExitProcess(0)

;----------------------------------------------------------;
; Functions called                                         ;
;----------------------------------------------------------;


findSymbolByHash:
    pushad
    mov ebp, [esp + 0x24]       ; load 1st arg: dllBase
    mov eax, [ebp + 0x3c]       ; get offset to PE signature
    ; load edx w/ DataDirectories array: assumes PE32
    mov edx, [ebp + eax + 4+20+96]
    add edx, ebp                ; edx:= addr IMAGE_EXPORT_DIRECTORY
    mov ecx, [edx + 0x18]       ; ecx:= NumberOfNames
    mov ebx, [edx + 0x20]       ; ebx:= RVA of AddressOfNames
    add ebx, ebp                ; rva->va
search_loop:
    dec ecx                     ; dec loop counter

    ; esi:= next name, uses ecx*4 because each pointer is 4 bytes
    mov esi, [ebx+ecx*4]
    add esi, ebp                ; rva->va
    push esi
    call edi              ; hash the current string
    add sp, 4

    ; check hash result against arg #2 on stack: symHash
    cmp eax, [esp + 0x28]
    jnz search_loop

    ; at this point we found the string in AddressOfNames
    mov ebx, [edx+0x24]         ; ebx:= ordinal table rva
    add ebx, ebp                ; rva->va

    ; turn cx into ordinal from name index.
    ; use ecx*2: each value is 2 bytes

    mov cx, [ebx+ecx*2]
    mov ebx, [edx+0x1c]         ; ebx:= RVA of AddressOfFunctions
    add ebx, ebp                ; rva->va

    ; eax:= Export function rva. Use ecx*4: each value is 4 bytes
    mov eax, [ebx+ecx*4]
    add eax, ebp                ; rva->va
done:
    mov [esp + 0x1c], eax       ; overwrite eax saved on stack
    popad
    ret


hashString:
    push esi
    push edi
    mov esi, dword [esp+0x0c]   ; load function argument in esi
calc_hash:
    xor edi, edi
    cld
hash_iter:
    xor eax, eax
    lodsb                       ; load next byte of input string
    cmp al, ah
    je  hash_done               ; check if at end of symbol
    ror edi, 0x0d               ; rotate right 13 (0x0d)
    add edi, eax
    jmp hash_iter
hash_done:
    mov eax, edi
    pop edi
    pop esi
    ret