global _start


section .text
_start: 

	;	PEB is located at offset 0x030 from the main the File Segment register
	;   LDR is located at offset PEB + 0x00C
	;   InMemoryOrderModuleList is located at offset LDR + 0x014
	;   First module Entry is the exe itself
	;   Second module Entry is ntdll.dll
	;   Third module Entry is kernel32.dll
	;   Fourth module Entry is Kernelbase.dll
	;----------------------------------------------------------------------
	; !peb
	; Ldr                       		76e77880
	;----------------------------------------------------------------------
	; PEB
	; dt nt!_TEB
	; +0x030 ProcessEnvironmentBlock 	: Ptr32 _PEB
	;----------------------------------------------------------------------
	; LDR
	; dt nt!_PEB
	; +0x00c Ldr              			: Ptr32 _PEB_LDR_DATA
	;----------------------------------------------------------------------
	; InMemoryOrderModuleList
	; Now find the start address of the InMemoryOrderModuleList using the LDR address
	; dt nt!_PEB_LDR_DATA 76e77880-8
	; +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x2b1990 - 0x2b2d08 ]
	;-----------------------------------------------------------------------
	; InMemoryOrderModuleList isn't a _LIST_ENTRY type but is a LDR_DATA_TABLE_ENTRY
	; accordingly with https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
	; 1st module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1990-8
	; BaseDllName      : _UNICODE_STRING "C:\Users\workshop\Desktop\nc.exe"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b1a20 - 0x76e7788c ]
	;-----------------------------------------------------------------------
	; 2nd module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1a20-8
	; BaseDllName      : _UNICODE_STRING "C:\Windows\SYSTEM32\ntdll.dll"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b1d48 - 0x2b1990 ]
	;-----------------------------------------------------------------------
	; 3rd module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1d48-8
	; BaseDllName      : _UNICODE_STRING "C:\Windows\system32\kernel32.dll"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b1e60 - 0x2b1a20 ]
	;-----------------------------------------------------------------------
	; 4th module
	; dt nt!_LDR_DATA_TABLE_ENTRY 0x2b1e60-8
	; BaseDllName      : _UNICODE_STRING "C:\Windows\system32\KERNELBASE.dll"
	; +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x2b2710 - 0x2b1d48 ]
	;-----------------------------------------------------------------------
	; Our main area of interest for now is which is Kernel32.dll. Every time you load a DLL, 
	; the address gets stored at the offset of DllBase which is 0x018. 
	; Our Start address of Linked Lists will be stored in the offset of InMemoryOrderLinks which is 0x008. 
	; Thus the offset difference would be DllBase – InMemoryOrderLinks = 0x018 – 0x008 = 0x10. 
	; Hence, the offset of Kernel32.dll would be LDR + 0x10


	; raise the chain since we load the kernel32.dll address in eax
	xor ecx, ecx
	mul ecx
	mov eax, [fs:ecx + 0x030]	; PEB loaded in eax
	mov eax, [eax + 0x00c]		; LDR loaded in eax
	mov eax, [eax + 0x014]		; InMemoryOrderModuleList loaded in eax
	mov eax, [eax]				; program.exe address loaded in eax (1st module)
	mov eax, [eax]				; ntdll.dll address loaded (2nd module)
	mov eax, [eax + 0x10]		; kernel32.dll address loaded (3rd module)
