.386
.model flat,stdcall,C
option casemap:none

include \masm32\include\kernel32.inc 
includelib \masm32\lib\kernel32.lib

include \masm32\include\user32.inc  
includelib \masm32\lib\user32.lib

include \masm32\include\Winmm.inc  
includelib \masm32\lib\Winmm.lib


Eealg proto :DWORD, :DWORD
ModePower proto :dword, :dword, :dword
NextRandInt proto :dword, :dword
GenPrimes proto :dword
public C Init_lib
public C GetKeys
public C RSA_encrypt
public C RSA_decrypt

.data
cur_heap dword ?

rand_seed dword ?
rand_a dword 7
rand_c dword 13

Vector_t struct
	_base dword ?
	_size dword ?
	_cap dword ?
Vector_t ends

my_primes Vector_t <0, 1, 200>


.code
Init_lib proc _primes_max : dword
	invoke HeapCreate, 4, 100h, 800h ; const, min, max. if max == 0 => dinamic
	mov cur_heap, eax

	invoke timeGetTime
	mov rand_seed, eax

	mov eax, my_primes._cap
	shl eax, 2
	invoke HeapAlloc, cur_heap, 4, eax 
	mov my_primes._base, eax
	invoke GenPrimes, _primes_max

	;invoke ExitProcess, 0  
	ret
Init_lib endp

Eealg proc _a : DWORD, _b : DWORD ; GCD in eax; x, y in [esp - 20] [esp - 24]
	cmp _a, 0
	jnz @@goOn
	push 0
	push 1
	mov eax, _b
	ret

	@@goOn:
	mov eax, _b
	xor edx, edx
	div _a
	push eax
	invoke Eealg, edx, _a
	mov ebx, eax ; d_i-1
	pop eax ; b / a
	mul dword ptr [esp - 24]
	mov edx, dword ptr [esp - 28]
	sub edx, eax
	
	push edx
	push dword ptr [esp - 20]
	mov eax, ebx
	ret
Eealg endp

ModePower proc _a : dword, _p : dword, _m : dword ; result in eax
	push ebx
	push ecx
	push edx
	push esi
	
	mov ecx, _p
	mov eax, 1
	mov ebx, _a
	mov esi, _m
	l_start:
		mul ebx
		div esi
		mov eax, edx
	loop l_start
	
	pop esi
	pop edx
	pop ecx
	pop ebx
	ret
ModePower endp

NextRandInt proc _n1 : dword, _n2 :dword
	mov eax, rand_seed
	mul rand_a
	add eax, rand_c
	mov rand_seed, eax

	mov ebx, _n2
	sub ebx, _n1
	xor edx, edx
	div ebx
	add edx, _n1
	mov eax, edx
	ret
NextRandInt endp

GenPrimes proc _n :dword
	sub esp, 4

	mov eax, _n
	shr eax, 3
	inc eax
	invoke HeapAlloc, cur_heap, 8, eax
	mov [ebp - 4], eax ; bitset

	mov eax, 1
	mov edx, my_primes._base
	mov [edx], eax

	mov ecx, 10b
	xor ebx, ebx
	mov esi, 2 
	@@loop:
		mov edx, ecx
		mov eax, [ebp - 4]
		and edx, dword ptr [eax + ebx*4]
		cmp edx, 0
		jnz @@continue

		push esi 
		push ecx 
		push ebx

		mov edi, ecx ; mask

		mov [ebp - 8], esi ; i
		mov edx, esi
		shr edx, 5 ; i / 32
		mov ecx, esi
		mov eax, edx
		shl eax, 5
		sub ecx, eax ; i - int(i / 32) * 32
		shl esi, 1 ; ii
		
		@@loop2:
			cmp esi, _n
			jae @@endloop2

			add ebx, edx
			mov eax, edi
			rol edi, cl
			cmp edi, eax
			ja @@l1
			inc ebx
			@@l1:

			mov eax, [ebp - 4]
			or dword ptr [eax + ebx*4], edi
			mov eax, dword ptr [eax + 8]
			add esi, [ebp - 8]
			jmp @@loop2
		@@endloop2:

		pop ebx
		pop ecx
		pop esi

		mov eax, my_primes._size
		mov edx, my_primes._base
		mov [edx + eax*4], esi
		inc my_primes._size

	@@continue:
		mov eax, ecx
		rol ecx, 1
		cmp ecx, eax
		ja @@l2
		inc ebx
		@@l2:

		inc esi
		cmp esi, _n
		jne @@loop

	ret
GenPrimes endp

GetKeys proc
	push ebp
	mov ebp, esp
	sub esp, 4

	mov eax, 3
	shl eax, 2
	invoke HeapAlloc, cur_heap, 4, eax
	mov [ebp - 4], eax ; out

	invoke NextRandInt, 7, my_primes._size	
	mov edi, my_primes._base
	mov ebx, [edi + eax*4] ;p
	push ebx
	invoke NextRandInt, 7, my_primes._size
	pop ebx
	mov ecx, [edi + eax*4] ;q 

	mov eax, ecx
	mul ebx
	mov edx, [ebp - 4]
	mov [edx + 8], eax ; m

	dec ebx
	dec ecx

	mov eax, ecx
	mul ebx
	mov edi, eax ; fi

	shr eax, 2 ; temp fi
	mov esi, 1
	mov ebx, my_primes._base
	xor edx, edx
	@@loop1:
		cmp eax, [ebx + esi*4]
		jbe @@endloop1

		push eax
		div dword ptr [ebx + esi*4]
		cmp edx, 0
		je @@no_rem

		pop eax
		inc esi
		xor edx, edx
		jmp @@loop1

		@@no_rem:
		pop ecx ; or anywhere else 
		jmp @@loop1
	@@endloop1:
	inc esi
	mov edx, [ebp - 4]
	mov eax, dword ptr [ebx + esi*4]
	mov [edx], eax ; e
	
	invoke Eealg, eax, edi

	mov ebx, [ebp - 4]
	mov edx, dword ptr [esp - 20] ; d
	cmp edx, 0
	jge @@L2
	add edx, edi
	@@L2:
	mov [ebx + 4], edx

	mov eax, ebx
	mov esp, ebp
	pop ebp
	ret
GetKeys endp

RSA_encrypt proc _in_base :dword, _size :dword, _a :dword, _n :dword ; return in eax
    sub esp, 4
	
	mov eax, _size
	shl eax, 2
	invoke HeapAlloc, cur_heap, 4, eax
	mov [ebp - 4], eax
	mov ecx, eax

	xor esi, esi
	mov ebx, _in_base           

	@@: 
		xor eax, eax
		mov al, byte ptr [ebx + esi]
		invoke ModePower, eax, _a, _n
		mov dword ptr [ecx + esi*4], eax
		inc esi
		cmp esi, _size
		jb @B

	mov eax, ecx
	ret
RSA_encrypt endp

RSA_decrypt proc _in_base :dword, _size :dword, _a :dword, _n :dword
	sub esp, 4
	
	mov eax, _size
	invoke HeapAlloc, cur_heap, 4, eax
	mov [ebp - 4], eax
	mov ecx, eax

	xor esi, esi
	mov ebx, _in_base 

	@@: 
		invoke ModePower, dword ptr [ebx + esi*4], _a, _n
		mov byte ptr [ecx + esi], al
		inc esi
		cmp esi, _size
		jb @B

	mov eax, ecx
	ret
RSA_decrypt endp

end