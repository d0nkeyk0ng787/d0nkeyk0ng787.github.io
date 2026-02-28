---
layout: post
title: "SysFinder Project"
date: 2026-02-28
---

# SysFinder Project

I have recently begun trying to gain a deep understanding of Operating Systems, how they work, and how they are designed. I have been reading [Operating Systems: Three Easy Pieces](https://pages.cs.wisc.edu/~remzi/OSTEP/) which, I have found to be a great resource that explores the fundamentals of OS design. 

I had quite a bit of fun doing the labs, but realised I'm not amazing at C and really want to get better. Having done some of the labs from the Process chapters in OSTEP, I decided I wanted to play around some more with system calls in C. This is a topic I have explored a little bit when creating payload droppers that bypass defensive mechanisms, predominantly as I go through the content on [Maldev Academy](https://maldevacademy.com). However, I can't say I have the most thorough understanding of the concepts, and for the most part, was doing my best to get code from the modules to work without really understanding how everything works.

So, I begun playing around with calling different system calls in my C code in Linux, then using [strace](https://man7.org/linux/man-pages/man1/strace.1.html) to monitor what's going on under the hood. As I was doing this, I started to get curious about the assembly instructions that occur for syscalls. Having utilised indirect syscalls in my payloads before, I know that syscalls all have what's known as a syscall stub, which are the instructions in ASM that are used to execute a syscall.

In Linux, that syscall stub looks like so:
```asm
mov rax, <syscall-id> ; moves the syscall number into the rax register
syscall               ; enter the kernel
ret
```

As you can see, for Linux, this syscall stub is pretty simple. Another cool thing about Linux is that given it is open source, we can easily look at the code for syscalls, including their ID value. We can find a table of Linux syscalls [here](https://syscalls.mebeim.net/?table=x86/64/x64/latest). As you can see, it includes the ID, which is the value that gets moved to the `rax` register so that when the `syscall` instruction is run, the OS knows where to go to find the relevant code in the kernel to perform the appropriate action. 
## Exploring Syscalls in Linux
As stated, my intention was to get better at C, so I wanted to play around with determining the system call ID for a given syscall in Linux programmatically. I did some research, and found that `strace` is utilising `ptrace()` for its functionality. So I decided to create a very limited recreation that find a given syscall. The code, with a breakdown of how it works, can be found below:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <signal.h>

//
// Syscall Number Finder
//  How it works:
//      1. fork() is invoked in order to create a child process which will act as the debugee. The parent will be the debugger
//      2. The if statement separates the execution into 2 blocks to be executed by the parent and child only respectively
//      3. The parent kicks off execution by printing, then running a waitpid on the child, returning execution back to the child process
//      4. The child prints, then runs ptrace with the PTRACE_TRACEME option on itself
//          * PTRACE_ME tells its parents process that it is to be traced by the parent
//      5. It then throws a SIGSTOP to return execution to the parent
//      6. The parent then runs ptrace with PTRACE_SYSCALL option, targeting the PID of the child, or the traced process
//          * PTRACE_SYSCALL is a resume request. It is telling the kernel to stop at the next syscall boundary (either the entry or the exit of the syscall)
//          * In practice, this means that the tracee, in this case the child, will run until the entry of the syscall. Meaning the syscall ID being loaded into rax
//      7. We then waitpid() on the child process. This returns execution to the child, which executes the syscall write()
//      8. Because we ran ptrace with PTRACE_SYSCALL, the kernel hasn't completed the execution of the syscall. It has paused at the entry. 
//          * This means, at present, the write() syscall ID has been loaded into the rax register and then paused execution
//      9. Back in the parent process, we again run ptrace with PTRACE_GETREGS, targeting the tracee or the child process, and providing the address of the regsStruct
//          * The regsStruct is a user_regs_struct which is defined in https://sites.uclouvain.be/SystInfo/usr/include/sys/user.h.html
//          * This struct will populate with various data about the traced process, including its various registers
//      10. I expected to be able to print regsStruct.rax and get the syscall ID but instead got -38. To get the syscall ID of the executed syscall, use orig_rax
//      11. My understanding is that this is because the syscall hasn't executed yet
//      12. And thats that, a fairly rudermentry strace recreation. You could change the write() syscall to whatever you wanted to find a given syscalls ID
//
int main(int argc, char **argv) {

    struct user_regs_struct regsStruct;

    int rc = fork();

    if (rc == 0) {
        printf("Child is executing read()\n");

        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        
        write(0, NULL, 0); // Change the syscall to the one you want to print the ID for. Cross-reference here https://syscalls.mebeim.net/?table=x86/64/x64/latest
    } else {
        printf("Parent is waiting!\n");

        waitpid(rc, 0, 0);

        ptrace(PTRACE_SYSCALL, rc, NULL, NULL);
        waitpid(rc, 0, 0);
        
        ptrace(PTRACE_GETREGS, rc, NULL, &regsStruct);

        printf("The syscall for read() is %ld\n", regsStruct.orig_rax);
    }
    
    return 0;
}
```

This isn't particularly useful however, as the Linux kernel is open source, we can simply lookup the system call ID ourselves quite easily. Windows however, is another story altogether. 
## SysFinder
To take this further, I wanted to get a similar effect in Windows. I initially expected to follow a similar principle of creating a child process, intercepting its execution of WinAPIs, for example `CreateThread`, to the point I could simply read the `rax` register value before the `NtCreateThreadEx` function is run and execution is handed off to the kernel. I was mistaken.

The tricky thing about Windows is that there are quite a few layers of abstraction, that trying to achieve this, at least with my unfortunately limited programming skills, was going to be quite difficult. 

After some further research, I once again came upon the [HellsGate](https://github.com/am0nsec/HellsGate) tool, which, is a tool to find the **System Service Numbers** (SSNs) of the function in `ntdll.dll`, so that it can then invoke them directly with the `syscall` instruction, in an attempt to evade user-land hooks. In addition to the Github repo for `HellsGate`, I also found this [ired.team](https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time) article which, offers a similar, but different implementation. 

Now, my goal was to utilise the fundamentals of this technique to print out a list of the `Nt*` functions from `ntdll.dll` and their corresponding SSN. As I could see it, the way to do this was as follows:
1. Read in `ntdll.dll` from disk
2. Parse the PE headers from the loaded `ntdll.dll`
3. Find the Export Address Table for `ntdll.dll` to find the addresses of the function names, and their respective code
4. Parse the `.rdata` section of `ntdll.dll`, which contains the `Nt*` function names
5. Parse the `.text` section of `ntdll.dll`, which contains the executable code for these functions, including their SSN
6. Use the RVA for the function names and the function code pair and then print them
### Reading NTDLL
To begin, we need into memory, `ntdll.dll` from disk. For this to occur, we need to do the following:
1. Get a handle to `C:\Windows\system32\ntdll.dll` with [CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
2. Allocate memory for `ntdll.dll` using [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc). This API will, if successful, return the value which is the base address of the allocated region
3. Read `ntdll.dll` into memory with [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile)
Nothing too crazy here, we end up with something approximating the following. Please note, I have removed some of the error checking logic for the sake of keeping things neat:
```c
hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

dwNtdllSize = GetFileSize("C:\\Windows\\System32\\ntdll.dll", NULL);

lpReadBuffer = VirtualAlloc(NULL, dwNtdllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);	

bReadResult = ReadFile(hFile, lpReadBuffer, dwNtdllSize, NULL, NULL);
```

Now, we have a copy of `ntdll.dll` loaded into memory, whose starting address is found at `lpReadBuffer`. We can now begin parsing the PE headers.
### Parsing PE Headers
We can now begin the fun stuff. To get the Export Address Table (EAT), we need to parse a few different headers. The following image shows the structure of a PE file:
![[/secreenshots/sysfinder-project/82d48168c1d343af13171c2a91c71738_MD5.jpg]]
As you can see, a number of headers, and we need to make our way down them to be able to get to the where the EAT, which is found in the Data Directory. There are a number of good resources for learning how to parse these headers, and that isn't really the subject of this post, so I won't step through that. However, my code for doing that, minus some error checking which you will find in the final version, can be seen below:
```c
// DOS HEader
PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpReadBuffer;
// NT Headers
PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpReadBuffer + pDosHeader->e_lfanew);
// Optional Header
IMAGE_OPTIONAL_HEADER OptionalHeader = pNtHeaders->OptionalHeader;
// Data Directory - Specifically, we are after the Export Directory, or the EAT
IMAGE_DATA_DIRECTORY DataDirectoryExport = OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

// Cast lpReadBuffer to (BYTE*) to perform pointer arithmetic. 
// The compiler won't do pointer arithmetic on void* types which is what VirtualAlloc() requests for the base address of the allocated memory. 
// So, we need to cast it to (BYTE*) to perform pointer arithmetic to get the address of the export directory.
PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lpReadBuffer + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
// Section Headers
PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER)(((PBYTE)pNtHeaders) + sizeof(IMAGE_NT_HEADERS));
```
We now have parsed all the headers from the PE file (`ntdll.dll` in this case), that we need. We now need to move onto using the information from these sections, to extract the `Nt*` functions, both the function names, their corresponding syscall stub, which, will ultimately lead us to the SSN.
### Extracting SSNs
We have parsed the headers, we have everything we need to get to our final result, we now need to put it altogether. Before I continue, I want to explain the `IMAGE_EXPORT_DIRECTORY` structure. This struct is defined in `winnt.h`, and looks like so:
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```
The key aspects of this struct, that are most relevant to my use case, are the following:
* `AddressOfNames` - These are the RVAs for `Nt*` function names. Each function, so `NtCreateThreadEx`, has a RVA, or offset from the base address of the module
* `AddressOfFunctions` - These are the RVAs which point to the executable code for 
* `AddressOfNameOrdinals` - These are the ordinal values that allow you to map the function names addresses in `AddressOfNames` to the code addressed in `AddressOfFunctions`

These 3 values, will be what we require to achieve the final result, as well as the `NumberOfFunctions` value which will be useful in our `for` loop. The next step is to create 3 arrays, to store all the addresses we need to find our SSNs, but before that, we need to create the following function:
```c
PVOID ConvertRVAtoPointer(IN PIMAGE_SECTION_HEADER pSection, IN DWORD dwRVA, IN PVOID lpReadBuffer) {
	return (PVOID)((BYTE*)lpReadBuffer + (dwRVA - pSection->VirtualAddress + pSection->PointerToRawData));
}
```

Typically, Windows loads a DLL into memory, maps each section to a specific virtual address, allowing it to be referenced from the base module address + the RVA of, for example, the functions in the EAT. But we didn't load `ntdll.dll` into module in the typical way, we read the raw file bytes from disk, which won't share the same layout as how it would if it was loaded into memory the usual way. 

This is quite an easy fix though, we simply need to provide to the above function, the section the RVA is in, the RVA, and the base address of where our `ntdll.dll` is found in memory. To get the correct address, we then need to perform the following equation:
```
Base Address + (RVA - Virtual Address + PointerToRawData)
```

You might be wondering what `pSection->VirtualAddress` and `pSection->PointerToRawData` are. As per MSDocs, the virtual address is:
```
The address of the first byte of the section when loaded into memory, relative to the image base. For object files, this is the address of the first byte before relocation is applied.
```
And, the `PointerToRawData` is:
```
A file pointer to the first page within the COFF file. This value must be a multiple of the **FileAlignment** member of the [IMAGE_OPTIONAL_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32) structure. If a section contains only uninitialized data, set this member is zero.
```
What does all this mean, essentially, we are just taking the `RVA`, subtracting the `VirtualAddress` so we get the correct offset of the target within the given section (so either `.rdata` or `.text`), and adding `PointerToRawData` to reposition that offset to where the section actually starts in the raw file. 

Now that we are there, we need to create our 3 arrays, which will contain our adjusted address values:
```c
DWORD* pAddressOfNtFuncNames = (DWORD*)ConvertRVAtoPointer(pRdataSection, pExportDirectory->AddressOfNames, (BYTE*)lpReadBuffer);
DWORD* pAddressOfNtFuncCode = (DWORD*)ConvertRVAtoPointer(pRdataSection, pExportDirectory->AddressOfFunctions, (BYTE*)lpReadBuffer);
WORD* pAddressOfNtFuncOrds = (WORD*)ConvertRVAtoPointer(pRdataSection, pExportDirectory->AddressOfNameOrdinals, (BYTE*)lpReadBuffer);
```

These arrays are quite simply, we are taking the addresses in the `AddressOfNames`, `AddressOfFunctions`, and `AddressOfNameOrdinals`, converting them to the correct value for our raw copy of `ntdll.dll` we loaded into memory, and then saving them into arrays. 

Our final bit of logic will begin with a counter, which will be based on the `NumberOfFunctions` value in the `PIMAGE_EXPORT_DIRECTORY` struct:
```c
for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
```

We will create two `DWORD` pointer variables, one will hold the address in the `.rdata` section for the `Nt*` function name. The other, will hold the address, in the `.text` section, for the syscall stub:
```c
DWORD* dwAddressOfNtFuncName = (DWORD*)ConvertRVAtoPointer(pRdataSection, pAddressOfNtFuncNames[i], (BYTE*)lpReadBuffer);
DWORD* dwAddressOfNtFuncCode = (DWORD*)ConvertRVAtoPointer(pTextSection, pAddressOfNtFuncCode[pAddressOfNtFuncOrds[i]], (BYTE*)lpReadBuffer);
```

With those addresses, we can now get the ASCII string name for the function, and the bytes of the syscall stub:
```c
LPCSTR szNtFuncName = (LPCSTR)dwAddressOfNtFuncName;
BYTE* pSyscallStub = (BYTE*)dwAddressOfNtFuncCode;
```

The final check, will ensure the function begins with an `N` to find `Nt*` functions only, as well as ensuring the syscall stub begins with the bytes `0x4C`, as we know the Windows syscall stub looks like so:
```asm
mov r10, rcx        ; save rcx (kernel will clobber it)
mov eax, <SSN>      ; load system service number
syscall             ; enter kernel
ret                 ; return to caller
```

Which, in bytes this looks like:
```
4C 8B D1            ; mov r10, rcx 
B8 XX 00 00 00      ; mov eax, SSN 
0F 05               ; syscall 
C3                  ; ret
```

Our final logic looks like so:
```c
LPCSTR szNtFuncName = (LPCSTR)dwAddressOfNtFuncName;
BYTE* pSyscallStub = (BYTE*)dwAddressOfNtFuncCode;

if (szNtFuncName[0] == 'N' && pSyscallStub[0] == 0x4C) {
	printf("	[+] %s :: ", szNtFuncName);
	printf("%d", (DWORD)pSyscallStub[4]);
	printf("\n");
}	
```

You might notice, for the `pSyscallStub` variable in the `printf` statement, I am extracting the value at index `4`. If you look above at the bytes, you will see the SSN value is the 4th byte in the sequence. Another thing you might notice, I am casting it to `DWORD`, this is so that I can get an integer value, rather than the hex value. 

When I build the project and run it, we can find the SSN for `NtCreateThreadEx` among others:
![[/secreenshots/sysfinder-project/71aea390a6f99d344330fbed1d6c401d_MD5.jpg]]
## Verification
At this stage, all that's really left is to verify that the SSN value we got for `NtCreateThreadEx` is the actual SSN value for that syscall. To do this, we can create a very simple program that executes `CreateThread()`, which will ultimately execute the `NtCreateThreadEx` function in `ntdll.dll`. 

With that created, we can open up WinDBG, and attach that program to our WinDBG. In addition to attaching my program, I also ran the command:
```
bm *!NtCreateThreadEx
```

This will create a breakpoint on any module, which exports a function that matches `NtCreateThreadEx`.
![[/secreenshots/sysfinder-project/b653449b4db9540ea5caba4eee08f569_MD5.jpg]]

We can now type `g` to continue execution until we hit the breakpoint. Ultimately, it does hit as we utilised `CreateThread` in our program.
![[/secreenshots/sysfinder-project/7cacde36849f830bad6f58c4eb71730b_MD5.jpg]]

We can see it broke on the instruction:
```asm
mov r10, rcx
```

From looking at the syscall stub earlier, we know that the next instruction will be the instruction that moves the SSN into the `eax/rax` register. So if we type `p` which will, step over the current instruction, we will hit that instruction, and see the SSN in the output of our debugger.
![[/secreenshots/sysfinder-project/9987919872cee0d1eeb97cdbd8097a82_MD5.jpg]]

As expected, that is exactly what has happened. So, we step one more time and then run the command `.formats` to dump the value at `eax` in a few different formats:
![[/secreenshots/sysfinder-project/c3048123daaab01487864c10f7b3ed56_MD5.jpg]]

As we can see, the SSN for `NtCreateThreadEx` is 201, exactly the same as what we saw in our output from parsing the `ntdll.dll` file.
## Wrapping Up
I found this to be quite a fun journey that required quite a bit of reading of new techniques. Overall, it was a good project to aid in improving my coding proficiency, I certainly found that once I was past the point of parsing the PE headers, and into the realm of working out getting the addresses in the correct format, I struggled quite a bit. 

Fortunately, I was able to get some assistance from Claude, specifically for working out the calculation of the addresses and the extensive typecasting which I am still not all over yet. 

Overall, I am quite happy that I managed to, for the most part, get this done without having AI writing or debugging my code aside from some minor points, and relied on it for the most part to work out the logic of things. 

Below you can find some of the resources I utilised to build this project. In addition, you can find the entire source code on my [Github here](https://github.com/d0nkeyk0ng787/SysFinder).
## Resources
1. https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
2. https://github.com/am0nsec/HellsGate
3. https://learn.microsoft.com
4. [Maldev Academy](https://maldevacademy.com) - Module 50: Parsing PE Headers
5. https://www.researchgate.net/figure/Basic-structure-of-PE-file-A-DOS-Header-DOS-header-starts-with-the-first-64-bytes-of_fig3_319936373