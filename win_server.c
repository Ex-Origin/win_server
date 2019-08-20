#include <windows.h>
#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock.h>

#pragma comment(lib, "ws2_32.lib")

struct args
{
    HANDLE stdout_read, stdin_write, stdout_write;
    SOCKET conn;
    HANDLE process;
};

DWORD WINAPI input(LPVOID p)
{
    struct args *local;
    char buf[0x1000];
    int nbytes;

    local = (struct args *)p;
    while(1)
    {
        nbytes = recv(local->conn, buf, 0x1000, 0);
        if(nbytes <= 0)
        {
            TerminateProcess(local->process, 1234);
            return 0;
        }
        if(!WriteFile(local->stdin_write, buf, nbytes, &nbytes, NULL))
        {
            fprintf(stderr, "WriteFile error\n");
            TerminateProcess(local->process, 1234);
            exit(1);
        }
    }
}

DWORD WINAPI output(LPVOID p)
{
    struct args *local;
    char buf[0x1000];
    int nbytes;

    local = (struct args *)p;
    while(1)
    {
        ReadFile(local->stdout_read, buf, 0x1000, &nbytes, NULL);
        if(nbytes <= 0)
        {
            TerminateProcess(local->process, 1234);
            return 0;
        }
        nbytes = send(local->conn, buf, nbytes, 0);
        if(nbytes <= 0)
        {
            TerminateProcess(local->process, 1234);
            return 0;
        }
    }
}

DWORD WINAPI end(LPVOID p)
{
    DWORD ExitCode;
    struct args *local;

    local = (struct args *)p;
    WaitForSingleObject(local->process, INFINITE);
    GetExitCodeProcess(local->process, &ExitCode);
    printf("Process %d is end with code %d\n", local->process, ExitCode);

    if(closesocket(local->conn))
    {
        fprintf(stderr, "closesocket error\n");
        exit(1);
    }

    if(!CloseHandle(local->stdin_write) || !CloseHandle(local->stdout_write))
    {
        fprintf(stderr, "CloseHandle error\n");
        exit(1);
    }

    free(p);
    return 0;
}

int main(int argc, char **args)
{
    WORD wVersionRequested;
    WSADATA wsaData;
    int err, len;
    SOCKET sockSrv, sockConn;
    SOCKADDR_IN addrSrv, addrClient;

    DWORD threadid;
    struct args *sub;
    HANDLE stdin_read, stdin_write, stdout_read, stdout_write;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    wVersionRequested = MAKEWORD(1, 1);

    if(argc < 3)
    {
        puts("Usage: server execve_file port");
        return 0;
    }

    err = WSAStartup(wVersionRequested, &wsaData);
    if(err != 0)
    {
        fprintf(stderr, "WSAStartup error\n");
        return -1;
    }

    sockSrv = socket(AF_INET, SOCK_STREAM, 0);
    addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
    addrSrv.sin_family = AF_INET;
    addrSrv.sin_port = htons(atoi(args[2]));

    bind(sockSrv, (SOCKADDR *)&addrSrv, sizeof(SOCKADDR));
    listen(sockSrv, 10);

    len = sizeof(SOCKADDR);

    sa.bInheritHandle = 1;
    sa.lpSecurityDescriptor = NULL;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);    

    while(1)
    {
        sockConn = accept(sockSrv, (SOCKADDR *)&addrClient, &len);
        printf("Connect %s \n", inet_ntoa(addrClient.sin_addr));
        printf("sockConn is %d\n", sockConn);

        if(!CreatePipe(&stdin_read, &stdin_write, &sa, 0) || !CreatePipe(&stdout_read, &stdout_write, &sa, 0))
        {
            fprintf(stderr, "CreatePipe Error\n");
            exit(1);
        }

        GetStartupInfo(&si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = stdout_write;
        si.hStdError = stdout_write;
        si.hStdInput = stdin_read;

        if(!CreateProcess(NULL, args[1], NULL, NULL, 1, 0, NULL, NULL, &si, &pi))
        {
            fprintf(stderr, "CreateProcess error");
            exit(1);
        }

        printf("Process %d is runing\n", pi.hProcess);

        sub = malloc(sizeof(struct args));
        sub->stdout_read = stdout_read;
        sub->stdin_write = stdin_write;
        sub->stdout_write = stdout_write;
        sub->conn = sockConn;
        sub->process = pi.hProcess;

        CreateThread(NULL, 0, input, sub, 0, NULL);
        CreateThread(NULL, 0, output, sub, 0, NULL);
        CreateThread(NULL, 0, end, sub, 0, NULL);
    }

    return 0;
}