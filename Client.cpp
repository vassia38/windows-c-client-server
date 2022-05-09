#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_PORT "27015"

#define BUFSIZE 512

DWORD ReadValues(WCHAR sendbuf[])
{
	WCHAR nume[30] = { 0 };
	WCHAR prenume[30] = { 0 };
	WCHAR varsta[4] = { 0 };
	WCHAR cnp[14] = { 0 };
	wprintf(L"Introdueti\nnumele: ");
	wscanf_s(L"%s", nume, _countof(nume));
	wprintf(L"prenumele: ");
	wscanf_s(L"%s", prenume, _countof(prenume));
	wprintf(L"varsta: ");
	wscanf_s(L"%s", varsta, _countof(varsta));
	wprintf(L"CNP: ");
	wscanf_s(L"%s", cnp, _countof(cnp));
	wprintf(L"\n");
	size_t len = wcslen(nume) + wcslen(prenume) + wcslen(varsta) + wcslen(cnp) + 4 + 1;
	wcscpy_s(sendbuf, len, nume);
	wcscat_s(sendbuf, len, L";");
	wcscat_s(sendbuf, len, prenume);
	wcscat_s(sendbuf, len, L";");
	wcscat_s(sendbuf, len, varsta);
	wcscat_s(sendbuf, len, L";");
	wcscat_s(sendbuf, len, cnp);
	wcscat_s(sendbuf, len, L";");
	return 0;
}

DWORD PipeClientFunc()
{
	WCHAR sendbuf[BUFSIZE] = { 0 };
	ReadValues(sendbuf);

	HANDLE hPipe;
	BOOL fSuccess = FALSE;
	DWORD cbToWrite, cbWritten, dwMode;
	const WCHAR* lpszPipename = L"\\\\.\\pipe\\mynamedpipe";

	while (1)
	{
		hPipe = CreateFile(
			lpszPipename,   // pipe name 
			GENERIC_READ |  // read and write access 
			GENERIC_WRITE,
			0,              // no sharing 
			NULL,           // default security attributes
			OPEN_EXISTING,  // opens existing pipe 
			0,              // default attributes 
			NULL);          // no template file 

		// Break if the pipe handle is valid. 
		if (hPipe != INVALID_HANDLE_VALUE)
			break;

		// Exit if an error other than ERROR_PIPE_BUSY occurs. 
		if (GetLastError() != ERROR_PIPE_BUSY)
		{
			wprintf(L"Could not open pipe. GLE=%d\n", GetLastError());
			return -1;
		}

		// All pipe instances are busy, so wait for 20 seconds. 
		if (!WaitNamedPipe(lpszPipename, 20000))
		{
			printf("Could not open pipe: 20 second wait timed out.");
			return -1;
		}
	}

	// The pipe connected; change to message-read mode. 
	dwMode = PIPE_READMODE_MESSAGE;
	fSuccess = SetNamedPipeHandleState(
		hPipe,    // pipe handle 
		&dwMode,  // new pipe mode 
		NULL,     // don't set maximum bytes 
		NULL);    // don't set maximum time 
	if (!fSuccess)
	{
		wprintf(L"SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
		return -1;
	}

	// Send a message to the pipe server. 
	cbToWrite = (wcslen(sendbuf) + 1) * sizeof(WCHAR);
	wprintf(L"Sending %d byte message: \"%s\"\n", cbToWrite, sendbuf);
	fSuccess = WriteFile(
		hPipe,			// pipe handle 
		sendbuf,        // message 
		cbToWrite,      // message length 
		&cbWritten,     // bytes written 
		NULL);          // not overlapped 

	if (!fSuccess)
	{
		wprintf(L"WriteFile to pipe failed. GLE=%d\n", GetLastError());
		return -1;
	}

	printf("\nMessage sent to server\n");
	return 0;
}

DWORD SocketClientFunc()
{
	WCHAR sendbuf[BUFSIZE] = {0};
	ReadValues(sendbuf);

	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	struct addrinfo* result = NULL, * ptr = NULL, hints;

	size_t lenmax = 100, len = lenmax;
	int iResult;


	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Attempt to connect to an address until one succeeds
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return 1;
		}

		// Connect to server.
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}

	// Send an initial buffer
	iResult = send(ConnectSocket, (char*)sendbuf, (int)wcslen(sendbuf) * sizeof(WCHAR), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	printf("Bytes Sent: %ld\n", iResult);

	// shutdown the connection since no more data will be sent
	iResult = shutdown(ConnectSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}

DWORD ShmemClientFunc()
{
	HANDLE hShmemSemaphore, hShmemMutex;
	hShmemSemaphore = OpenSemaphore(SEMAPHORE_ALL_ACCESS, FALSE, L"ShmemSemaphore");
	if (hShmemSemaphore == NULL) {
		wprintf(L"OpenSemaphore error: %d\n", GetLastError());
		return 1;
	}

	hShmemMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, L"ShmemMutex");
	if (hShmemMutex == NULL) {
		printf("OpenMutex error: %d\n", GetLastError());
		return 1;
	}

	WCHAR sendbuf[BUFSIZE] = { 0 };
	ReadValues(sendbuf);

	TCHAR szName[] = TEXT("MyFileMappingObject");
	HANDLE hMapFile;
	LPWSTR pBuf;
	LPSTR pCounter;

	hMapFile = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   // read/write access
		FALSE,                 // do not inherit the name
		szName);               // name of mapping object
	if (hMapFile == NULL)
	{
		wprintf(L"Could not open file mapping object (%d).\n", GetLastError());
		CloseHandle(hShmemMutex);
		CloseHandle(hShmemSemaphore);
		return 1;
	}

	pCounter = (LPSTR)MapViewOfFile(hMapFile,
		FILE_MAP_ALL_ACCESS,
		0, 0, 5 + BUFSIZE);
	if (pCounter == NULL)
	{
		wprintf(L"Could not map view of file (%d).\n", GetLastError());
		return 1;
	}

	pBuf = (LPWSTR)(pCounter + 5);
	if (pBuf == NULL)
	{
		wprintf(L"Could not map view of file (%d).\n", GetLastError());
		CloseHandle(hMapFile);
		CloseHandle(hShmemMutex);
		CloseHandle(hShmemSemaphore);
		return 1;
	}
	

	DWORD dwWaitResult = WaitForSingleObject(hShmemMutex, INFINITE);
	if (dwWaitResult == WAIT_ABANDONED) {
		wprintf(L"Got ownership of abandoned mutex :(\n");
		UnmapViewOfFile(pBuf);
		CloseHandle(hMapFile);
		CloseHandle(hShmemMutex);
		CloseHandle(hShmemSemaphore);
		return 99;
	}
	
	// Signal server
	int tries = 3;
	while(tries > 0 && !ReleaseSemaphore(hShmemSemaphore, 1, NULL))
	{
		int err = GetLastError();
		if (err == 298) {
			wprintf(L"Shmem busy...(too many posts to semaphore)\nTrying again...\n");
			tries--;
			Sleep(5000);
			continue;
		}
		printf("ReleaseSemaphore error: %d\n", GetLastError());
		UnmapViewOfFile(pBuf);
		CloseHandle(hMapFile);
		ReleaseMutex(hShmemMutex);
		CloseHandle(hShmemMutex);
		CloseHandle(hShmemSemaphore);
		return 99;
	}
	
	int counter = *(int*)pCounter;
	int offset = (wcslen(pBuf)) * sizeof(WCHAR);
	CopyMemory((LPVOID)(pBuf + offset), sendbuf, ((wcslen(sendbuf) + 1) * sizeof(WCHAR)));
	counter++;
	CopyMemory((LPVOID)pCounter, (BYTE*)&counter, 5);
	ReleaseMutex(hShmemMutex);

	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);
	CloseHandle(hShmemMutex);
	CloseHandle(hShmemSemaphore);
	return 0;
}

int wmain(int argc, WCHAR* argv[])
{
	if (argc < 2)
	{
		wprintf(L"No communication mode selected.\nUsage: Client.exe [mode]\nModes: -pipe, -socket, -shmem\n");
		return -1;
	}
	if (wcscmp(argv[1], L"-pipe") == 0) {
		wprintf(L"Launched with -pipe\n");
		PipeClientFunc();
		return 0;
	}
	if (wcscmp(argv[1], L"-socket") == 0) {
		wprintf(L"Launched with -socket\n");
		SocketClientFunc();
		return 0;
	}
	if (wcscmp(argv[1], L"-shmem") == 0) {
		wprintf(L"Launched with -shmem\n");
		ShmemClientFunc();
		return 0;
	}
	wprintf(L"Invalid mode!\nUsage: Client.exe [mode]\nModes: -pipe, -socket, -shmem\n");
	return 1;
}