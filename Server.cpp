#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <codecvt>
#include <queue>
#include "sqlite3.h"

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")

#define DEFAULT_PORT "27015"
#define BUFSIZE 512

struct PARAMETERS
{
	int position;
	HANDLE handle;
};

HANDLE ghDatabaseMutex;
std::queue<SOCKET> clientsPool;
HANDLE ghQueueMutex;
HANDLE ghQueueSemaphore;
HANDLE ghSocketInstancesSemaphore;
WCHAR szName[] = L"MyFileMappingObject";
HANDLE ghMapFile;
HANDLE ghShmemSemaphore;
HANDLE ghShmemMutex;

DWORD SaveToDB(LPWSTR* data)
{
	sqlite3* db;
	char* err_msg = 0;

	int rc = sqlite3_open("test.db", &db);
	if (rc != SQLITE_OK) {

		fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 1;
	}

	DWORD dwWaitResult = WaitForSingleObject(ghDatabaseMutex, INFINITE);
	if (dwWaitResult == WAIT_ABANDONED) {
		wprintf(L"Got ownership of abandoned mutex :(\n");
		return 99;
	}

	// TODO: Write to the database
	printf("Thread %d writing to database...\n",
		GetCurrentThreadId());
	sqlite3_stmt* stmt;
	// Use a  UTF-16 string literal
	rc = sqlite3_prepare16_v2(db, u"INSERT INTO Persoane(cnp, nume, prenume, varsta) VALUES (?,?,?,?)",
		-1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Sqlite error: %s\n", sqlite3_errmsg(db));
		ReleaseMutex(ghDatabaseMutex);
		return 1;
	}

	// Convert a wide string to a UTF-8 string
	std::wstring_convert<std::codecvt_utf8<WCHAR>> conv;
	auto nume = conv.to_bytes(std::wstring(data[0]));
	auto prenume = conv.to_bytes(std::wstring(data[1]));
	auto varsta = wcstol(data[2], NULL, 10);
	auto cnp = conv.to_bytes(std::wstring(data[3]));
	// And bind it
	sqlite3_bind_text(stmt, 1, cnp.c_str(), cnp.size(),
		SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, nume.c_str(), nume.size(),
		SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, prenume.c_str(), prenume.size(),
		SQLITE_STATIC);
	sqlite3_bind_int(stmt, 4, varsta);

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		fprintf(stderr, "Sqlite error: %s\n", sqlite3_errmsg(db));
		ReleaseMutex(ghDatabaseMutex);
		return 1;
	}

	sqlite3_finalize(stmt);
	sqlite3_close(db);
	wprintf(L"Succesfully saved to test.db > Persoane\n");
	ReleaseMutex(ghDatabaseMutex);
	return 0;
}

DWORD ProcessReceivedWString(LPWSTR pchRequest)
{
	wprintf(L"Client Request String:\"%s\"\n", pchRequest);
	WCHAR* dataString = (WCHAR*)calloc(wcslen(pchRequest) + 1, sizeof(WCHAR));
	if (dataString == NULL) {
		wprintf(L"calloc error, not enough memory!\n");
		return -1;
	}
	wcscpy_s(dataString, wcslen(pchRequest) + 1, pchRequest);
	WCHAR* buffer;
	WCHAR* token;
	token = wcstok_s(dataString, L";", &buffer);

	WCHAR nume[30] = { 0 };
	WCHAR prenume[30] = { 0 };
	WCHAR varsta[4] = { 0 };
	WCHAR cnp[14] = { 0 };
	WCHAR* data[4] = { nume, prenume, varsta, cnp };

	int i = 0;
	while (token != NULL && i < 4) {
		size_t len = wcslen(token) + 1;
		wcscpy_s(data[i], len, token);
		wprintf(L"%s\n", data[i]);
		i++;
		token = wcstok_s(NULL, L";", &buffer);
	}
	free(dataString);
	return SaveToDB(data);
}

DWORD WINAPI PipeInstanceThread(LPVOID lpvParam)
{	// This routine is a thread processing function to read from and reply to a client
	// via the open pipe connection passed from the main loop. Note this allows
	// the main loop to continue executing, potentially creating more threads of
	// of this procedure to run concurrently, depending on the number of incoming
	// client connections.
	HANDLE hHeap = GetProcessHeap();
	WCHAR* pchRequest = (WCHAR*)HeapAlloc(hHeap, 0, BUFSIZE * sizeof(WCHAR));
	DWORD cbBytesRead = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = NULL;

	if (lpvParam == NULL) {
		printf("\nERROR - Pipe Server Failure:\n");
		printf("\tPipeInstanceThread got an unexpected NULL value in lpvParam.\n");
		printf("\tPipeInstanceThread exitting.\n");
		if (pchRequest != NULL) HeapFree(hHeap, 0, pchRequest);
		return -1;
	}
	if (pchRequest == NULL) {
		printf("\nERROR - Pipe Server Failure:\n");
		printf("\tPipeInstanceThread got an unexpected NULL heap allocation.\n");
		printf("\tPipeInstanceThread exitting.\n");
		return (DWORD)-1;
	}

	wprintf(L"PipeInstanceThread created, receiving and processing messages.\n");
	hPipe = (HANDLE)lpvParam;
	while (1) {
		fSuccess = ReadFile(
			hPipe,
			pchRequest,
			BUFSIZE * sizeof(WCHAR),
			&cbBytesRead,
			NULL
		);
		if (!fSuccess || cbBytesRead == 0)
		{
			if (GetLastError() == ERROR_BROKEN_PIPE) {
				wprintf(L"InstanceThread: client disconnected.\n");
			}
			else {
				wprintf(L"InstanceThread ReadFile failed, GLE=%d.\n", GetLastError());
			}
			break;
		}
		// Process the incoming message.
		ProcessReceivedWString(pchRequest);
	}
	FlushFileBuffers(hPipe);
	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	HeapFree(hHeap, 0, pchRequest);

	printf("PipeInstanceThread exiting.\n");
	return 0;
}

DWORD WINAPI PipeThread(LPVOID lpvParam)
{
	BOOL   fConnected = FALSE;
	DWORD  dwThreadId = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
	LPCWSTR lpszPipename = L"\\\\.\\pipe\\mynamedpipe";
	// The main loop creates an instance of the named pipe and 
	// then waits for a client to connect to it. When the client 
	// connects, a thread is created to handle communications 
	// with that client, and this loop is free to wait for the
	// next client connect request. It is an infinite loop.
	while(1)
	{
		wprintf(L"\nPipe Server: thread awaiting client connection on %s\n", lpszPipename);
		hPipe = CreateNamedPipe(
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFSIZE,                  // output buffer size 
			BUFSIZE,                  // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 
		if (hPipe == INVALID_HANDLE_VALUE)
		{
			wprintf(L"CreateNamedPipe failed, GLE=%d.\n", GetLastError());
			return -1;
		}

		// Wait for the client to connect; if it succeeds, 
		// the function returns a nonzero value. If the function
		// returns zero, GetLastError returns ERROR_PIPE_CONNECTED. 
		fConnected = ConnectNamedPipe(hPipe, NULL)
					? TRUE
					: (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected)
		{
			printf("Client connected, creating a processing thread.\n");

			hThread = CreateThread(
				NULL,				// no security attribute 
				0,					// default stack size 
				PipeInstanceThread,	// thread proc
				(LPVOID)hPipe,		// thread parameter 
				0,					// not suspended 
				&dwThreadId);		// returns thread ID 

			if (hThread == NULL)
			{
				wprintf(L"CreateThread failed, GLE=%d.\n", GetLastError());
				return -1;
			}
			else CloseHandle(hThread);
		}
		else {
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
		}
	}

	return 0;
}

DWORD WINAPI SocketInstanceThread(LPVOID lpvParam)
{
	// ghQueueSemaphore is non-signaled when the clients queue is empty,
	// so wait;
	DWORD dwWaitResult = WaitForSingleObject(ghQueueSemaphore, INFINITE);
	if (dwWaitResult == WAIT_TIMEOUT) {
		wprintf(L"'INFINITE' Wait timed out ?? \n");
		ReleaseSemaphore(ghSocketInstancesSemaphore,1, NULL);
		return 98;
	}

	// safe to get a client from the queue
	dwWaitResult = WaitForSingleObject(ghQueueMutex, INFINITE);
	if (dwWaitResult == WAIT_ABANDONED) {
		wprintf(L"Got ownership of abandoned mutex :(\n");
		ReleaseSemaphore(ghSocketInstancesSemaphore, 1, NULL);
		return 99;
	}
	SOCKET ClientSocket = clientsPool.front();
	clientsPool.pop();
	ReleaseMutex(ghQueueMutex);

	int iResult, err = 0;

	WCHAR recvbuf[BUFSIZE] = { 0 };
	int recvbuflen = BUFSIZE;
	// Receive until the peer shuts down the connection
	do {

		iResult = recv(ClientSocket, (char*)recvbuf, recvbuflen * sizeof(WCHAR), 0);
		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);
			ProcessReceivedWString(recvbuf);
		}
		else if (iResult == 0) {
			err = 0;
			printf("Connection closing...\n");
		}
		else {
			err = WSAGetLastError();
			printf("recv failed with error: %d\n", err);
			break;
		}

	} while (iResult > 0);

	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		err = WSAGetLastError();
		printf("shutdown failed with error: %d\n", err);
	}
	// cleanup
	closesocket(ClientSocket);
	ReleaseSemaphore(ghSocketInstancesSemaphore, 1, NULL);
	return err;
}

DWORD WINAPI SocketThread(LPVOID lpvParam)
{
	WSADATA wsaData;

	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	int iSendResult;

	struct addrinfo* result = NULL;
	struct addrinfo hints;

	WORD wVersionRequested = MAKEWORD(2, 2);

	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
		printf("WSAStartup failed with error: %d\n", err);
		return 1;
	}
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	err = 0;
	while (err == 0) {
		// Accept a client socket
		wprintf(L"\nSocket Server: thread awaiting client connection\n");
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET)
		{
			err = WSAGetLastError();
			printf("accept failed with error: %d\n", err);
			break;
		}
		clientsPool.push(ClientSocket);
		ReleaseSemaphore(ghQueueSemaphore, 1, NULL);	// signal that the clients queue is not empty
		wprintf(L"new connection established\n");

		DWORD dwWaitResult = WaitForSingleObject(ghSocketInstancesSemaphore, 0);
		if (dwWaitResult == WAIT_TIMEOUT) {
			wprintf(L"Max SocketInstanceThreads created (one of them will handle the new client)\n");
			continue;
		}
		if (dwWaitResult == WAIT_OBJECT_0) {
			DWORD dwThreadId;
			HANDLE hThread;
			hThread = CreateThread(
				NULL,					// no security attribute 
				0,						// default stack size 
				SocketInstanceThread,	// thread proc
				NULL,					// thread parameter 
				0,						// not suspended 
				&dwThreadId);			// returns thread ID 

			if (hThread == NULL)
			{
				wprintf(L"CreateThread failed, GLE=%d.\n", GetLastError());
				return -1;
			}
			else CloseHandle(hThread);
		}
	}

	// No longer need server socket
	closesocket(ListenSocket);
	WSACleanup();
	return err;
}

DWORD WINAPI ShmemThread(LPVOID lpvParam)
{
	LPWSTR pBuf;
	LPSTR pCounter;
	pCounter = (LPSTR)MapViewOfFile(ghMapFile,
		FILE_MAP_ALL_ACCESS,
		0, 0, 5 + BUFSIZE);
	if (pCounter == NULL)
	{
		wprintf(L"Could not map view of file (%d).\n", GetLastError());
		return 1;
	}
	ZeroMemory((LPVOID)pCounter, 5);

	pBuf = (LPWSTR)(pCounter + 5);

	while (1) {
		wprintf(L"\nShared Memory Server: thread awaiting client connection\n");
		//Sleep(40000);	// leave some time so clients can write more to buffer; for testing
		DWORD dwWaitResult = WaitForSingleObject(ghShmemSemaphore, INFINITE);
		if (dwWaitResult == WAIT_TIMEOUT) {
			wprintf(L"'INFINITE' Wait timed out ?? \n");
			UnmapViewOfFile(pBuf);
			return 98;
		}
		
		dwWaitResult = WaitForSingleObject(ghShmemMutex, INFINITE);
		if (dwWaitResult == WAIT_ABANDONED) {
			wprintf(L"Got ownership of abandoned shmemMutex :(\n");
			UnmapViewOfFile(pBuf);
			return 99;
		}

		int counter = *(int*)pCounter;
		WCHAR* dataString = pBuf;
		while(counter > 0) {
			ProcessReceivedWString(dataString);
			dataString = dataString + wcslen(dataString) * sizeof(WCHAR);
			counter--;
		}
		ZeroMemory((LPVOID)pCounter, 5);
		ZeroMemory(pBuf, BUFSIZE);
		ReleaseMutex(ghShmemMutex);
	}
	UnmapViewOfFile(pCounter);
	UnmapViewOfFile(pBuf);
	return 0;
}

/*
PARAMETERS* params = (PARAMETERS*)calloc(1, sizeof(PARAMETERS));
if (params == NULL) {
	wprintf(L"calloc error, not enough memory\n");
	CloseHandle(hPipe);
	return 1;
}
params->position = lastPosition;
params->handle = hPipe;
*/

int wmain(int argc, WCHAR* argv[])
{
	WCHAR progPath[] = L"D:\\Projects\\Task6\\Server\\Server.exe";
	HKEY hKey;
	WCHAR path[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
	LONG status = RegCreateKeyEx(HKEY_CURRENT_USER, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (status != ERROR_SUCCESS) {
		wprintf(L"RegCreateKeyEx error (%d)\n", status);
		return 1;
	}

	status = RegSetValueEx(hKey, L"MyApp", 0, REG_SZ, (BYTE*)progPath, wcslen(progPath) * sizeof(WCHAR));
	if (status != ERROR_SUCCESS) {
		wprintf(L"RegSetValueEx error (%d)\n", status);
		return 1;
	}
	sqlite3* db;
	char* err_msg = 0;

	int rc = sqlite3_open("test.db", &db);
	if (rc != SQLITE_OK) {

		fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);

		return 1;
	}

	const char* sql =	"CREATE TABLE IF NOT EXISTS Persoane("
						"cnp VARCHAR(14) PRIMARY KEY,"
						"nume VARCHAR(30),"
						"prenume VARCHAR(30),"
						"varsta INT);";
	rc = sqlite3_exec(db, sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {

		fprintf(stderr, "SQL error: %s\n", err_msg);

		sqlite3_free(err_msg);
		sqlite3_close(db);

		return 1;
	}
	sqlite3_close(db);

	//WCHAR currentDir[BUFSIZE] = { 0 };
	//GetCurrentDirectory(BUFSIZE, currentDir);

	ghDatabaseMutex = CreateMutex(NULL, FALSE, NULL);
	if (ghDatabaseMutex == NULL)
	{
		printf("CreateMutex error: %d\n", GetLastError());
		return 1;
	}

	ghQueueMutex = CreateMutex(NULL, FALSE, NULL);
	if (ghQueueMutex == NULL)
	{
		printf("CreateMutex error: %d\n", GetLastError());
		return 1;
	}

	ghQueueSemaphore = CreateSemaphore(NULL, 0, 1, NULL);
	if (ghQueueSemaphore == NULL) {
		printf("CreateSemaphore error: %d\n", GetLastError());
		return 1;
	}

	ghSocketInstancesSemaphore = CreateSemaphore(NULL, 4, 4, NULL);
	if (ghSocketInstancesSemaphore == NULL) {
		printf("CreateSemaphore error: %d\n", GetLastError());
		return 1;
	}

	ghShmemSemaphore = CreateSemaphore(NULL, 0, 16, L"ShmemSemaphore");
	if (ghShmemSemaphore == NULL) {
		printf("CreateSemaphore error: %d\n", GetLastError());
		return 1;
	}

	ghShmemMutex = CreateMutex(NULL, FALSE, L"ShmemMutex");
	if (ghShmemMutex == NULL) {
		printf("CreateMutex error: %d\n", GetLastError());
		return 1;
	}
	
	ghMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,   // use paging file
		NULL,                   // default security
		PAGE_READWRITE,         // read/write access
		0,                      // maximum object size (high-order DWORD)
		5 + BUFSIZE,			// maximum object size (low-order DWORD)
		szName);                // name of mapping object
	if (ghMapFile == NULL)
	{
		wprintf(L"Could not create file mapping object (%d).\n", GetLastError());
		return 1;
	}

	DWORD dwPipeThreadId, dwSocketThreadId, dwShmemThreadId;
	HANDLE hPipeThread, hSocketThread, hShmemThread;

	hPipeThread = CreateThread(NULL, 0, PipeThread, NULL, 0, &dwPipeThreadId);
	if (hPipeThread == NULL) {
		wprintf(L"Creating thread for pipe comm failed. Error code: %d\n", GetLastError());
		return -1;
	}

	hSocketThread = CreateThread(NULL, 0, SocketThread, NULL, 0, &dwSocketThreadId);
	if(hSocketThread == NULL) {
		wprintf(L"Creating thread for socket comm failed. Error code: %d\n", GetLastError());
		return -1;
	}

	hShmemThread = CreateThread(NULL, 0, ShmemThread, NULL, 0, &dwShmemThreadId);
	if (hShmemThread == NULL) {
		wprintf(L"Creating thread for shared memory comm failed. Error code: %d\n", GetLastError());
		return -1;
	}

	WaitForSingleObject(hPipeThread, INFINITE);
	WaitForSingleObject(hSocketThread, INFINITE);
	WaitForSingleObject(hShmemThread, INFINITE);

	CloseHandle(hPipeThread);
	CloseHandle(hSocketThread);
	CloseHandle(hShmemThread);
	CloseHandle(ghDatabaseMutex);
	CloseHandle(ghQueueMutex);
	CloseHandle(ghQueueSemaphore);
	CloseHandle(ghSocketInstancesSemaphore);
	CloseHandle(ghMapFile);
	CloseHandle(ghShmemMutex);
	CloseHandle(ghShmemSemaphore);
	return 0;
}