#include "stdafx.h"
#include "CreateFileMap.h"

PVOID BuildRestrictedSD(PSECURITY_DESCRIPTOR pSD) 
{
	DWORD dwAclLength;
	PSID psidEveryone = NULL;
	PACL pDACL = NULL;
	BOOL bResult = FALSE;
	PACCESS_ALLOWED_ACE pACE = NULL;
	SID_IDENTIFIER_AUTHORITY siaWorld = SECURITY_WORLD_SID_AUTHORITY ;
	
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	
	__try
	{
		if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) 
		{
			//printf("InitializeSecurityDescriptor() failed with error %d\n", GetLastError());
		}

		if (!AllocateAndInitializeSid(&siaWorld, 1, 
			  						  SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, 
									  &psidEveryone)) 
		{
			//printf("AllocateAndInitializeSid() failed with error %d\n", GetLastError());
		}
		dwAclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(psidEveryone);

		pDACL = (PACL) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwAclLength);
		if (!pDACL)
		{
			//printf("HeapAlloc() failed with error %d\n", GetLastError());
		}
		
		if (!InitializeAcl(pDACL, dwAclLength, ACL_REVISION)) 
		{
			//printf("InitializeAcl() failed with error %d\n", GetLastError());
		}
		
		if (!AddAccessAllowedAce(pDACL, ACL_REVISION,
								 GENERIC_ALL,
								 psidEveryone)) 
		{
			//printf("AddAccessAllowedAce() failed with error %d\n", GetLastError());
		}

		if (!SetSecurityDescriptorDacl(pSD, TRUE, pDACL, FALSE)) 
		{
			//printf("SetSecurityDescriptorDacl() failed with error %d\n", GetLastError());
		}
		bResult = TRUE;
	} 
	__finally 
	{
		if (psidEveryone) 
			FreeSid(psidEveryone);
	}

	if (bResult == FALSE) 
	{
		if (pDACL) 
			HeapFree(GetProcessHeap(), 0, pDACL);

		pDACL = NULL;
	}
	return (PVOID) pDACL;
}

VOID FreeRestrictedSD(PVOID ptr) 
{
	if (ptr) 
		HeapFree(GetProcessHeap(), 0, ptr);

	return;
}

CShareRestrictedSD::CShareRestrictedSD()
{
	ptr=NULL;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = FALSE;

	ptr = BuildRestrictedSD(&sd);

	if (!ptr)
	{
	}
}

CShareRestrictedSD::~CShareRestrictedSD()
{
	if(ptr)
	{
		FreeRestrictedSD(ptr);
	}
}

SECURITY_ATTRIBUTES* CShareRestrictedSD::GetSA()
{
	if(ptr)
	{
		return &sa;
	}
	else
		return NULL;
}