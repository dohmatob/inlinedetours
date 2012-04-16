///////////////////////////////////////////
// (c) d0hm4t06 3. d0p91m4 (h4lf-jiffie)
//////////////////////////////////////////

#include "stdafx.h"

// ERROR CODES
#define DETOUR_NOERROR 0x00000000
#define DETOUR_ERROR_CAVE_TOOSMALL 0x00000001
#define DETOUR_ERROR_PAGE_PROTECTION 0x00000002
#define DETOUR_ERROR_NONEXISTENT_TRANSACTION 0x00000003
#define DETOUR_ERROR_NO_MEMORY 0x00000004
#define DETOUR_ERROR_INVALID_OPERATION 0x00000005

#define TRAVERSE_LL(ll,conductor) for(conductor=ll->head;conductor;conductor=conductor->next)

/////////////////////
// linked-list ADT
////////////////////
typedef PVOID ADT; // PVOID (void-pointer) is the de facto ADT (ABSTRACT DATA TYPE) because you can cast anything to it

typedef struct node_struct
{
	ADT data;
	struct node_struct *next;
	node_struct(ADT _data)
	{
		data = _data;
		next = 0; // a new node should have a NIL next link
	}
} node_t;

typedef struct linkedlist_struct
{
	node_t *head; // first node pointer
	node_t *tail; // current node pointer
	DWORD dwSize; // number of elements

	linkedlist_struct()
	{
		head = tail = 0; // this indicates ..
		dwSize = 0; // .. emptiness
	}

	///////////////////////
	// Add node by value
	//////////////////////
	void AddNode(ADT data) // complexity is 0(1)
	{
		node_t *tmp = new node_t(data);
		if (!head)
		{
			head = tmp;
		}
		else
		{
			tail->next = tmp;
		}
		tail = tmp;
		dwSize++;
	}

	////////////////////
	// Free all nodes
	///////////////////
	void Free(void)
	{
		node_t *tmp;
		while(head)
		{
			tmp = head->next;
			free(head);
			dwSize--;
			head = tmp;
		}
		assert(dwSize == 0);
	}

	//////////////////////////
	// Delete node by value
	/////////////////////////
	void DeleteNode(ADT data)
	{
		head = DeleteNode(data, head);
	}

    BOOL empty(void)
	{
	    return dwSize == 0;
	}

protected:
	/////////////////////////////////////////////////////////////////////////////////////////////////
	// Code inspired by this glorious tutorial http://www.cs.bu.edu/teaching/c/linked-list/delete/
	////////////////////////////////////////////////////////////////////////////////////////////////
	node_t *DeleteNode(ADT data, node_t *here)
	{
		if (!here)
		{
			return 0; // nothing to do here
		}
		if (here->data == data)
		{
			// delete this node
			node_t *tmp = here->next;
			free(here);
			dwSize--;
			return tmp; // return new pointer to sub-list that was headed by deleted node
		}
		here->next = DeleteNode(data, here->next); // recursively delete node from right sub-list and re-link the list
		return here; // when all is done
	}

} linkedlist_t;

/////////////////////
// g_detours ADT
////////////////////
typedef struct detour_struct
{
	PVOID pTarget;               // pointer to target function or instruction block
	PVOID pDetour;               // pointer to detour function or instruction block
	DWORD dwOriginalOpcodes; // number of bytes to be detoured from the start of target function, or size of target block
	PBYTE pTrampoline2Target;           // pointer to instruction block which reroutes to the original/undetoured function or instruction block

	detour_struct(PVOID _pTarget, PVOID _pDetour, DWORD _dwOriginalOpcodes)
	{
		pTarget = _pTarget;
		pDetour = _pDetour;
		dwOriginalOpcodes = _dwOriginalOpcodes;
	}

	~detour_struct(void)
	{
		if (pTrampoline2Target)
		{
			delete []pTrampoline2Target;
		}
	}
} detour_t;

typedef BOOL (WINAPI *BAD_MBI_FILTER)(MEMORY_BASIC_INFORMATION);

///////////////////////////
// Function declarations
//////////////////////////
extern "C" void FindSignatureInProcessMemory(HANDLE hProcess, PBYTE pSignature, DWORD dwSignature, linkedlist_t* hits, BAD_MBI_FILTER filter = 0);
extern "C" void CreateConsole(const char *title=0, DWORD wAttributes=FOREGROUND_GREEN | FOREGROUND_INTENSITY);
extern "C" DWORD UninstallDetour(PVOID *ppTarget);
extern "C" DWORD InstallDetour(PVOID *ppTarget, PVOID pDetour, DWORD dwOrignalOpcodesSize);
static void MakeJmp(DWORD dwSrcAddr, DWORD dwDstAddr, PBYTE pBuf);
static PVOID AllocateCodecave(DWORD dwSize);
static BOOL SuspendAllOtherThreads(void);
static BOOL ResumeAllOtherThreads(void);
static void EnterCriticalCodeSection(void);
static void LeaveCriticalCodeSection(void);
