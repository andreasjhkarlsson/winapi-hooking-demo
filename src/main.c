#include <stdio.h>
#include <Windows.h>
#include <Dbghelp.h>

BOOL ModifyImportTable(IMAGE_IMPORT_DESCRIPTOR* iid, void* target,void* replacement)
{
	IMAGE_THUNK_DATA* itd = (IMAGE_THUNK_DATA*)(((char*)GetModuleHandle(NULL)) + iid->FirstThunk);

	while (itd->u1.Function)
	{
		if (((void*)itd->u1.Function) == target)
		{
			// Temporary change access to memory area to READWRITE
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQuery(itd, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

			// Replace entry!!
			*((void**)itd) = replacement;

			// Restore memory permissions
			VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &mbi.Protect);

			return TRUE;
		}

		itd += 1;
	}
	return FALSE;
}

BOOL InstallHook(LPCSTR module, LPCSTR function, void* hook, void** original)
{
	HMODULE process = GetModuleHandle(NULL);

	// Save original address to function
	*original = (void*)GetProcAddress(GetModuleHandleA(module), function);
	
	ULONG entrySize;

	IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToData(process, 1, IMAGE_DIRECTORY_ENTRY_IMPORT, &entrySize);

	// Search for module
	while (iid->Name)
	{
		const char* name = ((char*)process) + iid->Name;

		if (stricmp(name, module) == 0)
		{
			return ModifyImportTable(iid, *original, hook);
		}
		iid += 1;
	}

	return FALSE;
}

int (__stdcall *RealMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

int __stdcall HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	printf("Program is trying to display a message box with title '%s' and text '%s'.\n\nAllow (y/n)? ",lpCaption,lpText);
	char choice;
	scanf_s("%c", &choice);
	if (choice == 'y')
	{
		return RealMessageBoxA(hWnd, lpText, lpCaption, uType);
	}
	else
	{
		printf("\nSupressing message...\n");
		return 0;
	}
}

int main()
{
	if (InstallHook("User32.dll", "MessageBoxA", (void*)HookedMessageBoxA, (void**)(&RealMessageBoxA)))
	{
		printf("Hook installed!\n\n");
		MessageBoxA(NULL, "Let me out!", "I'm trapped!", 0);
	}
	else
	{
		printf("Failed to install hook!\n");
	}

	return 0;
}