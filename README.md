### WinAPI Hooking Demo

Small example on how to hook winapi functions using the Import Address Table (IAT)

#### FAQ
###### How does this work?

Functions exported from dynamic libraries on Windows (DLL) are stored inside the Portable Executable (PE) headers which are then directly mapped to process memory.

When some code then wants to call these functions this table is usually consulted by calling the [GetProcAddress](https://msdn.microsoft.com/en-us/library/windows/desktop/ms683212(v=vs.85).aspx) function.

Since this table is simply stored in the process address space it's just a matter of finding the table and modify it.

######  Can non exported function be hooked?

Yes, but not with this method. See [this](https://github.com/TsudaKageyu/minhook) library which replaces the first instruction of a function with a jump to a trampoline function.

######  Can you hook functions in other processes?

Yes! You can employ this method by putting it inside of a DLL and then injecting it into the target process. The usual method for DLL injection is done using the [CreateRemoteThread](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682437(v=vs.85).aspx) function. You can find more details on this method [here](http://resources.infosecinstitute.com/using-createremotethread-for-dll-injection-on-windows/).
