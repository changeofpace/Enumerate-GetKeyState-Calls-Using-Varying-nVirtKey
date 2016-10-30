IDAPython script.

Bookmark all instances of calls to GetAsyncKeyState and GetKeyState which use a varying value (e.g. not const shift/ctrl/alt modifiers) for the nVirtKey arg.

Designed for x86, untested on x64.