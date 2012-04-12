all:
	C:\Program Files\CodeBlocks\MinGW\bin\mingw32-g++.exe -Wall -DBUILD_DLL -g -c C:\Users\rude-boi\CODE\basicproxy\main.cpp -o obj\Debug\main.o
	C:\Program Files\CodeBlocks\MinGW\bin\mingw32-g++.exe -shared -Wl,--output-def=bin\Debug\libbasicproxy.dll.def -Wl,--out-implib=bin\Debug\libbasicproxy.dll.a -Wl,--dll .\obj\Debug\main.o -o bin\Debug\basicproxy.dll --luser32