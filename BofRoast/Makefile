CFLAGS := -Os -s
CXXFLAGS += -w
COMPILED := compiled
CC_x64 := x86_64-w64-mingw32-gcc
STR_x64 := x86_64-w64-mingw32-strip
CC_x86 := i686-w64-mingw32-gcc
STR_x86 := i686-w64-mingw32-strip
RM := rm

kerberoast:
	$(CC_x64) -o $(COMPILED)/kerberoast.x64.o -c kerberoast.c $(CFLAGS) $(CXXFLAGS)
	$(STR_x64) -N kerberoast.c $(COMPILED)/kerberoast.x64.o
	$(CC_x86) -o $(COMPILED)/kerberoast.x86.o -c kerberoast.c $(CFLAGS) $(CXXFLAGS)
	$(STR_x86) -N kerberoast.c $(COMPILED)/kerberoast.x86.o

clean:
	$(RM) $(COMPILED)/*.o