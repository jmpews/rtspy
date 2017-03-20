SOURCES = $(wildcard *.c)

LINUX_INCLUDE_DIR = $(abspath thirdparty/readline/linux32/include)
LINUX_LIB_DIR = $(abspath thirdparty/readline/linux32/lib)

LINUX_CFLAGS = -O3 -m32 -I$(LINUX_INCLUDE_DIR) -std=c99
LINUX_LDFLAGS = -m32 -L$(LINUX_LIB_DIR)
LINUX_LIBS = -lreadline -lncurses
linux:
	gcc $(LINUX_CFLAGS) $(LINUX_LDFLAGS) -w -g $(SOURCES) -o rtspy-linux32
