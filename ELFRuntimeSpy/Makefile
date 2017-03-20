SOURCES = $(wildcard *.c)

LINUX_CFLAGS = 
LINUX_LDFLAGS = -L
LINUX_LIBS = -lreadline -lncurses
linux:
	gcc -std=c99 -w -g -o inject $(SOURCES)
