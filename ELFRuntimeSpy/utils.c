#include "utils.h"
#include "cli.h"

unsigned char
    soloader[] =
	"\x90"
	"\xeb\x13"
	"\x58"
	"\xba\x01\x00\x00\x00"
	"\x52"
	"\x50"
	"\xbb\x03\x00\x00\x00"
	"\xff\xd3"
	"\x83\xc4\x08"
	"\xcc"
	"\xe8\xe8\xff\xff\xff";

void ptrace_attach(int pid)
{
    if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0)
    {
		perror("ptrace_attach");
		exit(-1);
    }

    waitpid(pid, NULL, WUNTRACED);
}

void ptrace_cont(int pid)
{
    int s;

    if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) < 0)
    {
	perror("ptrace_cont");
	exit(-1);
    }

    while (!WIFSTOPPED(s))
	waitpid(pid, &s, WNOHANG);
}

void ptrace_detach(int pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
	perror("ptrace_detach");
	exit(-1);
    }
}

bool ptrace_read(int pid, unsigned long addr, void *data, unsigned int len)
{
    int bytesRead = 0;
    int i = 0;
    long word = 0;
    unsigned long *ptr = (unsigned long *)data;

    while (bytesRead < len)
    {
	word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
	if (word == -1)
	{
	    xdebug(fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed"));
	    return false;
	}
	bytesRead += sizeof(long);
	if (bytesRead > len)
	{
	    memcpy(ptr + i, &word, sizeof(long) - (bytesRead - len));
	    break;
	}
	ptr[i++] = word;
    }

    return true;
}

long
ptrace_memory_search(int pid, long start, long end, void *data, long len)
{
    long addr = start;
    char *buf = (char *)malloc(len);
    while(addr < end)
    {
        if(ptrace_read(pid, addr, buf, len))
            if(!memcmp(buf, data, len))
                return addr;
        addr += len;
    }
    return 0;
}

char *
ptrace_read_string(int pid, unsigned long start)
{
    char x = '\0';
    long end;
    char *str = NULL;
    end = ptrace_memory_search(pid, start, start+0x1000, &x, 1);
    if(!end)
        return NULL;
    str = (char *)malloc(end-start);
    if(ptrace_read(pid, start, str, end-start))
        return str;
    return NULL;
}

void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
    int byteCount = 0;
    long word = 0;

    while (byteCount < len)
    {
	memcpy(&word, vptr + byteCount, sizeof(word));
	word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
	if (word == -1)
	{
	    xdebug((stderr, "ptrace(PTRACE_POKETEXT) failed"));
	    exit(1);
	}
	byteCount += sizeof(word);
    }
}