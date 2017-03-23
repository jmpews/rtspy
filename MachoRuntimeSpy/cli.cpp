#include "cli.hpp"
#include "rtspy.hpp"

#include "Macho.hpp"
#include "utils.hpp"

#define _print_line_sep (printf("--------------------------------------------------------------\n"))

void print_welcome() {
    printf(GRN);
    _print_line_sep;
    printf("%s - macOS/IOS (%s) - by %s\n", PROGRAM_NAME, PROGRAM_VER, PROGRAM_AUTHOR);
    _print_line_sep;
    printf(RESET);
}

typedef struct cmd_arg {
    unsigned int argc;
    char *argv[8];
} cmd_arg_t;

static const char *const pszCmdPrompt = GRN ">> " RESET;
static char *pszLineRead = NULL;
static cmd_arg_t arg;

bool preprocess(char *pszOrig) {
    if (NULL == pszOrig)
        return false;

    char *pszStripHead = pszOrig;
    while (isspace(*pszStripHead))
        pszStripHead++;

    if ('\0' == *pszStripHead)
        return false;

    char *pszStripTail = pszStripHead + strlen(pszStripHead) - 1;
    while (pszStripTail > pszStripHead && isspace(*pszStripTail))
        pszStripTail--;
    *(++pszStripTail) = '\0';

    add_history(pszStripHead);
    arg.argc = 1;
    char *ndx = pszStripHead;
    arg.argv[0] = pszStripHead;
    while ((ndx = strchr(ndx, ' ')) != NULL) {
        *ndx = '\0';
        ndx++;
        arg.argv[arg.argc++] = ndx;
        // max argc
        if (arg.argc == 8)
            break;
    }
    return true;
}

bool ReadCmdLine() {
    if (pszLineRead) {
        free(pszLineRead);
        pszLineRead = NULL;
    }
    pszLineRead = readline(pszCmdPrompt);

    if (preprocess(pszLineRead)) {
        return true;
    } else {
        return false;
    }

}

void process_attach() {
    if (arg.argc != 2) {
        xerror("format: attach <pid>");
        return;
    }
    int pid = atoi(arg.argv[1]);
    if (!pid) {
        xerror("format: attach <pid>");
        return;
    }
    if (mrt) {
        delete (mrt);
    }
    mrt = new macho::MachoRT();
    mrt->setPid(pid);
    mrt->parse_macho();
    macho::MachoFD dyld;
    dyld.setPath(mrt->m_dyld_path);
    dyld.parse_macho();
    if (mrt->searchDyldImageLoadAddress(dyld.m_vm_64_addr)) {
        std::cout << "[+] DyldImageLoadAddress: 0x" << std::hex << mrt->m_dyld_load_addr << std::endl;
    }
}

void process_command() {
    while (1) {
        if (!ReadCmdLine()) {
            xerror("empty command.");
        }
        if (!strcmp(arg.argv[0], "attach")) {
            process_attach();
        } else {
            xerror("Unrecognized command");
        }
    }
}
