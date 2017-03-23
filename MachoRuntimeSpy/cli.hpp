#ifndef cli_hpp
#define cli_hpp

#include "rtspy.hpp"
#include <stdio.h>
#include <readline/readline.h>
#include <readline/history.h>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"


#define xwarn(str) printf(YEL "[!] " "%s" "\n" RESET, str)
#define xdebug(X) {if(GLOBAL_DEBUG){printf(RESET "[*] "); X; printf("\n");}}
#define xerror(str) printf(RED "[!] " "%s" "\n" RESET, str)
//#define xinfo(str) printf(GRN "[*] " "%s" "\n" RESET, str)
#define xinfo(X) {printf(RESET "[*] "); X; printf("\n");}

void process_command();
void print_welcome();
void print_usage();

#endif /* cli_hpp */
