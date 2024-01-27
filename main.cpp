#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <wait.h>

/* print a welcome message for entering HZDbg
 * fork a process and start tracing it and pause it as soon as it begins
 * print when it is paused
 * Resume it when user enters 'c'. It should print some message letting you know it has resumed.
 * After it is done free it from the Zombie state.
*/

void handle_user_action(char c, pid_t pid) {
    // continue program
    if (c == 'c') {
        // continue the process
        ptrace(PTRACE_CONT, pid, NULL, NULL);
    }

}

int main (int argc, char *argv[]) {
    std::cout << "**************Hi! Welcome to HZDbg*******************\n";
    if (argc > 1) {
        /*
         * Fork the current process and call the "exec" syscall in child
         * to launch the actual program to be traced.
        */
        int fork_result = fork();
        if (fork_result == 0) {
            // Child process
            // Child process asks parent to trace it.
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) { 
                std::cout << "Ptrace traceme was unsuccessful. Error code: " << errno << "\n";
                return 1;
            }
            // Use exec system call to load the actual program that has to be traced.
            // Since the process is being traced, after success of exec the process will be 
            // sent a SIGTRAP which will cause it to enter signal-delivery-stop.
            int r = execl(argv[1], argv[2], (char *) NULL);
            std::cout << "Exec result: " << r << std::endl;
        }
        else {
            std::cout << "tracee process pid: " << fork_result << "\n";
            // Wait on the child process to receive SIGTRAP
            int process_status;
            if (waitpid(fork_result, &process_status, WUNTRACED | WCONTINUED) != -1) {
                // Check if the tracee received SIGTRAP
                // SIGTRAP case requires special handling to distunguish it from
                // syscall stops.
                if (WIFSTOPPED(process_status) != 0) {
                    std::cout << argv[2] << " is in a signal-delivery-stop state\n";
                    if (WSTOPSIG(process_status) == SIGTRAP) {
                        std::cout << "Process received SIGTRAP\n";
                    }
                    // send a PTRACE_GETSIGINFO query to confirm that the signal is SIGTRAP
                    siginfo_t sig_info;
                    ptrace(PTRACE_GETSIGINFO, fork_result, NULL, (void *)&sig_info);

                    if (sig_info.si_code != SIGTRAP && sig_info.si_code != (SIGTRAP | 0x80)) {
                        std::cout << "This wasn't a syscall stop. si_code: " << sig_info.si_code << "\n";
                    }

                    // Wait for user action
                    char i;
                    printf(">>> ");
                    fflush(stdout);
                    i = getchar();
                    for(;getchar() != '\n' && getchar() != EOF;);
                    handle_user_action(i, fork_result);

                    // Wait to the process when it is done so it doesn't become a zombie.
                    if (waitpid(fork_result, &process_status, WUNTRACED | WCONTINUED) != -1) {
                        if (WIFEXITED(process_status) != 0) {
                            std::cout << argv[1] << " has exitted\n";
                        } else {
                            std::cout << "process hasn't exitted\n";
                        }

                    } else {
                        std::cout << "some problem with wait\n";
                    }
                }
                else {
                    std::cout << "Process isn't stopped, idk!\n";
                }
            }
            
        }
    }
    else {
        std::cout << "No tracee file provided, exiting!\n";
    }

    return 0;
}