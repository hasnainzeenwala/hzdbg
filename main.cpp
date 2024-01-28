#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <wait.h>
#include <string.h>

#define TRACEE_RUNNING 0
#define TRACEE_STOPPED 1
typedef int tracee_state;

/*
 Launch debugger with "hzdbg /traceepath traceename"
*/

tracee_state handle_user_action(pid_t pid)
{
    char i;
    printf(">>> ");
    fflush(stdout);
    i = getchar();
    for (; getchar() != '\n' && getchar() != EOF;)
        ;
    // continue program
    if (i == 'c')
    {
        // continue the process
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        return TRACEE_RUNNING;
    }
    return TRACEE_STOPPED;
}

void signal_receive_user_input_loop(pid_t pid, char *pname)
{
    for (;;)
    {
        int process_status;
        if (waitpid(pid, &process_status, WUNTRACED | WCONTINUED) != -1)
        {
            if (WIFSTOPPED(process_status) != 0)
            {
                std::cout << pname << " is in a signal-delivery-stop state\n";
                std::cout << pname << " received the " << strsignal(WSTOPSIG(process_status)) << " signal\n";

                // Display debugger prompt till the tracee process has been resumed
                while (handle_user_action(pid) == TRACEE_STOPPED);

            }
            else if (WIFEXITED(process_status) != 0)
            {
                std::cout << pname << " has exited with exit status: " << WEXITSTATUS(process_status) << "\n";
                std::cout << "Tracee has exited, peace out!\n";
                return;
            }
            else
            {
                std::cout << "Process hasn't stopped nor exited: [process status: " << process_status << "]\n";
            }
        }
    }
}

int main(int argc, char *argv[])
{
    std::cout << "**************Hi! Welcome to HZDbg*******************\n";
    if (argc > 1)
    {
        /*
         * Fork the current process and call the "exec" syscall in child
         * to launch the actual program to be traced.
         */
        int fork_result = fork();
        if (fork_result == 0)
        {
            // Child process
            // Child process asks parent to trace it.
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
            {
                std::cout << "Ptrace traceme was unsuccessful. Error code: " << errno << "\n";
                return 1;
            }
            // Use exec system call to load the actual program that has to be traced.
            // Since the process is being traced, after success of exec the process will be
            // sent a SIGTRAP which will cause it to enter signal-delivery-stop.
            int r = execl(argv[1], argv[2], (char *)NULL);
            std::cout << "Exec result: " << r << std::endl;
        }
        else
        {
            std::cout << "tracee process pid: " << fork_result << "\n";
            signal_receive_user_input_loop(fork_result, argv[2]);
        }
    }
    else
    {
        std::cout << "No tracee file provided, exiting!\n";
    }

    return 0;
}