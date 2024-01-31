#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <wait.h>
#include <string.h>
#include <sys/personality.h>
#include "shared.h"

#define TRACEE_RUNNING 0
#define TRACEE_STOPPED 1
typedef int tracee_state;

/*
 Launch debugger with "hzdbg <traceepath> traceename"
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
                logger->info("tracee process pid: {}", pid);
                logger->debug("{} is in a signal-delivery-stop state", pid);
                logger->debug("{} received the {} signal", pid, strsignal(WSTOPSIG(process_status)));

                // Display debugger prompt till the tracee process has been resumed
                while (handle_user_action(pid) == TRACEE_STOPPED)
                    ;
            }
            else if (WIFEXITED(process_status) != 0)
            {
                if (WEXITSTATUS(process_status) != 0)
                {
                    logger->info("Tracee process didn't exit happily, status: {}", WEXITSTATUS(process_status));
                }
                else
                {
                    logger->info("{} has exited", pid);
                }
                printf("HZDbg is done, peace out!\n");
                return;
            }
            else
            {
                logger->error("tracee {} process hasn't stopped nor exited: [process status: {}]", pid, process_status);
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
            init_logger("/tmp/traceeproc.log");

            // Set personality of this process to disable ASLR (Address space layout randomisation)
            // This will help in setting breakpoints. Otherwise we could have different offsets for
            // different region in the process address space, making it difficult to set breakpoints
            // from addresses obtained from objdump. The system call will take effect when we call
            // "exec" later
            if (personality(ADDR_NO_RANDOMIZE) == -1)
            {
                logger->error("Personality syscall failed: ", strerror(errno));
                return 1;
            }

            // Child process asks parent to trace it.
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
            {
                logger->error("Ptrace traceme was unsuccessful: {}", strerror(errno));
                return 1;
            }
            // Use exec system call to load the actual program that has to be traced.
            // Since the process is being traced, after success of exec the process will be
            // sent a SIGTRAP which will cause it to enter signal-delivery-stop.
            fflush(NULL); // call fflush to flush all output buffers of the current process before calling exec
            // BUG: Resource leak could be happening because I'm not closing the FDs of the parent process
            int r = execl(argv[1], argv[2], (char *)NULL);
            logger->error("Exec failed for {} {}", argv[2], strerror(errno));
            return 1;
        }
        else
        {
            init_logger("/tmp/hzdbg.log");
            signal_receive_user_input_loop(fork_result, argv[2]);
        }
    }
    else
    {
        printf("Don't have anything to trace. Please provide a tracee: ./hzdbg <traceepath> <traceename>\n");
        logger->info("No tracee file provided, exiting!");
    }

    return 0;
}