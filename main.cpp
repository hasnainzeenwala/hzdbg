#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <wait.h>
#include <string.h>
#include <sys/personality.h>
#include "shared.h"
#include <sstream>
#include <sys/user.h>

#define TRACEE_RUNNING 0
#define TRACEE_STOPPED 1
typedef int tracee_state;

/*
 Launch debugger with "hzdbg <traceepath> traceename"
*/

class Debugger
{
private:
    std::unordered_map<uint64_t, uint8_t> pc_to_first_byte;

public:
    Debugger() {}
    std::vector<std::string> take_input()
    {
        std::string line;
        printf(">>> ");
        fflush(stdout);
        std::getline(std::cin, line);

        std::vector<std::string> result;
        std::istringstream iss(line);
        std::string word;
        while (iss >> word)
        {
            result.push_back(word);
        }
        return result;
    }
    tracee_state handle_user_action(pid_t pid)
    {
        std::vector<std::string> input_tokens = take_input();
        // continue program
        if ("c" == input_tokens[0])
        {
            user_regs_struct regs;
            // get the current value of instruction pointer
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            logger->debug("IP for {} is at {:#x}", pid, regs.rip);

            // check if a break point was set here. (curr(ip) - 1 should exist in map)
            // if yes then resotre the old instruction and move the ip
            // back by 1 byte (because int3 instruction is 1 byte)
            // and IP would have moved by 1 byte after executing it.
            uint64_t bp_addr = regs.rip - 1;
            if (this->pc_to_first_byte.count(bp_addr) > 0)
            {
                // This stop is due to break point; restore the byte
                uint8_t b1 = this->pc_to_first_byte[bp_addr];
                uint64_t instr = ptrace(PTRACE_PEEKTEXT, pid, bp_addr, NULL);
                uint64_t restored_instr = ((instr & 0xffffffffffffff00) | b1);
                ptrace(PTRACE_POKETEXT, pid, bp_addr, restored_instr);
                logger->debug("Added {:#x} at {:#x}", restored_instr, bp_addr);

                regs.rip = bp_addr;
                ptrace(PTRACE_SETREGS, pid, NULL, &regs);

                // remove the instruction from the map
                this->pc_to_first_byte.erase(bp_addr);
            }

            // continue the process
            ptrace(PTRACE_CONT, pid, NULL, NULL);
            return TRACEE_RUNNING;
        }
        else if ("b" == input_tokens[0])
        {
            char *endptr;
            uint64_t bp_addr = strtoul(input_tokens[1].c_str(), &endptr, 16);
            logger->debug("setting breakpoint at addre {:#x}", bp_addr);

            // obtain the instruction
            // TODO: add error handling to PEEK* calls
            uint64_t instr = ptrace(PTRACE_PEEKTEXT, pid, bp_addr, NULL);
            logger->debug("found instruction: {:#x} at address: {:#x}", instr, bp_addr);

            // save its first byte because we're going to change it to generate a trap instruction
            uint8_t b1_instr = (uint8_t)(instr & 0xff);
            logger->debug("First byte of instr {:#x}", b1_instr);
            this->pc_to_first_byte[bp_addr] = b1_instr;

            // change first byte of instruction to 'int 3' (x86) to trigger a trap
            uint64_t instr_with_trap = (instr & 0xffffffffffffff00);
            instr_with_trap = instr_with_trap | 0xcc;
            logger->debug("changing instruciton at addr {:#x} to {:#x}", bp_addr, instr_with_trap);
            ptrace(PTRACE_POKETEXT, pid, bp_addr, instr_with_trap);

            // peeking the data again see if instr has correctly been modified
            // TODO: add error handling to PEEK* calls
            uint64_t debug_instr = ptrace(PTRACE_PEEKTEXT, pid, bp_addr, NULL);
            logger->debug("new instruction with trap: {:#x} at address: {:#x}", debug_instr, bp_addr);
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
};

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
            // BUG: Resource leak could be happening because I'm not closing the filestreams of the parent process
            // don't want to close stdin, stdout, stderr streams but want to close the streams
            // opened by logger. How to do that?
            int r = execl(argv[1], argv[2], (char *)NULL);
            logger->error("Exec failed for {} {}", argv[2], strerror(errno));
            return 1;
        }
        else
        {
            init_logger("/tmp/hzdbg.log");
            Debugger d;
            d.signal_receive_user_input_loop(fork_result, argv[2]);
        }
    }
    else
    {
        printf("Don't have anything to trace. Please provide a tracee: ./hzdbg <traceepath> <traceename>\n");
        logger->info("No tracee file provided, exiting!");
    }

    return 0;
}