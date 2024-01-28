#ifndef SHARED
#define SHARED
#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
extern std::shared_ptr<spdlog::logger> logger;
void init_logger(const char *logfile);
#endif