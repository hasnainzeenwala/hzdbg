#include <iostream>
#include "shared.h"
std::shared_ptr<spdlog::logger> logger;
void init_logger(const char *logfile)
{
    std::remove(logfile);
    try
    {
        logger = spdlog::basic_logger_mt("logger", logfile);
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        std::cout << "Log init failed: " << ex.what() << std::endl;
    }
    const char *log_level = std::getenv("HZDBG_LOG_LEVEL");
    if (log_level == NULL)
    {
        logger->set_level(spdlog::level::info);
        logger->info("Setting default log level: INFO");
    }
    else if (std::strcmp(log_level, "DEBUG") == 0)
    {
        logger->set_level(spdlog::level::debug);
    }
    else if (std::strcmp(log_level, "INFO") == 0)
    {
        logger->set_level(spdlog::level::info);
    }
    else if (std::strcmp(log_level, "ERROR") == 0)
    {
        logger->set_level(spdlog::level::err);
    }
    else if (std::strcmp(log_level, "WARN") == 0)
    {
        logger->set_level(spdlog::level::warn);
    }
    else
    {
        logger->set_level(spdlog::level::info);
        logger->info("Setting default log level: INFO");
    }
}