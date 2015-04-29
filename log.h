#ifndef __LOG_H__
#define __LOG_H__

#define LOG_LEVEL_DEBUG     0
#define LOG_LEVEL_INFO      1
#define LOG_LEVEL_WARNING   2
#define LOG_LEVEL_ERROR     3

#define LOG_LEVEL_DEFAULT   LOG_LEVEL_INFO

#define DEBUG(fmt, ...)     log_msg(LOG_LEVEL_DEBUG, \
    __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define INFO(fmt, ...)      log_msg(LOG_LEVEL_INFO, \
    __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define WARNING(fmt, ...)   log_msg(LOG_LEVEL_WARNING, \
    __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...)     log_msg(LOG_LEVEL_ERROR, \
    __FILE__, __LINE__, fmt, ##__VA_ARGS__)

int  log_init(const char *fname, int enable_stdout);
void log_set_level(int level);
void log_msg(int level, const char *fname, int line, const char *msg, ...);
void log_close();

#endif // __LOG_H__
