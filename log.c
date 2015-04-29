#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

int log_level, allow_stdout, prompt_flag;
FILE *flog;

const char *level_to_str(int level)
{
    const char *map[] = {"Debug", "Info", "Warning", "Error"};
    if(level < 0 || level >= 4)
        return "Unknown";
    return map[level];
}

void get_current_time(char *buf, int buflen)
{
    time_t t = time(0);
    struct tm *time_metric = localtime(&t);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", time_metric);
}

int log_init(const char *fname, int enable_stdout)
{
    allow_stdout = enable_stdout;
    log_level = LOG_LEVEL_DEFAULT;
    prompt_flag = 0;
    if(NULL == (flog = fopen(fname, "w"))) {
        perror("Failed to open log file: ");
        return -1;
    }
    return 0;
}

void log_set_level(int level)
{
    log_level = level;
}

const char *strip_file_name(const char *fname)
{
    int i;
    for(i = strlen(fname) - 1; i > 0; i--) {
        if(fname[i] == '\\' || fname[i] == '/')
            return fname + i + 1;
    }
    return fname;
}

void log_msg(int level, const char *fname, int line, const char *msg, ...)
{
    if(!flog) {
        if(!prompt_flag) {
            printf("Error: Log has not been initialized yet.\n");
            prompt_flag = 1;
        }
        return ;
    }

    va_list args;
    if(level >= log_level) {
        char tbuf[128];
        get_current_time(tbuf, 128);

        fprintf(flog, "[%s %s:%d] %s: ",
            tbuf, strip_file_name(fname), line, level_to_str(level));
        va_start(args, msg);
        vfprintf(flog, msg, args);
        va_end(args);
        fputs("", flog);

        if(allow_stdout) {
            printf("[%s %s:%d] %s: ",
                tbuf, strip_file_name(fname), line, level_to_str(level));
            va_start(args, msg);
            vprintf(msg, args);
            va_end(args);
            puts("");
        }
    }
}

void log_close()
{
    if(flog)
        fclose(flog);
}
