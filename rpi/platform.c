#include "platform.h"

#if defined(ANDROID)
#include <android/log.h>
#elif defined(_WIN32)
#include <windows.h>
#endif

#include <SDL_filesystem.h>
#include <stdio.h>

#include "ui/ui_util.h"

static char pref_path[4096] = {0};

void vpi_config_filename(char *out, size_t out_size)
{
    vpi_get_data_filename(out, out_size, "config.xml");
}

void vpi_get_data_filename(char *out, size_t out_size, const char *filename)
{
    if (!pref_path[0]) {
        char *s = SDL_GetPrefPath("", "Vanilla");
        vui_strncpy(pref_path, s, sizeof(pref_path));
        SDL_free(s);
    }
    snprintf(out, out_size, "%s%s", pref_path, filename);
}

void vpilog_va(const char *fmt, va_list va)
{
#if defined(ANDROID)
    __android_log_vprint(ANDROID_LOG_ERROR, "VPI", fmt, va);
// #elif defined(_WIN32)
//     char buf[4096];
//     vsnprintf(buf, sizeof(buf), fmt, va);
//     MessageBoxA(0, buf, 0, 0);
//#elif defined(__vita__)
    /*static FILE *log_file = NULL;
    if (!log_file) {
        char name[32];
        vpi_get_data_filename(name, sizeof(name), "log.txt");
        log_file = fopen(name, "a");
        if (!log_file) {
            log_file = stderr; // Fallback to stderr if file cannot be opened
        }
        fprintf(log_file, "-------------------------------- VPI log started\n");
    }
    vfprintf(log_file, fmt, va);
    fflush(log_file);*/
#else
    vfprintf(stderr, fmt, va);
#endif
}

void vpilog(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vpilog_va(fmt, va);
    va_end(va);
}

void vpi_asset_filename(char *buf, size_t size, const char *type, const char *filename)
{
#if defined(ANDROID)
    snprintf(buf, size, "%s/%s", type, filename);
#elif defined(_WIN32)
    snprintf(buf, size, "%s/assets/%s/%s", SDL_GetBasePath(), type, filename);
#elif defined(__vita__)
    snprintf(buf, size, "app0:assets/%s/%s", type, filename);
#else
    snprintf(buf, size, "%s/../share/vanilla/assets/%s/%s", SDL_GetBasePath(), type, filename);
#endif
}
