/*
******************************************************************************
File:     syscalls.c
Info:     Generated by Atollic TrueSTUDIO(R) 8.0.0   2017-10-17

The MIT License (MIT)
Copyright (c) 2009-2017 Atollic AB

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

******************************************************************************
*/

/* Includes */
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include "stm32l4xx_hal.h"
#include "StmUtil.h"

extern RTC_HandleTypeDef hrtc;
extern UART_HandleTypeDef huart2;

/* Variables */
#undef errno
extern int32_t errno;

uint8_t *__env[1] = { 0 };
uint8_t **environ = __env;

/* Functions */
void initialise_monitor_handles()
{
}

int _getpid(void)
{
	errno = ENOSYS;
	return -1;
}

int _gettimeofday(struct timeval  *ptimeval, void *ptimezone)
{
    if(ptimezone)
    {
        struct timezone* tz = ptimezone;
        tz->tz_minuteswest = _timezone / 60;
        tz->tz_dsttime = _daylight;
    }

    if(ptimeval)
    {
        RTC_TimeTypeDef time = {0};
        RTC_DateTypeDef date = {0};

        if((HAL_RTC_GetTime(&hrtc, &time, RTC_FORMAT_BIN) != HAL_OK) ||
           (HAL_RTC_GetDate(&hrtc, &date, RTC_FORMAT_BIN) != HAL_OK))
        {
            errno = ENOSYS;
            return -1;
        }

        struct tm local = {0};
        local.tm_year = date.Year + 100;
        local.tm_mon = date.Month - 1;
        local.tm_mday = date.Date;
        local.tm_wday = date.WeekDay - 1;
        local.tm_hour = time.Hours;
        local.tm_min = time.Minutes;
        local.tm_sec = time.Seconds;
        ptimeval->tv_sec = mktime(&local);
        ptimeval->tv_usec = (time.SecondFraction * 1000 * 1000 / time.SubSeconds);
    }

  return 0;
}

int _kill(int32_t pid, int32_t sig)
{
	errno = ENOSYS;
	return -1;
}

void _exit(int32_t status)
{
	while (1) {}		/* Make sure we hang here */
}

int _write(int32_t file, uint8_t *ptr, int32_t len)
{
#ifndef NDEBUG
    if ((g_itm[0] != 0) && (file == 2)) //STDERR with SWV
    {
        for(uint32_t n = 0; n < len; n++)
        {
            ITM_SendChar(ptr[n]);
        }
        return len;
    }
    else if ((file == 1) || ((g_itm[0] == 0) && (file == 2))) //STDOUT or STDERR without SWV
    {
        HAL_UART_Transmit(&huart2, ptr, len, HAL_MAX_DELAY);
        return len;
    }
    else if ((file >= ITMFILENO) && (file < ITMFILENO + ITMCHANNELNO))
    {
        for(uint32_t n = 0; n < len; n++)
        {
            ITM_Out(file - ITMFILENO, ptr[n]);
        }
        return len;
    }
#endif
    errno = ENOSYS;
    return -1;
}

void * _sbrk(int32_t incr)
{
	extern char   end; /* Set by linker.  */
	static char * heap_end;
	char *        prev_heap_end;

	if (heap_end == 0) {
		heap_end = & end;
	}

	prev_heap_end = heap_end;
	heap_end += incr;

	return (void *) prev_heap_end;
}

int _close(int32_t file)
{
    if ((file >= ITMFILENO) && (file < ITMFILENO + ITMCHANNELNO))
    {
        return 0;
    }
	errno = ENOSYS;
	return -1;
}


int _fstat(int32_t file, struct stat *st)
{
    if ((file >= ITMFILENO) && (file < ITMFILENO + ITMCHANNELNO))
    {
        st->st_mode = S_IFCHR;
        st->st_size = 0;
        return 0;
    }
	errno = ENOSYS;
	return -1;
}

int _isatty(int32_t file)
{
    if ((file >= ITMFILENO) && (file < ITMFILENO + ITMCHANNELNO))
    {
        return 1;
    }
	errno = ENOSYS;
	return 0;
}

int _lseek(int32_t file, int32_t ptr, int32_t dir)
{
    if ((file >= ITMFILENO) && (file < ITMFILENO + ITMCHANNELNO))
    {
        return 0;
    }
	errno = ENOSYS;
	return -1;
}

int _read(int32_t file, uint8_t *ptr, int32_t len)
{
    errno = ENOSYS;
    return -1;
}

int _readlink(const char *path, char *buf, size_t bufsize)
{
  errno = ENOSYS;
  return -1;
}

int _open(const uint8_t *path, int32_t flags, int32_t mode)
{
    unsigned int channel = 0;
    if((strlen((char*)path) == 7 ) &&
       !strncmp((char*)path, "ITM[", 4) &&
       !strcmp((char*)&path[6], "]") &&
       (sscanf((char*)&path[4],"%02u", &channel) == 1) &&
       (channel < ITMCHANNELNO) &&
       ((flags == 0x601) || (flags == 0x10601)))
    {
        return ITMFILENO + channel;
    }
	errno = ENOSYS;
	return -1;
}

int _wait(int32_t *status)
{
	errno = ENOSYS;
	return -1;
}

int _unlink(const uint8_t *name)
{
	errno = ENOSYS;
	return -1;
}

int _times(struct tms *buf)
{
    RTC_TimeTypeDef time = {0};
    RTC_DateTypeDef date = {0};

    if((HAL_RTC_GetTime(&hrtc, &time, RTC_FORMAT_BIN) != HAL_OK) ||
       (HAL_RTC_GetDate(&hrtc, &date, RTC_FORMAT_BIN) != HAL_OK))
    {
        errno = ENOSYS;
        return -1;
    }

    struct tm local = {0};
    local.tm_year = date.Year + 100;
    local.tm_mon = date.Month - 1;
    local.tm_mday = date.Date;
    local.tm_wday = date.WeekDay - 1;
    local.tm_hour = time.Hours;
    local.tm_min = time.Minutes;
    local.tm_sec = time.Seconds;

    buf->tms_utime = mktime(&local);        /* user time */
    buf->tms_stime = 0;                     /* system time */
    buf->tms_cutime = 0;                    /* user time, children */
    buf->tms_cstime = 0;                    /* system time, children */
    return 0;
}

int _stat(const uint8_t *file, struct stat *st)
{
	errno = ENOSYS;
	return -1;
}

int _symlink(const char *path1, const char *path2)
{
  errno = ENOSYS;
  return -1;
}

int _link(const uint8_t *old, const uint8_t *new)
{
	errno = ENOSYS;
	return -1;
}

int _fork(void)
{
	errno = ENOSYS;
	return -1;
}

int _execve(const uint8_t *name, uint8_t * const *argv, uint8_t * const *env)
{
	errno = ENOSYS;
	return -1;
}

