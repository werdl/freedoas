/*
 * freedoas - a cross-platform clone of OpenBSD's doas authorization tool
 * freedoas is licensed under the MIT license.
 *
 * freedoas should run on any system that has a struct passwd with a pw_password
 * field, although there is special logic for Linux which uses /etc/shadow. if
 * you are unsure if freedoas will run, below is a list of systems that support
 * the requirements:
 * - OpenBSD (tested most exhaustively)
 * - FreeBSD
 * - NetBSD
 * - DragonFly BSD
 * - macOS
 * - linux (tested on arch and debian, but should work on any linux distro that
 * has libc and /etc/shadow support)
 *
 * freedoas will probably work on other propietary Unices, but I haven't tested
 * it
 *
 * written by werdl (github.com/werdl) :)
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

enum Action {
    ACTION_PERMIT,
    ACTION_DENY,
};

typedef struct {
    char *name;
    char *value;
} EnvVar;

typedef struct {
    bool nopass;  // No password required
    bool nolog;   // Do not log to syslog
    bool persist; // create a 5-minute lock file during which no password is
                  // required
    bool keepenv;
    EnvVar *env; // Environment variables to set
} Options;

typedef struct {
    union {
        char *user;
        uid_t uid;

        char *group;
        gid_t gid;
    } identity;      // User or group identity
    bool is_user;    // true if user, false if group
    bool is_numeric; // true if uid/gid is numeric, false if it's a name
} Identity;

typedef struct {
    enum Action action; // Action to take (permit or deny)
    Options options;    // Options for the rule
    Identity identity;  // User or group identity for the rule
    Identity target;    // Target user or group identity
    char **argv;        // Command to execute
    int argc; // Number of arguments in argv (dynamically detemined by parser)
} Rule;

void log_msg(int level, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsyslog(level, fmt, args);
    va_end(args);
}

void do_die(int line, const char *file, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "%s:%d: ", file, line);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(EXIT_FAILURE);
}

#define die(...) do_die(__LINE__, __FILE__, __VA_ARGS__)

enum ParseError { PARSE_OK, PARSE_TOO_MANY_RULES, PARSE_BAD_PERMS_ON_CONFIG };

bool check_perms(const char *file) {
    struct stat st;
    if (stat(file, &st) < 0)
        return false;
    if (st.st_uid != 0)
        return false;
    
    // file must be writable only by root, and owned by root
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) // no group or other write permissions
        return false;
    if ((st.st_mode & S_IRUSR) == 0) // must be readable by user (root)
        return false;
    return true;
}

// parse in config from a file. if file is NULL, the default config file
// (/etc/doas.conf) is used.
int parse(char *file, Rule **rules, int *rule_count) {
    if (file == NULL) {
        file = "/etc/doas.conf";
    }

    if (!check_perms(file)) {
        log_msg(LOG_ERR, "bad permissions on %s", file);
        return PARSE_BAD_PERMS_ON_CONFIG;
    }

    int fd = open(file, O_RDONLY);

    // map file to a buffer
    int len = lseek(fd, 0, SEEK_END);
    char *data = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);

    printf("data: %s\n", data);

    int i = 0;
    int rule_num = 0;

    char *line = malloc(len + 1);

    if (!line) {
        close(fd);
        die("malloc");
    }
    
    int rule_size = 10;
    *rules = malloc(sizeof(Rule) * rule_size);
    if (!*rules) {
        free(line);
        close(fd);
        die("malloc");
    }

    while (i < len) {
        // empty buffer
        for (int j = 0; line[j]; j++) {
            line[j] = '\0';
        }

        // read a line from the buffer
        int j = 0;
        while (i < len && data[i] != '\n' && data[i] != '\r') {
            if (j >= len) {
                fprintf(stderr, "Line too long in %s\n", file);
                free(line);
                close(fd);
                return PARSE_TOO_MANY_RULES;
            }
            line[j++] = data[i++];
        }

        printf("line: %s\n", line);

    }



    return PARSE_OK;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    setuid(0); // Run as root to read protected files

    openlog("freedoas", LOG_PID | LOG_CONS, LOG_AUTH);

    // log invocation at LOG_DEBUG
    char *log_buf = malloc(sizeof(char) * (strlen(argv[1]) + 25));
    if (!log_buf)
        die("malloc");

    snprintf(log_buf, 1024, "freedoas invoked: %s", argv[1]);

    int used_bytes = strlen(log_buf);
    int size = 1024; // Initial size for log_buf

    for (int i = 2; i < argc; i++) {
        if (used_bytes + strlen(argv[i]) + 1 >= (unsigned long)size) {
            size *= 2;
            log_buf = realloc(log_buf, size);
            if (!log_buf)
                die("realloc");
        }

        log_buf[used_bytes++] = ' ';
        strcpy(log_buf + used_bytes, argv[i]);
        used_bytes += strlen(argv[i]);
    }

    log_msg(LOG_DEBUG, "%s", log_buf);
    free(log_buf);

    Rule *rules = NULL;

    int rule_count = 0;
    int parse_result = parse(NULL, &rules, &rule_count);
}
