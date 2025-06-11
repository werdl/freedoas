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

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#ifndef __OpenBSD__
#include <crypt.h>
#endif

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
        uid_t uid;
        gid_t gid;
    } id; // User or group ID
    union {
        char *user;  // User name
        char *group; // Group name
    } name;          // User or group name
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

bool check_perms(const char *file) {
    struct stat st;
    if (stat(file, &st) < 0)
        return false;
    if (st.st_uid != 0)
        return false;

    // file must be writable only by root, and owned by root
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) !=
        0) // no group or other write permissions
        return false;
    if ((st.st_mode & S_IRUSR) == 0) // must be readable by user (root)
        return false;
    return true;
}

bool is_num(const char *str) {
    while (*str) {
        if (*str < '0' || *str > '9') {
            return false;
        }
        str++;
    }
    return true;
}

void print_rule(const Rule *rule) {
    printf("Action: %s\n", rule->action == ACTION_PERMIT ? "permit" : "deny");
    printf("Options: nopass=%d, nolog=%d, persist=%d, keepenv=%d\n",
           rule->options.nopass, rule->options.nolog, rule->options.persist,
           rule->options.keepenv);
    if (rule->identity.is_user) {
        if (rule->identity.is_numeric) {
            printf("Identity: uid=%d\n", rule->identity.id.uid);
        } else {
            printf("Identity: user=%s\n", rule->identity.name.user);
        }
    } else {
        if (rule->identity.is_numeric) {
            printf("Identity: gid=%d\n", rule->identity.id.gid);
        } else {
            printf("Identity: group=%s\n", rule->identity.name.group);
        }
    }
    if (rule->target.is_user) {
        if (rule->target.is_numeric) {
            printf("Target: uid=%d\n", rule->target.id.uid);
        } else {
            printf("Target: user=%s\n", rule->target.name.user);
        }
    } else {
        if (rule->target.is_numeric) {
            printf("Target: gid=%d\n", rule->target.id.gid);
        } else {
            printf("Target: group=%s\n", rule->target.name.group);
        }
    }
    if (rule->argv) {
        printf("Command: ");
        for (int i = 0; i < rule->argc; i++) {
            printf("%s ", rule->argv[i]);
        }
        printf("\n");
    } else {
        printf("Command: none\n");
    }
}

int our_strtonum(const char *str, int min, int max, const char **errstr) {
    char *endptr;
    long val = strtol(str, &endptr, 10);

    if (endptr == str || *endptr != '\0') {
        *errstr = "not a number";
        return -1;
    }

    if (val < min || val > max) {
        *errstr = "out of range";
        return -1;
    }

    *errstr = NULL; // No error
    return (int)val;
}

// parse in config from a file. if file is NULL, the default config file
// (/etc/doas.conf) is used.
void parse(char *file, Rule **rules, int *rule_num) {
    if (file == NULL) {
        file = "doas.conf";
    }

    if (!check_perms(file)) {
        log_msg(LOG_ERR, "bad permissions on %s", file);
        die("bad permissions on %s", file);
    }

    int fd = open(file, O_RDONLY);

    // map file to a buffer
    int len = lseek(fd, 0, SEEK_END);
    char *data = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);

    printf("Parsing %s", data);

    int i = 0;

    int rule_size = 10;
    *rules = malloc(sizeof(Rule) * rule_size);
    if (!*rules) {
        close(fd);
        die("malloc");
    }

    while (i < len) {
        char *line = malloc(len + 1);
        if (!line)
            die("malloc");

        char *last = NULL;

        int j = 0;
        while (i < len && data[i] != '\n' && data[i] != '\r') {
            if (j >= len) {
                free(line);
                close(fd);
                die("Line too long");
            }
            line[j++] = data[i++];
        }
        line[j] = '\0';
        i += (data[i] == '\n' || data[i] == '\r') ? 1 : 0;

        char *permit_or_deny = strtok_r(line, " ", &last);

        if (!permit_or_deny) {
            continue; // empty line
        }

        if (!strcmp(permit_or_deny, "permit")) {
            (*rules)[*rule_num].action = ACTION_PERMIT;
        } else if (!strcmp(permit_or_deny, "deny")) {
            (*rules)[*rule_num].action = ACTION_DENY;
        } else {
            fprintf(stderr, "Invalid action '%s' in %s\n", permit_or_deny,
                    file);
            free(line);
            close(fd);
            die("Invalid action '%s' in %s", permit_or_deny, file);
        }

        (*rules)[*rule_num].options.nopass = false;
        (*rules)[*rule_num].options.nolog = false;
        (*rules)[*rule_num].options.persist = false;
        (*rules)[*rule_num].options.keepenv = false;
        (*rules)[*rule_num].options.env = NULL;

        // parse options
        char *option = strtok_r(NULL, " ", &last);
        while (option) {
            if (!strcmp(option, "nopass")) {
                (*rules)[*rule_num].options.nopass = true;
            } else if (!strcmp(option, "nolog")) {
                (*rules)[*rule_num].options.nolog = true;
            } else if (!strcmp(option, "persist")) {
                (*rules)[*rule_num].options.persist = true;
            } else if (!strcmp(option, "keepenv")) {
                (*rules)[*rule_num].options.keepenv = true;
            } else {
                break; // move to identity parsing
            }
            option = strtok_r(NULL, " ", &last);
        }

        if (!option) {
            fprintf(stderr, "No identity specified in %s\n", file);
            free(line);
            close(fd);
            die("No identity specified in %s", file);
        }

        // parse identity
        char *identity = strdup(option);

        if (!identity) {
            fprintf(stderr, "No identity specified in %s\n", file);
            free(line);
            close(fd);
            die("No identity specified in %s", file);
        }

        if (identity[0] == ':') {
            // group identity
            if (is_num(identity + 1)) {
                (*rules)[*rule_num].identity.is_numeric = true;
                char *errstr = malloc(256);
                (*rules)[*rule_num].identity.id.gid = our_strtonum(
                    identity + 1, 0, 65535, (const char **)&errstr);
                if (errstr) {
                    fprintf(stderr, "Invalid group ID %s in %s\n", identity,
                            file);
                    free(line);
                    close(fd);
                    die("Invalid group ID %s in %s", identity, file);
                }
            } else {
                (*rules)[*rule_num].identity.is_numeric = false;
                (*rules)[*rule_num].identity.name.group = strdup(identity + 1);
            }
            (*rules)[*rule_num].identity.is_user = false;
        } else {
            // user identity
            if (is_num(identity)) {
                (*rules)[*rule_num].identity.is_numeric = true;
                char *errstr = malloc(256);
                (*rules)[*rule_num].identity.id.uid =
                    our_strtonum(identity, 0, 65535, (const char **)&errstr);
                if (errstr) {
                    fprintf(stderr, "Invalid user ID %s in %s: %s\n", identity, errstr,
                            file);
                    free(line);
                    close(fd);
                    die("Invalid user ID %s in %s", identity, file);
                }
            } else {
                (*rules)[*rule_num].identity.is_numeric = false;
                (*rules)[*rule_num].identity.name.user = strdup(identity);
            }
            (*rules)[*rule_num].identity.is_user = true;
        }

        char *tok = strtok_r(NULL, " ", &last);
        char *as = tok ? strdup(tok) : NULL;

        if (!as || !strcmp(as, "cmd")) { // if as user is skipped, the next part
                                         // of the syntax is the command
            (*rules)[*rule_num].target.is_user = true;
            (*rules)[*rule_num].target.is_numeric = true; // default to numeric
            (*rules)[*rule_num].target.id.uid = 0;        // default to root
        } else if (!strcmp(as, "as")) {
            // target identity specified
            fprintf(stderr, "Expected as keyword, not %s in %s\n", as, file);
            free(line);
            close(fd);
            die("Expected as keyword, not %s in %s", as, file);
        } else {
            char *target_identity = strtok(NULL, " ");
            if (!target_identity) {
                fprintf(stderr, "No target identity specified in %s\n", file);
                free(line);
                close(fd);
                die("No target identity specified in %s", file);
            }

            if (!target_identity) {
                fprintf(stderr, "No target identity specified in %s\n", file);
                free(line);
                close(fd);
                die("No target identity specified in %s", file);
            }

            if (target_identity[0] == ':') {
                // group target identity
                if (is_num(target_identity + 1)) {
                    (*rules)[*rule_num].target.is_numeric = true;
                    (*rules)[*rule_num].target.id.gid =
                        atoi(target_identity + 1);
                } else {
                    (*rules)[*rule_num].target.is_numeric = false;
                    (*rules)[*rule_num].target.name.group =
                        strdup(target_identity + 1);
                }
                (*rules)[*rule_num].target.is_user = false;
            } else {
                // user target identity
                if (is_num(target_identity)) {
                    (*rules)[*rule_num].target.is_numeric = true;
                    (*rules)[*rule_num].target.id.uid = atoi(target_identity);
                } else {
                    (*rules)[*rule_num].target.is_numeric = false;
                    (*rules)[*rule_num].target.name.user =
                        strdup(target_identity);
                }
                (*rules)[*rule_num].target.is_user = true;
            }
        }

        // parse command
        char *cmd = strtok_r(NULL, " ", &last);
        if (!cmd) {
            (*rules)[*rule_num].argv = NULL; // no command specified
            (*rules)[*rule_num].argc = 0;
        } else {

            // allocate memory for argv
            (*rules)[*rule_num].argv = malloc(sizeof(char *) * 10);
            if (!(*rules)[*rule_num].argv) {
                free(line);
                close(fd);
                die("malloc");
            }

            (*rules)[*rule_num].argc = 0;
            while (cmd) {
                if ((*rules)[*rule_num].argc >= 10) {
                    // realloc if needed
                    (*rules)[*rule_num].argv = realloc(
                        (*rules)[*rule_num].argv,
                        sizeof(char *) * ((*rules)[*rule_num].argc + 10));
                    if (!(*rules)[*rule_num].argv) {
                        free(line);
                        close(fd);
                        die("realloc");
                    }
                }
                (*rules)[*rule_num].argv[(*rules)[*rule_num].argc++] =
                    strdup(cmd);
                cmd = strtok_r(NULL, " ", &last);
            }
        }

        (*rule_num)++;

        if (*rule_num >= rule_size) {
            rule_size *= 2;
            *rules = realloc(*rules, sizeof(Rule) * rule_size);
            if (!*rules) {
                free(line);
                close(fd);
                die("realloc");
            }
        }
    }

    // clean up
    munmap(data, len);
    close(fd);
}

gid_t *get_all_gids(void) {
    int gidsetlen = getgroups(0, NULL);
    if (gidsetlen < 0) {
        die("getgroups failed");
    }

    gid_t *gids = malloc(sizeof(gid_t) * gidsetlen);
    if (!gids) {
        die("malloc");
    }

    if (getgroups(gidsetlen, gids) < 0) {
        free(gids);
        die("getgroups failed");
    }
    return gids;
}

gid_t resolve_gid(const char *name) {
    if (is_num(name)) {
        return (gid_t)atoi(name);
    }

    struct group *grp = getgrnam(name);
    if (!grp) {
        log_msg(LOG_ERR, "Group %s not found", name);
        die("Group %s not found", name);
    }
    return grp->gr_gid;
}

uid_t resolve_uid(const char *name) {
    if (is_num(name)) {
        return (uid_t)atoi(name);
    }

    struct passwd *pwd = getpwnam(name);
    if (!pwd) {
        log_msg(LOG_ERR, "User %s not found", name);
        die("User %s not found", name);
    }
    return pwd->pw_uid;
}

bool password_check() {
    // confirm that the user knows their own password
    char *hostname = malloc(256);
    if (!hostname) {
        die("malloc");
    }

    if (gethostname(hostname, 256) < 0) {
        die("gethostname failed");
    }

    char *username = getlogin();

    if (!username) {
        die("getlogin failed");
    }

    char *buf = malloc(strlen(hostname) + strlen(username) + 50);

    snprintf(buf, strlen(hostname) + strlen(username) + 50,
             "doas (%s@%s) password: ", username, hostname);

    // prompt for password
    char *password = getpass(buf);
    free(buf);

    if (!password) {
        log_msg(LOG_ERR, "getpass failed");
        die("getpass failed");
    }

    // check if the password is correct
#ifdef __linux__
    // on linux, we use /etc/shadow to check the password
    struct spwd *sp = getspnam(getlogin());
    if (!sp) {
        log_msg(LOG_ERR, "User %s not found in /etc/shadow", getlogin());
        die("User %s not found in /etc/shadow", getlogin());
    }

    if (strcmp(sp->sp_pwdp, crypt(password, sp->sp_pwdp)) != 0) {
        log_msg(LOG_ERR, "Password check failed for user %s", getlogin());
        return false;
    }
#else
    // on other systems, we use the passwd file
    struct passwd *pwd = getpwnam_shadow(getlogin());
    if (!pwd) {
        log_msg(LOG_ERR, "User %s not found in /etc/passwd", getlogin());
        die("User %s not found in /etc/passwd", getlogin());
    }

    if (strcmp(pwd->pw_passwd, crypt(password, pwd->pw_passwd)) != 0) {
        log_msg(LOG_ERR, "Password check failed for user %s", getlogin());
        return false;
    }
#endif

    log_msg(LOG_DEBUG, "Password check succeeded for user %s", getlogin());
    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    seteuid(0); // Run as root to read protected files

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
    parse(NULL, &rules, &rule_count);

    // first, find a rule relevant to the user
    Rule **matched_rules = malloc(sizeof(Rule *) * rule_count);
    if (!matched_rules) {
        die("malloc");
    }

    uid_t current_uid = getuid();
    gid_t *gids = get_all_gids();

    char *login_name = getlogin();

    int matched_count = 0;
    for (int i = 0; i < rule_count; i++) {
        Rule *rule = &rules[i];

        // Check if the rule matches the user
        if (rule->identity.is_user) {
            if (rule->identity.is_numeric) {
                if (rule->identity.id.uid == current_uid) {
                    matched_rules[matched_count++] = rule;
                }
            } else {
                if (!strcmp(rule->identity.name.user, login_name)) {
                    matched_rules[matched_count++] = rule;
                }
            }
        } else {
            gid_t rule_gid;

            if (rule->identity.is_numeric) {
                rule_gid = rule->identity.id.gid;
            } else {
                rule_gid = resolve_gid(rule->identity.name.group);
            }

            for (int j = 0; j < getgroups(0, NULL); j++) {
                if (gids[j] == rule_gid) {
                    matched_rules[matched_count++] = rule;
                    break; // No need to check other gids
                }
            }
        }
    }
    free(gids);

    // now, check if any of the matched rules allow the command
    Rule *selected_rule = NULL;

    for (int i = 0; i < matched_count; i++) {
        Rule *rule = matched_rules[i];

        // Check if the rule matches the command
        if (rule->argc == 0 ||
            (rule->argv && strcmp(rule->argv[0], argv[1]) == 0)) {
            selected_rule = rule;
            continue; // last matching rule
        }

        if (rule->argc >= argc) {
            bool match = true;
            for (int j = 0; j < rule->argc && j < argc; j++) {
                if (!rule->argv[j]) {
                    match = false;
                    break; // no command specified in rule
                }

                if (!argv[j]) {
                    // might still match if rule has more args than argv
                    break;
                }

                if (strcmp(rule->argv[j], argv[j])) {
                    match = false;
                    break;
                }
            }
            if (match) {
                selected_rule = rule;
                continue; // last matching rule
            }
        }
    }

    free(matched_rules);

    print_rule(selected_rule);

    if (!selected_rule) {
        log_msg(LOG_ERR, "No matching rule found for command %s", argv[1]);
        die("No matching rule found for command %s", argv[1]);
    }

    if (selected_rule->action == ACTION_DENY) {
        log_msg(LOG_ERR, "Command %s denied by rule", argv[1]);
        die("Command %s denied by rule", argv[1]);
    }

    if (!selected_rule->options.nopass && !password_check()) {
        log_msg(LOG_ERR, "Password check failed for command %s", argv[1]);
        die("Password check failed for command %s", argv[1]);
    }

    char **argv_new = malloc(sizeof(char *) * (argc - 1));
    if (!argv_new) {
        die("malloc");
    }

    char *argv1 = strdup(argv[1]);
    if (!argv1) {
        die("strdup");
    }
    argv_new[0] = argv1;

    for (int i = 2; i < argc; i++) {
        argv_new[i - 1] = strdup(argv[i]);
        if (!argv_new[i - 1]) {
            die("strdup");
        }
    }
    argv_new[argc - 1] = NULL;

    // elevate privileges to the target user
    if (selected_rule->target.is_user) {
        if (selected_rule->target.is_numeric) {
            if (setuid(selected_rule->target.id.uid) < 0) {
                log_msg(LOG_ERR, "setuid failed: %s", strerror(errno));
                die("setuid failed: %s", strerror(errno));
            }
        } else {
            uid_t target_uid = resolve_uid(selected_rule->target.name.user);
            if (setuid(target_uid) < 0) {
                log_msg(LOG_ERR, "setuid failed: %s", strerror(errno));
                die("setuid failed: %s", strerror(errno));
            }
        }
    } else {
        // setgid
        if (selected_rule->target.is_numeric) {
            if (setgid(selected_rule->target.id.gid) < 0) {
                log_msg(LOG_ERR, "setgid failed: %s", strerror(errno));
                die("setgid failed: %s", strerror(errno));
            }
        } else {
            gid_t target_gid = resolve_gid(selected_rule->target.name.group);
            if (setgid(target_gid) < 0) {
                log_msg(LOG_ERR, "setgid failed: %s", strerror(errno));
                die("setgid failed: %s", strerror(errno));
            }
        }
    }

    execvp(argv1, argv_new);
    log_msg(LOG_ERR, "execvp failed: %s", strerror(errno));
    die("execvp failed: %s", strerror(errno));
}
