#ifndef PAM_EVENT_H
#define PAM_EVENT_H

#include <arpa/inet.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    PS_EVENT_SESSION_OPEN,
    PS_EVENT_SESSION_CLOSE,
    PS_EVENT_LOGIN_SUCCESS,
    PS_EVENT_LOGIN_FAILED,
    PS_EVENT_UNKNOWN
} ps_event_type_t;

typedef enum {
    PS_AUTH_PASSWORD,
    PS_AUTH_PUBLICKEY,
    PS_AUTH_UNKNOWN
} ps_auth_method_t;

typedef enum {
    PS_SERVICE_SSHD,
    PS_SERVICE_SUDO,
    PS_SERVICE_SU,
    PS_SERVICE_LOGIN,
    PS_SERVICE_OTHER
} ps_service_t;

typedef struct {
    ps_event_type_t  type;
    ps_auth_method_t auth_method;
    ps_service_t     service;
    char             username[64];
    char             source_ip[INET6_ADDRSTRLEN];
    int              port;
    pid_t            pid;
    uid_t            uid;
    char             hostname[256];
    uint64_t         timestamp_usec;
} ps_pam_event_t;

#endif /* PAM_EVENT_H */
