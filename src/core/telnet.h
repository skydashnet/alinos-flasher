#ifndef TELNET_H
#define TELNET_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #include <winsock2.h>
#else
  typedef int SOCKET;
#endif

typedef void (*telnet_log_cb)(const char *message, void *user_data);
void telnet_set_logger(telnet_log_cb cb, void *user_data);

typedef struct {
    SOCKET sock;
    char ip[64];
    int port;
    bool is_connected;
    char last_rx[4096];
    size_t last_rx_len;
} telnet_session_t;

typedef struct {
    const char *ssid_2g;
    const char *ssid_5g;
    const char *wifi_password;
    const char *tr069_url;
    const char *tr069_user;
    const char *tr069_pass;
    int pon_mode;           /* 4 = XPON Auto, 1 = GPON, 2 = EPON, 3 = LAN-WAN */
    const char *upport_id;  /* "0x102001" or "0x00000001" */
} alinos_config_t;

/* Telnet connection lifecycle */
int telnet_init_session(telnet_session_t *sess, const char *ip, int port);
int telnet_connect(telnet_session_t *sess, int timeout_sec);
void telnet_disconnect(telnet_session_t *sess);

/* Send and receive primitives */
int telnet_send_raw(telnet_session_t *sess, const char *buf, size_t len);
int telnet_send_cmd(telnet_session_t *sess, const char *cmd);
int telnet_expect(telnet_session_t *sess, const char *pattern, int timeout_sec);

/* Automated login and shell escalation */
int telnet_login_huawei(telnet_session_t *sess, const char *user, const char *pass, int timeout_sec);
int telnet_enter_shell(telnet_session_t *sess, int timeout_sec);

/* Step 2 Execution: EquipMode ON + restorehwmode + reboot */
int telnet_run_step2_equipmode(const char *ip, const char *user, const char *pass);

/* Step 4 Execution: Set permanent upport mode */
int telnet_run_step4_set_mode(const char *ip, const char *user, const char *pass, int mode, const char *upportid);

/* Step 5 / Permanent Config Injection: Locks SSID, WiFi Pass, TR-069, China Mode & Boardinfo */
int telnet_inject_permanent_alinos(const char *ip, const char *user, const char *pass, const alinos_config_t *cfg);

#endif /* TELNET_H */
