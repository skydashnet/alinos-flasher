#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "telnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static telnet_log_cb g_log_cb = NULL;
static void *g_log_udata = NULL;

void telnet_set_logger(telnet_log_cb cb, void *user_data) {
    g_log_cb = cb;
    g_log_udata = user_data;
}

static void log_print(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (g_log_cb) {
        g_log_cb(buf, g_log_udata);
    } else {
        printf("%s", buf);
        fflush(stdout);
    }
}

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #define SLEEP_MS(ms) Sleep(ms)
  #define CLOSE_SOCK(s) closesocket(s)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/time.h>
  #define SLEEP_MS(ms) usleep((ms) * 1000)
  #define CLOSE_SOCK(s) close(s)
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR   (-1)
#endif

/* Telnet RFC 854 Protocol Codes */
#define TELNET_IAC   255
#define TELNET_DONT  254
#define TELNET_DO    253
#define TELNET_WONT  252
#define TELNET_WILL  251

int telnet_init_session(telnet_session_t *sess, const char *ip, int port) {
    if (!sess) return -1;
    memset(sess, 0, sizeof(*sess));
    strncpy(sess->ip, ip ? ip : "192.168.100.1", sizeof(sess->ip) - 1);
    sess->port = (port > 0) ? port : 23;
    sess->sock = INVALID_SOCKET;
    sess->is_connected = false;
    return 0;
}

int telnet_connect(telnet_session_t *sess, int timeout_sec) {
    if (!sess) return -1;
    if (sess->is_connected) telnet_disconnect(sess);

    sess->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sess->sock == INVALID_SOCKET) {
        return -1;
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons((uint16_t)sess->port);
    saddr.sin_addr.s_addr = inet_addr(sess->ip);

#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(sess->sock, FIONBIO, &mode);
#else
    int flags = fcntl(sess->sock, F_GETFL, 0);
    fcntl(sess->sock, F_SETFL, flags | O_NONBLOCK);
#endif

    int res = connect(sess->sock, (struct sockaddr *)&saddr, sizeof(saddr));
    if (res < 0) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sess->sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;
        if (select((int)sess->sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
            CLOSE_SOCK(sess->sock);
            sess->sock = INVALID_SOCKET;
            return -2;
        }
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sess->sock, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        if (err != 0) {
            CLOSE_SOCK(sess->sock);
            sess->sock = INVALID_SOCKET;
            return -2;
        }
    }

#ifdef _WIN32
    mode = 0;
    ioctlsocket(sess->sock, FIONBIO, &mode);
#else
    fcntl(sess->sock, F_SETFL, flags);
#endif

    sess->is_connected = true;
    return 0;
}

void telnet_disconnect(telnet_session_t *sess) {
    if (!sess) return;
    if (sess->is_connected && sess->sock != INVALID_SOCKET) {
        CLOSE_SOCK(sess->sock);
        sess->sock = INVALID_SOCKET;
        sess->is_connected = false;
    }
}

int telnet_send_raw(telnet_session_t *sess, const char *buf, size_t len) {
    if (!sess || !sess->is_connected || sess->sock == INVALID_SOCKET) return -1;
    int sent = send(sess->sock, buf, (int)len, 0);
    return (sent >= 0) ? sent : -1;
}

int telnet_send_cmd(telnet_session_t *sess, const char *cmd) {
    if (!sess || !cmd) return -1;
    char buffer[1024];
    int len = snprintf(buffer, sizeof(buffer), "%s\r\n", cmd);
    return telnet_send_raw(sess, buffer, len);
}

/*
 * Reads incoming data, negotiates/strips RFC 854 Telnet commands,
 * and appends printable text to session buffer.
 */
static int telnet_read_filtered(telnet_session_t *sess, int timeout_ms) {
    if (!sess || !sess->is_connected) return -1;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sess->sock, &fds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int res = select((int)sess->sock + 1, &fds, NULL, NULL, &tv);
    if (res <= 0) return res; /* 0 = timeout, <0 = error */

    uint8_t raw[1024];
    int n = recv(sess->sock, (char *)raw, sizeof(raw) - 1, 0);
    if (n <= 0) {
        sess->is_connected = false;
        return -1;
    }

    /* Process Telnet IAC options */
    uint8_t filtered[1024];
    int f_len = 0;
    for (int i = 0; i < n; i++) {
        if (raw[i] == TELNET_IAC) {
            if (i + 1 < n) {
                uint8_t verb = raw[i + 1];
                if (verb == TELNET_DO || verb == TELNET_DONT || verb == TELNET_WILL || verb == TELNET_WONT) {
                    if (i + 2 < n) {
                        uint8_t opt = raw[i + 2];
                        uint8_t reply[3] = { TELNET_IAC, 0, opt };
                        if (verb == TELNET_DO) reply[1] = TELNET_WONT;
                        else if (verb == TELNET_WILL) reply[1] = TELNET_DONT;
                        else reply[1] = TELNET_WONT;
                        send(sess->sock, (const char *)reply, 3, 0);
                        i += 2;
                        continue;
                    }
                }
                i += 1;
                continue;
            }
        } else {
            /* Keep regular text */
            if (raw[i] != '\r') {
                filtered[f_len++] = raw[i];
            }
        }
    }

    filtered[f_len] = '\0';
    if (f_len > 0) {
        /* Append to last_rx buffer */
        if (sess->last_rx_len + f_len < sizeof(sess->last_rx) - 1) {
            memcpy(sess->last_rx + sess->last_rx_len, filtered, f_len);
            sess->last_rx_len += f_len;
            sess->last_rx[sess->last_rx_len] = '\0';
        } else {
            /* Slide buffer */
            memmove(sess->last_rx, sess->last_rx + f_len, sizeof(sess->last_rx) - f_len - 1);
            memcpy(sess->last_rx + sizeof(sess->last_rx) - f_len - 1, filtered, f_len);
            sess->last_rx[sizeof(sess->last_rx) - 1] = '\0';
        }
    }

    return f_len;
}

int telnet_expect(telnet_session_t *sess, const char *pattern, int timeout_sec) {
    if (!sess) return -1;
    int waited_ms = 0;
    int max_ms = timeout_sec * 1000;

    while (waited_ms < max_ms) {
        if (pattern && strstr(sess->last_rx, pattern) != NULL) {
            return 0; /* Found! */
        }
        int read_bytes = telnet_read_filtered(sess, 200);
        if (read_bytes < 0 && !sess->is_connected) {
            return -2; /* Disconnected */
        }
        waited_ms += 200;
        if (pattern && strstr(sess->last_rx, pattern) != NULL) {
            return 0;
        }
    }
    return -1; /* Timeout */
}

static void clear_rx_buffer(telnet_session_t *sess) {
    if (sess) {
        sess->last_rx_len = 0;
        sess->last_rx[0] = '\0';
    }
}

int telnet_login_huawei(telnet_session_t *sess, const char *user, const char *pass, int timeout_sec) {
    if (!sess) return -1;

    clear_rx_buffer(sess);
    log_print("    [•] Menunggu prompt Login ONT...\n");

    /* Wait for Login: or Username: */
    int r = telnet_expect(sess, "Login:", timeout_sec);
    if (r != 0) {
        r = telnet_expect(sess, "username:", timeout_sec);
        if (r != 0) {
            r = telnet_expect(sess, "Username:", timeout_sec);
        }
    }

    if (r != 0) {
        /* Sometimes telnet connects directly to prompt if already logged in */
        if (strstr(sess->last_rx, "WAP>") || strstr(sess->last_rx, "#")) {
            return 0;
        }
        log_print("    \033[1;31m[!] Timeout menunggu prompt login!\033[0m\n");
        return -1;
    }

    /* Send Username */
    const char *login_user = user ? user : "root";
    clear_rx_buffer(sess);
    telnet_send_cmd(sess, login_user);

    /* Wait for Password: */
    r = telnet_expect(sess, "Password:", timeout_sec);
    if (r != 0) {
        r = telnet_expect(sess, "password:", timeout_sec);
    }
    if (r != 0) {
        log_print("    \033[1;31m[!] Timeout menunggu prompt password!\033[0m\n");
        return -2;
    }

    /* Send Password */
    const char *login_pass = pass ? pass : "admin";
    clear_rx_buffer(sess);
    telnet_send_cmd(sess, login_pass);

    /* Wait for CLI Prompt (WAP> or SU_BP> or > or #) */
    SLEEP_MS(500);
    r = telnet_expect(sess, ">", timeout_sec);
    if (r != 0) {
        r = telnet_expect(sess, "#", timeout_sec);
    }

    if (r != 0) {
        /* Check if Login Failed */
        if (strstr(sess->last_rx, "Login incorrect") || strstr(sess->last_rx, "fail")) {
            log_print("    \033[1;31m[!] Login Telnet GAGAL (Kredensial salah: %s / %s)\033[0m\n", login_user, login_pass);
            return -3;
        }
        log_print("    \033[1;33m[?] Warning: Tidak mendeteksi prompt standar, melanjutkan...\033[0m\n");
    } else {
        log_print("    \033[1;32m[✓] Berhasil Login Telnet (%s)\033[0m\n", login_user);
    }

    return 0;
}

int telnet_enter_shell(telnet_session_t *sess, int timeout_sec) {
    if (!sess) return -1;

    clear_rx_buffer(sess);
    telnet_send_cmd(sess, "su");
    SLEEP_MS(500);

    clear_rx_buffer(sess);
    telnet_send_cmd(sess, "shell");
    SLEEP_MS(800);

    int r = telnet_expect(sess, "#", timeout_sec);
    if (r != 0) {
        r = telnet_expect(sess, "$", timeout_sec);
    }

    if (r == 0) {
        log_print("    \033[1;32m[✓] Berhasil masuk ke Linux Root Shell (#)\033[0m\n");
        return 0;
    }

    log_print("    \033[1;33m[!] Catatan: Melanjutkan dalam subshell shell...\033[0m\n");
    return 0;
}

int telnet_run_step2_equipmode(const char *ip, const char *user, const char *pass) {
    telnet_session_t sess;
    telnet_init_session(&sess, ip, 23);

    log_print("\n\033[1;36m[STEP 2: Mengaktifkan Factory EquipMode & Restore HW Mode]\033[0m\n");
    log_print("    Menghubungkan ke %s:23 ...\n", sess.ip);

    if (telnet_connect(&sess, 5) != 0) {
        log_print("    \033[1;31m[!] Gagal menghubungkan ke Telnet ONT (%s:23). Pastikan kabel LAN tercolok!\033[0m\n", sess.ip);
        return -1;
    }

    if (telnet_login_huawei(&sess, user, pass, 5) != 0) {
        telnet_disconnect(&sess);
        return -2;
    }

    telnet_enter_shell(&sess, 5);

    /* Sesi 1: EquipMode on */
    log_print("    [•] Mengirim: EquipMode.sh on ...\n");
    telnet_send_cmd(&sess, "EquipMode.sh on");
    SLEEP_MS(2500);

    log_print("    [•] Keluar dari shell sesi 1...\n");
    telnet_send_cmd(&sess, "exit");
    SLEEP_MS(1000);
    telnet_send_cmd(&sess, "quit");
    SLEEP_MS(1000);
    telnet_send_cmd(&sess, "quit");
    SLEEP_MS(1000);
    telnet_send_cmd(&sess, "a");
    SLEEP_MS(1500);

    telnet_disconnect(&sess);

    /* Sesi 2: restorehwmode */
    log_print("\n    [•] Menghubungkan ulang sesi 2 untuk restorehwmode...\n");
    SLEEP_MS(2000);

    if (telnet_connect(&sess, 5) != 0) {
        log_print("    \033[1;31m[!] Gagal menghubungkan ulang ke Telnet ONT.\033[0m\n");
        return -3;
    }

    if (telnet_login_huawei(&sess, user, pass, 5) != 0) {
        telnet_disconnect(&sess);
        return -4;
    }

    telnet_enter_shell(&sess, 5);

    log_print("    [•] Menjalankan restorehwmode.sh ...\n");
    telnet_send_cmd(&sess, "sudo restorehwmode.sh");
    SLEEP_MS(3000);
    telnet_send_cmd(&sess, "restorehwmode.sh");
    SLEEP_MS(3000);

    log_print("    [•] Mengirim perintah reboot...\n");
    telnet_send_cmd(&sess, "reboot");
    SLEEP_MS(1000);

    telnet_disconnect(&sess);
    log_print("    \033[1;32m[✓] STEP 2 Selesai! Modem sedang reboot.\033[0m\n");
    return 0;
}

int telnet_run_step4_set_mode(const char *ip, const char *user, const char *pass, int mode, const char *upportid) {
    telnet_session_t sess;
    telnet_init_session(&sess, ip, 23);

    const char *mode_str = "XPON (Auto Hybrid GPON/EPON)";
    if (mode == 1) mode_str = "GPON Murni";
    else if (mode == 2) mode_str = "EPON Murni";
    else if (mode == 3) mode_str = "LAN to WAN (Ethernet)";

    log_print("\n\033[1;36m[STEP 4: Mengunci Mode Uplink Optical -> %s]\033[0m\n", mode_str);
    log_print("    Menghubungkan ke %s:23 ...\n", sess.ip);

    if (telnet_connect(&sess, 5) != 0) {
        log_print("    \033[1;31m[!] Gagal menghubungkan ke Telnet ONT (%s:23).\033[0m\n", sess.ip);
        return -1;
    }

    if (telnet_login_huawei(&sess, user, pass, 5) != 0) {
        telnet_disconnect(&sess);
        return -2;
    }

    clear_rx_buffer(&sess);
    telnet_send_cmd(&sess, "su");
    SLEEP_MS(500);

    /* Send set upport mode */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "set upport mode %d upportid %s", mode, upportid ? upportid : "0x102001");
    log_print("    [•] Mengirim: %s\n", cmd);
    telnet_send_cmd(&sess, cmd);
    SLEEP_MS(1500);

    telnet_enter_shell(&sess, 5);

    /* Turn off equipmode */
    log_print("    [•] Mengirim: EquipMode.sh off ...\n");
    telnet_send_cmd(&sess, "EquipMode.sh off");
    SLEEP_MS(2500);

    log_print("    [•] Mengirim perintah reboot...\n");
    telnet_send_cmd(&sess, "reboot");
    SLEEP_MS(1000);

    telnet_disconnect(&sess);
    log_print("    \033[1;32m[✓] STEP 4 Selesai! Mode %s berhasil dikunci.\033[0m\n", mode_str);
    return 0;
}

int telnet_inject_permanent_alinos(const char *ip, const char *user, const char *pass, const alinos_config_t *cfg) {
    if (!cfg) return -1;
    telnet_session_t sess;
    telnet_init_session(&sess, ip, 23);

    log_print("\n\033[1;36m[STEP 5: Injeksi Konfigurasi Permanen ALINOSNET (Kebal Reset)]\033[0m\n");
    log_print("    Menghubungkan ke %s:23 ...\n", sess.ip);

    if (telnet_connect(&sess, 5) != 0) {
        log_print("    \033[1;31m[!] Gagal konek Telnet ONT. Pastikan modem aktif!\033[0m\n");
        return -1;
    }

    if (telnet_login_huawei(&sess, user, pass, 5) != 0) {
        telnet_disconnect(&sess);
        return -2;
    }

    telnet_enter_shell(&sess, 5);

    /* 1. Kunci PON mode di hw_boardinfo: obj 0x00000001 (current) dan 0x00000059 (default restore) */
    log_print("    [•] Menyetel hardware PON mode di NVRAM boardinfo -> mode %d ...\n", cfg->pon_mode);
    char boardinfo_cmd[512];
    snprintf(boardinfo_cmd, sizeof(boardinfo_cmd),
             "cat /mnt/jffs2/hw_boardinfo | sed 's/obj.id = \"0x00000001\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000001\" ; obj.value = \"%d\"/g' > /tmp/bi.tmp && "
             "cat /tmp/bi.tmp | sed 's/obj.id = \"0x00000059\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000059\" ; obj.value = \"%d\"/g' > /mnt/jffs2/hw_boardinfo && "
             "rm -f /tmp/bi.tmp /mnt/jffs2/hw_boardinfo.bak",
             cfg->pon_mode, cfg->pon_mode);
    telnet_send_cmd(&sess, boardinfo_cmd);
    SLEEP_MS(1000);

    /* 2. Kunci China Mode & Tampilkan WiFi Password di GUI */
    log_print("    [•] Mengunci China Mode & Plaintext WiFi Password di feature NVRAM...\n");
    telnet_send_cmd(&sess, "echo 'feature.name = \"HW_SSMP_FEATURE_CLI_CHINA_MODE\" feature.enable=\"1\" feature.attribute=\"1\";' > /mnt/jffs2/hw_hardinfo_feature");
    SLEEP_MS(300);
    telnet_send_cmd(&sess, "echo 'feature.name=\"AMP_FT_REMOTE_IP_WIFI_PWD_SHOW\" feature.enable=\"1\";' >> /mnt/jffs2/hw_hardinfo_feature");
    SLEEP_MS(300);
    telnet_send_cmd(&sess, "echo 'feature.name = \"AMP_FT_WIFI_PWD_SHOW\" feature.enable=\"1\"' >> /mnt/jffs2/hw_hardinfo_feature");
    SLEEP_MS(500);

    /* 3. Set WiFi SSID & Password */
    const char *s_2g = (cfg->ssid_2g && cfg->ssid_2g[0]) ? cfg->ssid_2g : "ALINOSNET";
    const char *s_5g = (cfg->ssid_5g && cfg->ssid_5g[0]) ? cfg->ssid_5g : "ALINOSNET_5G";
    const char *w_pass = (cfg->wifi_password && cfg->wifi_password[0]) ? cfg->wifi_password : "eeeeeeee";

    log_print("    [•] Mengatur SSID WiFi 2.4G : \033[1;37m%s\033[0m ...\n", s_2g);
    char wifi_cmd[256];
    snprintf(wifi_cmd, sizeof(wifi_cmd), "wap cli \"set wlan security ssid 1 name %s key %s visible 1\"", s_2g, w_pass);
    telnet_send_cmd(&sess, wifi_cmd);
    SLEEP_MS(800);

    log_print("    [•] Mengatur SSID WiFi 5.0G : \033[1;37m%s\033[0m ...\n", s_5g);
    snprintf(wifi_cmd, sizeof(wifi_cmd), "wap cli \"set wlan security ssid 5 name %s key %s visible 1\"", s_5g, w_pass);
    telnet_send_cmd(&sess, wifi_cmd);
    SLEEP_MS(800);

    /* 4. Set TR-069 ACS Server */
    const char *acs_url = (cfg->tr069_url && cfg->tr069_url[0]) ? cfg->tr069_url : "http://ont.alinos-dashboard.my.id";
    const char *acs_user = (cfg->tr069_user && cfg->tr069_user[0]) ? cfg->tr069_user : "admin";
    const char *acs_pass = (cfg->tr069_pass && cfg->tr069_pass[0]) ? cfg->tr069_pass : "ALINOSNET21";

    log_print("    [•] Mengatur TR-069 ACS URL: \033[1;37m%s\033[0m ...\n", acs_url);
    char tr_cmd[256];
    telnet_send_cmd(&sess, "wap cli \"set tr069 enable 1\"");
    SLEEP_MS(400);
    snprintf(tr_cmd, sizeof(tr_cmd), "wap cli \"set tr069 url %s\"", acs_url);
    telnet_send_cmd(&sess, tr_cmd);
    SLEEP_MS(400);
    snprintf(tr_cmd, sizeof(tr_cmd), "wap cli \"set tr069 username %s password %s\"", acs_user, acs_pass);
    telnet_send_cmd(&sess, tr_cmd);
    SLEEP_MS(400);
    telnet_send_cmd(&sess, "wap cli \"set tr069 inform enable 1 interval 600\"");
    SLEEP_MS(400);

    /* 5. Buka Firewall WAN Remote Access */
    log_print("    [•] Membuka Firewall Remote Access WAN (HTTP, HTTPS, Telnet, ICMP)...\n");
    telnet_send_cmd(&sess, "wap cli \"set firewall wanaccess http enable 1\"");
    telnet_send_cmd(&sess, "wap cli \"set firewall wanaccess https enable 1\"");
    telnet_send_cmd(&sess, "wap cli \"set firewall wanaccess telnet enable 1\"");
    telnet_send_cmd(&sess, "wap cli \"set firewall wanaccess icmp enable 1\"");
    SLEEP_MS(800);

    /* 6. RAHASIA PERMANEN: Kloning hw_ctree.xml ke hw_default_ctree.xml */
    log_print("    [•] \033[1;33mMENGUNCI KEBAL RESET: Menyimpan konfigurasi ke /mnt/jffs2/hw_default_ctree.xml ...\033[0m\n");
    telnet_send_cmd(&sess, "cp -rf /mnt/jffs2/hw_ctree.xml /mnt/jffs2/hw_default_ctree.xml");
    SLEEP_MS(1500);

    /* 7. Matikan EquipMode dan sinkronisasi flash */
    log_print("    [•] Mematikan EquipMode & Sync Flash Filesystem...\n");
    telnet_send_cmd(&sess, "EquipMode.sh off");
    SLEEP_MS(1500);
    telnet_send_cmd(&sess, "sync");
    SLEEP_MS(1000);

    log_print("    [•] Mengirim perintah reboot...\n");
    telnet_send_cmd(&sess, "reboot");
    SLEEP_MS(1000);

    telnet_disconnect(&sess);

    log_print("\n\033[1;32m================================================================================\033[0m\n");
    log_print("\033[1;32m[✓] SUKSES BESAR! Konfigurasi ALINOSNET berhasil disuntikkan secara PERMANEN!\033[0m\n");
    log_print("    Bahkan jika tombol RESET fisik ditekan / reset factory web dilakukan,\n");
    log_print("    modem akan tetap kembali ke settingan ALINOSNET ini (SSID, Password, TR069, Mode).\n");
    log_print("\033[1;32m================================================================================\033[0m\n\n");
    return 0;
}
