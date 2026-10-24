/* =====================================================================
 * ALINOS.NET FlashTool v1.3 - EG8145V5 Permanen Toolkit
 * Pengganti TOOLS FLASHER.exe (broadcast WAPP) + skrip .bat/VBS SendKeys
 * (telnet expect-based) dalam satu aplikasi C Win32 native.
 *
 * Protokol WAPP hasil reverse engineering TOOLS FLASHER.exe (Huawei ONT
 * Repair Enable Tool): grup multicast 224.0.0.99, port 4899 (+918),
 * paket kontrol 244 byte "WAPP...CEND", paket data header 20 byte
 * "DLUM" + potongan file; PKCRC = CRC32 zlib atas seluruh file.
 * Balasan ONT didengarkan di UDP 819.
 *
 * v1.3: layout ringkas responsif (muat 1366x768, jendela bisa dibesarkan),
 * kartu tersusun urut per step, login telnet full-otomatis multi
 * kredensial, progress bar, popup error, ikon aplikasi.
 * ===================================================================== */
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <wininet.h>
#include <shellapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include "embedded_triggers.h"

#define APP_VERSION  "2.0.2"
#define GITHUB_REPO  "skydashnet/alinos-flasher"

enum {
    ID_IP = 101, ID_ADAPTER, ID_SCAN_ADP, ID_GROUP, ID_PORT, ID_CHK918, ID_PKSIZE,
    ID_INTERVAL, ID_DURASI, ID_CREDS, ID_DEV_STATUS, ID_UPDATE,
    ID_BIN1, ID_BIN2, ID_BIN3, ID_BRW1, ID_BRW2, ID_BRW3,
    ID_FLASH1, ID_FLASH2, ID_FLASH3,
    ID_STEP2, ID_MODE, ID_STEP4, ID_REBOOT,
    ID_PPPUSER, ID_PPPPASS, ID_SSID1, ID_SSID5, ID_WKEY,
    ID_TRURL, ID_TRUSER, ID_TRPASS, ID_TRINFORM, ID_CRUSER, ID_CRPASS,
    ID_CHKWAN, ID_CHKREBOOT, ID_PROV,
    ID_CINFO, ID_CDETAIL, ID_APPLYCI,
    ID_WEB_RED, ID_WEB_BLUE,
    ID_FULLRUN, ID_LANJUT, ID_STOP, ID_LOG,
    ID_LOGSAVE, ID_LOGCOPY, ID_LOGCLEAR, ID_STATUS, ID_PROG,
    ID_LOGTOGGLE, ID_LOGOPEN
};

#define WM_LOGMSG     (WM_APP + 1)
#define WM_PROG       (WM_APP + 4)
#define WM_ERRPOP     (WM_APP + 5)
#define WM_DEV_UPDATE (WM_APP + 6)

static HWND g_hwnd, g_log;
static HWND hIp, hAdapter, hBtnScanAdp, hGroup, hPort, hChk918, hPkSize, hInterval, hDurasi, hCreds, hDevStatus, hBtnUpdate;
static volatile int g_updating = 0;
static HWND hBin1, hBin2, hBin3, hMode;
static HWND hPppUser, hPppPass, hSsid1, hSsid5, hWkey, hTrUrl, hTrUser,
            hTrPass, hTrInform, hCrUser, hCrPass, hChkWan, hChkReboot;
static HWND hCInfo, hCDetail;
static HWND hBtnFlash1, hBtnFlash2, hBtnFlash3, hBtnStep2, hBtnStep4,
            hBtnReboot, hBtnProv, hBtnFull, hBtnCI, hBtnLanjut, hBtnStop,
            hBtnWebRed, hBtnWebBlue;
static HWND hStatus, hProg, hProgTxt, hLogTitle;
static HWND hAllBtns[16];

static HANDLE g_hStopEvt, g_hGateEvt;
static volatile int g_running = 0;
static int g_log_open = 1;

/* ------------------------------ Log ------------------------------ */
static void logmsg(const char *fmt, ...) {
    char raw[1800], buf[2048];
    va_list ap; va_start(ap, fmt);
    _vsnprintf(raw, sizeof(raw) - 1, fmt, ap);
    raw[sizeof(raw) - 1] = 0;
    va_end(ap);
    SYSTEMTIME st; GetLocalTime(&st);
    _snprintf(buf, sizeof(buf) - 1, "[%02d:%02d:%02d] %s",
              st.wHour, st.wMinute, st.wSecond, raw);
    buf[sizeof(buf) - 1] = 0;
    char *copy = _strdup(buf);
    if (g_hwnd) PostMessage(g_hwnd, WM_LOGMSG, 0, (LPARAM)copy);
    else free(copy);
}
static void log_append(const char *s) {
    char buf[4096]; int j = 0;
    for (int i = 0; s[i] && j < 4000; i++) {
        if (s[i] == '\n' && (i == 0 || s[i - 1] != '\r')) buf[j++] = '\r';
        buf[j++] = s[i];
    }
    buf[j] = 0;
    int len = GetWindowTextLength(g_log);
    if (len > 200000) {
        SendMessage(g_log, EM_SETSEL, 0, 50000);
        SendMessage(g_log, EM_REPLACESEL, FALSE, (LPARAM)"");
        len = GetWindowTextLength(g_log);
    }
    SendMessage(g_log, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessage(g_log, EM_REPLACESEL, FALSE, (LPARAM)buf);
    SendMessage(g_log, EM_REPLACESEL, FALSE, (LPARAM)"\r\n");
    SendMessage(g_log, EM_SCROLLCARET, 0, 0);
    SendMessage(g_log, WM_VSCROLL, SB_BOTTOM, 0);
}

/* --------------------- Error terakhir & progress --------------------- */
static char g_lasterr[512];
static void set_err(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    _vsnprintf(g_lasterr, sizeof(g_lasterr) - 1, fmt, ap);
    g_lasterr[sizeof(g_lasterr) - 1] = 0;
    va_end(ap);
}
static volatile int g_p_lo = 0, g_p_hi = 100;
static void prog_range(int lo, int hi) { g_p_lo = lo; g_p_hi = hi; }
static void prog_local(int pct) {
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    int v = g_p_lo + (g_p_hi - g_p_lo) * pct / 100;
    if (g_hwnd) PostMessage(g_hwnd, WM_PROG, (WPARAM)v, 0);
}

/* ------------------------------ CRC32 ------------------------------ */
static unsigned long g_crc_tab[256];
static int g_crc_ready = 0;
static void crc_init(void) {
    for (unsigned long n = 0; n < 256; n++) {
        unsigned long c = n;
        for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320UL ^ (c >> 1)) : (c >> 1);
        g_crc_tab[n] = c;
    }
    g_crc_ready = 1;
}
static unsigned long crc32_of(const unsigned char *buf, size_t len) {
    unsigned long c = 0xFFFFFFFFUL;
    for (size_t n = 0; n < len; n++) c = g_crc_tab[(c ^ buf[n]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFUL;
}

/* ------------------------ Adapter & Device ------------------------ */
typedef struct {
    char ip[32];
    char mask[32];
    char desc[128];
    char display[160];
    int is_lan;
    int is_ont_subnet;
} AdapterInfo;

static AdapterInfo g_adapters[24];
static int g_num_adapters = 0;

static volatile int g_dev_state = 0; /* 0: waiting/offline, 1: online, 2: rescue/flashing, 3: alt ip */
static char g_dev_desc[160] = "[IDLE] Menunggu ONT di 192.168.100.1 (Kabel LAN / Power)";

/* --------------------------- Konfigurasi --------------------------- */
typedef struct {
    char ip[64], adapter[64], group[64];
    int port, use918, pksize, interval, durasi;
    char creds[1536];
    char cred_user[24][64], cred_pass[24][64];
    int ncreds;
    char bin1[MAX_PATH], bin2[MAX_PATH], bin3[MAX_PATH];
    int mode_idx;
    char pppuser[128], ppppass[128], ssid1[128], ssid5[128], wkey[128];
    char trurl[256], truser[128], trpass[128], trinform[16];
    char cruser[128], crpass[128];
    int wanaccess, provreboot;
    char cinfo[64], cdetail[64];
} Cfg;
static Cfg g_cfg;

static void get_text(HWND h, char *out, int cap) {
    GetWindowText(h, out, cap);
    out[cap - 1] = 0;
}
static int chk(HWND h) { return SendMessage(h, BM_GETCHECK, 0, 0) == BST_CHECKED; }
static void sanitize_field(char *s, int telnet_strict) {
    const char *bad = telnet_strict ? "\"'`$\\;|&<>\r\n" : "\"'\r\n";
    for (int i = 0; s[i]; i++) if (strchr(bad, s[i])) s[i] = '_';
}
static void parse_creds(void) {
    g_cfg.ncreds = 0;
    char buf[1536];
    strncpy(buf, g_cfg.creds, sizeof(buf) - 1); buf[sizeof(buf) - 1] = 0;
    char *p = buf;
    while (*p && g_cfg.ncreds < 24) {
        char *eol = strchr(p, '\n');
        if (eol) *eol = 0;
        char line[256];
        strncpy(line, p, sizeof(line) - 1); line[sizeof(line) - 1] = 0;
        /* trim */
        char *s = line; while (*s == ' ' || *s == '\t' || *s == '\r') s++;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) *--e = 0;
        if (*s) {
            char *colon = strchr(s, ':');
            if (colon) {
                *colon = 0;
                strncpy(g_cfg.cred_user[g_cfg.ncreds], s, 63);
                strncpy(g_cfg.cred_pass[g_cfg.ncreds], colon + 1, 63);
            } else {
                strncpy(g_cfg.cred_user[g_cfg.ncreds], s, 63);
                g_cfg.cred_pass[g_cfg.ncreds][0] = 0;
            }
            g_cfg.cred_user[g_cfg.ncreds][63] = 0;
            g_cfg.cred_pass[g_cfg.ncreds][63] = 0;
            g_cfg.ncreds++;
        }
        if (!eol) break;
        p = eol + 1;
    }
    if (g_cfg.ncreds == 0) {
        strcpy(g_cfg.cred_user[0], "root"); strcpy(g_cfg.cred_pass[0], "admin");
        g_cfg.ncreds = 1;
    }
}
static void read_cfg(void) {
    get_text(hIp, g_cfg.ip, 64);
    int adp_idx = (int)SendMessage(hAdapter, CB_GETCURSEL, 0, 0);
    if (adp_idx >= 0 && adp_idx < g_num_adapters) {
        strncpy(g_cfg.adapter, g_adapters[adp_idx].ip, sizeof(g_cfg.adapter) - 1);
    } else {
        strncpy(g_cfg.adapter, "0.0.0.0", sizeof(g_cfg.adapter) - 1);
    }
    get_text(hGroup, g_cfg.group, 64);
    char tmp[64];
    get_text(hPort, tmp, 64);     g_cfg.port = atoi(tmp);
    get_text(hPkSize, tmp, 64);   g_cfg.pksize = atoi(tmp);
    get_text(hInterval, tmp, 64); g_cfg.interval = atoi(tmp);
    get_text(hDurasi, tmp, 64);   g_cfg.durasi = atoi(tmp);
    g_cfg.use918 = chk(hChk918);
    GetWindowText(hCreds, g_cfg.creds, sizeof(g_cfg.creds));
    parse_creds();
    get_text(hBin1, g_cfg.bin1, MAX_PATH);
    get_text(hBin2, g_cfg.bin2, MAX_PATH);
    get_text(hBin3, g_cfg.bin3, MAX_PATH);
    g_cfg.mode_idx = (int)SendMessage(hMode, CB_GETCURSEL, 0, 0);
    if (g_cfg.mode_idx < 0) g_cfg.mode_idx = 0;
    get_text(hPppUser, g_cfg.pppuser, 128);
    get_text(hPppPass, g_cfg.ppppass, 128);
    get_text(hSsid1, g_cfg.ssid1, 128);
    get_text(hSsid5, g_cfg.ssid5, 128);
    get_text(hWkey, g_cfg.wkey, 128);
    get_text(hTrUrl, g_cfg.trurl, 256);
    get_text(hTrUser, g_cfg.truser, 128);
    get_text(hTrPass, g_cfg.trpass, 128);
    get_text(hTrInform, g_cfg.trinform, 16);
    get_text(hCrUser, g_cfg.cruser, 128);
    get_text(hCrPass, g_cfg.crpass, 128);
    get_text(hCInfo, g_cfg.cinfo, 64);
    get_text(hCDetail, g_cfg.cdetail, 64);
    g_cfg.wanaccess = chk(hChkWan);
    g_cfg.provreboot = chk(hChkReboot);
    if (!g_cfg.ip[0]) strcpy(g_cfg.ip, "192.168.100.1");
    if (!g_cfg.group[0]) strcpy(g_cfg.group, "255.255.255.255");
    if (g_cfg.port <= 0) g_cfg.port = 4891;
    if (g_cfg.pksize < 200 || g_cfg.pksize > 1472) g_cfg.pksize = 1000;
    if (g_cfg.interval < 0) g_cfg.interval = 0;
    if (g_cfg.interval > 1000) g_cfg.interval = 1000;
    if (g_cfg.durasi <= 0) g_cfg.durasi = 60;
    if (!g_cfg.trinform[0]) strcpy(g_cfg.trinform, "600");
    sanitize_field(g_cfg.pppuser, 1); sanitize_field(g_cfg.ppppass, 1);
    sanitize_field(g_cfg.ssid1, 1); sanitize_field(g_cfg.ssid5, 1); sanitize_field(g_cfg.wkey, 1);
    sanitize_field(g_cfg.trurl, 1); sanitize_field(g_cfg.truser, 1); sanitize_field(g_cfg.trpass, 1);
    sanitize_field(g_cfg.cruser, 1); sanitize_field(g_cfg.crpass, 1); sanitize_field(g_cfg.trinform, 1);
}

/* =====================================================================
 * BAGIAN 1 - Broadcast WAPP (pengganti TOOLS FLASHER.exe)
 * ===================================================================== */
static unsigned char *read_file_all(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    *out_len = (size_t)sz;
    return buf;
}
static const char *base_name(const char *p) {
    const char *b = strrchr(p, '\\');
    const char *f = strrchr(p, '/');
    if (f && (!b || f > b)) b = f;
    return b ? b + 1 : p;
}
static volatile int g_ont_started = 0;
static volatile int g_ont_finished = 0;

static void scan_network_adapters(const char *preferred_ip) {
    if (!hAdapter) return;
    SendMessage(hAdapter, CB_RESETCONTENT, 0, 0);
    g_num_adapters = 0;

    /* Entry default 0: 0.0.0.0 */
    strncpy(g_adapters[0].ip, "0.0.0.0", sizeof(g_adapters[0].ip));
    strncpy(g_adapters[0].display, "[Auto] 0.0.0.0 (Semua Adapter / Broadcast)", sizeof(g_adapters[0].display));
    g_adapters[0].is_lan = 0;
    g_adapters[0].is_ont_subnet = 0;
    SendMessage(hAdapter, CB_ADDSTRING, 0, (LPARAM)g_adapters[0].display);
    g_num_adapters = 1;

    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    IP_ADAPTER_INFO *pInfo = (IP_ADAPTER_INFO *)malloc(bufLen);
    if (pInfo) {
        if (GetAdaptersInfo(pInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
            free(pInfo);
            pInfo = (IP_ADAPTER_INFO *)malloc(bufLen);
        }
        if (pInfo && GetAdaptersInfo(pInfo, &bufLen) == NO_ERROR) {
            IP_ADAPTER_INFO *p = pInfo;
            while (p && g_num_adapters < 24) {
                IP_ADDR_STRING *addr = &p->IpAddressList;
                while (addr && g_num_adapters < 24) {
                    char *ip = addr->IpAddress.String;
                    if (ip && ip[0] && strcmp(ip, "0.0.0.0") != 0 && strcmp(ip, "127.0.0.1") != 0) {
                        int is_lan = (p->Type == MIB_IF_TYPE_ETHERNET);
                        int is_ont_sub = (strncmp(ip, "192.168.100.", 12) == 0 || strncmp(ip, "192.168.18.", 11) == 0);
                        int is_wifi = (p->Type == 71 /* IF_TYPE_IEEE80211 */);
                        if (!is_wifi) {
                            if (strstr(p->Description, "Wi-Fi") || strstr(p->Description, "Wireless") ||
                                strstr(p->Description, "802.11") || strstr(p->Description, "WLAN") ||
                                strstr(p->Description, "wlan")) {
                                is_wifi = 1;
                                is_lan = 0;
                            }
                        }

                        strncpy(g_adapters[g_num_adapters].ip, ip, sizeof(g_adapters[g_num_adapters].ip) - 1);
                        strncpy(g_adapters[g_num_adapters].mask, addr->IpMask.String, sizeof(g_adapters[g_num_adapters].mask) - 1);
                        strncpy(g_adapters[g_num_adapters].desc, p->Description, sizeof(g_adapters[g_num_adapters].desc) - 1);
                        g_adapters[g_num_adapters].is_lan = is_lan;
                        g_adapters[g_num_adapters].is_ont_subnet = is_ont_sub;

                        const char *tag = is_ont_sub ? "[ONT LAN]" : (is_lan ? "[LAN]" : (is_wifi ? "[WiFi]" : "[NET]"));
                        _snprintf(g_adapters[g_num_adapters].display, sizeof(g_adapters[g_num_adapters].display),
                                  "%s %s - %.32s", tag, ip, p->Description);

                        SendMessage(hAdapter, CB_ADDSTRING, 0, (LPARAM)g_adapters[g_num_adapters].display);
                        g_num_adapters++;
                    }
                    addr = addr->Next;
                }
                p = p->Next;
            }
        }
        if (pInfo) free(pInfo);
    }

    int best_idx = 0;
    if (preferred_ip && preferred_ip[0] && strcmp(preferred_ip, "0.0.0.0") != 0) {
        for (int i = 1; i < g_num_adapters; i++) {
            if (strcmp(g_adapters[i].ip, preferred_ip) == 0) {
                best_idx = i;
                break;
            }
        }
    }
    if (best_idx == 0) {
        for (int i = 1; i < g_num_adapters; i++) {
            if (g_adapters[i].is_ont_subnet) {
                best_idx = i;
                break;
            }
        }
        if (best_idx == 0) {
            for (int i = 1; i < g_num_adapters; i++) {
                if (g_adapters[i].is_lan) {
                    best_idx = i;
                    break;
                }
            }
        }
    }

    SendMessage(hAdapter, CB_SETCURSEL, best_idx, 0);
    strncpy(g_cfg.adapter, g_adapters[best_idx].ip, sizeof(g_cfg.adapter) - 1);
    logmsg("[NET] Auto-Discovery: Terpilih %s", g_adapters[best_idx].display);
}

static int probe_tcp_port(const char *ip, int port, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)port);
    sin.sin_addr.s_addr = inet_addr(ip);
    connect(s, (struct sockaddr *)&sin, sizeof(sin));
    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(s, &wf);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(0, NULL, &wf, NULL, &tv);
    int ok = 0;
    if (r > 0 && FD_ISSET(s, &wf)) {
        int err = 0, errlen = sizeof(err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen);
        if (err == 0) ok = 1;
    }
    closesocket(s);
    return ok;
}

static DWORD WINAPI device_discovery_thread(LPVOID p) {
    (void)p;
    int last_state = -1;

    while (1) {
        Sleep(1500);
        if (g_running) continue;

        char cur_ip[64] = "192.168.100.1";
        if (hIp) GetWindowText(hIp, cur_ip, sizeof(cur_ip));
        if (!cur_ip[0]) strcpy(cur_ip, "192.168.100.1");

        int state = 0;
        char status_buf[160] = "";

        if (g_ont_finished) {
            state = 1;
            _snprintf(status_buf, sizeof(status_buf), "[SELESAI] Flashing Selesai: Lampu Naik Semua! (Power Cycle)");
        } else if (g_ont_started) {
            state = 2;
            _snprintf(status_buf, sizeof(status_buf), "[RESCUE] ONT Bootloader: Menerima Flashing...");
        } else {
            /* 1. Cek SendARP (Layer 2) */
            ULONG mac[2];
            ULONG macLen = 6;
            DWORD arp_res = SendARP(inet_addr(cur_ip), 0, mac, &macLen);
            int arp_ok = (arp_res == NO_ERROR && macLen >= 6);
            char mac_str[32] = "";
            if (arp_ok) {
                unsigned char *b = (unsigned char *)mac;
                _snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                          b[0], b[1], b[2], b[3], b[4], b[5]);
            }

            /* 2. Cek Port 80 & 23 */
            int http_ok = probe_tcp_port(cur_ip, 80, 150);
            int telnet_ok = probe_tcp_port(cur_ip, 23, 150);

            if (arp_ok || http_ok || telnet_ok) {
                state = 1;
                if (mac_str[0]) {
                    _snprintf(status_buf, sizeof(status_buf),
                              "[ONLINE] %s (MAC %s | Web: %s | Telnet: %s)",
                              cur_ip, mac_str, http_ok ? "ON" : "OFF", telnet_ok ? "Siap" : "Tutup");
                } else {
                    _snprintf(status_buf, sizeof(status_buf),
                              "[ONLINE] %s (Web: %s | Telnet: %s)",
                              cur_ip, http_ok ? "ON" : "OFF", telnet_ok ? "Siap" : "Tutup");
                }
            } else {
                /* Cek alternatif IP 192.168.18.1 jika target sekarang 192.168.100.1 */
                if (strcmp(cur_ip, "192.168.100.1") == 0) {
                    int alt_http = probe_tcp_port("192.168.18.1", 80, 150);
                    int alt_arp = (SendARP(inet_addr("192.168.18.1"), 0, mac, &macLen) == NO_ERROR);
                    if (alt_http || alt_arp) {
                        state = 3;
                        _snprintf(status_buf, sizeof(status_buf),
                                  "[INFO] Terdeteksi di 192.168.18.1 (Klik di sini untuk ubah IP)");
                    }
                }
                if (state == 0) {
                    _snprintf(status_buf, sizeof(status_buf),
                              "[IDLE] Menunggu ONT di %s (Kabel LAN / Power)", cur_ip);
                }
            }
        }

        if (state != last_state || strcmp(status_buf, g_dev_desc) != 0) {
            last_state = state;
            g_dev_state = state;
            strncpy(g_dev_desc, status_buf, sizeof(g_dev_desc) - 1);
            if (g_hwnd) {
                char *copy = _strdup(status_buf);
                PostMessage(g_hwnd, WM_DEV_UPDATE, (WPARAM)state, (LPARAM)copy);
            }
        }
    }
    return 0;
}

static SOCKET udp_bound(const char *adapter_ip, int ttl) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&one, sizeof(one));
    if (ttl > 0) setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof(ttl));
    
    if (adapter_ip && adapter_ip[0] && strcmp(adapter_ip, "0.0.0.0") != 0) {
        struct in_addr ia;
        ia.s_addr = inet_addr(adapter_ip);
        if (ia.s_addr != INADDR_NONE) {
            setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ia, sizeof(ia));
            struct sockaddr_in baddr;
            memset(&baddr, 0, sizeof(baddr));
            baddr.sin_family = AF_INET;
            baddr.sin_addr = ia;
            bind(s, (struct sockaddr *)&baddr, sizeof(baddr));
            logmsg("[WAPP] Socket di-bind khusus ke adapter: %s", adapter_ip);
        }
    }
    return s;
}
static int stop_requested(void) { return WaitForSingleObject(g_hStopEvt, 0) == WAIT_OBJECT_0; }

/* Broadcast satu file .bin selama durasi detik. 0 = selesai normal. */
static int broadcast_file(const char *path) {
    size_t len = 0;
    unsigned char *data = read_file_all(path, &len);
    if (!data) { set_err("File tidak bisa dibaca: %s", path); logmsg("[WAPP] GAGAL baca file: %s", path); return -1; }
    const char *name = base_name(path);
    if (!g_crc_ready) crc_init();

    unsigned long crc = crc32_of(data, len);
    char board_list[128] = {0};
    if (len >= 0x128 && memcmp(data, "HWNP", 4) == 0) {
        crc = *(unsigned long *)(data + 0x08); /* Stored header CRC dari paket HWNP */
        memcpy(board_list, data + 0x24, 64);
        board_list[64] = 0;
    }

    int pksize = g_cfg.pksize;
    if (pksize <= 0) pksize = 1000;
    int nchunk = (int)((len + (size_t)pksize - 1) / (size_t)pksize);
    DWORD total_ms = (DWORD)g_cfg.durasi * 1000UL;

    logmsg("[WAPP] %s: %u byte, Checksum=0x%08lX, %d paket x %d byte", name, (unsigned)len, crc, nchunk, pksize);
    if (board_list[0]) {
        logmsg("[WAPP] Target Boards: %s", board_list);
    }
    logmsg("[WAPP] Broadcast ke %s:%d selama %d detik...", g_cfg.group, g_cfg.port, g_cfg.durasi);

    SOCKET s1 = udp_bound(g_cfg.adapter, 1);
    if (s1 == INVALID_SOCKET) {
        set_err("Gagal membuat socket UDP. Cek koneksi jaringan Windows.");
        logmsg("[WAPP] GAGAL buat socket (WSA error %d)", WSAGetLastError());
        free(data); return -1;
    }

    struct sockaddr_in dst; memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(g_cfg.group);
    struct sockaddr_in dst1 = dst; dst1.sin_port = htons((u_short)g_cfg.port);
    struct sockaddr_in dst_beacon = dst; dst_beacon.sin_port = htons(6877);

    /* Multicast Group 224.0.0.99 (Standar resmi TOOLS FLASHER / U-Boot Huawei) */
    struct sockaddr_in dst_mcast = dst;
    dst_mcast.sin_addr.s_addr = inet_addr("224.0.0.99");
    dst_mcast.sin_port = htons((u_short)g_cfg.port);
    struct sockaddr_in dst_mcast_918 = dst;
    dst_mcast_918.sin_addr.s_addr = inet_addr("224.0.0.99");
    dst_mcast_918.sin_port = htons(918);

    /* Subnet direct broadcast (menyesuaikan IP adapter yang dipilih) */
    struct sockaddr_in dst_sub = dst;
    char sub_bcast[64] = "255.255.255.255";
    if (g_cfg.adapter[0] && strcmp(g_cfg.adapter, "0.0.0.0") != 0) {
        char ip_copy[64];
        strncpy(ip_copy, g_cfg.adapter, sizeof(ip_copy) - 1);
        char *last_dot = strrchr(ip_copy, '.');
        if (last_dot) {
            strcpy(last_dot + 1, "255");
            strncpy(sub_bcast, ip_copy, sizeof(sub_bcast) - 1);
        }
    } else {
        strcpy(sub_bcast, "192.168.100.255");
    }
    dst_sub.sin_addr.s_addr = inet_addr(sub_bcast);
    dst_sub.sin_port = htons((u_short)g_cfg.port);

    /* Dual Port 918 (Huawei V3) */
    struct sockaddr_in dst_918 = dst; dst_918.sin_port = htons(918);
    struct sockaddr_in dst_918_sub = dst_sub; dst_918_sub.sin_port = htons(918);

    /* Paket Kontrol Trigger Beacon Master/Standby (Huawei V5: 147C|148C|... HG/EG8145V5) */
    unsigned char ctl_trig[244]; memset(ctl_trig, 0, sizeof(ctl_trig));
    memcpy(ctl_trig + 0x00, "WAPP", 4);
    *(unsigned long *)(ctl_trig + 0x48) = 1UL;
    *(unsigned long *)(ctl_trig + 0x50) = 0xd7646a87UL; /* CRC32 res_153 */
    *(unsigned long *)(ctl_trig + 0x54) = 14916UL;       /* Len res_153 */
    strncpy((char *)ctl_trig + 0x58, "147C|148C|149C|14FD|14ED|1118B|11AB|1960|", 63);
    memcpy(ctl_trig + 0xA0, "This is a multicast wap package control info packet.", 52);
    *(unsigned long *)(ctl_trig + 0xE0) = 15UL;          /* 15 chunks */
    *(unsigned long *)(ctl_trig + 0xE4) = 1000UL;        /* 1000 bytes/chunk */
    memcpy(ctl_trig + 0xF0, "CEND", 4);

    /* paket kontrol 244 byte WAPP...CEND untuk file target */
    unsigned char ctl[244]; memset(ctl, 0, sizeof(ctl));
    memcpy(ctl + 0x00, "WAPP", 4);
    *(unsigned long *)(ctl + 0x48) = 1UL;
    *(unsigned long *)(ctl + 0x50) = crc;
    *(unsigned long *)(ctl + 0x54) = (unsigned long)len;
    if (board_list[0]) {
        strncpy((char *)ctl + 0x58, board_list, 63);
    } else {
        strncpy((char *)ctl + 0x58, name, 63);
    }
    memcpy(ctl + 0xA0, "This is a multicast wap package control info packet.", 52);
    *(unsigned long *)(ctl + 0xE0) = (unsigned long)nchunk;
    *(unsigned long *)(ctl + 0xE4) = (unsigned long)pksize;
    memcpy(ctl + 0xF0, "CEND", 4);

    unsigned char *pkt = (unsigned char *)malloc(20 + (size_t)pksize);
    int stopped = 0;
    DWORD t0 = GetTickCount();
    DWORD last_ctl = 0, last_prog = 0;
    int idx = 0, pass_count = 0;
    g_ont_started = 0;
    g_ont_finished = 0;

    logmsg("[WAPP] Mode Master/Standby AKTIF: Memancarkan trigger beacon 147C/148C (HG/EG8145V5)...");

    while ((GetTickCount() - t0) < total_ms) {
        if (stop_requested()) { stopped = 1; break; }
        if (g_ont_finished) {
            logmsg("[WAPP] Sinyal Finish upgrade dari ONT diterima! Mengakhiri broadcast.");
            break;
        }

        DWORD now = GetTickCount();
        if (now - last_ctl >= 1000 || last_ctl == 0) {
            /* 1. Kirim Trigger Beacon Master/Standby ke port 6877, 4891, 918 (memicu modem ON/IDLE) */
            sendto(s1, (char *)ctl_trig, 244, 0, (struct sockaddr *)&dst_beacon, sizeof(dst_beacon));
            sendto(s1, (char *)ctl_trig, 244, 0, (struct sockaddr *)&dst_mcast, sizeof(dst_mcast));
            sendto(s1, (char *)ctl_trig, 244, 0, (struct sockaddr *)&dst1, sizeof(dst1));
            sendto(s1, (char *)ctl_trig, 244, 0, (struct sockaddr *)&dst_sub, sizeof(dst_sub));

            /* 2. Kirim 15 Chunks Trigger Payload (g_trigger_v5) agar daemon ONT aktif seketika */
            for (int ti = 0; ti < 15; ti++) {
                size_t toff = (size_t)ti * 1000;
                size_t tclen = (toff + 1000 <= 14916) ? 1000 : (14916 - toff);
                unsigned char tpkt[20 + 1000];
                memset(tpkt, 0, 20);
                memcpy(tpkt, "DLUM", 4);
                *(unsigned long *)(tpkt + 4) = 0UL;
                *(unsigned long *)(tpkt + 8) = (unsigned long)ti;
                *(unsigned long *)(tpkt + 12) = (unsigned long)tclen;
                *(unsigned long *)(tpkt + 16) = 0UL;
                memcpy(tpkt + 20, g_trigger_v5 + toff, tclen);
                sendto(s1, (char *)tpkt, (int)(20 + tclen), 0, (struct sockaddr *)&dst_mcast, sizeof(dst_mcast));
                sendto(s1, (char *)tpkt, (int)(20 + tclen), 0, (struct sockaddr *)&dst1, sizeof(dst1));
            }

            /* 3. Kirim Main WAPP Control Packet untuk firmware target (R020.bin) */
            sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst_mcast, sizeof(dst_mcast));
            sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst1, sizeof(dst1));
            sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst_sub, sizeof(dst_sub));
            sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst_beacon, sizeof(dst_beacon));
            if (g_cfg.use918) {
                sendto(s1, (char *)ctl_trig, 244, 0, (struct sockaddr *)&dst_mcast_918, sizeof(dst_mcast_918));
                sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst_mcast_918, sizeof(dst_mcast_918));
                sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst_918, sizeof(dst_918));
                sendto(s1, (char *)ctl, 244, 0, (struct sockaddr *)&dst_918_sub, sizeof(dst_918_sub));
            }
            last_ctl = now;
        }

        size_t off = (size_t)idx * (size_t)pksize;
        size_t clen = (off + (size_t)pksize <= len) ? (size_t)pksize : (len - off);

        /* HEADER RESMI DLUM HUAWEI:
         * Offset 0..3:  "DLUM"
         * Offset 4..7:  0 (Session / Sequence)
         * Offset 8..11: idx (Chunk Index: 0 .. N-1)
         * Offset 12..15: clen (Ukuran chunk saat ini, e.g. 1000)
         * Offset 16..19: 0 (Padding / Reserved)
         * Offset 20..  : Payload chunk data
         */
        memset(pkt, 0, 20);
        memcpy(pkt, "DLUM", 4);
        *(unsigned long *)(pkt + 4) = 0UL;
        *(unsigned long *)(pkt + 8) = (unsigned long)idx;
        *(unsigned long *)(pkt + 12) = (unsigned long)clen;
        *(unsigned long *)(pkt + 16) = 0UL;
        memcpy(pkt + 20, data + off, clen);

        sendto(s1, (char *)pkt, (int)(20 + clen), 0, (struct sockaddr *)&dst_mcast, sizeof(dst_mcast));
        sendto(s1, (char *)pkt, (int)(20 + clen), 0, (struct sockaddr *)&dst1, sizeof(dst1));
        sendto(s1, (char *)pkt, (int)(20 + clen), 0, (struct sockaddr *)&dst_sub, sizeof(dst_sub));
        if (g_cfg.use918) {
            sendto(s1, (char *)pkt, (int)(20 + clen), 0, (struct sockaddr *)&dst_mcast_918, sizeof(dst_mcast_918));
            sendto(s1, (char *)pkt, (int)(20 + clen), 0, (struct sockaddr *)&dst_918, sizeof(dst_918));
            sendto(s1, (char *)pkt, (int)(20 + clen), 0, (struct sockaddr *)&dst_918_sub, sizeof(dst_918_sub));
        }

        idx++;
        if (idx >= nchunk) {
            idx = 0;
            pass_count++;
            if (pass_count <= 5 || pass_count % 5 == 0) {
                logmsg("[WAPP] Pass #%d terkirim (%d paket). Menunggu ONT menyerap...", pass_count, nchunk);
            }
        }

        if (now - last_prog >= 200) {
            prog_local((int)((now - t0) * 100 / total_ms));
            last_prog = now;
        }

        int iv = g_cfg.interval;
        if (iv <= 0) { /* tanpa jeda */ }
        else if (iv >= 30) Sleep((DWORD)iv);
        else {
            int batch = 30 / iv;
            if (idx % batch == 0) Sleep((DWORD)(iv * batch));
        }
    }
    free(pkt);
    closesocket(s1);
    free(data);
    if (stopped) { logmsg("[WAPP] Broadcast %s dihentikan pengguna.", name); return 1; }
    prog_local(100);
    logmsg("[WAPP] Broadcast %s selesai (Total: %d pass terkirim).", name, pass_count);
    return 0;
}

/* --------------------- Listener balasan ONT --------------------- */
static DWORD WINAPI listener_thread(LPVOID p) {
    (void)p;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    struct sockaddr_in baddr;
    memset(&baddr, 0, sizeof(baddr));
    baddr.sin_family = AF_INET;
    baddr.sin_port = htons(819);
    baddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr *)&baddr, sizeof(baddr)) == SOCKET_ERROR) {
        closesocket(s);
        return 0;
    }

    char buf[2048];
    while (1) {
        struct sockaddr_in from;
        int fromlen = sizeof(from);
        int n = recvfrom(s, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fromlen);
        if (n > 0) {
            buf[n] = 0;
            if (strstr(buf, "Start upgrade")) {
                g_ont_started = 1;
                logmsg("[ONT-NOTIF] %s: Start upgrade! (Modem menerima firmware & mulai burning flash!)", inet_ntoa(from.sin_addr));
            } else if (strstr(buf, "Finish upgrade")) {
                g_ont_finished = 1;
                logmsg("[ONT-NOTIF] %s: Finish upgrade! (Flashing SELESAI 100%%, lampu modem akan naik semua!)", inet_ntoa(from.sin_addr));
            }
        }
    }
    closesocket(s);
    return 0;
}

/* =====================================================================
 * BAGIAN 2 - Telnet expect-based (pengganti .bat/VBS SendKeys)
 * Login FULL OTOMATIS: semua pasangan user:pass di daftar kredensial
 * dicoba satu per satu sampai berhasil.
 * ===================================================================== */
typedef struct { SOCKET s; char buf[8192]; int len; } Tn;

static int tn_connect(Tn *t, const char *ip) {
    t->len = 0;
    t->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (t->s == INVALID_SOCKET) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(23);
    a.sin_addr.s_addr = inet_addr(ip);
    if (connect(t->s, (struct sockaddr *)&a, sizeof(a)) == SOCKET_ERROR) {
        closesocket(t->s);
        t->s = INVALID_SOCKET;
        return -1;
    }
    return 0;
}
static void tn_close(Tn *t) {
    if (t->s != INVALID_SOCKET) closesocket(t->s);
    t->s = INVALID_SOCKET;
    t->len = 0;
}
static int tn_read_more(Tn *t, int timeout_ms) {
    fd_set rf; FD_ZERO(&rf); FD_SET(t->s, &rf);
    struct timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    int r = select(0, &rf, NULL, NULL, &tv);
    if (r <= 0) return 0;
    if (t->len > (int)sizeof(t->buf) - 1024) { memmove(t->buf, t->buf + 4096, t->len - 4096); t->len -= 4096; }
    int n = recv(t->s, t->buf + t->len, (int)sizeof(t->buf) - t->len - 1, 0);
    if (n <= 0) return -1;
    t->len += n;
    t->buf[t->len] = 0;
    return 1;
}
/* Tunggu sampai salah satu pola muncul. Return indeks pola / -1 timeout / -2 putus. */
static int tn_expect_any(Tn *t, const char **pats, int np, int timeout_ms) {
    DWORD end = GetTickCount() + (DWORD)timeout_ms;
    for (;;) {
        for (int i = 0; i < np; i++)
            if (pats[i] && strstr(t->buf, pats[i])) { t->len = 0; t->buf[0] = 0; return i; }
        if ((long)(GetTickCount() - end) >= 0) return -1;
        int slice = (int)(end - GetTickCount());
        if (slice > 250) slice = 250;
        if (slice < 0) slice = 0;
        int r = tn_read_more(t, slice);
        if (r < 0) return -2;
    }
}
static void tn_send(Tn *t, const char *s) {
    send(t->s, s, (int)strlen(s), 0);
}
/* Satu percobaan login di koneksi yang sudah tersambung. 0 = berhasil (prompt WAP). */
static int tn_try_login(Tn *t, const char *user, const char *pass) {
    const char *p_login[] = {"Login:", "login:", "Username:", "username:"};
    if (tn_expect_any(t, p_login, 4, 7000) < 0) return -1;
    char line[160];
    _snprintf(line, sizeof(line), "%s\r\n", user);
    tn_send(t, line);
    const char *p_pw[] = {"Password:", "password:"};
    if (tn_expect_any(t, p_pw, 2, 5000) < 0) return -1;
    _snprintf(line, sizeof(line), "%s\r\n", pass);
    tn_send(t, line);
    const char *p_res[] = {"WAP>", "incorrect", "Incorrect", "Invalid", "invalid", "ailed", "Login:", "login:"};
    int r = tn_expect_any(t, p_res, 8, 6000);
    return (r == 0) ? 0 : -1;
}
static int g_cred_hint = 0;
/* Login otomatis: putar semua kredensial (mulai dari yang terakhir berhasil). */
static int tn_login_auto(Tn *t) {
    int n = g_cfg.ncreds;
    for (int k = 0; k < n; k++) {
        int i = (g_cred_hint + k) % n;
        if (tn_connect(t, g_cfg.ip) != 0) {
            set_err("Tidak bisa terhubung ke %s:23.\nCek kabel LAN, IP modem, Windows Firewall, dan pastikan Telnet via LAN sudah diaktifkan di modem (Advanced > Firewall > Precision Device Control).", g_cfg.ip);
            logmsg("[TELNET] GAGAL connect ke %s:23", g_cfg.ip);
            return -1;
        }
        logmsg("[TELNET] Mencoba login %s (%d/%d)...", g_cfg.cred_user[i], k + 1, n);
        if (tn_try_login(t, g_cfg.cred_user[i], g_cfg.cred_pass[i]) == 0) {
            g_cred_hint = i;
            logmsg("[TELNET] Login berhasil: %s", g_cfg.cred_user[i]);
            /* naik ke su */
            tn_send(t, "su\r\n");
            const char *p_su[] = {"Password:", "password:", "WAP>"};
            int r = tn_expect_any(t, p_su, 3, 3000);
            if (r == 0 || r == 1) {
                char line[160];
                _snprintf(line, sizeof(line), "%s\r\n", g_cfg.cred_pass[i]);
                tn_send(t, line);
                tn_expect_any(t, p_su, 3, 2500);
            }
            return 0;
        }
        logmsg("[TELNET] Ditolak untuk user %s.", g_cfg.cred_user[i]);
        tn_close(t);
        Sleep(300);
    }
    set_err("Semua kredensial telnet ditolak ONT (%d pasangan dicoba).\nTambahkan pasangan user:pass yang benar di daftar kredensial, atau cek apakah Telnet LAN masih aktif.", n);
    logmsg("[TELNET] Semua kredensial gagal.");
    return -1;
}
static void tn_cmd(Tn *t, const char *cmd, int wait_ms) {
    if (stop_requested()) return;
    char line[1200];
    _snprintf(line, sizeof(line), "%s\r\n", cmd);
    logmsg("  >> %s", cmd);
    tn_send(t, line);
    DWORD end = GetTickCount() + (DWORD)wait_ms;
    while ((long)(GetTickCount() - end) < 0) {
        if (tn_read_more(t, 200) < 0) break;
    }
    if (t->len > 0) {
        char show[1500]; int j = 0;
        for (int i = 0; i < t->len && j < 1400; i++) {
            unsigned char c = (unsigned char)t->buf[i];
            if (c >= 32 && c < 127) show[j++] = (char)c;
            else if (c == '\n') show[j++] = ' ';
        }
        show[j] = 0;
        char *p = show;
        while (*p == ' ') p++;
        size_t L = strlen(p);
        while (L > 0 && p[L - 1] == ' ') p[--L] = 0;
        if (*p) logmsg("  << %.600s", p);
        t->len = 0; t->buf[0] = 0;
    }
}

/* ------------------------------ Langkah ------------------------------ */
static const struct { int mode; unsigned long id; const char *nama; } MODES[7] = {
    {4, 0x102001, "XPON"}, {1, 0x102001, "GPON"}, {2, 0x102001, "EPON"},
    {3, 0x1, "LAN 1 = WAN"}, {3, 0x2, "LAN 2 = WAN"}, {3, 0x3, "LAN 3 = WAN"}, {3, 0x4, "LAN 4 = WAN"}
};
static int step2(void) {
    Tn t;
    logmsg("[STEP2] Sesi A: EquipMode.sh on");
    if (tn_login_auto(&t) != 0) return -1;
    prog_local(20);
    tn_cmd(&t, "shell", 1500);
    tn_cmd(&t, "EquipMode.sh on", 2500);
    tn_cmd(&t, "exit", 800);
    tn_cmd(&t, "quit", 800);
    tn_close(&t);
    prog_local(45);
    if (stop_requested()) return 1;
    logmsg("[STEP2] Sesi B: restorehwmode + reboot");
    if (tn_login_auto(&t) != 0) return -1;
    prog_local(65);
    tn_cmd(&t, "shell", 1500);
    tn_cmd(&t, "sudo restorehwmode.sh", 4000);
    tn_cmd(&t, "restorehwmode.sh", 4000);
    prog_local(85);
    tn_cmd(&t, "reboot", 1000);
    tn_close(&t);
    prog_local(100);
    logmsg("[STEP2] Selesai - modem reboot.");
    return 0;
}
static int step4(void) {
    Tn t;
    const char *nama = MODES[g_cfg.mode_idx].nama;
    int mode_val = MODES[g_cfg.mode_idx].mode;
    logmsg("[STEP4] Set mode %s (mode=%d upportid=0x%lX) + Kunci Boardinfo NVRAM + EquipMode off + reboot",
           nama, mode_val, MODES[g_cfg.mode_idx].id);
    if (tn_login_auto(&t) != 0) return -1;
    prog_local(30);
    char c[512];
    _snprintf(c, sizeof(c), "set upport mode %d upportid 0x%lX",
              mode_val, MODES[g_cfg.mode_idx].id);
    tn_cmd(&t, c, 2000);
    prog_local(50);
    tn_cmd(&t, "shell", 1500);

    /* KUNCI KEBAL RESET DI HARDWARE BOARDINFO & OPTICAL BLINKING FIX (R019 - R023) */
    if (mode_val == 1) { /* GPON */
        _snprintf(c, sizeof(c),
            "cat /mnt/jffs2/hw_boardinfo | sed 's/obj.id = \"0x00000001\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000001\" ; obj.value = \"1\"/g' > /tmp/bi.tmp && "
            "cat /tmp/bi.tmp | sed 's/obj.id = \"0x00000059\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000059\" ; obj.value = \"1\"/g' > /mnt/jffs2/hw_boardinfo && "
            "rm -f /tmp/bi.tmp /mnt/jffs2/hw_boardinfo.bak /mnt/jffs2/vendor* /mnt/jffs2/optic_init_par.bin /dev/root && rm -rf /var/*");
        tn_cmd(&t, c, 1500);
        logmsg("[STEP4] Mode GPON dikunci. Vendor data & optic_init_par.bin dibersihkan (Anti-Blinking 2-5 Menit aktif).");
    } else if (mode_val == 2) { /* EPON */
        _snprintf(c, sizeof(c),
            "cat /mnt/jffs2/hw_boardinfo | sed 's/obj.id = \"0x00000001\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000001\" ; obj.value = \"2\"/g' > /tmp/bi.tmp && "
            "cat /tmp/bi.tmp | sed 's/obj.id = \"0x00000059\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000059\" ; obj.value = \"2\"/g' > /mnt/jffs2/hw_boardinfo && "
            "rm -f /tmp/bi.tmp /mnt/jffs2/hw_boardinfo.bak");
        tn_cmd(&t, c, 1500);
        logmsg("[STEP4] Mode EPON dikunci permanen di hw_boardinfo.");
    } else if (mode_val == 4) { /* XPON Auto Hybrid */
        _snprintf(c, sizeof(c),
            "cat /mnt/jffs2/hw_boardinfo | sed 's/obj.id = \"0x00000001\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000001\" ; obj.value = \"4\"/g' > /tmp/bi.tmp && "
            "cat /tmp/bi.tmp | sed 's/obj.id = \"0x00000059\" ; obj.value = \"[0-9]*\"/obj.id = \"0x00000059\" ; obj.value = \"4\"/g' > /mnt/jffs2/hw_boardinfo && "
            "echo 2 > /mnt/jffs2/xpon_mode && rm -f /tmp/bi.tmp /mnt/jffs2/hw_boardinfo.bak");
        tn_cmd(&t, c, 1500);
        logmsg("[STEP4] Mode XPON Auto Hybrid dikunci di hw_boardinfo & /mnt/jffs2/xpon_mode.");
    }

    /* Kunci Hardinfo Web Frame XGPON & MenuSmartAbroad */
    tn_cmd(&t, "set hardinfo value FT_WAN_ACCESS_IN_SECURITY=1;FT_WAN_ACCESS_SAVE_DB=1;AMP_FT_WIFI_PWD_SHOW=1;FT_UPPORT_MODE_GPON_EPON_ADAPT=1;SSMP_SPEC_WEB_FRAME=frame_XGPON;SSMP_SPEC_WEB_MENUXML=MenuSmartAbroad.xml;", 2000);

    prog_local(70);
    tn_cmd(&t, "EquipMode.sh off", 2500);
    prog_local(85);
    tn_cmd(&t, "reboot", 1000);
    tn_close(&t);
    prog_local(100);
    logmsg("[STEP4] Selesai - mode %s terkunci permanen, modem reboot.", nama);
    return 0;
}
static int step_reboot_only(void) {
    Tn t;
    logmsg("[REBOOT] Mengirim perintah reboot...");
    if (tn_login_auto(&t) != 0) return -1;
    tn_cmd(&t, "reboot", 1000);
    tn_close(&t);
    prog_local(100);
    logmsg("[REBOOT] Perintah terkirim.");
    return 0;
}
static int step_prov(void) {
    Tn t;
    logmsg("[PROV] Provisioning custom via wap cli...");
    if (tn_login_auto(&t) != 0) return -1;
    char c[640];
    const char *cmds_pre = "shell";
    tn_cmd(&t, cmds_pre, 1500);
    prog_local(8);
    struct { char buf[640]; } cmds[25];
    int n = 0;

    /* 1. Atur SSID & Password WiFi */
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wlan security ssid 1 name %s\"", g_cfg.ssid1);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wlan security ssid 1 key %s\"", g_cfg.wkey);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wlan security ssid 5 name %s\"", g_cfg.ssid5);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wlan security ssid 5 key %s\"", g_cfg.wkey);

    /* Format kompatibilitas firmware lawas */
    _snprintf(cmds[n++].buf, 640, "wap cli \"set ssid index 1 name %s visible 1 security WPA2-Personal password %s\"", g_cfg.ssid1, g_cfg.wkey);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set ssid index 5 name %s visible 1 security WPA2-Personal password %s\"", g_cfg.ssid5, g_cfg.wkey);

    /* 2. WAN Connection PPPoE */
    _snprintf(cmds[n++].buf, 640, "wap cli \"add wan conn name WAN_CUSTOM linktype ipoe_pppoe conntype tr069_internet vlanmode untag nat 1\"");
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wan conn name WAN_CUSTOM pppoe enable 1\"");
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wan conn name WAN_CUSTOM pppoe username %s password %s\"", g_cfg.pppuser, g_cfg.ppppass);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wan conn name WAN_CUSTOM pppoe dialmode auto\"");
    _snprintf(cmds[n++].buf, 640, "wap cli \"set wan conn name WAN_CUSTOM bindport lan1 1 lan2 1 lan3 1 lan4 1 ssid1 1\"");

    /* 3. TR-069 */
    _snprintf(cmds[n++].buf, 640, "wap cli \"set tr069 enable 1\"");
    _snprintf(cmds[n++].buf, 640, "wap cli \"set tr069 url %s\"", g_cfg.trurl);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set tr069 username %s password %s\"", g_cfg.truser, g_cfg.trpass);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set tr069 inform enable 1 interval %s\"", g_cfg.trinform);
    _snprintf(cmds[n++].buf, 640, "wap cli \"set tr069 connreq username %s password %s\"", g_cfg.cruser, g_cfg.crpass);

    for (int i = 0; i < n; i++) {
        tn_cmd(&t, cmds[i].buf, 1000);
        prog_local(8 + (i + 1) * 60 / n);
        if (stop_requested()) { tn_close(&t); return 1; }
    }

    if (g_cfg.wanaccess) {
        const char *fw[5] = {"http", "https", "telnet", "ftp", "icmp"};
        for (int i = 0; i < 5; i++) {
            _snprintf(c, sizeof(c), "wap cli \"set firewall wanaccess %s enable 1\"", fw[i]);
            tn_cmd(&t, c, 800);
        }
        logmsg("[PROV] WAN access dibuka (http/https/telnet/ftp/icmp).");
    }

    /* 4. Unlock China Mode & Plaintext Password */
    tn_cmd(&t, "echo 'feature.name = \"HW_SSMP_FEATURE_CLI_CHINA_MODE\" feature.enable=\"1\" feature.attribute=\"1\";' > /mnt/jffs2/hw_hardinfo_feature", 500);
    tn_cmd(&t, "echo 'feature.name=\"AMP_FT_REMOTE_IP_WIFI_PWD_SHOW\" feature.enable=\"1\";' >> /mnt/jffs2/hw_hardinfo_feature", 500);
    tn_cmd(&t, "echo 'feature.name = \"AMP_FT_WIFI_PWD_SHOW\" feature.enable=\"1\"' >> /mnt/jffs2/hw_hardinfo_feature", 500);

    /* 5. KUNCI KEBAL RESET FISIK (CLONE KE hw_default_ctree.xml) */
    logmsg("[PROV] Mengunci konfigurasi ke /mnt/jffs2/hw_default_ctree.xml (100%% KEBAL RESET FISIK)...");
    tn_cmd(&t, "cp -rf /mnt/jffs2/hw_ctree.xml /mnt/jffs2/hw_default_ctree.xml", 1500);
    tn_cmd(&t, "sync", 1000);

    prog_local(95);
    tn_cmd(&t, "exit", 700);
    tn_cmd(&t, "quit", 700);
    if (g_cfg.provreboot) {
        logmsg("[PROV] Reboot sesuai centang...");
        if (tn_login_auto(&t) == 0) { tn_cmd(&t, "reboot", 1000); tn_close(&t); }
    } else tn_close(&t);
    prog_local(100);
    logmsg("[PROV] Provisioning selesai. Modem sekarang 100%% KEBAL RESET FISIK!");
    return 0;
}
/* ------------------- Custom Info / Device Alias ------------------- */
static void sanitize_brand(char *s) {
    int j = 0;
    for (int i = 0; s[i] && j < 40; i++) {
        char c = s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == ' ' || c == '.' || c == '_' || c == '-')
            s[j++] = c;
    }
    s[j] = 0;
    while (j > 0 && s[j - 1] == ' ') s[--j] = 0;
}
static int step_custominfo(void) {
    Tn t;
    char info[64], det[64], c[640];
    strncpy(info, g_cfg.cinfo, 63); info[63] = 0; sanitize_brand(info);
    strncpy(det, g_cfg.cdetail, 63); det[63] = 0; sanitize_brand(det);
    if (!info[0]) { set_err("Field Custom Info masih kosong."); logmsg("[BRAND] Custom Info kosong - batal."); return -1; }
    if (!det[0]) { strncpy(det, info, 63); det[63] = 0; }
    logmsg("[BRAND] Menanam customInfo=\"%s\" customInfoDetail=\"%s\"...", info, det);
    if (tn_login_auto(&t) != 0) return -1;
    prog_local(30);
    tn_cmd(&t, "shell", 1500);
    _snprintf(c, sizeof(c),
        "sed -i 's/customInfo=\"[^\"]*\"/customInfo=\"%s\"/g; s/customInfoDetail=\"[^\"]*\"/customInfoDetail=\"%s\"/g' /mnt/jffs2/hw_ctree.xml",
        info, det);
    tn_cmd(&t, c, 1500);
    prog_local(55);
    _snprintf(c, sizeof(c),
        "[ -f /mnt/jffs2/hw_default_ctree.xml ] && sed -i 's/customInfo=\"[^\"]*\"/customInfo=\"%s\"/g; s/customInfoDetail=\"[^\"]*\"/customInfoDetail=\"%s\"/g' /mnt/jffs2/hw_default_ctree.xml; echo TANAM-SELESAI",
        info, det);
    tn_cmd(&t, c, 1500);
    prog_local(75);
    tn_cmd(&t, "grep -o 'customInfo=\"[^\"]*\"' /mnt/jffs2/hw_ctree.xml | head -1", 1500);
    tn_cmd(&t, "exit", 600);
    tn_cmd(&t, "quit", 600);
    tn_close(&t);
    prog_local(100);
    logmsg("[BRAND] Selesai. Nilai tampil di info perangkat (web/ACS).");
    return 0;
}

static int step_web_red(void) {
    Tn t;
    logmsg("[TEMA] Mengubah Web GUI ke MERAH (Huawei Engineering) + Unlock Downgrade Limit...");
    logmsg("[TEMA] Kompatibel: R019, R020, R021, R022, hingga R023.");
    if (tn_login_auto(&t) != 0) return -1;
    prog_local(30);
    tn_cmd(&t, "su", 1000);
    prog_local(60);
    tn_cmd(&t, "set hardinfo value FT_FACTORY_DOWNGRADE_LIMIT=0;SSMP_SPEC_WEB_FRAME=frame_huawei;SSMP_SPEC_WEB_MENUXML=MenuAbroad.xml;", 2000);
    prog_local(85);
    tn_cmd(&t, "reset", 1000);
    tn_close(&t);
    prog_local(100);
    logmsg("[TEMA] Selesai! Modem sedang reboot. Web GUI berubah MERAH dan menu Software Upgrade terbuka.");
    return 0;
}

static int step_web_blue(void) {
    Tn t;
    logmsg("[TEMA] Mengembalikan Web GUI ke BIRU (Smart XGPON) + Menu Global...");
    logmsg("[TEMA] Kompatibel: R019, R020, R021, R022, hingga R023.");
    if (tn_login_auto(&t) != 0) return -1;
    prog_local(30);
    tn_cmd(&t, "su", 1000);
    prog_local(60);
    tn_cmd(&t, "set hardinfo value FT_WAN_ACCESS_IN_SECURITY=1;FT_WAN_ACCESS_SAVE_DB=1;AMP_FT_WIFI_PWD_SHOW=1;FT_UPPORT_MODE_GPON_EPON_ADAPT=1;SSMP_SPEC_WEB_FRAME=frame_XGPON;SSMP_SPEC_WEB_MENUXML=MenuSmartAbroad.xml;", 2000);
    prog_local(85);
    tn_cmd(&t, "reset", 1000);
    tn_close(&t);
    prog_local(100);
    logmsg("[TEMA] Selesai! Modem sedang reboot. Web GUI berubah BIRU XGPON modern dengan menu WAN lengkap.");
    return 0;
}

/* =====================================================================
 * BAGIAN 3 - Orkestrasi worker + gerbang power cycle
 * ===================================================================== */
enum { ACT_FLASH1 = 1, ACT_FLASH2, ACT_FLASH3, ACT_STEP2, ACT_STEP4,
       ACT_PROV, ACT_REBOOT, ACT_FULL, ACT_CINFO, ACT_WEB_RED, ACT_WEB_BLUE };

static void ui_running(int on) {
    HWND btns[] = {hBtnFlash1, hBtnFlash2, hBtnFlash3, hBtnStep2, hBtnStep4,
                   hBtnReboot, hBtnProv, hBtnFull, hBtnCI, hBtnWebRed, hBtnWebBlue};
    for (unsigned i = 0; i < sizeof(btns) / sizeof(btns[0]); i++)
        if (btns[i]) EnableWindow(btns[i], !on);
    if (hBtnStop) EnableWindow(hBtnStop, on);
    if (!on && hBtnLanjut) EnableWindow(hBtnLanjut, FALSE);
}
/* Tunggu klik LANJUT (gerbang power cycle). 0 = lanjut, 1 = stop. */
static int gate_wait(const char *pesan) {
    logmsg("[JEDA] %s", pesan);
    logmsg("[JEDA] Setelah modem nyala lagi, klik tombol LANJUT.");
    ResetEvent(g_hGateEvt);
    PostMessage(g_hwnd, WM_APP + 2, 1, 0);
    HANDLE ev[2] = {g_hGateEvt, g_hStopEvt};
    DWORD r = WaitForMultipleObjects(2, ev, FALSE, INFINITE);
    PostMessage(g_hwnd, WM_APP + 2, 0, 0);
    if (r == WAIT_OBJECT_0 + 1) { logmsg("[JEDA] Dibatalkan pengguna."); return 1; }
    logmsg("[JEDA] Melanjutkan...");
    Sleep(1500);
    return 0;
}
static DWORD WINAPI worker_thread(LPVOID param) {
    int act = (int)(INT_PTR)param;
    int r = 0;
    g_lasterr[0] = 0;
    switch (act) {
    case ACT_FLASH1:
        prog_range(0, 100);
        logmsg("=== FLASH R020 (STEP 1) ===");
        r = broadcast_file(g_cfg.bin1);
        break;
    case ACT_FLASH2:
        prog_range(0, 100);
        logmsg("=== FLASH Permanen.bin (STEP 3) — status FAILED di akhir = WAJAR ===");
        r = broadcast_file(g_cfg.bin2);
        break;
    case ACT_FLASH3:
        prog_range(0, 100);
        logmsg("=== FLASH Preset.bin (STEP 3) ===");
        r = broadcast_file(g_cfg.bin3);
        break;
    case ACT_STEP2:  prog_range(0, 100); r = step2(); break;
    case ACT_STEP4:  prog_range(0, 100); r = step4(); break;
    case ACT_PROV:   prog_range(0, 100); r = step_prov(); break;
    case ACT_REBOOT: prog_range(0, 100); r = step_reboot_only(); break;
    case ACT_CINFO:  prog_range(0, 100); r = step_custominfo(); break;
    case ACT_WEB_RED:  prog_range(0, 100); r = step_web_red(); break;
    case ACT_WEB_BLUE: prog_range(0, 100); r = step_web_blue(); break;
    case ACT_FULL:
        logmsg("================ FULL RUN ================");
        prog_range(0, 18);
        logmsg("=== STEP 1: Flash R020 ===");
        r = broadcast_file(g_cfg.bin1);
        if (r == 0) r = gate_wait("Power cycle modem sekarang (matikan, tunggu 5 detik, nyalakan).");
        if (r == 0) { prog_range(18, 32); logmsg("=== STEP 2: Telnet EquipMode + Restore ==="); r = step2(); }
        if (r == 0) r = gate_wait("Modem sedang reboot dari Step 2. Tunggu sampai nyala stabil.");
        if (r == 0) { prog_range(32, 48); logmsg("=== STEP 3a: Flash Permanen (FAILED = wajar) ==="); r = broadcast_file(g_cfg.bin2); }
        if (r == 0) r = gate_wait("Power cycle modem sekarang.");
        if (r == 0) { prog_range(48, 64); logmsg("=== STEP 3b: Flash Preset ==="); r = broadcast_file(g_cfg.bin3); }
        if (r == 0) r = gate_wait("Power cycle modem sekarang.");
        if (r == 0) { prog_range(64, 78); logmsg("=== STEP 4: Set Mode + EquipMode OFF ==="); r = step4(); }
        if (r == 0) r = gate_wait("Modem sedang reboot dari Step 4. Tunggu sampai nyala stabil.");
        if (r == 0) { prog_range(78, 97); logmsg("=== STEP 5: Provisioning Custom ==="); r = step_prov(); }
        if (r == 0) {
            prog_range(100, 100); prog_local(100);
            logmsg("================ FULL RUN SELESAI ================");
            logmsg("Sisa manual: upload XML final via web (POST_STEP4) bila perlu.");
        }
        break;
    }
    if (r == 1 || stop_requested()) logmsg("[INFO] Proses dihentikan.");
    else if (r != 0) {
        logmsg("[ERROR] Proses gagal. Lihat popup / baris log di atas.");
        char *e = _strdup(g_lasterr[0] ? g_lasterr
                                       : "Proses gagal tanpa keterangan. Detail ada di log.");
        PostMessage(g_hwnd, WM_ERRPOP, 0, (LPARAM)e);
    }
    g_running = 0;
    PostMessage(g_hwnd, WM_APP + 3, 0, 0);
    return 0;
}

/* --------------------------- Persistensi INI --------------------------- */
static char g_ini[MAX_PATH];
static void ini_path(void) {
    char dir[MAX_PATH];
    GetModuleFileName(NULL, dir, MAX_PATH);
    char *s = strrchr(dir, '\\'); if (s) *s = 0;
    _snprintf(g_ini, MAX_PATH, "%s\\alinos_flashtool.ini", dir);
}
static void save_ini(void) {
    struct { HWND h; const char *k; } t[] = {
        {hIp, "ip"}, {hGroup, "group"}, {hPort, "port"},
        {hPkSize, "pksize"}, {hInterval, "interval"}, {hDurasi, "durasi"},
        {hBin1, "bin1"}, {hBin2, "bin2"}, {hBin3, "bin3"},
        {hPppUser, "pppuser"}, {hPppPass, "ppppass"}, {hSsid1, "ssid1"},
        {hSsid5, "ssid5"}, {hWkey, "wkey"}, {hTrUrl, "trurl"}, {hTrUser, "truser"},
        {hTrPass, "trpass"}, {hTrInform, "trinform"}, {hCrUser, "cruser"}, {hCrPass, "crpass"},
        {hCInfo, "cinfo"}, {hCDetail, "cdetail"}
    };
    char buf[1024];
    for (unsigned i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        if (!t[i].h) continue;
        GetWindowText(t[i].h, buf, sizeof(buf));
        WritePrivateProfileString("alinos", t[i].k, buf, g_ini);
    }
    WritePrivateProfileString("alinos", "adapter", g_cfg.adapter, g_ini);
    /* kredensial: gabung baris dengan '|' */
    if (hCreds) {
        GetWindowText(hCreds, buf, sizeof(buf));
        for (int i = 0; buf[i]; i++) if (buf[i] == '\n' || buf[i] == '\r') buf[i] = '|';
        char clean[1024]; int j = 0, prevbar = 1;
        for (int i = 0; buf[i] && j < 1000; i++) {
            if (buf[i] == '|') { if (prevbar) continue; prevbar = 1; }
            else prevbar = 0;
            clean[j++] = buf[i];
        }
        while (j > 0 && clean[j - 1] == '|') j--;
        clean[j] = 0;
        WritePrivateProfileString("alinos", "creds", clean, g_ini);
    }
    if (hChk918) WritePrivateProfileString("alinos", "use918", chk(hChk918) ? "1" : "0", g_ini);
    if (hChkWan) WritePrivateProfileString("alinos", "wanaccess", chk(hChkWan) ? "1" : "0", g_ini);
    if (hChkReboot) WritePrivateProfileString("alinos", "provreboot", chk(hChkReboot) ? "1" : "0", g_ini);
    if (hMode) {
        _snprintf(buf, sizeof(buf), "%d", (int)SendMessage(hMode, CB_GETCURSEL, 0, 0));
        WritePrivateProfileString("alinos", "mode", buf, g_ini);
    }
}
static void load_ini(void) {
    const char *base = "C:\\";
    struct { HWND h; const char *k; const char *def; } t[] = {
        {hIp, "ip", "192.168.100.1"},
        {hGroup, "group", "255.255.255.255"}, {hPort, "port", "4891"},
        {hPkSize, "pksize", "1000"}, {hInterval, "interval", "2"}, {hDurasi, "durasi", "60"},
        {hPppUser, "pppuser", "testmodem21"}, {hPppPass, "ppppass", "testmodem21"},
        {hSsid1, "ssid1", "ALINOSNET"}, {hSsid5, "ssid5", "ALINOSNET_5G"},
        {hWkey, "wkey", "eeeeeeee"}, {hTrUrl, "trurl", "http://ont.alinos-dashboard.my.id"},
        {hTrUser, "truser", "admin"}, {hTrPass, "trpass", "ALINOSNET21"},
        {hTrInform, "trinform", "600"}, {hCrUser, "cruser", "admin"}, {hCrPass, "crpass", "ALINOSNET21"},
        {hCInfo, "cinfo", "ALINOSNET"}, {hCDetail, "cdetail", "alinosnet"}
    };
    char buf[1024];
    for (unsigned i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
        if (!t[i].h) continue;
        GetPrivateProfileString("alinos", t[i].k, t[i].def, buf, sizeof(buf), g_ini);
        SetWindowText(t[i].h, buf);
    }
    char saved_adp[64] = "0.0.0.0";
    GetPrivateProfileString("alinos", "adapter", "0.0.0.0", saved_adp, sizeof(saved_adp), g_ini);
    scan_network_adapters(saved_adp);
    char exe_dir[MAX_PATH];
    GetModuleFileName(NULL, exe_dir, MAX_PATH);
    char *sl = strrchr(exe_dir, '\\'); if (sl) *sl = 0;
    struct { HWND h; const char *k; const char *fname; } b[] = {
        {hBin1, "bin1", "R020.bin"}, {hBin2, "bin2", "Permanen.bin"}, {hBin3, "bin3", "Preset.bin"}
    };
    for (unsigned i = 0; i < sizeof(b) / sizeof(b[0]); i++) {
        if (!b[i].h) continue;
        char def[MAX_PATH];
        _snprintf(def, MAX_PATH, "%s\\%s", exe_dir, b[i].fname);
        FILE *chk = fopen(def, "rb");
        if (chk) { fclose(chk); }
        else {
            _snprintf(def, MAX_PATH, "%s\\..\\firmware\\%s", exe_dir, b[i].fname);
            chk = fopen(def, "rb");
            if (chk) { fclose(chk); }
            else {
                _snprintf(def, MAX_PATH, "%s\\firmware\\%s", exe_dir, b[i].fname);
                chk = fopen(def, "rb");
                if (chk) { fclose(chk); }
                else {
                    _snprintf(def, MAX_PATH, "%s\\%s", exe_dir, b[i].fname);
                }
            }
        }
        GetPrivateProfileString("alinos", b[i].k, def, buf, sizeof(buf), g_ini);
        SetWindowText(b[i].h, buf);
    }
    (void)base;
    /* kredensial: '|' kembali jadi baris baru */
    GetPrivateProfileString("alinos", "creds",
        "root:admin|root:adminHW|root:a1234567|root:admin123|Epadmin:adminEp|telecomadmin:admintelecom|admin:admin|admin:adminHW",
        buf, sizeof(buf), g_ini);
    {
        char disp[1536]; int j = 0;
        for (int i = 0; buf[i] && j < 1500; i++) {
            if (buf[i] == '|') { disp[j++] = '\r'; disp[j++] = '\n'; }
            else disp[j++] = buf[i];
        }
        disp[j] = 0;
        SetWindowText(hCreds, disp);
    }
    SendMessage(hChk918, BM_SETCHECK, GetPrivateProfileInt("alinos", "use918", 1, g_ini) ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(hChkWan, BM_SETCHECK, GetPrivateProfileInt("alinos", "wanaccess", 0, g_ini) ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessage(hChkReboot, BM_SETCHECK, GetPrivateProfileInt("alinos", "provreboot", 0, g_ini) ? BST_CHECKED : BST_UNCHECKED, 0);
    int md = GetPrivateProfileInt("alinos", "mode", 0, g_ini);
    if (md < 0 || md > 6) md = 0;
    SendMessage(hMode, CB_SETCURSEL, md, 0);
    g_log_open = GetPrivateProfileInt("alinos", "logopen", 1, g_ini) ? 1 : 0;
}

/* =====================================================================
 * BAGIAN 4 - GUI v1.3
 * Prinsip desain (anti-slop): grid spasi 8px, palet terbatas (navy +
 * netral + 1 aksen sky), radius konsisten (kartu 8, tombol 8),
 * header solid tanpa gradien, hierarki lewat bobot font & spasi.
 * ===================================================================== */
#define COL_BG     RGB(15, 18, 24)
#define COL_CARD   RGB(25, 30, 40)
#define COL_CARDBR RGB(48, 58, 76)
#define COL_FIELD  RGB(17, 21, 28)
#define COL_HEAD   RGB(20, 24, 32)
#define COL_TXT    RGB(243, 244, 246)
#define COL_MUTED  RGB(156, 163, 175)
#define COL_ACCENT RGB(245, 158, 11)
#define COL_BTNF   RGB(35, 42, 56)
#define COL_LOGBG  RGB(11, 13, 17)
#define COL_LOGTX  RGB(74, 222, 128)

static HFONT g_font, g_fontMini, g_fontLog, g_fontBrand, g_fontTitle, g_fontBtn;
static HBRUSH g_brBg, g_brField, g_brLog, g_brBtn, g_brCard;
static HWND hBtnLogSave, hBtnLogCopy, hBtnLogClear;
static HWND g_muted[96];
static int g_nmuted = 0;

typedef struct { int x, y, w, h; const char *title; } Card;
static Card g_cards[8];
static const char *CARD_TITLES[8] = {
    "PENGATURAN KONEKSI & FLASHER",
    "STEP 1 - FLASH R020.BIN",
    "STEP 2 - EQUIPMODE + RESTORE",
    "STEP 3 - FLASH PERMANEN + PRESET",
    "STEP 4 - KUNCI MODE PON",
    "STEP 5 - PROVISI ALINOSNET",
    "STEP 6 - BRANDING ONT",
    ""
};

static HWND mk(const char *cls, const char *txt, DWORD style, int id) {
    HWND c = CreateWindow(cls, txt, WS_CHILD | WS_VISIBLE | style, 0, 0, 10, 10,
                          g_hwnd, (HMENU)(INT_PTR)id, NULL, NULL);
    SendMessage(c, WM_SETFONT, (WPARAM)g_font, TRUE);
    return c;
}
static HWND lbl(const char *t) { return mk("STATIC", t, 0, 0); }
static HWND mlbl(const char *t) {
    HWND c = mk("STATIC", t, 0, 0);
    SendMessage(c, WM_SETFONT, (WPARAM)g_fontMini, TRUE);
    if (g_nmuted < 96) g_muted[g_nmuted++] = c;
    return c;
}
static HWND edt(int id, int pass) {
    return mk("EDIT", "", WS_BORDER | ES_AUTOHSCROLL | (pass ? ES_PASSWORD : 0), id);
}
static HWND btn(const char *t, int id) { return mk("BUTTON", t, BS_OWNERDRAW, id); }
static HWND obtn(const char *t, int id) {
    HWND c = mk("BUTTON", t, BS_OWNERDRAW, id);
    SendMessage(c, WM_SETFONT, (WPARAM)g_fontBtn, TRUE);
    return c;
}
static WNDPROC g_oldChkProc = NULL;

static LRESULT CALLBACK CheckSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc; GetClientRect(hWnd, &rc);

        /* Fill background with Card color */
        HBRUSH brCard = CreateSolidBrush(COL_CARD);
        FillRect(hdc, &rc, brCard);
        DeleteObject(brCard);

        int checked = (SendMessage(hWnd, BM_GETCHECK, 0, 0) == BST_CHECKED);

        /* Draw check box square (14x14) */
        int boxY = (rc.bottom - rc.top - 14) / 2;
        RECT boxRc = { rc.left + 1, boxY, rc.left + 15, boxY + 14 };

        HBRUSH brBox = CreateSolidBrush(COL_FIELD);
        HPEN penBox = CreatePen(PS_SOLID, 1, checked ? COL_ACCENT : COL_CARDBR);
        HGDIOBJ oldBr = SelectObject(hdc, brBox);
        HGDIOBJ oldPen = SelectObject(hdc, penBox);
        RoundRect(hdc, boxRc.left, boxRc.top, boxRc.right, boxRc.bottom, 3, 3);

        if (checked) {
            /* Crisp amber checkmark */
            HPEN penChk = CreatePen(PS_SOLID, 2, COL_ACCENT);
            HGDIOBJ oldChkPen = SelectObject(hdc, penChk);
            MoveToEx(hdc, boxRc.left + 3, boxRc.top + 7, NULL);
            LineTo(hdc, boxRc.left + 6, boxRc.top + 10);
            LineTo(hdc, boxRc.left + 11, boxRc.top + 3);
            SelectObject(hdc, oldChkPen);
            DeleteObject(penChk);
        }

        SelectObject(hdc, oldBr);
        SelectObject(hdc, oldPen);
        DeleteObject(brBox);
        DeleteObject(penBox);

        /* Draw text in crisp white COL_TXT */
        char txt[128] = "";
        GetWindowText(hWnd, txt, sizeof(txt));
        if (txt[0]) {
            RECT txtRc = rc;
            txtRc.left += 20;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COL_TXT);
            HFONT f = (HFONT)SendMessage(hWnd, WM_GETFONT, 0, 0);
            HGDIOBJ oldF = SelectObject(hdc, f ? f : g_fontMini);
            DrawText(hdc, txt, -1, &txtRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            SelectObject(hdc, oldF);
        }

        EndPaint(hWnd, &ps);
        return 0;
    }
    return CallWindowProc(g_oldChkProc, hWnd, uMsg, wParam, lParam);
}

static HWND chkb(const char *t, int id) {
    HWND c = mk("BUTTON", t, BS_AUTOCHECKBOX, id);
    SendMessage(c, WM_SETFONT, (WPARAM)g_fontMini, TRUE);
    if (!g_oldChkProc) {
        g_oldChkProc = (WNDPROC)GetWindowLongPtr(c, GWLP_WNDPROC);
    }
    SetWindowLongPtr(c, GWLP_WNDPROC, (LONG_PTR)CheckSubclassProc);
    return c;
}
static void mv(HWND c, int x, int y, int w, int h) {
    if (c) SetWindowPos(c, NULL, x, y, w, h, SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS);
}

/* ------------------------- Mesin layout ------------------------- */
static HWND hBrw1, hBrw2, hBrw3;
static HWND L_IP, L_ADP, L_GRP, L_PRT, L_PKS, L_ITV, L_DUR, L_CRD, H_CRD, H_NOTE, L_S2D, L_PRM, L_PRS, L_CI, L_CD, L_S4N;
static HWND L_PV[11];
static HWND hBtnLogToggle, hBtnLogOpen;

static void do_layout(int W, int H) {
    const int M = 12, G = 8;
    if (W < 400 || H < 400) return;
    int logW = g_log_open ? (W >= 1250 ? (W * 34 / 100) : (W >= 1050 ? 360 : 320)) : 0;
    if (logW > 480) logW = 480;
    int paneW = W - 2 * M - (g_log_open ? (logW + G) : 0);
    if (paneW < 560 && g_log_open) {
        logW = W - 2 * M - G - 560;
        if (logW < 260) logW = 0;
        paneW = W - 2 * M - (logW > 0 ? (logW + G) : 0);
    }
    int colLW = (paneW - G) * 48 / 100;
    int colRW = paneW - G - colLW;
    int lx = M, rx = M + colLW + G;

    int stepsY = 186;
    g_cards[0] = (Card){M, 46, paneW, 132, CARD_TITLES[0]};
    g_cards[1] = (Card){lx, stepsY, colLW, 78, CARD_TITLES[1]};
    g_cards[2] = (Card){lx, stepsY + 84, colLW, 62, CARD_TITLES[2]};
    g_cards[3] = (Card){lx, stepsY + 152, colLW, 118, CARD_TITLES[3]};
    g_cards[4] = (Card){lx, stepsY + 276, colLW, 82, CARD_TITLES[4]};

    g_cards[5] = (Card){rx, stepsY, colRW, 268, CARD_TITLES[5]};
    g_cards[6] = (Card){rx, stepsY + 274, colRW, 84, CARD_TITLES[6]};

    int runY = stepsY + 368; /* 554 */
    int leftTotalH = runY + 62; /* 616 */

    int logH = (H - 58 > leftTotalH - 46) ? (H - 58) : (leftTotalH - 46);
    g_cards[7] = (Card){M + paneW + G, 46, logW, logH, ""};
    Card *k = &g_cards[0], *s1 = &g_cards[1], *s2 = &g_cards[2], *s3 = &g_cards[3],
         *s4 = &g_cards[4], *s5 = &g_cards[5], *s6 = &g_cards[6], *lg = &g_cards[7];

    /* --- Koneksi baris A: IP / Adapter / Scan / Grup / Port --- */
    int yA = k->y + 24;
    int cx = k->x + 14;

    /* IP Modem */
    mv(L_IP, cx, yA + 3, 58, 16);
    mv(hIp, cx + 58, yA, 96, 22);
    cx += 58 + 96 + 12;

    /* Sisi kanan: Port & Grup */
    int portW = 44, grpW = 98;
    int rxEnd = k->x + k->w - 14;

    mv(L_PRT, rxEnd - portW - 30, yA + 3, 28, 16);
    mv(hPort, rxEnd - portW, yA, portW, 22);

    int grpX = rxEnd - portW - 30 - 10 - grpW;
    mv(L_GRP, grpX - 36, yA + 3, 34, 16);
    mv(hGroup, grpX, yA, grpW, 22);

    /* Area tengah: Adapter Label + ComboBox + Tombol Scan */
    int adpRight = grpX - 36 - 12;
    int scanBtnW = 46;
    mv(L_ADP, cx, yA + 3, 50, 16);
    cx += 50;
    int adpW = adpRight - cx - scanBtnW - 6;
    if (adpW < 120) adpW = 120;
    mv(hAdapter, cx, yA, adpW, 140);
    mv(hBtnScanAdp, cx + adpW + 6, yA, scanBtnW, 22);

    /* --- Koneksi baris B: opsi broadcast + Live Device Detection Badge --- */
    int yB = k->y + 50; cx = k->x + 14;
    mv(hChk918, cx, yB + 1, 140, 20);                                   cx += 140 + 8;
    mv(L_PKS, cx, yB + 3, 42, 16); mv(hPkSize, cx + 42, yB, 42, 22);   cx += 42 + 42 + 8;
    mv(L_ITV, cx, yB + 3, 44, 16); mv(hInterval, cx + 44, yB, 34, 22); cx += 44 + 34 + 8;
    mv(L_DUR, cx, yB + 3, 40, 16); mv(hDurasi, cx + 40, yB, 34, 22);   cx += 40 + 34 + 12;

    int devStatusW = k->x + k->w - 14 - cx;
    if (devStatusW < 120) devStatusW = 120;
    mv(hDevStatus, cx, yB + 3, devStatusW, 18);

    /* --- Koneksi baris C: kredensial --- */
    mv(L_CRD, k->x + 14, k->y + 78, 120, 36);
    int credsW = (k->w - 148) * 62 / 100;
    if (credsW < 220) credsW = 220;
    mv(hCreds, k->x + 138, k->y + 74, credsW, 48);
    int hcrdX = k->x + 138 + credsW + 12;
    int hcrdW = k->x + k->w - 14 - hcrdX;
    if (hcrdW < 120) hcrdW = 120;
    mv(H_CRD, hcrdX, k->y + 80, hcrdW, 36);

    /* --- Step 1 --- */
    mv(hBin1, s1->x + 14, s1->y + 22, colLW - 28, 22);
    mv(hBrw1, s1->x + s1->w - 14 - 110 - 6 - 64, s1->y + 48, 64, 22);
    mv(hBtnFlash1, s1->x + s1->w - 14 - 110, s1->y + 48, 110, 22);

    /* --- Step 2 --- */
    mv(L_S2D, s2->x + 14, s2->y + 30, colLW - 170, 18);
    mv(hBtnStep2, s2->x + s2->w - 14 - 150, s2->y + 23, 150, 26);

    /* --- Step 3 --- */
    mv(L_PRM, s3->x + 14, s3->y + 23, 58, 16);
    mv(hBin2, s3->x + 14 + 60, s3->y + 20, colLW - 60 - 28, 22);
    mv(hBrw2, s3->x + s3->w - 14 - 72 - 6 - 56, s3->y + 44, 56, 22);
    mv(hBtnFlash2, s3->x + s3->w - 14 - 72, s3->y + 44, 72, 22);
    mv(L_PRS, s3->x + 14, s3->y + 69, 58, 16);
    mv(hBin3, s3->x + 14 + 60, s3->y + 66, colLW - 60 - 28, 22);
    mv(hBrw3, s3->x + s3->w - 14 - 72 - 6 - 56, s3->y + 90, 56, 22);
    mv(hBtnFlash3, s3->x + s3->w - 14 - 72, s3->y + 90, 72, 22);

    /* --- Step 4 --- */
    int modeW = colLW - 154; if (modeW < 100) modeW = 100;
    mv(hMode, s4->x + 14, s4->y + 22, modeW, 120);
    mv(hBtnStep4, s4->x + colLW - 14 - 116, s4->y + 21, 116, 25);
    mv(hBtnReboot, s4->x + 14, s4->y + 50, 72, 23);
    mv(L_S4N, s4->x + 92, s4->y + 54, (colLW - 106 > 50 ? colLW - 106 : 50), 16);

    /* --- Step 5 --- */
    int cellW = (colRW - 28 - G) / 2; if (cellW < 80) cellW = 80;
    HWND flds[12] = {hPppUser, hPppPass, hSsid1, hSsid5, hWkey, hTrUrl,
                     hTrUser, hTrPass, hTrInform, hCrUser, hCrPass, hChkWan};
    for (int i = 0; i < 12; i++) {
        int r = i / 2, c = i % 2;
        int fx = s5->x + 14 + c * (cellW + G);
        int baseY = s5->y + 22 + r * 33;
        if (i < 11) mv(L_PV[i], fx, baseY, cellW, 13);
        if (flds[i] == hChkWan) mv(flds[i], fx, baseY + 15, cellW, 20);
        else mv(flds[i], fx, baseY + 14, cellW, 20);
    }
    int provBtnW = (colRW - 28) * 48 / 100; if (provBtnW < 150) provBtnW = 150;
    mv(hBtnProv, s5->x + 14, s5->y + 232, provBtnW, 26);
    mv(hChkReboot, s5->x + 14 + provBtnW + 8, s5->y + 235, colRW - 28 - provBtnW - 8, 20);

    /* --- Step 6: Branding & Tema Web (Merah/Biru) --- */
    mv(L_CI, s6->x + 14, s6->y + 24, 68, 16);
    int ciW = colRW - 84 - 14 - 76; if (ciW < 70) ciW = 70;
    mv(hCInfo, s6->x + 84, s6->y + 21, ciW, 22);
    mv(hBtnCI, s6->x + s6->w - 14 - 72, s6->y + 20, 72, 24);

    int btnTemaW = (colRW - 28 - 8) / 2;
    mv(hBtnWebRed, s6->x + 14, s6->y + 50, btnTemaW, 26);
    mv(hBtnWebBlue, s6->x + 14 + btnTemaW + 8, s6->y + 50, btnTemaW, 26);

    /* --- Action Dock --- */
    mv(hBtnFull, M, runY, 230, 34);
    mv(hBtnLanjut, M + 238, runY, 94, 34);
    mv(hBtnStop, M + 340, runY, 94, 34);
    mv(hBtnUpdate, W - 16 - 150 - 78, 11, 74, 26);

    int progX = M + 444;
    int progRight = M + paneW;
    if (!g_log_open) {
        progRight -= 72;
        mv(hBtnLogOpen, M + paneW - 64, runY + 3, 64, 28);
    }
    int progW = progRight - progX - 48;
    if (progW < 50) progW = 50;
    mv(hProg, progX, runY + 6, progW, 22);
    mv(hProgTxt, progX + progW + 4, runY + 8, 44, 18);

    /* --- Status --- */
    mv(hStatus, M, runY + 40, paneW, 16);

    /* --- Log Panel --- */
    if (g_log_open) {
        int btnW = 56;
        mv(hLogTitle, lg->x + 14, lg->y + 11, (lg->w > 340 ? 110 : 70), 16);
        mv(hBtnLogToggle, lg->x + lg->w - 14 - 30, lg->y + 7, 30, 22);
        mv(hBtnLogClear, lg->x + lg->w - 14 - 30 - 6 - 56, lg->y + 7, 56, 22);
        mv(hBtnLogSave, lg->x + lg->w - 14 - 30 - 6 - 56 - 6 - btnW, lg->y + 7, btnW, 22);
        mv(hBtnLogCopy, lg->x + lg->w - 14 - 30 - 6 - 56 - 6 - btnW - 6 - btnW, lg->y + 7, btnW, 22);
        int logInnerW = lg->w - 20; if (logInnerW < 70) logInnerW = 70;
        int logInnerH = lg->h - 44; if (logInnerH < 70) logInnerH = 70;
        mv(g_log, lg->x + 10, lg->y + 34, logInnerW, logInnerH);
    }
}

static void apply_log_vis(void) {
    SendMessage(g_hwnd, WM_SETREDRAW, FALSE, 0);

    int sh = g_log_open ? SW_SHOW : SW_HIDE;
    ShowWindow(g_log, sh);
    ShowWindow(hLogTitle, sh);
    ShowWindow(hBtnLogCopy, sh);
    ShowWindow(hBtnLogSave, sh);
    ShowWindow(hBtnLogClear, sh);
    ShowWindow(hBtnLogToggle, sh);
    ShowWindow(hBtnLogOpen, g_log_open ? SW_HIDE : SW_SHOW);

    RECT rc; GetClientRect(g_hwnd, &rc);
    do_layout(rc.right, rc.bottom);

    SendMessage(g_hwnd, WM_SETREDRAW, TRUE, 0);
    RedrawWindow(g_hwnd, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
}

/* ------------------------- Aksi-aksi GUI ------------------------- */
static void browse_into(HWND target) {
    char path[MAX_PATH] = "";
    OPENFILENAME ofn; memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = "File BIN (*.bin)\0*.bin\0Semua file (*.*)\0*.*\0";
    ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileName(&ofn)) SetWindowText(target, path);
}
static void start_action(int act) {
    if (g_running) return;
    read_cfg();
    save_ini();
    if ((act == ACT_FLASH1 || act == ACT_FULL) && GetFileAttributes(g_cfg.bin1) == INVALID_FILE_ATTRIBUTES) {
        MessageBox(g_hwnd, "File R020.bin tidak ditemukan. Cek path-nya dulu.", "ALINOS.NET FlashTool", MB_ICONWARNING); return;
    }
    if ((act == ACT_FLASH2 || act == ACT_FULL) && GetFileAttributes(g_cfg.bin2) == INVALID_FILE_ATTRIBUTES) {
        MessageBox(g_hwnd, "File Permanen.bin tidak ditemukan. Cek path-nya dulu.", "ALINOS.NET FlashTool", MB_ICONWARNING); return;
    }
    if ((act == ACT_FLASH3 || act == ACT_FULL) && GetFileAttributes(g_cfg.bin3) == INVALID_FILE_ATTRIBUTES) {
        MessageBox(g_hwnd, "File Preset.bin tidak ditemukan. Cek path-nya dulu.", "ALINOS.NET FlashTool", MB_ICONWARNING); return;
    }
    ResetEvent(g_hStopEvt);
    g_running = 1;
    ui_running(1);
    SetWindowText(hStatus, "Berjalan...");
    PostMessage(g_hwnd, WM_PROG, 0, 0);
    HANDLE th = CreateThread(NULL, 0, worker_thread, (LPVOID)(INT_PTR)act, 0, NULL);
    if (th) CloseHandle(th);
}
static void log_copy(void) {
    int len = GetWindowTextLength(g_log);
    if (len <= 0) return;
    char *txt = (char *)malloc(len + 1);
    GetWindowText(g_log, txt, len + 1);
    if (OpenClipboard(g_hwnd)) {
        EmptyClipboard();
        HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, len + 1);
        char *p = (char *)GlobalLock(hg);
        memcpy(p, txt, len + 1); GlobalUnlock(hg);
        SetClipboardData(CF_TEXT, hg);
        CloseClipboard();
        logmsg("[LOG] Isi log disalin ke clipboard.");
    }
    free(txt);
}
static void log_save(void) {
    char path[MAX_PATH] = "alinos_flashtool_log.txt";
    OPENFILENAME ofn; memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn); ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = "File log (*.txt)\0*.txt\0Semua file (*.*)\0*.*\0";
    ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    if (!GetSaveFileName(&ofn)) return;
    int len = GetWindowTextLength(g_log);
    char *txt = (char *)malloc(len + 1);
    GetWindowText(g_log, txt, len + 1);
    HANDLE f = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wdone = 0;
        WriteFile(f, txt, (DWORD)strlen(txt), &wdone, NULL);
        CloseHandle(f);
        logmsg("[LOG] Log disimpan ke %s", path);
    }
    free(txt);
}
static void log_clear(void) { SetWindowText(g_log, ""); }

static WNDPROC g_oldComboProc = NULL;

static LRESULT CALLBACK ComboSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    static int s_hover = 0;
    if (uMsg == WM_MOUSEMOVE && !s_hover) {
        s_hover = 1;
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hWnd, 0 };
        TrackMouseEvent(&tme);
        InvalidateRect(hWnd, NULL, FALSE);
    } else if (uMsg == WM_MOUSELEAVE) {
        s_hover = 0;
        InvalidateRect(hWnd, NULL, FALSE);
    }

    if (uMsg == WM_PAINT) {
        LRESULT lr = CallWindowProc(g_oldComboProc, hWnd, uMsg, wParam, lParam);
        HDC hdc = GetWindowDC(hWnd);
        if (hdc) {
            RECT rc;
            GetWindowRect(hWnd, &rc);
            OffsetRect(&rc, -rc.left, -rc.top);

            /* Sleek Dark Border (Amber on hover/focus) */
            COLORREF brdColor = (s_hover || GetFocus() == hWnd) ? COL_ACCENT : COL_CARDBR;
            HPEN hPen = CreatePen(PS_SOLID, 1, brdColor);
            HGDIOBJ oldPen = SelectObject(hdc, hPen);
            HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(HOLLOW_BRUSH));
            RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 4, 4);

            /* Custom Modern Dropdown Button (replacing the 3D grey button) */
            RECT btnRc = { rc.right - 24, rc.top + 1, rc.right - 1, rc.bottom - 1 };
            HBRUSH hBtnBr = CreateSolidBrush(COL_FIELD);
            FillRect(hdc, &btnRc, hBtnBr);
            DeleteObject(hBtnBr);

            /* Draw sleek chevron arrow 'v' in COL_ACCENT (Amber) */
            HPEN hArrowPen = CreatePen(PS_SOLID, 2, COL_ACCENT);
            SelectObject(hdc, hArrowPen);
            int cx = btnRc.left + 11;
            int cy = (btnRc.top + btnRc.bottom) / 2 - 1;
            MoveToEx(hdc, cx - 4, cy - 2, NULL);
            LineTo(hdc, cx, cy + 2);
            LineTo(hdc, cx + 5, cy - 3);

            SelectObject(hdc, oldPen);
            SelectObject(hdc, oldBrush);
            DeleteObject(hPen);
            DeleteObject(hArrowPen);
            ReleaseDC(hWnd, hdc);
        }
        return lr;
    }
    return CallWindowProc(g_oldComboProc, hWnd, uMsg, wParam, lParam);
}

static WNDPROC g_oldProgProc = NULL;

static LRESULT CALLBACK ProgSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    if (uMsg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        RECT rc; GetClientRect(hWnd, &rc);

        /* Trough berlatar gelap */
        HBRUSH brBg = CreateSolidBrush(COL_FIELD);
        HPEN penBrd = CreatePen(PS_SOLID, 1, COL_CARDBR);
        HGDIOBJ oldBr = SelectObject(hdc, brBg);
        HGDIOBJ oldPen = SelectObject(hdc, penBrd);
        RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, 4, 4);
        SelectObject(hdc, oldBr);
        SelectObject(hdc, oldPen);
        DeleteObject(brBg);
        DeleteObject(penBrd);

        int pos = (int)SendMessage(hWnd, PBM_GETPOS, 0, 0);
        if (pos > 0) {
            int maxW = rc.right - rc.left - 4;
            int fillW = maxW * pos / 100;
            if (fillW > maxW) fillW = maxW;
            if (fillW > 0) {
                RECT fillRc = { rc.left + 2, rc.top + 2, rc.left + 2 + fillW, rc.bottom - 2 };
                HBRUSH brBar = CreateSolidBrush(COL_ACCENT);
                FillRect(hdc, &fillRc, brBar);
                DeleteObject(brBar);
            }
        }
        EndPaint(hWnd, &ps);
        return 0;
    }
    return CallWindowProc(g_oldProgProc, hWnd, uMsg, wParam, lParam);
}

/* tombol owner-drawn & dropdown combo: FULL RUN / LANJUT / STOP / General Step */
static void draw_obtn(DRAWITEMSTRUCT *d) {
    if (d->CtlID == ID_MODE || d->CtlID == ID_ADAPTER) {
        /* Custom Modern ComboBox Rendering */
        COLORREF fill = (d->itemState & ODS_SELECTED) ? RGB(45, 55, 72) : COL_FIELD;
        COLORREF border = (d->itemState & ODS_SELECTED) ? COL_ACCENT : COL_CARDBR;
        HBRUSH br = CreateSolidBrush(fill);
        HPEN pen = CreatePen(PS_SOLID, 1, border);
        HGDIOBJ ob = SelectObject(d->hDC, br), op = SelectObject(d->hDC, pen);
        Rectangle(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom);
        SelectObject(d->hDC, ob); SelectObject(d->hDC, op);
        DeleteObject(br); DeleteObject(pen);

        char txt[192] = "";
        if ((int)d->itemID >= 0) {
            SendMessage(d->hwndItem, CB_GETLBTEXT, d->itemID, (LPARAM)txt);
        }
        SetBkMode(d->hDC, TRANSPARENT);
        SetTextColor(d->hDC, (d->itemState & ODS_SELECTED) ? RGB(255, 255, 255) : COL_TXT);
        HFONT f = (HFONT)SendMessage(d->hwndItem, WM_GETFONT, 0, 0);
        HGDIOBJ of = SelectObject(d->hDC, f ? f : g_font);
        RECT trc = d->rcItem;
        trc.left += 6;
        DrawText(d->hDC, txt, -1, &trc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(d->hDC, of);
        return;
    }

    COLORREF fill, border, txtCol;
    int dis = (d->itemState & ODS_DISABLED) != 0;
    if (dis) {
        fill = RGB(36, 42, 54);
        border = RGB(50, 60, 76);
        txtCol = RGB(110, 120, 135);
    } else if (d->CtlID == ID_FULLRUN) {
        fill = RGB(217, 119, 6);   /* Signal Amber 600 */
        border = RGB(245, 158, 11);
        txtCol = RGB(255, 255, 255);
    } else if (d->CtlID == ID_LANJUT) {
        fill = RGB(16, 185, 129);  /* Emerald Green 500 */
        border = RGB(52, 211, 153);
        txtCol = RGB(255, 255, 255);
    } else if (d->CtlID == ID_STOP) {
        fill = RGB(225, 29, 72);   /* Rose Red 600 */
        border = RGB(244, 63, 94);
        txtCol = RGB(255, 255, 255);
    } else {
        /* General Step & Card Buttons: Professional Dark Slate */
        fill = RGB(36, 44, 58);
        border = RGB(64, 76, 96);
        txtCol = RGB(235, 240, 245);
    }

    if (!dis && (d->itemState & ODS_SELECTED)) {
        if (d->CtlID == ID_FULLRUN || d->CtlID == ID_LANJUT || d->CtlID == ID_STOP) {
            int r = GetRValue(fill) > 30 ? GetRValue(fill) - 30 : 0;
            int g = GetGValue(fill) > 30 ? GetGValue(fill) - 30 : 0;
            int b = GetBValue(fill) > 30 ? GetBValue(fill) - 30 : 0;
            fill = RGB(r, g, b);
        } else {
            fill = RGB(48, 58, 76);
            border = RGB(245, 158, 11); /* Subtle amber accent on click */
        }
    }

    HBRUSH br = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ ob = SelectObject(d->hDC, br), op = SelectObject(d->hDC, pen);
    RoundRect(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom, 6, 6);
    SelectObject(d->hDC, ob); SelectObject(d->hDC, op);
    DeleteObject(br); DeleteObject(pen);

    char txt[128]; GetWindowText(d->hwndItem, txt, sizeof(txt));
    SetBkMode(d->hDC, TRANSPARENT);
    SetTextColor(d->hDC, txtCol);
    HFONT f = (HFONT)SendMessage(d->hwndItem, WM_GETFONT, 0, 0);
    HGDIOBJ of = SelectObject(d->hDC, f);
    DrawText(d->hDC, txt, -1, &d->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(d->hDC, of);
}

/* ------------------------- Lukis latar (Double-Buffered) ------------------------- */
static void paint_bg(HWND h) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(h, &ps);
    RECT rc; GetClientRect(h, &rc);
    int W = rc.right, H = rc.bottom;
    if (W <= 0 || H <= 0) { EndPaint(h, &ps); return; }

    HDC memDC = CreateCompatibleDC(dc);
    HBITMAP memBM = CreateCompatibleBitmap(dc, W, H);
    HGDIOBJ oldBM = SelectObject(memDC, memBM);

    /* Fill latar belakang utama */
    FillRect(memDC, &rc, g_brBg);

    /* Header solid */
    HBRUSH hb = CreateSolidBrush(COL_HEAD);
    RECT hr = {0, 0, W, 48};
    FillRect(memDC, &hr, hb);
    DeleteObject(hb);

    SetBkMode(memDC, TRANSPARENT);
    HGDIOBJ of = SelectObject(memDC, g_fontBrand);
    SetTextColor(memDC, RGB(255, 255, 255));
    TextOut(memDC, 16, 5, "ALINOS.NET", 10);
    SIZE sz; GetTextExtentPoint32(memDC, "ALINOS.NET", 10, &sz);
    SetTextColor(memDC, COL_ACCENT);
    TextOut(memDC, 20 + sz.cx, 5, "FlashTool Pro", 13);
    SelectObject(memDC, g_fontTitle);
    SetTextColor(memDC, COL_MUTED);
    const char *sub = "HUAWEI ONT MASTER TOOLKIT - by SkydashNET for ALINOSNET";
    TextOut(memDC, 17, 30, sub, (int)strlen(sub));
    SetTextAlign(memDC, TA_RIGHT);
    SetTextColor(memDC, RGB(255, 255, 255));
    char ver_hdr[64];
    _snprintf(ver_hdr, sizeof(ver_hdr), "v%s by SkydashNET", APP_VERSION);
    TextOut(memDC, W - 16, 6, ver_hdr, (int)strlen(ver_hdr));
    SelectObject(memDC, g_fontMini);
    SetTextColor(memDC, COL_ACCENT);
    TextOut(memDC, W - 16, 30, "[KEBAL RESET PABRIK]", 20);
    SetTextAlign(memDC, TA_LEFT);

    /* Kartu + judul */
    for (int i = 0; i < 8; i++) {
        Card *c = &g_cards[i];
        if (c->w <= 0) continue;
        HBRUSH br = CreateSolidBrush(COL_CARD);
        HPEN pen = CreatePen(PS_SOLID, 1, COL_CARDBR);
        HGDIOBJ ob = SelectObject(memDC, br), op = SelectObject(memDC, pen);
        RoundRect(memDC, c->x, c->y, c->x + c->w, c->y + c->h, 8, 8);
        SelectObject(memDC, ob); SelectObject(memDC, op);
        DeleteObject(br); DeleteObject(pen);
        if (c->title && c->title[0]) {
            HBRUSH ab = CreateSolidBrush(COL_ACCENT);
            RECT sq = {c->x + 14, c->y + 8, c->x + 18, c->y + 19};
            FillRect(memDC, &sq, ab);
            DeleteObject(ab);
            SelectObject(memDC, g_fontTitle);
            SetTextColor(memDC, COL_TXT);
            RECT trc = {c->x + 24, c->y + 6, c->x + c->w - 14, c->y + 22};
            DrawText(memDC, c->title, -1, &trc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        }
    }
    SelectObject(memDC, of);

    /* Blit memDC ke layar sekali jalan tanpa flicker */
    BitBlt(dc, 0, 0, W, H, memDC, 0, 0, SRCCOPY);

    SelectObject(memDC, oldBM);
    DeleteObject(memBM);
    DeleteDC(memDC);
    EndPaint(h, &ps);
}

/* ------------------------- Auto-Update Engine ------------------------- */
static int semver_cmp(const char *v1, const char *v2) {
    while (*v1 == 'v' || *v1 == 'V' || *v1 == ' ') v1++;
    while (*v2 == 'v' || *v2 == 'V' || *v2 == ' ') v2++;
    int maj1 = 0, min1 = 0, pat1 = 0;
    int maj2 = 0, min2 = 0, pat2 = 0;
    sscanf(v1, "%d.%d.%d", &maj1, &min1, &pat1);
    sscanf(v2, "%d.%d.%d", &maj2, &min2, &pat2);
    if (maj1 != maj2) return maj1 - maj2;
    if (min1 != min2) return min1 - min2;
    return pat1 - pat2;
}

static int json_get_str(const char *json, const char *key, char *out, size_t out_sz) {
    char search[128];
    _snprintf(search, sizeof(search), "\"%s\":", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '\"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '\"' && i < out_sz - 1) {
        if (*p == '\\' && *(p+1)) {
            p++;
            if (*p == 'n') out[i++] = '\n';
            else if (*p == 'r') out[i++] = '\r';
            else if (*p == 't') out[i++] = '\t';
            else out[i++] = *p;
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = 0;
    return 1;
}

static DWORD WINAPI update_thread(LPVOID p) {
    int manual = (int)(INT_PTR)p;
    logmsg("[UPDATE] Memeriksa versi rilis terbaru di GitHub (%s)...", GITHUB_REPO);

    HINTERNET hNet = InternetOpenA("ALINOS-FlashTool/" APP_VERSION, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!hNet) {
        if (manual) MessageBox(g_hwnd, "Gagal menginisialisasi koneksi internet.", "Update", MB_ICONWARNING);
        g_updating = 0;
        return 1;
    }

    char api_url[256];
    _snprintf(api_url, sizeof(api_url), "https://api.github.com/repos/%s/releases/latest", GITHUB_REPO);
    HINTERNET hUrl = InternetOpenUrlA(hNet, api_url,
                                      "Accept: application/vnd.github.v3+json\r\n", -1,
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        logmsg("[UPDATE] Tidak dapat menghubungi server GitHub (Internet offline / repo belum ada rilis).");
        if (manual) MessageBox(g_hwnd, "Tidak dapat menghubungi GitHub.\nPastikan koneksi internet aktif dan rilis sudah dipublikasikan.", "Update", MB_ICONWARNING);
        InternetCloseHandle(hNet);
        g_updating = 0;
        return 2;
    }

    char *json = (char *)malloc(128 * 1024);
    if (!json) { InternetCloseHandle(hUrl); InternetCloseHandle(hNet); g_updating = 0; return 3; }
    
    DWORD total_read = 0, bytes_read = 0;
    while (InternetReadFile(hUrl, json + total_read, (128 * 1024) - 1 - total_read, &bytes_read) && bytes_read > 0) {
        total_read += bytes_read;
    }
    json[total_read] = 0;
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);

    char tag[64] = "", name[128] = "", dl_url[512] = "";
    json_get_str(json, "tag_name", tag, sizeof(tag));
    json_get_str(json, "name", name, sizeof(name));

    /* Cari browser_download_url untuk ALINOS-FlashTool.exe */
    const char *pos = json;
    while ((pos = strstr(pos, "\"browser_download_url\":")) != NULL) {
        char cand_url[512] = "";
        if (json_get_str(pos, "browser_download_url", cand_url, sizeof(cand_url))) {
            if (strstr(cand_url, "ALINOS-FlashTool.exe") != NULL) {
                strncpy(dl_url, cand_url, sizeof(dl_url) - 1);
                break;
            }
        }
        pos += 22;
    }
    free(json);

    if (!tag[0] || !dl_url[0]) {
        logmsg("[UPDATE] Rilis terbaru belum memiliki asset binary executable di GitHub.");
        if (manual) MessageBox(g_hwnd, "Belum ditemukan file pembaruan binary di rilis GitHub terbaru.", "Update", MB_ICONINFORMATION);
        g_updating = 0;
        return 4;
    }

    int cmp = semver_cmp(tag, APP_VERSION);
    if (cmp <= 0) {
        logmsg("[UPDATE] Aplikasi Anda sudah versi terbaru (v%s).", APP_VERSION);
        if (manual) {
            char msg[128];
            _snprintf(msg, sizeof(msg), "Aplikasi Anda sudah versi terbaru (v%s).\nTidak ada pembaruan.", APP_VERSION);
            MessageBox(g_hwnd, msg, "ALINOS-FlashTool", MB_ICONINFORMATION);
        }
        g_updating = 0;
        return 0;
    }

    /* Versi baru tersedia! */
    logmsg("[UPDATE] Versi baru ditemukan di GitHub: %s (%s)", tag, name);
    char prompt[512];
    _snprintf(prompt, sizeof(prompt),
              "Versi baru telah tersedia di GitHub!\n\n"
              "Versi Saat Ini : v%s\n"
              "Versi Terbaru  : %s (%s)\n\n"
              "Apakah Anda ingin mengunduh dan memperbarui aplikasi sekarang?",
              APP_VERSION, tag, name);

    if (MessageBox(g_hwnd, prompt, "Pembaruan Tersedia - ALINOS.NET FlashTool", MB_ICONINFORMATION | MB_YESNO | MB_DEFBUTTON1) != IDYES) {
        logmsg("[UPDATE] Pembaruan ditunda oleh pengguna.");
        g_updating = 0;
        return 0;
    }

    /* Proses download dan in-place upgrade */
    char cur_exe[MAX_PATH];
    GetModuleFileName(NULL, cur_exe, MAX_PATH);

    char new_exe[MAX_PATH], old_exe[MAX_PATH];
    _snprintf(new_exe, sizeof(new_exe), "%s.new", cur_exe);
    _snprintf(old_exe, sizeof(old_exe), "%s.old", cur_exe);

    logmsg("[UPDATE] Mengunduh pembaruan dari: %s", dl_url);
    HINTERNET hDlNet = InternetOpenA("ALINOS-FlashTool/" APP_VERSION, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    HINTERNET hDlUrl = InternetOpenUrlA(hDlNet, dl_url, NULL, 0,
                                        INTERNET_FLAG_RELOAD | INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hDlUrl) {
        logmsg("[UPDATE] GAGAL mengunduh file pembaruan.");
        MessageBox(g_hwnd, "Gagal mengunduh file pembaruan dari GitHub.", "Update Gagal", MB_ICONERROR);
        if (hDlNet) InternetCloseHandle(hDlNet);
        g_updating = 0;
        return 5;
    }

    FILE *fNew = fopen(new_exe, "wb");
    if (!fNew) {
        logmsg("[UPDATE] GAGAL membuat file temporer: %s", new_exe);
        MessageBox(g_hwnd, "Tidak dapat menulis file pembaruan. Pastikan folder memiliki izin tulis.", "Update Gagal", MB_ICONERROR);
        InternetCloseHandle(hDlUrl);
        InternetCloseHandle(hDlNet);
        g_updating = 0;
        return 6;
    }

    char dl_buf[8192];
    DWORD dl_read = 0, dl_total = 0;
    while (InternetReadFile(hDlUrl, dl_buf, sizeof(dl_buf), &dl_read) && dl_read > 0) {
        fwrite(dl_buf, 1, dl_read, fNew);
        dl_total += dl_read;
    }
    fclose(fNew);
    InternetCloseHandle(hDlUrl);
    InternetCloseHandle(hDlNet);

    if (dl_total < 50000) {
        DeleteFileA(new_exe);
        logmsg("[UPDATE] File yang diunduh terlalu kecil atau korup.");
        MessageBox(g_hwnd, "File pembaruan yang diunduh tidak valid.", "Update Gagal", MB_ICONERROR);
        g_updating = 0;
        return 7;
    }

    logmsg("[UPDATE] Unduhan selesai (%lu byte). Mempersiapkan penggantian otomatis...", dl_total);

    /* Buat helper script update di %TEMP% agar proses penggantian berjalan mulus setelah proses keluar */
    char temp_dir[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    char bat_path[MAX_PATH];
    _snprintf(bat_path, sizeof(bat_path), "%salinos_self_updater.bat", temp_dir);

    FILE *fBat = fopen(bat_path, "w");
    if (!fBat) {
        logmsg("[UPDATE] Gagal membuat skrip update temporer.");
        DeleteFileA(new_exe);
        g_updating = 0;
        return 8;
    }

    fprintf(fBat,
        "@echo off\r\n"
        ":wait_unlock\r\n"
        "timeout /t 1 /nobreak >nul\r\n"
        "del \"%s\" >nul 2>&1\r\n"
        "move /y \"%s\" \"%s\" >nul 2>&1\r\n"
        "if not exist \"%s\" goto wait_unlock\r\n"
        "start \"\" \"%s\"\r\n"
        "del \"%%~f0\" >nul 2>&1\r\n",
        cur_exe, new_exe, cur_exe, cur_exe, cur_exe);
    fclose(fBat);

    logmsg("[UPDATE] Pembaruan siap. Aplikasi akan memulai ulang secara otomatis...");
    MessageBox(g_hwnd, "Pembaruan berhasil diunduh!\nAplikasi akan memulai ulang secara otomatis ke versi terbaru.", "Pembaruan Berhasil", MB_ICONINFORMATION | MB_OK);

    ShellExecuteA(NULL, "open", bat_path, NULL, NULL, SW_HIDE);
    ExitProcess(0);
    return 0;
}

static void start_check_update(int manual) {
    if (g_updating) return;
    g_updating = 1;
    HANDLE th = CreateThread(NULL, 0, update_thread, (LPVOID)(INT_PTR)manual, 0, NULL);
    if (th) CloseHandle(th);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        g_hwnd = h;
        /* Koneksi */
        L_IP = mlbl("IP Modem"); L_ADP = mlbl("Adapter"); L_GRP = mlbl("Grup");
        L_PRT = mlbl("Port"); L_PKS = mlbl("PKSIZE"); L_ITV = mlbl("Interval"); L_DUR = mlbl("Durasi");
        hIp = edt(ID_IP, 0);
        hAdapter = mk("COMBOBOX", "", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_VSCROLL, ID_ADAPTER);
        g_oldComboProc = (WNDPROC)SetWindowLongPtr(hAdapter, GWLP_WNDPROC, (LONG_PTR)ComboSubclassProc);
        hBtnScanAdp = btn("Scan", ID_SCAN_ADP);
        SendMessage(hBtnScanAdp, WM_SETFONT, (WPARAM)g_fontMini, TRUE);
        hGroup = edt(ID_GROUP, 0);
        hPort = edt(ID_PORT, 0); hChk918 = chkb("Dual Port (4891+918)", ID_CHK918);
        hPkSize = edt(ID_PKSIZE, 0); hInterval = edt(ID_INTERVAL, 0); hDurasi = edt(ID_DURASI, 0);
        hDevStatus = mk("STATIC", "[IDLE] Menunggu ONT di 192.168.100.1 (Kabel LAN / Power)", SS_LEFT | SS_ENDELLIPSIS | SS_NOTIFY, ID_DEV_STATUS);
        SendMessage(hDevStatus, WM_SETFONT, (WPARAM)g_fontTitle, TRUE);
        L_CRD = mlbl("Kredensial Telnet (user:pass per baris)");
        hCreds = mk("EDIT", "", WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, ID_CREDS);
        H_CRD = mlbl("dicoba otomatis satu per satu sampai ada yang berhasil");
        H_NOTE = mlbl("");
        /* Step 1 */
        hBin1 = edt(ID_BIN1, 0);
        hBrw1 = btn("Browse", ID_BRW1);
        hBtnFlash1 = btn("Flash R020", ID_FLASH1);
        /* Step 2 */
        L_S2D = mlbl("Dua sesi telnet otomatis");
        hBtnStep2 = btn("Jalankan Step 2", ID_STEP2);
        /* Step 3 */
        L_PRM = mlbl("Permanen"); L_PRS = mlbl("Preset");
        hBin2 = edt(ID_BIN2, 0); hBrw2 = btn("Browse", ID_BRW2); hBtnFlash2 = btn("Flash", ID_FLASH2);
        hBin3 = edt(ID_BIN3, 0); hBrw3 = btn("Browse", ID_BRW3); hBtnFlash3 = btn("Flash", ID_FLASH3);
        /* Step 4 */
        hMode = mk("COMBOBOX", "", CBS_DROPDOWNLIST | CBS_OWNERDRAWFIXED | CBS_HASSTRINGS | WS_VSCROLL, ID_MODE);
        const char *modes[7] = {"XPON", "GPON", "EPON", "LAN 1 = WAN", "LAN 2 = WAN", "LAN 3 = WAN", "LAN 4 = WAN"};
        for (int i = 0; i < 7; i++) SendMessage(hMode, CB_ADDSTRING, 0, (LPARAM)modes[i]);
        SendMessage(hMode, CB_SETCURSEL, 0, 0);
        g_oldComboProc = (WNDPROC)SetWindowLongPtr(hMode, GWLP_WNDPROC, (LONG_PTR)ComboSubclassProc);
        hBtnStep4 = btn("Jalankan Step 4", ID_STEP4);
        hBtnReboot = btn("Reboot", ID_REBOOT);
        L_S4N = mlbl("reboot saja, tanpa set mode");
        /* Step 5 */
        const char *plabels[11] = {"PPPoE User", "PPPoE Pass", "SSID 2.4G", "SSID 5G", "WiFi Key",
                                   "TR-069 URL", "TR-069 User", "TR-069 Pass", "Inform (detik)",
                                   "ConnReq User", "ConnReq Pass"};
        for (int i = 0; i < 11; i++) L_PV[i] = mlbl(plabels[i]);
        hPppUser = edt(ID_PPPUSER, 0); hPppPass = edt(ID_PPPPASS, 1);
        hSsid1 = edt(ID_SSID1, 0); hWkey = edt(ID_WKEY, 0);
        hSsid5 = edt(ID_SSID5, 0); hTrUrl = edt(ID_TRURL, 0);
        hTrUser = edt(ID_TRUSER, 0); hTrPass = edt(ID_TRPASS, 1);
        hTrInform = edt(ID_TRINFORM, 0); hCrUser = edt(ID_CRUSER, 0); hCrPass = edt(ID_CRPASS, 1);
        hChkWan = chkb("Firewall WAN Remote", ID_CHKWAN);
        hBtnProv = btn("Terapkan Provisioning", ID_PROV);
        hChkReboot = chkb("Reboot setelah provisi", ID_CHKREBOOT);
        /* Step 6 */
        L_CI = mlbl("Custom Info");
        hCInfo = edt(ID_CINFO, 0);
        hBtnCI = btn("Terapkan", ID_APPLYCI);
        hBtnWebRed = btn("Web Merah (Downgrade)", ID_WEB_RED);
        hBtnWebBlue = btn("Web Biru (Smart XGPON)", ID_WEB_BLUE);
        /* Run + progress */
        hBtnFull = obtn("START FULL RUN AUTO", ID_FULLRUN);
        hBtnLanjut = obtn("LANJUT", ID_LANJUT);
        hBtnStop = obtn("STOP", ID_STOP);
        EnableWindow(hBtnLanjut, FALSE); EnableWindow(hBtnStop, FALSE);
        hProg = mk("msctls_progress32", "", PBS_SMOOTH, ID_PROG);
        SendMessage(hProg, PBM_SETRANGE32, 0, 100);
        SendMessage(hProg, PBM_SETPOS, 0, 0);
        g_oldProgProc = (WNDPROC)SetWindowLongPtr(hProg, GWLP_WNDPROC, (LONG_PTR)ProgSubclassProc);
        hProgTxt = mk("STATIC", "0%", SS_RIGHT, 0);
        hStatus = mk("STATIC", "Siap. FULL RUN berhenti di tiap power cycle dan menunggu klik LANJUT.", 0, ID_STATUS);
        /* Log */
        hLogTitle = mk("STATIC", "LOG AKTIVITAS", 0, 0);
        SendMessage(hLogTitle, WM_SETFONT, (WPARAM)g_fontTitle, TRUE);
        hBtnLogCopy = btn("Salin", ID_LOGCOPY);
        hBtnLogSave = btn("Simpan", ID_LOGSAVE);
        hBtnLogClear = btn("Bersihkan", ID_LOGCLEAR);
        hBtnLogToggle = btn(">>", ID_LOGTOGGLE);
        hBtnLogOpen = btn("<< Log", ID_LOGOPEN);
        hBtnUpdate = btn("Update", ID_UPDATE);
        SendMessage(hBtnUpdate, WM_SETFONT, (WPARAM)g_fontMini, TRUE);
        g_log = mk("EDIT", "", WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, ID_LOG);
        SendMessage(g_log, WM_SETFONT, (WPARAM)g_fontLog, TRUE);
        SendMessage(g_log, EM_SETLIMITTEXT, (1024 * 1024), 0);
        ini_path();
        load_ini();
        RECT rc; GetClientRect(h, &rc);
        do_layout(rc.right, rc.bottom);
        apply_log_vis();
        CreateThread(NULL, 0, listener_thread, NULL, 0, NULL);
        CreateThread(NULL, 0, device_discovery_thread, NULL, 0, NULL);
        start_check_update(0);
        logmsg("ALINOS.NET FlashTool v%s by SkydashNET siap. Auto-discovery & auto-update aktif.", APP_VERSION);
        logmsg("Login telnet full otomatis: daftar kredensial dicoba bergantian sampai berhasil. Upload XML via web tetap manual.");
        return 0;
    }
    case WM_GETMINMAXINFO: {
        MINMAXINFO *mm = (MINMAXINFO *)l;
        mm->ptMinTrackSize.x = 980;
        mm->ptMinTrackSize.y = 620;
        return 0;
    }
    case WM_SIZE:
        if (w != SIZE_MINIMIZED) {
            SendMessage(h, WM_SETREDRAW, FALSE, 0);
            do_layout(LOWORD(l), HIWORD(l));
            SendMessage(h, WM_SETREDRAW, TRUE, 0);
            RedrawWindow(h, NULL, NULL, RDW_ERASE | RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_UPDATENOW);
        }
        return 0;
    case WM_ERASEBKGND:
        /* Supresi penghapusan background untuk menghilangkan flicker/stutter secara total */
        return 1;
    case WM_PAINT:
        paint_bg(h);
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)w; HWND c = (HWND)l;
        if (c == hDevStatus) {
            if (g_dev_state == 1) SetTextColor(dc, RGB(74, 222, 128));
            else if (g_dev_state == 2) SetTextColor(dc, RGB(56, 189, 248));
            else if (g_dev_state == 3) SetTextColor(dc, RGB(250, 204, 21));
            else SetTextColor(dc, RGB(245, 158, 11));
            SetBkMode(dc, TRANSPARENT);
            SetBkColor(dc, COL_CARD);
            return (LRESULT)g_brCard;
        }
        SetTextColor(dc, COL_TXT);
        if (c == hLogTitle) SetTextColor(dc, COL_ACCENT);
        else for (int i = 0; i < g_nmuted; i++) if (g_muted[i] == c) { SetTextColor(dc, COL_MUTED); break; }
        SetBkMode(dc, TRANSPARENT);
        if (c == hStatus || c == hProgTxt) {
            SetBkColor(dc, COL_BG);
            return (LRESULT)g_brBg;
        }
        SetBkColor(dc, COL_CARD);
        return (LRESULT)g_brCard;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)w;
        if ((HWND)l == g_log) {
            SetTextColor(dc, COL_LOGTX); SetBkColor(dc, COL_LOGBG);
            return (LRESULT)g_brLog;
        }
        SetTextColor(dc, COL_TXT); SetBkColor(dc, COL_FIELD);
        return (LRESULT)g_brField;
    }
    case WM_CTLCOLORLISTBOX: {
        HDC dc = (HDC)w;
        SetTextColor(dc, COL_TXT); SetBkColor(dc, COL_FIELD);
        return (LRESULT)g_brField;
    }
    case WM_CTLCOLORBTN: {
        HDC dc = (HDC)w;
        DWORD st = (DWORD)GetWindowLong((HWND)l, GWL_STYLE);
        SetTextColor(dc, COL_TXT);
        if ((st & BS_TYPEMASK) == BS_AUTOCHECKBOX || (st & BS_TYPEMASK) == BS_AUTORADIOBUTTON) {
            SetBkColor(dc, COL_CARD);
            return (LRESULT)g_brCard;
        }
        SetBkColor(dc, COL_BTNF);
        return (LRESULT)g_brBtn;
    }
    case WM_MEASUREITEM: {
        MEASUREITEMSTRUCT *m = (MEASUREITEMSTRUCT *)l;
        if (m->CtlID == ID_MODE || m->CtlID == ID_ADAPTER) {
            m->itemHeight = 22;
            return TRUE;
        }
        break;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *d = (DRAWITEMSTRUCT *)l;
        draw_obtn(d);
        return TRUE;
    }
    case WM_DEV_UPDATE: {
        char *s = (char *)l;
        if (s) {
            SetWindowText(hDevStatus, s);
            free(s);
        }
        InvalidateRect(hDevStatus, NULL, TRUE);
        return 0;
    }
    case WM_LOGMSG: {
        char *s = (char *)l;
        if (s) { log_append(s); free(s); }
        return 0;
    }
    case WM_PROG: {
        SendMessage(hProg, PBM_SETPOS, w, 0);
        char b[16]; _snprintf(b, sizeof(b), "%d%%", (int)w);
        SetWindowText(hProgTxt, b);
        InvalidateRect(hProg, NULL, FALSE);
        return 0;
    }
    case WM_ERRPOP: {
        char *e = (char *)l;
        if (e) {
            SetWindowText(hStatus, "Gagal. Lihat popup error / log.");
            MessageBox(h, e, "ALINOS.NET FlashTool - Proses Gagal", MB_ICONERROR | MB_OK);
            free(e);
        }
        return 0;
    }
    case WM_APP + 2:
        EnableWindow(hBtnLanjut, w == 1);
        if (w == 1) SetWindowText(hStatus, "MENUNGGU: power cycle modem sekarang, tunggu nyala lagi, lalu klik LANJUT.");
        else SetWindowText(hStatus, "Berjalan...");
        return 0;
    case WM_APP + 3:
        ui_running(0);
        if (!g_lasterr[0])
            SetWindowText(hStatus, "Siap. FULL RUN berhenti di tiap power cycle dan menunggu klik LANJUT.");
        return 0;
    case WM_COMMAND: {
        int id = LOWORD(w);
        switch (id) {
        case ID_UPDATE:
            start_check_update(1);
            break;
        case ID_SCAN_ADP:
            scan_network_adapters(NULL);
            logmsg("[NET] Scan adapter jaringan selesai. Adapter terbaik otomatis dipilih.");
            break;
        case ID_ADAPTER:
            if (HIWORD(w) == CBN_SELCHANGE) {
                int sel = (int)SendMessage(hAdapter, CB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < g_num_adapters) {
                    strncpy(g_cfg.adapter, g_adapters[sel].ip, sizeof(g_cfg.adapter) - 1);
                    logmsg("[NET] Adapter terpilih: %s", g_adapters[sel].display);
                }
            }
            break;
        case ID_DEV_STATUS:
            if (g_dev_state == 3) {
                SetWindowText(hIp, "192.168.18.1");
                logmsg("[NET] Target IP modem diubah ke 192.168.18.1 sesuai deteksi ONT.");
            }
            break;
        case ID_BRW1: browse_into(hBin1); break;
        case ID_BRW2: browse_into(hBin2); break;
        case ID_BRW3: browse_into(hBin3); break;
        case ID_FLASH1: start_action(ACT_FLASH1); break;
        case ID_FLASH2: start_action(ACT_FLASH2); break;
        case ID_FLASH3: start_action(ACT_FLASH3); break;
        case ID_STEP2: start_action(ACT_STEP2); break;
        case ID_STEP4: start_action(ACT_STEP4); break;
        case ID_REBOOT: start_action(ACT_REBOOT); break;
        case ID_PROV: start_action(ACT_PROV); break;
        case ID_APPLYCI: start_action(ACT_CINFO); break;
        case ID_WEB_RED: start_action(ACT_WEB_RED); break;
        case ID_WEB_BLUE: start_action(ACT_WEB_BLUE); break;
        case ID_FULLRUN: start_action(ACT_FULL); break;
        case ID_LANJUT: SetEvent(g_hGateEvt); break;
        case ID_STOP: SetEvent(g_hStopEvt); logmsg("[STOP] Menghentikan..."); break;
        case ID_LOGTOGGLE:
            g_log_open = 0; apply_log_vis();
            WritePrivateProfileString("alinos", "logopen", "0", g_ini);
            break;
        case ID_LOGOPEN:
            g_log_open = 1; apply_log_vis();
            WritePrivateProfileString("alinos", "logopen", "1", g_ini);
            break;
        case ID_LOGCOPY: log_copy(); break;
        case ID_LOGSAVE: log_save(); break;
        case ID_LOGCLEAR: log_clear(); break;
        }
        return 0;
    }
    case WM_DESTROY:
        save_ini();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}

static void self_unblock(void) {
    char p[MAX_PATH];
    if (GetModuleFileName(NULL, p, MAX_PATH) > 0) {
        char s[MAX_PATH + 32];
        _snprintf(s, sizeof(s), "%s:Zone.Identifier", p);
        DeleteFile(s);
        char *sl = strrchr(p, '\\');
        if (sl) {
            *sl = 0;
            _snprintf(s, sizeof(s), "%s\\alinos_flashtool.ini:Zone.Identifier", p);
            DeleteFile(s);
            _snprintf(s, sizeof(s), "%s\\firmware\\R020.bin:Zone.Identifier", p);
            DeleteFile(s);
            _snprintf(s, sizeof(s), "%s\\firmware\\Permanen.bin:Zone.Identifier", p);
            DeleteFile(s);
            _snprintf(s, sizeof(s), "%s\\firmware\\Preset.bin:Zone.Identifier", p);
            DeleteFile(s);
        }
    }
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE hp, LPSTR cmd, int show) {
    (void)hp; (void)cmd;
    self_unblock();
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd) != 0) { MessageBox(NULL, "WSAStartup gagal", "Error", MB_ICONERROR); return 1; }
    INITCOMMONCONTROLSEX icc; icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);
    crc_init();
    g_hStopEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_hGateEvt = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_font = CreateFont(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_fontMini = CreateFont(-11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_fontLog = CreateFont(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Consolas");
    g_fontBrand = CreateFont(-22, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Bahnschrift");
    g_fontTitle = CreateFont(-12, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Bahnschrift");
    g_fontBtn = CreateFont(-13, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, "Segoe UI");
    g_brBg = CreateSolidBrush(COL_BG);
    g_brField = CreateSolidBrush(COL_FIELD);
    g_brLog = CreateSolidBrush(COL_LOGBG);
    g_brBtn = CreateSolidBrush(COL_BTNF);
    g_brCard = CreateSolidBrush(COL_CARD);
    WNDCLASS wc; memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hbrBackground = g_brBg;
    wc.lpszClassName = "AlinosFlashTool";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(hi, MAKEINTRESOURCE(1));
    RegisterClass(&wc);
    HWND h = CreateWindow("AlinosFlashTool", "ALINOS.NET FlashTool Pro v2.0 - by SkydashNET (Huawei ONT Toolkit)",
                          WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                          CW_USEDEFAULT, CW_USEDEFAULT, 1140, 660, NULL, NULL, hi, NULL);
    if (!h) return 1;
    SendMessage(h, WM_SETICON, ICON_BIG, (LPARAM)LoadIcon(hi, MAKEINTRESOURCE(1)));
    SendMessage(h, WM_SETICON, ICON_SMALL, (LPARAM)LoadIcon(hi, MAKEINTRESOURCE(1)));
    ShowWindow(h, show);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    WSACleanup();
    return 0;
}
