#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "flasher.h"
#include "hwnp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <conio.h>
  #define SLEEP_MS(ms) Sleep(ms)
  typedef int socklen_t;
  #define CLOSE_SOCK(s) closesocket(s)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <ifaddrs.h>
  #include <net/if.h>
  #include <termios.h>
  #define SLEEP_MS(ms) usleep((ms) * 1000)
  #define CLOSE_SOCK(s) close(s)
  typedef int SOCKET;
  #define INVALID_SOCKET (-1)
  #define SOCKET_ERROR   (-1)

  /* Simple non-blocking key check on POSIX */
  static int _kbhit(void) {
      struct termios oldt, newt;
      int ch;
      int oldf;
      tcgetattr(STDIN_FILENO, &oldt);
      newt = oldt;
      newt.c_lflag &= ~(ICANON | ECHO);
      tcsetattr(STDIN_FILENO, TCSANOW, &newt);
      oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
      fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
      ch = getchar();
      tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
      fcntl(STDIN_FILENO, F_SETFL, oldf);
      if (ch != EOF) {
          ungetc(ch, stdin);
          return 1;
      }
      return 0;
  }
  static int _getch(void) {
      return getchar();
  }
#endif

int flasher_net_init(void) {
#ifdef _WIN32
    WSADATA wsa;
    return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) ? 0 : -1;
#else
    return 0;
#endif
}

void flasher_net_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

void flasher_list_interfaces(void) {
#ifndef _WIN32
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;
    printf("\nDetected Network Interfaces:\n");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            struct sockaddr_in *p = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &p->sin_addr, ip, sizeof(ip));
            if (strcmp(ip, "127.0.0.1") != 0) {
                printf("  [•] %-12s : %s\n", ifa->ifa_name, ip);
            }
        }
    }
    freeifaddrs(ifaddr);
#endif
}

static void write_le32(uint8_t *p, uint32_t val) {
    p[0] = (uint8_t)(val & 0xFF);
    p[1] = (uint8_t)((val >> 8) & 0xFF);
    p[2] = (uint8_t)((val >> 16) & 0xFF);
    p[3] = (uint8_t)((val >> 24) & 0xFF);
}

/*
 * Build Huawei Multicast WAP Package Control Info Packet (244 bytes)
 */
static void build_control_packet(uint8_t *pkt, size_t file_size, uint32_t file_crc,
                                const char *board_ids, uint32_t total_chunks, uint32_t chunk_size) {
    memset(pkt, 0, FLASHER_CTRL_PACKET_SIZE);

    /* Magic "WAPP" */
    write_le32(pkt + 0x00, 0x57415050);

    /* Control packet flags */
    write_le32(pkt + 0x48, 1);
    write_le32(pkt + 0x4C, 0);

    /* File CRC and File Size */
    write_le32(pkt + 0x50, file_crc);
    write_le32(pkt + 0x54, (uint32_t)file_size);

    /* Board IDs string */
    if (board_ids && board_ids[0]) {
        size_t blen = strlen(board_ids);
        if (blen > 63) blen = 63;
        memcpy(pkt + 0x58, board_ids, blen);
        pkt[0x58 + blen] = '\0';
    }

    /* Fixed Huawei Multicast Beacon Signature */
    const char *beacon_str = "This is a multicast wap package control info packet.";
    strncpy((char *)(pkt + 0xA0), beacon_str, 53);

    /* Total Chunks and Chunk Size */
    write_le32(pkt + 0xE0, total_chunks);
    write_le32(pkt + 0xE4, chunk_size);

    /* Trailer "CEND" */
    write_le32(pkt + 0xF0, 0x43454E44);
}

/*
 * Build Huawei DLUM Data Chunk Packet (20 bytes header + payload)
 */
static void build_data_packet(uint8_t *pkt, uint32_t chunk_idx, uint32_t total_chunks,
                             size_t file_size, uint32_t file_crc, const uint8_t *chunk_data, size_t chunk_len) {
    /* Magic "DLUM" */
    write_le32(pkt + 0x00, 0x4D554C44);
    /* Current chunk index (0-based) */
    write_le32(pkt + 0x04, chunk_idx);
    /* Total chunks */
    write_le32(pkt + 0x08, total_chunks);
    /* File Size */
    write_le32(pkt + 0x0C, (uint32_t)file_size);
    /* File CRC32 */
    write_le32(pkt + 0x10, file_crc);

    /* Copy actual chunk bytes */
    memcpy(pkt + FLASHER_DATA_HDR_SIZE, chunk_data, chunk_len);
}

int flasher_broadcast_firmware(const flasher_options_t *opts, volatile bool *stop_flag) {
    if (!opts || !opts->bin_path) return -1;

    hwnp_package_t pkg;
    if (hwnp_load(opts->bin_path, &pkg) != 0) {
        printf("\033[1;31m[!] Error: Gagal memuat file firmware %s!\033[0m\n", opts->bin_path);
        return -1;
    }

    size_t file_size = pkg.raw_size;
    uint32_t file_crc = pkg.stored_header_crc;
    uint32_t chunk_size = (opts->chunk_size > 0) ? (uint32_t)opts->chunk_size : FLASHER_DEFAULT_CHUNK_SIZE;
    uint32_t total_chunks = (uint32_t)((file_size + chunk_size - 1) / chunk_size);
    int port = (opts->port > 0) ? opts->port : FLASHER_DEFAULT_PORT;
    int delay_ms = (opts->packet_delay_ms >= 0) ? opts->packet_delay_ms : FLASHER_DEFAULT_DELAY_MS;

    printf("\n\033[1;36m================================================================================\033[0m\n");
    printf("\033[1;32m[*] Memulai Huawei UDP Multicast Flasher Engine\033[0m\n");
    printf("    Target Firmware : \033[1;37m%s\033[0m (%zu bytes)\n", opts->bin_path, file_size);
    printf("    Total Chunks    : %u chunk (Ukuran per chunk: %u byte)\n", total_chunks, chunk_size);
    printf("    Port Siaran UDP : %d | Checksum: 0x%08X\n", port, file_crc);
    printf("    Mode Transmisi  : %s\n", opts->loop_carousel ? "Continuous Carousel Loop" : "Single Pass");
    printf("\033[1;33m    [Tekan SPACE atau ENTER di terminal ini untuk STOP Flashing]\033[0m\n");
    printf("\033[1;36m================================================================================\033[0m\n\n");

    /* Create UDP Socket */
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("\033[1;31m[!] Gagal membuat UDP socket!\033[0m\n");
        hwnp_free(&pkg);
        return -2;
    }

    /* Enable Broadcast */
    int broadcast_enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (const char *)&broadcast_enable, sizeof(broadcast_enable));

    /* Bind to local interface if specified */
    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0; /* Let OS assign ephemeral source port, matching Huawei flasher behavior */
    if (opts->bind_ip && strlen(opts->bind_ip) > 0) {
        bind_addr.sin_addr.s_addr = inet_addr(opts->bind_ip);
    } else {
        bind_addr.sin_addr.s_addr = INADDR_ANY;
    }
    bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr));

    /* Destination Address: 255.255.255.255:port */
    struct sockaddr_in dest_bcast;
    memset(&dest_bcast, 0, sizeof(dest_bcast));
    dest_bcast.sin_family = AF_INET;
    dest_bcast.sin_port = htons((uint16_t)port);
    dest_bcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    /* Pre-allocate packet buffers */
    uint8_t ctrl_pkt[FLASHER_CTRL_PACKET_SIZE];
    build_control_packet(ctrl_pkt, file_size, file_crc, pkg.board_ids, total_chunks, chunk_size);

    uint8_t *data_pkt = (uint8_t *)malloc(FLASHER_DATA_HDR_SIZE + chunk_size);
    if (!data_pkt) {
        CLOSE_SOCK(sock);
        hwnp_free(&pkg);
        return -3;
    }

    int cycle = 1;
    bool should_stop = false;
    time_t start_time = time(NULL);

    while (!should_stop) {
        if (stop_flag && *stop_flag) break;

        /* Send Control Beacon at start of each cycle */
        sendto(sock, (const char *)ctrl_pkt, FLASHER_CTRL_PACKET_SIZE, 0,
               (struct sockaddr *)&dest_bcast, sizeof(dest_bcast));
        SLEEP_MS(5);

        for (uint32_t i = 0; i < total_chunks; i++) {
            if (stop_flag && *stop_flag) {
                should_stop = true;
                break;
            }
            if (_kbhit()) {
                int key = _getch();
                if (key == ' ' || key == '\r' || key == '\n' || key == 'q' || key == 'Q' || key == 27) {
                    printf("\n\033[1;33m[*] Tombol Stop ditekan oleh pengguna.\033[0m\n");
                    should_stop = true;
                    break;
                }
            }

            size_t offset = (size_t)i * chunk_size;
            size_t cur_len = file_size - offset;
            if (cur_len > chunk_size) cur_len = chunk_size;

            build_data_packet(data_pkt, i, total_chunks, file_size, file_crc,
                              pkg.raw_data + offset, cur_len);

            sendto(sock, (const char *)data_pkt, (int)(FLASHER_DATA_HDR_SIZE + cur_len), 0,
                   (struct sockaddr *)&dest_bcast, sizeof(dest_bcast));

            /* Periodically send control packet beacon every 64 chunks */
            if ((i % 64) == 0 && i > 0) {
                sendto(sock, (const char *)ctrl_pkt, FLASHER_CTRL_PACKET_SIZE, 0,
                       (struct sockaddr *)&dest_bcast, sizeof(dest_bcast));
            }

            if (delay_ms > 0) {
                SLEEP_MS(delay_ms);
            }

            /* Render Terminal / GUI Progress Bar */
            if (i % 8 == 0 || i == total_chunks - 1) {
                time_t now = time(NULL);
                double elapsed = difftime(now, start_time);
                double kb_sent = ((double)cycle * file_size * ((double)(i + 1) / (double)total_chunks)) / 1024.0;
                double speed = (elapsed > 0) ? (kb_sent / elapsed) : 0.0;

                if (opts->on_progress) {
                    opts->on_progress(cycle, i + 1, total_chunks, speed, opts->user_data);
                } else {
                    float pct = ((float)(i + 1) / (float)total_chunks) * 100.0f;
                    int bar_width = 30;
                    int pos = (int)(bar_width * (pct / 100.0f));

                    printf("\r  \033[1;36mPass #%d\033[0m [\033[1;32m", cycle);
                    for (int b = 0; b < bar_width; b++) {
                        if (b < pos) printf("=");
                        else if (b == pos) printf(">");
                        else printf(" ");
                    }
                    printf("\033[0m] \033[1;37m%5.1f%%\033[0m (%u/%u) \033[1;33m%6.1f KB/s\033[0m",
                           pct, i + 1, total_chunks, speed);
                    fflush(stdout);
                }
            }
        }

        printf("\n\033[1;32m[✓] Siklus pengiriman #%d SELESAI (%zu bytes disiarkan).\033[0m\n", cycle, file_size);

        if (!opts->loop_carousel) {
            if (opts->max_cycles > 0 && cycle >= opts->max_cycles) {
                break;
            }
        }
        cycle++;
        SLEEP_MS(50);
    }

    printf("\n\033[1;32m[*] Flashing dihentikan dengan sukses.\033[0m\n");
    free(data_pkt);
    CLOSE_SOCK(sock);
    hwnp_free(&pkg);
    return 0;
}
