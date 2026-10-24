#ifndef FLASHER_H
#define FLASHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FLASHER_DEFAULT_PORT        4891
#define FLASHER_DEFAULT_CHUNK_SIZE  1000
#define FLASHER_DEFAULT_DELAY_MS    2
#define FLASHER_CTRL_PACKET_SIZE    244
#define FLASHER_DATA_HDR_SIZE       20

typedef void (*flasher_progress_cb)(int cycle, uint32_t current_chunk, uint32_t total_chunks, double speed_kbps, void *user_data);

typedef struct {
    const char *bin_path;
    const char *bind_ip;        /* NULL for INADDR_ANY */
    int port;                   /* Default 4891 */
    int chunk_size;             /* Default 1000 */
    int packet_delay_ms;        /* Default 2 */
    bool loop_carousel;         /* Keep looping until user stops (default true) */
    int max_cycles;             /* If not looping, number of full passes (e.g. 1 or 2) */
    flasher_progress_cb on_progress;
    void *user_data;
} flasher_options_t;

/* Initialize socket subsystem (WinSock on Windows) */
int flasher_net_init(void);

/* Cleanup socket subsystem */
void flasher_net_cleanup(void);

/* List detected local IPv4 network adapters */
void flasher_list_interfaces(void);

/* Run the multicast/broadcast firmware streamer */
int flasher_broadcast_firmware(const flasher_options_t *opts, volatile bool *stop_flag);

#endif /* FLASHER_H */
