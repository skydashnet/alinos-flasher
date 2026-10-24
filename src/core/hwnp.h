#ifndef HWNP_H
#define HWNP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define HWNP_MAGIC          0x504E5748  /* "HWNP" in little-endian / 0x48574E50 in big-endian */
#define HWTP_MAGIC          0x50545748  /* "HWTP" in little-endian / 0x48575450 in big-endian */
#define HWNP_ENTRY_SIZE     360
#define HWNP_MAX_FILES      32
#define HWNP_BOARD_LEN      128
#define HWNP_PATH_LEN       348

typedef struct {
    uint32_t crc32;
    uint32_t offset;
    uint32_t size;
    char path[HWNP_PATH_LEN];
    const uint8_t *data; /* pointer into package buffer */
} hwnp_file_entry_t;

typedef struct {
    uint32_t magic;
    uint32_t total_payload_size;
    uint32_t stored_header_crc;
    uint32_t calculated_header_crc;
    uint32_t first_file_offset;
    uint32_t timestamp_crc;
    uint32_t file_count;
    uint32_t version_flag;
    uint32_t entry_size;
    char board_ids[HWNP_BOARD_LEN];
    hwnp_file_entry_t entries[HWNP_MAX_FILES];
    uint8_t *raw_data;
    size_t raw_size;
    bool is_valid;
} hwnp_package_t;

/* Calculates standard IEEE 802.3 CRC32 (polynomial 0xEDB88320) */
uint32_t hwnp_crc32(const uint8_t *data, size_t length);

/* Load and parse a .bin file into an hwnp_package_t */
int hwnp_load(const char *filepath, hwnp_package_t *pkg);

/* Free allocated memory inside hwnp_package_t */
void hwnp_free(hwnp_package_t *pkg);

/* Display package metadata, boards, and file entries */
void hwnp_print_info(const hwnp_package_t *pkg);

/* Extract all files in package to destination directory */
int hwnp_extract_all(const hwnp_package_t *pkg, const char *out_dir);

#endif /* HWNP_H */
