#include "hwnp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
  #include <direct.h>
  #define MKDIR(path) _mkdir(path)
#else
  #define MKDIR(path) mkdir(path, 0755)
#endif

/* Precomputed CRC32 table (IEEE 802.3, standard polynomial 0xEDB88320) */
static uint32_t crc32_table[256];
static int crc32_table_init = 0;

static void init_crc32_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) {
            if (c & 1) {
                c = 0xEDB88320L ^ (c >> 1);
            } else {
                c = c >> 1;
            }
        }
        crc32_table[i] = c;
    }
    crc32_table_init = 1;
}

uint32_t hwnp_crc32(const uint8_t *data, size_t length) {
    if (!crc32_table_init) {
        init_crc32_table();
    }
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

static uint32_t read_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int hwnp_load(const char *filepath, hwnp_package_t *pkg) {
    if (!filepath || !pkg) return -1;
    memset(pkg, 0, sizeof(*pkg));

    FILE *f = fopen(filepath, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize < 0x128 + HWNP_ENTRY_SIZE) {
        fclose(f);
        return -2; /* Too small for valid header */
    }

    pkg->raw_data = (uint8_t *)malloc(fsize);
    if (!pkg->raw_data) {
        fclose(f);
        return -3; /* Out of memory */
    }

    if (fread(pkg->raw_data, 1, fsize, f) != (size_t)fsize) {
        free(pkg->raw_data);
        pkg->raw_data = NULL;
        fclose(f);
        return -4;
    }
    fclose(f);
    pkg->raw_size = (size_t)fsize;

    /* Parse header */
    pkg->magic = read_le32(pkg->raw_data + 0x00);
    if (pkg->magic != HWNP_MAGIC && pkg->magic != HWTP_MAGIC) {
        free(pkg->raw_data);
        pkg->raw_data = NULL;
        return -5; /* Invalid Magic */
    }

    pkg->total_payload_size = read_be32(pkg->raw_data + 0x04);
    pkg->stored_header_crc = read_le32(pkg->raw_data + 0x08);
    pkg->first_file_offset = read_le32(pkg->raw_data + 0x0C);
    pkg->timestamp_crc = read_le32(pkg->raw_data + 0x10);
    pkg->file_count = read_le32(pkg->raw_data + 0x14);
    pkg->version_flag = read_le32(pkg->raw_data + 0x18);
    pkg->entry_size = read_le32(pkg->raw_data + 0x1C);

    if (pkg->entry_size == 0) pkg->entry_size = HWNP_ENTRY_SIZE;

    /* Verify file header CRC32: bytes from 0x0C to end of file */
    pkg->calculated_header_crc = hwnp_crc32(pkg->raw_data + 0x0C, pkg->raw_size - 0x0C);
    pkg->is_valid = (pkg->stored_header_crc == pkg->calculated_header_crc);

    /* Read Board ID list */
    memcpy(pkg->board_ids, pkg->raw_data + 0x24, HWNP_BOARD_LEN - 1);
    pkg->board_ids[HWNP_BOARD_LEN - 1] = '\0';

    /* Parse File Entries */
    if (pkg->file_count > HWNP_MAX_FILES) {
        pkg->file_count = HWNP_MAX_FILES;
    }

    size_t table_offset = 0x128;
    for (uint32_t i = 0; i < pkg->file_count; i++) {
        size_t e_off = table_offset + (i * pkg->entry_size);
        if (e_off + pkg->entry_size > pkg->raw_size) break;

        const uint8_t *e_ptr = pkg->raw_data + e_off;
        pkg->entries[i].crc32 = read_le32(e_ptr + 0x00);
        pkg->entries[i].offset = read_le32(e_ptr + 0x04);
        pkg->entries[i].size = read_le32(e_ptr + 0x08);

        memcpy(pkg->entries[i].path, (const char *)(e_ptr + 0x0C), HWNP_PATH_LEN - 1);
        pkg->entries[i].path[HWNP_PATH_LEN - 1] = '\0';

        if (pkg->entries[i].offset + pkg->entries[i].size <= pkg->raw_size) {
            pkg->entries[i].data = pkg->raw_data + pkg->entries[i].offset;
        } else {
            pkg->entries[i].data = NULL;
        }
    }

    return 0;
}

void hwnp_free(hwnp_package_t *pkg) {
    if (pkg && pkg->raw_data) {
        free(pkg->raw_data);
        pkg->raw_data = NULL;
        pkg->raw_size = 0;
    }
}

void hwnp_print_info(const hwnp_package_t *pkg) {
    if (!pkg) return;
    printf("Container Magic : %s\n", (pkg->magic == HWNP_MAGIC) ? "HWNP (Network Packet)" : "HWTP");
    printf("Total Raw Size  : %zu bytes\n", pkg->raw_size);
    printf("Header Checksum : Stored=0x%08X | Calc=0x%08X [%s]\n",
           pkg->stored_header_crc, pkg->calculated_header_crc,
           pkg->is_valid ? "VALID" : "MISMATCH");
    printf("Target Boards   : %s\n", pkg->board_ids[0] ? pkg->board_ids : "(All boards)");
    printf("Files Packaged  : %u file(s)\n", pkg->file_count);
    printf("--------------------------------------------------------------------------------\n");
    printf(" #  Offset      Size (Bytes)  CRC32       Integrity  Target Path\n");
    printf("--------------------------------------------------------------------------------\n");
    for (uint32_t i = 0; i < pkg->file_count; i++) {
        const hwnp_file_entry_t *e = &pkg->entries[i];
        bool ok = false;
        if (e->data && e->size > 0) {
            uint32_t c = hwnp_crc32(e->data, e->size);
            ok = (c == e->crc32);
        }
        printf("[%02u] 0x%08X  %10u  0x%08X  [%s]   %s\n",
               i + 1, e->offset, e->size, e->crc32,
               ok ? "OK " : "ERR", e->path);
    }
    printf("--------------------------------------------------------------------------------\n");
}

static void recursive_mkdir(const char *dir) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (len == 0) return;
    if (tmp[len - 1] == '/' || tmp[len - 1] == '\\') tmp[len - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            *p = '\0';
            MKDIR(tmp);
            *p = '/';
        }
    }
    MKDIR(tmp);
}

int hwnp_extract_all(const hwnp_package_t *pkg, const char *out_dir) {
    if (!pkg || !pkg->raw_data || !out_dir) return -1;
    recursive_mkdir(out_dir);

    for (uint32_t i = 0; i < pkg->file_count; i++) {
        const hwnp_file_entry_t *e = &pkg->entries[i];
        if (!e->data || e->size == 0) continue;

        /* Strip "file:/" or "flash:" prefix */
        const char *rel_name = e->path;
        if (strncmp(rel_name, "file:/", 6) == 0) rel_name += 6;
        else if (strncmp(rel_name, "file:", 5) == 0) rel_name += 5;
        else if (strncmp(rel_name, "flash:", 6) == 0) rel_name += 6;
        while (*rel_name == '/' || *rel_name == '\\') rel_name++;

        char dest_path[1024];
        snprintf(dest_path, sizeof(dest_path), "%s/%s", out_dir, rel_name);

        /* Create directory for file */
        char dir_buf[1024];
        snprintf(dir_buf, sizeof(dir_buf), "%s", dest_path);
        char *last_slash = strrchr(dir_buf, '/');
        if (!last_slash) last_slash = strrchr(dir_buf, '\\');
        if (last_slash) {
            *last_slash = '\0';
            recursive_mkdir(dir_buf);
        }

        FILE *out = fopen(dest_path, "wb");
        if (out) {
            fwrite(e->data, 1, e->size, out);
            fclose(out);
        }
    }
    return 0;
}
