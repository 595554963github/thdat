#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

#pragma pack(push, 1)
struct TH95ArchiveHeader {
    char magic[4];
    uint32_t size;
    uint32_t zsize;
    uint32_t entry_count;
};
#pragma pack(pop)

struct DatEntry {
    char name[256];
    uint32_t offset;
    uint32_t size;
    uint32_t zsize;
};

struct crypt_params_t {
    unsigned char key;
    unsigned char step;
    unsigned int block;
    unsigned int limit;
};

static const crypt_params_t th95_crypt_params[] = {
    {0x1b, 0x37, 0x40, 0x2800},
    {0x51, 0xe9, 0x40, 0x3000},
    {0xc1, 0x51, 0x80, 0x3200},
    {0x03, 0x19, 0x400, 0x7800},
    {0xab, 0xcd, 0x200, 0x2800},
    {0x12, 0x34, 0x80, 0x3200},
    {0x35, 0x97, 0x80, 0x2800},
    {0x99, 0x37, 0x400, 0x2000}
};

static const crypt_params_t th12_crypt_params[] = {
    {0x1b, 0x73, 0x40, 0x3800},
    {0x51, 0x9e, 0x40, 0x4000},
    {0xc1, 0x15, 0x400, 0x2c00},
    {0x03, 0x91, 0x80, 0x6400},
    {0xab, 0xdc, 0x80, 0x6e00},
    {0x12, 0x43, 0x200, 0x3c00},
    {0x35, 0x79, 0x400, 0x3c00},
    {0x99, 0x7d, 0x80, 0x2800}
};

static const crypt_params_t th13_crypt_params[] = {
    {0x1b, 0x73, 0x100, 0x3800},
    {0x12, 0x43, 0x200, 0x3e00},
    {0x35, 0x79, 0x400, 0x3c00},
    {0x03, 0x91, 0x80, 0x6400},
    {0xab, 0xdc, 0x80, 0x6e00},
    {0x51, 0x9e, 0x100, 0x4000},
    {0xc1, 0x15, 0x400, 0x2c00},
    {0x99, 0x7d, 0x80, 0x4400}
};

static const crypt_params_t th14_crypt_params[] = {
    {0x1b, 0x73, 0x100, 0x3800},
    {0x12, 0x43, 0x200, 0x3e00},
    {0x35, 0x79, 0x400, 0x3c00},
    {0x03, 0x91, 0x80, 0x6400},
    {0xab, 0xdc, 0x80, 0x7000},
    {0x51, 0x9e, 0x100, 0x4000},
    {0xc1, 0x15, 0x400, 0x2c00},
    {0x99, 0x7d, 0x80, 0x4400}
};

unsigned int th95_get_crypt_param_index(const char* name) {
    unsigned char index = 0;
    while (*name) index += *name++;
    return index & 7;
}

const crypt_params_t* th95_get_crypt_param(unsigned int version, const char* name) {
    unsigned int i = th95_get_crypt_param_index(name);

    switch (version) {
    case 95:
    case 10:
    case 103:
    case 11:
        return &th95_crypt_params[i];
    case 12:
    case 125:
    case 128:
        return &th12_crypt_params[i];
    case 13:
        return &th13_crypt_params[i];
    case 14:
    case 143:
    case 15:
    case 16:
    case 165:
    case 17:
    case 18:
    case 185:
    case 19:
    case 20:
    default:
        return &th14_crypt_params[i];
    }
}

void th_decrypt(unsigned char* data, unsigned int size, unsigned char key, unsigned char step, unsigned int block, unsigned int limit) {
    if (!data || size == 0) return;

    unsigned char* temp = (unsigned char*)malloc(block);
    unsigned int increment = (block >> 1) + (block & 1);

    if (size < block >> 2)
        size = 0;
    else
        size -= (size % block < block >> 2) * (size % block) + (size % 2);

    if (limit % block != 0)
        limit = limit + (block - (limit % block));

    unsigned char* end = data + (size < limit ? size : limit);

    while (data < end) {
        unsigned char* in = data;
        unsigned char* out;
        if ((unsigned int)(end - data) < block) {
            block = (unsigned int)(end - data);
            increment = (block >> 1) + (block & 1);
        }

        for (out = temp + block - 1; out > temp;) {
            *out-- = *in ^ key;
            *out-- = *(in + increment) ^ (key + step * increment);
            ++in;
            key += step;
        }

        if (block & 1) {
            *out = *in ^ key;
            key += step;
        }
        key += step * increment;

        memcpy(data, temp, block);
        data += block;
    }

    free(temp);
}

static void th_crypt105_list(unsigned char* data, unsigned int size, unsigned int key) {
    if (!data) return;

    unsigned int mt[624];
    int index = 0;

    mt[0] = key;
    for (int i = 1; i < 624; i++) {
        mt[i] = (0x6C078965UL * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFFUL;
    }

    for (unsigned int i = 0; i < size; i++) {
        if (index == 0) {
            for (int j = 0; j < 624; j++) {
                unsigned int y = (mt[j] & 0x80000000UL) + (mt[(j + 1) % 624] & 0x7FFFFFFFUL);
                mt[j] = mt[(j + 397) % 624] ^ (y >> 1);
                if (y & 1) mt[j] ^= 0x9908B0DFUL;
            }
        }

        unsigned int y = mt[index];
        y ^= (y >> 11);
        y ^= ((y << 7) & 0x9D2C5680UL);
        y ^= ((y << 15) & 0xEFC60000UL);
        y ^= (y >> 18);

        data[i] ^= (y & 0xFF);
        index = (index + 1) % 624;
    }
}

static void th_crypt105_file(unsigned char* data, unsigned int size, unsigned int offset, unsigned char or_key) {
    if (!data) return;
    unsigned char key = ((offset >> 1) | or_key) & 0xFF;
    for (unsigned int i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

static void th105_data_crypt(unsigned int version, uint32_t offset, unsigned char* data, uint32_t size) {
    if (!data) return;

    if (version == 7575) {
        th_crypt105_file(data, size, offset, 0x08);
    }
    else if (version == 105105 || version == 105 || version == 123) {
        th_crypt105_file(data, size, offset, 0x23);
    }
}

static int th105_open(FILE* stream, unsigned int version, size_t* entry_count, DatEntry** entries) {
    if (!stream) return 0;
    fseek(stream, 0, SEEK_SET);

    unsigned short ec;
    unsigned int header_size;

    if (fread(&ec, 2, 1, stream) != 1) return 0;
    if (fread(&header_size, 4, 1, stream) != 1) return 0;

    if (header_size == 0) {
        *entry_count = 0;
        *entries = NULL;
        return 1;
    }

    unsigned char* header_buf = (unsigned char*)malloc(header_size);
    if (!header_buf) return 0;

    if (fread(header_buf, 1, header_size, stream) != header_size) {
        free(header_buf);
        return 0;
    }

    th_crypt105_list(header_buf, header_size, 6 + header_size);
    if (version != 105105) {
        unsigned char* ptr = header_buf;
        unsigned char key = 0xC5;
        unsigned char step1 = 0x83;
        unsigned char step2 = 0x53;
        for (unsigned int i = 0; i < header_size; ++i) {
            *ptr++ ^= key;
            key += step1;
            step1 += step2;
        }
    }

    *entry_count = ec;
    *entries = (DatEntry*)calloc(ec, sizeof(DatEntry));
    if (!*entries) {
        free(header_buf);
        return 0;
    }

    if (ec > 0) {
        unsigned char* ptr = header_buf;
        for (unsigned short i = 0; i < ec; ++i) {
            DatEntry* entry = *entries + i;
            memset(entry->name, 0, sizeof(entry->name));

            if (ptr + 8 > header_buf + header_size) break;

            entry->offset = *(uint32_t*)ptr;
            ptr += 4;
            entry->size = *(uint32_t*)ptr;
            ptr += 4;

            if (ptr >= header_buf + header_size) break;
            unsigned char name_length = *ptr++;

            if (name_length > 0 && ptr + name_length <= header_buf + header_size) {
                strncpy(entry->name, (const char*)ptr, name_length);
                ptr += name_length;
            }
            entry->zsize = entry->size;
        }
    }

    free(header_buf);
    return 1;
}

struct bitstream {
    unsigned char* buffer;
    size_t buffer_size;
    size_t buffer_pos;
    unsigned int byte;
    unsigned int bits;
    unsigned int byte_count;
};

void bitstream_init_buffer(bitstream* b, unsigned char* buffer, size_t size) {
    b->buffer = buffer;
    b->buffer_size = size;
    b->buffer_pos = 0;
    b->byte = 0;
    b->bits = 0;
    b->byte_count = 0;
}

uint32_t bitstream_read_buffer(bitstream* b, unsigned int bits) {
    while (bits > b->bits) {
        unsigned char c = 0;
        if (b->buffer_pos < b->buffer_size) {
            c = b->buffer[b->buffer_pos++];
        }
        b->byte = (b->byte << 8) | c;
        b->bits += 8;
        b->byte_count++;
    }
    b->bits -= bits;
    return (b->byte >> b->bits) & ((1 << bits) - 1);
}

size_t th_unlzss_buffer(unsigned char* input, size_t input_size, unsigned char* output, size_t output_size) {
    unsigned char dict[0x2000];
    unsigned int dict_head = 1;
    size_t bytes_written = 0;
    bitstream bs;

    bitstream_init_buffer(&bs, input, input_size);
    memset(dict, 0, sizeof(dict));

    while (bytes_written < output_size) {
        if (bitstream_read_buffer(&bs, 1)) {
            unsigned char c = bitstream_read_buffer(&bs, 8);
            if (output) output[bytes_written] = c;
            bytes_written++;
            dict[dict_head] = c;
            dict_head = (dict_head + 1) & 0x1fff;
        }
        else {
            unsigned int match_offset = bitstream_read_buffer(&bs, 13);
            if (!match_offset) break;

            unsigned int match_len = bitstream_read_buffer(&bs, 4) + 3;

            for (unsigned int i = 0; i < match_len; ++i) {
                unsigned char c = dict[(match_offset + i) & 0x1fff];
                if (output) output[bytes_written] = c;
                bytes_written++;
                dict[dict_head] = c;
                dict_head = (dict_head + 1) & 0x1fff;
                if (bytes_written >= output_size) break;
            }
        }
    }

    return bytes_written;
}

void fix_png_file(std::vector<unsigned char>& data) {
    if (data.size() < 8) return;

    if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 &&
        data[4] == 0x0D && data[5] == 0x0A && data[6] == 0x1A && data[7] == 0x0A) {
        return;
    }

    size_t i = 0;
    while (i < data.size()) {
        if (i + 4 <= data.size()) {
            uint32_t chunk_length = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3];
            if (i + 12 + chunk_length > data.size()) break;

            if (i == 0 && chunk_length == 0x0D && i + 12 <= data.size()) {
                if (data[i + 4] == 'I' && data[i + 5] == 'H' && data[i + 6] == 'D' && data[i + 7] == 'R') {
                    data[0] = 0x89;
                    data[1] = 0x50;
                    data[2] = 0x4E;
                    data[3] = 0x47;
                    data[4] = 0x0D;
                    data[5] = 0x0A;
                    data[6] = 0x1A;
                    data[7] = 0x0A;
                    return;
                }
            }

            i += 12 + chunk_length;
        }
        else {
            break;
        }
    }
}

void create_directories_for_path(const char* filepath) {
    char path[MAX_PATH];
    strncpy(path, filepath, sizeof(path));
    path[sizeof(path) - 1] = 0;

    char* p = path;
    while (*p) {
        if (*p == '/') {
            *p = '\\';
        }
        p++;
    }

    p = strchr(path, '\\');
    while (p) {
        char old_char = *(p + 1);
        *(p + 1) = 0;
        CreateDirectoryA(path, NULL);
        *(p + 1) = old_char;
        p = strchr(p + 1, '\\');
    }
}

bool IsTh95Format(unsigned int version) {
    return (version == 95 || version == 10 || version == 103 || version == 11 ||
        version == 12 || version == 125 || version == 128 || version == 13 ||
        version == 14 || version == 143 || version == 15 || version == 16 ||
        version == 165 || version == 17 || version == 18 || version == 185 ||
        version == 19 || version == 20);
}

bool IsTh105Format(unsigned int version) {
    return (version == 75 || version == 7575 || version == 105105 ||
        version == 105 || version == 123);
}

bool ExtractTh95Dat(const char* datPath, unsigned int version) {
    FILE* datFile = NULL;
    fopen_s(&datFile, datPath, "rb");
    if (!datFile) {
        printf("Failed to open file: %s\n", datPath);
        return false;
    }

    TH95ArchiveHeader header;
    if (fread(&header, sizeof(header), 1, datFile) != 1) {
        printf("Failed to read file header\n");
        fclose(datFile);
        return false;
    }

    th_decrypt((unsigned char*)&header, sizeof(header), 0x1b, 0x37, sizeof(header), sizeof(header));

    if (memcmp(header.magic, "THA1", 4) != 0) {
        printf("Invalid THA1 file header\n");
        fclose(datFile);
        return false;
    }

    uint32_t list_size = header.size - 123456789;
    uint32_t list_zsize = header.zsize - 987654321;
    uint32_t entry_count = header.entry_count - 135792468;

    printf("List size: %u, Compressed size: %u, File count: %u\n", list_size, list_zsize, entry_count);

    fseek(datFile, -(long)list_zsize, SEEK_END);

    unsigned char* zlist = (unsigned char*)malloc(list_zsize);
    if (!zlist || fread(zlist, list_zsize, 1, datFile) != 1) {
        printf("Failed to read file list\n");
        if (zlist) free(zlist);
        fclose(datFile);
        return false;
    }

    th_decrypt(zlist, list_zsize, 0x3e, 0x9b, 0x80, list_zsize);

    unsigned char* list = (unsigned char*)malloc(list_size);
    if (!list) {
        printf("Memory allocation failed\n");
        free(zlist);
        fclose(datFile);
        return false;
    }

    size_t decompressed = th_unlzss_buffer(zlist, list_zsize, list, list_size);
    free(zlist);

    if (decompressed != list_size) {
        printf("Failed to decompress file list: %zu/%u\n", decompressed, list_size);
        free(list);
        fclose(datFile);
        return false;
    }

    std::vector<DatEntry> entries(entry_count);
    unsigned char* ptr = list;
    unsigned char* list_end = list + list_size;

    for (uint32_t i = 0; i < entry_count; ++i) {
        if (ptr >= list_end) {
            printf("File list is corrupted\n");
            break;
        }

        size_t name_len = strlen((const char*)ptr);
        if (name_len > 255) name_len = 255;
        strncpy(entries[i].name, (const char*)ptr, name_len);
        entries[i].name[name_len] = '\0';
        ptr += name_len + 1;

        while ((uintptr_t)ptr % 4 != 0) ptr++;

        if (ptr + 12 > list_end) {
            printf("File list is corrupted\n");
            break;
        }

        entries[i].offset = *(uint32_t*)ptr; ptr += 4;
        entries[i].size = *(uint32_t*)ptr; ptr += 4;
        ptr += 4;
        entries[i].zsize = 0;

        if (i > 0) {
            entries[i - 1].zsize = entries[i].offset - entries[i - 1].offset;
        }
    }

    fseek(datFile, 0, SEEK_END);
    long filesize = ftell(datFile);
    fseek(datFile, 0, SEEK_SET);

    if (entry_count > 0) {
        entries[entry_count - 1].zsize = (filesize - list_zsize) - entries[entry_count - 1].offset;
    }

    fs::path dat_file(datPath);
    fs::path output_dir = dat_file.parent_path() / dat_file.stem().string();
    fs::create_directories(output_dir);

    int success_count = 0;

    for (uint32_t i = 0; i < entry_count; ++i) {
        if (entries[i].size == 0 || entries[i].zsize == 0) {
            printf("Skipping invalid entry: %s\n", entries[i].name);
            continue;
        }

        fs::path out_path = output_dir / entries[i].name;
        fs::create_directories(out_path.parent_path());

        fseek(datFile, entries[i].offset, SEEK_SET);

        unsigned char* zdata = (unsigned char*)malloc(entries[i].zsize);
        if (!zdata || fread(zdata, entries[i].zsize, 1, datFile) != 1) {
            printf("Failed to read file data: %s\n", entries[i].name);
            if (zdata) free(zdata);
            continue;
        }

        const crypt_params_t* params = th95_get_crypt_param(version, entries[i].name);

        th_decrypt(zdata, entries[i].zsize, params->key, params->step, params->block, params->limit);

        if (entries[i].zsize == entries[i].size) {
            std::vector<unsigned char> data(zdata, zdata + entries[i].size);

            std::string name_str = entries[i].name;
            if (name_str.size() >= 4 && name_str.substr(name_str.size() - 4) == ".png") {
                fix_png_file(data);
            }

            FILE* outFile = NULL;
            fopen_s(&outFile, out_path.string().c_str(), "wb");
            if (outFile) {
                fwrite(data.data(), entries[i].size, 1, outFile);
                fclose(outFile);
                printf("%s\n", entries[i].name);
                success_count++;
            }
        }
        else {
            unsigned char* data = (unsigned char*)malloc(entries[i].size);
            if (!data) {
                printf("Memory allocation failed: %s\n", entries[i].name);
                free(zdata);
                continue;
            }

            size_t decompressed = th_unlzss_buffer(zdata, entries[i].zsize, data, entries[i].size);

            if (decompressed == entries[i].size) {
                std::vector<unsigned char> data_vec(data, data + entries[i].size);

                std::string name_str = entries[i].name;
                if (name_str.size() >= 4 && name_str.substr(name_str.size() - 4) == ".png") {
                    fix_png_file(data_vec);
                }

                FILE* outFile = NULL;
                fopen_s(&outFile, out_path.string().c_str(), "wb");
                if (outFile) {
                    fwrite(data_vec.data(), entries[i].size, 1, outFile);
                    fclose(outFile);
                    printf("%s\n", entries[i].name);
                    success_count++;
                }
            }
            else {
                printf("Decompression failed: %s (%zu/%u)\n", entries[i].name, decompressed, entries[i].size);
            }

            free(data);
        }

        free(zdata);
    }

    free(list);
    fclose(datFile);

    printf("Successfully extracted %d/%u files\n", success_count, entry_count);
    return success_count > 0;
}

bool ExtractTh105Dat(const char* datPath, unsigned int version) {
    FILE* dat_stream = NULL;
    fopen_s(&dat_stream, datPath, "rb");
    if (!dat_stream) {
        printf("Failed to open file: %s\n", datPath);
        return false;
    }

    size_t entry_count = 0;
    DatEntry* entries = NULL;
    if (!th105_open(dat_stream, version, &entry_count, &entries)) {
        printf("Failed to open archive\n");
        if (entries) free(entries);
        fclose(dat_stream);
        return false;
    }

    char output_dir[MAX_PATH];
    char drive[_MAX_DRIVE];
    char dir[_MAX_DIR];
    char fname[_MAX_FNAME];
    _splitpath_s(datPath, drive, sizeof(drive), dir, sizeof(dir), fname, sizeof(fname), NULL, 0);
    _makepath_s(output_dir, sizeof(output_dir), drive, dir, fname, NULL);
    CreateDirectoryA(output_dir, NULL);

    for (size_t i = 0; i < entry_count; i++) {
        DatEntry* entry = &entries[i];
        if (entry->size == 0 || entry->size > 0x10000000) continue;

        char original_name[260];
        strncpy(original_name, entry->name, sizeof(original_name) - 1);
        original_name[sizeof(original_name) - 1] = 0;

        for (char* p = original_name; *p; p++) {
            if (*p == ':' || *p == '*' || *p == '?' || *p == '"' || *p == '<' || *p == '>' || *p == '|') {
                *p = '_';
            }
        }

        char filepath[MAX_PATH];
        snprintf(filepath, sizeof(filepath), "%s\\%s", output_dir, original_name);
        create_directories_for_path(filepath);

        unsigned char* data = (unsigned char*)malloc(entry->size);
        if (!data) {
            printf("Memory allocation failed: %s\n", entry->name);
            continue;
        }

        fseek(dat_stream, entry->offset, SEEK_SET);
        size_t read = fread(data, 1, entry->size, dat_stream);
        if (read != entry->size) {
            free(data);
            printf("Failed to read file: %s (Needed: %u, Read: %zu)\n", entry->name, entry->size, read);
            continue;
        }

        th105_data_crypt(version, entry->offset, data, entry->size);

        FILE* outfile = NULL;
        fopen_s(&outfile, filepath, "wb");
        if (outfile) {
            fwrite(data, 1, entry->size, outfile);
            fclose(outfile);
            printf("Extracted: %s (%u bytes)\n", entry->name, entry->size);
        }
        else {
            printf("Failed to write file: %s\n", filepath);
        }

        free(data);
    }

    printf("Found %zu files\n", entry_count);
    free(entries);
    fclose(dat_stream);
    return true;
}

bool ExtractThDat(const char* datPath, unsigned int version) {
    if (IsTh95Format(version)) {
        return ExtractTh95Dat(datPath, version);
    }
    else if (IsTh105Format(version)) {
        return ExtractTh105Dat(datPath, version);
    }
    else {
        printf("Unsupported version number: %u\n", version);
        return false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <dat file> <version number>\n", argv[0]);
        printf("Supported versions:\n");
        printf("  th95 format: 95,10,11,12,125,128,13,14,143,15,16,165,17,18,185,19,20\n");
        printf("  th105 format: 75,7575,105,105105,123\n");
        return 1;
    }

    const char* dat_file = argv[1];
    unsigned int version = atoi(argv[2]);

    if (ExtractThDat(dat_file, version)) {
        printf("Extraction completed!\n");
        return 0;
    }
    else {
        return 1;
    }
}