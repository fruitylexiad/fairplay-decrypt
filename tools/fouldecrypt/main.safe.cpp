#include <assert.h>
#include <limits.h>
#include <string>
#include <vector>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <time.h>
#include <sys/time.h>
#include <libkern/OSByteOrder.h>

#include <mach/mach.h>

#include "kerninfra/kerninfra.hpp"

#undef PAGE_SIZE
#define PAGE_SIZE 0x4000
#define EXEC_PAGE_SIZE 0x1000

int VERBOSE = 0;
#define DLOG(f_, ...)                                                                            \
{                                                                                                 \
    if (VERBOSE) {                                                                                \
        struct tm _tm123_;                                                                            \
        struct timeval _xxtv123_;                                                                     \
        gettimeofday(&_xxtv123_, NULL);                                                               \
        localtime_r(&_xxtv123_.tv_sec, &_tm123_);                                                     \
        printf("%02d:%02d:%02d.%06d\t", _tm123_.tm_hour, _tm123_.tm_min, _tm123_.tm_sec, _xxtv123_.tv_usec); \
        printf((f_), ##__VA_ARGS__);                                                                  \
        printf("\n");                                                                               \
    }                                                                                              \
};


bool has_prep_kernel = false;
int prepare_kernel() {
    if (!has_prep_kernel) {
        int ret = init_kerninfra(KERNLOG_NONE);
        if (ret) return ret;
        has_prep_kernel = true;
    }
    return 0;
}

extern "C" int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

extern "C" kern_return_t mach_vm_remap(vm_map_t, mach_vm_address_t *, mach_vm_size_t,
                            mach_vm_offset_t, int, vm_map_t, mach_vm_address_t,
                            boolean_t, vm_prot_t *, vm_prot_t *, vm_inherit_t);

void *__mmap(const char *info, void *base, size_t size, int prot, int flags, int fd, size_t off) {
    DLOG("-->> %s mmaping(%p, 0x%zx, %d, 0x%x, %d, 0x%zx)", info, base, size, prot, flags, fd, off);
    void *ret = mmap(base, size, prot, flags, fd, off);
    if (ret == MAP_FAILED) {
        perror("mmap");
    }
    DLOG("<<-- %s mmaping(%p, 0x%zx, %d, 0x%x, %d, 0x%zx) = %p", info, base, size, prot, flags, fd, off, ret);
    return ret;
}

int __mremap_encrypted(const char *info, void *base, size_t cryptsize, uint32_t cryptid, uint32_t cpuType, uint32_t cpuSubType) {
    DLOG("<<-- %s mremap_encrypted(%p, 0x%zx, %d, 0x%x, 0x%x)", info, base, cryptsize, cryptid, cpuType, cpuSubType);
    int ret = mremap_encrypted(base, cryptsize, cryptid, cpuType, cpuSubType);
    if (ret) {
        perror("mremap_encrypted");
    }
    DLOG("-->> %s mremap_encrypted(%p, 0x%zx, %d, 0x%x, 0x%x) = %d", info, base, cryptsize, cryptid, cpuType, cpuSubType, ret);
    return ret;
}

#define LOGINDENT "            "
void debugprint_vme(addr_t _vmentry) {
    auto encVmEntry = _vm_map_entry_p(_vmentry);
    DLOG(LOGINDENT"mmaped entry: %p - %p", (void *)encVmEntry.start().load(), (void *)encVmEntry.end().load());
    DLOG(LOGINDENT"mmaped vme_offset: 0x%llx", encVmEntry.vme_offset().load());
    DLOG(LOGINDENT"mmaped vme_flags: 0x%x", encVmEntry.vme_flags().load());
    DLOG(LOGINDENT"mmaped vme_object: 0x%llx", encVmEntry.vme_object().load());
}

void debugprint_vmobj(addr_t _vmobj) {
    auto vmobj = vm_object_t_p(_vmobj);
    DLOG(LOGINDENT"mmaped vmobj *shadow: %p **shadow: %p", (void *)vmobj.shadow().load_addr(), (void *)vmobj.shadow().shadow().load_addr());
    DLOG(LOGINDENT"mmaped vmobj pager: %p shadow pager: %p", (void *)vmobj.pager().load_addr(), (void *)vmobj.shadow().pager().load_addr());
    DLOG(LOGINDENT"mmaped vmobj shadow pager op: %p", (void *)vmobj.shadow().pager().mo_pager_ops().load_addr());
}

void debugprint_pager(addr_t _pager) {
    auto applePager = apple_protect_pager_t_p(_pager);
    DLOG(LOGINDENT"mmaped vme_object apple protect pager: ", NULL)
    DLOG(LOGINDENT"    backingOff %llx",  applePager.backing_offset().load())
    DLOG(LOGINDENT"    cryptoBackingOff %llx", applePager.crypto_backing_offset().load())
    DLOG(LOGINDENT"    cryptoStart %llx", applePager.crypto_start().load())
    DLOG(LOGINDENT"    cryptoEnd %llx", applePager.crypto_end().load())
    DLOG(LOGINDENT"    cryptInfo %p", (void *)applePager.crypt_info().load())
}
#undef LOGINDENT

static int
unprotect(int f, uint8_t *dupe, int cpuType, int cpuSubType, struct encryption_info_command *info, size_t macho_off)
{
#define LOGINDENT "        "
    assert((info->cryptoff & (EXEC_PAGE_SIZE - 1)) == 0);

    DLOG(LOGINDENT"Going to decrypt crypt page: off 0x%x size 0x%x cryptid %d, cpuType %x cpuSubType %x", info->cryptoff, info->cryptsize, info->cryptid, cpuType, cpuSubType);
    //getchar();

    size_t off_aligned = info->cryptoff & ~(PAGE_SIZE - 1);
    //size_t size_aligned = info->cryptsize + info->cryptoff - off_aligned;
    size_t map_padding = info->cryptoff - off_aligned;
    
    int err = 0;
    void *decryptedBuf = malloc(info->cryptsize);
    if (!decryptedBuf) { perror("malloc"); return 1; }

    if (!(info->cryptoff & (PAGE_SIZE - 1))) {
        DLOG(LOGINDENT"Already 16k aligned, directly go ahead :)");
        void *cryptbase = __mmap("16k-aligned", NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, info->cryptoff + macho_off);
        if (cryptbase == MAP_FAILED) { free(decryptedBuf); return 1; }
        // old-school mremap_encrypted
        if (__mremap_encrypted("unprotect", cryptbase, info->cryptsize, info->cryptid, cpuType, cpuSubType)) {
            munmap(cryptbase, info->cryptsize);
            free(decryptedBuf);
            return 1;
        }
        DLOG(LOGINDENT"    copying %p to %p, size %x", (char *)decryptedBuf, cryptbase, info->cryptsize);
        memmove(decryptedBuf, cryptbase, info->cryptsize);
        munmap(cryptbase, info->cryptsize);
    } else {
#if FOULDECRYPT_ALIGNED_ONLY
        fprintf(stderr, "Unaligned cryptoff refused: kernel patching is disabled in this build\n");
        free(decryptedBuf);
        return 1;
#else
        DLOG(LOGINDENT"Not 16k aligned, trying to do the hack :O");

        if (!!prepare_kernel()) {
            fprintf(stderr, "Failed to init kerninfra!!\n");
            exit(1);
        } else {
            DLOG(LOGINDENT"successfully initialized kerninfra!");
        }

        for (size_t off = off_aligned; off < info->cryptoff + info->cryptsize; off += PAGE_SIZE) {
            size_t off_end = MIN(off + PAGE_SIZE, info->cryptoff + info->cryptsize);
            size_t curMapLen = (off_end - off) & (PAGE_SIZE - 1); if (!curMapLen) curMapLen = PAGE_SIZE;
            size_t inPageStart = off < info->cryptoff ? info->cryptoff - off : 0;
            size_t inPageEnd = curMapLen;
            size_t cryptOff = off + inPageStart;
            DLOG(LOGINDENT"    processing file off %lx-%lx, curPage len: %lx, inPageStart: %lx, inPageEnd: %lx", off, off_end, curMapLen, inPageStart, inPageEnd);
            char *cryptbase = (char *)__mmap("directly 16k-aligned mmap", NULL, curMapLen, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, off + macho_off);

            if (__mremap_encrypted("unprotect", cryptbase, curMapLen, info->cryptid, cpuType, cpuSubType)) {
                munmap(cryptbase, curMapLen);
                return 1;
            }

            auto curp = proc_t_p(current_proc());
            addr_t _encVmEntry = lookup_vm_map_entry(curp.task()._map().load_addr(), (addr_t)(cryptbase));
            DLOG(LOGINDENT"    Got mmaped entry: %p", (void*)_encVmEntry);
            debugprint_vme(_encVmEntry);

            auto encVmEntry = _vm_map_entry_p(_encVmEntry);
            auto vmobj = encVmEntry.vme_object();
            debugprint_vmobj(vmobj.load_addr());
            auto applePager = apple_protect_pager_t_p(vmobj.shadow().pager().load_addr());
            DLOG(LOGINDENT"    mmaped vme_object apple protect pager: ", NULL);
            debugprint_pager(applePager.addr());

            applePager.crypto_backing_offset().store(macho_off + cryptOff);
            applePager.crypto_start().store(inPageStart);

            DLOG(LOGINDENT"    patched mmaped vme_object apple protect pager: ", NULL)
            debugprint_pager(applePager.addr());
            
            DLOG(LOGINDENT"    copying %p to %p, size %lx", (char *)decryptedBuf + cryptOff - info->cryptoff, cryptbase + inPageStart, curMapLen - inPageStart);
            memmove((char *)decryptedBuf + cryptOff - info->cryptoff, cryptbase + inPageStart, curMapLen - inPageStart);

            munmap(cryptbase, curMapLen);
        }
#endif
    }

    if (err) {
        return 1;
    }

    DLOG(LOGINDENT"copying enc pages, size: 0x%x..", info->cryptsize);
    memcpy(dupe + info->cryptoff, decryptedBuf, info->cryptsize);

    DLOG(LOGINDENT"cleaning up...");
    free(decryptedBuf);
    return 0;
#undef LOGINDENT
}

int
decrypt_macho_slide(int f, uint8_t *inputData, uint8_t *outputData, size_t macho_off) {
#define LOGINDENT "    "
    uint32_t offset = 0;
    int cpuType = 0, cpuSubType = 0;
    int ncmds = 0;
    if (*(uint32_t *)inputData == MH_MAGIC_64) { // 64bit
        struct mach_header_64* header = (struct mach_header_64*) inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        offset = sizeof(struct mach_header_64);
    } else if (*(uint32_t *)inputData == MH_MAGIC) { // 32bit
        struct mach_header* header = (struct mach_header*) inputData;
        cpuType = header->cputype;
        cpuSubType = header->cpusubtype;
        ncmds = header->ncmds;
        offset = sizeof(struct mach_header);
    }

    DLOG(LOGINDENT"finding encryption_info segment in slide...");
    
    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.

    struct encryption_info_command *encryption_info = NULL; // for both 32bit and 64bit macho, the command layout are the same
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command* command = (struct load_command*) (inputData + offset);

        if (command->cmd == LC_ENCRYPTION_INFO || command->cmd == LC_ENCRYPTION_INFO_64) {
            DLOG(LOGINDENT"    found encryption_info segment at offset %x", offset);
            encryption_info = (struct encryption_info_command*) command;
            // There should only be ONE header present anyways, so stop after
            // the first one.
            //
            break;
        }

        offset += command->cmdsize;
    }
    if (!encryption_info || !encryption_info->cryptid) {
        DLOG(LOGINDENT"this slide is not encrypted!");
        return 0;
    }
    
    // If "unprotect"'ing is successful, then change the "cryptid" so that
    // the loader does not attempt to decrypt decrypted pages.
    //
    
    DLOG(LOGINDENT"decrypting encrypted data...");
    if (unprotect(f, outputData, cpuType, cpuSubType, encryption_info, macho_off) == 0) {
        encryption_info = (struct encryption_info_command*) (outputData + offset);
        encryption_info->cryptid = 0;
    } else {
        return 1;
    }
    
    return 0;
#undef LOGINDENT
}

struct SafeSlice {
    size_t base;
    size_t size;
    size_t cryptoff;
    size_t cryptsize;
    size_t command;
    uint32_t cryptid;
};

static bool scratch_path(const char *path) {
    return !strncmp(path, "/private/var/tmp/", 17) || !strncmp(path, "/var/tmp/", 9);
}

static int preflight_slice(const uint8_t *data, size_t total, size_t base, size_t size, SafeSlice *out) {
    if (base > total || size > total - base || size < sizeof(struct mach_header)) return 1;
    const uint8_t *p = data + base;
    uint32_t magic;
    memcpy(&magic, p, sizeof(magic));
    size_t header_size = magic == MH_MAGIC_64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    if ((magic != MH_MAGIC && magic != MH_MAGIC_64) || size < header_size) return 1;
    const struct mach_header *h = (const struct mach_header *)p;
    if (h->ncmds > 4096 || h->sizeofcmds > size - header_size) return 1;
    size_t end = header_size + h->sizeofcmds, at = header_size;
    *out = {base, size, 0, 0, 0, 0};
    bool found = false;
    for (uint32_t i = 0; i < h->ncmds; ++i) {
        if (at > end || sizeof(struct load_command) > end - at) return 1;
        const struct load_command *lc = (const struct load_command *)(p + at);
        if (lc->cmdsize < sizeof(*lc) || lc->cmdsize > end - at || lc->cmdsize % 4) return 1;
        if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
            size_t required = lc->cmd == LC_ENCRYPTION_INFO_64 ? sizeof(struct encryption_info_command_64) : sizeof(struct encryption_info_command);
            if (found || lc->cmdsize < required) return 1;
            found = true;
            const struct encryption_info_command *e = (const struct encryption_info_command *)lc;
            out->cryptoff = e->cryptoff;
            out->cryptsize = e->cryptsize;
            out->cryptid = e->cryptid;
            out->command = at;
            if (e->cryptoff > size || e->cryptsize > size - e->cryptoff) return 1;
            if (e->cryptid && (e->cryptid != 1 || !e->cryptsize ||
                e->cryptoff < end || (e->cryptoff & 0x3fff) ||
                (base & 0x3fff) || (e->cryptsize & 0x3fff))) {
                fprintf(stderr, "Refusing unsupported or unaligned encrypted slice; kernel patching is disabled\n");
                return 1;
            }
        }
        at += lc->cmdsize;
    }
    return at == end ? 0 : 1;
}

int decrypt_macho(const char *inputFile, const char *outputFile) {
    char input_real[PATH_MAX], output_parent[PATH_MAX];
    if (!realpath(inputFile, input_real) || !scratch_path(input_real)) {
        fprintf(stderr, "Input must resolve inside /var/tmp; no app-container paths are accepted\n");
        return 1;
    }
    std::string output_path(outputFile);
    size_t slash = output_path.find_last_of('/');
    std::string parent = slash == std::string::npos ? "." : output_path.substr(0, slash);
    std::string name = slash == std::string::npos ? output_path : output_path.substr(slash + 1);
    if (parent.empty()) parent = "/";
    if (name.empty() || name == "." || name == ".." || !realpath(parent.c_str(), output_parent) ||
        !scratch_path((std::string(output_parent) + "/").c_str())) {
        fprintf(stderr, "Output parent must resolve inside /var/tmp\n");
        return 1;
    }
    int input = open(input_real, O_RDONLY | O_NOFOLLOW);
    if (input < 0) { perror("open input"); return 1; }
    struct stat st;
    if (fstat(input, &st) || !S_ISREG(st.st_mode) || st.st_size < 28 || (uint64_t)st.st_size > SIZE_MAX) {
        fprintf(stderr, "Invalid input file\n"); close(input); return 1;
    }
    size_t size = (size_t)st.st_size;
    uint8_t *data = (uint8_t *)mmap(NULL, size, PROT_READ, MAP_PRIVATE, input, 0);
    if (data == MAP_FAILED) { perror("map input"); close(input); return 1; }
    std::vector<SafeSlice> slices;
    uint32_t magic;
    memcpy(&magic, data, 4);
    int failed = 0;
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        bool swap = magic == FAT_CIGAM;
        auto value = [swap](uint32_t n) { return swap ? OSSwapInt32(n) : n; };
        if (size < sizeof(struct fat_header)) failed = 1;
        else {
            const struct fat_header *fh = (const struct fat_header *)data;
            uint32_t count = value(fh->nfat_arch);
            if (!count || count > 32 || count > (size - sizeof(*fh)) / sizeof(struct fat_arch)) failed = 1;
            else {
                const struct fat_arch *arches = (const struct fat_arch *)(fh + 1);
                for (uint32_t i = 0; i < count && !failed; ++i) {
                    size_t base = value(arches[i].offset), length = value(arches[i].size);
                    SafeSlice slice;
                    if (base < sizeof(*fh) + count * sizeof(*arches) || preflight_slice(data, size, base, length, &slice)) failed = 1;
                    for (const auto &previous : slices)
                        if (base < previous.base + previous.size && previous.base < base + length) failed = 1;
                    if (!failed) slices.push_back(slice);
                }
            }
        }
    } else {
        SafeSlice slice;
        failed = preflight_slice(data, size, 0, size, &slice);
        if (!failed) slices.push_back(slice);
    }
    unsigned encrypted = 0;
    for (const auto &slice : slices) encrypted += slice.cryptid != 0;
    if (failed || !encrypted) {
        fprintf(stderr, "Preflight failed or no encrypted slices; no output created\n");
        munmap(data, size); close(input); return 1;
    }
    int directory = open(output_parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    int output = directory < 0 ? -1 : openat(directory, name.c_str(), O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW, 0600);
    if (directory >= 0) close(directory);
    if (output < 0) { perror("create NEW output (existing files are refused)"); munmap(data, size); close(input); return 1; }
    uint8_t *dupe = (uint8_t *)MAP_FAILED;
    if (ftruncate(output, (off_t)size)) { perror("size output"); failed = 1; }
    if (!failed) {
        dupe = (uint8_t *)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, output, 0);
        if (dupe == MAP_FAILED) { perror("map output"); failed = 1; }
    }
    if (!failed) {
        memcpy(dupe, data, size);
        for (const auto &slice : slices) {
            if (!slice.cryptid) continue;
            if (decrypt_macho_slide(input, data + slice.base, dupe + slice.base, slice.base)) { failed = 1; break; }
            const struct encryption_info_command *e = (const struct encryption_info_command *)(dupe + slice.base + slice.command);
            if (e->cryptid != 0 || !memcmp(data + slice.base + slice.cryptoff, dupe + slice.base + slice.cryptoff, slice.cryptsize)) {
                fprintf(stderr, "Verification failed: cryptid not zero or encrypted bytes unchanged\n"); failed = 1; break;
            }
            fprintf(stderr, "Slice offset=%#zx cryptoff=%#zx cryptsize=%#zx: cryptid=0, encrypted-region bytes changed\n",
                    slice.base, slice.cryptoff, slice.cryptsize);
        }
        if (msync(dupe, size, MS_SYNC) || fsync(output)) { perror("flush output"); failed = 1; }
    }
    if (dupe != MAP_FAILED) munmap(dupe, size);
    munmap(data, size); close(input);
    if (close(output)) { perror("close output"); failed = 1; }
    if (failed) fprintf(stderr, "FAILED: newly created output is incomplete/unverified; do not use it\n");
    else fprintf(stderr, "Header and changed-byte checks passed; independently verify the saved output on the PC\n");
    return failed ? 1 : 0;
}
