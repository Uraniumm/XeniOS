// Experimental read-only FATX/XTAF image extractor for DmMountFdfxVolume.
// This is a staging implementation, not an image-backed VFS device.
// FATX header and dirents use big-endian integers on Xbox 360.
#ifndef XENIA_KERNEL_XBDM_FDFX_FATX_H_
#define XENIA_KERNEL_XBDM_FDFX_FATX_H_

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

namespace xe::kernel::xbdm::fdfx {

struct ExtractResult {
  size_t files = 0;
  size_t directories = 0;
  uint64_t extracted_bytes = 0;
  std::string error;
};

// The backing file may be shorter than the partition: the native driver
// zero-fills short reads / reads beyond physical EOF.
class FatxExtractor {
 public:
  FatxExtractor(std::span<const uint8_t> image, uint64_t logical_size,
                const std::filesystem::path& output_root)
      : image_(image), logical_size_(logical_size), output_root_(output_root) {}

  bool Extract(ExtractResult* out) {
    if (!out) return false;
    result_ = out;
    *result_ = {};
    if (logical_size_ < 0x3000 || (logical_size_ & 0x1ff)) {
      return Fail("invalid logical partition length");
    }
    uint8_t header[16] = {};
    if (!Read(0, header, sizeof(header)) ||
        std::memcmp(header, "XTAF", 4) != 0) {
      return Fail("missing XTAF signature at partition offset 0");
    }
    const uint32_t sectors_per_cluster = Be32(header + 8);
    root_cluster_ = Be32(header + 12);
    if (sectors_per_cluster < 8 || sectors_per_cluster > 128 ||
        (sectors_per_cluster & (sectors_per_cluster - 1))) {
      return Fail("unsupported FATX cluster size");
    }
    cluster_size_ = uint64_t(sectors_per_cluster) * 512;
    const uint64_t max_clusters = logical_size_ / cluster_size_ + 1;
    fat_entry_size_ = max_clusters < 0xfff0 ? 2 : 4;
    if (max_clusters > (std::numeric_limits<uint32_t>::max() / 4)) {
      return Fail("unreasonable cluster count");
    }
    const uint64_t fat_bytes =
        ((max_clusters * fat_entry_size_ + 0xfff) / 0x1000) * 0x1000;
    data_start_ = 0x1000 + fat_bytes;
    if (data_start_ >= logical_size_) {
      return Fail("FAT region exceeds logical partition");
    }
    cluster_count_ = (logical_size_ - data_start_) / cluster_size_;
    if (!cluster_count_ || root_cluster_ == 0 ||
        root_cluster_ > cluster_count_) {
      return Fail("invalid FATX root directory cluster");
    }
    std::error_code ec;
    std::filesystem::create_directories(output_root_, ec);
    if (ec) return Fail("unable to create extraction directory: " + ec.message());
    return ExtractDirectory(root_cluster_, output_root_, 0);
  }

 private:
  static uint32_t Be32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | uint32_t(p[3]);
  }
  static uint16_t Be16(const uint8_t* p) {
    return uint16_t((uint16_t(p[0]) << 8) | p[1]);
  }
  static void AppendUtf8(std::string& out, uint32_t codepoint) {
    if (codepoint < 0x80) {
      out.push_back(char(codepoint));
    } else if (codepoint < 0x800) {
      out.push_back(char(0xc0 | (codepoint >> 6)));
      out.push_back(char(0x80 | (codepoint & 0x3f)));
    } else {
      out.push_back(char(0xe0 | (codepoint >> 12)));
      out.push_back(char(0x80 | ((codepoint >> 6) & 0x3f)));
      out.push_back(char(0x80 | (codepoint & 0x3f)));
    }
  }
  static bool MakeSafeName(const uint8_t* bytes, uint8_t length,
                           std::string* name) {
    if (length == 0 || length > 42) return false;
    name->clear();
    // Windows-1252 byte -> Unicode, as used in other Xenia disc entries.
    static constexpr uint16_t kCp1252High[32] = {
        0x20ac,0x0081,0x201a,0x0192,0x201e,0x2026,0x2020,0x2021,
        0x02c6,0x2030,0x0160,0x2039,0x0152,0x008d,0x017d,0x008f,
        0x0090,0x2018,0x2019,0x201c,0x201d,0x2022,0x2013,0x2014,
        0x02dc,0x2122,0x0161,0x203a,0x0153,0x009d,0x017e,0x0178};
    for (uint8_t i = 0; i < length; ++i) {
      const uint8_t c = bytes[i];
      if (c < 32 || c == 127 || c == '/' || c == '\\' || c == ':' ||
          c == '"' || c == '*' || c == '?' || c == '<' || c == '>' ||
          c == '|' || c == ';') {
        return false;
      }
      const uint32_t cp = c < 0x80 ? c :
          (c < 0xa0 ? kCp1252High[c - 0x80] : c);
      AppendUtf8(*name, cp);
    }
    return *name != "." && *name != ".." && !name->empty();
  }
  bool Fail(std::string message) {
    result_->error = std::move(message);
    return false;
  }
  bool Read(uint64_t offset, void* destination, size_t count) const {
    if (offset > logical_size_ || count > logical_size_ - offset) return false;
    std::memset(destination, 0, count);
    if (offset < image_.size()) {
      const size_t available = std::min<size_t>(count, image_.size() - size_t(offset));
      std::memcpy(destination, image_.data() + size_t(offset), available);
    }
    return true;
  }
  bool ClusterOffset(uint32_t cluster, uint64_t* offset) const {
    if (cluster < 1 || cluster > cluster_count_) return false;
    const uint64_t value = data_start_ + uint64_t(cluster - 1) * cluster_size_;
    if (value > logical_size_ || cluster_size_ > logical_size_ - value) return false;
    *offset = value;
    return true;
  }
  bool NextCluster(uint32_t cluster, uint32_t* next, bool* end) const {
    if (cluster < 1 || cluster > cluster_count_) return false;
    uint8_t raw[4] = {};
    if (!Read(0x1000 + uint64_t(cluster) * fat_entry_size_,
              raw, fat_entry_size_)) return false;
    *next = fat_entry_size_ == 2 ? Be16(raw) : Be32(raw);
    *end = fat_entry_size_ == 2 ? *next >= 0xfff8 : *next >= 0xfffffff8;
    if (!*end && (*next < 1 || *next > cluster_count_)) return false;
    return true;
  }
  bool ExtractFile(uint32_t first_cluster, uint32_t size,
                   const std::filesystem::path& output) {
    if (size > logical_size_) return Fail("file length exceeds partition");
    std::ofstream stream(output, std::ios::binary | std::ios::trunc);
    if (!stream) return Fail("cannot create an extracted file");
    if (!size) { ++result_->files; return true; }
    if (!first_cluster) return Fail("nonempty file has no first cluster");
    std::unordered_set<uint32_t> seen;
    std::vector<uint8_t> buffer(static_cast<size_t>(cluster_size_));
    uint32_t cluster = first_cluster;
    uint64_t remaining = size;
    while (remaining) {
      if (!seen.insert(cluster).second) return Fail("cycle in file cluster chain");
      uint64_t offset = 0;
      if (!ClusterOffset(cluster, &offset)) return Fail("bad file cluster");
      const size_t count = size_t(std::min<uint64_t>(remaining, cluster_size_));
      if (!Read(offset, buffer.data(), count)) return Fail("file read out of bounds");
      stream.write(reinterpret_cast<const char*>(buffer.data()), count);
      if (!stream) return Fail("could not write extracted file data");
      remaining -= count;
      if (remaining) {
        uint32_t next = 0;
        bool end = false;
        if (!NextCluster(cluster, &next, &end) || end)
          return Fail("file cluster chain ended prematurely");
        cluster = next;
      }
    }
    ++result_->files;
    result_->extracted_bytes += size;
    return true;
  }
  bool ExtractDirectory(uint32_t first_cluster,
                        const std::filesystem::path& output, unsigned depth) {
    if (depth > 24 || result_->directories > 4096)
      return Fail("directory depth or count exceeded");
    if (!seen_directory_clusters_.insert(first_cluster).second)
      return Fail("directory recursion cycle");
    if (depth) ++result_->directories;
    uint32_t cluster = first_cluster;
    std::unordered_set<uint32_t> seen_chain;
    std::unordered_set<std::string> child_names;
    std::vector<uint8_t> buffer(static_cast<size_t>(cluster_size_));
    for (;;) {
      if (!seen_chain.insert(cluster).second)
        return Fail("cycle in directory cluster chain");
      uint64_t offset = 0;
      if (!ClusterOffset(cluster, &offset) ||
          !Read(offset, buffer.data(), buffer.size()))
        return Fail("bad directory cluster");
      for (size_t i = 0; i + 0x40 <= buffer.size(); i += 0x40) {
        const uint8_t* e = buffer.data() + i;
        const uint8_t len = e[0];
        if (len == 0xff) return true;  // Unused end-of-directory marker.
        if (len == 0 || len == 0xe5) continue;
        std::string name;
        if (!MakeSafeName(e + 2, len, &name))
          return Fail("unsafe or malformed FATX entry name");
        // FATX is case-insensitive; detect colliding names explicitly.
        std::string key = name;
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
          return char(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        });
        if (!child_names.insert(key).second) return Fail("duplicate FATX name");
        if (result_->files + result_->directories > 20000)
          return Fail("too many FATX entries");
        const uint32_t first = Be32(e + 0x2c);
        const uint32_t length = Be32(e + 0x30);
        const std::filesystem::path child = output / name;
        if (e[1] & 0x10) {
          std::error_code ec;
          std::filesystem::create_directory(child, ec);
          if (ec) return Fail("could not create FATX directory: " + ec.message());
          if (!ExtractDirectory(first, child, depth + 1)) return false;
        } else if (!ExtractFile(first, length, child)) {
          return false;
        }
      }
      uint32_t next = 0;
      bool end = false;
      if (!NextCluster(cluster, &next, &end))
        return Fail("invalid directory FAT chain");
      if (end) return true;
      cluster = next;
    }
  }

  std::span<const uint8_t> image_;
  uint64_t logical_size_ = 0;
  std::filesystem::path output_root_;
  uint64_t cluster_size_ = 0;
  uint64_t data_start_ = 0;
  uint64_t cluster_count_ = 0;
  uint32_t root_cluster_ = 0;
  uint32_t fat_entry_size_ = 0;
  ExtractResult* result_ = nullptr;
  std::unordered_set<uint32_t> seen_directory_clusters_;
};

}  // namespace xe::kernel::xbdm::fdfx

#endif  // XENIA_KERNEL_XBDM_FDFX_FATX_H_
