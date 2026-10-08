#pragma once
#include "irforge/core/Event.hpp"
#include <filesystem>
#include <fstream>
#include <mutex>
namespace irforge {
class JsonlWriter {
    std::filesystem::path directory_;
    std::ofstream events_, alerts_;
    std::mutex mutex_;
    std::size_t lines_{};

  public:
    explicit JsonlWriter(const std::string &);
    void event(const SecurityEvent &);
    void alert(const Json &);
    void document(const std::string &, const Json &);
    void flush();
};
} // namespace irforge
