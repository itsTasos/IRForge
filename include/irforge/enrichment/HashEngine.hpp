#pragma once
#include "irforge/core/Event.hpp"
#include <span>
#include <stop_token>
namespace irforge {
struct HashResult {
    std::string status, sha256;
    std::uint64_t bytes{};
    std::uint32_t error{};
    Json before, after;
};
std::string sha256Bytes(std::span<const std::uint8_t>);
HashResult hashFile(const std::string &, std::uint64_t maxBytes = 100ULL * 1024 * 1024,
                    std::stop_token stop = {}, int timeoutSeconds = 30);
Json signatureFile(const std::string &);
Json artifactMetadata(const std::string &, std::uint64_t maxBytes = 100ULL * 1024 * 1024, bool hash = true,
                      bool signature = true, std::stop_token stop = {}, int timeoutSeconds = 30);
std::string expandWindowsPath(const std::string &);
bool pathWithinRoot(const std::string &, const std::string &, bool permitMissingLeaf = false);
Json pathBoundaryCheck(const std::string &, const std::string &, bool permitMissingLeaf = false);
Json fileIdentityMetadata(const std::string &);
} // namespace irforge
