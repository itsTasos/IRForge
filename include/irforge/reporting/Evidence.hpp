#pragma once
#include "irforge/core/Event.hpp"
namespace irforge {
void privateDirectory(const std::string &, bool requireEmpty = true);
void writeDocument(const std::filesystem::path &, const Json &);
Json evidenceManifest(const std::string &directory, const std::string &caseId,
                      std::uint64_t maxBytes = 64ULL * 1024 * 1024);
Json verifyEvidence(const std::string &manifest);
void zipEvidence(const std::string &directory, const std::string &zip,
                 std::uint64_t maxBytes = 64ULL * 1024 * 1024);
Json forensicSnapshot(const std::string &output, bool includeEvtx = false,
                      const Json &storedHealth = Json::object(), const Json &artifacts = Json::array());
} // namespace irforge
