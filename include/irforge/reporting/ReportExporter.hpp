#pragma once
#include "irforge/storage/SqliteStore.hpp"
namespace irforge {
std::string htmlEscape(const std::string &);
std::string csvCell(const std::string &);
Json stixBundle(const Json &incident);
std::string incidentHtml(const Json &incident, const Json &context);
Json exportIncident(StoreWorker &, const std::string &id, const std::string &directory,
                    const std::string &format);
} // namespace irforge
