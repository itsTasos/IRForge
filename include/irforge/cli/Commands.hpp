#pragma once
#include "irforge/core/Event.hpp"
#include <map>
#include <optional>
#include <set>
namespace irforge {
class Arguments {
    std::map<std::string, std::string> values_;

  public:
    Arguments(const std::vector<std::string> &, std::size_t first, const std::set<std::string> &values,
              const std::set<std::string> &flags = {});
    bool has(const std::string &key) const { return values_.contains(key); }
    std::string get(const std::string &key, const std::string &fallback = "") const;
    std::string require(const std::string &key) const;
    int integer(const std::string &key, int fallback, int minimum, int maximum) const;
};
std::optional<int> platformCommand(const std::vector<std::string> &);
} // namespace irforge
