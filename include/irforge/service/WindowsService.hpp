#pragma once
#include "irforge/core/Event.hpp"
#include <functional>
#include <stop_token>
namespace irforge {
using ServiceRunner = std::function<int(const std::vector<std::string> &, std::stop_token)>;
std::optional<int> serviceCommand(const std::vector<std::string> &, const ServiceRunner &);
bool validServiceTransition(const std::string &from, const std::string &to);
} // namespace irforge
