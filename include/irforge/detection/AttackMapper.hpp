#pragma once
#include "irforge/core/Event.hpp"
namespace irforge {
class AttackMapper {
  public:
    static const Json &dataset();
    static Json technique(const std::string &);
    static void validate(const std::vector<std::string> &);
};
} // namespace irforge
