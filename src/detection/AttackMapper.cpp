#include "irforge/detection/AttackMapper.hpp"
#include "AttackData.hpp"
namespace irforge {
const Json &AttackMapper::dataset() {
    static const Json data = Json::parse(attackData);
    return data;
}
Json AttackMapper::technique(const std::string &id) {
    for (auto &row : dataset().at("techniques"))
        if (row.at("id") == id) {
            if (row.value("revoked", false) || row.value("deprecated", false))
                throw std::runtime_error("ATT&CK mapping is revoked/deprecated: " + id);
            return row;
        }
    throw std::runtime_error("ATT&CK ID absent from pinned reviewed subset: " + id);
}
void AttackMapper::validate(const std::vector<std::string> &ids) {
    if (ids.size() > 16)
        throw std::runtime_error("too many ATT&CK mappings");
    for (auto &id : ids)
        (void)technique(id);
}
} // namespace irforge
