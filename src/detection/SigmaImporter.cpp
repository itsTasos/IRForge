#include "irforge/detection/SigmaImporter.hpp"
#include <cctype>
#include <map>
#include <set>
#include <yaml-cpp/yaml.h>
namespace irforge {
namespace {
void bounded(const YAML::Node &n, int depth, int &count) {
    if (depth > 8 || ++count > 512)
        throw std::runtime_error("Sigma YAML exceeds structural bounds");
    if (!n.Tag().empty() && n.Tag() != "?" && n.Tag() != "!")
        throw std::runtime_error("Sigma YAML custom tags unsupported");
    if (n.IsScalar() && n.Scalar().size() > 4096)
        throw std::runtime_error("Sigma scalar too long");
    if (n.IsMap()) {
        std::set<std::string> keys;
        for (auto item : n) {
            auto key = item.first.as<std::string>();
            if (!keys.insert(key).second)
                throw std::runtime_error("duplicate Sigma key " + key);
            bounded(item.second, depth + 1, count);
        }
    } else if (n.IsSequence())
        for (auto item : n)
            bounded(item, depth + 1, count);
}
Json leaf(const std::string &key, const std::string &value) {
    const std::map<std::string, std::string> mapping = {{"Image", "process.image_path"},
                                                        {"CommandLine", "process.command_line"},
                                                        {"ParentImage", "process.parent.image_path"}};
    auto separator = key.find('|');
    auto field = key.substr(0, separator);
    auto it = mapping.find(field);
    if (it == mapping.end())
        throw std::runtime_error("unsupported Sigma field " + field);
    auto modifier = separator == std::string::npos ? "" : key.substr(separator + 1);
    if (modifier.ends_with("|all"))
        modifier.resize(modifier.size() - 4);
    std::string op = "equals_ci", text = value;
    if (modifier == "contains")
        op = "contains_ci";
    else if (modifier == "startswith")
        op = "starts_with_ci";
    else if (modifier == "endswith")
        op = "ends_with_ci";
    else if (!modifier.empty() && modifier != "all")
        throw std::runtime_error("unsupported Sigma modifier " + modifier);
    if (text.find('?') != std::string::npos)
        throw std::runtime_error("Sigma ? wildcard unsupported");
    if (text.find('*') != std::string::npos) {
        if (!modifier.empty())
            throw std::runtime_error("wildcards with modifiers unsupported");
        bool first = text.front() == '*', last = text.back() == '*';
        if (first)
            text.erase(0, 1);
        if (last && !text.empty())
            text.pop_back();
        if (text.find('*') != std::string::npos || text.empty())
            throw std::runtime_error("only nonempty outer Sigma wildcards supported");
        op = first && last ? "contains_ci" : first ? "ends_with_ci" : "starts_with_ci";
    }
    return {{"field", it->second}, {"operator", op}, {"value", text}};
}
Json selection(const YAML::Node &node) {
    if (!node.IsMap() || node.size() == 0)
        throw std::runtime_error("Sigma selection must be a nonempty field map");
    Json all = Json::array();
    for (auto item : node) {
        auto key = item.first.as<std::string>();
        auto values = item.second;
        bool every = key.ends_with("|all");
        if (values.IsSequence()) {
            if (values.size() == 0 || values.size() > 32)
                throw std::runtime_error("Sigma selection list bounds");
            Json rows = Json::array();
            for (auto v : values) {
                if (!v.IsScalar())
                    throw std::runtime_error("Sigma nested values unsupported");
                rows.push_back(leaf(key, v.as<std::string>()));
            }
            all.push_back({{every ? "and" : "or", rows}});
        } else if (values.IsScalar())
            all.push_back(leaf(key, values.as<std::string>()));
        else
            throw std::runtime_error("Sigma null/object values unsupported");
    }
    return {{"and", all}};
}
class Expression {
    std::vector<std::string> tokens;
    std::size_t at = 0;
    int depth = 0;
    const std::map<std::string, Json> &selections;
    bool take(const std::string &s) {
        if (at < tokens.size() && tokens[at] == s) {
            ++at;
            return true;
        }
        return false;
    }
    Json primary() {
        if (++depth > 8)
            throw std::runtime_error("Sigma condition nesting too deep");
        Json result;
        if (take("not"))
            result = {{"not", primary()}};
        else if (take("(")) {
            result = disjunction();
            if (!take(")"))
                throw std::runtime_error("Sigma condition closing parenthesis missing");
        } else {
            if (at == tokens.size())
                throw std::runtime_error("Sigma condition missing selection");
            auto name = tokens[at++];
            auto it = selections.find(name);
            if (it == selections.end())
                throw std::runtime_error("unsupported condition or missing selection: " + name);
            result = it->second;
        }
        --depth;
        return result;
    }
    Json conjunction() {
        Json rows = Json::array({primary()});
        while (take("and"))
            rows.push_back(primary());
        return rows.size() == 1 ? rows[0] : Json{{"and", rows}};
    }
    Json disjunction() {
        Json rows = Json::array({conjunction()});
        while (take("or"))
            rows.push_back(conjunction());
        return rows.size() == 1 ? rows[0] : Json{{"or", rows}};
    }

  public:
    Expression(const std::string &input, const std::map<std::string, Json> &s) : selections(s) {
        for (std::size_t i = 0; i < input.size();) {
            auto c = static_cast<unsigned char>(input[i]);
            if (std::isspace(c)) {
                ++i;
                continue;
            }
            if (c == '(' || c == ')') {
                tokens.emplace_back(1, static_cast<char>(c));
                ++i;
                continue;
            }
            auto start = i;
            while (i < input.size() &&
                   (std::isalnum(static_cast<unsigned char>(input[i])) || input[i] == '_'))
                ++i;
            if (start == i)
                throw std::runtime_error("unsupported Sigma condition character");
            tokens.push_back(input.substr(start, i - start));
            if (tokens.size() > 128)
                throw std::runtime_error("Sigma condition token limit");
        }
    }
    Json parse() {
        auto j = disjunction();
        if (at != tokens.size())
            throw std::runtime_error("unsupported trailing Sigma condition syntax");
        return j;
    }
};
} // namespace
Json importSigma(const std::string &input, const std::string &origin) {
    if (input.size() > 262144)
        throw std::runtime_error("Sigma input exceeds 256 KiB");
    auto documents = YAML::LoadAll(input);
    if (documents.size() != 1)
        throw std::runtime_error("exactly one Sigma document required");
    auto yaml = documents[0];
    int count = 0;
    bounded(yaml, 0, count);
    const std::set<std::string> keys = {
        "title",      "id",   "description", "status",    "author",         "date",  "modified",
        "references", "tags", "logsource",   "detection", "falsepositives", "level", "license"};
    if (!yaml.IsMap())
        throw std::runtime_error("Sigma rule must be an object");
    for (auto item : yaml)
        if (!keys.contains(item.first.as<std::string>()))
            throw std::runtime_error("unsupported Sigma property " + item.first.as<std::string>());
    auto log = yaml["logsource"];
    if (!log.IsMap() || log["product"].as<std::string>("") != "windows" ||
        log["category"].as<std::string>("") != "process_creation")
        throw std::runtime_error("only Windows process_creation Sigma logsource supported");
    for (auto item : log)
        if (item.first.as<std::string>() != "product" && item.first.as<std::string>() != "category")
            throw std::runtime_error("unsupported Sigma logsource constraint");
    auto detection = yaml["detection"];
    if (!detection.IsMap() || !detection["condition"].IsScalar())
        throw std::runtime_error("Sigma detection/condition missing");
    std::map<std::string, Json> selections;
    for (auto item : detection) {
        auto name = item.first.as<std::string>();
        if (name == "condition")
            continue;
        if (name == "timeframe")
            throw std::runtime_error("Sigma timeframe/correlation unsupported");
        selections.emplace(name, selection(item.second));
    }
    auto severity = yaml["level"].as<std::string>("medium");
    int score = severity == "critical" ? 60
                : severity == "high"   ? 40
                : severity == "medium" ? 25
                : severity == "low"    ? 10
                                       : 5;
    Json rule = {{"schema_version", 2},
                 {"id", yaml["id"].as<std::string>()},
                 {"name", yaml["title"].as<std::string>()},
                 {"description", yaml["description"].as<std::string>(yaml["title"].as<std::string>())},
                 {"severity", severity},
                 {"score", score},
                 {"event_type", "process_start"},
                 {"condition", Expression(detection["condition"].as<std::string>(), selections).parse()},
                 {"source", origin + "; author=" + yaml["author"].as<std::string>("unspecified")},
                 {"license", yaml["license"].as<std::string>("UNSPECIFIED")},
                 {"attack", Json::array()},
                 {"false_positives", Json::array()},
                 {"confidence", "medium"}};
    if (auto tags = yaml["tags"]) {
        if (!tags.IsSequence())
            throw std::runtime_error("Sigma tags must be a list");
        for (auto tag : tags) {
            auto value = tag.as<std::string>();
            if (value.starts_with("attack.t")) {
                auto id = value.substr(7);
                id[0] = 'T';
                rule["attack"].push_back(id);
            }
        }
    }
    if (auto fp = yaml["falsepositives"]) {
        if (!fp.IsSequence())
            throw std::runtime_error("Sigma falsepositives must be a list");
        for (auto row : fp)
            rule["false_positives"].push_back(row.as<std::string>());
    }
    (void)RuleEngine::parse(rule);
    return rule;
}
Json testRules(const RuleEngine &engine, const std::vector<SecurityEvent> &events) {
    ProcessTracker tracker;
    Json result = {{"events", events.size()}, {"matches", Json::array()}, {"rule_counts", Json::object()}};
    for (const auto &e : events) {
        tracker.observe(e);
        for (const auto &m : engine.evaluate(e, tracker)) {
            result["matches"].push_back(
                {{"event_id", e.id}, {"rule_id", m.ruleId}, {"reason", m.reason}, {"points", m.points}});
            auto &count = result["rule_counts"][m.ruleId];
            count = count.is_null() ? 1 : count.get<int>() + 1;
        }
    }
    return result;
}
} // namespace irforge
