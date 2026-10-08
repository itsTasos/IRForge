#include "irforge/core/Clock.hpp"
#include "irforge/core/Config.hpp"
#include "irforge/core/EventBus.hpp"
#include "irforge/output/JsonlWriter.hpp"
#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <future>
using namespace irforge;
TEST_CASE("bounded queue FIFO drops newest and drains on close") {
    EventBus bus(2);
    SecurityEvent e;
    e.id = 1;
    REQUIRE(bus.publish(e));
    e.id = 2;
    REQUIRE(bus.publish(e));
    e.id = 3;
    REQUIRE_FALSE(bus.publish(e));
    REQUIRE(bus.dropped() == 1);
    bus.close();
    REQUIRE(bus.pop()->id == 1);
    REQUIRE(bus.pop()->id == 2);
    REQUIRE_FALSE(bus.pop());
    REQUIRE_FALSE(bus.publish(e));
}
TEST_CASE("queue wakes blocked consumer and tolerates flood") {
    EventBus bus(10);
    auto waiting = std::async(std::launch::async, [&] { return bus.pop(); });
    bus.close();
    REQUIRE_FALSE(waiting.get());
    EventBus flood(10);
    for (int i = 0; i < 100000; ++i)
        flood.publish(SecurityEvent{});
    REQUIRE(flood.dropped() == 99990);
    flood.close();
}
TEST_CASE("schema roundtrip preserves Unicode explicit nulls and precision") {
    SecurityEvent e;
    e.id = 5;
    e.type = EventType::ProcessStart;
    e.timestampUtc = parseUtc("2026-10-08T10:00:00.123Z");
    e.source = "test";
    e.host = "lab";
    ProcessPayload p;
    p.identity = {42, 12345, 0};
    p.imagePath = "C:\\Users\\Δοκιμή\\工具.exe";
    e.payload = p;
    Json j = e;
    REQUIRE(j["payload"]["command_line"].is_null());
    REQUIRE(Json(j.get<SecurityEvent>()) == j);
    REQUIRE(utf8(utf16(*p.imagePath)) == *p.imagePath);
    REQUIRE_THROWS(utf16(std::string("\xff")));
    REQUIRE_THROWS(parseUtc("2026-02-30T10:00:00.000Z"));
    REQUIRE_THROWS(parseUtc("2026-10-08T10:00:00Z"));
}
TEST_CASE("configuration validates bounded input") {
    auto c = Config::load(std::string(IRFORGE_SOURCE_DIR) + "/config/default.json");
    REQUIRE(c.network_poll_ms == 1000);
    auto path = std::filesystem::temp_directory_path() / "irforge-invalid-config.json";
    {
        std::ofstream f(path);
        f << "{\"schema_version\":1,\"queue_capacity\":0}";
    }
    REQUIRE_THROWS(Config::load(path.string()));
    std::filesystem::remove(path);
    {
        std::ofstream f(path);
        f << "{\"schema_version\":1,\"unknown\":true}";
    }
    REQUIRE_THROWS(Config::load(path.string()));
    std::filesystem::remove(path);
}
TEST_CASE("virtual clock watermark never goes backwards") {
    VirtualClock c;
    c.advance(100);
    c.advance(10);
    REQUIRE(c.now() == 100);
}
TEST_CASE("idle queue timeout is distinct from drained shutdown") {
    EventBus bus(2);
    REQUIRE_FALSE(bus.popFor(std::chrono::milliseconds(1)));
    REQUIRE_FALSE(bus.drained());
    bus.close();
    REQUIRE(bus.drained());
}
TEST_CASE("Windows path parsing refuses ambiguous expansion and normalizes explicit paths") {
    REQUIRE(executablePath("\"C:\\Users\\Alice\\Tool.exe\" -x") ==
            std::optional<std::string>("c:\\users\\alice\\tool.exe"));
    REQUIRE_FALSE(executablePath("C:\\Program Files\\Tool.exe -x"));
    REQUIRE_FALSE(executablePath("%APPDATA%\\Tool.exe"));
    REQUIRE(normalizePath("C:/Users/Alice/./bin/../Tool.exe") == "c:\\users\\alice\\tool.exe");
}
TEST_CASE("address classification covers both families and malformed inputs") {
    REQUIRE(addressClass("127.0.0.1") == "loopback");
    REQUIRE(addressClass("10.1.2.3") == "private_local");
    REQUIRE(addressClass("169.254.1.2") == "link_local");
    REQUIRE(addressClass("224.0.0.1") == "multicast");
    REQUIRE(addressClass("0.0.0.0") == "unspecified");
    REQUIRE(addressClass("8.8.8.8") == "public");
    REQUIRE(addressClass("::1") == "loopback");
    REQUIRE(addressClass("fe80::1%3") == "link_local");
    REQUIRE(addressClass("fc00::1") == "private_local");
    REQUIRE(addressClass("ff02::1") == "multicast");
    REQUIRE(addressClass("::") == "unspecified");
    REQUIRE(addressClass("2001:4860:4860::8888") == "public");
    REQUIRE(addressClass("::ffff:10.1.2.3") == "private_local");
    REQUIRE(addressClass("not-an-ip") == "invalid");
}
TEST_CASE("event decoding rejects integer truncation and roundtrips maximum raw Registry values") {
    SecurityEvent e;
    e.id = 50;
    e.type = EventType::RegistryValueAdded;
    e.timestampUtc = utcNow();
    e.source = "test";
    e.host = "test";
    RegistryPayload p;
    p.hive = "HKCU";
    p.keyPath = "example";
    p.valueName = "binary";
    p.view = "64";
    p.newData = RegistryValue{3, std::vector<std::uint8_t>(65536, 255), {}, {}};
    e.payload = p;
    Json j = e;
    REQUIRE(j.dump().size() > 262144);
    REQUIRE(Json(j.get<SecurityEvent>()) == j);
    j["payload"]["new_data"]["raw"][0] = 256;
    REQUIRE_THROWS(j.get<SecurityEvent>());
    j = Json(e);
    j["payload"]["actor_pid"] = -1;
    REQUIRE_THROWS(j.get<SecurityEvent>());
    j = Json(e);
    j["event_id"] = 1.5;
    REQUIRE_THROWS(j.get<SecurityEvent>());
}
