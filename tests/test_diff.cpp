#include "irforge/monitoring/Diff.hpp"
#include <catch2/catch_test_macros.hpp>
using namespace irforge;
TEST_CASE("TCP snapshots deduplicate state transitions and preserve state on failure") {
    NetworkDiff diff;
    TcpPayload p;
    p.ownerPid = 7;
    p.ownerCreationTime100ns = 10;
    p.protocol = "tcp4";
    p.localAddress = "127.0.0.1";
    p.localPort = 123;
    p.remoteAddress = "8.8.8.8";
    p.remotePort = 443;
    p.state = "ESTABLISHED";
    auto first = diff.update({p}, 0);
    REQUIRE(first.size() == 1);
    REQUIRE(std::get<TcpPayload>(first[0].payload).firstSnapshot);
    for (int i = 0; i < 10; ++i)
        REQUIRE(diff.update({p}, i).empty());
    REQUIRE(diff.update({}, 11, false).empty());
    REQUIRE(diff.update({p}, 12).empty());
    p.state = "CLOSE_WAIT";
    auto changed = diff.update({p}, 13);
    REQUIRE(changed.size() == 1);
    REQUIRE(std::get<TcpPayload>(changed[0].payload).change == "state_changed");
    p.ownerCreationTime100ns = 20;
    auto reuse = diff.update({p}, 14);
    REQUIRE(reuse.size() == 2);
    auto gone = diff.update({}, 15);
    REQUIRE(gone.size() == 1);
    REQUIRE(gone[0].type == EventType::TcpConnectionClosed);
    REQUIRE(diff.update({}, 16).empty());
}
TEST_CASE("Registry typed diff is baseline aware and cannot invent writer PID") {
    RegistrySnapshot before;
    before.keys["Run"]["existing"] = decodeRegistryValue(4, {2, 0, 0, 0});
    REQUIRE(registryDiff(before, before, "HKCU", "64", 0).empty());
    auto after = before;
    after.keys["Run"]["added"] = decodeRegistryValue(1, {'x', 0, 0, 0});
    after.keys["Run"]["existing"] = decodeRegistryValue(4, {3, 0, 0, 0});
    auto events = registryDiff(before, after, "HKCU", "64", 1);
    REQUIRE(events.size() == 2);
    for (const auto &e : events) {
        auto r = std::get<RegistryPayload>(e.payload);
        REQUIRE_FALSE(r.actorPid);
        REQUIRE(r.newData);
        REQUIRE(Json(e)["payload"]["actor_pid"].is_null());
    }
    auto removed = registryDiff(after, {}, "HKCU", "32", 2);
    REQUIRE(removed.size() == 3);
    REQUIRE(removed.back().type == EventType::RegistryKeyDeleted);
    REQUIRE_THROWS(decodeRegistryValue(1, {1}));
    REQUIRE_THROWS(decodeRegistryValue(4, {1, 2}));
    REQUIRE(decodeRegistryValue(3, {1, 2, 3}).raw.size() == 3);
}
TEST_CASE("service diff includes complete selected configuration") {
    RegistrySnapshot after;
    auto &values = after.keys["SYSTEM\\CurrentControlSet\\Services\\Example"];
    values["start"] = decodeRegistryValue(4, {2, 0, 0, 0});
    values["type"] = decodeRegistryValue(4, {16, 0, 0, 0});
    RegistryValue image{1, {}, "C:\\Users\\Alice\\service.exe", {}};
    values["imagepath"] = image;
    auto events = registryDiff({}, after, "HKLM", "64", 1);
    REQUIRE(events.size() == 4);
    REQUIRE(std::get<RegistryPayload>(events[0].payload).serviceStart == 2);
}
