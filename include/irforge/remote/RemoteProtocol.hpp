#pragma once
#include "irforge/storage/SqliteStore.hpp"
namespace irforge {
Json redactRemoteEvent(Json, bool redactCommandLines = true);
Json validateRemotePacket(const Json &, const Json &enrollment);
Json acceptRemoteBatch(StoreWorker &, const Json &batch, const Json &enrollment);
Json remoteRead(StoreWorker &, const Json &, const Json &enrollment);
void validateEnrollment(const Json &);
} // namespace irforge
