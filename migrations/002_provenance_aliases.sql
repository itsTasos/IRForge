CREATE TABLE event_aliases(id TEXT PRIMARY KEY, canonical_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE);
CREATE TABLE cases(id TEXT PRIMARY KEY, created_ms INTEGER NOT NULL, document TEXT NOT NULL);
CREATE INDEX provenance_source_record ON event_provenance(source,source_record_id);
CREATE INDEX remote_spool_created ON remote_spool(created_ms);
