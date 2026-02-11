// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addr_relay_logger.h>

#include <logging.h>
#include <util/fs.h>

#include <sqlite3.h>

#include <cassert>

namespace AddrRelayLogging {

std::unique_ptr<AddrRelayLogger> g_addr_relay_logger;

AddrRelayLogger::AddrRelayLogger() {}

AddrRelayLogger::~AddrRelayLogger()
{
    Close();
}

bool AddrRelayLogger::Init(const std::string& datadir)
{
    LOCK(m_cs_db);

    m_db_path = fs::PathToString(fs::PathFromString(datadir) / "addr_relay_log.sqlite");

    int ret = sqlite3_open(m_db_path.c_str(), &m_db);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: Failed to open database: %s\n", sqlite3_errmsg(m_db));
        if (m_db) {
            sqlite3_close(m_db);
            m_db = nullptr;
        }
        return false;
    }

    if (!CreateTables()) {
        LogInfo("AddrRelayLogger: Failed to create tables\n");
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }

    m_enabled = true;
    LogInfo("AddrRelayLogger: Initialized at %s\n", m_db_path);
    return true;
}

void AddrRelayLogger::Close()
{
    LOCK(m_cs_db);

    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
    m_enabled = false;
}

bool AddrRelayLogger::CreateTables()
{
    AssertLockHeld(m_cs_db);

    const char* sql_peer_info = R"(
        CREATE TABLE IF NOT EXISTS peer_info (
            peer_id INTEGER PRIMARY KEY,
            peer_addr TEXT NOT NULL,
            first_seen INTEGER NOT NULL
        );
    )";

    const char* sql_addr_events = R"(
        CREATE TABLE IF NOT EXISTS addr_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL,
            services INTEGER NOT NULL,
            ntime INTEGER NOT NULL,
            peer_id INTEGER NOT NULL,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_addr_events_timestamp ON addr_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_addr_events_peer ON addr_events(peer_id);
    )";

    const char* sql_send_summary = R"(
        CREATE TABLE IF NOT EXISTS send_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL,
            addr_known_size INTEGER NOT NULL,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_send_summary_timestamp ON send_summary(timestamp);
    )";

    const char* sql_recv_summary = R"(
        CREATE TABLE IF NOT EXISTS recv_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id INTEGER NOT NULL,
            addr_known_size INTEGER NOT NULL,
            num_proc INTEGER NOT NULL,
            num_rate_limit INTEGER NOT NULL,
            addr_token_bucket REAL NOT NULL,
            timestamp INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recv_summary_timestamp ON recv_summary(timestamp);
    )";

    char* err_msg = nullptr;

    int ret = sqlite3_exec(m_db, sql_peer_info, nullptr, nullptr, &err_msg);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: SQL error creating peer_info table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return false;
    }

    ret = sqlite3_exec(m_db, sql_addr_events, nullptr, nullptr, &err_msg);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: SQL error creating addr_events table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return false;
    }

    ret = sqlite3_exec(m_db, sql_send_summary, nullptr, nullptr, &err_msg);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: SQL error creating send_summary table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return false;
    }

    ret = sqlite3_exec(m_db, sql_recv_summary, nullptr, nullptr, &err_msg);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: SQL error creating recv_summary table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return false;
    }

    return true;
}

std::string AddrRelayLogger::EventTypeToString(EventType type) const
{
    switch (type) {
        case EventType::RECV: return "RECV";
        case EventType::RECV_REMOVED: return "RECV-REMOVED";
        case EventType::SEND: return "SEND";
        case EventType::SEND_REMOVED: return "SEND-REMOVED";
        default: return "UNKNOWN";
    }
}

void AddrRelayLogger::LogAddrEvent(EventType event_type, const CAddress& addr, int64_t peer_id, int64_t timestamp)
{
    if (!m_enabled) return;

    LOCK(m_cs_db);

    if (!m_db) return;

    const char* sql = R"(
        INSERT INTO addr_events (event_type, ip_address, port, services, ntime, peer_id, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    int ret = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: Failed to prepare statement: %s\n", sqlite3_errmsg(m_db));
        return;
    }

    std::string event_str = EventTypeToString(event_type);
    std::string ip_str = addr.ToStringAddr();

    sqlite3_bind_text(stmt, 1, event_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ip_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, addr.GetPort());
    sqlite3_bind_int64(stmt, 4, addr.nServices);
    int64_t nTime_int64 = addr.nTime.time_since_epoch().count();
    sqlite3_bind_int64(stmt, 5, nTime_int64);
    sqlite3_bind_int64(stmt, 6, peer_id);
    sqlite3_bind_int64(stmt, 7, timestamp);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        LogInfo("AddrRelayLogger: Failed to execute statement: %s\n", sqlite3_errmsg(m_db));
    }

    sqlite3_finalize(stmt);
}

void AddrRelayLogger::LogPeerInfo(int64_t peer_id, const std::string& peer_addr, int64_t timestamp)
{
    if (!m_enabled) return;

    LOCK(m_cs_db);

    if (!m_db) return;

    const char* sql = R"(
        INSERT OR IGNORE INTO peer_info (peer_id, peer_addr, first_seen)
        VALUES (?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    int ret = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: Failed to prepare statement: %s\n", sqlite3_errmsg(m_db));
        return;
    }

    sqlite3_bind_int64(stmt, 1, peer_id);
    sqlite3_bind_text(stmt, 2, peer_addr.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, timestamp);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        LogInfo("AddrRelayLogger: Failed to execute statement: %s\n", sqlite3_errmsg(m_db));
    }

    sqlite3_finalize(stmt);
}

void AddrRelayLogger::LogSendSummary(int64_t peer_id, size_t addr_known_size, int64_t timestamp)
{
    if (!m_enabled) return;

    LOCK(m_cs_db);

    if (!m_db) return;

    const char* sql = R"(
        INSERT INTO send_summary (peer_id, addr_known_size, timestamp)
        VALUES (?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    int ret = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: Failed to prepare statement: %s\n", sqlite3_errmsg(m_db));
        return;
    }

    sqlite3_bind_int64(stmt, 1, peer_id);
    sqlite3_bind_int64(stmt, 2, static_cast<int64_t>(addr_known_size));
    sqlite3_bind_int64(stmt, 3, timestamp);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        LogInfo("AddrRelayLogger: Failed to execute statement: %s\n", sqlite3_errmsg(m_db));
    }

    sqlite3_finalize(stmt);
}

void AddrRelayLogger::LogRecvSummary(int64_t peer_id, size_t addr_known_size, uint64_t num_proc, uint64_t num_rate_limit, double addr_token_bucket, int64_t timestamp)
{
    if (!m_enabled) return;

    LOCK(m_cs_db);

    if (!m_db) return;

    const char* sql = R"(
        INSERT INTO recv_summary (peer_id, addr_known_size, num_proc, num_rate_limit, addr_token_bucket, timestamp)
        VALUES (?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt;
    int ret = sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr);
    if (ret != SQLITE_OK) {
        LogInfo("AddrRelayLogger: Failed to prepare statement: %s\n", sqlite3_errmsg(m_db));
        return;
    }

    sqlite3_bind_int64(stmt, 1, peer_id);
    sqlite3_bind_int64(stmt, 2, static_cast<int64_t>(addr_known_size));
    sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(num_proc));
    sqlite3_bind_int64(stmt, 4, static_cast<int64_t>(num_rate_limit));
    sqlite3_bind_double(stmt, 5, addr_token_bucket);
    sqlite3_bind_int64(stmt, 6, timestamp);

    ret = sqlite3_step(stmt);
    if (ret != SQLITE_DONE) {
        LogInfo("AddrRelayLogger: Failed to execute statement: %s\n", sqlite3_errmsg(m_db));
    }

    sqlite3_finalize(stmt);
}

} // namespace AddrRelayLogging
