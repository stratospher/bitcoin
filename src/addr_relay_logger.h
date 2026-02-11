// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDR_RELAY_LOGGER_H
#define BITCOIN_ADDR_RELAY_LOGGER_H

#include <netaddress.h>
#include <protocol.h>
#include <sync.h>

#include <atomic>
#include <memory>
#include <string>

struct sqlite3;

namespace AddrRelayLogging {

enum class EventType {
    RECV,
    RECV_REMOVED,
    SEND,
    SEND_REMOVED
};

class AddrRelayLogger {
private:
    sqlite3* m_db{nullptr};
    mutable Mutex m_cs_db;
    std::string m_db_path;
    std::atomic<bool> m_enabled{false};

    bool CreateTables() EXCLUSIVE_LOCKS_REQUIRED(m_cs_db);
    std::string EventTypeToString(EventType type) const;

public:
    AddrRelayLogger();
    ~AddrRelayLogger();

    /** Initialize the logger with database path */
    bool Init(const std::string& datadir) EXCLUSIVE_LOCKS_REQUIRED(!m_cs_db);

    /** Close the database */
    void Close() EXCLUSIVE_LOCKS_REQUIRED(!m_cs_db);

    /** Log peer information
     * @param peer_id The peer ID
     * @param peer_addr The peer's network address (IP:port)
     * @param timestamp Current time
     */
    void LogPeerInfo(int64_t peer_id, const std::string& peer_addr, int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(!m_cs_db);

    /** Log an address event (RECV/RECV-REMOVED/SEND/SEND-REMOVED)
     * @param event_type The type of event
     * @param addr The address being logged
     * @param peer_id The peer ID we received from or sending to
     * @param timestamp Current time
     */
    void LogAddrEvent(EventType event_type, const CAddress& addr, int64_t peer_id, int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(!m_cs_db);

    /** Log a SEND event summary
     * @param peer_id The peer ID we're sending to
     * @param addr_known_size Size of m_addr_known filter
     * @param timestamp Current time
     */
    void LogSendSummary(int64_t peer_id, size_t addr_known_size, int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(!m_cs_db);

    /** Log a RECV event summary
     * @param peer_id The peer ID we're receiving from
     * @param addr_known_size Size of m_addr_known filter
     * @param num_proc Number of addresses processed
     * @param num_rate_limit Number of addresses rate limited
     * @param addr_token_bucket Current addr token bucket value
     * @param timestamp Current time
     */
    void LogRecvSummary(int64_t peer_id, size_t addr_known_size, uint64_t num_proc, uint64_t num_rate_limit, double addr_token_bucket, int64_t timestamp) EXCLUSIVE_LOCKS_REQUIRED(!m_cs_db);

    bool IsEnabled() const { return m_enabled; }
};

// Global logger instance
extern std::unique_ptr<AddrRelayLogger> g_addr_relay_logger;

} // namespace AddrRelayLogging

#endif // BITCOIN_ADDR_RELAY_LOGGER_H
