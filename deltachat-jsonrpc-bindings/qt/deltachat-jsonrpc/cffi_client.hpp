#pragma once

#include "deltachat-jsonrpc/generated/types.hpp"
#include "deltachat-jsonrpc/generated/client.hpp"
#include "deltachat.h"

#include <QMutex>
#include <QMutexLocker>

#include <thread>
#include <cstdint>

class CffiTransport : public Transport {
public:
    explicit CffiTransport(dc_accounts_t* accounts)
        : jsonrpc_(dc_jsonrpc_init(accounts))
    {
        if (!jsonrpc_) std::abort();
        thread_ = std::thread([this] { run(); });
    }

    virtual ~CffiTransport() {
        done_ = true;
        // Unblock dc_jsonrpc_next_response by sending a dummy request
        if (jsonrpc_) dc_jsonrpc_request(jsonrpc_, "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"get_system_info\"}");
        if (thread_.joinable()) thread_.join();
        QMutexLocker lk(&mu_);
        for (auto& [id, prom] : pending_) {
            prom.set_value({{}, "Transport destructed", -32060});
        }
        pending_.clear();
        if (jsonrpc_) dc_jsonrpc_unref(jsonrpc_);
    }

    virtual std::future<Result<QJsonValue>> send(const QString method, const QJsonValue params) override {
        uint32_t id = next_id_++;
        QJsonObject envelope{
            {"jsonrpc", "2.0"},
            {"id", static_cast<qint64>(id)},
            {"method", method},
            {"params", params},
        };

        std::promise<Result<QJsonValue>> prom;
        std::future<Result<QJsonValue>> fut = prom.get_future();

        {
            QMutexLocker lk(&mu_);
            pending_[id] = std::move(prom);
        }

        QByteArray json = QJsonDocument(envelope).toJson(QJsonDocument::Compact);
        dc_jsonrpc_request(jsonrpc_, json.constData());
        return fut;
    }
private:
    void run() {
        while (!done_) {
            char* raw_json = dc_jsonrpc_next_response(jsonrpc_);
            if (!raw_json) {
              break;
            }
            QByteArray json{raw_json};
            dc_str_unref(raw_json);
            if (done_) break;

            QJsonObject obj = QJsonDocument::fromJson(json).object();

            if (!obj["id"].isDouble()) {
              qCritical() << "No valid rpc id in" << QString{json};
              continue;
            }
            uint32_t id = static_cast<uint32_t>(obj["id"].toInt());

            std::promise<Result<QJsonValue>> prom;
            {
                QMutexLocker lk(&mu_);
                if (auto nh = pending_.extract(id)) {
                  prom = std::move(nh.mapped());
                } else {
                  qCritical() << "Could not map response" << QString{json};
                  continue;
                }
            }
            prom.set_value(parseResult(obj));
        }
    }

private:
    dc_jsonrpc_instance_t* jsonrpc_;
    std::thread thread_;
    QMutex mu_;
    std::atomic<uint32_t> next_id_{1};
    std::atomic<bool> done_{false};
    std::unordered_map<uint32_t, std::promise<Result<QJsonValue>>> pending_;
};

class CffiDeltaChat : public RawClient {
public:
  explicit CffiDeltaChat(dc_accounts_t* accounts)
    : RawClient(std::make_unique<CffiTransport>(accounts)) {}
};
