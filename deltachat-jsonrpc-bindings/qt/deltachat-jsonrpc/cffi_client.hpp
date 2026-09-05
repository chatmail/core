#pragma once

#include "deltachat.h"
#include "generated/client.hpp"
#include "generated/types.hpp"

#include <cstdint>
#include <mutex>
#include <thread>

namespace deltachat {

class CffiTransport : public Transport {
  using CompletionHandler = Transport::CompletionHandler;

public:
  explicit CffiTransport(dc_accounts_t *accounts)
      : jsonrpc_(dc_jsonrpc_init(accounts)) {
    if (!jsonrpc_)
      std::abort();
    thread_ = std::thread([this] { run(); });
  }

  ~CffiTransport() override {
    done_ = true;
    // Unblock dc_jsonrpc_next_response by sending a dummy request
    if (jsonrpc_)
      dc_jsonrpc_request(
          jsonrpc_,
          "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"get_system_info\"}");
    if (thread_.joinable())
      thread_.join();
    std::lock_guard lk(mu_);
    for (auto &[id, cb] : pending_) {
      cb(Result<QJsonValue>::error(-32060, "Transport destructed"));
    }
    pending_.clear();
    if (jsonrpc_)
      dc_jsonrpc_unref(jsonrpc_);
  }

  virtual void send(const QString method, const QJsonValue params,
                    CompletionHandler onCompleted) override {
    uint32_t id = next_id_++;
    QJsonObject envelope{
        {"jsonrpc", "2.0"},
        {"id", static_cast<qint64>(id)},
        {"method", method},
        {"params", params},
    };

    {
      std::lock_guard lk(mu_);
      pending_[id] = std::move(onCompleted);
    }

    QByteArray json = QJsonDocument(envelope).toJson(QJsonDocument::Compact);
    dc_jsonrpc_request(jsonrpc_, json.constData());
  }

private:
  void run() {
    while (!done_) {
      char *raw_json = dc_jsonrpc_next_response(jsonrpc_);
      if (!raw_json) {
        break;
      }
      QByteArray json{raw_json};
      dc_str_unref(raw_json);
      if (done_)
        break;

      QJsonObject obj = QJsonDocument::fromJson(json).object();

      if (!obj["id"].isDouble()) {
        qCritical() << "No valid rpc id in" << QString{json};
        continue;
      }
      uint32_t id = static_cast<uint32_t>(obj["id"].toInt());

      CompletionHandler cb;
      {
        std::lock_guard<std::mutex> lk(mu_);
        if (auto nh = pending_.extract(id)) {
          cb = std::move(nh.mapped());
        } else {
          qCritical() << "Could not map response" << QString{json};
          continue;
        }
      }
      cb(parseResult(obj));
    }
  }

private:
  dc_jsonrpc_instance_t *jsonrpc_;
  std::thread thread_;
  std::mutex mu_;
  std::atomic<uint32_t> next_id_{1};
  std::atomic<bool> done_{false};
  std::unordered_map<uint32_t, CompletionHandler> pending_;
};

class CffiDeltaChat : public RawClient {
public:
  explicit CffiDeltaChat(dc_accounts_t *accounts)
      : RawClient(std::make_unique<CffiTransport>(accounts)) {}
};

} // namespace deltachat
Q_DECLARE_METATYPE(deltachat::CffiDeltaChat *)
