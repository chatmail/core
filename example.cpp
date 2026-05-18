#include <cstdio>
#include <cstdlib>
#include <string>
#include <iostream>

#include "deltachat-jsonrpc/c/generated/dc_json_cjson.h"
#include "deltachat-jsonrpc/c/generated/rpc.hpp"
#include "../chatmail-core-2.43.0/deltachat.h"

struct CffiTransport {
    dc_jsonrpc_instance_t* jsonrpc;
    char* buf_ = nullptr;
    CffiTransport(dc_accounts_t* accounts) : jsonrpc(dc_jsonrpc_init(accounts)) {if (!jsonrpc) {std::abort();}}
    CffiTransport(CffiTransport&& o) : jsonrpc(o.jsonrpc), buf_(o.buf_) { o.jsonrpc = nullptr; o.buf_ = nullptr; }
    CffiTransport& operator=(CffiTransport&&) = delete;
    CffiTransport(const CffiTransport&) = delete;
    void send(const char* json) { dc_jsonrpc_request(jsonrpc, json); }
    const char* read() {
        if (buf_) { dc_str_unref(buf_); buf_ = nullptr; }
        buf_ = dc_jsonrpc_next_response(jsonrpc);
        if (!buf_) { dc_jsonrpc_unref(jsonrpc); jsonrpc = nullptr; return nullptr; }
        return buf_;
    }
    ~CffiTransport() { if (buf_) dc_str_unref(buf_); if (jsonrpc) dc_jsonrpc_unref(jsonrpc); }
    void close() { send("{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"get_system_info\"})\")"); }
};


// struct StdioTransport {
//     std::string buf_;
//     void send(const char* json) { printf("%s\n", json); fflush(stdout); }
//     const char* read() {
//         if (!std::getline(std::cin, buf_)) return nullptr;
//         return buf_.c_str();
//     }
// };

//   struct CffiTransport {
//     dc_jsonrpc_instance_t* jsonrpc;
//     CffiTransport(dc_accounts_t* accounts) : jsonrpc(dc_jsonrpc_init(accounts)) {}
//     void send(const char* json) { dc_jsonrpc_request(jsonrpc, json); }
//     std::string read() {
//         char* r = dc_jsonrpc_next_response(jsonrpc);
//         if (!r) {dc_jsonrpc_unref(jsonrpc); return {};}
//         std::string s(r);
//         dc_str_unref(r);
//         return s;
//     }
//     void close() { }
// };
// ;

void logger(std::string msg) {
    std::cerr << msg << std::endl;
}

int main() {
    auto* raw_accounts = dc_accounts_new("my-accounts", 1);

    if (!raw_accounts) return -1;
    dc::Rpc<CffiTransport> rpc(CffiTransport{raw_accounts}, logger);
    dc_accounts_unref(raw_accounts);

    printf("arch: %s\n", rpc.get_system_info().find("arch"));

    auto account_ids = rpc.get_all_account_ids();
    printf("size 1: %zu\n", account_ids.size());
    auto acc_id = account_ids.size() == 0 ? rpc.add_account() : account_ids.view()[0];
    printf("acc_id: %u\n", acc_id);

    auto a = dc::ArrayString("is_chatmail", "addr");
    printf("a %zu\n", a.size());
    printf("a %i\n", bool(a));
    auto config = rpc.batch_get_config(acc_id, std::move(a));

    printf("s: %zu\n", config.size());
    printf("c: %s\n", config._c->keys[0]);
    printf("c: %s\n", config._c->values[0]);
    printf("c: %s\n", config._c->keys[1]);
    printf("c: %s\n", config._c->values[1]);
    printf("c: %s\n", config.find("addr")._c);

    auto chat_id = rpc.secure_join(acc_id, "https://i.delta.chat/#AFE2503F3BDC9058CBEAB8AEBAA028AE86816AD5&v=3&i=_CmYTfzPFjM9JQV_R05mK4Qg&s=1F7dmW_qhOGytyFXUbo6who5&a=uxyjz202n%40nine.testrun.org&n=1");
    // auto chat_id = 12;

    auto e = rpc.get_next_event_batch();
    for (size_t i = 0; i < e.size(); ++i) {
        printf("kind: %i\n", e[i].event()._c->kind);
    }
// {
//     printf("kind: %i\n", rpc.get_next_event().event()._c->kind);
// }

    auto y = rpc.send_msg(acc_id, chat_id, dc::MessageData(string_new("hi"), {}, {}, {}, {}, {}, {}, {}, {}));
    // rpc.sleep(10);

    auto chat = rpc.get_full_chat_by_id(acc_id, chat_id);
    printf("canSend: %s\n", chat.canSend() ? "yes" : "no");
    printf("isContactRequest: %s\n", chat.isContactRequest()? "yes" : "no");
}

