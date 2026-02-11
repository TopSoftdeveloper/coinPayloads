#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <functional>

#pragma comment(lib, "winhttp.lib")

// WebSocket client using WinHTTP (Windows 8+).
// Connects to coinBank server, sends connect/event, receives admin commands.

struct WsClientCallbacks {
    std::function<void(const std::string& action, const std::string& payload)> on_command;
    std::function<void()> on_connect;
    std::function<void(int code, const std::string& msg)> on_close;
    std::function<void(const std::string& err)> on_error;
};

class WsClient {
public:
    WsClient();
    ~WsClient();

    bool connect(const std::string& hostPort);
    void disconnect();

    bool is_connected() const { return connected_; }

    bool send(const std::string& json);

    // Blocking receive. Returns false on error/closed.
    bool receive(std::string& out_action, std::string& out_payload);

    void set_callbacks(const WsClientCallbacks& cb) { callbacks_ = cb; }

private:
    HINTERNET hSession_{ NULL };
    HINTERNET hConnect_{ NULL };
    HINTERNET hRequest_{ NULL };
    HINTERNET hWebSocket_{ NULL };
    bool connected_{ false };
    WsClientCallbacks callbacks_;
};
