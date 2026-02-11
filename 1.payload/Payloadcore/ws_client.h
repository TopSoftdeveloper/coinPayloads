#pragma once

#include <windows.h>
#include <string>
#include <functional>

// Do NOT include winhttp.h here - it conflicts with wininet.h when both are
// included in the same translation unit (e.g. wss_examples.cpp uses WinInet).
// WinHTTP is used only in ws_client.cpp; handles are opaque here.

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

    /** Last error message after a failed connect(); empty if none. */
    const std::string& get_last_error() const { return last_error_; }

    bool is_connected() const { return connected_; }

    bool send(const std::string& json);

    // Blocking receive. Returns false on error/closed.
    bool receive(std::string& out_action, std::string& out_payload);

    void set_callbacks(const WsClientCallbacks& cb) { callbacks_ = cb; }

private:
    void* hSession_{ NULL };   // WinHTTP HINTERNET
    void* hConnect_{ NULL };   // WinHTTP HINTERNET
    void* hRequest_{ NULL };   // WinHTTP HINTERNET
    void* hWebSocket_{ NULL }; // WinHTTP HINTERNET
    bool connected_{ false };
    std::string last_error_;
    WsClientCallbacks callbacks_;
};
