#include "stdafx.h"
#include "ws_client.h"
#include <winhttp.h>
#include <sstream>

#pragma comment(lib, "winhttp.lib")

// Cast opaque handles from header to WinHTTP HINTERNET (avoids including winhttp.h in header,
// which would conflict with wininet.h in translation units that use both).
#define H(x) (static_cast<HINTERNET>(x))

static std::string get_win32_error_string(DWORD err) {
    if (err == 0) return "";
    char* msg = NULL;
    DWORD len = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&msg, 0, NULL);
    std::string result;
    if (len && msg) {
        result.assign(msg, len);
        while (!result.empty() && (result.back() == '\r' || result.back() == '\n')) result.pop_back();
        LocalFree(msg);
    } else {
        std::ostringstream oss;
        oss << "error " << err;
        result = oss.str();
    }
    return result;
}

static std::wstring to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    std::wstring w(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], len);
    return w;
}

WsClient::WsClient() {}

WsClient::~WsClient() {
    disconnect();
}

void WsClient::disconnect() {
    if (hWebSocket_) {
        WinHttpCloseHandle(H(hWebSocket_));
        hWebSocket_ = NULL;
    }
    if (hRequest_) {
        WinHttpCloseHandle(H(hRequest_));
        hRequest_ = NULL;
    }
    if (hConnect_) {
        WinHttpCloseHandle(H(hConnect_));
        hConnect_ = NULL;
    }
    if (hSession_) {
        WinHttpCloseHandle(H(hSession_));
        hSession_ = NULL;
    }
    connected_ = false;
}

bool WsClient::connect(const std::string& hostPort) {
    last_error_.clear();
    disconnect();

    std::string host;
    int port = 8443;  // default WS port (plain WS, no WSS)
    size_t colon = hostPort.find(':');
    if (colon != std::string::npos) {
        host = hostPort.substr(0, colon);
        port = atoi(hostPort.c_str() + colon + 1);
        if (port <= 0) port = 8443;
    } else {
        host = hostPort;
    }

    std::wstring whost = to_wide(host);

    hSession_ = WinHttpOpen(
        L"CoinBankPayload/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!hSession_) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpOpen: " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        return false;
    }

    // Plain HTTP/WS only (no WSS/TLS - server provides WS only)
    INTERNET_PORT iport = (INTERNET_PORT)port;
    hConnect_ = WinHttpConnect(H(hSession_), whost.c_str(), iport, 0);
    if (!hConnect_) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpConnect: " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        disconnect();
        return false;
    }

    hRequest_ = WinHttpOpenRequest(
        H(hConnect_),
        L"GET",
        L"/",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0
    );
    if (!hRequest_) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpOpenRequest: " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        disconnect();
        return false;
    }

    // Set WebSocket upgrade (plain WS, no TLS)
    if (!WinHttpSetOption(H(hRequest_), WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0)) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpSetOption(UPGRADE): " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        disconnect();
        return false;
    }

    if (!WinHttpSendRequest(H(hRequest_), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpSendRequest: " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        disconnect();
        return false;
    }

    if (!WinHttpReceiveResponse(H(hRequest_), NULL)) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpReceiveResponse: " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        disconnect();
        return false;
    }

    hWebSocket_ = WinHttpWebSocketCompleteUpgrade(H(hRequest_), 0);
    if (!hWebSocket_) {
        DWORD err = GetLastError();
        last_error_ = "WinHttpWebSocketCompleteUpgrade: " + get_win32_error_string(err) + " (" + std::to_string(err) + ")";
        disconnect();
        return false;
    }

    WinHttpCloseHandle(H(hRequest_));
    hRequest_ = NULL;

    connected_ = true;
    if (callbacks_.on_connect) callbacks_.on_connect();
    return true;
}

bool WsClient::send(const std::string& json) {
    if (!hWebSocket_ || !connected_) return false;
    DWORD err = WinHttpWebSocketSend(H(hWebSocket_), WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        (PVOID)json.c_str(), (DWORD)json.size());
    return (err == NO_ERROR);
}

bool WsClient::receive(std::string& out_action, std::string& out_payload) {
    if (!hWebSocket_ || !connected_) return false;

    char buf[65536];
    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType;

    DWORD err = WinHttpWebSocketReceive(H(hWebSocket_), buf, sizeof(buf) - 1, &bytesRead, &bufType);
    if (err != NO_ERROR) return false;
    if (bufType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) return false;
    if (bytesRead == 0) return true;

    buf[bytesRead] = '\0';
    std::string raw(buf);
    out_payload = raw;
    out_action.clear();

    size_t actPos = raw.find("\"action\"");
    if (actPos != std::string::npos) {
        size_t colon = raw.find(':', actPos);
        size_t start = raw.find('"', colon);
        if (start != std::string::npos) {
            start++;
            size_t end = raw.find('"', start);
            if (end != std::string::npos) {
                out_action = raw.substr(start, end - start);
            }
        }
    }
    return true;
}
