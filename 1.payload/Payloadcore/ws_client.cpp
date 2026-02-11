#include "stdafx.h"
#include "ws_client.h"

#pragma comment(lib, "winhttp.lib")

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
        WinHttpCloseHandle(hWebSocket_);
        hWebSocket_ = NULL;
    }
    if (hRequest_) {
        WinHttpCloseHandle(hRequest_);
        hRequest_ = NULL;
    }
    if (hConnect_) {
        WinHttpCloseHandle(hConnect_);
        hConnect_ = NULL;
    }
    if (hSession_) {
        WinHttpCloseHandle(hSession_);
        hSession_ = NULL;
    }
    connected_ = false;
}

bool WsClient::connect(const std::string& hostPort) {
    disconnect();

    std::string host;
    int port = 8443;
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
    if (!hSession_) return false;

    DWORD secureFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hSession_, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&secureFlags, sizeof(secureFlags));

    INTERNET_PORT iport = (INTERNET_PORT)port;
    hConnect_ = WinHttpConnect(hSession_, whost.c_str(), iport, 0);
    if (!hConnect_) {
        disconnect();
        return false;
    }

    DWORD flags = (port == 443 || port == 8443) ? WINHTTP_FLAG_SECURE : 0;
    hRequest_ = WinHttpOpenRequest(
        hConnect_,
        L"GET",
        L"/",
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );
    if (!hRequest_) {
        disconnect();
        return false;
    }

    if (flags) {
        WinHttpSetOption(hRequest_, WINHTTP_OPTION_SECURITY_FLAGS, (LPVOID)&secureFlags, sizeof(secureFlags));
    }

    DWORD upgrade = 1;
    if (!WinHttpSetOption(hRequest_, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, &upgrade, sizeof(upgrade))) {
        disconnect();
        return false;
    }

    if (!WinHttpSendRequest(hRequest_, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        disconnect();
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest_, NULL)) {
        disconnect();
        return false;
    }

    hWebSocket_ = WinHttpWebSocketCompleteUpgrade(hRequest_, 0);
    if (!hWebSocket_) {
        disconnect();
        return false;
    }

    WinHttpCloseHandle(hRequest_);
    hRequest_ = NULL;

    connected_ = true;
    if (callbacks_.on_connect) callbacks_.on_connect();
    return true;
}

bool WsClient::send(const std::string& json) {
    if (!hWebSocket_ || !connected_) return false;
    DWORD err = WinHttpWebSocketSend(hWebSocket_, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        (PVOID)json.c_str(), (DWORD)json.size());
    return (err == NO_ERROR);
}

bool WsClient::receive(std::string& out_action, std::string& out_payload) {
    if (!hWebSocket_ || !connected_) return false;

    char buf[65536];
    DWORD bytesRead = 0;
    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType;

    DWORD err = WinHttpWebSocketReceive(hWebSocket_, buf, sizeof(buf) - 1, &bytesRead, &bufType);
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
