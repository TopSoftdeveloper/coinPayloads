#ifndef WstDebugInfo_h
#define WstDebugInfo_h

#include <windows.h>
#include <stdlib.h>
#include <strsafe.h>

#ifdef UNICODE
#define DbgPrintf DbgPrintfW
#else
#define DbgPrintf DbgPrintfA
#endif

inline void __cdecl DbgPrintfW(LPCWSTR format, ...) 
{
    va_list	args;
    va_start(args, format);
    size_t nBufLen = _vscwprintf(format, args);

    if (nBufLen > 0) 
    {
        nBufLen = sizeof(WCHAR) * (nBufLen + 1);

        LPWSTR buf = (LPWSTR) malloc(nBufLen);

        if (buf) 
        {
            HRESULT hr = StringCbVPrintfW(buf, nBufLen, format, args);

            if (SUCCEEDED(hr)) 
            {
                OutputDebugStringW(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}

inline void __cdecl DbgPrintfA(LPCSTR format, ...) 
{
    va_list	args;
    va_start(args, format);
    size_t nBufLen = _vscprintf(format, args);

    if (nBufLen > 0) 
    {
        nBufLen = sizeof(CHAR) * (nBufLen + 1);

        LPSTR buf = (LPSTR) malloc(nBufLen);

        if (buf) 
        {
            HRESULT hr = StringCbVPrintfA(buf, nBufLen, format, args);

            if (SUCCEEDED(hr)) 
            {
                OutputDebugStringA(buf);
            }
            free(buf);
        }
        va_end(args);
    }
}
#endif