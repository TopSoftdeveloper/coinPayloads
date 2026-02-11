#pragma once

#ifndef SIMPLE_WEB_CRYPTO_HPP
#define SIMPLE_WEB_CRYPTO_HPP

#include <cmath>
#include <iomanip>
#include <istream>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace SimpleWeb {
#if _MSC_VER == 1700
  inline double round(double x) noexcept { return floor(x + 0.5); }
#endif

  class Crypto {
    const static std::size_t buffer_size = 131072;

    static bool hash_alg(const std::string& input, LPCWSTR algId, std::size_t hashSize, std::string& out) noexcept {
      BCRYPT_ALG_HANDLE hAlg = NULL;
      BCRYPT_HASH_HANDLE hHash = NULL;
      NTSTATUS status;
      status = BCryptOpenAlgorithmProvider(&hAlg, algId, NULL, 0);
      if (!BCRYPT_SUCCESS(status)) return false;
      status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
      if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
      status = BCryptHashData(hHash, (PUCHAR)input.data(), (ULONG)input.size(), 0);
      if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
      out.resize(hashSize);
      status = BCryptFinishHash(hHash, (PUCHAR)&out[0], (ULONG)hashSize, 0);
      BCryptDestroyHash(hHash);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return BCRYPT_SUCCESS(status);
    }

    static bool hash_stream(std::istream& stream, LPCWSTR algId, std::size_t hashSize, std::string& out) noexcept {
      BCRYPT_ALG_HANDLE hAlg = NULL;
      BCRYPT_HASH_HANDLE hHash = NULL;
      NTSTATUS status;
      status = BCryptOpenAlgorithmProvider(&hAlg, algId, NULL, 0);
      if (!BCRYPT_SUCCESS(status)) return false;
      status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
      if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
      std::vector<char> buffer(buffer_size);
      std::streamsize read_length;
      while ((read_length = stream.read(&buffer[0], buffer_size).gcount()) > 0)
        if (!BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)buffer.data(), (ULONG)read_length, 0)))
          { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
      out.resize(hashSize);
      status = BCryptFinishHash(hHash, (PUCHAR)&out[0], (ULONG)hashSize, 0);
      BCryptDestroyHash(hHash);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return BCRYPT_SUCCESS(status);
    }

  public:
    class Base64 {
    public:
      static constexpr char enc[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      static std::string encode(const std::string& ascii) noexcept {
        std::string base64;
        size_t n = ascii.size();
        base64.resize(static_cast<std::size_t>(4 * ceil(static_cast<double>(n) / 3.0)));
        size_t i = 0, j = 0;
        for (; i + 2 < n; i += 3, j += 4) {
          unsigned v = (unsigned char)ascii[i] << 16 | (unsigned char)ascii[i + 1] << 8 | (unsigned char)ascii[i + 2];
          base64[j] = enc[(v >> 18) & 63]; base64[j + 1] = enc[(v >> 12) & 63];
          base64[j + 2] = enc[(v >> 6) & 63]; base64[j + 3] = enc[v & 63];
        }
        if (i < n) {
          unsigned v = (unsigned char)ascii[i] << 16;
          if (i + 1 < n) v |= (unsigned char)ascii[i + 1] << 8;
          base64[j++] = enc[(v >> 18) & 63]; base64[j++] = enc[(v >> 12) & 63];
          base64[j++] = (i + 1 < n) ? enc[(v >> 6) & 63] : '=';
          base64[j] = '=';
        }
        return base64;
      }

      static std::string decode(const std::string& base64) noexcept {
        static int dec[256];
        static bool once = []() {
          for (int i = 0; i < 256; i++) dec[i] = -1;
          for (int i = 0; i < 26; i++) { dec['A' + i] = i; dec['a' + i] = 26 + i; }
          for (int i = 0; i < 10; i++) dec['0' + i] = 52 + i;
          dec['+'] = 62; dec['/'] = 63;
          return true;
        }();
        std::string ascii;
        ascii.resize((6 * base64.size()) / 8);
        size_t j = 0;
        for (size_t i = 0; i + 3 < base64.size(); i += 4) {
          int a = dec[(unsigned char)base64[i]], b = dec[(unsigned char)base64[i + 1]];
          int c = dec[(unsigned char)base64[i + 2]], d = dec[(unsigned char)base64[i + 3]];
          if (a < 0 || b < 0) break;
          unsigned v = (a << 18) | (b << 12) | (c >= 0 ? c << 6 : 0) | (d >= 0 ? d : 0);
          ascii[j++] = (char)(v >> 16); if (c >= 0) ascii[j++] = (char)(v >> 8); if (d >= 0) ascii[j++] = (char)v;
        }
        ascii.resize(j);
        return ascii;
      }
    };

    static std::string to_hex_string(const std::string& input) noexcept {
      std::stringstream hex_stream;
      hex_stream << std::hex << std::internal << std::setfill('0');
      for (auto& byte : input) hex_stream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(byte));
      return hex_stream.str();
    }

    static std::string md5(const std::string& input, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_alg(input, BCRYPT_MD5_ALGORITHM, 16, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_MD5_ALGORITHM, 16, hash);
      return hash;
    }

    static std::string md5(std::istream& stream, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_stream(stream, BCRYPT_MD5_ALGORITHM, 16, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_MD5_ALGORITHM, 16, hash);
      return hash;
    }

    static std::string sha1(const std::string& input, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_alg(input, BCRYPT_SHA1_ALGORITHM, 20, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_SHA1_ALGORITHM, 20, hash);
      return hash;
    }

    static std::string sha1(std::istream& stream, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_stream(stream, BCRYPT_SHA1_ALGORITHM, 20, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_SHA1_ALGORITHM, 20, hash);
      return hash;
    }

    static std::string sha256(const std::string& input, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_alg(input, BCRYPT_SHA256_ALGORITHM, 32, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_SHA256_ALGORITHM, 32, hash);
      return hash;
    }

    static std::string sha256(std::istream& stream, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_stream(stream, BCRYPT_SHA256_ALGORITHM, 32, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_SHA256_ALGORITHM, 32, hash);
      return hash;
    }

    static std::string sha512(const std::string& input, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_alg(input, BCRYPT_SHA512_ALGORITHM, 64, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_SHA512_ALGORITHM, 64, hash);
      return hash;
    }

    static std::string sha512(std::istream& stream, std::size_t iterations = 1) noexcept {
      std::string hash;
      if (!hash_stream(stream, BCRYPT_SHA512_ALGORITHM, 64, hash)) return std::string();
      for (std::size_t c = 1; c < iterations; ++c) hash_alg(hash, BCRYPT_SHA512_ALGORITHM, 64, hash);
      return hash;
    }

    static std::string pbkdf2(const std::string& password, const std::string& salt, int iterations, int key_size) noexcept {
      std::string key;
      key.resize(static_cast<std::size_t>(key_size));
      BCRYPT_ALG_HANDLE hAlg = NULL;
      NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
      if (!BCRYPT_SUCCESS(status)) return std::string();
      status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)password.data(), (ULONG)password.size(), (PUCHAR)salt.data(), (ULONG)salt.size(), (ULONGLONG)iterations, (PUCHAR)&key[0], (ULONG)key_size, 0);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      return BCRYPT_SUCCESS(status) ? key : std::string();
    }
  };
}
#endif /* SIMPLE_WEB_CRYPTO_HPP */
