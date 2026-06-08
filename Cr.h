#pragma once
#include <string>
#include <cwctype>


const std::wstring UKR_UPPER = L"АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";
const std::wstring UKR_LOWER = L"абвгґдеєжзиіїйклмнопрстуфхцчшщьюя";
const std::wstring ENG_UPPER = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::wstring ENG_LOWER = L"abcdefghijklmnopqrstuvwxyz";


inline wchar_t shiftChar(wchar_t c, int shift, bool encrypt) {
    size_t pos;
    int dir = encrypt ? 1 : -1;

    if ((pos = UKR_UPPER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(UKR_UPPER.length());
        return UKR_UPPER[(pos + (shift * dir) % len + len) % len];
    }
    if ((pos = UKR_LOWER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(UKR_LOWER.length());
        return UKR_LOWER[(pos + (shift * dir) % len + len) % len];
    }
    if ((pos = ENG_UPPER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(ENG_UPPER.length());
        return ENG_UPPER[(pos + (shift * dir) % len + len) % len];
    }
    if ((pos = ENG_LOWER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(ENG_LOWER.length());
        return ENG_LOWER[(pos + (shift * dir) % len + len) % len];
    }
    return c;
}


class Cipher {
public:
    virtual ~Cipher() = default;
    virtual std::wstring encrypt(const std::wstring& text) = 0;
    virtual std::wstring decrypt(const std::wstring& text) = 0;
};


class CaesarCipher : public Cipher {
private:
    int shift;
public:
    CaesarCipher(int s) : shift(s) {}
    std::wstring encrypt(const std::wstring& text) override {
        std::wstring result = text;
        for (wchar_t& c : result) c = shiftChar(c, shift, true);
        return result;
    }
    std::wstring decrypt(const std::wstring& text) override {
        std::wstring result = text;
        for (wchar_t& c : result) c = shiftChar(c, shift, false);
        return result;
    }
};


class VigenereCipher : public Cipher {
private:
    std::wstring key;
    int getShiftValue(wchar_t keyChar) {
        size_t pos;
        if ((pos = UKR_UPPER.find(keyChar)) != std::wstring::npos) return static_cast<int>(pos);
        if ((pos = UKR_LOWER.find(keyChar)) != std::wstring::npos) return static_cast<int>(pos);
        if ((pos = ENG_UPPER.find(keyChar)) != std::wstring::npos) return static_cast<int>(pos);
        if ((pos = ENG_LOWER.find(keyChar)) != std::wstring::npos) return static_cast<int>(pos);
        return 0;
    }
public:
    VigenereCipher(const std::wstring& k) : key(k) {
        if (key.empty()) key = L"а";
    }
    std::wstring encrypt(const std::wstring& text) override {
        std::wstring result = text;
        size_t keyIndex = 0;
        for (size_t i = 0; i < text.length(); ++i) {
            if (UKR_UPPER.find(text[i]) != std::wstring::npos || UKR_LOWER.find(text[i]) != std::wstring::npos ||
                ENG_UPPER.find(text[i]) != std::wstring::npos || ENG_LOWER.find(text[i]) != std::wstring::npos) {
                int shift = getShiftValue(key[keyIndex % key.length()]);
                result[i] = shiftChar(text[i], shift, true);
                keyIndex++;
            }
        }
        return result;
    }
    std::wstring decrypt(const std::wstring& text) override {
        std::wstring result = text;
        size_t keyIndex = 0;
        for (size_t i = 0; i < text.length(); ++i) {
            if (UKR_UPPER.find(text[i]) != std::wstring::npos || UKR_LOWER.find(text[i]) != std::wstring::npos ||
                ENG_UPPER.find(text[i]) != std::wstring::npos || ENG_LOWER.find(text[i]) != std::wstring::npos) {
                int shift = getShiftValue(key[keyIndex % key.length()]);
                result[i] = shiftChar(text[i], shift, false);
                keyIndex++;
            }
        }
        return result;
    }
};


class XORCipher : public Cipher {
private:
    std::wstring key;
public:
    XORCipher(const std::wstring& k) : key(k) { if (key.empty()) key = L"key"; }
    std::wstring encrypt(const std::wstring& text) override {
        std::wstring result = text;
        for (size_t i = 0; i < text.length(); ++i) result[i] = text[i] ^ key[i % key.length()];
        return result;
    }
    std::wstring decrypt(const std::wstring& text) override { return encrypt(text); }
}; once
