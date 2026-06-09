#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:wWinMainCRTStartup")

#include <windows.h>
#include <string>
#include <cwctype>
#include <clocale>
#include <memory>

// ============================================================================
// 1. АЛГОРИТМИ ШИФРУВАННЯ
// ============================================================================
inline const std::wstring UKR_UPPER = L"\u0410\u0411\u0412\u0413\u0490\u0414\u0415\u0404\u0416\u0417\u0418\u0406\u0407\u0419\u041a\u041b\u041c\u041d\u041e\u041f\u0420\u0421\u0422\u0423\u0424\u0425\u0426\u0427\u0428\u0429\u042c\u042e\u042f";
inline const std::wstring UKR_LOWER = L"\u0430\u0431\u0432\u0433\u0491\u0434\u0435\u0454\u0436\u0437\u0438\u0456\u0457\u0439\u043a\u043b\u043c\u043d\u043e\u043f\u0440\u0441\u0442\u0443\u0444\u0445\u0446\u0447\u0448\u0449\u044c\u044e\u044f";
inline const std::wstring ENG_UPPER = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
inline const std::wstring ENG_LOWER = L"abcdefghijklmnopqrstuvwxyz";

inline wchar_t shiftChar(wchar_t c, int shift, bool encrypt) {
    size_t pos;
    int dir = encrypt ? 1 : -1;

    if ((pos = UKR_UPPER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(UKR_UPPER.length());
        int p = static_cast<int>(pos);
        return UKR_UPPER[(p + (shift * dir) % len + len) % len];
    }
    if ((pos = UKR_LOWER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(UKR_LOWER.length());
        int p = static_cast<int>(pos);
        return UKR_LOWER[(p + (shift * dir) % len + len) % len];
    }
    if ((pos = ENG_UPPER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(ENG_UPPER.length());
        int p = static_cast<int>(pos);
        return ENG_UPPER[(p + (shift * dir) % len + len) % len];
    }
    if ((pos = ENG_LOWER.find(c)) != std::wstring::npos) {
        int len = static_cast<int>(ENG_LOWER.length());
        int p = static_cast<int>(pos);
        return ENG_LOWER[(p + (shift * dir) % len + len) % len];
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
    VigenereCipher(const std::wstring& k) : key(k) { if (key.empty()) key = L"\u0430"; }

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

// Модернізований та безпечний шифр XOR з виводом у HEX-форматі
class XORCipher : public Cipher {
private:
    std::wstring key;
public:
    XORCipher(const std::wstring& k) : key(k) { if (key.empty()) key = L"key"; }

    std::wstring encrypt(const std::wstring& text) override {
        std::wstring result = L"";
        wchar_t buf[8];
        for (size_t i = 0; i < text.length(); ++i) {
            wchar_t ciphered = text[i] ^ key[i % key.length()];
            swprintf(buf, 8, L"%04X", ciphered); // Переводимо символ у безпечний 16-ковий код
            result += buf;
        }
        return result;
    }

    std::wstring decrypt(const std::wstring& text) override {
        if (text.length() % 4 != 0) {
            return L"\u041f\u043e\u043c\u0438\u043b\u043a\u0430: \u043d\u0435\u0432\u0456\u0440\u043d\u0438\u0439 \u0444\u043e\u0440\u043c\u0430\u0442 HEX!"; // "Помилка: невірний формат HEX!"
        }
        std::wstring result = L"";
        for (size_t i = 0; i < text.length(); i += 4) {
            std::wstring hexPart = text.substr(i, 4);
            wchar_t ciphered = static_cast<wchar_t>(wcstoul(hexPart.c_str(), nullptr, 16));
            wchar_t decrypted = ciphered ^ key[(i / 4) % key.length()];
            result += decrypted;
        }
        return result;
    }
};

// ============================================================================
// 2. ГРАФІЧНИЙ ІНТЕРФЕЙС (WIN32 API)
// ============================================================================
#define IDC_BTN_ENCRYPT 1001
#define IDC_BTN_DECRYPT 1002
#define IDC_COMBO_CIPHER 1003
#define IDC_BTN_REVERSE 1004

HWND hInputText, hKeyText, hOutputText, hCipherCombo;

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        HFONT hFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        // "Вхідний текст:"
        HWND hStatic1 = CreateWindowW(L"STATIC", L"\u0412\u0445\u0456\u0434\u043d\u0438\u0439 \u0442\u0435\u043a\u0441\u0442:", WS_VISIBLE | WS_CHILD, 10, 10, 150, 20, hwnd, NULL, NULL, NULL);
        hInputText = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 10, 30, 460, 25, hwnd, NULL, NULL, NULL);

        // "Оберіть шифр:"
        HWND hStatic2 = CreateWindowW(L"STATIC", L"\u041e\u0431\u0435\u0440\u0456\u0442\u044c \u0448\u0438\u0444\u0440:", WS_VISIBLE | WS_CHILD, 10, 70, 150, 20, hwnd, NULL, NULL, NULL);
        hCipherCombo = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, 10, 90, 200, 100, hwnd, (HMENU)IDC_COMBO_CIPHER, NULL, NULL);

        // "Шифр Цезаря", "Шифр Віженера", "Шифр XOR"
        SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"\u0428\u0438\u0444\u0440 \u0426\u0435\u0437\u0430\u0440\u044f");
        SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"\u0428\u0438\u0444\u0440 \u0412\u0456\u0436\u0435\u043d\u0435\u0440\u0430");
        SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"\u0428\u0438\u0444\u0440 XOR");
        SendMessageW(hCipherCombo, CB_SETCURSEL, 0, 0);

        // "Ключ (число або текст):"
        HWND hStatic3 = CreateWindowW(L"STATIC", L"\u041a\u043b\u044e\u0447 (\u0447\u0438\u0441\u043b\u043e \u0430\u0431\u043e \u0442\u0435\u043a\u0441\u0442):", WS_VISIBLE | WS_CHILD, 240, 70, 200, 20, hwnd, NULL, NULL, NULL);
        hKeyText = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 240, 90, 230, 25, hwnd, NULL, NULL, NULL);

        // "ЗАШИФРУВАТИ", "ДЕШИФРУВАТИ"
        HWND hBtn1 = CreateWindowW(L"BUTTON", L"\u0417\u0410\x0428\u0418\u0424\u0420\u0423\u0412\u0410\u0422\u0418", WS_VISIBLE | WS_CHILD, 10, 130, 220, 35, hwnd, (HMENU)IDC_BTN_ENCRYPT, NULL, NULL);
        HWND hBtn2 = CreateWindowW(L"BUTTON", L"\u0414\u0415\x0428\u0418\u0424\u0420\u0423\u0412\u0410\u0422\u0418", WS_VISIBLE | WS_CHILD, 250, 130, 220, 35, hwnd, (HMENU)IDC_BTN_DECRYPT, NULL, NULL);

        // "▲   РЕВЕРС ТЕКСТУ (Результат на початок)   ▲"
        HWND hBtnRev = CreateWindowW(L"BUTTON", L"\u25b2   \u0420\u0415\u0412\u0415\u0420\u0421 \u0422\u0415\u041a\u0421\u0422\u0423 (\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 \u2794 \u0412\u0445\u0456\u0434)   \u25b2", WS_VISIBLE | WS_CHILD, 10, 175, 460, 30, hwnd, (HMENU)IDC_BTN_REVERSE, NULL, NULL);

        // "Результат:"
        HWND hStatic4 = CreateWindowW(L"STATIC", L"\u0420\u0435\x0437\u0443\u043b\u044c\u0442\u0430\u0442:", WS_VISIBLE | WS_CHILD, 10, 215, 150, 20, hwnd, NULL, NULL, NULL);
        hOutputText = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY, 10, 235, 460, 25, hwnd, NULL, NULL, NULL);

        SendMessageW(hStatic1, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hStatic2, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hStatic3, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hStatic4, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hInputText, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hKeyText, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hOutputText, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hCipherCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtn1, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtn2, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hBtnRev, WM_SETFONT, (WPARAM)hFont, TRUE);
        break;
    }
    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_BTN_REVERSE) {
            int outLen = GetWindowTextLengthW(hOutputText);
            std::wstring outText(outLen + 1, L'\0');
            GetWindowTextW(hOutputText, &outText[0], outLen + 1);
            outText.resize(outLen);

            SetWindowTextW(hInputText, outText.c_str());
            SetWindowTextW(hOutputText, L"");
            break;
        }

        if (LOWORD(wParam) == IDC_BTN_ENCRYPT || LOWORD(wParam) == IDC_BTN_DECRYPT) {
            int inputLen = GetWindowTextLengthW(hInputText);
            std::wstring inputText(inputLen + 1, L'\0');
            GetWindowTextW(hInputText, &inputText[0], inputLen + 1);
            inputText.resize(inputLen);

            int keyLen = GetWindowTextLengthW(hKeyText);
            std::wstring keyText(keyLen + 1, L'\0');
            GetWindowTextW(hKeyText, &keyText[0], keyLen + 1);
            keyText.resize(keyLen);

            int cipherIndex = (int)SendMessageW(hCipherCombo, CB_GETCURSEL, 0, 0);
            std::unique_ptr<Cipher> activeCipher;

            if (cipherIndex == 0) {
                int shift = _wtoi(keyText.c_str());
                activeCipher = std::make_unique<CaesarCipher>(shift);
            }
            else if (cipherIndex == 1) {
                activeCipher = std::make_unique<VigenereCipher>(keyText);
            }
            else {
                activeCipher = std::make_unique<XORCipher>(keyText);
            }

            std::wstring resultText;
            if (LOWORD(wParam) == IDC_BTN_ENCRYPT) {
                resultText = activeCipher->encrypt(inputText);
            }
            else {
                resultText = activeCipher->decrypt(inputText);
            }

            SetWindowTextW(hOutputText, resultText.c_str());
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    _wsetlocale(LC_ALL, L"Ukrainian");

    const wchar_t CLASS_NAME[] = L"CryptoSpyProjectClass";

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassW(&wc);

    // "Криптографічний додаток (Курсовий проєкт)"
    HWND hwnd = CreateWindowExW(
        0, CLASS_NAME, L"\u041a\u0440\u0438\u043f\u0442\u043e\u0433\u0440\u0430\u0444\u0456\x0447\u043d\u0438\u0439 \u0434\u043e\u0434\u0430\u0442\u043e\u043a (\u041a\u0443\u0440\u0441\u043e\u0432\u0438\u0439 \u043f\u0440\u043e\u0454\u043a\u0442)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 320,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}