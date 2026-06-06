#include <windows.h>
#include <string>
#include <memory>
#include <cwctype>
#include <stdexcept>

const std::wstring UKR_UPPER = L"АБВГҐДЕЄЖЗИІЇЙКЛМНОПРСТУФХЦЧШЩЬЮЯ";
const std::wstring UKR_LOWER = L"абвгґдеєжзиіїйклмнопрстуфхцчшщьюя";
const std::wstring ENG_UPPER = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::wstring ENG_LOWER = L"abcdefghijklmnopqrstuvwxyz";

wchar_t shiftChar(wchar_t c, int shift, bool encrypt) {
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
};



#define IDC_BTN_ENCRYPT 101
#define IDC_BTN_DECRYPT 102
#define IDC_COMBO_CIPHER 103
#define IDC_BTN_SWAP    104  

HWND hInputText, hKeyText, hOutputText, hCipherCombo;

void SetModernFont(HWND hwnd) {
    HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    SendMessage(hwnd, WM_SETFONT, (WPARAM)hFont, TRUE);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        SetModernFont(CreateWindowW(L"STATIC", L"Вхідний текст:", WS_VISIBLE | WS_CHILD, 15, 10, 200, 20, hwnd, NULL, NULL, NULL));
        SetModernFont(CreateWindowW(L"STATIC", L"Ключ (слово або число):", WS_VISIBLE | WS_CHILD, 15, 115, 200, 20, hwnd, NULL, NULL, NULL));
        SetModernFont(CreateWindowW(L"STATIC", L"Оберіть алгоритм:", WS_VISIBLE | WS_CHILD, 250, 115, 200, 20, hwnd, NULL, NULL, NULL));
        SetModernFont(CreateWindowW(L"STATIC", L"Результат:", WS_VISIBLE | WS_CHILD, 15, 235, 100, 20, hwnd, NULL, NULL, NULL));

        
        HWND hBtnSwap = CreateWindowW(L"BUTTON", L"🔄 Перенести у вхід", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 290, 230, 180, 23, hwnd, (HMENU)IDC_BTN_SWAP, NULL, NULL);
        SetModernFont(hBtnSwap);

        hInputText = CreateWindowW(L"EDIT", L"Привіт, це мій курсовий проект!", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL, 15, 30, 455, 75, hwnd, NULL, NULL, NULL);
        hKeyText = CreateWindowW(L"EDIT", L"ключ", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 15, 135, 210, 25, hwnd, NULL, NULL, NULL);
        hOutputText = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 15, 255, 455, 95, hwnd, NULL, NULL, NULL);

        SetModernFont(hInputText);
        SetModernFont(hKeyText);
        SetModernFont(hOutputText);

        hCipherCombo = CreateWindowW(L"COMBOBOX", L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, 250, 135, 220, 200, hwnd, (HMENU)IDC_COMBO_CIPHER, NULL, NULL);
        SetModernFont(hCipherCombo);
        SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"Шифр Цезаря (UA / EN)");
        SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"Шифр Віженера (UA / EN)");
        SendMessageW(hCipherCombo, CB_ADDSTRING, 0, (LPARAM)L"XOR Шифр (Універсальний)");
        SendMessageW(hCipherCombo, CB_SETCURSEL, 0, 0);

        HWND hBtnEnc = CreateWindowW(L"BUTTON", L"🔒 ЗАШИФРУВАТИ", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 15, 180, 210, 40, hwnd, (HMENU)IDC_BTN_ENCRYPT, NULL, NULL);
        HWND hBtnDec = CreateWindowW(L"BUTTON", L"🔓 ДЕШИФРУВАТИ", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON, 250, 180, 220, 40, hwnd, (HMENU)IDC_BTN_DECRYPT, NULL, NULL);
        SetModernFont(hBtnEnc);
        SetModernFont(hBtnDec);

        break;
    }
    case WM_COMMAND: {
       
        if (LOWORD(wParam) == IDC_BTN_SWAP) {
            int outLen = GetWindowTextLengthW(hOutputText);
            if (outLen > 0) {
                std::wstring outText(outLen + 1, L'\0');
                GetWindowTextW(hOutputText, &outText[0], outLen + 1);
                outText.resize(outLen);

                
                SetWindowTextW(hInputText, outText.c_str());
                SetWindowTextW(hOutputText, L"");
            }
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

            int cipherIndex = SendMessageW(hCipherCombo, CB_GETCURSEL, 0, 0);
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
    const wchar_t CLASS_NAME[] = L"CryptoGuiWindowClass";

    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClassW(&wc);і

    HWND hwnd = CreateWindowExW(
        0, CLASS_NAME, L"Криптографічний додаток (Курсовий проєкт)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 410,
        NULL, NULL, hInstance, NULL
    );

    if (hwnd == NULL) return 0;

    ShowWindow(hwnd, nCmdShow);

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}