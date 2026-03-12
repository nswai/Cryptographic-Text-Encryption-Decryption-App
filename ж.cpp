#include <iostream>
#include <string>
#include <fstream>

using namespace std;

// Caesar encryption
string caesarEncrypt(string text, int key)
{
    for (char &c : text)
        c = c + key;
    return text;
}

// Caesar decryption
string caesarDecrypt(string text, int key)
{
    for (char &c : text)
        c = c - key;
    return text;
}

// XOR encryption/decryption
string xorCipher(string text, char key)
{
    for (char &c : text)
        c = c ^ key;
    return text;
}

// Save text to file
void saveToFile(string text)
{
    ofstream file("result.txt");
    file << text;
    file.close();
    cout << "Результат збережено у файл result.txt\n";
}

int main()
{
    int choice;
    string text;
    int key;

    cout << "==== Криптографічний додаток ====\n";
    cout << "1 - Caesar шифрування\n";
    cout << "2 - Caesar дешифрування\n";
    cout << "3 - XOR шифрування\n";
    cout << "4 - XOR дешифрування\n";
    cout << "Ваш вибір: ";
    cin >> choice;

    cin.ignore();

    cout << "Введіть текст: ";
    getline(cin, text);

    if (choice == 1)
    {
        cout << "Введіть ключ: ";
        cin >> key;
        string result = caesarEncrypt(text, key);
        cout << "Зашифрований текст: " << result << endl;
        saveToFile(result);
    }
    else if (choice == 2)
    {
        cout << "Введіть ключ: ";
        cin >> key;
        string result = caesarDecrypt(text, key);
        cout << "Розшифрований текст: " << result << endl;
        saveToFile(result);
    }
    else if (choice == 3)
    {
        char k;
        cout << "Введіть символ ключа: ";
        cin >> k;
        string result = xorCipher(text, k);
        cout << "Зашифрований текст: " << result << endl;
        saveToFile(result);
    }
    else if (choice == 4)
    {
        char k;
        cout << "Введіть символ ключа: ";
        cin >> k;
        string result = xorCipher(text, k);
        cout << "Розшифрований текст: " << result << endl;
        saveToFile(result);
    }
    else
    {
        cout << "Невірний вибір\n";
    }

    return 0;
}