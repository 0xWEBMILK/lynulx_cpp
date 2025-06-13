#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <set>
#include <cctype>
#include <cstdlib>

using namespace std;

string xor_encrypt_decrypt(const string &data, const string &key) {
    string output = data;
    for (size_t i = 0; i < data.size(); ++i) {
        output[i] = data[i] ^ key[i % key.size()];
    }
    return output;
}

string string_to_hex(const string &input) {
    stringstream hex_stream;
    hex_stream << hex << setfill('0');
    for (unsigned char c : input) {
        hex_stream << setw(2) << static_cast<int>(c);
    }
    return hex_stream.str();
}

string hex_to_string(const string &input) {
    string output;
    if (input.length() % 2 != 0) return "";
    for (size_t i = 0; i < input.length(); i += 2) {
        string byteString = input.substr(i, 2);
        char byte = static_cast<char>(strtoul(byteString.c_str(), nullptr, 16));
        output.push_back(byte);
    }
    return output;
}

string get_current_date() {
    time_t now = time(nullptr);
    tm *ltm = localtime(&now);
    ostringstream oss;
    oss << (1900 + ltm->tm_year) << '-'
        << setw(2) << setfill('0') << (1 + ltm->tm_mon) << '-'
        << setw(2) << setfill('0') << ltm->tm_mday;
    return oss.str();
}

string get_past_date(int offset) {
    time_t now = time(nullptr);
    now -= offset * 24 * 3600;
    tm *ltm = localtime(&now);
    ostringstream oss;
    oss << (1900 + ltm->tm_year) << '-'
        << setw(2) << setfill('0') << (1 + ltm->tm_mon) << '-'
        << setw(2) << setfill('0') << ltm->tm_mday;
    return oss.str();
}

struct CleaningRecord {
    int id;
    string client_name;
    string address;
    string phone;
    string work_name;
    double cost;
    string executor_name;
    string date;
};

class CleaningDatabase {
private:
    vector<CleaningRecord> records;
    const string encryption_key;

    pair<string, size_t> parse_json_value(const string &json_str, size_t start_pos) const {
        size_t value_start = json_str.find_first_not_of(" \t\n\r", start_pos);
        if (value_start == string::npos) return make_pair("", start_pos);

        if (json_str[value_start] == '"') {
            size_t end_quote = json_str.find('"', value_start + 1);
            if (end_quote == string::npos) return make_pair("", start_pos);
            return make_pair(json_str.substr(value_start + 1, end_quote - value_start - 1), end_quote + 1);
        } else if (json_str[value_start] == '{') {
            size_t end_brace = json_str.find('}', value_start + 1);
            if (end_brace == string::npos) return make_pair("", start_pos);
            return make_pair(json_str.substr(value_start, end_brace - value_start + 1), end_brace + 1);
        } else {
            size_t value_end = json_str.find_first_of(",}] \t\n\r", value_start);
            if (value_end == string::npos) value_end = json_str.length();
            return make_pair(json_str.substr(value_start, value_end - value_start), value_end);
        }
    }

    string record_to_json(const CleaningRecord &record, bool encrypt) const {
        ostringstream json;
        json << "{"
            << "\"id\":" << record.id << ","
            << "\"client_name\":\"" << (encrypt ? string_to_hex(xor_encrypt_decrypt(record.client_name, encryption_key)) : record.client_name) << "\","
            << "\"address\":\"" << (encrypt ? string_to_hex(xor_encrypt_decrypt(record.address, encryption_key)) : record.address) << "\","
            << "\"phone\":\"" << (encrypt ? string_to_hex(xor_encrypt_decrypt(record.phone, encryption_key)) : record.phone) << "\","
            << "\"work_name\":\"" << (encrypt ? string_to_hex(xor_encrypt_decrypt(record.work_name, encryption_key)) : record.work_name) << "\","
            << "\"cost\":" << fixed << setprecision(2) << record.cost << ","
            << "\"executor_name\":\"" << (encrypt ? string_to_hex(xor_encrypt_decrypt(record.executor_name, encryption_key)) : record.executor_name) << "\","
            << "\"date\":\"" << (encrypt ? string_to_hex(xor_encrypt_decrypt(record.date, encryption_key)) : record.date) << "\""
            << "}";
        return json.str();
    }

    CleaningRecord json_to_record(const string &json_str, bool decrypt) const {
        CleaningRecord record = {0, "", "", "", "", 0.0, "", ""};
        if (json_str.empty() || json_str.front() != '{' || json_str.back() != '}') {
            return record;
        }

        size_t pos = 1;
        while (pos < json_str.length() - 1) {
            auto key_result = parse_json_value(json_str, pos);
            if (key_result.first.empty()) break;
            string key = key_result.first;
            pos = key_result.second;

            pos = json_str.find_first_not_of(" \t\n\r", pos);
            if (pos == string::npos || json_str[pos] != ':') break;
            pos++;

            auto value_result = parse_json_value(json_str, pos);
            string value = value_result.first;
            pos = value_result.second;

            try {
                if (key == "id") {
                    record.id = stoi(value);
                } else if (key == "client_name") {
                    record.client_name = decrypt ? xor_encrypt_decrypt(hex_to_string(value), encryption_key) : value;
                } else if (key == "address") {
                    record.address = decrypt ? xor_encrypt_decrypt(hex_to_string(value), encryption_key) : value;
                } else if (key == "phone") {
                    record.phone = decrypt ? xor_encrypt_decrypt(hex_to_string(value), encryption_key) : value;
                } else if (key == "work_name") {
                    record.work_name = decrypt ? xor_encrypt_decrypt(hex_to_string(value), encryption_key) : value;
                } else if (key == "cost") {
                    record.cost = stod(value);
                } else if (key == "executor_name") {
                    record.executor_name = decrypt ? xor_encrypt_decrypt(hex_to_string(value), encryption_key) : value;
                } else if (key == "date") {
                    record.date = decrypt ? xor_encrypt_decrypt(hex_to_string(value), encryption_key) : value;
                }
            } catch (...) {
                continue;
            }

            pos = json_str.find_first_not_of(" \t\n\r", pos);
            if (pos != string::npos && json_str[pos] == ',') pos++;
        }

        return record;
    }

public:
    CleaningDatabase(const string &key) : encryption_key(key) {}

    void add_record(const CleaningRecord &record) {
        records.push_back(record);
    }

    bool save_to_file(const string &filename) const {
        ofstream file(filename);
        if (!file.is_open()) return false;

        file << "[";
        for (size_t i = 0; i < records.size(); ++i) {
            file << record_to_json(records[i], true);
            if (i < records.size() - 1) file << ",";
        }
        file << "]";
        return true;
    }

    bool load_from_file(const string &filename) {
        ifstream file(filename);
        if (!file.is_open()) return false;

        string content((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        if (content.empty()) return true;

        content.erase(remove_if(content.begin(), content.end(), ::isspace), content.end());

        if (content[0] != '[' || content.back() != ']') return false;

        size_t pos = 1;
        while (pos < content.size() - 1) {
            size_t record_start = content.find('{', pos);
            if (record_start == string::npos) break;

            size_t record_end = content.find('}', record_start);
            if (record_end == string::npos) break;

            string record_str = content.substr(record_start, record_end - record_start + 1);
            CleaningRecord record = json_to_record(record_str, true);
            if (record.id != 0) {
                records.push_back(record);
            }

            pos = record_end + 1;
            if (pos < content.size() && content[pos] == ',') pos++;
        }

        return true;
    }

    vector<string> get_addresses_last_3_days() const {
        vector<string> addresses;
        string current_date = get_current_date();
        string three_days_ago = get_past_date(3);

        for (const auto &record : records) {
            if (record.date >= three_days_ago && record.date <= current_date) {
                addresses.push_back(record.address);
            }
        }
        return addresses;
    }

    vector<string> get_clients_for_work_last_week(const string &work_name) const {
        vector<string> clients;
        string current_date = get_current_date();
        string week_ago = get_past_date(7);

        for (const auto &record : records) {
            if (record.work_name == work_name && 
                record.date >= week_ago && 
                record.date <= current_date) {
                clients.push_back(record.client_name);
            }
        }
        return clients;
    }

    int get_client_count_for_period(const string &start_date, const string &end_date) const {
        set<string> unique_clients;
        for (const auto &record : records) {
            if (record.date >= start_date && record.date <= end_date) {
                unique_clients.insert(record.client_name);
            }
        }
        return unique_clients.size();
    }

    void print_all_records() const {
        cout << "All records in database:\n";
        for (const auto &record : records) {
            cout << "ID: " << record.id << ", Client: " << record.client_name 
                 << ", Address: " << record.address << ", Work: " << record.work_name
                 << ", Date: " << record.date << endl;
        }
    }
};

int main() {
    CleaningDatabase db("secret_key");
    string filename = "database.json";

    while (true) {
        cout << "\n=== МЕНЮ я===\n"
             << "1. Добавить запись\n"
             << "2. Показать все записи\n"
             << "3. Сохранить базу в файл\n"
             << "4. Загрузить базу из файла\n"
             << "5. Адреса за последние 3 дня\n"
             << "6. Клиенты по типу работ за последнюю неделю\n"
             << "7. Уникальные клиенты за период\n"
             << "0. Выход\n"
             << "Выбор: ";

        int choice;
        cin >> choice;
        cin.ignore();

        if (choice == 0) break;

        switch (choice) {
            case 1: {
                CleaningRecord r;
                cout << "ID: "; cin >> r.id; cin.ignore();
                cout << "ФИО клиента: "; getline(cin, r.client_name);
                cout << "Адрес: "; getline(cin, r.address);
                cout << "Телефон: "; getline(cin, r.phone);
                cout << "Название работы: "; getline(cin, r.work_name);
                cout << "Стоимость: "; cin >> r.cost; cin.ignore();
                cout << "Исполнитель: "; getline(cin, r.executor_name);
                cout << "Дата (ГГГГ-ММ-ДД или пусто для сегодня): ";
                getline(cin, r.date);
                if (r.date.empty()) r.date = get_current_date();
                db.add_record(r);
                cout << "Запись добавлена.\n";
                break;
            }
            case 2:
                db.print_all_records();
                break;
            case 3:
                if (db.save_to_file(filename)) cout << "Сохранено в файл.\n";
                else cout << "Ошибка при сохранении.\n";
                break;
            case 4:
                if (db.load_from_file(filename)) cout << "Загружено из файла.\n";
                else cout << "Ошибка при загрузке.\n";
                break;
            case 5: {
                auto addresses = db.get_addresses_last_3_days();
                cout << "Адреса за 3 дня:\n";
                for (const auto &addr : addresses) cout << "- " << addr << endl;
                break;
            }
            case 6: {
                string work;
                cout << "Введите название работы: ";
                getline(cin, work);
                auto clients = db.get_clients_for_work_last_week(work);
                cout << "Клиенты:\n";
                for (const auto &c : clients) cout << "- " << c << endl;
                break;
            }
            case 7: {
                string start, end;
                cout << "Начало периода (ГГГГ-ММ-ДД): "; getline(cin, start);
                cout << "Конец периода (ГГГГ-ММ-ДД): "; getline(cin, end);
                int count = db.get_client_count_for_period(start, end);
                cout << "Уникальных клиентов: " << count << endl;
                break;
            }
            default:
                cout << "Неверный выбор. Попробуйте снова.\n";
        }
    }

    cout << "Выход...\n";
    return 0;
}