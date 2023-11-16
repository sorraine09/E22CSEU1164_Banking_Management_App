#include <iostream>
#include <vector>
#include <stack>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <random>
#include <openssl/sha.h>
#include <openssl/evp.h>

using namespace std;

struct Node {
    string data;
    Node* next;
};
class LinkedList {
    Node* head;
    Node* tail;
    int size;
public:
    LinkedList() {
        head = nullptr;
        tail = nullptr;
        size = 0;
    }void addLast(string value) {
        Node* temp = new Node();
        temp->data = value;
        temp->next = nullptr;
        if (size == 0) {
            head = tail = temp;
        }
        else {
            tail->next = temp;
            tail = temp;
        }size++;
    }void display() {
        Node* temp = head;
        while (temp != nullptr) {
            cout << temp->data;
            temp = temp->next;
        }cout << endl;
    }string getAt(int idx) {
        if (size == 0) {
            cout << "List is empty" << endl;
            return "-1";
        }
        else if (idx == 0 || idx >= size) {
            cout << "Invalid arguments";
            return "-1";
        }
        else {
            Node* temp = head;
            for (int i = 0; i < idx; i++) {
                temp = temp->next;
            }return temp->data;
        }
    }
};

const string server = "tcp://127.0.0.1:3306";
const string username = "root";
const string password = "oneaboveall";

bool account(sql::Connection* con, string accountnumber) {
    bool flag = false;
    sql::Statement* stmt = con->createStatement();
    sql::ResultSet* res = stmt->executeQuery("SELECT Account_No FROM user_account WHERE Account_No='" + accountnumber + "'");
    if (!res->next()) {
        flag = true;
    }
    return flag;
}

bool second_tables(sql::Connection* con, string accountnumber) {
    bool flag = true;
    sql::Statement* stmt = con->createStatement();
    sql::ResultSet* res = stmt->executeQuery("SELECT Account_No FROM card_details WHERE Account_No='" + accountnumber + "'");
    if (!res->next()) {
        flag = false;
    }
    return flag;
}

string generateUniqueCARDNumber(sql::Connection* con) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long long> dis(1000000000000000, 9999999999999999);
    string cardNumber;
    bool cardExists = true;
    while (cardExists) {
        long long random = dis(gen);
        cardNumber = to_string(random);
        sql::Statement* stmt = con->createStatement();
        sql::ResultSet* res = stmt->executeQuery("SELECT Card_Number FROM card_details WHERE Card_Number = '" + cardNumber + "'");
        if (!res->next()) {
            cardExists = false;
        }
        delete res;
        delete stmt;
    }
    return cardNumber;
}

string generateUniqueACCNumber(sql::Connection* con) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long long> dis(10000000000000, 99999999999999);
    string accNumber;
    bool cardExists = true;
    while (cardExists) {
        long long random = dis(gen);
        accNumber = to_string(random);
        sql::Statement* stmt = con->createStatement();
        sql::ResultSet* res = stmt->executeQuery("SELECT Account_No FROM card_details WHERE Account_No = '" + accNumber + "'");
        if (!res->next()) {
            cardExists = false;
        }
        delete res;
        delete stmt;
    }
    return accNumber;
}
string generateCVVNumber() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> distrib(100, 999);
    int random_number = distrib(gen);
    return to_string(random_number);
}

//This function computes the SHA - 256 hash of the input string and returns it as a hexadecimal string.

string sha256(const string& input) {
    EVP_MD_CTX* mdctx;  // A context for managing the hashing process.
    const EVP_MD* md;  // A pointer to the SHA-256 hash algorithm.
    unsigned char hash[EVP_MAX_MD_SIZE];  // An array to store the binary hash result.
    unsigned int hash_len;  // The length of the binary hash in bytes.

    // Initialize OpenSSL's hash algorithms.
    OpenSSL_add_all_digests();

    // Get the SHA-256 hash algorithm.
    md = EVP_get_digestbyname("sha256");
    if (!md) {
        // If SHA-256 is not available, print an error and return an empty string.
        cout << "Error: SHA-256 not available." << endl;
        return "";
    }

    // Create a new context for the hash operation.
    mdctx = EVP_MD_CTX_new();

    // Initialize the context with the SHA-256 algorithm.
    EVP_DigestInit_ex(mdctx, md, NULL);

    // Update the context with the binary data of the input string.
    EVP_DigestUpdate(mdctx, input.c_str(), input.size());

    // Finalize the hash calculation and store the result in the 'hash' array.
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);

    // Free the context to release resources.
    EVP_MD_CTX_free(mdctx);

    // Create a dynamic character array to store the hexadecimal representation of the hash.
    char* hexHash = new char[2 * hash_len + 1];

    // Add a null terminator at the end of the hexadecimal string.
    hexHash[2 * hash_len] = 0;

    // Convert the binary hash to a hexadecimal string.
    for (unsigned int i = 0; i < hash_len; i++) {
        // Format each byte of the hash as a two-character hexadecimal value.
        snprintf(hexHash + 2 * i, 3, "%02x", hash[i]);
    }

    // Clean up OpenSSL resources.
    EVP_cleanup();

    // Return the hexadecimal hash as a string.
    return hexHash;
}

void insertCardDetails(sql::Connection* con, string accountnumber, string card, string hashedCVV, string balance) {
    string firstName, lastName;
    try {
        sql::Statement* stmt = con->createStatement();
        sql::ResultSet* res = stmt->executeQuery("SELECT First_Name, Last_Name FROM user_account WHERE Account_No = '" + accountnumber + "'");
        if (res->next()) {
            firstName = res->getString("First_Name");
            lastName = res->getString("Last_Name");
        }
        delete res;

        sql::PreparedStatement* pstmtm = con->prepareStatement("INSERT INTO card_details(Account_No, CVV, Card_Number, Balance, Full_Name) VALUES (?, ?, ?, ?, ?)");
        pstmtm->setString(1, accountnumber);
        pstmtm->setString(2, hashedCVV);  // Store the hashed CVV in the database
        pstmtm->setString(3, card);
        pstmtm->setString(4, balance);
        pstmtm->setString(5, firstName + " " + lastName);
        int rowsAffected = pstmtm->executeUpdate();

        if (rowsAffected > 0) {
            cout << "Card details inserted successfully." << endl;
        }
        else {
            cout << "Failed to insert card details." << endl;
        }
    }
    catch (sql::SQLException& e) {
        cout << "SQL Error: " << e.what() << endl;
    }
}

bool checking_cardnumber(sql::Connection* con, string cardnumber) {
    bool flag = false;
    sql::Statement* stmt = con->createStatement();
    sql::ResultSet* res = stmt->executeQuery("SELECT Card_Number FROM card_details WHERE Card_Number='" + cardnumber + "'");
    if (!res->next()) {
        flag = true;
    }return flag;
}
bool checking_cvvnumber(sql::Connection* con, string cvv) {
    bool flag = false;
    sql::Statement* stmt = con->createStatement();
    sql::ResultSet* res = stmt->executeQuery("SELECT CVV FROM card_details WHERE CVV='" + cvv + "'");
    if (!res->next()) {
        flag = true;
    }return flag;
}
string retrieving_data(sql::Connection* con, string cardno) {
    sql::Statement* stmt = con->createStatement();
    sql::ResultSet* res = stmt->executeQuery("SELECT Balance from card_details where  Card_Number='" + cardno + "'");
    string resultstring;
    if (res->next()) {
        resultstring = res->getString(1);
    }return resultstring;
}
void update_balance(sql::Connection* con, string cardno, string balance) {
    try {
        sql::PreparedStatement* prep_stmt;
        prep_stmt = con->prepareStatement("UPDATE card_details SET Balance = ? WHERE Card_Number = ?");
        prep_stmt->setString(1, balance);
        prep_stmt->setString(2, cardno);
        prep_stmt->executeUpdate();

        delete prep_stmt;
        std::cout << "Amount updated successfully." << std::endl;
    }
    catch (sql::SQLException& e) {
        std::cout << "SQL Exception: " << e.what() << std::endl;
    }
}

vector<vector<string>> resultSetToArray(sql::ResultSet* resultSet) {
    vector<vector<string>> resultArray;

    int columnCount = resultSet->getMetaData()->getColumnCount();

    while (resultSet->next()) {
        vector<string> rowData;
        for (int i = 1; i <= columnCount; i++) {
            rowData.push_back(resultSet->getString(i)); // Add data from each column to the row vector
        }
        resultArray.push_back(rowData); // Add the row vector to the result array
    }

    return resultArray;
}
vector<string> twoDToOneD(const vector<vector<string>>& twoDVector) {
    vector<string> oneDVector;

    for (size_t i = 0; i < twoDVector.size(); i++) {
        for (size_t j = 0; j < twoDVector[i].size(); j++) {
            oneDVector.push_back(twoDVector[i][j]);
        }
    }

    return oneDVector;
}

bool isValidPanNumber(string pan) {
    if (pan.length() != 10) {
        return false;
    }
    for (int i = 0; i < 6; ++i) {
        if (!isalpha(pan[i])) {
            return false;
        }
    }
    for (int i = 6; i < 9; ++i) {
        if (!isdigit(pan[i])) {
            return false;
        }
    }
    if (!isalpha(pan[9])) {
        return false;
    }
    return true;
}

int main() {

    cout << "                                 - - - - - - - - - - - |  FIN SAFE  | - - - - - - - - - - -                             ";
    cout << "     " << endl;

    stack<string> user_aadhar_no;
    stack<string> user_first_name;
    stack<string> user_last_name;
    stack<string> user_pan_no;
    stack<string> user_dob;
    stack<string> user_phone_no;
    stack<string> user_email_id;
    stack<string> user_address;
    stack<string> generatedAccountNumbers;
    stack<string> user_card_number;
    stack<string> user_cvv_number;



    sql::Driver* driver;
    sql::Connection* con;
    sql::PreparedStatement* pstmt;
    sql::PreparedStatement* pstmtm;

    try {
        driver = get_driver_instance();
        con = driver->connect(server, username, password);
        con->setSchema("cpp_project");
        pstmt = con->prepareStatement("INSERT INTO user_account(adhaar_no, First_Name, last_name, pan_no, date_of_birth, phone_no, email_id, address, account_no) VALUES(?,?,?,?,?,?,?,?,?)");
        pstmtm = con->prepareStatement("INSERT INTO card_details(Account_No,CVV,Card_Number) VALUES(?,?,?)");
    }
    catch (sql::SQLException& e) {
        cout << "Could not connect to the server. Error code: " << e.getErrorCode() << endl;
        cout << "SQL State: " << e.getSQLState() << endl;
        cout << "Error message: " << e.what() << endl;
        system("pause");
        exit(1);
    }

    while (true) {

        cout << "Please Press: " << endl;
        cout << "1 - To create a new account" << endl;
        cout << "2 - If you are an existing User" << endl;
        cout << "3 - EXIT" << endl;
        cout << "- - - - - - - - - - - - - - - - - - - - - - - -  Please choose a valid option - - - - - - - - - - - - - - - - - - - - -  " << endl;
        int option;
        cin >> option;

        if (option == 1) {
            string aadhar_no, first_name, last_name, pan_number, dob, Phone_Number, email_id, address;
            cout << "Please enter your UIDAI issued 12-digit AADHAAR Number: ";
            cin >> aadhar_no;

            bool containsNonDigits = true;
            for (char c : aadhar_no) {
                if (isalpha(c)) {
                    containsNonDigits = false;
                    break;
                }
            }
            if (aadhar_no.length() != 12 || containsNonDigits == false) {
                cout << "Invalid Aadhar Number . It should be 12-digit long and should not contain any alphabets." << endl;
                cout << "  " << endl;
                continue;
            }user_aadhar_no.push(aadhar_no);

            cout << "Please enter your First Name: ";
            cin >> first_name;
            user_first_name.push(first_name);

            cout << "Please enter your Last Name: ";
            cin >> last_name;
            user_last_name.push(last_name);

            cout << "Please enter your I.T. Department issued 10-character PAN Number: ";
            cin >> pan_number;
            if (!isValidPanNumber(pan_number)) {
                cout << "Invalid PAN number !" << endl;
                cout << "  " << endl;
                continue;
            }user_pan_no.push(pan_number);

            cout << "Please enter your Date-of-Birth (in the format dd-mm-yyyy): ";
            cin >> dob;
            user_dob.push(dob);
            cout << "Please enter your Phone Number: ";
            cin >> Phone_Number;
            user_phone_no.push(Phone_Number);
            if (Phone_Number.length() != 10) {
                cout << "Invalid Phone number. It should be 10 digit long." << endl;
                cout << "  " << endl;
                continue;
            }
            cout << "Please enter your email id: ";
            cin >> email_id;
            user_email_id.push(email_id);
            cout << "Please enter your Address: ";
            cin >> address;
            user_address.push(address);
            string accountNumber = generateUniqueACCNumber(con);

            pstmt->setString(1, user_aadhar_no.top());
            pstmt->setString(2, user_first_name.top());
            pstmt->setString(3, user_last_name.top());
            pstmt->setString(4, user_pan_no.top());
            pstmt->setString(5, user_dob.top());
            pstmt->setString(6, user_phone_no.top());
            pstmt->setString(7, user_email_id.top());
            pstmt->setString(8, user_address.top());
            pstmt->setString(9, accountNumber);

            pstmt->execute();
            cout << "Account created successfully with account number: " << accountNumber << endl;
            cout << "    " << endl;

            user_aadhar_no.pop();
            user_first_name.pop();
            user_last_name.pop();
            user_pan_no.pop();
            user_dob.pop();
            user_phone_no.pop();
            user_email_id.pop();
            user_address.pop();
        }
        else if (option == 2) {
            while (true) {
                cout << "Please Press: " << endl;
                cout << "1 - To generate payment card details" << endl;
                cout << "2 - To enquire about your balance" << endl;
                cout << "3 - To deposit in your account" << endl;
                cout << "4 - To withdraw from your account " << endl;
                cout << "5 - EXIT" << endl;
                int op;
                cin >> op;
                if (op == 1) {
                    cout << "Please enter your 14-digit account number: ";
                    string accountnumber;
                    cin >> accountnumber;
                    bool flag3 = account(con, accountnumber);
                    bool flag2 = second_tables(con, accountnumber);
                    if (flag3 == false && flag2 == true) {
                        cout << " " << endl;
                        cout << "CAUTION: This account number has already generated card details previously. " << endl;
                        cout << "" << endl;
                        return 0;
                    }
                    else {
                        string balance = "0";
                        string card = generateUniqueCARDNumber(con);
                        string cvv = generateCVVNumber();
                        cout << "Your unique 16-digit Card Number: " << card << endl;
                        cout << "Your CVV Number: " << cvv << endl;
                        cout << " " << endl;
                        string hashedCVV = sha256(cvv);

                        insertCardDetails(con, accountnumber, card, hashedCVV, balance);
                        cout << "Please note down your unique 3-digit CVV for future transactions." << endl;
                        cout << "CAUTION: Please don't disclose it to any other individual" << endl;
                        cout << "" << endl;
                        return 0;
                    }
                }
                else if (op == 2) {
                    cout << "Please enter your unique 16-digit Card Number: ";
                    string cardnumber;
                    cin >> cardnumber;
                    bool var = checking_cardnumber(con, cardnumber);
                    if (var == 1) {
                        cout << "Please enter a valid Card Number" << endl;
                        continue;
                    }
                    else if (var == 0) {
                        sql::Statement* stmt = con->createStatement();
                        sql::ResultSet* res = stmt->executeQuery("SELECT * FROM card_details WHERE Card_Number='" + cardnumber + "'");
                        vector<vector<string>>resultset = resultSetToArray(res);
                        vector < string>oned = twoDToOneD(resultset);
                        LinkedList s;
                        for (auto val : oned) {
                            s.addLast(val);
                        }string cvv_code = s.getAt(1);
                        cout << "Please enter your CVV: ";
                        string cvv_enquiry;

                        cin >> cvv_enquiry;

                        string hashedCVV_enquiry = sha256(cvv_enquiry);
                        if (hashedCVV_enquiry == cvv_code) {
                            cout << "The available balance is: Rs.";
                            string bal = s.getAt(2);
                            cout << bal;
                            return 0;
                        }
                        else {
                            cout << "Please enter correct CVV." << endl;
                            cout << " " << endl;
                            continue;
                        }
                        continue;
                    }
                }
                else if (op == 3) {
                    cout << "PLease enter your unique 16-digit Card Number: ";
                    string cardnum;
                    cin >> cardnum;
                    bool flag = checking_cardnumber(con, cardnum);
                    cout << "Please enter your CVV: ";
                    string cvv_deposit;
                    cin >> cvv_deposit;
                    string hashed_CVV_deposit = sha256(cvv_deposit);
                    bool flag4 = checking_cvvnumber(con, hashed_CVV_deposit);
                    if (flag == false && flag4 == false) {
                        string balance;
                        cout << "Enter the amount you want to deposit: Rs.";
                        cin >> balance;
                        if (stoi(balance) > 0) {
                            string org_balance = retrieving_data(con, cardnum);
                            int original = stoi(org_balance);
                            int new1 = stoi(balance);
                            int replace_amount = original + new1;
                            string replace = to_string(replace_amount);
                            update_balance(con, cardnum, replace);
                            cout << "You have made a successful deposit of: Rs." << replace << endl;
                        }
                        else if (stoi(balance) == 0) {
                            cout << "Please enter a valid amount." << endl;
                            cout << "" << endl;
                            continue;
                        }
                        else {
                            cout << "Please enter a valid amount." << endl;
                            cout << "" << endl;
                            continue;
                        }
                    }
                    else {
                        cout << "Please enter your credentials correctly." << endl;
                        cout << "" << endl;
                        continue;
                    }
                }
                else if (op == 4) {
                    cout << "PLease enter your unique 16-digit Card Number: ";
                    string cardnum_withdraw;
                    cin >> cardnum_withdraw;
                    bool flag = checking_cardnumber(con, cardnum_withdraw);
                    cout << "Please enter your CVV: ";
                    string cvv_withdraw;
                    cin >> cvv_withdraw;
                    string hashed_CVV_withdraw = sha256(cvv_withdraw);
                    bool flag4 = checking_cvvnumber(con, hashed_CVV_withdraw);
                    if (flag == false && flag4 == false) {
                        string balance;
                        cout << "Enter the amount you want to withdraw: Rs.";
                        cin >> balance;
                        if (stoi(balance) > 0) {
                            string org_balance = retrieving_data(con, cardnum_withdraw);
                            int original = stoi(org_balance);
                            int new1 = stoi(balance);
                            int replace_amount = original - new1;
                            if (replace_amount > 0) {
                                string replace = to_string(replace_amount);
                                update_balance(con, cardnum_withdraw, replace);
                                cout << "You have made a successful deposit of: Rs." << replace << endl;
                            }
                            else {
                                cout << "Insufficient Bank Balance ! " << endl;
                                return 0;
                            }
                        }
                        else if (stoi(balance) == 0) {
                            cout << "Please enter a valid amount! " << endl;
                            continue;
                        }
                        else {
                            cout << "Please enter a valid amount." << endl;
                            continue;
                        }
                    }
                    else {
                        cout << "Please enter your credentials correctly." << endl;
                        continue;
                    }
                }
                else if (op == 5) {
                    return 0;
                }
            }

        }
        else if (option == 3) {
            return 0;
        }
        else {
            continue;
        }
    }

    delete pstmt;
    delete con;
    system("pause");
    return 0;
}