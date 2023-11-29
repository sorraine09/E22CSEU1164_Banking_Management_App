#include <chrono>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/prepared_statement.h>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <stack>
#include <vector>


using namespace std;

struct Node {
  string data;
  Node *next;
};
class LinkedList {
  Node *head;
  Node *tail;
  int size;

public:
  LinkedList() {
    head = nullptr;
    tail = nullptr;
    size = 0;
  }
  void addLast(string value) {
    Node *temp = new Node();
    temp->data = value;
    temp->next = nullptr;
    if(size == 0) {
      head = tail = temp;
    }
    else {
      tail->next = temp;
      tail = temp;
    }
    size++;
  }
  void display() {
    Node *temp = head;
    while(temp != nullptr) {
      cout << temp->data;
      temp = temp->next;
    }
    cout << endl;
  }
  string getAt(int idx) {
    if(size == 0) {
      cout << "List is empty" << endl;
      return "-1";
    }
    else if(idx == 0 || idx >= size) {
      cout << "Invalid arguments";
      return "-1";
    }
    else {
      Node *temp = head;
      for(int i = 0; i < idx; i++) {
        temp = temp->next;
      }
      return temp->data;
    }
  }
};

const string server = "tcp://127.0.0.1:3306";
const string username = "root";
const string password = "oneaboveall";
string currentAccountNumber = "";

void setCurrentAccountNumber(const string &accNumber) {
  currentAccountNumber = accNumber;
}

string getCurrentAccountNumber() {
  return currentAccountNumber;
}

void resetSession() {
  currentAccountNumber = "";
}


bool isAllDigits(const string &str) {
  return all_of(str.begin(), str.end(), ::isdigit);
}

bool isValidAccountNumberTransfer(sql::Connection *con, const string &accountNumber) {
  sql::PreparedStatement *pstmt = con->prepareStatement("SELECT Account_No FROM user_account WHERE Account_No = ?");
  pstmt->setString(1, accountNumber);

  sql::ResultSet *res = pstmt->executeQuery();

  return res->next();
}

string getCardNumberForAccountNumber(sql::Connection *con, const string &accountNumber) {
  sql::PreparedStatement *pstmt = con->prepareStatement("SELECT Card_Number FROM card_details WHERE Account_No = ?");
  pstmt->setString(1, accountNumber);

  sql::ResultSet *res = pstmt->executeQuery();

  if(res->next()) {
    return res->getString("Card_Number");
  }

  return "";
}


bool hasSufficientBalance(sql::Connection *con, const string &cardNumber, const string &amount) {
  sql::PreparedStatement *pstmt = con->prepareStatement("SELECT Balance FROM card_details WHERE Card_Number = ?");
  pstmt->setString(1, cardNumber);

  sql::ResultSet *res = pstmt->executeQuery();

  if(res->next()) {
    string balanceStr = res->getString("Balance");

    // Convert the balance to an integer
    int balance = stoi(balanceStr);

    // Check if the balance is sufficient
    return balance >= stoi(amount);
  }

  return false;
}


bool transferFunds(sql::Connection *con, const string &senderCardNumber, const string &recipientAccountNumber, const string &amount) {

  sql::PreparedStatement *pstmtSender = con->prepareStatement("SELECT Balance FROM card_details WHERE Card_Number = ?");
  pstmtSender->setString(1, senderCardNumber);

  sql::ResultSet *resSender = pstmtSender->executeQuery();

  if(resSender->next()) {
    string senderBalance = resSender->getString("Balance");

    int intSenderBalance = stoi(senderBalance);

    int newSenderBalance = intSenderBalance - stoi(amount);

    if(newSenderBalance < 0) {
      return false;
    }

    sql::PreparedStatement *pstmtUpdateSender = con->prepareStatement("UPDATE card_details SET Balance = ? WHERE Card_Number = ?");
    pstmtUpdateSender->setString(1, to_string(newSenderBalance));
    pstmtUpdateSender->setString(2, senderCardNumber);
    pstmtUpdateSender->executeUpdate();

    string recipientCardNumber = getCardNumberForAccountNumber(con, recipientAccountNumber);

    sql::PreparedStatement *pstmtRecipient = con->prepareStatement("SELECT Balance FROM card_details WHERE Card_Number = ?");
    pstmtRecipient->setString(1, recipientCardNumber);

    sql::ResultSet *resRecipient = pstmtRecipient->executeQuery();

    if(resRecipient->next()) {
      string recipientBalance = resRecipient->getString("Balance");

      int intRecipientBalance = stoi(recipientBalance);
      int newRecipientBalance = intRecipientBalance + stoi(amount);

      sql::PreparedStatement *pstmtUpdateRecipient = con->prepareStatement("UPDATE card_details SET Balance = ? WHERE Card_Number = ?");
      pstmtUpdateRecipient->setString(1, to_string(newRecipientBalance));
      pstmtUpdateRecipient->setString(2, recipientCardNumber);
      pstmtUpdateRecipient->executeUpdate();

      return true;
    }
  }

  return false;
}

void inquireTransferDetails(sql::Connection *con, const string &accountNumber) {
  try {
    // Prepare and execute a SQL query to retrieve transfer details
    sql::PreparedStatement *pstmt = con->prepareStatement(
        "SELECT transaction_id, payee_account_number, beneficiary_account_number, amount, date_time FROM Transaction_Details WHERE payee_account_number = ? ");
    pstmt->setString(1, accountNumber);

    sql::ResultSet *res = pstmt->executeQuery();

    // Check if there are any transfer details
    if(res->next()) {
      // Display header
      cout << "Transfer Details:" << endl;
      cout << setw(15) << "Transaction ID" << setw(20) << "Payee Account" << setw(25) << "Beneficiary Account" << setw(15) << "Amount" << setw(25) << "Transaction Date" << endl;
      cout << setfill('-') << setw(85) << "" << setfill(' ') << endl;

      // Loop through results and display each transfer detail
      do {
        cout << setw(15) << res->getString("transaction_id")
             << setw(20) << res->getString("payee_account_number")
             << setw(25) << res->getString("beneficiary_account_number")
             << setw(15) << "Rs." << res->getString("amount")
             << setw(25) << res->getString("date_time") << endl;
      } while(res->next());
      cout << endl;
    }
    else {
      cout << "No transfer details found for the account." << endl;
    }

    // Clean up
    delete pstmt;
    delete res;
  }
  catch(const sql::SQLException &e) {
    cerr << "SQL Error: " << e.what() << endl;
  }
}


long long generateRandomTransactionId() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<long long> distribution(10000000000000, 99999999999999);

  return distribution(gen);
}

void insertTransferDetails(sql::Connection *con, const string &transaction_id_string, const string &payeeAccountNumber, const string &beneficiaryAccountNumber, const string &amount) {
  try {
    // Prepare and execute a SQL query to insert transfer details
    sql::PreparedStatement *pstmt = con->prepareStatement(
        "INSERT INTO Transaction_Details (transaction_id,payee_account_number, beneficiary_account_number, amount, date_time) "
        "VALUES (?, ?, ?, ?, NOW())");
    pstmt->setString(1, transaction_id_string);
    pstmt->setString(2, payeeAccountNumber);
    pstmt->setString(3, beneficiaryAccountNumber);
    pstmt->setString(4, amount);

    pstmt->execute();
    delete pstmt;

    cout << "Transfer details successfully recorded." << endl;
  }
  catch(const sql::SQLException &e) {
    cerr << "SQL Error: " << e.what() << endl;
  }
}


bool isReceiverCardNumberPresent(sql::Connection *con, const std::string &receiverCardNumber) {
  try {
    sql::PreparedStatement *pstmt = con->prepareStatement("SELECT COUNT(*) AS count FROM card_details WHERE Card_Number = ?");
    pstmt->setString(1, receiverCardNumber);

    sql::ResultSet *res = pstmt->executeQuery();

    if(res->next()) {
      int count = res->getInt("count");
      return count > 0; // If count is greater than 0, the card number is present
    }

    // Error handling: Card number not found
    return false;
  }
  catch(const sql::SQLException &e) {
    std::cerr << "SQL Error: " << e.what() << std::endl;
    return false;
  }
}


bool useridf(sql::Connection *con, string userid) {
  bool flag = false;
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT user_id FROM LOGIN_DETAILS WHERE user_id='" + userid + "'");
  if(!res->next()) {
    flag = true;
  }
  return flag;
}

bool isValidLogin(sql::Connection *con, string userid, string pass) {
  sql::PreparedStatement *pstmt = con->prepareStatement("SELECT user_id, pass, account_no FROM LOGIN_DETAILS");
  sql::ResultSet *res = pstmt->executeQuery();

  while(res->next()) {
    string fetchedUserID = res->getString("user_id");
    string fetchedPassword = res->getString("pass");

    if(userid == fetchedUserID && pass == fetchedPassword) {
      setCurrentAccountNumber(res->getString("account_no"));
      delete res;
      delete pstmt;
      return true; // Match found, login successful
    }
  }

  delete res;
  delete pstmt;
  return false; // No match found, login unsuccessful
}


string getAccountNumberForUserID(sql::Connection *con, const string &userid) {
  sql::PreparedStatement *pstmtv = con->prepareStatement("SELECT account_no FROM LOGIN_DETAILS WHERE user_id = ?");
  pstmtv->setString(1, userid);
  sql::ResultSet *res = pstmtv->executeQuery();

  if(res->next()) {
    string accountNumber = res->getString("account_no");
    delete res;
    delete pstmtv;
    return accountNumber;
  }

  delete res;
  delete pstmtv;
  return ""; // Return an empty string if no account number is found
}
bool passf(sql::Connection *con, string passw, string userid) {
  bool flag = false;
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT pass FROM LOGIN_DETAILS WHERE pass='" + passw + "'");
  if(!res->next()) {
    flag = true;
  }
  return flag;
}

// Function to check if card details were already generated for a given account number
bool hasCardDetails(sql::Connection *con, const string &accountnumber) {
  sql::PreparedStatement *pstmt = con->prepareStatement("SELECT * FROM card_details WHERE Account_No = ?");
  pstmt->setString(1, accountnumber);
  sql::ResultSet *res = pstmt->executeQuery();

  bool cardDetailsExist = res->next();

  delete res;
  delete pstmt;

  return cardDetailsExist;
}


bool account(sql::Connection *con, string accountnumber) {
  bool flag = false;
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT Account_No FROM user_account WHERE Account_No='" + accountnumber + "'");
  if(!res->next()) {
    flag = true;
  }
  return flag;
}

bool second_tables(sql::Connection *con, string accountnumber) {
  bool flag = true;
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT Account_No FROM card_details WHERE Account_No='" + accountnumber + "'");
  if(!res->next()) {
    flag = false;
  }
  return flag;
}

string generateUniqueCARDNumber(sql::Connection *con) {
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<long long> dis(1000000000000000, 9999999999999999);
  string cardNumber;
  bool cardExists = true;
  while(cardExists) {
    long long random = dis(gen);
    cardNumber = to_string(random);
    sql::Statement *stmt = con->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT Card_Number FROM card_details WHERE Card_Number = '" + cardNumber + "'");
    if(!res->next()) {
      cardExists = false;
    }
    delete res;
    delete stmt;
  }
  return cardNumber;
}


string generateUniqueSecretKey(int length) {
  string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  string secretKey = "";
  for(int i = 0; i < length; ++i) {
    secretKey += charset[rand() % charset.length()];
  }
  return secretKey;
}

string generateTOTP(const string &secretKey) {
  // Use the current time as a seed for the TOTP
  auto now = chrono::system_clock::now();
  auto seconds = chrono::time_point_cast<chrono::seconds>(now);
  auto value = seconds.time_since_epoch().count();

  // Convert the secret key to a C-string
  const char *key = secretKey.c_str();

  // Convert the value to a C-string
  unsigned char text[8];
  text[0] = (value >> 56) & 0xFF;
  text[1] = (value >> 48) & 0xFF;
  text[2] = (value >> 40) & 0xFF;
  text[3] = (value >> 32) & 0xFF;
  text[4] = (value >> 24) & 0xFF;
  text[5] = (value >> 16) & 0xFF;
  text[6] = (value >> 8) & 0xFF;
  text[7] = value & 0xFF;

  // Use HMAC-SHA1 to generate TOTP
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len;
  HMAC(EVP_sha1(), key, static_cast<int>(secretKey.length()), text, sizeof(text), result, &result_len);

  // Extract a 6-digit OTP from the result
  int offset = result[result_len - 1] & 0xF;
  int binary = ((result[offset] & 0x7F) << 24) | ((result[offset + 1] & 0xFF) << 16) | ((result[offset + 2] & 0xFF) << 8) | (result[offset + 3] & 0xFF);
  int otp = binary % 1000000;

  // Format the OTP to a 6-digit string
  ostringstream oss;
  oss << setw(6) << setfill('0') << otp;

  return oss.str();
}


string generateUniqueACCNumber(sql::Connection *con) {
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<long long> dis(10000000000000, 99999999999999);
  string accNumber;
  bool cardExists = true;
  while(cardExists) {
    long long random = dis(gen);
    accNumber = to_string(random);
    sql::Statement *stmt = con->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT Account_No FROM LOGIN_DETAILS WHERE Account_No = '" + accNumber + "'");
    if(!res->next()) {
      cardExists = false;
    }
    delete res;
    delete stmt;
  }
  return accNumber;
}


string generateUniqueUserID() {
  random_device rd;
  mt19937 gen(rd());

  // Generate random alphabetical characters
  uniform_int_distribution<int> alphaDist('A', 'Z');
  string alphabets;
  for(int i = 0; i < 5; ++i) {
    alphabets += static_cast<char>(alphaDist(gen));
  }

  // Generate random digits
  uniform_int_distribution<int> digitDist(0, 9);
  string digits;
  for(int i = 0; i < 5; ++i) {
    digits += to_string(digitDist(gen));
  }

  return alphabets + digits;
}

string generateRandomPassword(int length) {
  random_device rd;
  mt19937 gen(rd());

  // Define character sets
  const string uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const string lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
  const string digitChars = "0123456789";
  const string specialChars = "!@#$%^&*()_-+=<>?";

  // Combine all character sets
  const string allChars = uppercaseChars + lowercaseChars + digitChars + specialChars;

  // Initialize distributions
  uniform_int_distribution<int> charDist(0, allChars.size() - 1);

  // Generate password
  string password;
  for(int i = 0; i < length; ++i) {
    password += allChars[charDist(gen)];
  }

  return password;
}


string generateCVVNumber() {
  random_device rd;
  mt19937 gen(rd());
  uniform_int_distribution<int> distrib(100, 999);
  int random_number = distrib(gen);
  return to_string(random_number);
}

// This function computes the SHA - 256 hash of the input string and returns it as a hexadecimal string.

string sha256(const string &input) {
  EVP_MD_CTX *mdctx;                   // A context for managing the hashing process.
  const EVP_MD *md;                    // A pointer to the SHA-256 hash algorithm.
  unsigned char hash[EVP_MAX_MD_SIZE]; // An array to store the binary hash result.
  unsigned int hash_len;               // The length of the binary hash in bytes.

  // Initialize OpenSSL's hash algorithms.
  OpenSSL_add_all_digests();

  // Get the SHA-256 hash algorithm.
  md = EVP_get_digestbyname("sha256");
  if(!md) {
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
  char *hexHash = new char[2 * hash_len + 1];

  // Add a null terminator at the end of the hexadecimal string.
  hexHash[2 * hash_len] = 0;

  // Convert the binary hash to a hexadecimal string.
  for(unsigned int i = 0; i < hash_len; i++) {
    // Format each byte of the hash as a two-character hexadecimal value.
    snprintf(hexHash + 2 * i, 3, "%02x", hash[i]);
  }

  // Clean up OpenSSL resources.
  EVP_cleanup();

  // Return the hexadecimal hash as a string.
  return hexHash;
}

void insertCardDetails(sql::Connection *con, string accountnumber, string card, string hashedCVV, string balance) {
  string firstName, lastName;
  try {
    sql::Statement *stmt = con->createStatement();
    sql::ResultSet *res = stmt->executeQuery("SELECT First_Name, Last_Name FROM user_account WHERE Account_No = '" + accountnumber + "'");
    if(res->next()) {
      firstName = res->getString("First_Name");
      lastName = res->getString("Last_Name");
    }
    delete res;

    sql::PreparedStatement *pstmtm = con->prepareStatement("INSERT INTO card_details(Account_No, CVV, Card_Number, Balance, Full_Name) VALUES (?, ?, ?, ?, ?)");
    pstmtm->setString(1, accountnumber);
    pstmtm->setString(2, hashedCVV); // Store the hashed CVV in the database
    pstmtm->setString(3, card);
    pstmtm->setString(4, balance);
    pstmtm->setString(5, firstName + " " + lastName);
    int rowsAffected = pstmtm->executeUpdate();

    if(rowsAffected > 0) {
      cout << "Card details inserted successfully." << endl;
    }
    else {
      cout << "Failed to insert card details." << endl;
    }
  }
  catch(sql::SQLException &e) {
    cout << "SQL Error: " << e.what() << endl;
  }
}

bool checking_cardnumber(sql::Connection *con, string cardnumber) {
  bool flag = false;
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT Card_Number FROM card_details WHERE Card_Number='" + cardnumber + "'");
  if(!res->next()) {
    flag = true;
  }
  return flag;
}
bool checking_cvvnumber(sql::Connection *con, string cvv) {
  bool flag = false;
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT CVV FROM card_details WHERE CVV='" + cvv + "'");
  if(!res->next()) {
    flag = true;
  }
  return flag;
}
string retrieving_data(sql::Connection *con, string cardno) {
  sql::Statement *stmt = con->createStatement();
  sql::ResultSet *res = stmt->executeQuery("SELECT Balance from card_details where  Card_Number='" + cardno + "'");
  string resultstring;
  if(res->next()) {
    resultstring = res->getString(1);
  }
  return resultstring;
}
void update_balance(sql::Connection *con, string cardno, string balance) {
  try {
    sql::PreparedStatement *prep_stmt;
    prep_stmt = con->prepareStatement("UPDATE card_details SET Balance = ? WHERE Card_Number = ?");
    prep_stmt->setString(1, balance);
    prep_stmt->setString(2, cardno);
    prep_stmt->executeUpdate();

    delete prep_stmt;
    std::cout << "Amount updated successfully." << std::endl;
  }
  catch(sql::SQLException &e) {
    std::cout << "SQL Exception: " << e.what() << std::endl;
  }
}

vector<vector<string>> resultSetToArray(sql::ResultSet *resultSet) {
  vector<vector<string>> resultArray;

  int columnCount = resultSet->getMetaData()->getColumnCount();

  while(resultSet->next()) {
    vector<string> rowData;
    for(int i = 1; i <= columnCount; i++) {
      rowData.push_back(resultSet->getString(i)); // Add data from each column to the row vector
    }
    resultArray.push_back(rowData); // Add the row vector to the result array
  }

  return resultArray;
}
vector<string> twoDToOneD(const vector<vector<string>> &twoDVector) {
  vector<string> oneDVector;

  for(size_t i = 0; i < twoDVector.size(); i++) {
    for(size_t j = 0; j < twoDVector[i].size(); j++) {
      oneDVector.push_back(twoDVector[i][j]);
    }
  }

  return oneDVector;
}

bool isValidPanNumber(string pan) {
  if(pan.length() != 10) {
    return false;
  }
  for(int i = 0; i < 6; ++i) {
    if(!isalpha(pan[i])) {
      return false;
    }
  }
  for(int i = 6; i < 9; ++i) {
    if(!isdigit(pan[i])) {
      return false;
    }
  }
  if(!isalpha(pan[9])) {
    return false;
  }
  return true;
}

int main() {
  srand(static_cast<unsigned>(time(0)));

  cout << "                                 - - - - - - - - - - - |  Secure Transact  | - - - - - - - - - - -                             ";
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


  sql::Driver *driver;
  sql::Connection *con;
  sql::PreparedStatement *pstmt;
  sql::PreparedStatement *pstmtm;
  sql::PreparedStatement *pstmtmm;

  try {
    driver = get_driver_instance();
    con = driver->connect(server, username, password);
    con->setSchema("cpp_project");
    pstmt = con->prepareStatement("INSERT INTO user_account(adhaar_no, First_Name, last_name, pan_no, date_of_birth, phone_no, email_id, address, account_no) VALUES(?,?,?,?,?,?,?,?,?)");
    pstmtm = con->prepareStatement("INSERT INTO card_details(Account_No,CVV,Card_Number) VALUES(?,?,?)");
    pstmtmm = con->prepareStatement("INSERT INTO LOGIN_DETAILS(account_no,user_id,pass) VALUES(?,?,?)");
  }
  catch(sql::SQLException &e) {
    cout << "Could not connect to the server. Error code: " << e.getErrorCode() << endl;
    cout << "SQL State: " << e.getSQLState() << endl;
    cout << "Error message: " << e.what() << endl;
    system("pause");
    exit(1);
  }

  while(true) {

    cout << "Please Press: " << endl;
    cout << "1 - To create a new account" << endl;
    cout << "2 - If you are an existing User" << endl;
    cout << "3 - EXIT" << endl;
    cout << "- - - - - - - - - - - - - - - - - - - - - - - -  Please choose a valid option - - - - - - - - - - - - - - - - - - - - -  " << endl;
    int option;
    cin >> option;

    if(option == 1) {
      string aadhar_no, first_name, last_name, pan_number, dob, Phone_Number, email_id, address;
      cout << "Please enter your UIDAI issued 12-digit AADHAAR Number: ";
      cin >> aadhar_no;

      bool containsNonDigits = true;
      for(char c : aadhar_no) {
        if(isalpha(c)) {
          containsNonDigits = false;
          break;
        }
      }
      if(aadhar_no.length() != 12 || containsNonDigits == false) {
        cout << "Invalid Aadhar Number . It should be 12-digit long and should not contain any alphabets." << endl;
        cout << "  " << endl;
        continue;
      }
      user_aadhar_no.push(aadhar_no);

      cout << "Please enter your First Name: ";
      cin >> first_name;
      user_first_name.push(first_name);

      cout << "Please enter your Last Name: ";
      cin >> last_name;
      user_last_name.push(last_name);

      cout << "Please enter your I.T. Department issued 10-character PAN Number: ";
      cin >> pan_number;
      if(!isValidPanNumber(pan_number)) {
        cout << "Invalid PAN number !" << endl;
        cout << "  " << endl;
        continue;
      }
      user_pan_no.push(pan_number);

      cout << "Please enter your Date-of-Birth (in the format dd-mm-yyyy): ";
      cin >> dob;
      user_dob.push(dob);
      cout << "Please enter your Phone Number: ";
      cin >> Phone_Number;
      user_phone_no.push(Phone_Number);
      if(Phone_Number.length() != 10) {
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
      string userid = generateUniqueUserID();
      string pass = generateRandomPassword(10);


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

      pstmtmm->setString(1, accountNumber);
      pstmtmm->setString(2, userid);
      pstmtmm->setString(3, pass);
      pstmtmm->execute();

      cout << "Account created successfully with account number: " << accountNumber << "  User ID: " << userid << " Password: " << pass << endl;
      cout << "PLEASE NOTE DOWN YOUR UserID and Password FOR FUTURE USE AND DONOT SHARE IT WITH ANYONE. ";
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
    else if(option == 2) {
      string userid;
      cout << "Please enter your UserID to login: ";
      cin >> userid;
      string pass;
      cout << "Please enter your Password to login: ";
      cin >> pass;
      if(isValidLogin(con, userid, pass)) {
        cout << "Login successful!" << endl;
        setCurrentAccountNumber(getAccountNumberForUserID(con, userid));

        // string secret_key = generateUniqueSecretKey(con, 14);

        string sessionSecretKey = generateUniqueSecretKey(14);

        // string hashedsecret_key = sha256(secret_key);

        while(true) {
          cout << "Please Press: " << endl;
          cout << "1 - To generate payment card details" << endl;
          cout << "2 - To enquire about your balance" << endl;
          cout << "3 - To deposit in your account" << endl;
          cout << "4 - To withdraw from your account " << endl;
          cout << "5 - To transfer funds from your account to another account " << endl;
          cout << "6 - To enquire about transfer details " << endl;
          cout << "7 - To logout" << endl;
          cout << "8 - EXIT" << endl;
          int op;
          cin >> op;
          // ...

          if(op == 1) {
            // Check if card details were already generated for the current session's account number
            if(hasCardDetails(con, getCurrentAccountNumber())) {
              cout << "CAUTION: This account number has already generated card details previously." << endl;
              cout << "" << endl;
            }
            else {
              string balance = "0";
              string card = generateUniqueCARDNumber(con);
              string cvv = generateCVVNumber();
              cout << "Your unique 16-digit Card Number: " << card << endl;
              cout << "Your CVV Number: " << cvv << endl;
              cout << " " << endl;
              string hashedCVV = sha256(cvv);

              // Use the current session's account number
              insertCardDetails(con, getCurrentAccountNumber(), card, hashedCVV, balance);
              cout << "Please note down your unique 3-digit CVV for future transactions." << endl;
              cout << "CAUTION: Please don't disclose it to any other individual" << endl;
              cout << "" << endl;
            }
          }

          else if(op == 2) {
            cout << "Please enter your unique 16-digit Card Number: ";
            string cardnumber;
            cin >> cardnumber;
            bool var = checking_cardnumber(con, cardnumber);
            if(var == 1) {
              cout << "Please enter a valid Card Number" << endl;
              continue;
            }
            else if(var == 0) {
              sql::Statement *stmt = con->createStatement();
              sql::ResultSet *res = stmt->executeQuery("SELECT * FROM card_details WHERE Card_Number='" + cardnumber + "'");
              vector<vector<string>> resultset = resultSetToArray(res);
              vector<string> oned = twoDToOneD(resultset);
              LinkedList s;
              for(auto val : oned) {
                s.addLast(val);
              }
              string cvv_code = s.getAt(1);
              cout << "Please enter your CVV: ";
              string cvv_enquiry;

              cin >> cvv_enquiry;

              string hashedCVV_enquiry = sha256(cvv_enquiry);
              if(hashedCVV_enquiry == cvv_code) {
                cout << "The available balance is: Rs.";
                string bal = s.getAt(2);
                cout << bal;
                continue;
              }
              else {
                cout << "Please enter correct CVV." << endl;
                cout << " " << endl;
                continue;
              }
              continue;
            }
          }
          else if(op == 3) {
            cout << "PLease enter your unique 16-digit Card Number: ";
            string cardnum;
            cin >> cardnum;
            bool flag = checking_cardnumber(con, cardnum);
            cout << "Please enter your CVV: ";
            string cvv_deposit;
            cin >> cvv_deposit;
            string hashed_CVV_deposit = sha256(cvv_deposit);
            bool flag4 = checking_cvvnumber(con, hashed_CVV_deposit);
            if(flag == false && flag4 == false) {
              string balance;
              cout << "Enter the amount you want to deposit: Rs.";
              cin >> balance;
              if(stoi(balance) > 0) {
                string org_balance = retrieving_data(con, cardnum);
                int original = stoi(org_balance);
                int new1 = stoi(balance);
                int replace_amount = original + new1;
                string replace = to_string(replace_amount);
                update_balance(con, cardnum, replace);
                cout << "You have made a successful deposit of: Rs." << replace << endl;
              }
              else if(stoi(balance) == 0) {
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
          else if(op == 4) {
            cout << "PLease enter your unique 16-digit Card Number: ";
            string cardnum_withdraw;
            cin >> cardnum_withdraw;
            bool flag = checking_cardnumber(con, cardnum_withdraw);
            cout << "Please enter your CVV: ";
            string cvv_withdraw;
            cin >> cvv_withdraw;
            string hashed_CVV_withdraw = sha256(cvv_withdraw);
            bool flag4 = checking_cvvnumber(con, hashed_CVV_withdraw);
            if(flag == false && flag4 == false) {
              string balance;
              cout << "Enter the amount you want to withdraw: Rs.";
              cin >> balance;
              if(stoi(balance) > 0) {
                string org_balance = retrieving_data(con, cardnum_withdraw);
                int original = stoi(org_balance);
                int new1 = stoi(balance);
                int replace_amount = original - new1;
                if(replace_amount > 0) {
                  string replace = to_string(replace_amount);
                  update_balance(con, cardnum_withdraw, replace);
                  cout << "You have made a successful deposit of: Rs." << replace << endl;
                }
                else {
                  cout << "Insufficient Bank Balance ! " << endl;
                  return 0;
                }
              }
              else if(stoi(balance) == 0) {
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
          else if(op == 5) {
            cout << "Please enter the beneficiary's 14-digit account number : ";
            string recipientAccountNumber;
            cin >> recipientAccountNumber;
            bool flag_receiverCardNumber = isReceiverCardNumberPresent(con, recipientAccountNumber);
            if(flag_receiverCardNumber == false) {
              if(recipientAccountNumber.length() == 14 && isAllDigits(recipientAccountNumber)) {
                if(isValidAccountNumberTransfer(con, recipientAccountNumber)) {
                  string amount;
                  cout << "Enter the amount you want to transfer: Rs.";
                  cin >> amount;
                  if(stoi(amount) > 0) {
                    string senderCardNumber = getCardNumberForAccountNumber(con, getCurrentAccountNumber());
                    if(hasSufficientBalance(con, senderCardNumber, amount)) {
                      string sessionTOTP = generateTOTP(sessionSecretKey);
                      cout << "This is the OTP: " << sessionTOTP << endl;
                      auto otpStartTime = chrono::system_clock::now();
                      const int otpTimeLimitSeconds = 20;
                      cout << "Enter your OTP within " << otpTimeLimitSeconds << " seconds (First 3 digits should be your CVV, then type your OTP): ";
                      string userTOTP;
                      cin >> userTOTP;
                      string cvv = userTOTP.substr(0, 3);
                      string hash_cvv_transfer = sha256(cvv);
                      bool check_cvv_transfer = checking_cvvnumber(con, hash_cvv_transfer);
                      string restTOTP = userTOTP.substr(3);
                      auto otpEndTime = chrono::system_clock::now();
                      chrono::duration<double> elapsedSeconds = otpEndTime - otpStartTime;
                      if(elapsedSeconds.count() <= otpTimeLimitSeconds) {
                        if(sessionTOTP == restTOTP && check_cvv_transfer == false) {
                          if(transferFunds(con, senderCardNumber, recipientAccountNumber, amount)) {
                            long long transactionId = generateRandomTransactionId();
                            string transactionIdString = to_string(transactionId);
                            insertTransferDetails(con, transactionIdString, getCurrentAccountNumber(), recipientAccountNumber, amount);
                            cout << "Funds transfer successful!" << endl;
                            continue;
                          }
                          else {
                            cout << "Error transferring funds. Please try again later." << endl;
                            continue;
                          }
                        }
                        else {
                          while(true) {
                            cout << "Invalid OTP" << endl;
                            cout << "Please Press: " << endl;
                            cout << "1 - Regenerate OTP" << endl;
                            cout << "2 - Back to Main Menu" << endl;
                            int otpOption;
                            cin >> otpOption;
                            if(otpOption == 1) {
                              string sessionTOTP = generateTOTP(sessionSecretKey);
                              cout << "This is the OTP: " << sessionTOTP << endl;
                              auto otpStartTime = chrono::system_clock::now();
                              const int otpTimeLimitSeconds = 20;
                              cout << "Enter your OTP within " << otpTimeLimitSeconds << " seconds (First 3 digits should be your CVV, then type your OTP): ";
                              string userTOTP;
                              cin >> userTOTP;
                              string cvv = userTOTP.substr(0, 3);
                              string hash_cvv_transfer = sha256(cvv);
                              bool check_cvv_transfer = checking_cvvnumber(con, hash_cvv_transfer);
                              string restTOTP = userTOTP.substr(3);
                              auto otpEndTime = chrono::system_clock::now();
                              chrono::duration<double> elapsedSeconds = otpEndTime - otpStartTime;
                              if(elapsedSeconds.count() <= otpTimeLimitSeconds) {
                                if(sessionTOTP == restTOTP && check_cvv_transfer == false) {
                                  if(transferFunds(con, senderCardNumber, recipientAccountNumber, amount)) {
                                    long long transactionId = generateRandomTransactionId();
                                    string transactionIdString = to_string(transactionId);
                                    insertTransferDetails(con, transactionIdString, getCurrentAccountNumber(), recipientAccountNumber, amount);
                                    cout << "Funds transfer successful!" << endl;
                                    break;
                                  }
                                  else {
                                    cout << "Error transferring funds. Please try again later." << endl;
                                    continue;
                                  }
                                }
                                else {
                                  cout << "Time limit exceeded for OTP entry. Returning to the main menu." << endl;
                                }
                              }
                            }
                            else if(otpOption == 2) {
                              cout << "Returning to the main menu." << endl;
                              break;
                            }
                            else {
                              cout << "Invalid option. Returning to the main menu." << endl;
                              break;
                            }
                          }
                        }
                      }
                      else {
                        cout << "Time limit exceeded for OTP entry. Returning to the main menu." << endl;
                        while(true) {
                          cout << "Invalid OTP" << endl;
                          cout << "Please Press: " << endl;
                          cout << "1 - Regenerate OTP" << endl;
                          cout << "2 - Back to Main Menu" << endl;
                          int otpOption;
                          cin >> otpOption;
                          if(otpOption == 1) {
                            string sessionTOTP = generateTOTP(sessionSecretKey);
                            cout << "This is the OTP: " << sessionTOTP << endl;
                            auto otpStartTime = chrono::system_clock::now();
                            const int otpTimeLimitSeconds = 20;
                            cout << "Enter your OTP within " << otpTimeLimitSeconds << " seconds (First 3 digits should be your CVV, then type your OTP): ";
                            string userTOTP;
                            cin >> userTOTP;
                            string cvv = userTOTP.substr(0, 3);
                            string hash_cvv_transfer = sha256(cvv);
                            bool check_cvv_transfer = checking_cvvnumber(con, hash_cvv_transfer);
                            string restTOTP = userTOTP.substr(3);
                            auto otpEndTime = chrono::system_clock::now();
                            chrono::duration<double> elapsedSeconds = otpEndTime - otpStartTime;
                            if(elapsedSeconds.count() <= otpTimeLimitSeconds) {
                              if(sessionTOTP == restTOTP && check_cvv_transfer == false) {
                                if(transferFunds(con, senderCardNumber, recipientAccountNumber, amount)) {
                                  long long transactionId = generateRandomTransactionId();
                                  string transactionIdString = to_string(transactionId);
                                  insertTransferDetails(con, transactionIdString, getCurrentAccountNumber(), recipientAccountNumber, amount);
                                  cout << "Funds transfer successful!" << endl;
                                  break;
                                }
                                else {
                                  cout << "Error transferring funds. Please try again later." << endl;
                                  continue;
                                }
                              }
                              else {
                                cout << "Time limit exceeded for OTP entry. Returning to the main menu." << endl;
                              }
                            }
                          }
                          else if(otpOption == 2) {
                            cout << "Returning to the main menu." << endl;
                            break;
                          }
                          else {
                            cout << "Invalid option. Returning to the main menu." << endl;
                            break;
                          }
                        }
                      }
                    }
                    else {
                      cout << "Insufficient balance for funds transfer!" << endl;
                      continue;
                    }
                  }
                  else {
                    cout << "Please enter a valid amount." << endl;
                    continue;
                  }
                }
                else {
                  cout << "Invalid recipient account number." << endl;
                  continue;
                }
              }
              else {
                cout << "Invalid account number format . Please enter a 14-digit number." << endl;
                continue;
              }
            }
            else {
              cout << "This beneficiary account has not generated card details, hence transfer cannnot be made" << endl;
            }
          }
          else if(op == 6) {
            inquireTransferDetails(con, getCurrentAccountNumber());
            continue;
          }
          else if(op == 7) {
            resetSession();
            cout << "Logged out successfully." << endl;
            break;
          }
          else if(op == 8) {
            return 0;
          }
        }
      }
      else {
        cout << " INVALID LOGIN CREDENTIALS ! " << endl;
      }
    }
    else if(option == 3) {
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
