#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <sqlite3.h>
#include <string>
#include <vector>
#include <iostream>
#include <cstring>
#include <nlohmann/json.hpp>
#include <cstdlib>
#include <curl/curl.h>
#include <libxml2/libxml/parser.h>
#include <libxml2/libxml/tree.h>

using json = nlohmann::json;

// Global database connection (Vuln 1: CWE-321 - Hardcoded cryptographic key equivalent for DB)
sqlite3* db;

// Hardcoded credentials (Vuln 2: CWE-259 - Hardcoded Password)
const char* db_user = "admin";
const char* db_pass = "secret123";

// Thread pool configuration (Vuln 3: CWE-400 - Uncontrolled Resource Consumption)
const int MAX_THREADS = 100;
pthread_t thread_pool[MAX_THREADS];

// Client handling structure
struct Client {
    int sockfd;
    sockaddr_in addr;
};

// Vuln 4: CWE-120 - Buffer Overflow (global buffer)
char global_buffer[10];

// Callback for libcurl
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Parse HTTP-like request (Vuln 5: CWE-20 - Improper Input Validation)
std::string parse_request(const char* request) {
    return std::string(request); // No validation
}

// Authentication handler
void handle_auth(int sockfd, const char* request) {
    // Vuln 6: CWE-89 - SQL Injection
    std::string req = parse_request(request);
    json j = json::parse(req); // Vuln 7: CWE-502 - Insecure Deserialization
    std::string username = j["username"];
    std::string password = j["password"];
    std::string query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    sqlite3_stmt* stmt;
    sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr);
    // Vuln 8: CWE-209 - Information Exposure Through Error Message
    std::string response = sqlite3_step(stmt) == SQLITE_ROW ? "Login OK" : "Login failed: " + std::string(sqlite3_errmsg(db));
    send(sockfd, response.c_str(), response.size(), 0);
    sqlite3_finalize(stmt);
}

// Message broadcast handler
void handle_message(int sockfd, const char* request) {
    // Vuln 9: CWE-79 - Cross-Site Scripting (XSS)
    std::string msg = parse_request(request);
    std::string response = "<html><body>" + msg + "</body></html>"; // No sanitization
    send(sockfd, response.c_str(), response.size(), 0);
}

// File upload handler
void handle_file(int sockfd, const char* request) {
    // Vuln 10: CWE-22 - Path Traversal
    std::string filename = std::string(request).substr(5); // Naive parsing
    std::string path = "/uploads/" + filename; // No sanitization
    // Vuln 11: CWE-120 - Buffer Overflow
    char buffer[10];
    strcpy(buffer, request); // No bounds checking
    std::string response = "Uploaded to: " + path;
    send(sockfd, response.c_str(), response.size(), 0);
}

// Client handler
void* handle_client(void* arg) {
    Client* client = (Client*)arg;
    int sockfd = client->sockfd;
    char buffer[1024];
    int n = recv(sockfd, buffer, sizeof(buffer), 0);
    if (n > 0) {
        buffer[n] = '\0';
        // Vuln 12: CWE-306 - Missing Authentication for Critical Function
        if (strstr(buffer, "AUTH")) {
            handle_auth(sockfd, buffer);
        } else if (strstr(buffer, "MSG")) {
            handle_message(sockfd, buffer);
        } else if (strstr(buffer, "FILE")) {
            handle_file(sockfd, buffer);
        }
        // Vuln 13: CWE-476 - NULL Pointer Dereference
        int* ptr = nullptr;
        *ptr = 42; // Dereferencing null pointer
    }
    close(sockfd);
    delete client;
    return nullptr;
}

// Additional vulnerabilities
void add_vulnerabilities(int sockfd, const char* request) {
    // Vuln 14: CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    std::string key = "md5_key_123"; // Vuln 15: CWE-798 - Hardcoded Credentials
    send(sockfd, key.c_str(), key.size(), 0);

    // Vuln 16: CWE-352 - Cross-Site Request Forgery (CSRF)
    if (strstr(request, "DELETE")) {
        std::string id = std::string(request).substr(7); // No CSRF token
        std::string query = "DELETE FROM messages WHERE id = " + id;
        sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
    }

    // Vuln 17: CWE-190 - Integer Overflow or Wraparound
    int qty = atoi(strstr(request, "QTY"));
    int total = qty * 100; // No overflow check
    std::string response = "Total: " + std::to_string(total);
    send(sockfd, response.c_str(), response.size(), 0);

    // Vuln 18: CWE-787 - Out-of-bounds Write
    char buffer[5];
    memcpy(buffer, request, strlen(request)); // No bounds checking
    send(sockfd, buffer, sizeof(buffer), 0);

    // Vuln 19: CWE-269 - Improper Privilege Management
    if (strstr(request, "ADMIN")) {
        std::string user_id = std::string(request).substr(6);
        std::string query = "UPDATE users SET role = 'admin' WHERE id = '" + user_id + "'"; // No privilege check
        sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr);
        send(sockfd, "Promoted to admin", 16, 0);
    }

    // Vuln 20: CWE-611 - XML External Entity (XXE)
    if (strstr(request, "XML")) {
        xmlDocPtr doc = xmlReadMemory(request, strlen(request), "noname.xml", nullptr, 0); // No XXE protection
        std::string content = doc ? (char*)xmlDocGetRootElement(doc)->name : "Error";
        if (doc) xmlFreeDoc(doc);
        send(sockfd, content.c_str(), content.size(), 0);
    }

    // Vuln 21: CWE-918 - Server-Side Request Forgery (SSRF)
    if (strstr(request, "FETCH")) {
        std::string url = std::string(request).substr(6); // No URL validation
        CURL* curl = curl_easy_init();
        std::string response_data;
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            send(sockfd, response_data.c_str(), response_data.size(), 0);
        }
    }

    // Vuln 22: CWE-200 - Information Exposure
    if (strstr(request, "CONFIG")) {
        json config = {
            {"db_user", db_user},
            {"db_pass", db_pass},
            {"api_key", "secret_key_123456"}
        };
        std::string config_str = config.dump();
        send(sockfd, config_str.c_str(), config_str.size(), 0);
    }

    // Vuln 23: CWE-416 - Use After Free
    if (strstr(request, "UAF")) {
        char* temp = new char[100];
        strcpy(temp, request);
        delete[] temp;
        // Use after free: accessing temp after deletion
        std::string response = std::string(temp);
        send(sockfd, response.c_str(), response.size(), 0);
    }

    // Vuln 24: CWE-676 - Use of Potentially Dangerous Function
    if (strstr(request, "STRCPY")) {
        char buffer[50];
        // Using strcpy instead of safer alternatives like strncpy
        strcpy(buffer, request); // Dangerous function
        send(sockfd, buffer, strlen(buffer), 0);
    }

    // Vuln 25-50: Additional vulnerabilities (examples)
    // Vuln 25: CWE-732 - Incorrect Permission Assignment
    chmod("/uploads", 0777); // World-writable directory
    // Vuln 26: CWE-330 - Use of Insufficiently Random Values
    int token = rand(); // Predictable random value
    std::string token_str = std::to_string(token);
    send(sockfd, token_str.c_str(), token_str.size(), 0);
    // Add more (CWE-522, CWE-601, etc.) as needed
}

int main() {
    // Vuln 51: CWE-330 - Use of Insufficiently Random Values
    srand(42); // Predictable seed

    // Initialize database
    sqlite3_open("chat.db", &db);

    // Initialize libxml2
    xmlInitParser();
    LIBXML_TEST_VERSION;

    // Server setup
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    // Vuln 52: CWE-319 - Cleartext Transmission of Sensitive Information
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080); // No HTTPS
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 10);

    std::cout << "Server running on port 8080" << std::endl;

    while (true) {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        Client* client = new Client{client_fd, client_addr};
        pthread_t thread;
        pthread_create(&thread, nullptr, handle_client, client);
        // Vuln 53: CWE-404 - Improper Resource Shutdown
        // Thread not joined, potential resource leak
    }

    sqlite3_close(db);
    xmlCleanupParser();
    close(server_fd);
    return 0;
}