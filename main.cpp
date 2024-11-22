#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <sstream>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>

// Validate URL format
bool isValidURL(const std::string& url) {
    const std::regex urlRegex(R"(^(http|https)://([^:/]+)(:([0-9]+))?(/.*)?$)");
    return std::regex_match(url, urlRegex);
}

// Create a socket and connect to the host
int createConnection(const std::string& host, int port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cerr << "Error: Cannot resolve host " << host << std::endl;
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        std::cerr << "Error: Cannot create socket." << std::endl;
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        std::cerr << "Error: Cannot connect to " << host << std::endl;
        close(sock);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);
    return sock;
}

// Create an SSL socket and connect to the host
SSL* createSSLConnection(int sock) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Error: Unable to create SSL context." << std::endl;
        return nullptr;
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        std::cerr << "Error: Unable to create SSL object." << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }

    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) != 1) {
        std::cerr << "Error: SSL connection failed." << std::endl;
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    return ssl;
}

// Send an HTTP GET request to the server
bool sendHTTPRequest(int sock, SSL* ssl, const std::string& host, const std::string& path) {
    std::stringstream request;
    request << "GET " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Connection: close\r\n";
    request << "\r\n";

    const std::string requestStr = request.str();
    if (ssl) {
        return SSL_write(ssl, requestStr.c_str(), requestStr.length()) > 0;
    } else {
        return send(sock, requestStr.c_str(), requestStr.length(), 0) != -1;
    }
}

// Receive HTTP response from the server
std::string receiveHTTPResponse(int sock, SSL* ssl) {
    const size_t bufferSize = 4096;
    char buffer[bufferSize];
    std::string response;

    ssize_t bytesRead;
    while ((bytesRead = (ssl ? SSL_read(ssl, buffer, bufferSize) : recv(sock, buffer, bufferSize, 0))) > 0) {
        response.append(buffer, bytesRead);
    }

    return response;
}

// Extract the file name from the URL
std::string getFileNameFromURL(const std::string& url) {
    size_t lastSlash = url.find_last_of('/');
    size_t lastDot = url.find_last_of('.');
    if (lastSlash != std::string::npos && lastDot != std::string::npos && lastDot > lastSlash) {
        return url.substr(lastSlash + 1);  // Get the file name
    }
    return "downloaded_file";  // Default if URL doesn't have a proper file name
}

// Function to log progress
void logProgress(size_t downloaded, size_t total) {
    float progress = (static_cast<float>(downloaded) / total) * 100;
    std::cout << "Progress: " << downloaded << "/" << total << " (" << progress << "%)" << std::endl;
}

// Main download function with enhanced logging
bool downloadURL(const std::string& url, const std::string& outputPath) {
    std::smatch match;
    const std::regex urlRegex(R"(^(http|https)://([^:/]+)(:([0-9]+))?(/.*)?$)");
    if (!std::regex_match(url, match, urlRegex)) {
        std::cerr << "Invalid URL format.\n";
        return false;
    }

    std::string host = match[2].str();
    std::string portStr = match[4].matched ? match[4].str() : (match[1] == "https" ? "443" : "80");  // Default port 443 for HTTPS, 80 for HTTP
    int port = std::stoi(portStr);
    std::string path = match[5].matched ? match[5].str() : "/";  // Default path

    int sock = createConnection(host, port);
    if (sock < 0) return false;

    bool isHTTPS = (match[1] == "https");
    SSL* ssl = nullptr;
    if (isHTTPS) {
        ssl = createSSLConnection(sock);
        if (!ssl) {
            close(sock);
            return false;
        }
    }

    // Send HTTP GET request
    auto start = std::chrono::high_resolution_clock::now();
    if (!sendHTTPRequest(sock, ssl, host, path)) {
        std::cerr << "Error: Failed to send HTTP request.\n";
        if (ssl) SSL_free(ssl);
        close(sock);
        return false;
    }

    // Receive HTTP response
    std::string response = receiveHTTPResponse(sock, ssl);
    if (ssl) SSL_free(ssl);
    close(sock);

    // Find the starting position of the file content in the response
    size_t bodyStart = response.find("\r\n\r\n");
    if (bodyStart == std::string::npos) {
        std::cerr << "Error: No body found in the HTTP response.\n";
        return false;
    }
    bodyStart += 4;  // Skip the headers

    // Log content type and file size
    size_t contentLength = 0;
    size_t contentPos = response.find("Content-Length: ");
    if (contentPos != std::string::npos) {
        size_t endPos = response.find("\r\n", contentPos + 15);
        if (endPos != std::string::npos) {
            contentLength = std::stoi(response.substr(contentPos + 15, endPos - contentPos - 15));
            std::cout << "Content-Length: " << contentLength << " bytes" << std::endl;
        }
    }

    std::string contentType;
    size_t contentTypePos = response.find("Content-Type: ");
    if (contentTypePos != std::string::npos) {
        size_t endPos = response.find("\r\n", contentTypePos + 14);
        if (endPos != std::string::npos) {
            contentType = response.substr(contentTypePos + 14, endPos - contentTypePos - 14);
            std::cout << "Content-Type: " << contentType << std::endl;
        }
    }

    // Write the file to disk and log progress
    std::ofstream file(outputPath, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open output file: " << outputPath << "\n";
        return false;
    }

    size_t downloaded = 0;
    size_t total = contentLength > 0 ? contentLength : response.size() - bodyStart;
    file.write(response.c_str() + bodyStart, response.size() - bodyStart);
    downloaded += response.size() - bodyStart;

    logProgress(downloaded, total);

    file.close();

    // Log the time taken
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    std::cout << "Download completed in: " << duration.count() << " seconds" << std::endl;
    std::cout << "Downloaded file: " << outputPath << std::endl;

    return true;
}

// Command-line mode
void commandLineMode(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <URL> <Output File Path>\n";
        return;
    }
    std::string url = argv[1];
    std::string outputPath = argv[2];

    if (!isValidURL(url)) {
        std::cerr << "Invalid URL format.\n";
        return;
    }

    if (!downloadURL(url, outputPath)) {
        std::cerr << "Download failed.\n";
    }
}

// Interactive mode
void interactiveMode() {
    std::string url, outputPath;
    std::cout << "Enter URL: ";
    std::cin >> url;
    std::cout << "Enter output file path: ";
    std::cin >> outputPath;

    if (!isValidURL(url)) {
        std::cerr << "Invalid URL format.\n";
        return;
    }

    if (!downloadURL(url, outputPath)) {
        std::cerr << "Download failed.\n";
    }
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        commandLineMode(argc, argv);
    } else {
        interactiveMode();
    }
    return 0;
}
