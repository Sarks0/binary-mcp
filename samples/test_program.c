#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This program demonstrates features that binary analysis can detect

void print_banner() {
    printf("=================================\n");
    printf("  Binary Analysis Test Program\n");
    printf("=================================\n");
}

void string_operations() {
    const char* secret = "S3cr3tP@ssw0rd";
    const char* url = "https://example.com/api/endpoint";
    const char* ip = "192.168.1.100";

    printf("Processing data...\n");
    printf("Server: %s\n", ip);
}

int calculate_sum(int a, int b) {
    return a + b;
}

int main(int argc, char* argv[]) {
    print_banner();

    printf("\nTesting basic operations:\n");
    int result = calculate_sum(42, 58);
    printf("Sum: %d\n", result);

    printf("\nTesting string operations:\n");
    string_operations();

    printf("\nProgram completed successfully!\n");

    return 0;
}
