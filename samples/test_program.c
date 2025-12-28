#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * TEST PROGRAM FOR BINARY ANALYSIS
 *
 * This program contains intentionally fake/dummy strings and patterns
 * to test binary analysis detection capabilities. All credentials,
 * URLs, and IP addresses are fictional and for testing purposes ONLY.
 *
 * DO NOT use any patterns from this file in production code.
 */

void print_banner() {
    printf("=================================\n");
    printf("  Binary Analysis Test Program\n");
    printf("=================================\n");
}

void string_operations() {
    // FAKE TEST DATA - intentionally detectable patterns for analysis testing
    const char* secret = "FAKE_TEST_CREDENTIAL_DO_NOT_USE";
    const char* url = "https://test.example.invalid/api/endpoint";
    const char* ip = "192.0.2.1";  // TEST-NET-1 reserved for documentation

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
