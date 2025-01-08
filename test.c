#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    char *test_cases[] = {
        "Regular text that should not be sanitized\n",
        "Email: test@example.com\n",
        "Credit Card: 1234-5678-1234-5678\n",
        "Secret: secret_abcdef1234567890\n",
        "Random Long String: abcdef1234567890abcdef1234567890abcd\n",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
    };

    int test_count = sizeof(test_cases) / sizeof(test_cases[0]);
    FILE *pipe = popen("./pbsanitize", "w");
    if (!pipe) {
        printf("Failed to open pipe to pbsanitize\n");
        return 1;
    }

    for (int i = 0; i < test_count; i++) {
        fprintf(pipe, "%s", test_cases[i]);
    }
    pclose(pipe);

    sleep(1);

    char result[4096];
    memset(result, 0, sizeof(result));

    #ifdef __APPLE__
    FILE *pb = popen("pbpaste", "r");
    #else
    FILE *pb = popen("xsel -ob", "r");
    #endif

    if (!pb) {
        printf("Failed to read clipboard\n");
        return 1;
    }

    size_t total = 0;
    size_t bytes;
    while ((bytes = fread(result + total, 1, sizeof(result) - total - 1, pb)) > 0) {
        total += bytes;
    }
    pclose(pb);

    printf("Content in clipboard:\n%s\n", result);

    int failed = 0;
    char *pos = result;
    for (int i = 0; i < test_count; i++) {
        if (i == 0 && strstr(pos, "Regular text that should not be sanitized") == NULL) {
            printf("Test failed: Regular text was sanitized\n");
            failed = 1;
        }
        if (i > 0 && strchr(pos, '*') == NULL) {
            printf("Test failed: Sensitive data not sanitized in case %d\n", i);
            failed = 1;
        }
        pos = strchr(pos, '\n');
        if (pos) pos++;
    }

    return failed;
}