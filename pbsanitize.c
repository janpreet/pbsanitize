#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <unistd.h>
#include <fcntl.h>
#ifdef __APPLE__
#include <ApplicationServices/ApplicationServices.h>
#endif

#define MAX_BUFFER 1048576
#define PATTERN_COUNT 33

const char *patterns[] = {
    "[A-Za-z0-9]{40,64}",
    "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+",
    "ghp_[A-Za-z0-9]{36}",
    "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
    "[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}",
    "secret_[A-Za-z0-9]+",
    "[A-Za-z0-9]{32,}",
    "AKIA[0-9A-Z]{16}",
    "-----BEGIN[^-]+-----.*-----END[^-]+-----",
    "(?i)private[^\\n]+",
    "[sS][eE][cC][rR][eE][tT].{0,20}[=:].{0,20}[A-Za-z0-9+/]{8,}",
    "[aA][pP][iI][_-][kK][eE][yY].{0,20}[=:].{0,20}[A-Za-z0-9+/]{8,}",
    "(?i)(aws_access_key|aws_secret_key|password|token|secret|api_key)(\\s*[=:]\\s*)['\"]?[^\\s'\",]+['\"]?",
    "(?i)(private_key)(\\s*[=:]\\s*)['\"]?-----BEGIN[^'\",]*-----END[^'\",]*['\"]?",
    "(?i)(connection_string)(\\s*[=:]\\s*)['\"]?[^\\s'\",]+['\"]?",
    "(?i)(bearer\\s+)['\"]?[^\\s'\",]+['\"]?",
    "(?i)(\"?\\w*password\"?\\s*[:=]?\\s*\\{?\\s*\"?value\"?\\s*[:=]?\\s*)['\"]?[^\\s'\",}]+['\"]?",
    "(?i)(\"?\\w*user\"?\\s*[:=]?\\s*\\{?\\s*\"?value\"?\\s*[:=]?\\s*)['\"]?[^\\s'\",}]+['\"]?",
    "(?i)(\"?\\w*(password|secret|key|token)\"?\\s*[:=]?\\s*['\"])[^\"']+[\"']",
    "(?i)(\"?\\w*(password|secret|key|token)\"?\\s*[:=]?\\s*\\{?\\s*\"?value\"?\\s*[:=]?\\s*)['\"]?[^\\s'\",}]+['\"]?",
    "(?i)(jdbc|mongodb(\\+srv)?|postgresql|mysql|redis|ldap)://[^\\s<'\"]+",
    "(?i)(authorization|auth|x-api-key)\\s*[:=]\\s*['\"]?\\S+['\"]?",
    "(?i)ssh-rsa\\s+[A-Za-z0-9/+]+[=]{0,3}(\\s+[\\S]+)?",
    "(?i)(env|export)\\s+\\w+=['\"][^'\"]+['\"]",
    "(?i)(facebook|fb|twitter|github|google|aws|stripe)\\S*['\"][0-9a-zA-Z\\-_]+['\"]",
    "(?i)(session|cookie)[-_]?(id|token|key)?\\s*[:=]\\s*['\"]?\\S+['\"]?",
    "(?i)(AZURE|GCP|HEROKU|DO|DIGITALOCEAN)[-_]?(SECRET|TOKEN|KEY|PASSWORD)\\s*[:=]\\s*['\"]?\\S+['\"]?",
    "(?i)(sha256|md5|sha1):([A-Fa-f0-9]{2}:){15,31}[A-Fa-f0-9]{2}",
    "(?i)(aws[-_]?(secret)?[-_]?(access)?[-_]?key([-_]?id)?|s3[-_]?bucket)\\s*[:=]\\s*['\"]?\\S+['\"]?",
    "(?i)\\?(password|secret|token|key|auth|api[-_]?key)=[^\\s&]+",
    "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b",
    "\\b(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\\b",
    "\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b"
};

void sanitize_text(char *text) {
    regex_t regex;
    regmatch_t match;
    char *original = strdup(text);
    
    for (int i = 0; i < PATTERN_COUNT; i++) {
        if (regcomp(&regex, patterns[i], REG_EXTENDED | REG_ICASE | REG_NEWLINE) != 0) continue;
        
        char *pos = text;
        while (regexec(&regex, pos, 1, &match, 0) == 0) {
            int start = match.rm_so;
            int end = match.rm_eo;
            if (start == end) break;
            
            for (int j = start; j < end && pos[j] != '\0'; j++) {
                if (!isspace(pos[j])) pos[j] = '*';
            }
            
            if (end - start < 2) break;
            pos += match.rm_so + 1;
        }
        regfree(&regex);
    }
    
    if (strlen(text) != strlen(original)) {
        strcpy(text, original);
    }
    free(original);
}

#ifdef __APPLE__
void mac_copy_to_clipboard(const char *text) {
    PasteboardRef pasteboard;
    if (PasteboardCreate(kPasteboardClipboard, &pasteboard) != noErr) return;
    PasteboardClear(pasteboard);
    CFDataRef data = CFDataCreate(NULL, (const UInt8 *)text, strlen(text));
    PasteboardPutItemFlavor(pasteboard, (PasteboardItemID)1, 
                           CFSTR("public.utf8-plain-text"), data, 0);
    CFRelease(data);
    CFRelease(pasteboard);
}
#else
void linux_copy_to_clipboard(const char *text) {
    FILE *xsel = popen("xsel -ib", "w");
    if (xsel) {
        fprintf(xsel, "%s", text);
        pclose(xsel);
    }
}
#endif

int main(void) {
    char buffer[MAX_BUFFER];
    size_t content_len = 0;
    size_t bytes_read;
    while ((bytes_read = fread(buffer + content_len, 1, 
           MAX_BUFFER - content_len, stdin)) > 0) {
        content_len += bytes_read;
        if (content_len >= MAX_BUFFER) break;
    }
    buffer[content_len] = '\0';
    sanitize_text(buffer);
    
    #ifdef __APPLE__
    mac_copy_to_clipboard(buffer);
    #else
    linux_copy_to_clipboard(buffer);
    #endif
    
    return 0;
}