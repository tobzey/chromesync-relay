// Small stdin/stdout bridge to macOS Keychain. No secret appears in argv.
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc < 3 || argc > 4 || strlen(argv[2]) != 64) return 2;
  for (int i = 0; i < 64; i++) if (!strchr("0123456789abcdef", argv[2][i])) return 2;
  const char *service = "io.chromesync.v2";
  SecKeychainRef keychain = NULL;
  // Optional explicit keychain is used by isolated native integration tests.
  if (argc == 4 && SecKeychainOpen(argv[3], &keychain) != errSecSuccess) return 3;
  UInt32 length = 0; void *password = NULL; SecKeychainItemRef item = NULL;
  OSStatus status = SecKeychainFindGenericPassword(keychain, (UInt32)strlen(service), service, 64, argv[2], &length, &password, &item);
  if (!strcmp(argv[1], "lookup")) {
    if (status != errSecSuccess) return 3;
    if (fwrite(password, 1, length, stdout) != length) return 4;
    SecKeychainItemFreeContent(NULL, password);
  } else if (!strcmp(argv[1], "store")) {
    if (password) SecKeychainItemFreeContent(NULL, password);
    size_t cap = 1024 * 1024; unsigned char *data = malloc(cap + 1);
    if (!data) return 4;
    size_t size = fread(data, 1, cap + 1, stdin);
    if (size > cap || ferror(stdin) || (status != errSecSuccess && status != errSecItemNotFound)) { free(data); return 3; }
    if (item) status = SecKeychainItemModifyAttributesAndData(item, NULL, (UInt32)size, data);
    else status = SecKeychainAddGenericPassword(keychain, (UInt32)strlen(service), service, 64, argv[2], (UInt32)size, data, NULL);
    memset_s(data, cap + 1, 0, cap + 1); free(data);
    if (status != errSecSuccess) return 3;
  } else return 2;
  if (item) CFRelease(item);
  if (keychain) CFRelease(keychain);
  return 0;
}
