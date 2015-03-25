/**
 * Ported the drupal password hash with C.
 *
 * Author: Everright Chen
 * Email : everright.chen@gmail.com
 * Web   : http://www.everright.cn
 */

#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <stdio.h>

#define DRUPAL_HASH_COUNT 15
#define DRUPAL_MIN_HASH_COUNT 7
#define DRUPAL_MAX_HASH_COUNT 30
#define DRUPAL_HASH_LENGTH 55
#define DRUPAL_SALT "$S$"

static char *
ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
_password_base64_encode(char *out, const unsigned char *in, int count)
{
  int i = 0, v;
  do {
    v = (unsigned char)in[i++];
    *out++ = ITOA64[v & 0x3f];
    if (i < count)
      v |= (unsigned char)in[i] << 8;
    *out++ = ITOA64[(v >> 6) & 0x3f];
    if (i++ >= count)
      break;
    if (i < count)
      v |= (unsigned char)in[i] << 16;
    *out++ = ITOA64[(v >> 12) & 0x3f];
    if (i++ >= count)
      break;
    *out++ = ITOA64[(v >> 18) & 0x3f];
  } while (i < count);
}

char *
_password_generate_salt(int count_log2) {
  static char output[13];
  unsigned char iv[6];
  int len = sizeof(iv);
  strcpy(output, DRUPAL_SALT);
  output[3] = ITOA64[count_log2];

  RAND_bytes(iv, len);
  _password_base64_encode(&output[4], iv, len);

  return output;
}

char *
_password_crypt(char *password, char *setting)
{
  static char output[99];
  SHA512_CTX ctx;
  char hash[SHA512_DIGEST_LENGTH];
  char *p, *salt;
  int count_log2, length, count;

  if (strncmp(setting, DRUPAL_SALT, 3))
    return output;

  p = strchr(ITOA64, setting[3]);
  if (!p)
    return output;
  count_log2 = p - ITOA64;
  if (count_log2 < DRUPAL_MIN_HASH_COUNT || count_log2 > DRUPAL_MAX_HASH_COUNT)
    return output;

  salt = setting + 4;
  if (strlen(salt) < 8)
    return output;

  length = strlen(password);

  SHA512_Init(&ctx);
  SHA512_Update(&ctx, salt, 8);
  SHA512_Update(&ctx, password, length);
  SHA512_Final(hash, &ctx);

  count = 1 << count_log2;
  do {
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, hash, SHA512_DIGEST_LENGTH);
    SHA512_Update(&ctx, password, length);
    SHA512_Final(hash, &ctx);
  } while (--count);

  memcpy(output, setting, 12);
  _password_base64_encode(&output[12], hash, SHA512_DIGEST_LENGTH);

  output[DRUPAL_HASH_LENGTH] = '\0';

  return output;
}

int main(int argc, char **argv)
{
  if (argc > 3 || argc < 2) return 1;

  int count_log2 = DRUPAL_HASH_COUNT;
  if (argc == 3) {
    count_log2 = strtol(argv[2], NULL, 10);
    if (count_log2 < DRUPAL_MIN_HASH_COUNT) {
      count_log2 = DRUPAL_MIN_HASH_COUNT;
    }
    else if (count_log2 > DRUPAL_MAX_HASH_COUNT) {
      count_log2 = DRUPAL_MAX_HASH_COUNT;
    }
  }

  char *salt = _password_generate_salt(count_log2);
  puts(_password_crypt(argv[1], salt));

  return 0;
}
