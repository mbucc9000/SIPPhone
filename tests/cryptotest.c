#include "sp_sha1.h"
#include "sp_aes.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
static void hx(const uint8_t *b, int n, char *o) { for (int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); }
static void check(const char *name, const uint8_t *got, int n, const char *want) {
    char s[200]; hx(got, n, s);
    if (strcmp(s, want)) { printf("FAIL %s\n  got  %s\n  want %s\n", name, s, want); fails++; }
    else printf("ok   %s\n", name);
}
static int unhex(const char *h, uint8_t *o) { int n=0; while(h[0]&&h[1]){ unsigned v; sscanf(h,"%2x",&v); o[n++]=v; h+=2;} return n; }

int main(void) {
    /* SHA-1 "abc" (FIPS 180) */
    { uint8_t d[20]; sp_sha1_ctx c; sp_sha1_init(&c); sp_sha1_update(&c,"abc",3); sp_sha1_final(&c,d);
      check("sha1(abc)", d, 20, "a9993e364706816aba3e25717850c26c9cd0d89d"); }
    /* SHA-1 two-block message */
    { uint8_t d[20]; sp_sha1_ctx c; sp_sha1_init(&c);
      const char *m="abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
      sp_sha1_update(&c,m,strlen(m)); sp_sha1_final(&c,d);
      check("sha1(56-byte)", d, 20, "84983e441c3bd26ebaae4aa1f95129e5e54670f1"); }
    /* HMAC-SHA1 RFC 2202 test case 2: key "Jefe", data "what do ya want for nothing?" */
    { uint8_t mac[20]; sp_hmac_sha1((const uint8_t*)"Jefe",4,(const uint8_t*)"what do ya want for nothing?",28,mac,20);
      check("hmac-sha1(Jefe)", mac, 20, "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"); }
    /* HMAC-SHA1 RFC 2202 test case 1: key 20x0b, data "Hi There" */
    { uint8_t key[20]; memset(key,0x0b,20); uint8_t mac[20];
      sp_hmac_sha1(key,20,(const uint8_t*)"Hi There",8,mac,20);
      check("hmac-sha1(0x0b)", mac, 20, "b617318655057264e28bc0b6fb378c8ef146be00"); }
    /* AES-128 single block, FIPS-197 Appendix B/C.1 */
    { uint8_t key[16],pt[16],ct[16]; sp_aes a;
      unhex("000102030405060708090a0b0c0d0e0f",key);
      unhex("00112233445566778899aabbccddeeff",pt);
      sp_aes128_init(&a,key); sp_aes_encrypt_block(&a,pt,ct);
      check("aes128-ecb", ct, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"); }
    /* AES-128-CTR, NIST SP 800-38A F.5.1 (first two blocks) */
    { uint8_t key[16],ctr[16],buf[32]; sp_aes a;
      unhex("2b7e151628aed2a6abf7158809cf4f3c",key);
      unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",ctr);
      unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",buf);
      sp_aes128_init(&a,key); sp_aes_ctr_xor(&a,ctr,buf,32);
      check("aes128-ctr", buf, 32, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"); }
    printf("\n%s\n", fails ? "FAILURES" : "all crypto vectors pass");
    return fails ? 1 : 0;
}
