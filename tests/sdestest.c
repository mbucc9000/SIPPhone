#include "sp_sdp.h"
#include "sp_srtp.h"
#include <stdio.h>
#include <string.h>

static int fails=0, oks=0;
#define CK(c,...) do{ if(c){oks++;} else {fails++; printf("FAIL "); printf(__VA_ARGS__); printf("\n");} }while(0)

int main(void){
    /* build a secure offer, parse it back */
    uint8_t key[30]; for(int i=0;i<30;i++) key[i]=(uint8_t)(i*7+3);
    int pts[2]={0,8}; char sdp[1024];
    sp_sdp_build(sdp, sizeof sdp, "192.0.2.10", 40000, 111, 1, pts, 2, 101, SP_DIR_SENDRECV, key, 1);
    CK(strstr(sdp,"RTP/SAVP")!=NULL, "secure offer uses RTP/SAVP");
    CK(strstr(sdp,"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:")!=NULL, "offer has a=crypto inline");

    sp_sdp s;
    CK(sp_sdp_parse(sdp, strlen(sdp), &s)==0, "secure offer parses");
    CK(s.savp==1, "parsed savp flag");
    CK(s.have_crypto==1 && s.crypto_tag==1, "parsed crypto tag");
    CK(memcmp(s.crypto_key,key,30)==0, "crypto key round-trips through the SDP");

    /* a plain offer has no crypto / no savp */
    sp_sdp_build(sdp, sizeof sdp, "192.0.2.10", 40000, 1,1, pts,2,101, SP_DIR_SENDRECV, NULL, 0);
    CK(strstr(sdp,"RTP/AVP")!=NULL && strstr(sdp,"SAVP")==NULL, "plain offer uses RTP/AVP");
    CK(strstr(sdp,"crypto")==NULL, "plain offer has no crypto");
    sp_sdp_parse(sdp, strlen(sdp), &s);
    CK(s.savp==0 && s.have_crypto==0, "plain offer parses as non-secure");

    /* a real-looking VoIP.ms/Asterisk SAVP answer */
    const char *ast =
        "v=0\r\no=root 1 1 IN IP4 208.100.60.8\r\ns=Asterisk\r\nc=IN IP4 208.100.60.8\r\nt=0 0\r\n"
        "m=audio 13624 RTP/SAVP 0 101\r\n"
        "a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-16\r\n"
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19fX19fX19fX19fX19fX19fX19fX19fX18w|2^31\r\n"
        "a=ptime:20\r\na=sendrecv\r\n";
    CK(sp_sdp_parse(ast, strlen(ast), &s)==0, "asterisk SAVP answer parses");
    CK(s.savp==1 && s.have_crypto==1, "asterisk answer is secure");
    CK(sp_sdp_choose(&s)==0, "codec PCMU chosen from the secure answer");
    CK(strcmp(s.ip,"208.100.60.8")==0 && s.port==13624, "media addr from secure answer");

    /* an unknown crypto suite must NOT be accepted as our suite */
    const char *other =
        "v=0\r\no=- 1 1 IN IP4 1.2.3.4\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\n"
        "m=audio 5000 RTP/SAVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        "a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:" "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2\r\n"
        "a=sendrecv\r\n";
    CK(sp_sdp_parse(other, strlen(other), &s)==0, "other-suite answer parses");
    CK(s.savp==1 && s.have_crypto==0, "unsupported crypto suite is not accepted");

    printf("\n%d passed, %d failed\n", oks, fails);
    return fails?1:0;
}
