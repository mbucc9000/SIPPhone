#include "sp_srtp.h"
#include "sp_aes.h"
#include <stdio.h>
#include <string.h>

static int fails=0, oks=0;
#define CK(c,...) do{ if(c){oks++;} else {fails++; printf("FAIL "); printf(__VA_ARGS__); printf("\n");} }while(0)
static int unhex(const char*h,uint8_t*o){int n=0;while(h[0]&&h[1]){unsigned v;sscanf(h,"%2x",&v);o[n++]=v;h+=2;}return n;}
static void hx(const uint8_t*b,int n,char*o){for(int i=0;i<n;i++)sprintf(o+2*i,"%02x",b[i]);}

/* build a minimal RTP packet: V=2, PT=0, given seq/ts/ssrc, payload of `pn` bytes value `val` */
static int mk(uint8_t*p,uint16_t seq,uint32_t ts,uint32_t ssrc,int pn,uint8_t val){
    p[0]=0x80;p[1]=0;p[2]=seq>>8;p[3]=seq;p[4]=ts>>24;p[5]=ts>>16;p[6]=ts>>8;p[7]=ts;
    p[8]=ssrc>>24;p[9]=ssrc>>16;p[10]=ssrc>>8;p[11]=ssrc;
    for(int i=0;i<pn;i++)p[12+i]=val;
    return 12+pn;
}

int main(void){
    /* ---- RFC 3711 B.3 key derivation ---- */
    uint8_t keying[30]; char s[64];
    unhex("E1F97A0D3E018BE0D64FA32C06DE4139",keying);           /* master key */
    unhex("0EC675AD498AFEEBB6960B3AABE6",keying+16);            /* master salt */
    sp_srtp a; sp_srtp_init(&a,keying);
    hx(a.salt,14,s);  CK(!strcmp(s,"30cbbc08863d8c85d49db34a9ae1"),"session salt %s",s);
    hx(a.auth,20,s);  CK(!strcmp(s,"cebe321f6ff7716b6fd4ab49af256a156d38baa4"),"session auth key %s",s);
    /* session enc key (label 0): encrypt a zero block with it and compare to a fresh cipher keyed by the B.3 value */
    { uint8_t z[16]={0},g[16],w[16],ek[16]; sp_aes ref;
      unhex("C61E7A93744F39EE10734AFE3FF7A087",ek); sp_aes128_init(&ref,ek);
      sp_aes_encrypt_block(&a.enc,z,g); sp_aes_encrypt_block(&ref,z,w);
      CK(!memcmp(g,w,16),"session enc key matches B.3"); }

    /* ---- round trip ---- */
    uint8_t tx_k[30], rx_k[30];
    for(int i=0;i<30;i++){tx_k[i]=i+1;}            /* some key; both sides share it */
    memcpy(rx_k,tx_k,30);
    sp_srtp tx, rx; sp_srtp_init(&tx,tx_k); sp_srtp_init(&rx,rx_k);
    { uint8_t p[256], orig[256]; int n=mk(p,1000,55555,0xdeadbeef,160,0xAB); memcpy(orig,p,n);
      int pn=sp_srtp_protect(&tx,p,n,sizeof p);
      CK(pn==n+10,"protect adds 10-byte tag (%d)",pn);
      CK(memcmp(p+12,orig+12,160)!=0,"payload encrypted (differs from plaintext)");
      CK(memcmp(p,orig,12)==0,"header unchanged");
      int un=sp_srtp_unprotect(&rx,p,pn);
      CK(un==n,"unprotect returns rtp length (%d)",un);
      CK(memcmp(p,orig,n)==0,"decrypts back to the original packet"); }

    /* ---- tamper: any bit flip in the protected packet is rejected ---- */
    { sp_srtp t2,r2; sp_srtp_init(&t2,tx_k); sp_srtp_init(&r2,rx_k);
      uint8_t p[256]; int n=mk(p,7,1,0xdeadbeef,160,0x11); int pn=sp_srtp_protect(&t2,p,n,sizeof p);
      p[40]^=0x01;    /* flip a ciphertext bit */
      CK(sp_srtp_unprotect(&r2,p,pn)==-1,"tampered payload rejected");
      sp_srtp_init(&r2,rx_k); n=mk(p,8,1,0xdeadbeef,160,0x11); pn=sp_srtp_protect(&t2,p,n,sizeof p);
      p[pn-1]^=0x01;  /* flip a tag bit */
      CK(sp_srtp_unprotect(&r2,p,pn)==-1,"tampered tag rejected"); }

    /* ---- wrong key cannot decrypt/auth ---- */
    { sp_srtp t2,r2; uint8_t bad[30]; for(int i=0;i<30;i++)bad[i]=0x99;
      sp_srtp_init(&t2,tx_k); sp_srtp_init(&r2,bad);
      uint8_t p[256]; int n=mk(p,3,1,0xdeadbeef,160,0x22); int pn=sp_srtp_protect(&t2,p,n,sizeof p);
      CK(sp_srtp_unprotect(&r2,p,pn)==-1,"wrong key rejected"); }

    /* ---- replay: the same packet twice is rejected the second time ---- */
    { sp_srtp t2,r2; sp_srtp_init(&t2,tx_k); sp_srtp_init(&r2,rx_k);
      uint8_t p[256],save[256]; int n=mk(p,100,1,0xdeadbeef,160,0x33); int pn=sp_srtp_protect(&t2,p,n,sizeof p);
      memcpy(save,p,pn);
      CK(sp_srtp_unprotect(&r2,p,pn)==n,"first copy accepted");
      memcpy(p,save,pn);
      CK(sp_srtp_unprotect(&r2,p,pn)==-1,"replayed copy rejected"); }

    /* ---- reorder within the window is accepted; stream stays correct ---- */
    { sp_srtp t2,r2; sp_srtp_init(&t2,tx_k); sp_srtp_init(&r2,rx_k);
      uint8_t pk[8][256]; int pl[8];
      for(int i=0;i<8;i++){ uint8_t q[256]; int n=mk(q,200+i,i,0xdeadbeef,160,(uint8_t)(0x40+i));
                            pl[i]=sp_srtp_protect(&t2,q,n,sizeof q); memcpy(pk[i],q,pl[i]); }
      int order[8]={0,2,1,3,5,4,6,7}, good=0;
      for(int i=0;i<8;i++){ uint8_t q[256]; memcpy(q,pk[order[i]],pl[order[i]]);
        int un=sp_srtp_unprotect(&r2,q,pl[order[i]]);
        if(un>0 && q[12]==(uint8_t)(0x40+order[i])) good++; }
      CK(good==8,"reordered-but-fresh packets all decrypt right (%d/8)",good); }

    /* ---- sequence rollover (seq wraps 65535 -> 0), ROC increments, still decrypts ---- */
    { sp_srtp t2,r2; sp_srtp_init(&t2,tx_k); sp_srtp_init(&r2,rx_k);
      int good=0; uint16_t seqs[4]={65534,65535,0,1};
      for(int i=0;i<4;i++){ uint8_t q[256]; int n=mk(q,seqs[i],i,0xcafe0001,160,(uint8_t)(0x70+i));
        int pn=sp_srtp_protect(&t2,q,n,sizeof q);
        int un=sp_srtp_unprotect(&r2,q,pn);
        if(un>0 && q[12]==(uint8_t)(0x70+i)) good++; }
      CK(good==4 && r2.roc==1,"rollover across 65535->0 handled (%d/4, roc=%u)",good,r2.roc); }

    /* ---- base64 round trip (SDES inline) ---- */
    { char b[41]; uint8_t back[30]; sp_srtp_keying_to_b64(tx_k,b);
      CK(strlen(b)==40,"inline base64 is 40 chars (%zu)",strlen(b));
      CK(sp_srtp_keying_from_b64(b,back)==0 && !memcmp(back,tx_k,30),"base64 round trips");
      CK(sp_srtp_keying_from_b64("short",back)==-1,"too-short base64 rejected");
      /* trailing SDES params after the inline value are ignored */
      char withp[64]; sprintf(withp,"%s|2^20|1:4",b);
      CK(sp_srtp_keying_from_b64(withp,back)==0 && !memcmp(back,tx_k,30),"inline with |lifetime ok"); }

    printf("\n%d passed, %d failed\n",oks,fails);
    return fails?1:0;
}
