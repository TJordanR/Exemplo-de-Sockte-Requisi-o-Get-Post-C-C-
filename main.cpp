/// BIBLIOTECA GLOBAL EM C++
#include <iostream>

/// BIBLIOTECA CRYPTOGRAFIA
#include "sha256.h"

/// BIBLIOTECAS GLOBAIS EM C
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/// MANIPULACAO DE STRING CARACTERES ESPECIAIS
#include <ctype.h>
#include <sstream>

/// BIBLIOTECA WINDOWS SOCKTES
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma  comment(lib,"ws2_32.lib")
#include <httpext.h>
#include <winsock.h>
#include <wincrypt.h>
//#include <WinTrust.h>
//#include <wintrust.h>
#include <schannel.h>
#include <security.h>
#include <ssp/ssp.h>

#pragma comment(lib, "WSock32.Lib")
#pragma comment(lib, "Crypt32.Lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "MSVCRTD.lib")

//#include <libcurl.h>
/// BIBLIOTECA WINDOWS
#include <windows.h>

/// BIBLIOTECAS ADICIONAIS FUNÇOES OU CHAMADAS
#include <vector>
#include <locale>
#include <sstream>

/// BIBLIOTECAS SSL/TSL
//#include <ssl.h>

/// DEFINE UM TAMANHO DE STRING DE PESQUISA
#define MAX 0xffff

/// BIBLIOTECAS INTERNAS
#include "metodo_busca_http.h"
#include "tls.h"

/// BIBLIOTECA CURL
#include <curl.h>

using namespace std;
using std::string;
using std::cout;
using std::endl;

/// ALOCADOR DE ENDEREÇO DE IP
const char *MAX_TAM_GET2;
/// ALOCADOR DA REQUISICAO GET
char *inicio_x;
/// ALOCADOR DE RETORNO DE CAMINHO
char *Exten;

// REQUISICAO_DOMINIO_GET_IP_EXTERNO
void CONSULTA_IP_DOMINIO_GET(){

    /* DICAS CISCO DE HELLO COM SERVIDORE CABEÇALHO DE REQUISIÇÃO E RESPOSTA
    Introdução SSL com transação e intercâmbio de pacotes da amostra
    LINK: https://www.cisco.com/c/pt_br/support/docs/security-vpn/secure-socket-layer-ssl/116181-technote-product-00.html
    */

    /* EXEMPLO: CABEÇARIO DE RECEPÇÃO GET PORTA 80
    POST http://192.168.0.2/Login.htm
    Host: 192.168.0.2
    User-Agent: Mozilla/5.0
    Accept: text/html
    Accept-Language: pt-BR,pt
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 44
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Pragma: no-cache
    Cache-Control: no-cache
    Origin: http://192.168.0.2
    command=login&username=admin&password=396127
    */

    /* SERVIDOR WEBSOCKET EXEMPLO MOZILLA DEVELOPER
    DOCUMENTAÇÃO MOZILLA DEVELOPER
    LINK: https://developer.mozilla.org/pt-BR/docs/WebSockets/Writing_WebSocket_servers

    GET /chat HTTP/1.1
    Host: example.com:8000
    Upgrade: websocket
    Connection: Upgrade
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
    Sec-WebSocket-Version: 13
    */


    const char passcet[] = {
    "dGhlIHNhbXBsZSBub25jZQ=="
    };




    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO GET
    char inicio_0[MAX] = " HTTP/1.1\r\n Host: https://ferramentasparawebmaster.com.br:443\r\n";
    char inicio_1[MAX] = "GET / Cliente Hello\r\n 22\r\n TLS 1.0\r\n 0x0301\r\n 192";
    char inicio_2[MAX] = "Upgrade: websocket\r\n";
    char inicio_3[MAX] = "Connection: Upgrade\r\n";
    char inicio_4[MAX] = "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n";
    char inicio_5[MAX] = "Sec-WebSocket-Version: 13\r\n";
    char inicio_6[MAX] = "Cliente Hello\r\n 22\r\n TLS 1.0\r\n 0x0301\r\n 192";

    //char inicio_2[MAX] = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n";
    //char inicio_3[MAX] = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    //char inicio_4[MAX] = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    //char inicio_5[MAX] = "Accept-Encoding: gzip, deflate, br\r\n";
    //char inicio_6[MAX] = "Content-Type: application/x-www-form-urlencoded\r\n";
    //char inicio_7[MAX] = "Content-Length: 48\r\n";
    //char inicio_8[MAX] = "Connection: keep-alive\r\n";
    //char inicio_9[MAX] = "Referer: https://ferramentasparawebmaster.com.br/descobrir-ip-do-site\r\n";
    //char inicio_10[MAX] = "Cookie: _ga=GA1.3.87740843.1567036521; PHPSESSID=rfc87g0s3i3pqqf79vth39of81; _gid=GA1.3.1449835433.1574726510; hibext_instdsigdipv2=1\r\n";
    //char inicio_11[MAX] = "Upgrade-Insecure-Requests: 1\r\n";
    //char inicio_12[MAX] = "url=http%3A%2F%2Fwww.facebook.com.br&submit=Enviar\r\n";
    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    //char inicio_13[MAX] = " HTTP/1.1\r\n";
    //char inicio_14[MAX]  = "Host: ferramentasparawebmaster.com.br\r\n";
    char inicio_15[MAX]  = "\r\n\r\n";
    //char inicio_16[MAX]  = " Connection: keep-alive\r\n\r\n";
    //char inicio_17[MAX]  = " Keep-Alive: 300\r\n";
    //char inicio_18[MAX]  = "\r\n\r\n";
    ///-------------------------------------------------------------------------------------------

    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "199.168.188.234";
        //char ss[17];
        //FILE *pp;
        //char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        //pp = fopen(ss,"r");
        //pp = fopen(uu, (ss, "r"));
        //fscanf(pp, "%s", aa);
        printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        //fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        //strcat(inicio_1, inicio_2);  // USER-AGENT
        ///strcat(inicio_1, inicio_3);  // ACCEPT
        ///strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        ///strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        //strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        //strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        //strcat(inicio_1, inicio_8);  // CONNECTION
        //strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        //strcat(inicio_1, inicio_10); // PROGMA
        //strcat(inicio_1, inicio_11); // CACHE-CONTROL
        //strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        //strcat(inicio_1, inicio_13); // HTTP/1.1
        //strcat(inicio_1, inicio_14); // HOST
        //strcat(inicio_1, inicio_15); // \R\N\R\N
        //strcat(inicio_1, inicio_16); // CONNECTION
        //strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        //char aa[50] = "192.168.0.2";
        //char ss[17];
        //FILE *pp;
        //char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        //pp = fopen(ss,"r");
        //pp = fopen(uu, (ss, "r"));
        //printf( "%s\n", aa);
        //strcat(inicio_1, inicio_14);
        //strcat(inicio_1, aa);
        //strcat(inicio_1, inicio_15);
        //strcat(inicio_1, inicio_16);
        //strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << "------------------------------------------------------------------" << endl;
        cout << inicio_x << endl;
        cout << "------------------------------------------------------------------" << endl;
        //fclose(pp);
    }

}
// REQUISICAO_DOMINIO_POST_IP_EXTERNO
void CONSULTA_IP_DOMINIO_POST1(){

    /// CABEÇARIO DE RECEPÇÃO GET
   /*
    Host: ferramentasparawebmaster.com.br
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,* / *;q=0.8
    Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 48
    Origin: https://ferramentasparawebmaster.com.br
    Connection: keep-alive
    Referer: https://ferramentasparawebmaster.com.br/descobrir-ip-do-site
    Cookie: _ga=GA1.3.87740843.1567036521; PHPSESSID=rfc87g0s3i3pqqf79vth39of81; _gid=GA1.3.1449835433.1574726510; hibext_instdsigdipv2=1
    Upgrade-Insecure-Requests: 1

    url=http%3A%2F%2Fwww.fribal.com.br&submit=Enviar

    <input type="text" name="url" id="url" value="" class="form-control">

    Host: ferramentasparawebmaster.com.br
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0
    Accept: * / *
    Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
    Accept-Encoding: gzip, deflate, br
    Content-Type: application/x-www-form-urlencoded; charset=UTF-8
    X-Requested-With: XMLHttpRequest
    Content-Length: 109
    Origin: https://ferramentasparawebmaster.com.br
    Connection: keep-alive
    Referer: https://ferramentasparawebmaster.com.br/descobrir-ip-do-site/output
    Cookie: _ga=GA1.3.87740843.1567036521; PHPSESSID=rfc87g0s3i3pqqf79vth39of81; _gid=GA1.3.1449835433.1574726510; hibext_instdsigdipv2=1

    page=https%3A%2F%2Fferramentasparawebmaster.com.br%2Fdescobrir-ip-do-site%2Foutput&ref=Direct&screen=1366x768

    */

    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;
    //char requisicao[MAX] = "www.facebook.com";
    char requisicao[100];
    ///printf("DIGITE O SITE DE BUSCA:");
    ///gets(requisicao);
    ///printf("\n\n");

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO POST
    char inicio_0[MAX] = "HTTP/1.0\r\nHost: ferramentasparawebmaster.com.br\r\n";
    char inicio_1[MAX] = "GET /68425a4600d40df93bc47276b755bbd3c39e9092624614bf307732adfed89870 ";
    ///char inicio_1[MAX] = "GET /ferramentasparawebmaster.com.br/descobrir-ip-do-site/output"; //original
    char inicio_2[MAX] = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n";
    char inicio_3[MAX] = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    char inicio_4[MAX] = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    char inicio_5[MAX] = "Accept-Encoding: gzip, deflate, br\r\n";
    char inicio_6[MAX] = "Content-Type: application/x-www-form-urlencoded\r\n";
    char inicio_7[MAX] = "Content-Length: 48\r\n";
    char inicio_8[MAX] = "Connection: keep-alive\r\n";
    char inicio_9[MAX] = "Referer: https://ferramentasparawebmaster.com.br/descobrir-ip-do-site\r\n";
    char inicio_10[MAX] = "Cookie: _ga=GA1.3.87740843.1567036521; PHPSESSID=rfc87g0s3i3pqqf79vth39of81; _gid=GA1.3.1449835433.1574726510; hibext_instdsigdipv2=1\r\n";
    char inicio_11[MAX] = "Upgrade-Insecure-Requests: 1\r\n";
    char inicio_12[MAX] = "url=http%3A%2F%2Fwww.facebook.com.br&submit=Enviar\r\n";
    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_13[MAX] = " HTTP/1.1\r\n";
    char inicio_14[MAX]  = "Host: ferramentasparawebmaster.com.br\r\n";
    char inicio_15[MAX]  = "\r\n\r\n";
    char inicio_16[MAX]  = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX]  = " Keep-Alive: 300\r\n";

    ///-------------------------------------------------------------------------------------------

    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "199.168.188.234";
        ///char ss[17];
        ///FILE *pp;
        ///char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///fscanf(pp, "%s", aa);
        ///printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        ///fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        strcat(inicio_1, inicio_2);  // USER-AGENT
        strcat(inicio_1, inicio_3);  // ACCEPT
        strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        strcat(inicio_1, inicio_8);  // CONNECTION
        strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        strcat(inicio_1, inicio_10); // PROGMA
        strcat(inicio_1, inicio_11); // CACHE-CONTROL
        strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        strcat(inicio_1, inicio_13); // HTTP/1.1
        strcat(inicio_1, inicio_14); // HOST
        strcat(inicio_1, inicio_15); // \R\N\R\N
        strcat(inicio_1, inicio_16); // CONNECTION
        strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        ///char aa[50] = "192.168.0.2";
        ///char ss[17];
        ///FILE *pp;
        ///char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///printf( "%s\n", aa);
        ///strcat(inicio_1, inicio_14);
        ///strcat(inicio_1, aa);
        ///strcat(inicio_1, inicio_15);
        ///strcat(inicio_1, inicio_16);
        ///strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << inicio_x;
//        fclose(pp);
    }

}
// REQUISICAO_DOMINIO_POST_IP_EXTERNO_V2-TESTE CHA256 TOTALMENTE CRYPTOGRAFADO NAS REQUISIÇOES
void CONSULTA_IP_DOMINIO_POST(){

    /// CABEÇARIO DE RECEPÇÃO GET

    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;
    //char requisicao[MAX] = "www.facebook.com";
    char requisicao[100];
    ///printf("DIGITE O SITE DE BUSCA:");
    ///gets(requisicao);
    ///printf("\n\n");

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO POST
    char inicio_0[MAX]; char inicio_1[MAX];
    char inicio_2[MAX]; char inicio_3[MAX];
    char inicio_4[MAX]; char inicio_5[MAX];
    char inicio_6[MAX]; char inicio_7[MAX];
    char inicio_8[MAX]; char inicio_9[MAX];
    char inicio_10[MAX];char inicio_11[MAX];
    char inicio_12[MAX];char inicio_13[MAX];
    char inicio_14[MAX];char inicio_15[MAX];
    char inicio_16[MAX];char inicio_17[MAX];

    string cab_0 = "HTTP/1.0\r\nHost: ferramentasparawebmaster.com.br\r\n";
    string cab_1 = "GET /ferramentasparawebmaster.com.br/descobrir-ip-do-site/output";
    string cab_2 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0\r\n";
    string cab_3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    string cab_4 = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    string cab_5 = "Accept-Encoding: gzip, deflate, br\r\n";
    string cab_6 = "Content-Type: application/x-www-form-urlencoded\r\n";
    string cab_7 = "Content-Length: 48\r\n";
    string cab_8 = "Connection: keep-alive\r\n";
    string cab_9 = "Referer: https://ferramentasparawebmaster.com.br/descobrir-ip-do-site\r\n";
    string cab_10 = "Cookie: _ga=GA1.3.87740843.1567036521; PHPSESSID=rfc87g0s3i3pqqf79vth39of81; _gid=GA1.3.1449835433.1574726510; hibext_instdsigdipv2=1\r\n";
    string cab_11 = "Upgrade-Insecure-Requests: 1\r\n";
    string cab_12 = "url=http%3A%2F%2Fwww.facebook.com.br&submit=Enviar\r\n";
    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    string cab_13 = " HTTP/1.1\r\n";
    string cab_14  = "Host: ferramentasparawebmaster.com.br\r\n";
    string cab_15  = "\r\n\r\n";
    string cab_16  = " Connection: keep-alive\r\n\r\n";
    string cab_17  = " Keep-Alive: 300\r\n";

    ///-------------------------------------------------------------------------------------------
    string inicio_00 = "HTTP/1.0\r\nHost: ferramentasparawebmaster.com.br\r\n";
    char inicio_000[MAX];

    //string inicio_001 = "Content Type:ClientHello";
    string output00 = sha256(cab_0);
    string output01 = sha256(cab_1);
    string output02 = sha256(cab_2);
    string output03 = sha256(cab_3);
    string output04 = sha256(cab_4);
    string output05 = sha256(cab_5);
    string output06 = sha256(cab_6);
    string output07 = sha256(cab_7);
    string output08 = sha256(cab_8);
    string output09 = sha256(cab_9);
    string output10 = sha256(cab_10);
    string output11 = sha256(cab_11);
    string output12 = sha256(cab_12);
    string output13 = sha256(cab_13);
    string output14 = sha256(cab_14);
    string output15 = sha256(cab_15);
    string output16 = sha256(cab_16);
    string output17 = sha256(cab_17);
    strcpy(inicio_0, output00.c_str() );
    strcpy(inicio_1, output01.c_str() );
    strcpy(inicio_2, output02.c_str() );
    strcpy(inicio_3, output03.c_str() );
    strcpy(inicio_4, output04.c_str() );
    strcpy(inicio_5, output05.c_str() );
    strcpy(inicio_6, output06.c_str() );
    strcpy(inicio_7, output07.c_str() );
    strcpy(inicio_8, output08.c_str() );
    strcpy(inicio_9, output09.c_str() );
    strcpy(inicio_10, output10.c_str() );
    strcpy(inicio_11, output11.c_str() );
    strcpy(inicio_12, output12.c_str() );
    strcpy(inicio_13, output13.c_str() );
    strcpy(inicio_14, output14.c_str() );
    strcpy(inicio_15, output15.c_str() );
    strcpy(inicio_16, output16.c_str() );
    strcpy(inicio_17, output17.c_str() );


    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "199.168.188.234";
        ///char ss[17];
        ///FILE *pp;
        ///char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///fscanf(pp, "%s", aa);
        ///printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        ///fclose(pp);

    }

    /// CABECARIO SIMPLES
    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        ///-------------------------------------------------------------------------------------------

    }

    /// CABECARIO COMPLETO
    if(a == 2)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        strcat(inicio_1, inicio_2);  // USER-AGENT
        strcat(inicio_1, inicio_3);  // ACCEPT
        strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        strcat(inicio_1, inicio_8);  // CONNECTION
        strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        strcat(inicio_1, inicio_10); // PROGMA
        strcat(inicio_1, inicio_11); // CACHE-CONTROL
        strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        strcat(inicio_1, inicio_13); // HTTP/1.1
        strcat(inicio_1, inicio_14); // HOST
        strcat(inicio_1, inicio_15); // \R\N\R\N
        strcat(inicio_1, inicio_16); // CONNECTION
        strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }
    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        ///char aa[50] = "192.168.0.2";
        ///char ss[17];
        ///FILE *pp;
        ///char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///printf( "%s\n", aa);
        ///strcat(inicio_1, inicio_14);
        ///strcat(inicio_1, aa);
        ///strcat(inicio_1, inicio_15);
        ///strcat(inicio_1, inicio_16);
        ///strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << inicio_x;
//        fclose(pp);
    }

}
// TESTE DVR RECEBE 100% FUNCIONAL
void REQUISICAO_GET(){

   /// CABEÇARIO DE RECEPÇÃO GET
   /*
    POST http://192.168.0.2/Login.htm
    Host: 192.168.0.2
    User-Agent: Mozilla/5.0
    Accept: text/html
    Accept-Language: pt-BR,pt
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 44
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Pragma: no-cache
    Cache-Control: no-cache
    Origin: http://192.168.0.2
    command=login&username=admin&password=396127
    Host: 192.168.0.2
    */

    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO GET
    char inicio_0 [MAX] = "POST http://192.168.0.2/mt.js ";
    char inicio_1 [MAX] = "Host: 192.168.0.2\r\n";
    char inicio_2 [MAX] = "User-Agent: InternetExplorer/11.0\r\n";
    char inicio_3 [MAX] = "Accept: text/html\r\n"; ///"Accept: text/html\r\n"; //Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
    char inicio_4 [MAX] = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    char inicio_5 [MAX] = "Accept-Encoding: gzip, deflate\r\n";
    char inicio_6 [MAX] = "Content-Type: application/x-www-form-urlencoded\r\n";
    char inicio_7 [MAX] = "Content-Length: 44\r\n";
    char inicio_8 [MAX] = "Connection: keep-alive\r\n";
    char inicio_9 [MAX] = "Upgrade-Insecure-Requests: 1\r\n";
    char inicio_10[MAX] = "Pragma: no-cache\r\n";
    char inicio_11[MAX] = "Cache-Control: no-cache\r\n";
    char inicio_12[MAX] = "command=login&username=admin&password=admin";

    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_13[MAX] = " HTTP/1.1\r\n";
    char inicio_14[MAX] = "Host: ";
    char inicio_15[MAX] = "\r\n\r\n";
    char inicio_16[MAX] = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX] = " Keep-Alive: 300\r\n";
    ///-------------------------------------------------------------------------------------------

    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "192.168.0.2";
        //char ss[17];
        //FILE *pp;
        //char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        //pp = fopen(ss,"r");
        //pp = fopen(uu, (ss, "r"));
        //fscanf(pp, "%s", aa);
        printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        //fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        strcat(inicio_1, inicio_2);  // USER-AGENT
        strcat(inicio_1, inicio_3);  // ACCEPT
        strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        strcat(inicio_1, inicio_8);  // CONNECTION
        //strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        //strcat(inicio_1, inicio_10); // PROGMA
        //strcat(inicio_1, inicio_11); // CACHE-CONTROL
        //strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        strcat(inicio_1, inicio_13); // HTTP/1.1
        strcat(inicio_1, inicio_14); // HOST
        strcat(inicio_1, inicio_15); // \R\N\R\N
        strcat(inicio_1, inicio_16); // CONNECTION
        strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        //char aa[50] = "192.168.0.2";
        //char ss[17];
        //FILE *pp;
        //char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        //pp = fopen(ss,"r");
        //pp = fopen(uu, (ss, "r"));
        //printf( "%s\n", aa);
        //strcat(inicio_1, inicio_14);
        //strcat(inicio_1, aa);
        //strcat(inicio_1, inicio_15);
        //strcat(inicio_1, inicio_16);
        //strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << "------------------------------------------------------------------" << endl;
        cout << inicio_x << endl;
        cout << "------------------------------------------------------------------" << endl;
        //fclose(pp);
    }

}
// TESTE DVR ENVISO 100% FUNCIONAL
void REQUISICAO_POST(){
    /// CABEÇARIO DE ENVIO POST
    /*
    POST http://192.168.0.2/Login.htm
    Host: 192.168.0.2
    User-Agent: Mozilla/5.0
    Accept: text/html
    Accept-Language: pt-BR,pt
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 44
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Pragma: no-cache
    Cache-Control: no-cache
    Origin: http://192.168.0.2
    command=login&username=admin&password=396127
    */

    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO POST
    char inicio_0[MAX] = "POST http://192.168.0.2/Login.htm ";
    char inicio_1[MAX] = "Host: 192.168.0.2\r\n";
    char inicio_2[MAX] = "User-Agent: InternetExplorer/11.0\r\n";
    char inicio_3[MAX] = "Accept: text/html\r\n";
    char inicio_4[MAX] = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    char inicio_5[MAX] = "Accept-Encoding: gzip, deflate\r\n";
    char inicio_6[MAX] = "Content-Type: application/x-www-form-urlencoded\r\n";
    char inicio_7[MAX] = "Content-Length: 44\r\n";
    char inicio_8[MAX] = "Connection: keep-alive\r\n";
    char inicio_9[MAX] = "Upgrade-Insecure-Requests: 1\r\n";
    char inicio_10[MAX] = "Pragma: no-cache\r\n";
    char inicio_11[MAX] = "Cache-Control: no-cache\r\n";
    char inicio_12[MAX] = "command=login&username=admin&password=admin";
    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_13[MAX] = " HTTP/1.1\r\n";
    char inicio_14[MAX]  = "Host: ";
    char inicio_15[MAX]  = "\r\n\r\n";
    char inicio_16[MAX]  = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX]  = " Keep-Alive: 300\r\n";

    ///-------------------------------------------------------------------------------------------

    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "192.168.0.2";
        ///char ss[17];
        ///FILE *pp;
        ///char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///fscanf(pp, "%s", aa);
        ///printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        ///fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        strcat(inicio_1, inicio_2);  // USER-AGENT
        strcat(inicio_1, inicio_3);  // ACCEPT
        strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        strcat(inicio_1, inicio_8);  // CONNECTION
        strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        strcat(inicio_1, inicio_10); // PROGMA
        strcat(inicio_1, inicio_11); // CACHE-CONTROL
        strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        strcat(inicio_1, inicio_13); // HTTP/1.1
        strcat(inicio_1, inicio_14); // HOST
        strcat(inicio_1, inicio_15); // \R\N\R\N
        //strcat(inicio_1, inicio_16); // CONNECTION
        //strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        ///char aa[50] = "192.168.0.2";
        ///char ss[17];
        ///FILE *pp;
        ///char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///printf( "%s\n", aa);
        ///strcat(inicio_1, inicio_14);
        ///strcat(inicio_1, aa);
        ///strcat(inicio_1, inicio_15);
        ///strcat(inicio_1, inicio_16);
        ///strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << inicio_x;
//        fclose(pp);
    }
}
// TESTE DVR RECEBE 100% FUNCIONAL
void REQUISICAO_GET1(){

   /// CABEÇARIO DE RECEPÇÃO GET
   /*
    POST http://192.168.0.2/Login.htm
    Host: 192.168.0.2
    User-Agent: Mozilla/5.0
    Accept: text/html
    Accept-Language: pt-BR,pt
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 44
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Pragma: no-cache
    Cache-Control: no-cache
    Origin: http://192.168.0.2
    command=login&username=admin&password=admin
    Host: 192.168.0.2

    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
    Accept: * /*
    Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
    Accept-Encoding: gzip, deflate
    Connection: keep-alive
    Referer: http://192.168.0.2/Login.htm
    Cookie: hibext_instdsigdipv2=1; NetSuveillanceWebCookie=%7B%22username%22%3A%22admin%22%7D
    Pragma: no-cache
    Cache-Control: no-cache

    */

    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO GET
    char inicio_0 [MAX] = "POST http://192.168.0.2/English.js ";
    char inicio_1 [MAX] = "Host: 192.168.0.2\r\n";
    char inicio_2 [MAX] = "User-Agent: InternetExplorer/11.0\r\n";
    char inicio_3 [MAX] = "Accept: text/html\r\n"; ///"Accept: text/html\r\n"; //Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
    char inicio_4 [MAX] = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    char inicio_5 [MAX] = "Accept-Encoding: gzip, deflate\r\n";
    char inicio_6 [MAX] = "Content-Type: application/x-www-form-urlencoded\r\n";
    char inicio_7 [MAX] = "Content-Length: 44\r\n";
    char inicio_8 [MAX] = "Referer: http://192.168.0.2/Login.htm\r\n";
    char inicio_9 [MAX] = "Upgrade-Insecure-Requests: 1\r\n";
    char inicio_10[MAX] = "Pragma: no-cache\r\n";
    char inicio_11[MAX] = "Cache-Control: no-cache\r\n";
    char inicio_12[MAX] = "Cookie: hibext_instdsigdipv2=1; NetSuveillanceWebCookie=%7B%22username%22%3A%22admin%22%7D";

    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_13[MAX] = " HTTP/1.1\r\n";
    char inicio_14[MAX] = "Host: ";
    char inicio_15[MAX] = "\r\n\r\n";
    char inicio_16[MAX] = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX] = " Keep-Alive: 300\r\n";
    ///-------------------------------------------------------------------------------------------

    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "192.168.0.2";
        //char ss[17];
        //FILE *pp;
        //char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        //pp = fopen(ss,"r");
        //pp = fopen(uu, (ss, "r"));
        //fscanf(pp, "%s", aa);
        printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        //fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        strcat(inicio_1, inicio_2);  // USER-AGENT
        strcat(inicio_1, inicio_3);  // ACCEPT
        strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        strcat(inicio_1, inicio_8);  // CONNECTION
        //strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        //strcat(inicio_1, inicio_10); // PROGMA
        //strcat(inicio_1, inicio_11); // CACHE-CONTROL
        //strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        strcat(inicio_1, inicio_13); // HTTP/1.1
        strcat(inicio_1, inicio_14); // HOST
        strcat(inicio_1, inicio_15); // \R\N\R\N
        strcat(inicio_1, inicio_16); // CONNECTION
        strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        //char aa[50] = "192.168.0.2";
        //char ss[17];
        //FILE *pp;
        //char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        //pp = fopen(ss,"r");
        //pp = fopen(uu, (ss, "r"));
        //printf( "%s\n", aa);
        //strcat(inicio_1, inicio_14);
        //strcat(inicio_1, aa);
        //strcat(inicio_1, inicio_15);
        //strcat(inicio_1, inicio_16);
        //strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << "------------------------------------------------------------------" << endl;
        cout << inicio_x << endl;
        cout << "------------------------------------------------------------------" << endl;
        //fclose(pp);
    }

}
// TESTE DVR ENVISO 100% FUNCIONAL
void REQUISICAO_POST1(){
    /// CABEÇARIO DE ENVIO POST
    /*
    POST http://192.168.0.2/Login.htm
    Host: 192.168.0.2
    User-Agent: Mozilla/5.0
    Accept: text/html
    Accept-Language: pt-BR,pt
    Accept-Encoding: gzip, deflate
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 44
    Connection: keep-alive
    Upgrade-Insecure-Requests: 1
    Pragma: no-cache
    Cache-Control: no-cache
    Origin: http://192.168.0.2
    command=login&username=admin&password=admin
    */

    int a = 1;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// CABECARIO DE REQUISIÇÃO POST
    char inicio_0[MAX] = "POST http://192.168.0.2/English.js ";
    char inicio_1[MAX] = "Host: 192.168.0.2\r\n";
    char inicio_2[MAX] = "User-Agent: InternetExplorer/11.0\r\n";
    char inicio_3[MAX] = "Accept: text/html\r\n";
    char inicio_4[MAX] = "Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3\r\n";
    char inicio_5[MAX] = "Accept-Encoding: gzip, deflate\r\n";
    char inicio_6[MAX] = "Content-Type: application/x-www-form-urlencoded\r\n";
    char inicio_7[MAX] = "Content-Length: 44\r\n";
    char inicio_8[MAX] = "Referer: http://192.168.0.2/Login.htm\r\n";
    char inicio_9[MAX] = "Upgrade-Insecure-Requests: 1\r\n";
    char inicio_10[MAX] = "Pragma: no-cache\r\n";
    char inicio_11[MAX] = "Cache-Control: no-cache\r\n";
    char inicio_12[MAX] = "Cookie: hibext_instdsigdipv2=1; NetSuveillanceWebCookie=%7B%22username%22%3A%22admin%22%7D";
    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_13[MAX] = " HTTP/1.1\r\n";
    char inicio_14[MAX]  = "Host: ";
    char inicio_15[MAX]  = "\r\n\r\n";
    char inicio_16[MAX]  = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX]  = " Keep-Alive: 300\r\n";

    ///-------------------------------------------------------------------------------------------

    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char *aa = "192.168.0.2";
        ///char ss[17];
        ///FILE *pp;
        ///char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///fscanf(pp, "%s", aa);
        ///printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        ///fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_0);  // POST HOST
        strcat(inicio_1, inicio_2);  // USER-AGENT
        strcat(inicio_1, inicio_3);  // ACCEPT
        strcat(inicio_1, inicio_4);  // ACCEPT-LANGUAGER
        strcat(inicio_1, inicio_5);  // ACCEPT-ENCODING
        strcat(inicio_1, inicio_6);  // CONTENT-TYPE
        strcat(inicio_1, inicio_7);  // CONTENT-LENGTH
        strcat(inicio_1, inicio_8);  // CONNECTION
        strcat(inicio_1, inicio_9);  // UPGRADE-INSEGURE-REQUISIT
        strcat(inicio_1, inicio_10); // PROGMA
        strcat(inicio_1, inicio_11); // CACHE-CONTROL
        strcat(inicio_1, inicio_12); /// COMANDO DE INSERÇÃO DE DADOS NO POST
        strcat(inicio_1, inicio_13); // HTTP/1.1
        strcat(inicio_1, inicio_14); // HOST
        strcat(inicio_1, inicio_15); // \R\N\R\N
        //strcat(inicio_1, inicio_16); // CONNECTION
        //strcat(inicio_1, inicio_17); // KEEP-ALEVE
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        ///char aa[50] = "192.168.0.2";
        ///char ss[17];
        ///FILE *pp;
        ///char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        ///pp = fopen(ss,"r");
        ///pp = fopen(uu, (ss, "r"));
        ///printf( "%s\n", aa);
        ///strcat(inicio_1, inicio_14);
        ///strcat(inicio_1, aa);
        ///strcat(inicio_1, inicio_15);
        ///strcat(inicio_1, inicio_16);
        ///strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << inicio_x;
//        fclose(pp);
    }
}
// PESQUISA GOOGLE GERAL
void PESQUISA_GOOGLE_GERAL(){

    /// PESQUISA GOOGLE IMAGENS

    int a = 1, l, i;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// PESQUISA GOOGLE GERAL
    char inicio_0[100];  // MINHA PESQUISA 0 // MINHA PESQUISA TRATADA COM + tive que definir um numero pq o MAX estava trazendo lixo na minha pesquisa
    char inicio_1[MAX] = "GET /";
    char inicio_2[MAX] = "/search?newwindow=1";
    char inicio_3[MAX] = "&source=hp";
    char inicio_4[MAX] = "&ei=";
    char inicio_5[MAX] = "4d1pXfzRG9fA5OUPqeS0-AU";
    char inicio_6[MAX] = "&q=";
    char inicio_7[50];   //MINHA PESQUISA 1 // MINHA PESQUISA TRATADA COM + tive que definir um numero pq o MAX estava trazendo lixo na minha pesquisa
    char inicio_8[MAX] = "&oq=";
    char inicio_9[50];   //MINHA PESQUISA 2 // MINHA PESQUISA TRATADA COM + tive que definir um numero pq o MAX estava trazendo lixo na minha pesquisa
    char inicio_10[MAX] = "&gs_l=psy-ab";
    char inicio_11[MAX] = ".3..0l10.56315.56944..58087...0.0..0.251.1041.0j5j1......0....1..gws-wiz.....0..0i131.W_DAVf_f25c";
    char inicio_12[MAX] = "&ved=0ahUKEwi8xoWviqzkAhVXILkGHSkyDV8Q4dUDCAU&uact=5";
    char inicio_13[MAX] = " HTTP/1.1\r\n";

    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_14[MAX]  = "Host: ";
    char inicio_15[MAX]  = "\r\n\r\n";
    char inicio_16[MAX]  = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX]  = " Keep-Alive: 300\r\n";

    ///-------------------------------------------------------------------------------------------
    /// COMPLEMENTAR NA ESTRUTURA DE TRATAMENTO DA STRING

    /// PESQUISA DO GOOGLE
    system("cls");
    printf("Digte a sua pesquisa: ");
    /// DIGITAR A PASQUISA EM FORMA DE STRING
    gets(inicio_0);
    i = strlen(inicio_0);

    /// TRATAMENTO DE STRING PARA ACRECENTRAR O SINAL DE MAIS "+"
    for(l=0; l<=i; l++)
    {
        //if(inicio_0[l] == '+') para acrecentar o sinal + na pesquisa requer a quebra e construçao da string com stcat();
        //{
        //    inicio_0[l] = '%2B';
        //}else
        if(inicio_0[l] == ' ')
        {
            inicio_0[l] = '+';
        }
        printf("%c", inicio_0[l]);
    }
    /// UNIFICAR A MATRIZ E TRASFORMAR E STRING NOVAMENTE PARA PESQUISA
    strcat(inicio_7, inicio_0);
    printf("\n");
    printf("|%s|\n", inicio_7);
    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char aa[0];
        char ss[17];
        FILE *pp;
        char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        pp = fopen(ss,"r");
        pp = fopen(uu, (ss, "r"));
        fscanf(pp, "%s", aa);
        printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_2);  /// GET /
        strcat(inicio_1, inicio_3);  //
        strcat(inicio_1, inicio_4);  //
        strcat(inicio_1, inicio_5);  //
        strcat(inicio_1, inicio_6);  //
        strcat(inicio_1, inicio_7);  /// MINHA PESQUISA 1
        strcat(inicio_1, inicio_8);  //
        strcat(inicio_1, inicio_7);  /// MINHA PESQUISA 2
        strcat(inicio_1, inicio_10); //
        strcat(inicio_1, inicio_11); //
        strcat(inicio_1, inicio_12); //
        strcat(inicio_1, inicio_13); /// HTTP/1.1
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        char aa[0];
        char ss[17];
        FILE *pp;
        char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        pp = fopen(ss,"r");
        pp = fopen(uu, (ss, "r"));
        fscanf(pp, "%[^\n]s", aa);
        strcat(inicio_1, inicio_14);
        strcat(inicio_1, aa);
        strcat(inicio_1, inicio_15);
        strcat(inicio_1, inicio_16);
        strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << inicio_x;
        fclose(pp);
    }
}
// PESQUISA GOOGLE IMAGEM
void PESQUISA_GOOGLE_IMAGEM(){

    /// PESQUISA GOOGLE IMAGENS

    int a = 1, l, i;
    /// DEFINIR O IP
    int seleciona_ip=1;

    ///-------------------------------------------------------------------------------------------
    /// PESQUISA GOOGLE IMAGEM
    char inicio_0[100];  // MINHA PESQUISA 0 // MINHA PESQUISA TRATADA COM + tive que definir um numero pq o MAX estava trazendo lixo na minha pesquisa
    char inicio_1[MAX] = "GET /";
    char inicio_2[MAX] = "/search?newwindow=1";
    char inicio_3[MAX] = "&client=firefox-b-d&biw=1354";
    char inicio_4[MAX] = "&bih=625&tbm=isch&sa=1&ei=";
    char inicio_5[MAX] = "u7dQXcnKG9HV5OUPg7eDmAw";
    char inicio_6[MAX] = "&q=";
    char inicio_7[50];   //MINHA PESQUISA 1 // MINHA PESQUISA TRATADA COM + tive que definir um numero pq o MAX estava trazendo lixo na minha pesquisa
    char inicio_8[MAX] = "&oq=";
    char inicio_9[50];   //MINHA PESQUISA 2 // MINHA PESQUISA TRATADA COM + tive que definir um numero pq o MAX estava trazendo lixo na minha pesquisa
    char inicio_10[MAX] = "&gs_l=img";
    char inicio_11[MAX] = ".3.0.0i7i30l10.21794.23098..25097...0.0..0.226.563.0j2j1......0....1..gws-wiz-img.";
    char inicio_12[MAX] = "nk-wQaaY7ck";
    char inicio_13[MAX] = " HTTP/1.1\r\n";

    /// PARA FAZER O DOWNLOAD DO SITE E CONTEUDOS
    char inicio_14[MAX]  = "Host: ";
    char inicio_15[MAX]  = "\r\n\r\n";
    char inicio_16[MAX]  = " Connection: keep-alive\r\n\r\n";
    char inicio_17[MAX]  = " Keep-Alive: 300\r\n";
    ///-------------------------------------------------------------------------------------------

    ///-------------------------------------------------------------------------------------------
    /// COMPLEMENTAR NA ESTRUTURA DE TRATAMENTO DA STRING

    /// PESQUISA DO GOOGLE
    system("cls");
    printf("Digte a sua pesquisa: ");
    /// DIGITAR A PASQUISA EM FORMA DE STRING
    gets(inicio_0);
    i = strlen(inicio_0);

    /// TRATAMENTO DE STRING PARA ACRECENTRAR O SINAL DE MAIS "+"
    for(l=0; l<=i; l++)
    {
        //if(inicio_0[l] == '+') para acrecentar o sinal + na pesquisa requer a quebra e construçao da string com stcat();
        //{
        //    inicio_0[l] = '%2B';
        //}else
        if(inicio_0[l] == ' ')
        {
            inicio_0[l] = '+';
        }
        printf("%c", inicio_0[l]);
    }
    /// UNIFICAR A MATRIZ E TRASFORMAR E STRING NOVAMENTE PARA PESQUISA
    strcat(inicio_7, inicio_0);
    printf("\n");
    printf("|%s|\n", inicio_7);
    printf("\n\n");

    /// IP COLETADO DO CONSOLE OU SCANIAMENTO EXTERNO OU "INTERNO SERVER"
    if(seleciona_ip == 1)
    {
        char aa[0];
        char ss[17];
        FILE *pp;
        char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\IP.txt";
        pp = fopen(ss,"r");
        pp = fopen(uu, (ss, "r"));
        fscanf(pp, "%s", aa);
        printf("\nIP OU SITE REQUISITADO!\n");
        printf("\n%s\n\n", aa);
        MAX_TAM_GET2 = aa;
        fclose(pp);

    }

    if(a == 1)
    {
        ///-------------------------------------------------------------------------------------------
        /// MONTAGEM DE ESTRUTURA DE SOLICITAÇÃO GET EM HTTP V 1.1
        strcat(inicio_1, inicio_2);  /// GET /
        strcat(inicio_1, inicio_3);  //
        strcat(inicio_1, inicio_4);  //
        strcat(inicio_1, inicio_5);  //
        strcat(inicio_1, inicio_6);  //
        strcat(inicio_1, inicio_7);  /// MINHA PESQUISA 1
        strcat(inicio_1, inicio_8);  //
        strcat(inicio_1, inicio_7);  /// MINHA PESQUISA 2
        strcat(inicio_1, inicio_10); //
        strcat(inicio_1, inicio_11); //
        strcat(inicio_1, inicio_12); //
        strcat(inicio_1, inicio_13); /// HTTP/1.1
        ///-------------------------------------------------------------------------------------------

    }

    /// CHAMADA O CAMINHO DO SITE PARA MONTAGEM DA REQUISIÇÃO
    /// CHAMA O SITE PARA MONTAGEM DA REQUISIÇÃO
    if(a == 1)
    {
        char aa[0];
        char ss[17];
        FILE *pp;
        char uu [] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE.txt";
        pp = fopen(ss,"r");
        pp = fopen(uu, (ss, "r"));
        fscanf(pp, "%[^\n]s", aa);
        strcat(inicio_1, inicio_14);
        strcat(inicio_1, aa);
        strcat(inicio_1, inicio_15);
        strcat(inicio_1, inicio_16);
        strcat(inicio_1, inicio_17);
        inicio_x = inicio_1;
        cout << inicio_x;
        fclose(pp);
    }

}
// PESQUISA GOOGLE METODOS V1
void PESQUISA_GOOGLE(){

    ///-------------------------------------------------------------------------------------------
    WSADATA wsa;
    SOCKET socket_desc;
    struct sockaddr_in server;
    char *message, server_reply[90000];
    int recv_size;
    int contador=0;
    int total_len = 0;
    int file_len = 99352;
    int len;
    FILE *file = NULL;

    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("FALHA NO CODIGO : %d",WSAGetLastError());
        printf("erro linha 134\n");
    }

    if((socket_desc = socket(AF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET)
    {
        printf("ERRO NA CRIACAO DO SOCKTES: %d\n", WSAGetLastError());
        printf("erro linha 141\n");
    }

    server.sin_addr.s_addr  = inet_addr(MAX_TAM_GET2);
    server.sin_family =  AF_INET;
    server.sin_port = htons( 80 );

    ///ERRO DE CONECSÃO
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        puts("ERRO DE CONECSAO\n");
        printf("erro linha 170\n");
    }

    /// TRASFERE O CONTEUDO DE INICIO_1 PARA MESSAGE
    // CONTEUDO DE REQUISIÇÃO DO SERVIDO GET / HTTP 1.1/
    message = inicio_x;
    printf("%s\n", message);

    /// FALAH NA CHAMADA DE MSG
    if( send(socket_desc, message, strlen(message), 0) < 0)
    {
        puts("FALHA NA CHAMADA DE MSG");
        printf("erro linha 183\n");
    }

    char *filename = "T:\\PESQUISA_GOOGLE_CPP_V2\\PESQUISA_GOOGLE.html";
    remove(filename);
    file = fopen(filename, "a");

    puts("Data Send");
    ///Receive a reply from the server
    if((recv_size = recv(socket_desc, server_reply, 1, 0)) == SOCKET_ERROR)
    {
        puts("recv failed");
        MAX_TAM_GET2 = NULL;
        printf("erro linha 194\n");
    }

    /// PONTEIRO DE DADOS
    MAX_TAM_GET2 = (server_reply);

    while(1)
    {
        int received_len = recv(socket_desc, server_reply , sizeof server_reply , 0);
        if( received_len < 0 ){
            break;
        }

        total_len += received_len;
        fwrite(server_reply , received_len , 1, file);

        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);

        if( total_len >= file_len ){
        }
        if(received_len == 0)
        {
            contador++;
            if(contador == 3)
            {
                break;
            }
        }
    }

    puts("Reply received\n");
    fclose(file);

    printf("\n=========================================================\n");
    if(MAX_TAM_GET2 == NULL)
    {
        printf("Erro sem retorno linha 207\n");
    }
    else
    {
        printf("OK\n");
        printf("Funcional \n\n");
        system("pause");
        system("cls");
        puts(MAX_TAM_GET2);
    }
}
// PESQUISA GOOGLE METODO PORTA 80
void PESQUISA_GOOGLE_80(){
    ///-------------------------------------------------------------------------------------------
    WSADATA wsa;
    SOCKET socket_desc;
    struct sockaddr_in server;
    char *message, server_reply[90000];
    int recv_size;
    int contador=0;
    int total_len = 0;
    int file_len = 99352;
    int len;
    FILE *file = NULL;

    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("FALHA NO CODIGO : %d",WSAGetLastError());
        printf("erro linha 134\n");
    }

    if((socket_desc = socket(AF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET)
    {
        printf("ERRO NA CRIACAO DO SOCKTES: %d\n", WSAGetLastError());
        printf("erro linha 141\n");
    }

    server.sin_addr.s_addr  = inet_addr(MAX_TAM_GET2);
    server.sin_family =  AF_INET;
    server.sin_port = htons( 80 );

    ///ERRO DE CONECSÃO
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        puts("ERRO DE CONECSAO\n");
        printf("erro linha 170\n");
    }

    /// TRASFERE O CONTEUDO DE INICIO_1 PARA MESSAGE
    // CONTEUDO DE REQUISIÇÃO DO SERVIDO GET / HTTP 1.1/
    message = inicio_x;
    printf("%s\n", message);

    /// FALAH NA CHAMADA DE MSG
    if( send(socket_desc, message, strlen(message), 0) < 0)
    {
        puts("FALHA NA CHAMADA DE MSG");
        printf("erro linha 183\n");
    }

    char *filename = "T:\\PESQUISA_GOOGLE_CPP_V2\\PESQUISA_GOOGLE.html";
    remove(filename);
    file = fopen(filename, "a");

    puts("Data Send");
    ///Receive a reply from the server
    if((recv_size = recv(socket_desc, server_reply, 1, 0)) == SOCKET_ERROR)
    {
        puts("recv failed");
        MAX_TAM_GET2 = NULL;
        printf("erro linha 194\n");
    }

    /// PONTEIRO DE DADOS
    MAX_TAM_GET2 = (server_reply);

    while(1)
    {
        int received_len = recv(socket_desc, server_reply , sizeof server_reply , 0);
        if( received_len < 0 ){
            break;
        }

        total_len += received_len;
        fwrite(server_reply , received_len , 1, file);

        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);

        if( total_len >= file_len ){
        }
        if(received_len == 0)
        {
            contador++;
            if(contador == 3)
            {
                break;
            }
        }
    }

    puts("Reply received\n");
    fclose(file);

    printf("\n=========================================================\n");
    if(MAX_TAM_GET2 == NULL)
    {
        printf("Erro sem retorno linha 207\n");
    }
    else
    {
        printf("OK\n");
        printf("Funcional \n\n");
        system("pause");
        system("cls");
        puts(MAX_TAM_GET2);
    }

}
/// NÃO IMPLEMENTADO UTILIZAR OPENSSL PARA FAZER REQUISIÇÃO COM CERTIFICADOS DE SEGURANÇA
void PESQUISA_GOOGLE_443(){

    ///-------------------------------------------------------------------------------------------
    WSADATA wsa;
    SOCKET socket_desc;
    struct sockaddr_in server;
    char *message, server_reply[90000];
    int recv_size;
    int contador=0;
    int total_len = 0;
    int file_len = 99352;
    int len;
    FILE *file = NULL;

    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("FALHA NO CODIGO : %d",WSAGetLastError());
        printf("erro linha 134\n");
    }

    if((socket_desc = socket(AF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET)
    {
        printf("ERRO NA CRIACAO DO SOCKTES: %d\n", WSAGetLastError());
        printf("erro linha 141\n");
    }

    server.sin_addr.s_addr  = inet_addr(MAX_TAM_GET2);
    server.sin_family =  AF_INET;
    server.sin_port = htons( 443 );

    ///ERRO DE CONECSÃO
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        puts("ERRO DE CONECSAO\n");
        printf("erro linha 170\n");
    }

    /// TRASFERE O CONTEUDO DE INICIO_1 PARA MESSAGE
    // CONTEUDO DE REQUISIÇÃO DO SERVIDO GET / HTTP 1.1/
    message = inicio_x;
    printf("%s\n", message);

    /// FALAH NA CHAMADA DE MSG
    if( send(socket_desc, message, strlen(message), 0) < 0)
    {
        puts("FALHA NA CHAMADA DE MSG");
        printf("erro linha 183\n");
    }

    char *filename = "T:\\PESQUISA_GOOGLE_CPP_V2\\PESQUISA_GOOGLE.html";
    remove(filename);
    file = fopen(filename, "a");

    puts("Data Send");
    ///Receive a reply from the server
    if((recv_size = recv(socket_desc, server_reply, 1, 0)) == SOCKET_ERROR)
    {
        puts("recv failed");
        MAX_TAM_GET2 = NULL;
        printf("erro linha 194\n");
    }

    /// PONTEIRO DE DADOS
    MAX_TAM_GET2 = (server_reply);

    while(1)
    {
        int received_len = recv(socket_desc, server_reply , sizeof server_reply , 0);
        if( received_len < 0 ){
            break;
        }

        total_len += received_len;
        fwrite(server_reply , received_len , 1, file);

        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);

        if( total_len >= file_len ){
        }
        if(received_len == 0)
        {
            contador++;
            if(contador == 3)
            {
                break;
            }
        }
    }

    puts("Reply received\n");
    fclose(file);

    printf("\n=========================================================\n");
    if(MAX_TAM_GET2 == NULL)
    {
        printf("Erro sem retorno linha 207\n");
    }
    else
    {
        printf("OK\n");
        printf("Funcional \n\n");
        system("pause");
        system("cls");
        puts(MAX_TAM_GET2);
    }


}
// TRATAEMNTO DE ARQUIVOS AUXILIAR
void DOWNLOAD_ARQUIVOS(){


    //char *filename = "T:\\PESQUISA_GOOGLE\\PESQUISA_GOOGLE.html";
    //172.217.30.36
    //t0.gstatic.com
    //images?q=tbn:ANd9GcRxLZ-gyloxhXBtYDAWlyNyw1NokViCHU9WSlFD4kHx-ZZdbTs-XvbhrIAeZg

    /// CABEÇARIO DE SOLICITAÇÃO GET
    char inicio_1[MAX] = "GET /";
    char inicio_2[MAX] = " HTTP/1.1\r\n";
    char inicio_3[MAX] = "Host: ";
    char inicio_4[MAX] = "\r\n\r\n";
    char inicio_5[MAX] = " Connection: keep-alive\r\n\r\n";
    char inicio_6[MAX] = " Keep-Alive: 300\r\n";
    char url[100] = "images?q=tbn:ANd9GcRxLZ-gyloxhXBtYDAWlyNyw1NokViCHU9WSlFD4kHx-ZZdbTs-XvbhrIAeZg";
    char site[50] = "t0.gstatic.com";

    /// COSNTRUÇÃO DA SOLICITAÇÃO DO GET
    strcat(inicio_1, url);
    strcat(inicio_1, inicio_2);
    strcat(inicio_1, inicio_3);
    strcat(inicio_1, site);
    strcat(inicio_1, inicio_4);
    strcat(inicio_1, inicio_5);
    strcat(inicio_1, inicio_6);


    ///-------------------------------------------------------------------------------------------
    WSADATA wsa;
    SOCKET socket_desc;
    struct sockaddr_in server;
    char *message, server_reply[90000];
    int recv_size;
    int contador=0;
    int total_len = 0;
    int file_len = 99352;
    int len;
    FILE *file = NULL;
    FILE *file1 = NULL;

    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("FALHA NO CODIGO : %d",WSAGetLastError());
        printf("erro linha 134\n");
    }

    if((socket_desc = socket(AF_INET, SOCK_STREAM, 0 )) == INVALID_SOCKET)
    {
        printf("ERRO NA CRIACAO DO SOCKTES: %d\n", WSAGetLastError());
        printf("erro linha 141\n");
    }

    server.sin_addr.s_addr  = inet_addr("172.217.30.36");
    server.sin_family =  AF_INET;
    server.sin_port = htons( 80 );

    ///ERRO DE CONECSÃO
    if (connect(socket_desc, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        puts("ERRO DE CONECSAO\n");
        printf("erro linha 170\n");
    }

    /// TRASFERE O CONTEUDO DE INICIO_1 PARA MESSAGE
    // CONTEUDO DE REQUISIÇÃO DO SERVIDO GET / HTTP 1.1/
    message = inicio_1;
    printf("--%s\n", message);

    /// FALAH NA CHAMADA DE MSG
    if( send(socket_desc, message, strlen(message), 0) < 0)
    {
        puts("FALHA NA CHAMADA DE MSG");
        printf("erro linha 183\n");
    }
    char *filename1 = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\LIXO.jpg";
    remove(filename1);
    file1 = fopen(filename1, "ab");

    char *filename = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\IMAGEM01.jpg";
    remove(filename);
    file = fopen(filename, "ab");

    puts("Data Send");
    ///Receive a reply from the server
    if((recv_size = recv(socket_desc, server_reply, 366, 0)) == SOCKET_ERROR)
    {
        puts("recv failed");
        MAX_TAM_GET2 = NULL;
        printf("erro linha 194\n");
    }

    /// PONTEIRO DE DADOS
    MAX_TAM_GET2 = (server_reply);

    while(1)
    {

        int received_len = recv(socket_desc, server_reply , sizeof 1 , 0);
        if( received_len < 0 ){ break; }
        total_len += received_len;
        fwrite(server_reply , received_len , 1, file);
        printf("\nReceived byte size = %d\nTotal lenght = %d", received_len, total_len);
        if( total_len >= file_len ){    }
        if(received_len == 0){
            contador++;
            if(contador == 3){ break; }
        }

    }

    puts("Arquivo Recebido com Sucesso! \n");
    fclose(file);

    printf("\n=========================================================\n");
    if(MAX_TAM_GET2 == NULL)
    {printf("Erro sem retorno linha 207\n");}
    else
    {
        printf("Funcional \n\n");
        system("pause");
        puts(MAX_TAM_GET2);
    }
}
// TRATAEMNTO DE URL AUXILIAR 1
void TRATAMENTO_HTML_URL(){

    printf("\n\n======================================================================\n\n");
    int  i , l;
    int  cont = 1;
    int *matrix_1;
    bool ativador = false;
    char urls[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\URL.txt";
    char ch;
    FILE *arqs;
    arqs = fopen(urls, "a");

    matrix_1 = (int*)malloc(sizeof(int)*90000);

    i = strlen(MAX_TAM_GET2);
    for(l=0; l<=i; l++)
    {
    matrix_1[l] = MAX_TAM_GET2[l];
    ///printf("%c", matrix_1[l]);
    }

    for(l=0; l<=i; l++)
    {

        ///LINK PARA DOWNLOAD IMAGEM INICIO
        //src="http://  images?q=t
        if(matrix_1[l]   == 'i'  && matrix_1[l+1] == 'm' && matrix_1[l+2] == 'a'
        && matrix_1[l+3] == 'g'  && matrix_1[l+4] == 'e' && matrix_1[l+5] == 's'
        && matrix_1[l+6] == '?'  && matrix_1[l+7] == 'q' && matrix_1[l+8] == '='
        && matrix_1[l+9] == 't'){
        printf("\n##################| INICIO DO LINK URL |##################\n");
        ativador = true;

        }else

        ///LINK PARA DOWNLOAD IMAGEM FIM
        //" width="  images?q=t
        if(matrix_1[l]   == '"' && matrix_1[l+1] == ' '  && matrix_1[l+2] == 'w'
        && matrix_1[l+3] == 'i' && matrix_1[l+4] == 'd'  && matrix_1[l+5] == 't'
        && matrix_1[l+6] == 'h' && matrix_1[l+7] == '='  && matrix_1[l+8] == '"'){
        printf("\n##################|   FIM  DO LINK URL |##################\n");
        ativador = false;
        ch = '\n';
        fprintf(arqs, "%c", ch );
        }//if

        if(ativador == true)
        {
            if(matrix_1[l] == '/'){
                matrix_1[l] = ' ';
                printf("%c", matrix_1[l]);
                fprintf(arqs, "%c", matrix_1[l] );
            }else
                printf("%c", matrix_1[l]);
                fprintf(arqs, "%c", matrix_1[l] );
        }
    }

}
// TRATAEMNTO DE SITE AUXILIAR 2
void TRATAMENTO_HTML_SITE(){

    printf("\n\n======================================================================\n\n");
    int  i , l;
    int  cont = 1;
    int *matrix_1;
    bool ativador = false;
    char urls[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\SITE.txt";
    char ch;
    FILE *arqs;
    arqs = fopen(urls, "a");

    matrix_1 = (int*)malloc(sizeof(int)*90000);

    i = strlen(MAX_TAM_GET2);
    for(l=0; l<=i; l++)
    {
        matrix_1[l] = MAX_TAM_GET2[l];
        ///printf("%c", matrix_1[l]);
    }

    for(l=0; l<=i; l++)
    {
        ///LINK PARA DOWNLOAD IMAGEM INICIO //src="http://  http://
        if(matrix_1[l-9] == 'r' && matrix_1[l-8] == 'c'
        && matrix_1[l-7] == '=' && matrix_1[l-6] == '"'  && matrix_1[l-5] == 'h'
        && matrix_1[l-4] == 't' && matrix_1[l-3] == 't'  && matrix_1[l-2] == 'p'
        && matrix_1[l-1] == ':' && matrix_1[l]   == '/'  && matrix_1[l+1] == '/'){
        printf("\n##################| INICIO DO LINK SITE |##################\n");
        ativador = true;
        }else

        ///LINK PARA DOWNLOAD IMAGEM FIM  //" width="  images?q=t
        if(matrix_1[l]   == '/' && matrix_1[l+1] == 'i'  && matrix_1[l+2] == 'm'
        && matrix_1[l+3] == 'a' && matrix_1[l+4] == 'g'  && matrix_1[l+5] == 'e'
        && matrix_1[l+6] == 's' && matrix_1[l+7] == '?'  && matrix_1[l+8] == 'q'
        && matrix_1[l+9] == '='){
        printf("\n##################|   FIM  DO LINK SITE |##################\n");
        ativador = false;
        cont = cont++;
        ch = '\n';
        fprintf(arqs, "%c", ch );
        }//if

        if(ativador == true)
        {
            if(matrix_1[l] == '/'){
                matrix_1[l] = ' ';
                printf("%c", matrix_1[l]);
                fprintf(arqs, "%c", matrix_1[l] );
            }else
                printf("%c", matrix_1[l]);
                fprintf(arqs, "%c", matrix_1[l] );
        }
    }

}
// TRATAEMNTO DE INPUT AUXILIAR
void TRATAMENTO_HTML_INPUT(){

    printf("\n\n======================================================================\n\n");
    int  i , l;
    int  cont = 1;
    int *matrix_1;
    bool ativador = false;
    char urls[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\IMPUT.txt";
    char ch;
    FILE *arqs;
    arqs = fopen(urls, "a");

    matrix_1 = (int*)malloc(sizeof(int)*90000);

    i = strlen(MAX_TAM_GET2);
    for(l=0; l<=i; l++)
    {
        matrix_1[l] = MAX_TAM_GET2[l];
        ///printf("%c", matrix_1[l]);
    }

    for(l=0; l<=i; l++)
    {
        ///LINK PARA DOWNLOAD IMAGEM INICIO //src="http://  http://
        if(matrix_1[l-6] == '<' && matrix_1[l-5] == 'i'&& matrix_1[l-4] == 'n'
        && matrix_1[l-3] == 'p'  && matrix_1[l-2] == 'u'
        && matrix_1[l-1] == 't' && matrix_1[l] == ' '  ){
        printf("\n##################| INICIO DO LINK IMPUT |##################\n");
        ativador = true;
        }else

        ///LINK PARA DOWNLOAD IMAGEM FIM  //" width="  images?q=t
        if(matrix_1[l]   == '>' ){
        printf("\n##################|   FIM  DO LINK IMPUT |##################\n");
        ativador = false;
        cont = cont++;
        ch = '\n';
        fprintf(arqs, "%c", ch );
        }//if

        if(ativador == true)
        {
            if(matrix_1[l] == '/'){
                matrix_1[l] = ' ';
                printf("%c", matrix_1[l]);
                fprintf(arqs, "%c", matrix_1[l] );
            }else
                printf("%c", matrix_1[l]);
                fprintf(arqs, "%c", matrix_1[l] );
        }
    }

}
// TRATAEMNTO DE FUNÇOSE AUXILIAR
void TRATAMENTO_HTML_FUNCOES(){

    printf("\n\n======================================================================\n\n");
    int  i , l, a, loop;
    int *matriz, *mat;
    bool ativador = false;


    matriz = (int*)malloc(sizeof(int)*90000);
    mat    = (int*)malloc(sizeof(int)*90000);

    i = strlen(MAX_TAM_GET2);
    for(l=0,a=1; l<=i; l++, a++)
    {
        matriz[l] = MAX_TAM_GET2[l];
        mat[l] = MAX_TAM_GET2[a];
        ///printf("%c", matriz[l]);
    }

    for(loop=0;loop <= i;loop++)
    {

        if(matriz[loop] == '<')
        {
            /// CABEÇARIO DOCTYPE <!doctype> </!doctype>
            if(matriz[loop+1] == '!' && matriz[loop+2] == 'd' && matriz[loop+3] == 'o' && matriz[loop+4] == 'c'
               &&matriz[loop+5] == 't' &&matriz[loop+6] == 'y' &&matriz[loop+7] == 'p' && matriz[loop+8] == 'e')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <!doctype>\n");
            }else

            /// CABEÇARIO HTML <html> </html>
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 't' && matriz[loop+3] == 'm' && matriz[loop+4] == 'l')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <html>\n");
            }else

            /// CABEÇARIO HEAD <head> </head>
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 'e' && matriz[loop+3] == 'a' && matriz[loop+4] == 'd')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <head>\n");
            }else

            /// CABEÇARIO BODY <body> </body>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'o' && matriz[loop+3] == 'd' && matriz[loop+4] == 'y')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <body>\n");
            }else

            /// CABEÇARIO TITLE <title> </title>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'i' && matriz[loop+3] == 't' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <title>\n");
            }else

            /// CABEÇARIO FORM <form> </form>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'o' && matriz[loop+3] == 'r' && matriz[loop+4] == 'm')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <form>\n");
            }else

            /// CABEÇARIO INPUT <input> </input>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'n' && matriz[loop+3] == 'p' && matriz[loop+4] == 'u'
               && matriz[loop+5] == 't')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <input>\n");
            }else

            /// CABEÇARIO CENTER <center> </center>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'e' && matriz[loop+3] == 'n' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 'r')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <center>\n");
            }else

            /// CABEÇARIO A <a>
            if(matriz[loop+1] == 'a')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <a>\n");
            }else
            /// CABEÇARIO B <b>
            if(matriz[loop+1] == 'b')
            {
                printf("cabeçalho do texto em <b>\n");
            }else
            /// CABEÇARIO Q <q>
            if(matriz[loop+1] == 'q')
            {
                printf("cabeçalho do texto em <q>\n");
            }else
            /// CABEÇARIO I <i>
            if(matriz[loop+1] == 'i')
            {
                printf("cabeçalho do texto em <i>\n");
            }else
            /// CABEÇARIO S <s>
            if(matriz[loop+1] == 's')
            {
                printf("cabeçalho do texto em <s>\n");
            }else
            /// CABEÇARIO U <u>
            if(matriz[loop+1] == 'u')
            {
                printf("cabeçalho do texto em <a>\n");
            }else

            /// CABEÇARIO BR <br> </br>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'r')
            {
                printf("cabeçalho do texto em <br>\n");
            }else

            /// CABEÇARIO HR <hr> </hr>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'r')
            {
                printf("cabeçalho do HR que n foi <hr>\n");
            }else

            /// CABEÇARIO LI <li> </li>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'i')
            {
                printf("cabeçalho do <li>\n");
            }else
            /// CABEÇARIO OL <ol> </ol>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'l')
            {
                printf("cabeçalho do <ol>\n");
            }else
            /// CABEÇARIO UL <ul> </ul>
            if(matriz[loop+1] == 'u' && matriz[loop+2] == 'l')
            {
                printf("cabeçalho do <ul>\n");
            }else
            /// CABEÇARIO DL <dl> </dl>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'l')
            {
                printf("cabeçalho do <dl>\n");
            }else
            /// CABEÇARIO DT <dt> </dt>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 't')
            {
                printf("cabeçalho do <dt>\n");
            }else
            /// CABEÇARIO DD <dd> </dd>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'd')
            {
                printf("cabeçalho do <dd>\n");
            }else


            /// CABEÇARIO em <em> </em>
            if(matriz[loop+1] == 'e' && matriz[loop+2] == 'm')
            {
                printf("cabeçalho do <em>\n");
            }else
            /// CABEÇARIO rp <rp> </rp>
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 'p')
            {
                printf("cabeçalho do <rp>\n");
            }else
            /// CABEÇARIO rt <rt> </rt>
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 't')
            {
                printf("cabeçalho do <rt>\n");
            }else
            /// CABEÇARIO th <th> </th>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'h')
            {
                printf("cabeçalho do <th>\n");
            }else

            /// CABEÇARIO tr <tr> </tr>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'r')
            {
                printf("cabeçalho do <tr>\n");
            }else
            /// CABEÇARIO tt <tt> </tt>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 't')
            {
                printf("cabeçalho do <tt>\n");
            }else
            ///<bdi>

            /// CABEÇARIO bdi <bdi> </bdi>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'd' && matriz[loop+3] == 'i')
            {
                printf("cabeçalho do texto em <bdi>\n");
            }else
            /// CABEÇARIO bdo <big> </big>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'i' && matriz[loop+3] == 'g')
            {
                printf("cabeçalho do texto em <big>\n");
            }else
            /// CABEÇARIO map <map> </map>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'a' && matriz[loop+3] == 'p')
            {
                printf("cabeçalho do texto em <map>\n");
            }else/// CABEÇARIO ins <ins> </ins>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'n' && matriz[loop+3] == 's')
            {
                printf("cabeçalho do texto em <ins>\n");
            }else

            /// CABEÇARIO kbd <kbd> </kbd>
            if(matriz[loop+1] == 'k' && matriz[loop+2] == 'b' && matriz[loop+3] == 'd')
            {
                printf("cabeçalho do texto em <kbd>\n");
            }else/// CABEÇARIO col <col> </col>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'o' && matriz[loop+3] == 'l')
            {
                printf("cabeçalho do texto em <col>\n");
            }else/// CABEÇARIO dfn <dfn> </dfn>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'f' && matriz[loop+3] == 'n')
            {
                printf("cabeçalho do texto em <dfn>\n");
            }else/// CABEÇARIO del <del> </del>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'e' && matriz[loop+3] == 'l')
            {
                printf("cabeçalho do texto em <del>\n");
            }else/// CABEÇARIO dir <dir> </dir>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'i' && matriz[loop+3] == 'r')
            {
                printf("cabeçalho do texto em <dir>\n");
            }else/// CABEÇARIO div <div> </div>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'i' && matriz[loop+3] == 'v')
            {
                printf("cabeçalho do texto em <div>\n");
            }else


            /// CABEÇARIO nav <nav> </nav>
            if(matriz[loop+1] == 'n' && matriz[loop+2] == 'a' && matriz[loop+3] == 'v')
            {
                printf("cabeçalho do texto em <nav>\n");
            }else/// CABEÇARIO pre <pre> </pre>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'r' && matriz[loop+3] == 'e')
            {
                printf("cabeçalho do texto em <pre>\n");
            }else/// CABEÇARIO wbr <wbr> </wbr>
            if(matriz[loop+1] == 'w' && matriz[loop+2] == 'b' && matriz[loop+3] == 'r')
            {
                printf("cabeçalho do texto em <wbr>\n");
            }else/// CABEÇARIO var <var> </var>
            if(matriz[loop+1] == 'v' && matriz[loop+2] == 'a' && matriz[loop+3] == 'r')
            {
                printf("cabeçalho do texto em <var>\n");
            }else/// CABEÇARIO sub <sub> </sub>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'u' && matriz[loop+3] == 'b')
            {
                printf("cabeçalho do texto em <sub>\n");
            }else/// CABEÇARIO svg <svg> </svg>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'v' && matriz[loop+3] == 'q')
            {
                printf("cabeçalho do texto em <svg>\n");
            }else

            /// CABEÇARIO sup <sup> </sup>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'u' && matriz[loop+3] == 'p')
            {
                printf("cabeçalho do texto em <sup>\n");
            }else


            /// CABEÇARIO abbr <abbr> </abbr>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'd' && matriz[loop+3] == 'd' && matriz[loop+4] == 'r')
            {
                printf("cabeçalho do texto em <abbr>\n");
            }else
            /// CABEÇARIO area <area> </area>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'r' && matriz[loop+3] == 'e' && matriz[loop+4] == 'a')
            {
                printf("cabeçalho do texto em <area>\n");
            }else
            /// CABEÇARIO time <time> </time>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'i' && matriz[loop+3] == 'm' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em <time>\n");
            }else
            /// CABEÇARIO span <span> </span>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'p' && matriz[loop+3] == 'a' && matriz[loop+4] == 'n')
            {
                printf("cabeçalho do texto em <span>\n");
            }else
            /// CABEÇARIO ruby <ruby> </ruby>
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 'u' && matriz[loop+3] == 'b' && matriz[loop+4] == 'y')
            {
                printf("cabeçalho do texto em <ruby>\n");
            }else

            /// CABEÇARIO samp <samp> </samp>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'a' && matriz[loop+3] == 'm' && matriz[loop+4] == 'p')
            {
                printf("cabeçalho do texto em <samp>\n");
            }else
            /// CABEÇARIO link <link> </link>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'i' && matriz[loop+3] == 'n' && matriz[loop+4] == 'k')
            {
                printf("cabeçalho do texto em <link>\n");
            }else
            /// CABEÇARIO main <main> </main>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'a' && matriz[loop+3] == 'i' && matriz[loop+4] == 'n')
            {
                printf("cabeçalho do texto em <main>\n");
            }else
            /// CABEÇARIO font <font> </font>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'o' && matriz[loop+3] == 'n' && matriz[loop+4] == 't')
            {
                printf("cabeçalho do texto em <font>\n");
            }else
            /// CABEÇARIO data <data> </data>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'a' && matriz[loop+3] == 't' && matriz[loop+4] == 'a')
            {
                printf("cabeçalho do texto em <data>\n");
            }else
            /// CABEÇARIO cite <cite> </cite>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'i' && matriz[loop+3] == 't' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em <cite>\n");
            }else
            /// CABEÇARIO code <code> </code>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'o' && matriz[loop+3] == 'd' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em <code>\n");
            }else
            /// CABEÇARIO base <base> </base>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'a' && matriz[loop+3] == 's' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em base\n");
            }else
            /// CABEÇARIO mark <mark> </mark>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'r' && matriz[loop+3] == 'r' && matriz[loop+4] == 'k')
            {
                printf("cabeçalho do texto em mark\n");
            }else
            /// CABEÇARIO meta <meta> </meta>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'e' && matriz[loop+3] == 't' && matriz[loop+4] == 'a')
            {
                printf("cabeçalho do texto em <meta>\n");
            }else

            /// CABEÇARIO embed <embed> </embed>
            if(matriz[loop+1] == 'e' && matriz[loop+2] == 'm' && matriz[loop+3] == 'b' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'd')
            {
                printf("cabeçalho do texto em <embed>\n");
            }else
            /// CABEÇARIO aside <aside> </aside>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 's' && matriz[loop+3] == 'i' && matriz[loop+4] == 'd'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <aside>\n");
            }else
            /// CABEÇARIO frame <frame> </frame>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'r' && matriz[loop+3] == 'a' && matriz[loop+4] == 'm'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <frame>\n");
            }else
            /// CABEÇARIO input <input> </input>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'n' && matriz[loop+3] == 'p' && matriz[loop+4] == 'u'
               && matriz[loop+5] == 't')
            {
                printf("cabeçalho do texto em <input>\n");
            }else
            /// CABEÇARIO label <label> </label>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'a' && matriz[loop+3] == 'b' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'l')
            {
                printf("cabeçalho do texto em <label>\n");
            }else

            /// CABEÇARIO meter <meter> </meter>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'e' && matriz[loop+3] == 't' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'r')
            {
                printf("cabeçalho do texto em <meter>\n");
            }else
            /// CABEÇARIO param <param> </param>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'a' && matriz[loop+3] == 'r' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'm')
            {
                printf("cabeçalho do texto em <param>\n");
            }else
            /// CABEÇARIO small <small> </small>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'm' && matriz[loop+3] == 'a' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'l')
            {
                printf("cabeçalho do texto em <small>\n");
            }else
            /// CABEÇARIO style <style> </style>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 't' && matriz[loop+3] == 'y' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <style>\n");
            }else
            /// CABEÇARIO table <table> </table>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 's' && matriz[loop+3] == 'b' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <table>\n");
            }else

            /// CABEÇARIO tbody <tbody> </tbody>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'b' && matriz[loop+3] == 'o' && matriz[loop+4] == 'd'
               && matriz[loop+5] == 'y')
            {
                printf("cabeçalho do texto em <tbody>\n");
            }else
            /// CABEÇARIO tfoot <tfoot> </tfoot>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'f' && matriz[loop+3] == 'o' && matriz[loop+4] == 'o'
               && matriz[loop+5] == 't')
            {
                printf("cabeçalho do texto em <tfoot>\n");
            }else
            /// CABEÇARIO thead <thead> </thead>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'h' && matriz[loop+3] == 'e' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'd')
            {
                printf("cabeçalho do texto em <thead>\n");
            }else
            /// CABEÇARIO track <track> </track>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'r' && matriz[loop+3] == 'a' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'k')
            {
                printf("cabeçalho do texto em <track>\n");
            }else
            /// CABEÇARIO video <video> </video>
            if(matriz[loop+1] == 'v' && matriz[loop+2] == 'i' && matriz[loop+3] == 'd' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'o')
            {
                printf("cabeçalho do texto em <video>\n");
            }else
            /// CABEÇARIO audio <audio> </audio>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'u' && matriz[loop+3] == 'd' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'o')
            {
                printf("cabeçalho do texto em <audio>\n");
            }else
            /// CABEÇARIO source <source> </source>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'o' && matriz[loop+3] == 'u' && matriz[loop+4] == 'r'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <source> \n");
            }else
            /// CABEÇARIO applet <applet> </applet>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'p' && matriz[loop+3] == 'p' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <applet> \n");
            }else
            /// CABEÇARIO <dialog> <dialog> </dialog>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'i' && matriz[loop+3] == 'a' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'o' && matriz[loop+6] == 'g')
            {
                printf("cabeçalho do texto em <dialog> \n");
            }else
            /// CABEÇARIO <button> <button> </button>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'u' && matriz[loop+3] == 't' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'o' && matriz[loop+6] == 'n')
            {
                printf("cabeçalho do texto em <button> \n");
            }else
            /// CABEÇARIO <canvas> <canvas> </canvas>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'a' && matriz[loop+3] == 'n' && matriz[loop+4] == 'v'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 's')
            {
                printf("cabeçalho do texto em <canvas> \n");
            }else
            /// CABEÇARIO <legend> <legend> </legend>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'e' && matriz[loop+3] == 'g' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'n' && matriz[loop+6] == 'd')
            {
                printf("cabeçalho do texto em <legend> \n");
            }else
            /// CABEÇARIO <header> <header> </header>
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 'e' && matriz[loop+3] == 'a' && matriz[loop+4] == 'd'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 'r')
            {
                printf("cabeçalho do texto em <header> \n");
            }else
            /// CABEÇARIO <iframe> <iframe> </iframe>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'f' && matriz[loop+3] == 'r' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'm' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <iframe> \n");
            }else
            /// CABEÇARIO <object> <object> </object>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'b' && matriz[loop+3] == 'j' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <object> \n");
            }else
            /// CABEÇARIO <option> <option> </option>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'p' && matriz[loop+3] == 't' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'o' && matriz[loop+6] == 'n')
            {
                printf("cabeçalho do texto em <option> \n");
            }else
            /// CABEÇARIO <output> <output> </output>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'u' && matriz[loop+3] == 't' && matriz[loop+4] == 'p'
               && matriz[loop+5] == 'u' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <output> \n");
            }else
            /// CABEÇARIO <figure> <figure> </figure>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'i' && matriz[loop+3] == 'g' && matriz[loop+4] == 'u'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <figure> \n");
            }else
            /// CABEÇARIO <strike> <strike> </strike>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 't' && matriz[loop+3] == 'r' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'k' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <strike> \n");
            }else
            /// CABEÇARIO <strong> <strong> </strong>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 't' && matriz[loop+3] == 'r' && matriz[loop+4] == 'o'
               && matriz[loop+5] == 'n' && matriz[loop+6] == 'g')
            {
                printf("cabeçalho do texto em <strong> \n");
            }else
            /// CABEÇARIO <select> <select> </select>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'e' && matriz[loop+3] == 'l' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <select> \n");
            }else
            /// CABEÇARIO <script> <script> </script>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'c' && matriz[loop+3] == 'r' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'p' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <script> \n");
            }else
            /// CABEÇARIO <footer> <footer> </footer>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'o' && matriz[loop+3] == 'o' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 'r')
            {
                printf("cabeçalho do texto em <footer> \n");
            }else
            /// CABEÇARIO <acronym> <acronym> </acronym>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'c' && matriz[loop+3] == 'r' && matriz[loop+4] == 'o'
               && matriz[loop+5] == 'n' && matriz[loop+6] == 'y' && matriz[loop+7] == 'm')
            {
                printf("cabeçalho do texto em <acronym> \n");
            }else
            /// CABEÇARIO <address> <address> </address>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'd' && matriz[loop+3] == 'd' && matriz[loop+4] == 'r'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 's' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <address> \n");
            }else
            /// CABEÇARIO <article> <article> </article>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'r' && matriz[loop+3] == 't' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 'l' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em <article> \n");
            }else
            /// CABEÇARIO <details> <details> </details>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'e' && matriz[loop+3] == 't' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'i' && matriz[loop+6] == 'l' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <details> \n");
            }else
            /// CABEÇARIO <caption> <caption> </caption>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'a' && matriz[loop+3] == 'p' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'i' && matriz[loop+6] == 'o' && matriz[loop+7] == 'n')
            {
                printf("cabeçalho do texto em <caption> \n");
            }else
            /// CABEÇARIO <picture> <picture> </picture>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'i' && matriz[loop+3] == 'c' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'u' && matriz[loop+6] == 'r' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em <picture> \n");
            }else
            /// CABEÇARIO <section> <section> </section>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'e' && matriz[loop+3] == 'c' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'i' && matriz[loop+6] == 'o' && matriz[loop+7] == 'n')
            {
                printf("cabeçalho do texto em <section> \n");
            }else
            /// CABEÇARIO <summary> <summary> </summary>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'u' && matriz[loop+3] == 'm' && matriz[loop+4] == 'm'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'r' && matriz[loop+7] == 'y')
            {
                printf("cabeçalho do texto em <summary> \n");
            }else
            /// CABEÇARIO <basefont> <basefont> </basefont>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'a' && matriz[loop+3] == 's' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'f' && matriz[loop+6] == 'o' && matriz[loop+7] == 'n' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <basefont> \n");
            }else
            /// CABEÇARIO <colgroup> <colgroup> </colgroup>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'o' && matriz[loop+3] == 'l' && matriz[loop+4] == 'g'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'o' && matriz[loop+7] == 'u' && matriz[loop+7] == 'p')
            {
                printf("cabeçalho do texto em <colgroup> \n");
            }else
            /// CABEÇARIO <datalist> <datalist> </datalist>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'a' && matriz[loop+3] == 't' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'l' && matriz[loop+6] == 'i' && matriz[loop+7] == 's' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <datalist>  \n");
            }else
            /// CABEÇARIO <frameset> <frameset> </frameset>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'r' && matriz[loop+3] == 'a' && matriz[loop+4] == 'm'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 's' && matriz[loop+7] == 'e' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <frameset>  \n");
            }else
            /// CABEÇARIO <fieldset> <fieldset> </fieldset>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'i' && matriz[loop+3] == 'e' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'd' && matriz[loop+6] == 's' && matriz[loop+7] == 'e' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <fieldset>  \n");
            }else
            /// CABEÇARIO <progress> <progress> </progress>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'r' && matriz[loop+3] == 'o' && matriz[loop+4] == 'g'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'e' && matriz[loop+7] == 's' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <progress>  \n");
            }else
            /// CABEÇARIO <optgroup> <optgroup> </optgroup>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'p' && matriz[loop+3] == 't' && matriz[loop+4] == 'g'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'o' && matriz[loop+7] == 'u' && matriz[loop+7] == 'p')
            {
                printf("cabeçalho do texto em <optgroup>  \n");
            }else
            /// CABEÇARIO <noframes> <noframes> </noframes>
            if(matriz[loop+1] == 'n' && matriz[loop+2] == 'o' && matriz[loop+3] == 'f' && matriz[loop+4] == 'r'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'm' && matriz[loop+7] == 'e' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <noframes>  \n");
            }else
            /// CABEÇARIO <noscript> <noscript> </noscript>
            if(matriz[loop+1] == 'n' && matriz[loop+2] == 'o' && matriz[loop+3] == 's' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'i' && matriz[loop+7] == 'p' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <noscript>  \n");
            }else
            /// CABEÇARIO <template> <template> </template>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'e' && matriz[loop+3] == 'm' && matriz[loop+4] == 'p'
               && matriz[loop+5] == 'l' && matriz[loop+6] == 'a' && matriz[loop+7] == 't' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em <template>  \n");
            }else
            /// CABEÇARIO <textarea> <textarea> </textarea>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'e' && matriz[loop+3] == 'x' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'r' && matriz[loop+7] == 'e' && matriz[loop+7] == 'a')
            {
                printf("cabeçalho do texto em <textarea>  \n");
            }else
            /// CABEÇARIO <figcaption> <figcaption> </figcaption>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'i' && matriz[loop+3] == 'g' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'p' && matriz[loop+7] == 't' && matriz[loop+7] == 'i'
               && matriz[loop+7] == 'o' && matriz[loop+7] == 'n')
            {
                printf("cabeçalho do texto em <figcaption>  \n");
            }else
            /// CABEÇARIO  <blockquote> <blockquote> </blockquote>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'l' && matriz[loop+3] == 'o' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'k' && matriz[loop+6] == 'q' && matriz[loop+7] == 'u' && matriz[loop+7] == 'o'
               && matriz[loop+7] == 't' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em  <blockquote>  \n");
            }else


            /// CABEÇARIO <!--> </!-->
            if(matriz[loop+1] == '!' && matriz[loop+2] == '-' && matriz[loop+3] == '-')
            {
                printf("cabeçalho do texto em <!-->\n");
            }else

            ///TAMANHO DO <h1> a </h6>
            if(matriz[loop+1] == 'h')
            {
                if(matriz[loop+2] =='1'||matriz[loop+2] =='2'||
                   matriz[loop+2] =='3'||matriz[loop+2] =='4'||
                   matriz[loop+2] =='5'||matriz[loop+2] =='6')
                    {
                        printf("tamanho do <h>\n");
                    }
            }else
            ///PARAGRAFO
            if(matriz[loop+1] == 'p')
            {
                if(matriz[loop+2] == '>')
                {
                    printf("paragrafo\n");
                }
            }else
            ///IMAGEM
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'm' && matriz[loop+3] == 'g')
            {

                if(matriz[loop+4] == ' ' || matriz[loop+5] == 's')
                {
                    printf("imagem\n");
                }else
                printf("imagem a ser definida ou verificar o codigo \n");

            }
        }





        if(matriz[loop] == '<' && matriz[loop] == '/'){
            printf("\n##################| FIM  DO LINK IMPUT |##################\n");
            ativador = false;

        }// END IF

        if(ativador == true)
        {
            if(matriz[loop] == '/'){
                matriz[loop] = ' ';
                printf("%c", matriz[loop]);
                //fprintf(arqs, "%c", matriz[loop] );
            }else
                printf("%c", matriz[loop]);
                //fprintf(arqs, "%c", matriz[loop] );
        }
    }// END FOR


   system("pause");

}
// TRATAEMNTO DE EXTENÇOES AUXILIAR
void TRATAMENTO_HTML_EXTENCOES(){

    printf("\n\n======================================================================\n\n");
    int  i , l, loop;
    int *matriz;

    matriz = (int*)malloc(sizeof(int)*90000);

    i = strlen(MAX_TAM_GET2);
    for(l=0; l<=i; l++)
    {
        matriz[l] = MAX_TAM_GET2[l];
        ///printf("%c", matriz[l]);
    }

    for(loop=0;loop <= i;loop++)
    {

        if(matriz[loop] == '.')
        {

            /// CABEÇARIO .TXT
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'x' && matriz[loop+3] == 't')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.txt";
            }else
            /// CABEÇARIO .EXE
            if(matriz[loop+1] == 'e' && matriz[loop+2] == 'x' && matriz[loop+3] == 'e')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.exe";
            }else
            /// CABEÇARIO .RAR
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 'a' && matriz[loop+3] == 'r')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.rar";
            }else
            /// CABEÇARIO .ZIP
            if(matriz[loop+1] == 'z' && matriz[loop+2] == 'i' && matriz[loop+3] == 'p')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.zip";
            }else
            /// CABEÇARIO .PDF
            if(matriz[loop] == '.' && matriz[loop+1] == 'p' && matriz[loop+2] == 'd' && matriz[loop+3] == 'f')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.pdf";
            }else
            /// CABEÇARIO .PNG
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'n' && matriz[loop+3] == 'g')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.png";
            }else
            /// CABEÇARIO .JPG
            if(matriz[loop+1] == 'j' && matriz[loop+2] == 'p' && matriz[loop+3] == 'g')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.jpg";
            }else
            /// CABEÇARIO .ICO
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'c' && matriz[loop+3] == 'o')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.ico";
            }else
            /// CABEÇARIO .GIF
            if(matriz[loop+1] == 'g' && matriz[loop+2] == 'i' && matriz[loop+3] == 'f')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.gif";
            }else
            /// CABEÇARIO .AVI
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'v' && matriz[loop+3] == 'i')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.avi";
            }else
            /// CABEÇARIO .MPG
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'p' && matriz[loop+3] == 'g')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.mpg";
            }else
            /// CABEÇARIO .WMV
            if(matriz[loop+1] == 'w' && matriz[loop+2] == 'm' && matriz[loop+3] == 'v')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.wmv";
            }else
            /// CABEÇARIO .MOV
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'o' && matriz[loop+3] == 'v')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.mov";
            }else
            /// CABEÇARIO .MP3
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'p' && matriz[loop+3] == '3')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.mp3";
            }else
            /// CABEÇARIO .WAV
            if(matriz[loop+1] == 'w' && matriz[loop+2] == 'a' && matriz[loop+3] == 'v')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.wav";
            }else
            /// CABEÇARIO . HTM
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 't' && matriz[loop+3] == 'm')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.htm";
            }else
            /// CABEÇARIO .THML
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 't' && matriz[loop+3] == 'm' && matriz[loop+4] == 'l')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.html";
            }else
            /// CABEÇARIO .XLSX
            if(matriz[loop+1] == 'x' && matriz[loop+2] == 'l' && matriz[loop+3] == 's' && matriz[loop+4] == 'x')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.xlmx";
            }else
            /// CABEÇARIO .DOCX
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'o' && matriz[loop+3] == 'c' && matriz[loop+4] == 'x')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.dcox";
            }else
            /// CABEÇARIO .XML
            if(matriz[loop+1] == 'x' && matriz[loop+2] == 'm' && matriz[loop+3] == 'l')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.xml";
            }else
            /// CABEÇARIO .XLS
            if(matriz[loop+1] == 'x' && matriz[loop+2] == 'l' && matriz[loop+3] == 's')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.xls";
            }else
            /// CABEÇARIO .DOC
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'o' && matriz[loop+3] == 'c')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.doc";
            }else
            /// CABEÇARIO .DLL
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'l' && matriz[loop+3] == 'l')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.dll";
            }else
            /// CABEÇARIO .CPP
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'p' && matriz[loop+3] == 'p')
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.cpp";
            }else
            /// CABEÇARIO .C
            if( matriz[loop+1] == 'c' && loop == 3)
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.c";
            }else
            /// CABEÇARIO .H
            if(matriz[loop+1] == 'h' )
            {
                printf("TIPO DO EXTENCAO .\n");
                Exten = "T:\\\DOWNLOAD\\\ARQUIVO_DOWNLOAD.Ahga";
            }



        }
    }

    system("pause");
}
// TRATAEMNTO DE LAYOUT AUXILIAR
void LEYALT_PAGINA_HTML(){


    printf("\n\n======================================================================\n\n");
    int  i , l, a, loop;
    int *matriz, *mat;
    bool ativador = false;


    matriz = (int*)malloc(sizeof(int)*90000);
    mat    = (int*)malloc(sizeof(int)*90000);

    i = strlen(MAX_TAM_GET2);
    for(l=0,a=1; l<=i; l++, a++)
    {
        matriz[l] = MAX_TAM_GET2[l];
        mat[l] = MAX_TAM_GET2[a];
        ///printf("%c", matriz[l]);
    }

    for(loop=0;loop <= i;loop++)
    {

       if(matriz[loop] == '<')
        {
            /// CABEÇARIO DOCTYPE <!doctype> </!doctype>
            if(matriz[loop+1] == '!' && matriz[loop+2] == 'd' && matriz[loop+3] == 'o' && matriz[loop+4] == 'c'
               &&matriz[loop+5] == 't' &&matriz[loop+6] == 'y' &&matriz[loop+7] == 'p' && matriz[loop+8] == 'e')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <!doctype>\n");
            }else

            /// CABEÇARIO HTML <html> </html>
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 't' && matriz[loop+3] == 'm' && matriz[loop+4] == 'l')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <html>\n");
            }else

            /// CABEÇARIO HEAD <head> </head>
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 'e' && matriz[loop+3] == 'a' && matriz[loop+4] == 'd')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <head>\n");
            }else

            /// CABEÇARIO BODY <body> </body>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'o' && matriz[loop+3] == 'd' && matriz[loop+4] == 'y')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <body>\n");
            }else

            /// CABEÇARIO TITLE <title> </title>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'i' && matriz[loop+3] == 't' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <title>\n");
            }else

            /// CABEÇARIO FORM <form> </form>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'o' && matriz[loop+3] == 'r' && matriz[loop+4] == 'm')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <form>\n");
            }else

            /// CABEÇARIO INPUT <input> </input>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'n' && matriz[loop+3] == 'p' && matriz[loop+4] == 'u'
               && matriz[loop+5] == 't')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <input>\n");
            }else

            /// CABEÇARIO CENTER <center> </center>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'e' && matriz[loop+3] == 'n' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 'r')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("\ncabeçalho do texto em <center>\n");
            }else

            /// CABEÇARIO A <a>
            if(matriz[loop+1] == 'a')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <a>\n");
            }else
            /// CABEÇARIO B <b>
            if(matriz[loop+1] == 'b')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <b>\n");
            }else
            /// CABEÇARIO Q <q>
            if(matriz[loop+1] == 'q')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <q>\n");
            }else
            /// CABEÇARIO I <i>
            if(matriz[loop+1] == 'i')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <i>\n");
            }else
            /// CABEÇARIO S <s>
            if(matriz[loop+1] == 's')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <s>\n");
            }else
            /// CABEÇARIO U <u>
            if(matriz[loop+1] == 'u')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <a>\n");
            }else

            /// CABEÇARIO BR <br> </br>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'r')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do texto em <br>\n");
            }else

            /// CABEÇARIO HR <hr> </hr>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'r')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do HR que n foi <hr>\n");
            }else

            /// CABEÇARIO LI <li> </li>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'i')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do <li>\n");
            }else
            /// CABEÇARIO OL <ol> </ol>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'l')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do <ol>\n");
            }else
            /// CABEÇARIO UL <ul> </ul>
            if(matriz[loop+1] == 'u' && matriz[loop+2] == 'l')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do <ul>\n");
            }else
            /// CABEÇARIO DL <dl> </dl>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'l')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do <dl>\n");
            }else
            /// CABEÇARIO DT <dt> </dt>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 't')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do <dt>\n");
            }else
            /// CABEÇARIO DD <dd> </dd>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'd')
            {   printf("\n##################| INICIO DO CONTADOR TAGS |##################\n");
                ativador = true;
                printf("cabeçalho do <dd>\n");
            }else


            /// CABEÇARIO em <em> </em>
            if(matriz[loop+1] == 'e' && matriz[loop+2] == 'm')
            {
                printf("cabeçalho do <em>\n");
            }else
            /// CABEÇARIO rp <rp> </rp>
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 'p')
            {
                printf("cabeçalho do <rp>\n");
            }else
            /// CABEÇARIO rt <rt> </rt>
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 't')
            {
                printf("cabeçalho do <rt>\n");
            }else
            /// CABEÇARIO th <th> </th>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'h')
            {
                printf("cabeçalho do <th>\n");
            }else

            /// CABEÇARIO tr <tr> </tr>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'r')
            {
                printf("cabeçalho do <tr>\n");
            }else
            /// CABEÇARIO tt <tt> </tt>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 't')
            {
                printf("cabeçalho do <tt>\n");
            }else
            ///<bdi>

            /// CABEÇARIO bdi <bdi> </bdi>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'd' && matriz[loop+3] == 'i')
            {
                printf("cabeçalho do texto em <bdi>\n");
            }else
            /// CABEÇARIO bdo <big> </big>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'i' && matriz[loop+3] == 'g')
            {
                printf("cabeçalho do texto em <big>\n");
            }else
            /// CABEÇARIO map <map> </map>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'a' && matriz[loop+3] == 'p')
            {
                printf("cabeçalho do texto em <map>\n");
            }else/// CABEÇARIO ins <ins> </ins>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'n' && matriz[loop+3] == 's')
            {
                printf("cabeçalho do texto em <ins>\n");
            }else

            /// CABEÇARIO kbd <kbd> </kbd>
            if(matriz[loop+1] == 'k' && matriz[loop+2] == 'b' && matriz[loop+3] == 'd')
            {
                printf("cabeçalho do texto em <kbd>\n");
            }else/// CABEÇARIO col <col> </col>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'o' && matriz[loop+3] == 'l')
            {
                printf("cabeçalho do texto em <col>\n");
            }else/// CABEÇARIO dfn <dfn> </dfn>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'f' && matriz[loop+3] == 'n')
            {
                printf("cabeçalho do texto em <dfn>\n");
            }else/// CABEÇARIO del <del> </del>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'e' && matriz[loop+3] == 'l')
            {
                printf("cabeçalho do texto em <del>\n");
            }else/// CABEÇARIO dir <dir> </dir>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'i' && matriz[loop+3] == 'r')
            {
                printf("cabeçalho do texto em <dir>\n");
            }else/// CABEÇARIO div <div> </div>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'i' && matriz[loop+3] == 'v')
            {
                printf("cabeçalho do texto em <div>\n");
            }else


            /// CABEÇARIO nav <nav> </nav>
            if(matriz[loop+1] == 'n' && matriz[loop+2] == 'a' && matriz[loop+3] == 'v')
            {
                printf("cabeçalho do texto em <nav>\n");
            }else/// CABEÇARIO pre <pre> </pre>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'r' && matriz[loop+3] == 'e')
            {
                printf("cabeçalho do texto em <pre>\n");
            }else/// CABEÇARIO wbr <wbr> </wbr>
            if(matriz[loop+1] == 'w' && matriz[loop+2] == 'b' && matriz[loop+3] == 'r')
            {
                printf("cabeçalho do texto em <wbr>\n");
            }else/// CABEÇARIO var <var> </var>
            if(matriz[loop+1] == 'v' && matriz[loop+2] == 'a' && matriz[loop+3] == 'r')
            {
                printf("cabeçalho do texto em <var>\n");
            }else/// CABEÇARIO sub <sub> </sub>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'u' && matriz[loop+3] == 'b')
            {
                printf("cabeçalho do texto em <sub>\n");
            }else/// CABEÇARIO svg <svg> </svg>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'v' && matriz[loop+3] == 'q')
            {
                printf("cabeçalho do texto em <svg>\n");
            }else

            /// CABEÇARIO sup <sup> </sup>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'u' && matriz[loop+3] == 'p')
            {
                printf("cabeçalho do texto em <sup>\n");
            }else


            /// CABEÇARIO abbr <abbr> </abbr>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'd' && matriz[loop+3] == 'd' && matriz[loop+4] == 'r')
            {
                printf("cabeçalho do texto em <abbr>\n");
            }else
            /// CABEÇARIO area <area> </area>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'r' && matriz[loop+3] == 'e' && matriz[loop+4] == 'a')
            {
                printf("cabeçalho do texto em <area>\n");
            }else
            /// CABEÇARIO time <time> </time>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'i' && matriz[loop+3] == 'm' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em <time>\n");
            }else
            /// CABEÇARIO span <span> </span>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'p' && matriz[loop+3] == 'a' && matriz[loop+4] == 'n')
            {
                printf("cabeçalho do texto em <span>\n");
            }else
            /// CABEÇARIO ruby <ruby> </ruby>
            if(matriz[loop+1] == 'r' && matriz[loop+2] == 'u' && matriz[loop+3] == 'b' && matriz[loop+4] == 'y')
            {
                printf("cabeçalho do texto em <ruby>\n");
            }else

            /// CABEÇARIO samp <samp> </samp>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'a' && matriz[loop+3] == 'm' && matriz[loop+4] == 'p')
            {
                printf("cabeçalho do texto em <samp>\n");
            }else
            /// CABEÇARIO link <link> </link>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'i' && matriz[loop+3] == 'n' && matriz[loop+4] == 'k')
            {
                printf("cabeçalho do texto em <link>\n");
            }else
            /// CABEÇARIO main <main> </main>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'a' && matriz[loop+3] == 'i' && matriz[loop+4] == 'n')
            {
                printf("cabeçalho do texto em <main>\n");
            }else
            /// CABEÇARIO font <font> </font>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'o' && matriz[loop+3] == 'n' && matriz[loop+4] == 't')
            {
                printf("cabeçalho do texto em <font>\n");
            }else
            /// CABEÇARIO data <data> </data>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'a' && matriz[loop+3] == 't' && matriz[loop+4] == 'a')
            {
                printf("cabeçalho do texto em <data>\n");
            }else
            /// CABEÇARIO cite <cite> </cite>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'i' && matriz[loop+3] == 't' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em <cite>\n");
            }else
            /// CABEÇARIO code <code> </code>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'o' && matriz[loop+3] == 'd' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em <code>\n");
            }else
            /// CABEÇARIO base <base> </base>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'a' && matriz[loop+3] == 's' && matriz[loop+4] == 'e')
            {
                printf("cabeçalho do texto em base\n");
            }else
            /// CABEÇARIO mark <mark> </mark>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'r' && matriz[loop+3] == 'r' && matriz[loop+4] == 'k')
            {
                printf("cabeçalho do texto em mark\n");
            }else
            /// CABEÇARIO meta <meta> </meta>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'e' && matriz[loop+3] == 't' && matriz[loop+4] == 'a')
            {
                printf("cabeçalho do texto em <meta>\n");
            }else

            /// CABEÇARIO embed <embed> </embed>
            if(matriz[loop+1] == 'e' && matriz[loop+2] == 'm' && matriz[loop+3] == 'b' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'd')
            {
                printf("cabeçalho do texto em <embed>\n");
            }else
            /// CABEÇARIO aside <aside> </aside>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 's' && matriz[loop+3] == 'i' && matriz[loop+4] == 'd'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <aside>\n");
            }else
            /// CABEÇARIO frame <frame> </frame>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'r' && matriz[loop+3] == 'a' && matriz[loop+4] == 'm'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <frame>\n");
            }else
            /// CABEÇARIO input <input> </input>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'n' && matriz[loop+3] == 'p' && matriz[loop+4] == 'u'
               && matriz[loop+5] == 't')
            {
                printf("cabeçalho do texto em <input>\n");
            }else
            /// CABEÇARIO label <label> </label>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'a' && matriz[loop+3] == 'b' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'l')
            {
                printf("cabeçalho do texto em <label>\n");
            }else

            /// CABEÇARIO meter <meter> </meter>
            if(matriz[loop+1] == 'm' && matriz[loop+2] == 'e' && matriz[loop+3] == 't' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'r')
            {
                printf("cabeçalho do texto em <meter>\n");
            }else
            /// CABEÇARIO param <param> </param>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'a' && matriz[loop+3] == 'r' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'm')
            {
                printf("cabeçalho do texto em <param>\n");
            }else
            /// CABEÇARIO small <small> </small>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'm' && matriz[loop+3] == 'a' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'l')
            {
                printf("cabeçalho do texto em <small>\n");
            }else
            /// CABEÇARIO style <style> </style>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 't' && matriz[loop+3] == 'y' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <style>\n");
            }else
            /// CABEÇARIO table <table> </table>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 's' && matriz[loop+3] == 'b' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e')
            {
                printf("cabeçalho do texto em <table>\n");
            }else

            /// CABEÇARIO tbody <tbody> </tbody>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'b' && matriz[loop+3] == 'o' && matriz[loop+4] == 'd'
               && matriz[loop+5] == 'y')
            {
                printf("cabeçalho do texto em <tbody>\n");
            }else
            /// CABEÇARIO tfoot <tfoot> </tfoot>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'f' && matriz[loop+3] == 'o' && matriz[loop+4] == 'o'
               && matriz[loop+5] == 't')
            {
                printf("cabeçalho do texto em <tfoot>\n");
            }else
            /// CABEÇARIO thead <thead> </thead>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'h' && matriz[loop+3] == 'e' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'd')
            {
                printf("cabeçalho do texto em <thead>\n");
            }else
            /// CABEÇARIO track <track> </track>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'r' && matriz[loop+3] == 'a' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'k')
            {
                printf("cabeçalho do texto em <track>\n");
            }else
            /// CABEÇARIO video <video> </video>
            if(matriz[loop+1] == 'v' && matriz[loop+2] == 'i' && matriz[loop+3] == 'd' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'o')
            {
                printf("cabeçalho do texto em <video>\n");
            }else
            /// CABEÇARIO audio <audio> </audio>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'u' && matriz[loop+3] == 'd' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'o')
            {
                printf("cabeçalho do texto em <audio>\n");
            }else
            /// CABEÇARIO source <source> </source>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'o' && matriz[loop+3] == 'u' && matriz[loop+4] == 'r'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <source> \n");
            }else
            /// CABEÇARIO applet <applet> </applet>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'p' && matriz[loop+3] == 'p' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <applet> \n");
            }else
            /// CABEÇARIO <dialog> <dialog> </dialog>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'i' && matriz[loop+3] == 'a' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'o' && matriz[loop+6] == 'g')
            {
                printf("cabeçalho do texto em <dialog> \n");
            }else
            /// CABEÇARIO <button> <button> </button>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'u' && matriz[loop+3] == 't' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'o' && matriz[loop+6] == 'n')
            {
                printf("cabeçalho do texto em <button> \n");
            }else
            /// CABEÇARIO <canvas> <canvas> </canvas>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'a' && matriz[loop+3] == 'n' && matriz[loop+4] == 'v'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 's')
            {
                printf("cabeçalho do texto em <canvas> \n");
            }else
            /// CABEÇARIO <legend> <legend> </legend>
            if(matriz[loop+1] == 'l' && matriz[loop+2] == 'e' && matriz[loop+3] == 'g' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'n' && matriz[loop+6] == 'd')
            {
                printf("cabeçalho do texto em <legend> \n");
            }else
            /// CABEÇARIO <header> <header> </header>
            if(matriz[loop+1] == 'h' && matriz[loop+2] == 'e' && matriz[loop+3] == 'a' && matriz[loop+4] == 'd'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 'r')
            {
                printf("cabeçalho do texto em <header> \n");
            }else
            /// CABEÇARIO <iframe> <iframe> </iframe>
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'f' && matriz[loop+3] == 'r' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'm' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <iframe> \n");
            }else
            /// CABEÇARIO <object> <object> </object>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'b' && matriz[loop+3] == 'j' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <object> \n");
            }else
            /// CABEÇARIO <option> <option> </option>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'p' && matriz[loop+3] == 't' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'o' && matriz[loop+6] == 'n')
            {
                printf("cabeçalho do texto em <option> \n");
            }else
            /// CABEÇARIO <output> <output> </output>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'u' && matriz[loop+3] == 't' && matriz[loop+4] == 'p'
               && matriz[loop+5] == 'u' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <output> \n");
            }else
            /// CABEÇARIO <figure> <figure> </figure>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'i' && matriz[loop+3] == 'g' && matriz[loop+4] == 'u'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <figure> \n");
            }else
            /// CABEÇARIO <strike> <strike> </strike>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 't' && matriz[loop+3] == 'r' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'k' && matriz[loop+6] == 'e')
            {
                printf("cabeçalho do texto em <strike> \n");
            }else
            /// CABEÇARIO <strong> <strong> </strong>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 't' && matriz[loop+3] == 'r' && matriz[loop+4] == 'o'
               && matriz[loop+5] == 'n' && matriz[loop+6] == 'g')
            {
                printf("cabeçalho do texto em <strong> \n");
            }else
            /// CABEÇARIO <select> <select> </select>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'e' && matriz[loop+3] == 'l' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <select> \n");
            }else
            /// CABEÇARIO <script> <script> </script>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'c' && matriz[loop+3] == 'r' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'p' && matriz[loop+6] == 't')
            {
                printf("cabeçalho do texto em <script> \n");
            }else
            /// CABEÇARIO <footer> <footer> </footer>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'o' && matriz[loop+3] == 'o' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 'r')
            {
                printf("cabeçalho do texto em <footer> \n");
            }else
            /// CABEÇARIO <acronym> <acronym> </acronym>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'c' && matriz[loop+3] == 'r' && matriz[loop+4] == 'o'
               && matriz[loop+5] == 'n' && matriz[loop+6] == 'y' && matriz[loop+7] == 'm')
            {
                printf("cabeçalho do texto em <acronym> \n");
            }else
            /// CABEÇARIO <address> <address> </address>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'd' && matriz[loop+3] == 'd' && matriz[loop+4] == 'r'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 's' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <address> \n");
            }else
            /// CABEÇARIO <article> <article> </article>
            if(matriz[loop+1] == 'a' && matriz[loop+2] == 'r' && matriz[loop+3] == 't' && matriz[loop+4] == 'i'
               && matriz[loop+5] == 'c' && matriz[loop+6] == 'l' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em <article> \n");
            }else
            /// CABEÇARIO <details> <details> </details>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'e' && matriz[loop+3] == 't' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'i' && matriz[loop+6] == 'l' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <details> \n");
            }else
            /// CABEÇARIO <caption> <caption> </caption>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'a' && matriz[loop+3] == 'p' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'i' && matriz[loop+6] == 'o' && matriz[loop+7] == 'n')
            {
                printf("cabeçalho do texto em <caption> \n");
            }else
            /// CABEÇARIO <picture> <picture> </picture>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'i' && matriz[loop+3] == 'c' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'u' && matriz[loop+6] == 'r' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em <picture> \n");
            }else
            /// CABEÇARIO <section> <section> </section>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'e' && matriz[loop+3] == 'c' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'i' && matriz[loop+6] == 'o' && matriz[loop+7] == 'n')
            {
                printf("cabeçalho do texto em <section> \n");
            }else
            /// CABEÇARIO <summary> <summary> </summary>
            if(matriz[loop+1] == 's' && matriz[loop+2] == 'u' && matriz[loop+3] == 'm' && matriz[loop+4] == 'm'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'r' && matriz[loop+7] == 'y')
            {
                printf("cabeçalho do texto em <summary> \n");
            }else
            /// CABEÇARIO <basefont> <basefont> </basefont>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'a' && matriz[loop+3] == 's' && matriz[loop+4] == 'e'
               && matriz[loop+5] == 'f' && matriz[loop+6] == 'o' && matriz[loop+7] == 'n' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <basefont> \n");
            }else
            /// CABEÇARIO <colgroup> <colgroup> </colgroup>
            if(matriz[loop+1] == 'c' && matriz[loop+2] == 'o' && matriz[loop+3] == 'l' && matriz[loop+4] == 'g'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'o' && matriz[loop+7] == 'u' && matriz[loop+7] == 'p')
            {
                printf("cabeçalho do texto em <colgroup> \n");
            }else
            /// CABEÇARIO <datalist> <datalist> </datalist>
            if(matriz[loop+1] == 'd' && matriz[loop+2] == 'a' && matriz[loop+3] == 't' && matriz[loop+4] == 'a'
               && matriz[loop+5] == 'l' && matriz[loop+6] == 'i' && matriz[loop+7] == 's' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <datalist>  \n");
            }else
            /// CABEÇARIO <frameset> <frameset> </frameset>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'r' && matriz[loop+3] == 'a' && matriz[loop+4] == 'm'
               && matriz[loop+5] == 'e' && matriz[loop+6] == 's' && matriz[loop+7] == 'e' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <frameset>  \n");
            }else
            /// CABEÇARIO <fieldset> <fieldset> </fieldset>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'i' && matriz[loop+3] == 'e' && matriz[loop+4] == 'l'
               && matriz[loop+5] == 'd' && matriz[loop+6] == 's' && matriz[loop+7] == 'e' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <fieldset>  \n");
            }else
            /// CABEÇARIO <progress> <progress> </progress>
            if(matriz[loop+1] == 'p' && matriz[loop+2] == 'r' && matriz[loop+3] == 'o' && matriz[loop+4] == 'g'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'e' && matriz[loop+7] == 's' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <progress>  \n");
            }else
            /// CABEÇARIO <optgroup> <optgroup> </optgroup>
            if(matriz[loop+1] == 'o' && matriz[loop+2] == 'p' && matriz[loop+3] == 't' && matriz[loop+4] == 'g'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'o' && matriz[loop+7] == 'u' && matriz[loop+7] == 'p')
            {
                printf("cabeçalho do texto em <optgroup>  \n");
            }else
            /// CABEÇARIO <noframes> <noframes> </noframes>
            if(matriz[loop+1] == 'n' && matriz[loop+2] == 'o' && matriz[loop+3] == 'f' && matriz[loop+4] == 'r'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'm' && matriz[loop+7] == 'e' && matriz[loop+7] == 's')
            {
                printf("cabeçalho do texto em <noframes>  \n");
            }else
            /// CABEÇARIO <noscript> <noscript> </noscript>
            if(matriz[loop+1] == 'n' && matriz[loop+2] == 'o' && matriz[loop+3] == 's' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'r' && matriz[loop+6] == 'i' && matriz[loop+7] == 'p' && matriz[loop+7] == 't')
            {
                printf("cabeçalho do texto em <noscript>  \n");
            }else
            /// CABEÇARIO <template> <template> </template>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'e' && matriz[loop+3] == 'm' && matriz[loop+4] == 'p'
               && matriz[loop+5] == 'l' && matriz[loop+6] == 'a' && matriz[loop+7] == 't' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em <template>  \n");
            }else
            /// CABEÇARIO <textarea> <textarea> </textarea>
            if(matriz[loop+1] == 't' && matriz[loop+2] == 'e' && matriz[loop+3] == 'x' && matriz[loop+4] == 't'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'r' && matriz[loop+7] == 'e' && matriz[loop+7] == 'a')
            {
                printf("cabeçalho do texto em <textarea>  \n");
            }else
            /// CABEÇARIO <figcaption> <figcaption> </figcaption>
            if(matriz[loop+1] == 'f' && matriz[loop+2] == 'i' && matriz[loop+3] == 'g' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'a' && matriz[loop+6] == 'p' && matriz[loop+7] == 't' && matriz[loop+7] == 'i'
               && matriz[loop+7] == 'o' && matriz[loop+7] == 'n')
            {
                printf("cabeçalho do texto em <figcaption>  \n");
            }else
            /// CABEÇARIO  <blockquote> <blockquote> </blockquote>
            if(matriz[loop+1] == 'b' && matriz[loop+2] == 'l' && matriz[loop+3] == 'o' && matriz[loop+4] == 'c'
               && matriz[loop+5] == 'k' && matriz[loop+6] == 'q' && matriz[loop+7] == 'u' && matriz[loop+7] == 'o'
               && matriz[loop+7] == 't' && matriz[loop+7] == 'e')
            {
                printf("cabeçalho do texto em  <blockquote>  \n");
            }else


            /// CABEÇARIO <!--> </!-->
            if(matriz[loop+1] == '!' && matriz[loop+2] == '-' && matriz[loop+3] == '-')
            {
                printf("cabeçalho do texto em <!-->\n");
            }else

            ///TAMANHO DO <h1> a </h6>
            if(matriz[loop+1] == 'h')
            {
                if(matriz[loop+2] =='1'||matriz[loop+2] =='2'||
                   matriz[loop+2] =='3'||matriz[loop+2] =='4'||
                   matriz[loop+2] =='5'||matriz[loop+2] =='6')
                    {
                        printf("tamanho do <h>\n");
                    }
            }else
            ///PARAGRAFO
            if(matriz[loop+1] == 'p')
            {
                if(matriz[loop+2] == '>')
                {
                    printf("paragrafo\n");
                }
            }else
            ///IMAGEM
            if(matriz[loop+1] == 'i' && matriz[loop+2] == 'm' && matriz[loop+3] == 'g')
            {

                if(matriz[loop+4] == ' ' || matriz[loop+5] == 's')
                {
                    printf("imagem\n");
                }else
                printf("imagem a ser definida ou verificar o codigo \n");

            }
        }





        if(matriz[loop+1] == '"' && matriz[loop+2] == '>' ){
            printf("%c%c", matriz[loop+1], matriz[loop+2]);
            printf("\n##################| FIM  DO LINK IMPUT |##################\n");
            ativador = false;

        }else// END IF
        if(matriz[loop+1] == '>' && matriz[loop+2] == '<' ){
            printf("%c%c", matriz[loop+1], matriz[loop+2]);
            printf("\n##################| FIM  DO LINK IMPUT |##################\n");
            ativador = false;

        }else// END IF
        if(matriz[loop+1] == '<' && matriz[loop+2] == '/' ){
            printf("%c%c", matriz[loop+1], matriz[loop+2]);
            printf("\n##################| FIM  DO LINK IMPUT |##################\n");
            ativador = false;

        }// END IF


        if(ativador == true)
        {
            /*if(matriz[loop] == '/'){
                matriz[++loop] = '||';
                printf("%c", matriz[loop]);
                //fprintf(arqs, "%c", matriz[loop] );
            }else*/
                printf("%c", matriz[loop]);
                //fprintf(arqs, "%c", matriz[loop] );
        }
    }// END FOR

    printf("\n\n======================================================================\n\n");

    system("pause");







}
// TRATAEMNTO DE CARACTERES AUXILIAR
void IMPRIMINDO_CARACTERES_ESPECIAIS(){


    bool ativador = false;
    char aa[800];
    char ss[800];
    int cc;
    FILE *pp;
    char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\IMAGEM01.jpg";
    pp = fopen(uu, (ss, "rb"));

    char urls[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\CARACTERES2.txt";
    FILE *arqs;
    arqs = fopen(urls, "ab");
    char tt[900];

    while( fgetc(pp)!= EOF)
    {

        fscanf(pp, "%s", aa);
        printf("%s", aa);
        fprintf(arqs, "%s", aa);

    }
    fclose(pp);

    /// TRATAMENTO COM DIVISAO DE CARACTERES ESPECIAIS
    /*/*
      while( fgetc(pp)!= EOF)
    {
        if(ativador == false){
        if(strcmp(aa, "Age:"))
            {
            //VERIFICA O NOME
                fscanf(pp, "%s", aa);
                printf("%s-", aa);
            }else{  ativador = true;    }
        }else{
            //SANVA NO DIRETORIO
            fscanf(pp, "%s", aa);
            printf("%s", aa);

            //strcat(tt , aa);
            fprintf(arqs, "%s", aa);
            //printf("%s", tt);
        }

    }
    fclose(pp);

    */

    /*/// SALVANDO E LENDO CARACTERES ESPECIAIS
    bool ativador = false;
    char aa[200];
    char ss[200];
    int cc;
    FILE *pp;
    char uu[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\IMAGEM01.jpg";
    pp = fopen(uu, (ss, "rb"));

    char urls[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\CARACTERES2.txt";
    FILE *arqs;
    arqs = fopen(urls, "a");
    char tt[200];

    while( fgetc(pp)!= EOF)
    {

        if(strcmp(aa, "ÿØÿà")){ /// AQUI SALVA O CARACTER QUE VOCE DESEJA
            fscanf(pp, "%s", aa);
            printf("%s-", aa);

        }else{
            strcat(tt , aa);
            fprintf(arqs, "%s", tt);
            printf("%s", tt);

        }

    }
    fclose(pp);
*/

     /*/// DIGITAR A PASQUISA EM FORMA DE STRING
    int i, l;
    //gets(MAX_TAM_GET2);
    i = strlen(MAX_TAM_GET2);

    /// TRATAMENTO DE STRING PARA ACRECENTRAR O SINAL DE MAIS "+"
    for(l=0; l<=i; l++)
    {
        printf("%c", MAX_TAM_GET2[l]);
    }


        printf("\nINTERPRETADOR DE HTML\n");

        char urls1[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\IMAGEM01.jpg";
        char ch;
        int cha;
        FILE *arqs1;
        arqs1 = fopen(urls1, "rb");

        if(arqs1 == NULL)
        printf("Erro, nao foi possivel abrir o arquivo\n");
        else
        while( (cha=fgetc(arqs1))!= EOF)
        {

            fscanf(arqs1,"%c", cha);

        }
        fclose(arqs1);
        printf("\n\n");*/

    /*
    wchar_t caracter = 'ÿ';
    wchar_t c = 408;
    //int l = 0;
    char urls[] = "T:\\PESQUISA_GOOGLE_CPP_V2\\SITE_URL\\CARACTERES.txt";
    FILE *arqs;
    arqs = fopen(urls, "a");
    for(l; l <= 267; l++){
        //printf("%d {%c} ", l, l);
        //fprintf(arqs, "%c", l);
        if(c == l){
            cout << "deu certo caracer especial!" << endl;
        }
        if(!isprint(l)){
            printf("\n\n%c\n\n", l);
            fprintf(arqs, "%c", l);
        }

    }
        caracter = printf("%c ", l);
        printf("--%c--", c);



    //fprintf(arqs, "%c", c);
    fclose(arqs);
*/


}
// TRATAEMNTO DE BIBLIOTECAS AUXILIAR
void CHAMA_METODOS_BIBLIOTECA_TESTE(){
    printf("\n\n\n\n\n");
    int definir_navegador;
    printf("Definir Navegador:");
    scanf("%d", &definir_navegador);
    cout << endl;


    int port;
    char ip_busca;
    struct METODO_BUSCA_HTTP_80 mbh;
    mbh.navegador = definir_navegador;

    ///mbh.navegador *testes = new mbh.ips_navegadores(4);

    printf("%s\n", mbh.Ip_Site);
    printf("%s\n", mbh.Site_Host);
    port = mbh.porta_retorno();
    printf("%d\n", port);

    ip_busca = mbh.ips_navegadores();
    printf("%s\n", ip_busca);
    //ip_busca = mbh.bing;
    //printf("%s\n", mbh.bing);
    //ip_busca = mbh.yahoo;
    //printf("%s\n", mbh.yahoo);
    //ip_busca = mbh.duckduckgo;
    //printf("%s\n", mbh.duckduckgo);
    //ip_busca = mbh.baidu;
    //printf("%s\n", mbh.baidu);
    //ip_busca = mbh.aol;
    //printf("%s\n", mbh.aol);
    //ip_busca = mbh.ask;
    //printf("%s\n", mbh.ask);
}


int main(int argc, char *argv[]){


    ///CONSULTA_IP_DOMINIO_GET();
    //PESQUISA_GOOGLE_80();
    ///====CONSULTA_IP_DOMINIO_POST();
    ///====PESQUISA_GOOGLE_443();
    REQUISICAO_GET();
    PESQUISA_GOOGLE();

    //REQUISICAO_POST();
    //PESQUISA_GOOGLE();

    //REQUISICAO_GET1();
    //PESQUISA_GOOGLE();

    //REQUISICAO_POST();

    //IMPRIMINDO_CARACTERES_ESPECIAIS();
    //DOWNLOAD_ARQUIVOS();
    //EDITOR_IMAGEM_ARQUIVO();
    //EDITOR_IMAGEM_ARQUIVO_02();
    //PESQUISA_GOOGLE_GERAL();
    ///PESQUISA_GOOGLE_IMAGEM();
    ///PESQUISA_GOOGLE();
    //LEYALT_PAGINA_HTML();
    ///CHAMA_METODOS_BIBLIOTECA_TESTE();
    ///TRATAMENTO_HTML_SITE();     // imagens
    ///TRATAMENTO_HTML_URL();      // imagens
    ///TRATAMENTO_HTML_INPUT();    // dvr
    //TRATAMENTO_HTML_FUNCOES();
    ///--TRATAMENTO_HTML_EXTENCOES();

    //LEYALT_PAGINA_HTML();
}

