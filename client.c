#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <signal.h>

#define HOST "localhost"
#define PORT 8765

#define BUFSIZZ 1024
static char *REQUEST_TEMPLATE=
   "GET / HTTP/1.0\r\nUser-Agent:"
   "EKRClient\r\nHost: %s:%d\r\n\r\n";

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"





BIO *bio_err=0;
static char *pass;
static int require_server_auth=1;

int err_exit(string)
  char *string;
  {
    fprintf(stderr,"%s\n",string);
    exit(0);
  }

/* Print SSL errors and exit*/
int berr_exit(string)
  char *string;
  {
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
  }

static void sigpipe_handle(int x){
}

static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }

SSL_CTX *initialize_ctx(keyfile,password)
  char *keyfile;
  char *password;
  {
    SSL_METHOD *meth;
    SSL_CTX *ctx;
    
    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      
      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);
    
    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
      berr_exit("Can't read certificate file");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx,
      password_cb);
    if(!(SSL_CTX_use_PrivateKey_file(ctx,
      keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if(!(SSL_CTX_load_verify_locations(ctx,
      "568ca.pem",0)))
      berr_exit("Can't read CA list");
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx,1);
#endif
    
    return ctx;
  }

void check_cert(ssl,host)
  SSL *ssl;
  char *host;
  {
    X509 *peer;
    char peer_CN[256];
    
    if(SSL_get_verify_result(ssl)!=X509_V_OK)
      berr_exit("Certificate doesn't verify");

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID
      (X509_get_subject_name(peer),
      NID_commonName, peer_CN, 256);
    if(strcasecmp(peer_CN,host))
    err_exit
      ("Common name doesn't match host name");
  }

int tcp_connect(host,port)
  char *host;
  int port;
  {
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    
    if(!(hp=gethostbyname(host)))
      berr_exit("Couldn't resolve host");
    memset(&addr,0,sizeof(addr));
    addr.sin_addr=*(struct in_addr*)
      hp->h_addr_list[0];
    addr.sin_family=AF_INET;
    addr.sin_port=htons(port);

    if((sock=socket(AF_INET,SOCK_STREAM,
      IPPROTO_TCP))<0)
      err_exit("Couldn't create socket");
    if(connect(sock,(struct sockaddr *)&addr,
      sizeof(addr))<0)
      err_exit("Couldn't connect socket");
    
    return sock;
  }


static int http_request(ssl)
  SSL *ssl;
  {
    char *request=0;
    char buf[BUFSIZZ];
    int r;
    int len, request_len;
    
    /* Now construct our HTTP request */
    request_len=strlen(REQUEST_TEMPLATE)+
      strlen(HOST)+6;
    if(!(request=(char *)malloc(request_len)))
      err_exit("Couldn't allocate request");
    snprintf(request,request_len,REQUEST_TEMPLATE,
      HOST,PORT);

    /* Find the exact request_len */
    request_len=strlen(request);

    r=SSL_write(ssl,request,request_len);
    switch(SSL_get_error(ssl,r)){      
      case SSL_ERROR_NONE:
        if(request_len!=r)
          err_exit("Incomplete write!");
        break;
        default:
          berr_exit("SSL write problem");
    }
    
    /* Now read the server's response, assuming
       that it's terminated by a close */
    while(1){
      r=SSL_read(ssl,buf,BUFSIZZ);
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          fprintf(stderr,
            "SSL Error: Premature close\n");
          goto done;
        default:
          berr_exit("SSL read problem");
      }

      fwrite(buf,1,len,stdout);
    }
    
  shutdown:
    r=SSL_shutdown(ssl);
    switch(r){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }
    
  done:
    SSL_free(ssl);
    free(request);
    return(0);
  }





int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
      SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
    extern char *optarg;
    int c;

  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }






  ctx = initialize_ctx("alice.pem","password");

    /* Connect the TCP socket*/
    sock=tcp_connect(host,port);

    /* Connect the SSL socket */
    ssl=SSL_new(ctx);
    sbio=BIO_new_socket(sock,BIO_NOCLOSE);
    SSL_set_bio(ssl,sbio,sbio);

    if(SSL_connect(ssl)<=0)
      berr_exit("SSL connect error");
    if(require_server_auth)
      check_cert(ssl,"Bob's Server");

    /* Now make our HTTP request */
    http_request(ssl);





  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  //send(sock, secret, strlen(secret),0);
  //len = recv(sock, &buf, 255, 0);
  SSL_write(ssl,secret,strlen(secret)+1);
  len = SSL_read(ssl, &buf, 255);
  buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  close(sock);
  return 1;
}
