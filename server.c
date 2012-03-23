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

#define PORT 8765
#define BUFSIZZ 1024

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

BIO *bio_err=0;
static char *pass;

void destroy_ctx(ctx)
  SSL_CTX *ctx;
  {
    SSL_CTX_free(ctx);
  }

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


static int http_serve(ssl,s)
  SSL *ssl;
  int s;
  {
    char buf[BUFSIZZ];
    int r,len;
    BIO *io,*ssl_bio;
    
    io=BIO_new(BIO_f_buffer());
    ssl_bio=BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio,ssl,BIO_CLOSE);
    BIO_push(io,ssl_bio);
    
    while(1){
      r=BIO_gets(io,buf,BUFSIZZ-1);

      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_NONE:
          len=r;
          break;
        default:
          berr_exit("SSL read problem");
      }

      /* Look for the blank line that signals
         the end of the HTTP headers */
      if(!strcmp(buf,"\r\n") ||
        !strcmp(buf,"\n"))
        break;
    }

    if((r=BIO_puts
      (io,"HTTP/1.0 200 OK\r\n"))<=0)
      err_exit("Write error");
    if((r=BIO_puts
      (io,"Server: EKRServer\r\n\r\n"))<=0)
      err_exit("Write error");
    if((r=BIO_puts
      (io,"Server test page\r\n"))<=0)
      err_exit("Write error");
    
    if((r=BIO_flush(io))<0)
      err_exit("Error flushing BIO");


    
    r=SSL_shutdown(ssl);
    if(!r){
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify*/
      shutdown(s,1);
      r=SSL_shutdown(ssl);
    }
      
    switch(r){  
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        berr_exit("Shutdown failed");
    }

    SSL_free(ssl);
    close(s);

    return(0);
  }

















int main(int argc, char **argv)
{
  int s,r, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
        SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  





  ctx = initialize_ctx("bob.pem","password");









  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {


        sbio=BIO_new_socket(s,BIO_NOCLOSE);
        ssl=SSL_new(ctx);
        SSL_set_bio(ssl,sbio,sbio);
        
        if((r=SSL_accept(ssl)<=0))
          berr_exit("SSL accept error");
        
        http_serve(ssl,s);


      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";

      len = recv(s, &buf, 255, 0);
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);
      send(s, answer, strlen(answer), 0);
      close(sock);
      close(s);
      return 0;
    }
  }
  destroy_ctx(ctx);
  close(sock);
  return 1;
}
