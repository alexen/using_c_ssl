/*
 * main.c
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <common/common.h>


int do_client_loop_v2( SSL* ssl )
{
     char buf[ 80 ];
     const size_t buflen = sizeof( buf );

     while( !feof( stdin ) )
     {
          const size_t n_read = fread( buf, 1, buflen - 1, stdin );
          if( SSL_write( ssl, buf, n_read ) <= 0 )
          {
               return 0;
          }
     }

     return 1;
}


int main( int argc, char **argv )
{
     static const char* const CA_FILE = "/home/alexen/worktrash/ssl/rootcert.pem";
     static const char* const CERT_FILE = "/home/alexen/worktrash/ssl/client.pem";
     static const char* const PK_FILE = "/home/alexen/worktrash/ssl/client.pem";
     static const char* const PK_PASSWORD = "111111";
     static const char* const CIPHER_LIST = "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH";

     ssl_init();
     ssl_seed_prng_bytes( 1024 );

     struct ssl_ctx_setup_input input = { 0 };
     input.cert_file = CERT_FILE;
     input.pk_file = PK_FILE;
     input.pk_password = PK_PASSWORD;
     input.ca_file = CA_FILE;
     input.verify_callback = ssl_verify_callback;
     input.verify_flags = SSL_VERIFY_PEER;
     input.verify_depth = 4;
     input.ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2;
     input.cipher_list = CIPHER_LIST;

     SSL_CTX* ctx = ssl_ctx_setup( &input );
     BIO* conn = BIO_new_connect( "localhost:8080" );
     SSL_ERROR_INTERRUPT_IF( !conn, "create new connection error" );
     if( BIO_do_connect( conn ) <= 0 )
     {
          SSL_ERROR_INTERRUPT( "remote host connection error" );
     }
     SSL* ssl = SSL_new( ctx );
     SSL_ERROR_INTERRUPT_IF( !ssl, "ssl creating error" );
     SSL_set_bio( ssl, conn, conn );
     if( SSL_connect( ssl ) <= 0 )
     {
          SSL_ERROR_INTERRUPT( "ssl connection error" );
     }
     const long ret_code = ssl_do_post_connection_check( ssl, "server.localsecurity.org" );
     if( ret_code != X509_V_OK )
     {
          fprintf( stderr, "- error: peer certificate: %s\n", X509_verify_cert_error_string( ret_code ) );
          SSL_ERROR_INTERRUPT( "peer certificate verification error" );
     }
     printf( "ssl connection established\n" );
     if( do_client_loop_v2( ssl ) )
     {
          SSL_shutdown( ssl );
     }
     else
     {
          SSL_clear( ssl );
     }
     printf( "ssl connection closed\n" );
     SSL_free( ssl );
     SSL_CTX_free( ctx );
     ssl_shutdown();
     return EXIT_SUCCESS;
}
