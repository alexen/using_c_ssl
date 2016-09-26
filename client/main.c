/*
 * main.c
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#include <stdlib.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <common/common.h>


int do_client_loop( SSL* ssl )
{
     while( 1 )
     {
          char buf[ 80 ] = { 0 };
          if( !fgets( buf, sizeof( buf ), stdin ) )
          {
               break;
          }
          int n_written = 0;
          for( int total_written = 0; total_written < sizeof( buf ); total_written += n_written )
          {
               n_written = SSL_write( ssl, buf + n_written, strlen( buf ) - total_written );
               if( n_written <= 0 )
               {
                    return 0;
               }
          }
     }
     return 1;
}


SSL_CTX* setup_client_ctx( const char* certfile, const char* pk_file, const char* pk_password )
{
     SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );
     SSL_ERROR_INTERRUPT_IF( !ctx, "ssl context creating error" );
     if( certfile && !SSL_CTX_use_certificate_chain_file( ctx, certfile ) )
     {
          SSL_ERROR_INTERRUPT( "using cert chain file error" );
     }
     if( pk_file && !SSL_CTX_use_PrivateKey_file( ctx, pk_file, SSL_FILETYPE_PEM ) )
     {
          SSL_ERROR_INTERRUPT( "using private key file error" );
     }
     return ctx;
}


int main( int argc, char **argv )
{
     ssl_init();
     ssl_seed_prng_bytes( 1024 );
     SSL_CTX* ctx = setup_client_ctx( NULL, NULL, NULL );
     BIO* conn = BIO_new_connect( "localhost:8080" );
     SSL_ERROR_INTERRUPT_IF( !conn, "create new connection error" );
     if( BIO_do_connect( conn ) <= 0 )
     {
          SSL_ERROR_INTERRUPT( "remote host connection error" );
     }
     SSL* ssl = SSL_new( ctx );
     SSL_ERROR_INTERRUPT_IF( !ssl, "ssl creating error" );
     SSL_set_bio( ssl, conn, conn );
     if( SSL_connect( ssl ) )
     {
          SSL_ERROR_INTERRUPT( "ssl connection error" );
     }
     printf( "ssl connection established\n" );
     if( do_client_loop( ssl ) )
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
