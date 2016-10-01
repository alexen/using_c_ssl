/*
 * main.c
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <common/common.h>


int do_server_loop( SSL* ssl )
{
     int n_read = 0;
     do
     {
          char buf[ 80 ] = { 0 };
          for( int total_read = 0; total_read < sizeof( buf ); total_read += n_read )
          {
               n_read = SSL_read( ssl, buf + total_read, sizeof( buf ) - total_read );
               if( n_read <= 0 )
               {
                    break;
               }
               fwrite( buf, 1, n_read, stdout );
          }
     }
     while( n_read > 0 );

     return (SSL_get_shutdown( ssl ) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}


void* server_thread( void* args )
{
     SSL* ssl = (SSL*) args;
     pthread_detach( pthread_self() );
     if( SSL_accept( ssl ) <= 0 )
     {
          SSL_ERROR_INTERRUPT( "accepting SSL connection error" );
     }
     printf( "SSL connection opened\n" );
     if( do_server_loop( ssl ) )
     {
          SSL_shutdown( ssl );
     }
     else
     {
          SSL_clear( ssl );
     }
     printf( "SSL connection closed\n" );
     SSL_free( ssl );
     ERR_remove_state( 0 );
     return NULL;
}


int main( int argc, char **argv )
{
     static const char* const certfile = "/home/alexen/worktrash/ssl/server.pem";
     static const char* const pkfile = "/home/alexen/worktrash/ssl/server.pem";
     static const char* const pkpassword = "111111";

     ssl_init();
     ssl_seed_prng_bytes( 1024 );
     SSL_CTX* ctx = ssl_ctx_setup( certfile, pkfile, pkpassword );
     BIO* acc = BIO_new_accept( "8080" );
     SSL_ERROR_INTERRUPT_IF( !acc, "create new accept error" );
     if( BIO_do_accept( acc ) <= 0 )
     {
          SSL_ERROR_INTERRUPT( "bind error" );
     }
     pthread_t t_id;
     while( 1 )
     {
          if( BIO_do_accept( acc ) <= 0 )
          {
               SSL_ERROR_INTERRUPT( "accept error" );
          }
          BIO* client = BIO_pop( acc );
          SSL* ssl = SSL_new( ctx );
          SSL_ERROR_INTERRUPT_IF( !ssl, "creating SSL error" );
          SSL_set_bio( ssl, client, client );
          const int errnum = pthread_create( &t_id, NULL, server_thread, ssl );
          SYS_ERROR_INTERRUPT_IF( errnum != 0, errnum, "thread creating error" );
     }
     SSL_CTX_free( ctx );
     BIO_free( acc );
     ssl_shutdown();
     return EXIT_SUCCESS;
}
