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


void do_server_loop( BIO* bio )
{
     int n_read = 0;
     do
     {
          char buf[ 80 ] = { 0 };
          for( int total_read = 0; total_read < sizeof( buf ); total_read += n_read )
          {
               n_read = BIO_read( bio, buf + n_read, sizeof( buf ) - total_read );
               if( n_read <= 0 )
               {
                    break;
               }
               fwrite( buf, 1, total_read, stdout );
          }
     }
     while( n_read > 0 );
}


void* server_thread( void* args )
{
     BIO* client = (BIO*) args;
     pthread_detach( pthread_self() );
     printf( "connection opened\n" );
     do_server_loop( client );
     printf( "connection closed\n" );
     BIO_free( client );
     ERR_remove_state( 0 );
     return NULL;
}


int main( int argc, char **argv )
{
     ssl_init();
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
          const int errnum = pthread_create( &t_id, NULL, server_thread, client );
          SYS_ERROR_INTERRUPT_IF( errnum != 0, errnum, "thread creating error" );
     }
     BIO_free( acc );
     ssl_shutdown();
     return EXIT_SUCCESS;
}
