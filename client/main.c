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


void do_client_loop( BIO* bio )
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
               n_written = BIO_write( bio, buf + n_written, strlen( buf ) - total_written );
               if( n_written <= 0 )
               {
                    return;
               }
          }
     }
}


int main( int argc, char **argv )
{
     openssl_init();
     BIO* conn = BIO_new_connect( "localhost:8080" );
     SSL_ERROR_INTERRUPT_IF( !conn, "create new connection error" );
     if( BIO_do_connect( conn ) <= 0 )
     {
          SSL_ERROR_INTERRUPT( "remote host connection error" );
     }
     printf( "connection established\n" );
     do_client_loop( conn );
     printf( "connection closed\n" );
     BIO_free( conn );
     openssl_shutdown();
     return EXIT_SUCCESS;
}
