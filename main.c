/*
 *  main.c
 *
 *  Created on: Sep 22, 2016
 *       Author: alexen
 *
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <common/common.h>


#define ERROR_EXIT_IF( condition_ ) \
     do{ if( (condition_) ){ print_ssl_errors(); exit( EXIT_FAILURE ); } }while( 0 )


void print_ssl_errors()
{
     const char* file = NULL;
     const char* data = NULL;
     int line = 0;
     int flags = 0;

     unsigned long err_code = 0;
     while( (err_code = ERR_get_error_line_data( &file, &line, &data, &flags )) )
     {
          char errstr[ 256 ] = { 0 };
          const size_t ERRSTR_LEN = sizeof( errstr );
          ERR_error_string_n( err_code, errstr, ERRSTR_LEN - 1 );
          fprintf( stderr, "ssl error: %ld at \"%s\":%d: %s", err_code, file, line, errstr );
          ( data && (flags & ERR_TXT_STRING) )
               ? fprintf( stderr, ", data: %s\n", data )
               : fprintf( stderr, "\n" );
          data = NULL;
          flags = 0;
     }
}


void seed_prng( int bytes )
{
     ERROR_EXIT_IF( RAND_load_file( "/dev/urandom", bytes ) == 0 );
}


void prime_status_cb( int code, int arg, void* cb_args )
{
     if( code == 0 )
     {
          printf( "*" );
     }
     else if( code == 1 && arg && !(arg % 10) )
     {
          printf( "." );
     }
     else
     {
          printf( "\nGot one!\n" );
     }
     fflush( stdout );
}


BIGNUM* generate_prime( int bits, int safe, int print_hex )
{
     printf( "Searching for a %sprime %d bits in size...", (safe ? "safe" : ""), bits );
     BIGNUM* prime = BN_generate_prime( NULL, bits, safe, NULL, NULL, prime_status_cb, NULL );
     if( !prime )
     {
          return NULL;
     }
     char* str = print_hex ? BN_bn2hex( prime ) : BN_bn2dec( prime );
     if( str )
     {
          printf( "Found prime: %s\n", str );
          OPENSSL_free( str );
     }
     return prime;
}


int main( int argc, char** argv )
{
     ssl_init();
     ssl_shutdown();
     return EXIT_SUCCESS;
}
