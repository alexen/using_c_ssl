/*
 * common.cpp
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#include <common/common.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


static pthread_mutex_t* mutex_array = NULL;


static void locking_function( int mode, int n, const char* file, int line )
{
     int errnum = 0;

     if( mode & CRYPTO_LOCK )
     {
          errnum = pthread_mutex_lock( &mutex_array[ n ] );
     }
     else
     {
          errnum = pthread_mutex_unlock( &mutex_array[ n ] );
     }

     SYS_ERROR_INTERRUPT_IF( errnum != 0, errnum, "mutex locking/unlocking error" );
}


static unsigned long id_function()
{
     return (unsigned long) pthread_self();
}


static int openssl_thread_init()
{
     const int num_locks = CRYPTO_num_locks();
     mutex_array = (pthread_mutex_t*) malloc( num_locks * sizeof( pthread_mutex_t ) );
     if( !mutex_array )
     {
          return 0;
     }
     for( int i = 0; i < num_locks; ++i )
     {
          const int errnum = pthread_mutex_init( &mutex_array[ i ], NULL );
          SYS_ERROR_INTERRUPT_IF( errnum != 0, errnum, "mutex initialization error" );
     }
     CRYPTO_set_id_callback( id_function );
     CRYPTO_set_locking_callback( locking_function );
     return 1;
}


static int openssl_thread_cleanup()
{
     if( !mutex_array )
     {
          return 0;
     }
     for( int i = 0; i < CRYPTO_num_locks(); ++i )
     {
          const int errnum = pthread_mutex_destroy( &mutex_array[ i ] );
          SYS_ERROR_INTERRUPT_IF( errnum != 0, errnum, "mutex destroying error" );
     }
     free( mutex_array );
     mutex_array = NULL;
     CRYPTO_set_id_callback( NULL );
     CRYPTO_set_locking_callback( NULL );
     return 1;
}


void openssl_init()
{
     if( !openssl_thread_init() || !SSL_library_init() )
     {
          SSL_ERROR_INTERRUPT( "openssl initialization failed" );
     }
     SSL_load_error_strings();
}


void openssl_shutdown()
{
     if( !openssl_thread_cleanup() )
     {
          SSL_ERROR_INTERRUPT( "openssl shutdown failed" );
     }
     ERR_free_strings();
}


void sys_error_report_and_exit( int errnum, const char* file, int line, const char* message )
{
     fprintf( stderr, "** sys error: %s:%i %s: %s\n", file, line, message, strerror( errnum ) );
     exit( EXIT_FAILURE );
}


void ssl_error_report_and_exit( const char* file, int line, const char* message )
{
     fprintf( stderr, "** ssl error: %s:%i %s\n", file, line, message );
     ERR_print_errors_fp( stderr );
     exit( EXIT_FAILURE );
}
