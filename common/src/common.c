/*
 * common.cpp
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#include <common/common.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>


static pthread_mutex_t* mutex_array = NULL;


static void locking_function_callback( int mode, int n, const char* file, int line )
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


static unsigned long id_function_callback()
{
     return (unsigned long) pthread_self();
}


static int password_callback( char* buf, int size, int flags, void* userdata )
{
     const char* password = (const char*) userdata;
     const int passwordLen = strlen( password );
     strncpy( buf, password, passwordLen );
     return passwordLen;
}


SSL_CTX* ssl_ctx_setup( const char* certfile, const char* pk_file, const char* pk_password )
{
     SSL_CTX* ctx = SSL_CTX_new( SSLv23_method() );
     SSL_ERROR_INTERRUPT_IF( !ctx, "ssl context creating error" );
     if( certfile && !SSL_CTX_use_certificate_chain_file( ctx, certfile ) )
     {
          SSL_ERROR_INTERRUPT( "using cert chain file error" );
     }
     if( pk_file )
     {
          if( pk_password )
          {
               SSL_CTX_set_default_passwd_cb( ctx, password_callback );
               SSL_CTX_set_default_passwd_cb_userdata( ctx, (void*) pk_password );
          }
          if( !SSL_CTX_use_PrivateKey_file( ctx, pk_file, SSL_FILETYPE_PEM ) )
          {
               SSL_ERROR_INTERRUPT( "using private key file error" );
          }
     }
     return ctx;
}


int ssl_verify_callback( int ok, X509_STORE_CTX* store )
{
     if( !ok )
     {
          X509* cert = X509_STORE_CTX_get_current_cert( store );
          const int depth = X509_STORE_CTX_get_error_depth( store );
          const int error = X509_STORE_CTX_get_error( store );

          fprintf( stderr, "- error with certificate in depth %i\n", depth );
          fprintf( stderr, "  issuer:" );
          X509_NAME_print_ex_fp( stderr, X509_get_issuer_name( cert ), 0, XN_FLAG_SEP_COMMA_PLUS );
          fprintf( stderr, "  subject:" );
          X509_NAME_print_ex_fp( stderr, X509_get_subject_name( cert ), 0, XN_FLAG_SEP_COMMA_PLUS );
          fprintf( stderr, "  error %i:%s\n", error, X509_verify_cert_error_string( error ) );
     }

     return ok;
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
     CRYPTO_set_id_callback( id_function_callback );
     CRYPTO_set_locking_callback( locking_function_callback );
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


void ssl_init()
{
     if( !openssl_thread_init() || !SSL_library_init() )
     {
          SSL_ERROR_INTERRUPT( "openssl initialization failed" );
     }
     SSL_load_error_strings();
}


void ssl_shutdown()
{
     if( !openssl_thread_cleanup() )
     {
          SSL_ERROR_INTERRUPT( "openssl shutdown failed" );
     }
     ERR_free_strings();
}


void ssl_seed_prng_bytes( int bytes )
{
     const int n_bytes = RAND_load_file( "/dev/urandom", bytes );
     SYS_ERROR_INTERRUPT_IF( n_bytes != bytes, errno, "rand seeding error" );
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
