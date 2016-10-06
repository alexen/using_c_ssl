/*
 * common.h
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#pragma once

#include <openssl/ossl_typ.h>


void ssl_init();

void ssl_shutdown();

void ssl_seed_prng_bytes( int bytes );

struct ssl_ctx_setup_input {
     const char* cert_file;
     const char* pk_file;
     const char* pk_password;
     const char* ca_file;
     const char* ca_dir;
     int verify_flags;
     int verify_depth;
     int (*verify_callback)( int, X509_STORE_CTX* );
     const char* cipher_list;
     long ssl_options;
     DH* (*tmp_dh_callback)( SSL*, int, int );
};

SSL_CTX* ssl_ctx_setup( const struct ssl_ctx_setup_input* const input );

int ssl_verify_callback( int ok, X509_STORE_CTX* store );

long ssl_do_post_connection_check( SSL* ssl, const char* host );

void sys_error_report_and_exit( int errnum, const char* file, int line, const char* message );

void ssl_error_report_and_exit( const char* file, int line, const char* message );

#define SSL_ERROR_INTERRUPT( msg_ ) \
     do { ssl_error_report_and_exit( __FILE__, __LINE__, msg_ ); } while( 0 )
#define SYS_ERROR_INTERRUPT( errnum_, msg_ ) \
     do { sys_error_report_and_exit( errnum_, __FILE__, __LINE__, msg_ ); } while( 0 )
#define SSL_ERROR_INTERRUPT_IF( cond_, msg_ ) \
     do { if( (cond_) ) SSL_ERROR_INTERRUPT( msg_ ); } while( 0 )
#define SYS_ERROR_INTERRUPT_IF( cond_, errnum_, msg_ ) \
     do { if( (cond_) ) SYS_ERROR_INTERRUPT( errnum_, msg_ ); } while( 0 )
