/*
 * common.h
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#pragma once


void ssl_init();
void ssl_shutdown();
void ssl_seed_prng_bytes( int bytes );
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
