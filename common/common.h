/*
 * common.h
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#pragma once


void openssl_init();
void openssl_shutdown();
void stdlib_error_report_and_exit( int errnum, const char* file, int line, const char* message );
void openssl_error_report_and_exit( const char* file, int line, const char* message );
