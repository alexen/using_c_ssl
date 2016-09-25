/*
 * common.cpp
 *
 *  Created on: Sep 25, 2016
 *      Author: alexen
 */

#include <common/common.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>


void handle_error( const char* file, int line, const char* message )
{
     fprintf( stderr, "** %s:%i %s\n", file, line, message );
     ERR_print_errors_fp( stderr );
     exit( EXIT_FAILURE );
}
