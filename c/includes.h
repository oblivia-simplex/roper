#ifndef HATCH_INCLUDES_H
#define HATCH_INCLUDES_H

/**
 * General purpose, standard stuff
 **/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

/** 
 * For ptrace, in particular
 **/

#include <sys/user.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>

/** 
 * For socket functionality
 **/

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * Project-specific headers
 **/

#include "hatchery.h"

#endif
