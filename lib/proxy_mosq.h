/*
Support for PROXY v1 from a load balancer.
*/

#ifndef PROXY_MOSQ_H
#define PROXY_MOSQ_H

#include "mosquitto.h"
#include "mosquitto_internal.h"

#define PROXY_MAX_SIZE 108
#define PROXY_MIN_SIZE 32
#define PROXY_HOST_SIZE 40
#define PROXY_CR 0x0D
#define PROXY_LF 0x0A

#define PROXY_INVALID 1
#define PROXY_VALID 2
#define PROXY_READING 3

#define PROXY_STATE_HDR 0
#define PROXY_STATE_CONN 1
#define PROXY_STATE_IP_SRC 2
#define PROXY_STATE_IP_DST 3
#define PROXY_STATE_PORT_SRC 4
#define PROXY_STATE_PORT_DST 5
#define PROXY_STATE_END 6

int proxy__read_header(struct mosquitto *mosq);
int8_t proxy__verify_header(struct mosquitto *mosq);

#endif
