// all available options:
// https://github.com/lwip-tcpip/lwip/blob/STABLE-2_1_3_RELEASE/src/include/lwip/opt.h
//
#ifndef lwipopts_h
#define lwipopts_h

// freestanding envrionment
#define NO_SYS 1       // we don't have an OS
#define LWIP_SOCKET 0  // requires multi-threaded environments with os
#define LWIP_NETCONN 0 // requires multi-threaded environments with os
#define LWIP_MPU_COMPATIBLE 0
#define LWIP_TCPIP_CORE_LOCKING 0

// features
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_UDP 1
#define LWIP_TCP 1
#define LWIP_DHCP 1
#define LWIP_IGMP 0 // LWIP_IPV4
#define LWIP_ICMP LWIP_IPV4
#define LWIP_DNS LWIP_UDP
#define LWIP_MDNS_RESPONDER LWIP_UDP
#define LWIP_NETIF_HOSTNAME 1

#define PPP_SUPPORT 0
#define PPP_NUM_TIMEOUTS 0
// ~ 10 seconds faster dhcp bound (Address Conflict Detection)
#define LWIP_DHCP_DOES_ACD_CHECK 0

// callbacks
#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_EXT_STATUS_CALLBACK 0

// stats
#define LWIP_STATS 1
#define LINK_STATS 1
#define IP_STATS 1
#define ICMP_STATS 1
#define IGMP_STATS 1
#define IPFRAG_STATS 1
#define UDP_STATS 1
#define TCP_STATS 1
#define MEM_STATS 1
#define MEMP_STATS 1
#define PBUF_STATS 1
#define SYS_STATS 1

#define MEMP_NUM_SYS_TIMEOUT 16

// debug switches, debugging is enabled in arch/cc.h
// #define DHCP_DEBUG LWIP_DBG_ON
// #define SNTP_DEBUG LWIP_DBG_ON
// #define TIMERS_DEBUG LWIP_DBG_ON
// #define LWIP_DEBUG_TIMERNAMES 1
//
#define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
#define LWIP_DBG_TYPES_ON                                                      \
    (LWIP_DBG_ON | LWIP_DBG_TRACE | LWIP_DBG_STATE | LWIP_DBG_FRESH)

// sntp
#define LWIP_SNTP 1
#define SNTP_SERVER_DNS 1
#define SNTP_GET_SERVERS_FROM_DHCP 1

#endif // lwipopts_h
