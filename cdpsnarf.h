/*
 *   $Id: cdpsnarf.h 798 2008-02-18 21:41:20Z zapotek $
 *      
 *     CDPSnarf CDP packet sniffer
 *   Copyright (C) 2006-2007   Zapotek
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef SNARF_H_
#define SNARF_H_

typedef struct _assoc_array {
  int   value;
  const char   *string;
} assoc_array;

typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#include "includes/oui.h"
//#include "includes/crc16/crc.c"

struct address {
    int proto_type;
    int proto_len;
    int proto;
    int address_len;
    int address;
} *addresses;

// Type codes of the CDP TLV
#define TYPE_DEVICE_ID      0x0001 // supported
#define TYPE_ADDRESS        0x0002 // supported
#define TYPE_PORT_ID        0x0003 // supported
#define TYPE_CAPABILITIES   0x0004 // supported
#define TYPE_IOS_VERSION    0x0005 // supported
#define TYPE_PLATFORM       0x0006 // supported
#define TYPE_IP_PREFIX      0x0007 // supported but needs further testing
#define TYPE_PROTOCOL_HELLO     0x0008 // supported
#define TYPE_VTP_MGMT_DOMAIN    0x0009 // supported
#define TYPE_NATIVE_VLAN        0x000a // supported
#define TYPE_DUPLEX             0x000b // supported
/*                              0x000c */
/*                              0x000d */
#define TYPE_VOIP_VLAN_REPLY    0x000e
#define TYPE_VOIP_VLAN_QUERY    0x000f
#define TYPE_POWER              0x0010
#define TYPE_MTU                0x0011 // supported
#define TYPE_TRUST_BITMAP       0x0012 // supported
#define TYPE_UNTRUSTED_COS      0x0013 // supported
#define TYPE_SYSTEM_NAME        0x0014 // supported
#define TYPE_SYSTEM_OID         0x0015 // supported
#define TYPE_MANAGEMENT_ADDR    0x0016 // supported
#define TYPE_LOCATION           0x0017
#define TYPE_EXT_PORT_ID        0x0018
#define TYPE_POWER_REQUESTED    0x0019
#define TYPE_POWER_AVAILABLE    0x001a // not fully supported
#define TYPE_PORT_UNIDIR        0x001b

// the names of the above type codes in the same order
static const char* TYPE_NAMES[] = {
    NULL,
    "Device ID",
    "Addresses" ,
    "Port ID" ,
    "Capabilities" ,
    "Software version" ,
    "Platform" ,
    "IP Prefix/Gateway (used for ODR)" ,
    "Protocol Hello" ,
    "VTP Management Domain" ,
    "Native VLAN" ,
    "Duplex" ,
    NULL,
    NULL,
    "VoIP VLAN Reply" ,
    "VoIP VLAN Query" ,
    "Power consumption" ,
    "MTU",
    "Trust Bitmap" ,
    "Untrusted Port CoS" ,
    "System Name" ,
    "System Object ID" ,
    "Management Address" ,
    "Location" ,
    "External Port-ID" ,
    "Power Requested" ,
    "Power Available" ,
    "Port Unidirectional" ,
};

#define TYPE_HELLO_CLUSTER_MGMT    0x0112

static assoc_array type_hello_vals[] = {
        { TYPE_HELLO_CLUSTER_MGMT,   "Cluster Management" },
        { 0,                    NULL }
};

#define MAC_OFFSET 6

// bytes the from the beggining of the packet used for Ethernet and LLC
#define ENCAP_OFFSET  22

// sizes of the type and length fields in the TLV structure
#define TLV_TYPE_SIZE     2
#define TLV_LENGTH_SIZE   2


// layer 2 protocol type available
char *PROTO_TYPES[] = {
    "Uknown",
    "NLPID",
    "802.2"
};

// IDs of Layer 3 protocols
// NOTE: Keep these in order
double long PROTO[] = {
    0x81,
    0xCC,
    0x86DD, // Cisco says 0x0800 for IPv6 alhtough it is 86DD
    0x6003,
    0x809B,
    0x8137,
    0x80c4,
    0x0600,
    0x8019
};

// Layer 3 protocols used
// NOTE: Keep these in order
char PROTO_NAMES[][15] = {
    "ISO CLNS",
    "IP",
    "IPv6",
    "DECNET Phase IV",
    "AppleTalk",
    "Novell IPX",
    "Banyan VINES",
    "XNS",
    "Apollo Domain"
};

// bit masks for each available capability
int CAPABILITIES[] = {
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40
};

// capability names
char CAPABILITIES_NAMES[7][19] = {
    "Router",
    "Transparent bridge",
    "Source Route Bridge",
    "Switch",
    "Host",
    "IGMP",
    "Repeater"
};

#endif /*SNARF_H_*/
