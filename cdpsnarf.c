/*
 *     CDPSnarf CDP packet sniffer
 *   Copyright (C) 2006-2010   Anastasios "Zapotek" Laskos
 *                                  <tasos.laskos@gmail.com>
 *                                  <zapotek@segfault.gr>
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

/**
 * @author: Zapotek <zapotek@segfault.gr>
 * @description:
 *      CDPSnarf is a network sniffer exclusively written to extract
 *      information from CDP packets.
 *      It provides all the information a "show cdp neighbors detail"
 *      command would return on a Cisco router and even more.
 * 
 *      Example output:
 *      -----------------------------------------------------------
 *      CDPSnarf v0.1.5 initiated.
 *         Author: Zapotek <zapotek@segfault.gr>
 *         Website: http://www.segfault.gr

 *      Waiting for a CDP packet...
 *      
 *      [#1] Sniffed CDP advertisement with a size of 406 bytes.
 *           0 seconds since last advertisement.
 *      -------------------------------------------------------
 *      Source MAC address: 0x00:0x0D:0xED:0x42:0xCD:0x02
 *      
 *      CDP Version: 2
 *      TTL: 180 ms
 *      Checksum: 0x2033
 *      
 *      Device ID: cisco-router-1.lab
 *      
 *      Addresses:
 *         Address #: 1
 *         Protocol type: [1] NLPID format
 *         Protocol: IP
 *         Address: 192.168.0.20
 *      
 *      
 *         Address #: 2
 *         Protocol type: [2] 802.2 format
 *         Protocol: IPv6
 *         Address: FE80:0000:0000:0000:0250:56FF:FEC0:000700
 *      
 *      
 *      Port ID: FastEthernet1/2
 *      
 *      Capabilities:
 *         [0x08]       Switch
 *         [0x20]       IGMP
 *      
 *      Software version: Cisco Internetwork Operating System Software
 *      IOS (tm) C2950 Software (C2950-I6Q4L2-M), Version 12.1(19)EA1a, RELEASE SOFTWARE (fc1)
 *      Copyright (c) 1986-2003 by cisco Systems, Inc.
 *      Compiled Tue 09-Dec-03 00:12 by yenanh
 *      
 *      Platform: cisco WS-C2950-12
 *      
 *      Protocol Hello:
 *         OUI: Cisco
 *         Protocol ID: Cluster Management
 *         Cluster Master IP address: 0.0.0.0
 *         Unknown (IP address?): 255.255.255.255
 *         Version: 1
 *         Sub Version: 2
 *         Status: 0x21
 *         Unknown: 0xFF
 *         Cluster Commander MAC address: 0x00:0x00:0x00:0x00:0x00:0x00
 *         Switch's MAC address: 0x00:0x0D:0xDF:0x67:0x00:0xCD
 *         Unknown: 0xFF
 *         Management VLAN: 0
 *      
 *      
 *      VTP Management Domain:
 *      
 *      Native VLAN: 279
 *      
 *      Duplex: [0x01] Full
 *      
 *      Trust Bitmap: 0
 *      
 *      Untrusted Port CoS: 0
 *      
 *      Management Address:
 *         Address #: 1
 *         Protocol type: [0] NLPID format
 *         Protocol: IP
 *         Address: 192.168.0.20
 *      -----------------------------------------------------------
 * 
 *  In the absence of a Makefile compile with:
 *      gcc -lm -lpcap cdpsnarf.c -o cdpsnarf
 */

/*
 * CDP packet format from Cisco:
 *  http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#xtocid12
 * 
 * Additional info from Cisco:
 *  http://www.cisco.com/en/US/products/hw/switches/ps663/products_tech_note09186a0080094713.shtml#cdp
 * 
 * Wireshark ouput:
 *  http://wiki.wireshark.org/CDP
 * 
 */ 

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <netinet/in.h>
#include "cdpsnarf.h"

#define VERSION "v0.1.6"
#define SVN_REV "$Rev: 797 $"

void tlv_parse( const u_char* , int );
int  tlv_get_number( const u_char*, int );
u_char* tlv_get_text( const u_char* , int );

void print_cdp_addresses( const u_char *, int, int );
void print_ipv6_address( const u_char *, int );
void print_ipv4_address( int );
void print_ip_prefixes( const u_char *, int );
void print_capabilities( int );
void print_protoname( int );
void print_help( char ** );
void print_bin( int );
void payload2hex( const u_char *, int, char * );

int* hex2ipv4( int );
char* get_assoc_value( int, assoc_array * );
//int compute_checksum( const u_char *, int );

int debug = 0;

int main( int argc, char *argv[] ) {
    
    // PCAP session handler
    pcap_t  *handle = 0;
    // PCAP dumper pointer
    pcap_dumper_t *dumper = 0;
    
    // the compiled pcap filter
    struct  bpf_program fp;
    // header structure returned by PCAP
    struct  pcap_pkthdr *header;
    
    // expression filter for CDP packets
    char    filter_exp[] = "ether[12:2] <= 1500 && ether[14:2] == 0xAAAA"
                           " && ether[16:1] == 0x03 && ether[17:2] == 0x0000"
                           " && ether[19:1] == 0x0C && ether[20:2] == 0x2000"
                           " && ether host 01:00:0C:CC:CC:CC";
    // device to sniff on
    char    *dev = NULL;
    // error buffer
    char    errbuf[ PCAP_ERRBUF_SIZE ];

    // our netmask
    bpf_u_int32 mask = 0;
    // our IP address
    bpf_u_int32 net = 0;

    // pcap_next_ex()'s return value
    int     pcap_packet = 1;
    // captured packet's payload
    u_char  *data;
    
    time_t timer = 0;
    
    char *dumpfile = NULL;
    int c;
    int i = 0;
   
    printf( "CDPSnarf %s [%s] initiated.\n", VERSION, SVN_REV );
    printf( "   Author: Anastasios \"Zapotek\" Laskos\n" );
    printf( "             <tasos.laskos@gmail.com>\n" );
    printf( "                <zapotek@segfault.gr>\n" );
    printf( "   Website: http://www.segfault.gr\n" );
    printf( "            http://github.com/Zapotek/cdpsnarf\n\n" );
    
    // get command line arguments
    while( ( c = getopt( argc, argv, "i:dhw:r:" ) ) != -1 ) {
        switch( c ) {
            case 'i':
                dev = optarg;
                handle = pcap_open_live( dev, BUFSIZ, 1, 269000, errbuf );
                
                if( handle == NULL ) {
                    fprintf( stderr, "Couldn't open device %s: %s\n", dev, errbuf );
                    return( 2 );
                }
                
                // get device properties
                if( pcap_lookupnet( dev, &net, &mask, errbuf ) == -1 ) {
                    fprintf( stderr, "Couldn't get netmask for device %s: %s\n",
                             dev, errbuf );
                    net = 0;
                    mask = 0;
                }
                break;
                
            case 'd':
                debug = 1;
                break;
            
            case 'r':
                dumpfile = optarg;
                handle = pcap_open_offline( dumpfile, errbuf );
                if( !handle ){
                    fprintf( stderr, "Couldn't open file %s: %s\n",
                             dumpfile, errbuf );
                    return( 2 );
                }
                
                net = 0;
                mask = 0;
                break;
                                
            case 'w':
                dumper = pcap_dump_open( handle, optarg );
                if( !dumper ){
                    fprintf( stderr, "Couldn't write to file %s: %s\n",
                             optarg, errbuf );
                }
                break;
                
            case '?':
                if( optopt == 'd' || optopt == 'w' ) {
                    fprintf( stderr, "Option -%c requires an argument.\n",
                             optopt );
                } else if( isprint ( optopt ) ) {
                    fprintf( stderr, "Unknown option `-%c'.\n", optopt );
                } else {
                    fprintf( stderr, "Unknown option character `\\x%x'.\n",
                             optopt );
                }
                return 1;

           case 'h':
           default:
               print_help( argv );
               return( 0 );
             
           }
    }
    
    if( !dev && !dumpfile ) {
        print_help( argv );
        return( 0 );
    }
    
    // compile filter
    if( pcap_compile( handle, &fp, filter_exp, 0, mask ) < 0 ) {
        fprintf( stderr, "Couldn't parse filter %s: %s\n", filter_exp,
                 pcap_geterr( handle ) );
        return( 2 );
    }

    // apply compiled filter
    if( pcap_setfilter( handle, &fp ) < 0 ) {
        fprintf( stderr, "Couldn't install filter %s: %s\n", filter_exp,
                 pcap_geterr( handle ) );
        return( 2 );
    }
    
    printf( "Reading packets from %s.\n", ( dev ) ? dev : dumpfile );
    printf( "Waiting for a CDP packet...\n\n" );
    
    // loop forever
    while( pcap_packet == 1 ) {
        
        // grab a packet
        pcap_packet =
            pcap_next_ex( handle, &header, (const u_char **) &data );
        
        // write each packet to the dumpfile as soon as it arrives        
        if( dumper ){
            pcap_dump( (u_char *)dumper, header, data );
            pcap_dump_flush( dumper );
        }
        
        // handle error cases
        switch( pcap_packet ){
            // EOF
            case -2:
                printf( "End of file reached.\nNo more packets to analyze.\n" );
                return( 0 );
            
            // unexpected error
            case -1:
                fprintf( stderr, "An error occured while capturing packet.\n" );
                return( 2 );
            
            // timeout
            case 0:
               fprintf( stderr, "Timeout waiting for CDP packet.\n" );
               // who cares, just keep waiting...
               pcap_packet = 1;
               continue;
        }
        
        
        // tell user we grabed a packet and it's length
        printf( "[#%d] Sniffed CDP advertisement with a size of %d bytes.\n",
                i++, header->len );
        
        // if this is not our first packet display time delta
        if( i > 1 ) {
            printf( "     %.0f seconds since last advertisement.\n",
                    difftime( time( 0 ), timer ) );
        }
        
        printf( "-------------------------------------------------------" );
        
        // start timer
        timer = time( 0 );
        
        // parse TLV tree
        tlv_parse( data, header->len );
        
        printf( "\n" );
    }
    
    // close session
    pcap_close( handle );
    
    return( 0 );
}

/**
 * Function for Type/Length/Value structure parsing (like CDP frames)
 * It traverses the TLV structure and prints out CDP data.
 * 
 * @param   const u_char* payload   the packet data
 * @param   int length              the packet length
 * 
 */
void tlv_parse( const u_char* payload, int length ) {
    
    // the next "Type" field
    int tlv_type;
    // the next "Length" field
    int tlv_length;
    int addresses_num, duplex;
    int offset = 0;
    int tmp = 0;
    u_char* value;
//    unsigned short our_checksum;
    
    printf( "\nSource MAC address: " );
    payload2hex( payload + MAC_OFFSET, 6, ":" );
    
//    compute_checksum( payload, length );
    
    // set payload pointer right after Ethernet and LLC data
    payload += ENCAP_OFFSET;
    
    // get CDP version
    printf( "\nCDP Version: %d\n", *(payload++) );
    
    // get CDP time-to-live
    printf( "TTL: %d ms\n", *(payload++) );
    
    // get checksum
    tmp = tlv_get_number( payload, 2 );
    printf( "Checksum: 0x%02X ", tmp );
    payload += 2;
    
//    our_checksum = crc16_checksum( payload, length - ENCAP_OFFSET - 4 );
    
//    printf( "\n---------------\n" );
//    payload2hex( payload, length - ENCAP_OFFSET - 4, " 0x" );
//    printf( "\n---------------\n" );
    
//    if( our_checksum == tmp ) {
//        printf( "[Correct, 0x%02X]", our_checksum );
//    } else {
//        printf( "[Invalid, should be 0x%02X]", our_checksum );
//    }
    
    printf( "\n\n" );
    
    // subtract Ethernet & LLC encapsulation
    length -= ENCAP_OFFSET + 4;
    // parse TLV until we reach the end of packet data
    while( length ) {
        
        // get next Type
        tlv_type    = tlv_get_number( payload, TLV_TYPE_SIZE );
        if( debug ) printf( "[TLV type: 0x%02X]\n", tlv_type );
        // appropriately forward the pointer
        payload += TLV_TYPE_SIZE;
        
        // get next Length
        tlv_length  = tlv_get_number( payload, TLV_LENGTH_SIZE );
        if( debug ) printf( "[TLV length: %d bytes]\n", tlv_length );
        /*
         * subtract the length of the Type field and the Length field to
         * accurately get the length of the Value field
         */
        tlv_length -= TLV_TYPE_SIZE + TLV_LENGTH_SIZE;
        // appropriately forward the pointer
        payload += TLV_LENGTH_SIZE;
        
        // print current type name
        printf( "%s: ", TYPE_NAMES[tlv_type] );
        
        switch( tlv_type ) {
            
            // addresses are special because the require further parsing
            case TYPE_ADDRESS:
            case TYPE_MANAGEMENT_ADDR:
                // get the number of addresses included in the packet
                addresses_num = tlv_get_number( payload, 4 );
                // parse addresses into the addresses struct
                print_cdp_addresses( payload, addresses_num, tlv_length );
                break;
            
            // capabilities require bitmask matching
            case TYPE_CAPABILITIES:
                printf( "\n" );
                print_capabilities( tlv_get_number( payload, tlv_length ) );
                break;
            
            // nothing special about duplex, just requires a bit more logic
            case TYPE_DUPLEX:
                duplex = tlv_get_number( payload, tlv_length );
                
                printf( "[0x%02x] %s\n", duplex,
                                        ( duplex ) ? "Full" : "Half" );
                break;
            
            case TYPE_PROTOCOL_HELLO:
                printf( "\n" );
                
                tmp = tlv_get_number( payload, 3 );
                
                printf( "   OUI: %s\n", get_assoc_value( tmp, OUI_NAMES ) );
                offset += 3;
                
                tmp = tlv_get_number( payload + offset, 2 );
                
                printf( "   Protocol ID: %s\n",
                        get_assoc_value( tmp, type_hello_vals ) );
                
                if( tmp == TYPE_HELLO_CLUSTER_MGMT ){
                    offset += 2;
                    
                    printf( "   Cluster Master IP address: " );
                    tmp = tlv_get_number( payload + offset, 4 );
                    print_ipv4_address( tmp );
                    offset += 4;
                    
                    printf( "\n   Unknown (IP address?): " );
                    tmp = tlv_get_number( payload + offset, 4 );
                    print_ipv4_address( tmp );
                    offset += 4;
                    
                    printf( "\n   Version: %d\n", 
                            tlv_get_number( payload + offset, 1 ) );
                    offset += 1;
                    
                    printf( "   Sub Version: %d\n", 
                            tlv_get_number( payload + offset, 1 ) );
                    offset += 1;
                    
                    printf( "   Status: 0x%02X\n", 
                            tlv_get_number( payload + offset, 1 ) );
                    offset += 1;
                    
                    printf( "   Unknown: 0x%02X\n", 
                            tlv_get_number( payload + offset, 1 ) );
                    offset += 1;
                    
                    printf( "   Cluster Commander MAC address: " );
                    payload2hex( payload + offset, 6, ":" );
                    offset += 6;
                    
                    printf( "   Switch's MAC address: " );
                    payload2hex( payload + offset, 6, ":" );
                    offset += 6;
                    
                    printf( "   Unknown: 0x%02X\n", 
                            tlv_get_number( payload + offset, 1 ) );
                    offset += 1;
                    
                    printf( "   Management VLAN: %d\n", 
                            tlv_get_number( payload + offset, 1 ) );
                    offset += 1;
                }
                
                printf( "\n" );
                break;
            
            case TYPE_POWER_AVAILABLE:
                printf( "\n" );
                printf( "    Request ID: %u(?)\n",
                        tlv_get_number( payload, 4 ) );
                offset += 4;
                
                printf( "    Management ID: %u(?)\n",
                        tlv_get_number( payload + offset, 4 ) );
                offset += 4;
                
                tmp = tlv_get_number( payload + offset, TLV_LENGTH_SIZE );
                printf( "    Power Available: %u mW(?)\n",
                        tlv_get_number( payload + offset, 2 ) );
                
                break;
            
            case TYPE_TRUST_BITMAP:
                tmp = tlv_get_number( payload, 2 );
                printf( "0x%02X", tmp );
                if( tmp ) {
                    printf( "[" );
                    print_bin( tmp );
                    printf( "]" );
                }
                printf( "\n" );
                break;
            
            case TYPE_IP_PREFIX:
                printf( "\n" );
                print_ip_prefixes( payload, tlv_length );
                break;
            
            case TYPE_MTU:
            case TYPE_NATIVE_VLAN:
            case TYPE_UNTRUSTED_COS:
                printf( "%u\n", tlv_get_number( payload, 2 ) );
                break;
            
            // the rest type values are just text, so print the text
            default:
                value = tlv_get_text( payload, tlv_length );
                printf( "%s\n", value );
                free( value );
                break;
        }
        
        tmp = 0;
        offset = 0;
        // forward pointer to the next TLV
        payload += tlv_length;
        // lessen the length variable
        length -= tlv_length + TLV_TYPE_SIZE + TLV_LENGTH_SIZE;
        
        printf( "\n" );
        
    }
    
}

/**
 * Function for getting a number residing in the next "length" bytes
 * of the payload
 * 
 * @param   const u_char* payload   the payload
 * @param   int length              the aforementioned length
 * 
 * @return  int                     the aforementioned number
 */
int tlv_get_number( const u_char* payload, int length ) {
    int z, tl;
    long div;
    
    tl = 0x0;
    for( div = pow( 0x100, length - 1 ), z = 0;
         z < length;
         div /= 0x100, z++ )
    {
        tl += ( div ) ? *payload++ * div : *payload++ ;
    }

    return tl;
}

/**
 * Function for getting a string residing in the next "length" bytes
 * of the payload
 * 
 * @param   const u_char* payload   the payload
 * @param   int length              the aforementioned length
 * 
 * @return  const u_char*           the aforementioned string
 */
u_char* tlv_get_text( const u_char* payload, int length ) {
    u_char* value;
    
    value = malloc( length + 1);
    memcpy( value, payload, length );
    value[length] = '\0';
    
    return value;
}

/**
 * Function for parsing the Addresses field of the CDP packet into
 * addresses struct
 * 
 * @param    const u_char *payload      payload pointer located right
 *                                      before the addresses field
 * 
 * @param    int address_num            the number of included addresses
 * @param    int address_len            the length of the field
 * 
 */
void print_cdp_addresses( const u_char *payload, int address_num,
                          int address_len )
{
    int i;
    
    payload += 4;
    
    // save enough space for all included addresses
    addresses = calloc( address_num, address_len );
    /* 
     * loop thought all the addresses harvesting data and storing them
     * into the appropriate members of addresses
     */
    for( i = 0; i < address_num; addresses++, i++ ) {
        printf( "\n   Address #: %d\n", i + 1 );
        addresses->proto_type = *payload++;
        
        if( debug )
            printf( "[Protocol type: 0x%04X]\n", addresses->proto_type );
            
        printf( "   Protocol type: [%d] %s format\n",
                addresses->proto_type,
                PROTO_TYPES[addresses->proto_type] );

        addresses->proto_len  = *payload++;
        if( debug )
            printf( "[Protocol length: %d bytes]\n", addresses->proto_len );
        
        /*
         * The cool thing with protocols other than IP and ISO CLNS
         * (whose protocol length is 1 byte)
         * is that they all have a suffix of 0xaaaa03000000 so we can
         * ignore it and store only the 2 last hex values (ex. 86dd for IPv6)
         * 
         */
        if( addresses->proto_len == 8 ) {
            addresses->proto  =
                tlv_get_number( payload + (addresses->proto_len - 2), 2 );
        } else {
            addresses->proto  =
                tlv_get_number( payload, addresses->proto_len );
        }
        
        if( debug )
            printf( "[Address protocol: 0x%04X]\n", addresses->proto );
            
        printf( "   Protocol: " );
        print_protoname( addresses->proto );
        printf( " \n" );
        
        payload += addresses->proto_len;
        
        addresses->address_len  =
            tlv_get_number( payload, TLV_LENGTH_SIZE );
        
        if( debug )
            printf( "[Address length: %d bytes]\n", addresses->address_len );
            
        payload += TLV_LENGTH_SIZE;
        
        printf( "   Address: " );
        if( addresses->address_len <= 4 ) {
            print_ipv4_address( tlv_get_number( payload, addresses->address_len ) );
        } else {
            print_ipv6_address( tlv_get_text( payload, addresses->address_len ),
                                addresses->address_len );
        }
        printf( "\n\n" );
        
        payload += addresses->address_len;
    }
    
    addresses -= i;
    
    free( addresses );
}

/**
 * Function for convertng hexadecimal IP addresses to decimal parts
 * ( ex. 0xC0A80014 to 192.168.0.20 )
 * 
 * @param int hex   hexadecimal format of IP address
 *
 * @return  array with 4 entries holding each IP address decimal value
 */
int* hex2ipv4( int hex ) {
    int *ip_address;
    
    ip_address = calloc( 4, sizeof(int) );
    
    ip_address[3] = hex & 0xff;
    ip_address[2] = (hex & 0xff00) / 0x100;
    ip_address[1] = (hex & 0xff0000) / 0x10000;
    ip_address[0] = (hex & 0xff000000) / 0x1000000;
                    
    return ip_address;  
}

/**
 * Print IPv4 address based on a hexadecimal value
 * 
 * @param   int hex     hex version of the IP address
 * 
 */
void print_ipv4_address( int hex ) {
    int *ip_address;
    
    ip_address = hex2ipv4( hex );
    printf( "%u.%u.%u.%u",
            ip_address[0],
            ip_address[1],
            ip_address[2],
            ip_address[3] );
    
    free( ip_address );
}

/**
 * Print IPv6 address based on a hexadecimal string
 * 
 * @param   const u_char *payload     hex string of the IP address
 * @param   int length                length of the IP address
 * 
 */
void print_ipv6_address( const u_char *payload, int length ) {
    do {
        printf( "%02X", *payload++ );
        if( length != 1 && length % 2 ) printf( ":" );
    } while( length-- );
}

/**
 * Prints IPv4 prefixes
 * 
 * @param   const u_char *payload     payload right before the IP prefixes
 * @param   int length                length of the IP prefixes
 * 
 */
void print_ip_prefixes( const u_char *payload, int length ) {
    int iterations, offset = 0, i = 1;
    
    for( iterations = length / 5; iterations; iterations--, offset += 5 ) {
        printf( "    [%d] ", i++ );
        print_ipv4_address( tlv_get_number( payload + offset, 4 ) );
        printf( "/%d\n", tlv_get_number( payload + 4 + offset, 1 ) );
    }
    
}

/**
 * Print help message
 * 
 * @param   char *argv[]    program command line arguments
 * 
 */
void print_help( char *argv[] ) {
    printf( "%s -i <dev> [-h] [-w savefile] [-r dumpfile] [-d]\n\n", argv[0] );
    printf( "   -i      define the interface to sniff on\n" );
    printf( "   -w      write packets to PCAP dump file\n" );
    printf( "   -r      read packets from PCAP dump file\n" );
    printf( "   -d      show debugging information\n" );
    printf( "   -h      show help message and exit\n\n" );
}

/**
 * Function for printing device's capabilities
 * 
 * @param   int bitmask     hexadecimal capabilities' bitmask
 * 
 */
void print_capabilities( int bitmask ) {
    int i;
   
    // loop through all capability bitmasks searching for matches
    for( i = 0; i < sizeof CAPABILITIES / sizeof (int); i++ ) {
        // print match
        if( CAPABILITIES[i] & bitmask )
            printf( "   [0x%02X]\t%s\n", CAPABILITIES[i],
                    CAPABILITIES_NAMES[i] );
    }
}

/**
 * Function for printing protocol in use
 * 
 * @param   int hex     hexadecimal protocol ID
 * 
 */
void print_protoname( int hex ) {
    int i;
    
    for( i = 0; i < sizeof PROTO_NAMES / sizeof (char); i++ ) {
        if( PROTO[i] == hex ) {
            printf( "%s", PROTO_NAMES[i] );
            return;
        }

    }
    printf( "Uknown" );
}

/**
 * Simple debugging function for printing a given payload as a 
 * sequence of hexadecimal values
 * 
 * @param   const u_char *payload   the payload
 * @param   int length              how much of the payload to print
 * @param   char *delim             delimiter between hex values
 * 
 */
void payload2hex( const u_char *payload, int length, char *delim ) {
    
    while( length-- ) {
        printf( "%02X", *payload++ );
        if( length != 0 ) printf( "%s", delim );
    }
    printf( "\n" );
    
}

/**
 * Function used with the "_assoc_array" struct in order to get
 * stored strings based on the stored values
 * 
 * @param   int value           the value to look for
 * @param   assoc_array *aray   the struct
 * 
 * @return char *
 */
char* get_assoc_value( int value, assoc_array *array ){
    int i = 0;
    while( array[i].string ){
        if( array[i].value == value ) return (char *) array[i].string;
        i++;
    }
    return 0;
}

/**
 * Print binary representation of a number
 * 
 * @param   int num     number to convert to binary
 */
void print_bin( int number ) {
    int remainder;

    if( number <= 1 ) {
        printf( "%d", number );
        return;
    }

    remainder = number % 2;
    print_bin( number >> 1 );    
    printf( "%d", remainder );
}

//int compute_checksum( const u_char *payload, int length ) {
//    u_char *data;
//
//    data = malloc( length + 20 );
//    
//    memcpy( data, payload, ENCAP_OFFSET + 2 );
//    data += ENCAP_OFFSET + 2;
//    memcpy( data, payload + ENCAP_OFFSET + 4, length - 2 );
//    data -= ENCAP_OFFSET + 2;
//    
//    payload2hex( payload, length, " 0x" );
//    printf( "\n-----------------\n" );
//    payload2hex( data, length - 2, " 0x" );
//    
//    printf( "\n:::: 0x%04X ::::\n", crc16_checksum( data, length - 2 ) );
//    printf( ":::: 0x%04X ::::\n", crc16_checksum( payload, length ) );
//    
//    free( data );
//    
//    return( 1 );
//}
