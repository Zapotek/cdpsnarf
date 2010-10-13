/*
 *     CDPSnarf CDP packet sniffer
 *   Copyright (C) 2006-2010   Tasos "Zapotek" Laskos
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

#ifndef OUI_H_
#define OUI_H_

/*
 * Registered OUIs: http://standards.ieee.org/regauth/oui/oui.txt
 *
 */

#define OUI_ENCAP_ETHER     0x000000    /* encapsulated Ethernet */
#define OUI_XEROX           0x000006    /* Xerox */
#define OUI_CISCO           0x00000C    /* Cisco (future use) */
#define OUI_NORTEL          0x000081    /* Nortel SONMP */
#define OUI_CISCO_90        0x0000F8    /* Cisco (IOS 9.0 and above?) */
#define OUI_ERICSSON        0x0001EC    /* Ericsson Group */    
#define OUI_CATENA          0x00025A    /* Catena Networks */
#define OUI_SONY_ERICSSON   0x000AD9    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_2 0x000E07    /* Sony Ericsson Mobile Communications AB */
#define OUI_PROFINET        0x000ECF    /* PROFIBUS Nutzerorganisation e.V. */
#define OUI_SONY_ERICSSON_3 0x000FDE    /* Sony Ericsson Mobile Communications AB */
#define OUI_IEEE_802_3      0x00120F    /* IEEE 802.3 */
#define OUI_MEDIA_ENDPOINT  0x0012BB    /* Media (TIA TR-41 Committee) */
#define OUI_SONY_ERICSSON_4 0x0012EE    /* Sony Ericsson Mobile Communications AB */
#define OUI_ERICSSON_MOBILE 0x0015E0    /* Ericsson Mobile Platforms */ 
#define OUI_SONY_ERICSSON_5 0x001620    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_6 0x0016B8    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_7 0x001813    /* Sony Ericsson Mobile Communications AB */
#define OUI_SONY_ERICSSON_8 0x001963    /* Sony Ericsson Mobile Communications AB */
#define OUI_CISCOWL         0x004096    /* Cisco Wireless (Aironet) */
#define OUI_ERICSSON_2      0x008037    /* Ericsson Group */    
#define OUI_BRIDGED         0x0080C2    /* Bridged Frame-Relay, RFC 2427 */
                                        /* and Bridged ATM, RFC 2684 */
#define OUI_IEEE_802_1      0x0080C2    /* IEEE 802.1 Committee */
#define OUI_ATM_FORUM       0x00A03E    /* ATM Forum */
#define OUI_EXTREME         0x00E02B    /* Extreme EDP/ESRP */
#define OUI_CABLE_BPDU      0x00E02F    /* DOCSIS spanning tree BPDU */
#define OUI_SIEMENS         0x080006    /* Siemens AG */
#define OUI_APPLE_ATALK     0x080007    /* Appletalk */
#define OUI_HP              0x080009    /* Hewlett-Packard */

// the names of the above OUI codes
static assoc_array OUI_NAMES[] = {
    { OUI_ENCAP_ETHER,   "Encapsulated Ethernet" },
    { OUI_XEROX,   "Xerox" },
    { OUI_CISCO,   "Cisco" },
    { OUI_NORTEL,   "Nortel SONMP" },
    { OUI_CISCO_90,   "Cisco" },
    { OUI_ERICSSON,   "Ericsson Group" },
    { OUI_CATENA,   "Catena Networks" },
    { OUI_SONY_ERICSSON,   "Sony Ericsson Mobile Communications AB" },
    { OUI_SONY_ERICSSON_2,   "Sony Ericsson Mobile Communications AB" },
    { OUI_PROFINET,   "PROFIBUS Nutzerorganisation e.V." },
    { OUI_SONY_ERICSSON_3,   "Sony Ericsson Mobile Communications AB" },
    { OUI_IEEE_802_3,   "IEEE 802.3" },
    { OUI_MEDIA_ENDPOINT,   "Media (TIA TR-41 Committee)" },
    { OUI_SONY_ERICSSON_4,   "Sony Ericsson Mobile Communications AB" },
    { OUI_ERICSSON_MOBILE,   "Sony Ericsson Mobile Communications AB" },
    { OUI_SONY_ERICSSON_5,   "Sony Ericsson Mobile Communications AB" },
    { OUI_SONY_ERICSSON_6,   "Sony Ericsson Mobile Communications AB" },
    { OUI_SONY_ERICSSON_7,   "Sony Ericsson Mobile Communications AB" },
    { OUI_SONY_ERICSSON_8,   "Sony Ericsson Mobile Communications AB" },
    { OUI_CISCOWL,   "Cisco Wireless (Aironet)" },
    { OUI_ERICSSON_2,   "Ericsson Group" },
    { OUI_BRIDGED,   " Bridged Frame-Relay/ATM" },
    { OUI_IEEE_802_1,   "IEEE 802.1 Committee" },
    { OUI_ATM_FORUM,   "ATM Forum" },
    { OUI_EXTREME,   "Extreme EDP/ESRP" },
    { OUI_CABLE_BPDU,   "DOCSIS spanning tree BPDU" },
    { OUI_SIEMENS,   "Siemens AG" },
    { OUI_APPLE_ATALK,   "Appletalk" },
    { OUI_HP,   "Hewlett-Packard" }
};

#endif /*OUI_H_*/
