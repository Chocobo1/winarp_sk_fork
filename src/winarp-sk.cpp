/*
 * WinARP Swiss Knife
 * winarp_sk is the Windows lite version of arp_sk
 *
 * It requires WinPcap (http://winpcap.polito.it/)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include "packet32.h"
#include "winpcap_common.h"
#include "winarp_sk.h"
#include "getopt.h"
#include <ddk/Ndis.h>



/* Main Program */
int main( int argc, char *argv[] )
{
	/* getopt */
	extern char  *optarg;
	register int opt;

	/* WinPcap */
	LPADAPTER lpAdapter = 0;
	LPPACKET  lpPacket;

	/* ARP Packet */
	struct arp_packet arp_pkt;

	/* Ethernet & ARP packet */
	unsigned char	arpsender[ARP_ETH_ADD_SPACE];
	unsigned char	arptarget[ARP_ETH_ADD_SPACE];
	unsigned char	ethersource[ETH_ADD_LEN];
	unsigned char	etherdest[ETH_ADD_LEN];
	unsigned char	ipsource[ARP_IP_ADD_SPACE];
	unsigned char	ipdest[ARP_IP_ADD_SPACE];
	int           opcode = 0;

	/* Flags */
	int flag_mode = 0;
	int flag_delay = 0;
	int flag_count = 0;
	int flag_dst_ethaddr = 0;
	int flag_src_ethaddr = 0;
	int flag_send_macaddr = 0;
	int flag_send_ipaddr = 0;
	int flag_tar_macaddr = 0;
	int flag_tar_ipaddr = 0;
	int adapter_open = 0;

	/* Others */
	unsigned int tmpaddr[6];
	int          delay = 2000;
	int          count = -1;
	int          packetcount = 0;
	int          i;


	/* Get options */
	while( ( opt = getopt( argc, argv, "aig:hm:D:S:d:T:s:F:t:c:" ) ) != EOF )
	{
		switch( opt )
		{
			/* Show ethernet address */
			case 'a' :
				if( open_adapter( &lpAdapter ) == EXIT_FAILURE )
				{
					exit( EXIT_FAILURE );
				}

				get_ether_addr( lpAdapter, NULL );
				close_adapter( lpAdapter );

				exit( EXIT_SUCCESS );

			/* Show IP address */
			case 'i' :
				get_ip_addr( NULL );

				exit( EXIT_SUCCESS );

			/* Get the MAC address of a remote host */
			case 'g' :
				if( ( strlen( optarg ) < 7 ) || ( strlen( optarg ) > 15 ) )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%d.%d.%d.%d",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2], &tmpaddr[3] );

				for( i = 0; i < 4; i++ )
				{
					ipdest[i] = ( unsigned char )tmpaddr[i];
				}

				open_adapter( &lpAdapter );
				get_remote_mac( lpAdapter, ipdest, NULL, 1 );
				close_adapter( lpAdapter );

				exit( EXIT_SUCCESS );

			/* Help */
			case 'h' :
				usage( argv[0] );

				exit( EXIT_SUCCESS );

			/* Number of packets to send */
			case 'c' :
				if( ( count = atoi( optarg ) ) <= 0 )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				flag_count = 1;
				break;

			/* Delay between packets */
			case 't' :
				delay = atoi( optarg );
				flag_delay = 1;
				break;

			/* ARP mode (request or reply) */
			case 'm' :
				if( atoi( optarg ) == 1 )
				{
					opcode = ARP_OP_REQUEST;
				}
				else
				{
					if( atoi( optarg ) == 2 )
					{
						opcode = ARP_OP_REPLY;
					}
					else
					{
						usage( argv[0] );

						exit( EXIT_FAILURE );
					}
				} ;

				flag_mode = 1;
				break;

			/* Ethernet destination address */
			case 'D' :
				if( strlen( optarg ) != 17 )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%02X-%02X-%02X-%02X-%02X-%02X",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2],
						&tmpaddr[3], &tmpaddr[4], &tmpaddr[5] );

				for( i = 0; i < 6; i++ )
				{
					etherdest[i] = ( unsigned char )tmpaddr[i];
				}

				flag_dst_ethaddr = 1;
				memset( tmpaddr, 0, sizeof( tmpaddr ) );
				break;

			/* Ethernet source address */
			case 'S' :
				if( strlen( optarg ) != 17 )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%02X-%02X-%02X-%02X-%02X-%02X",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2],
						&tmpaddr[3], &tmpaddr[4], &tmpaddr[5] );

				for( i = 0; i < 6; i++ )
				{
					ethersource[i] = ( unsigned char )tmpaddr[i];
				}

				flag_src_ethaddr = 1;
				memset( tmpaddr, 0, sizeof( tmpaddr ) );
				break;

			/* Target IP address */
			case 'd' :
				if( ( strlen( optarg ) < 7 ) || ( strlen( optarg ) > 15 ) )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%d.%d.%d.%d",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2],
						&tmpaddr[3] );

				for( i = 0; i < 4; i++ )
				{
					ipdest[i] = ( unsigned char )tmpaddr[i];
				}

				flag_tar_ipaddr = 1;
				memset( tmpaddr, 0, sizeof( tmpaddr ) );
				break;

			/* Target MAC address */
			case 'T' :
				if( strlen( optarg ) != 17 )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%02X-%02X-%02X-%02X-%02X-%02X",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2],
						&tmpaddr[3], &tmpaddr[4], &tmpaddr[5] );

				for( i = 0; i < 6; i++ )
				{
					arptarget[i] = ( unsigned char )tmpaddr[i];
				}

				flag_tar_macaddr = 1;
				memset( tmpaddr, 0, sizeof( tmpaddr ) );
				break;

			/* Sender IP address */
			case 's' :
				if( ( strlen( optarg ) < 7 ) || ( strlen( optarg ) > 15 ) )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%d.%d.%d.%d",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2],
						&tmpaddr[3] );

				for( i = 0; i < 4; i++ )
				{
					ipsource[i] = ( unsigned char )tmpaddr[i];
				}

				flag_send_ipaddr = 1;
				memset( tmpaddr, 0, sizeof( tmpaddr ) );
				break;

			/* Sender MAC address */
			case 'F' :
				if( strlen( optarg ) != 17 )
				{
					usage( argv[0] );

					exit( EXIT_FAILURE );
				}

				sscanf( optarg, "%02X-%02X-%02X-%02X-%02X-%02X",
						&tmpaddr[0], &tmpaddr[1], &tmpaddr[2],
						&tmpaddr[3], &tmpaddr[4], &tmpaddr[5] );

				for( i = 0; i < 6; i++ )
				{
					arpsender[i] = ( unsigned char )tmpaddr[i];
				}

				flag_send_macaddr = 1;
				memset( tmpaddr, 0, sizeof( tmpaddr ) );
				break;
		}
	}

	/* Check minimal options */
	if( ( flag_mode && flag_send_ipaddr && flag_tar_ipaddr ) != 1 )
	{
		usage( argv[0] );

		exit( EXIT_FAILURE );
	}

	/* Check ethernet source address */
	if( flag_src_ethaddr != 1 )
	{
		if( open_adapter( &lpAdapter ) == EXIT_FAILURE )
		{
			exit( EXIT_FAILURE );
		}

		/* if no address is specified the current adapter address is used */
		get_ether_addr( lpAdapter, ethersource );
		flag_src_ethaddr = 1;
		adapter_open = 1;
	}

	/* Check ethernet destination address */
	if( ( flag_dst_ethaddr != 1 ) && ( flag_tar_ipaddr == 1 ) )
	{
		if( adapter_open != 1 )
		{
			if( open_adapter( &lpAdapter ) == EXIT_FAILURE )
			{
				exit( EXIT_FAILURE );
			}

			adapter_open = 1;
		}

		/* if no address is specified the MAC address of ARP Target is used */
		if( get_remote_mac( lpAdapter, ipdest, etherdest, 0 ) == EXIT_FAILURE )
		{
			exit( EXIT_FAILURE );
		}

		flag_dst_ethaddr = 1;
	}


	/* Check arp sender MAC address */
	if( flag_send_macaddr != 1 )
	{
		if( adapter_open != 1 )
		{
			if( open_adapter( &lpAdapter ) == EXIT_FAILURE )
			{
				exit( EXIT_FAILURE );
			}

			adapter_open = 1;
		}

		/* if no address is specified the current adapter address is used */
		get_ether_addr( lpAdapter, arpsender );
		flag_send_macaddr = 1;
	}

	/* Check arp target MAC address */
	if( ( flag_tar_macaddr != 1 ) && ( flag_tar_ipaddr == 1 ) )
	{
		if( adapter_open != 1 )
		{
			if( open_adapter( &lpAdapter ) == EXIT_FAILURE )
			{
				exit( EXIT_FAILURE );
			}

			adapter_open = 1;
		}

		/* if no address is specified the MAC address of ARP Target is used */
		if( get_remote_mac( lpAdapter, ipdest, arptarget, 0 ) == EXIT_FAILURE )
		{
			exit( EXIT_FAILURE );
		}

		flag_tar_macaddr = 1;
	}

	/* Check options and set default fields */
	if( ( flag_mode && flag_dst_ethaddr && flag_src_ethaddr &&
			flag_send_macaddr && flag_send_ipaddr && flag_tar_macaddr &&
			flag_tar_ipaddr ) != 1 )
	{
		usage( argv[0] );

		exit( EXIT_FAILURE );
	}

	/* Open selected adapter */
	if( adapter_open != 1 )
	{
		open_adapter( &lpAdapter );
	}

	/* Allocate PACKET structure */
	if( ( lpPacket = PacketAllocatePacket() ) == NULL )
	{
		fprintf( stderr, "\nError : failed to allocate the LPPACKET structure" );
		PacketCloseAdapter( lpAdapter );

		exit( EXIT_FAILURE );
	}

	/* Init packet structure */
	memset( &arp_pkt, 0, sizeof( struct arp_packet ) );

	/* Build custom ARP packet */
	arp_build( &arp_pkt, etherdest, ethersource, opcode, arpsender, ipsource, arptarget, ipdest );

	/* Init packet */
	PacketInitPacket( lpPacket, &arp_pkt, sizeof( arp_pkt ) );

	/* Set number of packets to send */
	if( PacketSetNumWrites( lpAdapter, 1 ) == FALSE )
	{
		fprintf( stderr, "\nWarning : unable to send more than one packet in a single write\n" );
	}

	/* Print start informations */
	print_start( etherdest, ethersource, opcode, arpsender, ipsource, arptarget, ipdest );

	/* Send packet */
	printf( "+ Start sending\n" );
	printf( "  " );

	while( 1 )
	{
		if( PacketSendPacket( lpAdapter, lpPacket, TRUE ) == FALSE )
		{
			fprintf( stderr, "\nError : unable to send the packets\n" );
			PacketCloseAdapter( lpAdapter );
			PacketFreePacket( lpPacket );

			exit( EXIT_FAILURE );
		}

		printf( "." );
		packetcount++;

		if( ( packetcount % 46 ) == 0 )
		{
			printf( "\n  " );
		}

		Sleep( delay );

		if( count > 0 )
		{
			count--;
			if( !( ( count != 0 ) && ( count != -1 ) ) )
			{
				PacketFreePacket( lpPacket );
				close_adapter( lpAdapter );

				/* Print statistics */
				printf( "\n+ End sending\n" );
				statistics( packetcount );

				exit( EXIT_SUCCESS );
			}
		}

		if( _kbhit() )
		{
			PacketFreePacket( lpPacket );
			close_adapter( lpAdapter );

			/* Print statistics */
			printf( "\n+ End sending\n" );
			statistics( packetcount );

			exit( EXIT_SUCCESS );
		}
	}

	return( EXIT_SUCCESS );
}



int arp_build( struct arp_packet *arp_pkt, unsigned char *dst_etheraddr,
			   unsigned char *src_etheraddr, int ar_op, unsigned char *ar_sha,
			   unsigned char *ar_sip, unsigned char *ar_tha, unsigned char *ar_tip )
{
	/* Set ethernet header */
	memcpy( &( arp_pkt->eth_dst_addr ), dst_etheraddr, ETH_ADD_LEN );
	memcpy( &( arp_pkt->eth_src_addr ), src_etheraddr, ETH_ADD_LEN );
	arp_pkt->eth_type = htons( ETH_TYPE_ARP );

	/* Set ARP header */
	arp_pkt->ar_hrd = htons( ARP_HW_ETH );
	arp_pkt->ar_pro = htons( ARP_PRO_IP );
	arp_pkt->ar_hln = ARP_ETH_ADD_SPACE;
	arp_pkt->ar_pln = ARP_IP_ADD_SPACE;
	arp_pkt->ar_op  = htons( ar_op );

	memcpy( &( arp_pkt->ar_sha ), ar_sha, ARP_ETH_ADD_SPACE );
	memcpy( &( arp_pkt->ar_spa ), ar_sip, ARP_IP_ADD_SPACE );
	memcpy( &( arp_pkt->ar_tha ), ar_tha, ARP_ETH_ADD_SPACE );
	memcpy( &( arp_pkt->ar_tpa ), ar_tip, ARP_IP_ADD_SPACE );

	/* Set ethernet padding */
	memset( arp_pkt->eth_pad, 32, ETH_PADDING_ARP );

	return( EXIT_SUCCESS );
}


void usage( char *name )
{
	printf( "WinARP Swiss Knife version %s\n", RELEASE_VERSION );
	printf( "\nusage: %s -m mode [-D dst_ether_addr] [-S src_ether_addr] [-F sender_MAC] -d sender_IP [-T target_MAC] -s target_IP [-t delay] [-c count]\n\n", name );

	printf( "Ethernet options:\n" );
	printf( "  -D  ethernet address of destination [MAC of ARP target]\n" );
	printf( "  -S  ethernet address of source [selected adapter MAC address]\n" );
	printf( "\n" );

	printf( "ARP options:\n" );
	printf( "  -m  ARP mode (request = 1 and reply = 2)\n" );
	printf( "  -F  MAC address of sender [selected adapter MAC address]\n" );
	printf( "  -s  IP address of sender\n" );
	printf( "  -T  MAC address of target [MAC of ARP target]\n" );
	printf( "  -d  IP address of target\n" );
	printf( "\n" );

	printf( "Misc. options:\n" );
	printf( "  -c  number of packets to send [infinity]\n" );
	printf( "  -t  time between successive packets in ms [2000 ms]\n" );
	printf( "  -h  help\n" );
	printf( "\n" );

	printf( "Standalone options:\n" );
	printf( "  -a  show ethernet address of adapter\n" );
	printf( "  -i  show ip address\n" );
	printf( "  -g  ip_addr : get the remote MAC address of a host\n" );
	printf( "\n" );
}


void get_ether_addr( LPADAPTER lpAdapter, unsigned char *ether_addr )
{
	/* Variables */
	ULONG            IoCtlBufferLength = ( sizeof( PACKET_OID_DATA ) + sizeof( ULONG ) - 1 );
	PPACKET_OID_DATA OidData;


	/* Memory allocation for PACKET_OID_DATA structure */
	OidData = ( struct _PACKET_OID_DATA * )malloc( IoCtlBufferLength );

	/* Set Oid to indicate our query */
	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;

	/* Query the adapter for his MAC address */
	if( PacketRequest( lpAdapter, FALSE, OidData ) == FALSE )
	{
		if( ( ether_addr ) == NULL )
		{
			printf( "\n+ Ethernet address of adapter : 00-00-00-00-00-00\n" );
		}
		else
		{
			memset( ether_addr, 0, 6 );
			printf( "\n" );
		}
	}
	else
	{
		if( ( ether_addr ) == NULL )
		{
			printf( "\n+ Ethernet address of adapter : %02X-%02X-%02X-%02X-%02X-%02X\n",
					( OidData->Data )[0], ( OidData->Data )[1], ( OidData->Data )[2],
					( OidData->Data )[3], ( OidData->Data )[4], ( OidData->Data )[5] );
		}
		else
		{
			memcpy( ether_addr, OidData->Data, 6 );
		}
	}

	/* Free buffer */
	free( OidData );
}


void print_start( unsigned char *dst_etheraddr, unsigned char *src_etheraddr,
				  int ar_op, unsigned char *ar_sha, unsigned char *ar_sip,
				  unsigned char *ar_tha, unsigned char *ar_tip )
{
	/* Print Ethernet header informations */
	printf( "\n+ ETH - Destination MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",
			dst_etheraddr[0], dst_etheraddr[1], dst_etheraddr[2],
			dst_etheraddr[3], dst_etheraddr[4], dst_etheraddr[5] );

	printf( "+ ETH - Source MAC      : %02X-%02X-%02X-%02X-%02X-%02X\n",
			src_etheraddr[0], src_etheraddr[1], src_etheraddr[2],
			src_etheraddr[3], src_etheraddr[4], src_etheraddr[5] );

	/* Print ARP informations */
	if( ar_op == 1 )
	{
		printf( "+ ARP - ARP Request\n" );
	}
	else
	{
		printf( "+ ARP - ARP Reply\n" );
	}

	printf( "+ ARP - Sender MAC address : %02X-%02X-%02X-%02X-%02X-%02X\n",
			ar_sha[0], ar_sha[1], ar_sha[2],
			ar_sha[3], ar_sha[4], ar_sha[5] );

	printf( "+ ARP - Sender IP address  : %d.%d.%d.%d\n",
			ar_sip[0], ar_sip[1], ar_sip[2],
			ar_sip[3] );

	printf( "+ ARP - Target MAC address : %02X-%02X-%02X-%02X-%02X-%02X\n",
			ar_tha[0], ar_tha[1], ar_tha[2],
			ar_tha[3], ar_tha[4], ar_tha[5] );

	printf( "+ ARP - Target IP address  : %d.%d.%d.%d\n\n",
			ar_tip[0], ar_tip[1], ar_tip[2],
			ar_tip[3] );
}


void statistics( int count )
{
	printf( "\n+ Statistics\n" );
	printf( "  + %d packets transmitted (each: %d bytes - total: %d bytes)\n", count, sizeof( struct arp_packet ), count * sizeof( struct arp_packet ) );
}


int get_remote_mac( LPADAPTER lpAdapter, unsigned char *iptarget, unsigned char *remotemac, int mode )
{
	/* WinPcap */
	LPPACKET lpPacketRequest;
	LPPACKET lpPacketReply;
	char     buffer[256000];

	/* Packet */
	struct arp_packet arp_pkt;
	unsigned char broadcast[ETH_ADD_LEN];
	unsigned char macsender[ARP_ETH_ADD_SPACE];
	unsigned char mactarget[ARP_ETH_ADD_SPACE];
	unsigned char	ipsender[ARP_IP_ADD_SPACE];

	/* Others */
	int send_ok = 0;
	DWORD timestamp = 0;


	/* Init fields */
	memset( broadcast, 0xFF, 6 );
	memset( mactarget, 0, 6 );
	get_ether_addr( lpAdapter, macsender );
	get_ip_addr( ipsender );

	/* Allocate PACKET structure for ARP Request packet */
	if( ( lpPacketRequest = PacketAllocatePacket() ) == NULL )
	{
		fprintf( stderr, "\nError : failed to allocate the LPPACKET structure.\n" );

		return( EXIT_FAILURE );
	}

	/* Init packet structure */
	memset( &arp_pkt, 0, sizeof( struct arp_packet ) );

	/* Build ARP Request packet */
	arp_build( &arp_pkt, broadcast, macsender, ARP_OP_REQUEST, macsender, ipsender, mactarget, iptarget );

	/* Init ARP Request packet */
	PacketInitPacket( lpPacketRequest, &arp_pkt, sizeof( arp_pkt ) );

	/* Set number of ARP Request packets to send */
	if( PacketSetNumWrites( lpAdapter, 1 ) == FALSE )
	{
		fprintf( stderr, "\nWarning : unable to send more than one packet in a single write.\n" );
	}


	/* Set hardware filter to directed mode */
	if( PacketSetHwFilter( lpAdapter, NDIS_PACKET_TYPE_DIRECTED ) == FALSE )
	{
		printf( "\nWarning: unable to set directed mode.\n" );
	}

	/* Set a 512K buffer in the driver */
	if( PacketSetBuff( lpAdapter, 512000 ) == FALSE )
	{
		printf( "\nError: unable to set the kernel buffer.\n" );
		PacketFreePacket( lpPacketRequest );

		return( EXIT_FAILURE );
	}

	/* Set a 1 second read timeout */
	if( PacketSetReadTimeout( lpAdapter, -1 ) == FALSE )
	{
		printf( "\nWarning: unable to set the read tiemout.\n" );
	}

	/* Allocate PACKET structure for ARP Reply packet */
	if( ( lpPacketReply = PacketAllocatePacket() ) == NULL )
	{
		printf( "\nError: failed to allocate the LPPACKET structure.\n" );
		PacketFreePacket( lpPacketRequest );

		return( EXIT_FAILURE );
	}

	/* Init ARP Reply packet */
	PacketInitPacket( lpPacketReply, ( char * )buffer, 256000 );

	/* Allocate memory for remote MAC address */
	if( mode == 1 )
	{
		remotemac = ( unsigned char * )malloc( sizeof( unsigned char ) * 6 );
	}

	timestamp = GetTickCount();

	/* Main capture loop */
	while( 1 )
	{
		if( send_ok != 1 )
		{
			/* Send packet */
			if( PacketSendPacket( lpAdapter, lpPacketRequest, TRUE ) == FALSE )
			{
				fprintf( stderr, "\nError : unable to send the packets.\n" );
				PacketFreePacket( lpPacketRequest );
				PacketFreePacket( lpPacketReply );

				return( EXIT_FAILURE );
			}

			/* Free packet */
			PacketFreePacket( lpPacketRequest );
			send_ok = 1;
		}

		/* Capture the packets */
		if( PacketReceivePacket( lpAdapter, lpPacketReply, TRUE ) == FALSE )
		{
			printf( "\nError: PacketReceivePacket failed.\n" );
			PacketFreePacket( lpPacketReply );

			return( EXIT_FAILURE );
		}

		if( lpPacketReply->ulBytesReceived > 0 )
		{
			if( read_arp_reply( lpPacketReply, iptarget, remotemac ) == EXIT_SUCCESS )
			{

				if( mode == 1 )
				{
					printf( "\n+ Sender IP address  : %d.%d.%d.%d\n",
							iptarget[0], iptarget[1], iptarget[2], iptarget[3] );

					printf( "+ Sender MAC address : %02X-%02X-%02X-%02X-%02X-%02X\n",
							remotemac [0], remotemac [1], remotemac [2],
							remotemac [3], remotemac [4], remotemac [5] );

					printf( "\n" );
				}

				break;
			}
		}

		if( ( GetTickCount() - timestamp ) > 2000 )
		{
			printf( "\nError: unable to get MAC address from %d.%d.%d.%d\n",
					iptarget[0], iptarget[1], iptarget[2], iptarget[3] );

			return( EXIT_FAILURE );
		}
	}

	if( mode == 1 )
	{
		free( remotemac );
	}

	/* Free packet */
	PacketFreePacket( lpPacketReply );

	return( EXIT_SUCCESS );
}


int read_arp_reply( LPPACKET lpPacket, unsigned char *iptarget, unsigned char *result )
{
	/* Variables */
	unsigned short int ether_type;
	unsigned char      ipsender[4];
	unsigned int       off = 0;
	unsigned int       tlen, tlen1;
	struct bpf_hdr     *hdr;
	char	             *pChar;
	char	             *buf;


	/* Initialization */
	off = 0;

	/* Init buffer with packet data */
	buf = ( char * )lpPacket->Buffer;

	/* Read packet */
	hdr = ( struct bpf_hdr * )( buf + off );
	tlen1 = hdr->bh_datalen;
	tlen = hdr->bh_caplen;
	off += hdr->bh_hdrlen;
	pChar = ( char * )( buf + off );
	off = Packet_WORDALIGN( off + tlen );

	/* Read Ethernet type */
	memcpy( &ether_type, pChar + 12, 2 );
	ether_type = ntohs( ether_type );

	if( ether_type == ETH_TYPE_ARP )
	{
		/* Copy ip address of sender */
		memcpy( ipsender, pChar + 28, 4 );

		if( ( iptarget[0] == ipsender[0] ) && ( iptarget[1] == ipsender[1] ) &&
				( iptarget[2] == ipsender[2] ) && ( iptarget[3] == ipsender[3] ) )
		{

			/* Copy MAC address of sender */
			memcpy( result, pChar + 22, 6 );
		}
		else
		{

			return( EXIT_FAILURE );
		}
	}
	else
	{

		return( EXIT_FAILURE );
	}

	return( EXIT_SUCCESS );
}


int get_ip_addr( unsigned char *ip_addr )
{
	/* Winsock */
	WORD		    wVersionRequested;
	WSADATA		wsaData;

	/* Others */
	char           hostname[256];
	struct hostent *info;
	unsigned char  ipaddr[4];


	wVersionRequested = MAKEWORD( 1, 1 );
	if( WSAStartup( wVersionRequested, &wsaData ) != 0 )
	{
		fprintf( stderr, "\nError: unable to start WinSock\n" );

		return( EXIT_FAILURE );
	}

	if( gethostname( hostname, 256 ) == SOCKET_ERROR )
	{
		fprintf( stderr, "\nError: unable to get ip address\n" );
		WSACleanup();

		return( EXIT_FAILURE );
	}

	if( ( info = gethostbyname( hostname ) ) != NULL )
	{
		memcpy( ipaddr, ( unsigned char * )( *info->h_addr_list ), 4 );
		if( ip_addr != NULL )
		{
			memcpy( ip_addr, ipaddr, 4 );
		}
		else
		{
			printf( "\n+ IP address : %d.%d.%d.%d\n",
					ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3] );
		}
	}
	else
	{
		fprintf( stderr, "\nError: unable to get ip address\n" );
		WSACleanup();

		return( EXIT_FAILURE );
	}

	WSACleanup();

	return( EXIT_SUCCESS );
}


