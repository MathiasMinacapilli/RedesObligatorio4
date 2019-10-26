/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_arpcache.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/* Send an ARP request. */
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip) {

}

/* Send an ICMP error. */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

}

sr_arp_hdr_t* get_arp_header(uint8_t *packet) {
  sr_arp_hdr_t *arp_hdr_from_packet = (sr_arp_hdr_t *) packet;
  sr_arp_hdr_t *arp_hdr = malloc(sizeof(sr_arp_hdr_t));
  size_t desplazamiento = 0;

  /*Copio la memoria del paquete a mi header nuevo casteado*/
  
  /*ar_hrd*/
  memcpy(arp_hdr+desplazamiento, arp_hdr_from_packet+desplazamiento, sizeof(unsigned short));  
  desplazamiento += sizeof(unsigned short);
  
  /*ar_pro*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, sizeof(unsigned short));
  desplazamiento += sizeof(unsigned short);
  
  /*ar_hln*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, sizeof(unsigned char));
  desplazamiento += sizeof(unsigned char);
  
  /*ar_pln*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, sizeof(unsigned char));
  desplazamiento += sizeof(unsigned char);

  /*ar_op*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, sizeof(unsigned short));
  desplazamiento += sizeof(unsigned short);
  
  /*ar_sha*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, 
    sizeof(unsigned char) * ETHER_ADDR_LEN
  );
  desplazamiento += sizeof(unsigned char);
  
  /*ar_sip*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, sizeof(uint32_t));
  desplazamiento += sizeof(uint32_t);
  
  /*ar_tha*/
  memcpy(
    arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento,
    sizeof(unsigned char) * ETHER_ADDR_LEN
  );
  desplazamiento += sizeof(unsigned char) * ETHER_ADDR_LEN;
  
  /*ar_tip*/
  memcpy(arp_hdr + desplazamiento, arp_hdr_from_packet + desplazamiento, sizeof(uint32_t));
  desplazamiento += sizeof(uint32_t);

  return arp_hdr;
}

void enviar_paquete_esperando_por_MAC(unsigned char* MAC_destino, struct sr_packet* paquete_esperando, struct sr_instance* sr){
  struct sr_ethernet_hdr * paquete_ethernet = (struct sr_ethernet_hdr *) paquete_esperando->buf;
  memcpy(paquete_ethernet, MAC_destino, sizeof(unsigned char) * ETHER_ADDR_LEN);   
  uint8_t *buf = paquete_esperando->buf;
  unsigned int len = paquete_esperando->len;
  const char* iface = paquete_esperando->iface;
  sr_send_packet(sr, buf, len, iface);
}


/* add or update sender to ARP cache */
void add_or_update_ARP_cache(uint32_t source_ip, unsigned char* MAC_destino, struct sr_instance *sr) {
  struct sr_arpcache cache = sr->cache;
  struct sr_arpreq *arp_req = sr_arpcache_insert(&cache, MAC_destino, source_ip);
  if (arp_req != NULL){
    struct sr_packet* paquetes_esperando = arp_req->packets;
    while (paquetes_esperando != NULL){
      enviar_paquete_esperando_por_MAC(MAC_destino, paquetes_esperando, sr);
      paquetes_esperando = paquetes_esperando->next;          
    }
    sr_arpreq_destroy(&cache, arp_req);      
  }  
}

/*
 * Chequear que la mac destino del paquete ARP sea una de mis interfaces, en particular
 * por la MAC que me llego definidas en sr O la MAC de broadcast
int is_for_my_interfaces(struct sr_instances *sr, uint8_t *packet) {
  struct sr_if* my_interfaces = sr->if_list;
  
  while (my_interfaces != NULL) {
    if (
  }
}
*/

void handle_arp_request(struct sr_instance *sr, char* interface, uint8_t *packet) {
  /* arp_request */
  struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr*) packet;
  uint32_t interface_ip = 0;
  struct sr_if* interfaces = sr->if_list;
  int found_ip = 0;
  while (interfaces != NULL && found_ip == 0) {
    if (interfaces->addr == interface) {
      interface_ip = interfaces->ip;
      found_ip = 1;
    }
  }
  if (interface_ip == arp_hdr->ar_tip) {
    /* la request pregunta por mi ip */
  }
}

void handle_arp_reply() {
  /* arp_reply */
}

void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Get ARP header and addresses */
  sr_arp_hdr_t* arp_hdr = get_arp_header(packet);

  /* add or update sender to ARP cache*/
  /* actualizamos o agregamos el mapeo de IP del que recibo -> MAC del que recibo
   en la cache arp*/
  add_or_update_ARP_cache(arp_hdr->ar_sip, arp_hdr->ar_sha, sr);

  /* check if the ARP packet is for one of my interfaces. */
  /* is_for_my_interfaces(sr, packet); */
  
  /* check if it is a request or reply*/
  unsigned short op = arp_hdr->ar_op;

  /* if it is a request, construct and send an ARP reply*/
  if (op == arp_op_request) {
    handle_arp_request(sr, interface, packet);
  }   

  /* else if it is a reply, add to ARP cache if necessary and send packets waiting for that reply*/
  else if (op == arp_op_reply) {
    handle_arp_reply();
  }
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {


	/* Get IP header and addresses */

	/* Check if packet is for me or the destination is in my routing table*/

	/* If non of the above is true, send ICMP net unreachable */

	/* Else if for me, check if ICMP and act accordingly*/

	/* Else, check TTL, ARP and forward if corresponds (may need an ARP request and wait for the reply) */

}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtain dest and src MAC address */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */

