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

uint8_t* create_arp_packet(struct sr_instance *sr, unsigned char* source_MAC, unsigned char* destiny_MAC, uint32_t source_IP, uint32_t destiny_IP, unsigned short oper){
    int ethPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *ethPacket = malloc(ethPacketLen);
    sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) ethPacket;
    memcpy(ethHdr->ether_dhost, destiny_MAC, ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_shost, source_MAC, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ethHdr->ether_type = htons(ethertype_arp);
    sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (ethPacket + sizeof(sr_ethernet_hdr_t));
    arpHdr->ar_hrd = htons(1);
    arpHdr->ar_pro = htons(2048);
    arpHdr->ar_hln = 6;
    arpHdr->ar_pln = 4;
    arpHdr->ar_op = htons(oper);
    memcpy(arpHdr->ar_sha, source_MAC, ETHER_ADDR_LEN);
    memcpy(arpHdr->ar_tha, destiny_MAC, ETHER_ADDR_LEN);
    arpHdr->ar_sip = source_IP;
    arpHdr->ar_tip = destiny_IP;
    return ethPacket;
}


/* Send an ARP request. */
/*Se utiliza cuando se realiza el Forwarding (capa 3), cuando no tengo la MAC en la cache*/
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip) {

  /*Consultar cual es la if de salida [out_interdace] respecto a la routing table*/
  struct sr_rt* iter_forwarding_table = sr->routing_table;
    uint32_t maxMask = 0x00000000; /*o 0x0*, es decir, la mask menos restrictiva posible*/
    char* out_interface;
    while(iter_forwarding_table != NULL){
      uint32_t destination = iter_forwarding_table->dest.s_addr;
      uint32_t mask = iter_forwarding_table->mask.s_addr;
      if((mask > maxMask) && ((ip & mask) ^ destination) == 0){ /*el operador xor, si dos bit son iguales da 0*/
          out_interface = iter_forwarding_table->interface;
          maxMask = mask;
      } 
    iter_forwarding_table = iter_forwarding_table->next;
    }

    struct sr_if* instance_of_out_interface = sr_get_interface(sr, out_interface);
  /*Mandar la request por la if obtenida de la tabla*/

  uint8_t * broadcast = generate_ethernet_addr(0xFF);
  uint8_t* arp_request = create_arp_packet(sr, instance_of_out_interface->addr, broadcast, instance_of_out_interface->ip, ip, arp_op_request);
  sr_send_packet(sr, arp_request, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), instance_of_out_interface->name);

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

int compare_macs(uint8_t * mac1, uint8_t * mac2){
  int i = 0;
  for(i = 0; i < 6 ; i++){
    if (mac1[i] != mac2[i]){
      return 0;
    }
  }
  return 1;
}


/*
 * Chequear que la mac destino del paquete ARP sea una de mis interfaces, en particular
 * por la MAC que me llego definidas en sr O la MAC de broadcast*/
int is_for_my_interfaces(struct sr_instance * sr, uint8_t *packet, char *interface) {
  struct sr_ethernet_hdr * ethernet_packet = (struct sr_ethernet_hdr *)packet;
  uint8_t * destiny_MAC = ethernet_packet->ether_shost;
  uint8_t * broadcast = generate_ethernet_addr(0xFF);
  int equals = compare_macs(destiny_MAC, broadcast);
  if (equals == 1){
    return 1;
  }
  struct sr_if * interface_instance = sr_get_interface(sr , interface);
  unsigned char* interface_MAC = interface_instance->addr;
  uint8_t * interfaz_MAC = (uint8_t *)interface_MAC;
  if (compare_macs(destiny_MAC, interfaz_MAC)) {
	  return 1;
  }
  return 0;  
}



void handle_arp_request(struct sr_instance *sr, char* interface, uint8_t *packet) {
  /* arp_request */
  struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr*) packet;
  uint32_t requested_ip = arp_hdr->ar_tip;
  struct sr_if* requested_interface = sr_get_interface_given_ip(sr, requested_ip);
  if (requested_interface == 0){
      /*descarto el paquete*/
      return;
  } else {
      /*crea respuesta arp*/
      uint8_t * arp_packet = create_arp_packet(sr, requested_interface->addr, arp_hdr->ar_sha, requested_interface->ip, arp_hdr->ar_sip, arp_op_reply);
      sr_send_packet(sr, arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), requested_interface->name);
  }
}


void handle_arp_reply(struct sr_instance *sr, unsigned char* MAC_destino, uint32_t source_ip) {
  /* arp_reply */
  add_or_update_ARP_cache(source_ip, MAC_destino, sr);
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
  int is_for_me = is_for_my_interfaces(sr, packet, interface);
  if(is_for_me > 0){
      /* check if it is a request or reply*/
    unsigned short op = arp_hdr->ar_op;

    /* if it is a request, construct and send an ARP reply*/
    if (op == arp_op_request) {
      handle_arp_request(sr, interface, packet);
    }   

    /* else if it is a reply, add to ARP cache if necessary and send packets waiting for that reply*/
    else if (op == arp_op_reply) {
      handle_arp_reply(sr, arp_hdr->ar_sha, arp_hdr->ar_sip) ;
    }
  }
    free(arp_hdr);
}


sr_ip_hdr_t* get_ip_header(uint8_t *packet) {
  sr_ip_hdr_t *ip_hdr_from_packet = (sr_ip_hdr_t *) packet;
  sr_ip_hdr_t *ip_hdr = malloc(sizeof(sr_ip_hdr_t));
  size_t desplazamiento = 0;

  /*Copio la memoria del paquete a mi header nuevo casteado*/
  
  /*ip_tos*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint8_t));  
  desplazamiento += sizeof(uint8_t);

    /*ip_len*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint16_t));  
  desplazamiento += sizeof(uint16_t);

      /*ip_id*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint16_t));  
  desplazamiento += sizeof(uint16_t);

      /*ip_off*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint16_t));  
  desplazamiento += sizeof(uint16_t);

      /*ip_ttl*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint8_t));  
  desplazamiento += sizeof(uint8_t);

      /*ip_p*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint8_t));  
  desplazamiento += sizeof(uint8_t);

      /*ip_sum*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint16_t));  
  desplazamiento += sizeof(uint16_t);

      /*ip_src*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint32_t));  
  desplazamiento += sizeof(uint32_t);

        /*ip_dst*/
  memcpy(ip_hdr+desplazamiento, ip_hdr_from_packet+desplazamiento, sizeof(uint32_t));  
  desplazamiento += sizeof(uint32_t);

  return ip_hdr; 
}

int is_for_my_ip(struct sr_instance * sr, uint32_t ip_dst, char* interface){
  struct sr_if * interface_instance = sr_get_interface(sr , interface);
  uint32_t interface_IP = interface_instance->ip;
  if (interface_IP == ip_dst){
    return 1;
  }
  return 0;
}

char* is_in_table(struct sr_instance * sr, uint32_t ip_dst){
  struct sr_rt* iter_forwarding_table = sr->routing_table;
  uint32_t maxMask = 0x00000000; /*o 0x0*, es decir, la mask menos restrictiva posible*/
  char* out_interface = NULL;
  while(iter_forwarding_table != NULL){
   uint32_t destination = iter_forwarding_table->dest.s_addr;
      uint32_t mask = iter_forwarding_table->mask.s_addr;
      if((mask > maxMask) && ((ip_dst & mask) ^ destination) == 0){ /*el operador xor, si dos bit son iguales da 0*/
          out_interface = iter_forwarding_table->interface;
          maxMask = mask;
      }
    iter_forwarding_table = iter_forwarding_table->next;
    }
  return out_interface;
}

int is_ICMP(struct sr_ip_hdr* ip_hdr){
  if (ip_hdr->ip_p == 0x01){
    return 1;
  }
  return 0;
}

int is_TTL_expired(struct sr_ip_hdr* ip_hdr){
  uint8_t TTL = ip_hdr->ip_ttl;
  uint8_t expired = 0x01;
  if(TTL == expired){
    return 1;
  }
  return 0;
}

void decrement_TTL_and_rechecksum(struct sr_ip_hdr* ip_hdr){
  uint8_t resta = 0x01;
  uint8_t nuevo_TTL = ip_hdr->ip_ttl - resta;
  ip_hdr->ip_ttl = nuevo_TTL;
  ip_hdr->ip_sum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

uint8_t* create_ip_packet(struct sr_instance *sr, unsigned char* source_MAC,
 unsigned char* destiny_MAC, struct sr_ip_hdr * ip_header, unsigned int len){
    int ethPacketLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    uint8_t *ethPacket = malloc(ethPacketLen);
    sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) ethPacket;
    memcpy(ethHdr->ether_dhost, destiny_MAC, ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_shost, source_MAC, sizeof(uint8_t) * ETHER_ADDR_LEN);
    ethHdr->ether_type = htons(ethertype_ip);
    sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *) (ethPacket + sizeof(sr_ethernet_hdr_t));
    memcpy(ipHdr, ip_header, len);
    return ethPacket;
}

void handle_arp_and_ip(struct sr_instance * sr, struct sr_ip_hdr* ip_hdr, char* interface, unsigned int len){
  struct sr_arpcache* arp_cache = &sr->cache;
  struct sr_arpentry* entry_arp = sr_arpcache_lookup(arp_cache, ip_hdr->ip_dst);
  struct sr_if* interface_instance = sr_get_interface(sr, interface);
  unsigned char * source_MAC = interface_instance->addr;
  if(entry_arp == NULL){
    /*METER PA LISTA DE ESPERADOS*/
    /*el destiny mac lo pongo null, porque no la se todavia, cuando alguien lo averigua
    edita el paquete y lo manda */
    /*el len que llega es de toda la trama ethernet, le saco el header ethernet*/
    uint8_t * ethPacket = create_ip_packet(sr, source_MAC, NULL, ip_hdr, len - sizeof(sr_ethernet_hdr_t));
    sr_arpcache_queuereq(arp_cache, ip_hdr->ip_dst, ethPacket,len, interface);
    free(ethPacket); /*Lo dice el comentario de sr_arpcache_queuereq*/
  } else {
    /*Si tengo la direccion mac, creo la trama ethernet y la mando*/
    uint8_t * ethPacket = create_ip_packet(sr, source_MAC, entry_arp->mac, ip_hdr, len - sizeof(sr_ethernet_hdr_t));
    sr_send_packet(sr, ethPacket, len, interface);
    free(ethPacket);
  }
  free(entry_arp);
}

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {


	/* Get IP header and addresses */
  struct sr_ip_hdr* ip_hdr = get_ip_header(packet);

	/* Check if packet is for me or the destination is in my routing table*/

  int is_for_me = is_for_my_ip(sr, ip_hdr->ip_dst, interface);
  /*NO HABRIA QUE PREGUNTAR POR LA MAC TAMBIEN? pa que me pasan el header_ethernet sino?*/

  char* is_in_my_routing_table = is_in_table(sr, ip_hdr->ip_dst);

  if (is_for_me > 0) {
    /* Else if for me, check if ICMP and act accordingly*/
    if(is_ICMP(ip_hdr) > 0){
      /*manejar icmp*/
    } else {
      /*devolver icmp port unreachable*/
    }
   
  } else if (is_for_me == 0 && is_in_my_routing_table != NULL) {
    /* Else, check TTL, ARP and forward if corresponds (may need an ARP request and wait for the reply) */
    /*check ttl*/
    if(is_TTL_expired(ip_hdr) > 0){
      /*mandar IMCP tipo 11, return;*/
    } else {
      /*Decrementar TTL, calcular checksum, ver si MAC esta en ARP cache, 
      sino preguntar y esperar. Cuando tengo MAC, hacer trama ethernet y reenviar*/
      decrement_TTL_and_rechecksum(ip_hdr);
      handle_arp_and_ip(sr, ip_hdr, is_in_my_routing_table, len);
    }
  } else {
	  /* If non of the above is true, send ICMP net unreachable */
  }


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

