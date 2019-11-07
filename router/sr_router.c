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

#define DEBUG 1

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



/**********************************************************************
 ************************CREAR PAQUETE ARP*****************************
 **********************************************************************
 **********************************************************************/



uint8_t* create_arp_packet(struct sr_instance *sr, unsigned char* source_MAC, unsigned char* destiny_MAC, uint32_t source_IP, uint32_t destiny_IP, unsigned short oper){

    if (DEBUG == 1) {
      printf("DEBUG: Creando arp packet...\n");
    }

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

    if (DEBUG == 1) {
      printf("DEBUG: Terminado de crear arp packet...\n");
    }

    return ethPacket;
}


/**********************************************************************
 ***********************ENVIAR ARP REQUEST*****************************
 **********************************************************************
 **********************************************************************/

/* Send an ARP request. */
/*Se utiliza cuando se realiza el Forwarding (capa 3), cuando no tengo la MAC en la cache*/
void sr_arp_request_send(struct sr_instance *sr, uint32_t ip2) {

  if (DEBUG == 1) {
    printf("DEBUG: Iniciando el envio de arp request...\n");
  }

  /*Consultar cual es la if de salida [out_interdace] respecto a la routing table*/
  struct sr_rt* iter_forwarding_table = sr->routing_table;
  uint32_t ip = ntohl(ip2);
    uint32_t maxMask = 0x00000000; /*o 0x0*, es decir, la mask menos restrictiva posible*/
    char* out_interface;
    while(iter_forwarding_table != NULL){
      uint32_t destination = iter_forwarding_table->dest.s_addr;
      uint32_t mask = iter_forwarding_table->mask.s_addr;

      if((mask > maxMask) && ((ip & mask) ^ ntohl(destination)) == 0){ /*el operador xor, si dos bit son iguales da 0*/
          out_interface = iter_forwarding_table->interface;
          maxMask = mask;
      } 
    iter_forwarding_table = iter_forwarding_table->next;
    }

    struct sr_if* instance_of_out_interface = sr_get_interface(sr, out_interface);
  /*Mandar la request por la if obtenida de la tabla*/

  uint8_t * broadcast = generate_ethernet_addr(0xFF);
  uint8_t* arp_request = create_arp_packet(sr, instance_of_out_interface->addr, broadcast, instance_of_out_interface->ip, htonl(ip), arp_op_request);

  if (DEBUG == 1) {
    printf("DEBUG: Enviando paquete...\n");
  }
  sr_send_packet(sr, arp_request, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), instance_of_out_interface->name);

}



/**********************************************************************
 ************************ENVIAR ICMP ERROR*****************************
 **********************************************************************
 **********************************************************************/


/* Send an ICMP error. */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{

}


/**********************************************************************
 ************************OBTENER ARP HEADER****************************
 **********************************************************************
 **********************************************************************/

sr_arp_hdr_t* get_arp_header(uint8_t *packet) {
  sr_arp_hdr_t *arp_hdr = malloc(sizeof(sr_arp_hdr_t));
  
  memcpy(arp_hdr, packet, sizeof(sr_arp_hdr_t));

  return arp_hdr;
}



/**********************************************************************
 ******************ENVIAR PAQUETE ESPERANDO POR MAC********************
 **********************************************************************
 **********************************************************************/

void enviar_paquete_esperando_por_MAC(unsigned char* MAC_destino, struct sr_packet* paquete_esperando, struct sr_instance* sr){

  if (DEBUG == 1) {
    printf("DEBUG: Comienzo de envio de paquete esperando por mac...\n");
  }  
  printf("%s",paquete_esperando->iface);
  struct sr_ethernet_hdr * paquete_ethernet = (struct sr_ethernet_hdr *) paquete_esperando->buf;
  memcpy(paquete_ethernet->ether_dhost, MAC_destino, ETHER_ADDR_LEN); 
  uint8_t *buf = paquete_esperando->buf;
  unsigned int len = paquete_esperando->len;
  const char* iface = paquete_esperando->iface;
  sr_send_packet(sr, buf, len, iface);
}



/**********************************************************************
 ************************INSERTAR EN CACHE ARP*************************
 **********************************************************************
 **********************************************************************/

/* add or update sender to ARP cache */
void add_or_update_ARP_cache(uint32_t source_ip, unsigned char* MAC_destino, struct sr_instance *sr) {

  if (DEBUG == 1) {
    printf("DEBUG: Agregando o actualizando la ARP cache...\n");
  }

  struct sr_arpentry * arp_entry = sr_arpcache_lookup(&sr->cache, source_ip);
  if(arp_entry == NULL){
    struct sr_arpcache cache = sr->cache;
    struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache, MAC_destino, source_ip);
    if (arp_req != NULL){
      if (DEBUG == 1) {
        printf("DEBUG: EL ARP REQ != NULL...\n");
      }
      struct sr_packet* paquetes_esperando = arp_req->packets;
      while (paquetes_esperando != NULL){
        enviar_paquete_esperando_por_MAC(MAC_destino, paquetes_esperando, sr);
        paquetes_esperando = paquetes_esperando->next;          
      }
      sr_arpreq_destroy(&cache, arp_req);      
      }  
  } else {
    if (DEBUG == 1) {
      printf("DEBUG: La asociacion IP-MAC ya se encuentra en la tabla...\n");
    }

    free(arp_entry);
  }
}


/**********************************************************************
 **************************COMPARAR MACS*******************************
 **********************************************************************
 **********************************************************************/

int compare_macs(uint8_t * mac1, uint8_t * mac2){
  int i = 0;
  for(i = 0; i < 6 ; i++){
    if (mac1[i] != mac2[i]){
      return 0;
    }
  }
  return 1;
}


/**********************************************************************
 **************CHEQUEAR SI MAC DESTINO ES PARA MI INTERFAZ*************
 **********************************************************************
 **********************************************************************/
/*
 * Chequear que la mac destino del paquete ARP sea una de mis interfaces, en particular
 * por la MAC que me llego definidas en sr O la MAC de broadcast*/
int is_for_my_interfaces(struct sr_instance * sr, uint8_t *packet, char *interface) {

  if (DEBUG == 1) {
    printf("DEBUG: Chequeando que el paquete recibido sea para una de mis interfaces...\n");
  }

  struct sr_ethernet_hdr * ethernet_packet = (struct sr_ethernet_hdr *)packet;
  uint8_t * destiny_MAC = ethernet_packet->ether_dhost;
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


/**********************************************************************
 *********************MANEJAR ARP REQUEST******************************
 **********************************************************************
 **********************************************************************/

void handle_arp_request(struct sr_instance *sr, char* interface, uint8_t *packet) {
  /* arp_request */

  if (DEBUG == 1) {
    printf("DEBUG: Manejando la request arp...\n");
  }

  struct sr_arp_hdr *arp_hdr = (struct sr_arp_hdr*) (packet);
  uint32_t requested_ip = arp_hdr->ar_tip;
  
  struct sr_if* requested_interface = sr_get_interface_given_ip(sr, requested_ip);
  if (requested_interface == 0) {
      /*descarto el paquete*/
      if (DEBUG == 1) {
        printf("DEBUG: La request recibida NO es para mi, descartando paquete...\n");
      }
      return;
  } else {
      /*crea respuesta arp*/
      if (DEBUG == 1) {
        printf("DEBUG: La request recibida es para mi. Creando y enviando respuesta a la request...\n");
      }
      uint8_t * arp_packet = create_arp_packet(sr, requested_interface->addr, arp_hdr->ar_sha, requested_interface->ip, arp_hdr->ar_sip, arp_op_reply);
      sr_send_packet(sr, arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), requested_interface->name);
  }
}


void handle_arp_reply(struct sr_instance *sr, unsigned char* MAC_destino, uint32_t source_ip) {
  /* arp_reply */
  if (DEBUG == 1) {
    printf("DEBUG: Manejando respuesta de consulta arp...\n");
  }
  add_or_update_ARP_cache(source_ip, MAC_destino, sr);
}


/**********************************************************************
 ***********************MANEJAR PAQUETE ARP****************************
 **********************************************************************
 **********************************************************************/

void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {
  /* packet es un paquete ethernet */

  /* Get ARP header and addresses */
  if (DEBUG == 1) {
    printf("DEBUG: Obteniendo el header arp...\n");
  }
  uint8_t *arp_hdr_pointer = packet + sizeof(sr_ethernet_hdr_t);
  print_hdr_arp(arp_hdr_pointer);
  sr_arp_hdr_t* arp_hdr = get_arp_header(arp_hdr_pointer);

  print_hdr_arp((uint8_t *) (arp_hdr));

  /* add or update sender to ARP cache*/
  /* actualizamos o agregamos el mapeo de IP del que recibo -> MAC del que recibo
   en la cache arp*/
  add_or_update_ARP_cache(arp_hdr->ar_sip, arp_hdr->ar_sha, sr);
  
  /* check if the ARP packet is for one of my interfaces. */
  int is_for_me = is_for_my_interfaces(sr, packet, interface);
  if (is_for_me > 0) {
    if (DEBUG == 1) {
      printf("DEBUG: El paquete arp es para mi, procesando el paquete...\n");
    }
      /* check if it is a request or reply*/
    unsigned short op = ntohs(arp_hdr->ar_op);

    /* if it is a request, construct and send an ARP reply*/
    if (op == arp_op_request) {
      if (DEBUG == 1) {
        printf("DEBUG: Es un ARP request...\n");
      }
      handle_arp_request(sr, interface, arp_hdr_pointer);
    }   

    /* else if it is a reply, add to ARP cache if necessary and send packets waiting for that reply*/
    else if (op == arp_op_reply) {
      if (DEBUG == 1) {
        printf("DEBUG: Es un ARP reply...\n");
      }
      handle_arp_reply(sr, arp_hdr->ar_sha, arp_hdr->ar_sip);
    }
  }
  if (DEBUG == 1) {
    printf("DEBUG: Liberando ARP header...\n");
  }
  free(arp_hdr);
}



/**********************************************************************
 **********************OBTENER HEADER IP*******************************
 **********************************************************************
 **********************************************************************/

sr_ip_hdr_t* get_ip_header(uint8_t *packet) {
  sr_ip_hdr_t *ip_hdr_from_packet = (sr_ip_hdr_t *) (packet);
  sr_ip_hdr_t *ip_hdr = malloc(ntohs(ip_hdr_from_packet->ip_len));
  
  memcpy(ip_hdr, ip_hdr_from_packet, ntohs(ip_hdr_from_packet->ip_len));
  return ip_hdr; 
}


/**********************************************************************
 ************************IS FOR MY IP**********************************
 **********************************************************************
 **********************************************************************/
int is_for_my_ip(struct sr_instance * sr, uint32_t ip_dst){
  if (DEBUG == 1) {
    printf("DEBUG: Chequeando que el paquete IP sea para mi...\n");
  }
  struct sr_if * my_interfaces = sr->if_list;
  while(my_interfaces != NULL){
    if (my_interfaces->ip == ip_dst){
      if (DEBUG == 1) {
        printf("DEBUG: El paquete IP es para mi...\n");
      }
      return 1;
    }
    my_interfaces = my_interfaces->next;
  }
  if (DEBUG == 1) {
    printf("DEBUG: El paquete IP NO es para mi...\n");
  }
  return 0;
}



/**********************************************************************
 **********************IS IN MY FORWARDING TABLE***********************
 **********************************************************************
 **********************************************************************/
char* is_in_table(struct sr_instance * sr, uint32_t ip_dst){

  if (DEBUG == 1) {
    printf("DEBUG: Chequeando que el destino este en mi forwarding table...\n");
  }

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



/**********************************************************************
 ******************************IS ICMP*********************************
 **********************************************************************
 **********************************************************************/

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




/**********************************************************************
 *****************DECREMENTAR TTL Y RE-CHECKSUM************************
 **********************************************************************
 **********************************************************************/
void decrement_TTL_and_rechecksum(struct sr_ip_hdr* ip_hdr){
  if (DEBUG == 1) {
    printf("DEBUG: Paquete antes del re-checksum...\n");
    print_hdr_ip((uint8_t*)ip_hdr);
  }
  uint8_t resta = 0x01;
  uint8_t nuevo_TTL = ip_hdr->ip_ttl - resta;
  /*memcpy(&ip_hdr->ip_ttl, &nuevo_TTL, sizeof(uint8_t));*/
  ip_hdr->ip_ttl = nuevo_TTL;
  ip_hdr->ip_sum = ip_cksum(ip_hdr,/*ntohs(ip_hdr->ip_len)*/sizeof(sr_ip_hdr_t));
  /*memcpy(&ip_hdr->ip_sum, &ip_sum, sizeof(uint16_t));*/
  if (DEBUG == 1) {
    printf("DEBUG: Paquete despues del re-checksum...\n");
    print_hdr_ip((uint8_t*)ip_hdr);
  }

}


/**********************************************************************
 ************************CREAR PAQUETE IP******************************
 **********************************************************************
 **********************************************************************/
uint8_t* create_ip_packet(struct sr_instance *sr, unsigned char* source_MAC,
 unsigned char* destiny_MAC, struct sr_ip_hdr * ip_header){

    if (DEBUG == 1) {
      printf("DEBUG: Creando paquete IP...\n");
    }
    int ethPacketLen = sizeof(sr_ethernet_hdr_t) + ntohs(ip_header->ip_len);
    uint8_t *ethPacket = malloc(ethPacketLen);
    sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) ethPacket;
    print_addr_eth(source_MAC);
    if(destiny_MAC != NULL){    
      if (DEBUG == 1) {
        printf("DEBUG: La Destiny MAC es: ...\n");
        print_addr_eth(destiny_MAC);  
      }
      memcpy(ethHdr->ether_dhost, destiny_MAC, ETHER_ADDR_LEN);
    }else{
      if (DEBUG == 1) {
        printf("DEBUG: DESTINY_MAC = NULL\n");
      }
    }
    memcpy(ethHdr->ether_shost, source_MAC, ETHER_ADDR_LEN);
    ethHdr->ether_type = htons(ethertype_ip);
    sr_ip_hdr_t *ipHdr = (sr_ip_hdr_t *) (ethPacket + sizeof(sr_ethernet_hdr_t));
    memcpy(ipHdr, ip_header, ntohs(ip_header->ip_len));
    
    if (DEBUG == 1) {
      printf("DEBUG: Paquete IP creado, con todos sus headers!!!!!!!!!!!!!!!!!:\n");
      print_hdrs((uint8_t *) ethPacket, ethPacketLen);
    }

    return ethPacket;
}



/**********************************************************************
 ************************MANEJAR ARP E IP******************************
 **********************************************************************
 **********************************************************************/
void handle_arp_and_ip(struct sr_instance * sr, struct sr_ip_hdr* ip_hdr, char* interface, unsigned int len){

  if (DEBUG == 1) {
    printf("DEBUG: Manejando ARP e IP...\n");
  }

  struct sr_arpcache* arp_cache = &sr->cache;
  struct sr_arpentry* entry_arp = sr_arpcache_lookup(arp_cache, ip_hdr->ip_dst);
  struct sr_if* interface_instance = sr_get_interface(sr, interface);
  unsigned char * source_MAC = interface_instance->addr;
  if(entry_arp == NULL){
    /*METER PA LISTA DE ESPERADOS*/
    /*el destiny mac lo pongo null, porque no la se todavia, cuando alguien lo averigua
    edita el paquete y lo manda */
    /*el len que llega es de toda la trama ethernet, le saco el header ethernet*/
    printf("LA ENTRY ARP ERA NULL \n");
    uint8_t * broadcast = generate_ethernet_addr(0xFF);
    /*En vez de pasar NULL se puede pasar con broadcast por ejemplo, o una direccion cualqueira, 
    sino en el create_ip_packet le pongo un if destiny_MAC != NULL*/
    uint8_t * ethPacket = create_ip_packet(sr, source_MAC, broadcast, ip_hdr);
    sr_arpcache_queuereq(arp_cache, ip_hdr->ip_dst, ethPacket,len, interface);
    free(ethPacket); /*Lo dice el comentario de sr_arpcache_queuereq*/
  } else {
    /*Si tengo la direccion mac, creo la trama ethernet y la mando*/
    if (DEBUG == 1) {
      printf("DEBUG: Tengo la MAC, voy a mandar el paquete\n");
    }
    uint8_t * ethPacket = create_ip_packet(sr, source_MAC, entry_arp->mac, ip_hdr);
    sr_send_packet(sr, ethPacket, len, interface);
    free(ethPacket);
    free(entry_arp);
  }
  
}



/**********************************************************************
 ************************CREAR PAQUETE ICMP*****************************
 **********************************************************************
 **********************************************************************/

void create_icmp_packet(struct sr_instance * sr, char* out_interface,
  uint8_t icmp_type, uint8_t icmp_code, struct sr_ip_hdr* ip_hdr, unsigned char * destiny_MAC){

  if (DEBUG == 1) {
    printf("DEBUG: Creando paquete ICMP...\n");
  }

  uint8_t type_3 = 0x03;
  struct sr_if * out_interface_instance = sr_get_interface(sr, out_interface);
  uint32_t source_IP = out_interface_instance->ip; 
  unsigned char * source_MAC = out_interface_instance->addr;
  if(icmp_type == 0x00){
    int ipPacketLen = ntohs(ip_hdr->ip_len);
    uint8_t * ipPacket = malloc(ipPacketLen);
    sr_ip_hdr_t *ipHdr = (struct sr_ip_hdr *) (ipPacket);
    memcpy(ipPacket, ip_hdr, ipPacketLen);

    sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (ipPacket + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_type = 0x00;
    icmp_hdr->icmp_sum = icmp_cksum(icmp_hdr, ipPacketLen - sizeof(sr_ip_hdr_t));



    ipHdr->ip_src = ip_hdr->ip_dst;
    ipHdr->ip_dst = ip_hdr->ip_src;
    ipHdr->ip_ttl = 64;
    ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));
    
    uint8_t* ethPacket = create_ip_packet(sr, source_MAC, destiny_MAC, ipHdr);
    sr_send_packet(sr, ethPacket, ipPacketLen + sizeof(sr_ethernet_hdr_t), out_interface);
    printf("EL PAQUETE QUE MADNE FUE\n");
    print_hdrs(ethPacket, ipPacketLen + sizeof(sr_ethernet_hdr_t));
    free(ethPacket);
    free(ipPacket);





    return;
  }
  if(type_3 == icmp_type){

    if (DEBUG == 1) {
      printf("DEBUG: ICMP de tipo 3...\n");
    }

    /*hacer tipo 3*/
    /*hacer el ip_hdr y pasarselo a la funcion de hacer el paquete ip, icmp va adentro 
    de ip como payload*/
    int ipPacketLen = sizeof(sr_icmp_t3_hdr_t) + sizeof(ip_hdr->ip_len); /*Deberia ser el ip_hl en realidad!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
    uint8_t * ipPacket = malloc(ipPacketLen);
    sr_ip_hdr_t *ipHdr = (struct sr_ip_hdr *) ipPacket;

    sr_icmp_t3_hdr_t * icmp3Hdr = (struct sr_icmp_t3_hdr *) ipHdr + sizeof(sr_ip_hdr_t);
    icmp3Hdr->icmp_type = 0x03;
    icmp3Hdr->icmp_code = icmp_code;
    icmp3Hdr->unused = 0x00;

    /*que mierda es esto*/
    icmp3Hdr->next_mtu = 0x00;
    
    /*icmp3Hdr->data = memcpy(icmp3Hdr->data, ip_hdr, ICMP_DATA_SIZE);*/
    memcpy(icmp3Hdr->data, ip_hdr, ICMP_DATA_SIZE);

    /*Esto esta en el RFC de ICMP que pa calcular el checksum tiene que ser 0*/
    icmp3Hdr->icmp_sum = 0x00;
    icmp3Hdr->icmp_sum = icmp3_cksum(icmp3Hdr, sizeof(sr_icmp_t3_hdr_t));


    ipHdr->ip_tos = 0x00;
    ipHdr->ip_len = ipPacketLen;
    ipHdr->ip_id = 0x00;
    ipHdr->ip_off = htons(IP_DF);
    ipHdr->ip_ttl = 0x30;
    ipHdr->ip_p = 0x01;   
    ipHdr->ip_src = source_IP; /*la ip de la interfaz por la que lo saco*/
    ipHdr->ip_dst = ip_hdr->ip_src; /*la ip del que se lo mando*/
    ipHdr->ip_v = (unsigned int)4;
    ipHdr->ip_hl = 5;     

    ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));

    uint8_t* ethPacket = create_ip_packet(sr, source_MAC, destiny_MAC, ipHdr);
    sr_send_packet(sr, ethPacket, ipPacketLen + sizeof(sr_ethernet_hdr_t), out_interface);
    free(ethPacket);
    free(ipPacket);



  } else {

    if (DEBUG == 1) {
      printf("DEBUG: ICMP tipo NO 3...\n");
    }

    /*hacer el que corresponda*/
    int ipPacketLen = sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t); /*Deberia ser el ip_hl en realidad*/
    uint8_t * ipPacket = malloc(ipPacketLen);
    sr_ip_hdr_t *ipHdr = (struct sr_ip_hdr *) ipPacket;

    /*Aca irian los htons y eso ni idea*/

    sr_icmp_hdr_t * icmpHdr = (struct sr_icmp_hdr *) ipHdr + sizeof(sr_ip_hdr_t);
    icmpHdr->icmp_type = icmp_type;
    icmpHdr->icmp_code = icmp_code;

    /*Esto esta en el RFC de ICMP que pa calcular el checksum tiene que ser 0*/
    icmpHdr->icmp_sum = 0x00;
    icmpHdr->icmp_sum = icmp_cksum(icmpHdr, sizeof(sr_icmp_hdr_t));

    ipHdr->ip_tos = 0x00;
    ipHdr->ip_len = ipPacketLen;
    ipHdr->ip_id = 0x00;
    ipHdr->ip_off = htons(IP_DF);
    ipHdr->ip_ttl = 0x30;
    ipHdr->ip_p = 0x01;   
    ipHdr->ip_src = source_IP; /*la ip de la interfaz por la que lo saco*/
    ipHdr->ip_dst = ip_hdr->ip_src; /*la ip del que se lo mando*/
    ipHdr->ip_sum = ip_cksum(ipHdr, sizeof(sr_ip_hdr_t));
    ipHdr->ip_v = (unsigned int)4;
    ipHdr->ip_hl = 5; 

    uint8_t* ethPacket = create_ip_packet(sr, source_MAC, destiny_MAC, ipHdr);
    if (DEBUG == 1) {
      printf("DEBUG: Mandando paquete...\n");
    }
    sr_send_packet(sr, ethPacket, ipPacketLen + sizeof(sr_ethernet_hdr_t), out_interface);
    free(ethPacket);
    free(ipPacket);
  }
}


/**********************************************************************
 ************************MANEJAR PAQUETE IP****************************
 **********************************************************************
 **********************************************************************/
void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  if (DEBUG == 1) {
    printf("DEBUG: Procesando el paquete IP...\n");
  }

	/* Get IP header and addresses */
  uint8_t * ip_hdr_pointer = packet + sizeof(sr_ethernet_hdr_t);
  struct sr_ip_hdr* ip_hdr = get_ip_header(ip_hdr_pointer);
  uint32_t ip_checksum = ip_cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	/* Check if packet is for me or the destination is in my routing table*/
  if (ip_checksum == ip_hdr->ip_sum) {

    if (DEBUG == 1) {
      printf("DEBUG: Paquete IP sano, continua procesamiento...\n");
    }
    int is_for_me = is_for_my_ip(sr, ip_hdr->ip_dst);
    /*NO HABRIA QUE PREGUNTAR POR LA MAC TAMBIEN? pa que me pasan el header_ethernet sino?*/

    char* is_in_my_routing_table = is_in_table(sr, ip_hdr->ip_dst);

    if (is_for_me > 0) {
      if (DEBUG == 1) {
        printf("DEBUG: El paquete es para mi...\n");
      }
          printf("SE VIENE EL SIZE OOOOOOOOOOOOOOOOOOF..\n");
          printf("%d\n", sizeof(sr_ip_hdr_t));
          printf("SE FUEEEEEEEEEEEEEEEEEEEEEEE...\n");


      /* Else if for me, check if ICMP and act accordingly*/
      if(is_ICMP(ip_hdr) > 0){

        if (DEBUG == 1) {
          printf("DEBUG: El paquete es ICMP...\n");
        }

        /*manejar icmp, si es un echo request hay que mandar un echo reply*/

        sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) 
            + sizeof(sr_ip_hdr_t));/*o sea (packet + 34)*/
        /*if(icmp_cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)) == icmp_hdr->icmp_sum){*/
          fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
          print_hdr_icmp(icmp_hdr);


          if(icmp_hdr->icmp_type == 0x08){
            printf("DEBUG:EN EL IF 2222222222222222222...\n");
            create_icmp_packet(sr, interface, 0x00, 0x00, ip_hdr, eHdr->ether_shost);
          /*}*/
          }  else {
            printf("DEBUG:EN EL discoooooooooooooooooooordsssssss...\n");
          /*discard*/
        }
      } else {

        if (DEBUG == 1) {
          printf("DEBUG: El paquete IP tiene payload NO ICMP, se retorna ICMP port unreachable...\n");
        }

        /*devolver icmp port unreachable*/
        create_icmp_packet(sr, interface, 0x03, 0x03, ip_hdr, eHdr->ether_shost);

      }
    
    } else if (is_for_me == 0 && is_in_my_routing_table != NULL) {
      if (DEBUG == 1) {
        printf("DEBUG: El paquete no es para mi pero esta en mi tabla de forwarding...\n");
      }
      /* Else, check TTL, ARP and forward if corresponds (may need an ARP request and wait for the reply) */
      /*check ttl*/
      if(is_TTL_expired(ip_hdr) > 0){
        if (DEBUG == 1) {
          printf("DEBUG: TTL expirado, enviando mensaje de error...\n");
        }
        /*mandar IMCP tipo 11, return;*/
        create_icmp_packet(sr, interface, 0x0B, 0x00, ip_hdr, eHdr->ether_shost);

      } else {
        if (DEBUG == 1) {
          printf("DEBUG: TTL NO expirado...");
        }
        /*Decrementar TTL, calcular checksum, ver si MAC esta en ARP cache, 
        sino preguntar y esperar. Cuando tengo MAC, hacer trama ethernet y reenviar*/
        if (DEBUG == 1) {
          printf("DEBUG: Decrementando TTL y re calculando checksum...\n");
        }
        decrement_TTL_and_rechecksum(ip_hdr);
        handle_arp_and_ip(sr, ip_hdr, is_in_my_routing_table, len);
      }
    } else {
      /* If non of the above is true, send ICMP net unreachable */
      if (DEBUG == 1) {
        printf("DEBUG: Creando ICMP net unreachable...\n");
      }
      create_icmp_packet(sr, interface, 0x03, 0x00, ip_hdr, eHdr->ether_shost);
    }

  } else {  /*Si el checksum de IP no me da igual que lo que viene en el paquete*/
    if (DEBUG == 1) {
      printf("DEBUG: Descartando paquete...\n");
    }
    /*deberia descartar el paquete*/
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
  if (DEBUG == 1) {
    printf("DEBUG: EL PAQUETE QUE ME LLEGA ES: \n:");
  }
    print_hdrs(packet,len);
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */

