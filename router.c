#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>

// Tabela de rutare
struct route_table_entry *rtable;
int rtable_size;
struct trie_node *trie_root;

// Tabela ARP cache
struct arp_table_entry *arptable;
int arptable_size;

#define ETHERTYPE_IP 0x0800	 // IP protocol
#define ETHERTYPE_ARP 0x0806 // Address resolution protocol */
#define MAX_ARP_ENTRIES 100	 // un numar arbitrar destul de mare

uint32_t router_ips[7]; // adresele IP ale routerelor

/* ZONA PENTRU TRIE TREE */
struct trie_node
{
	struct trie_node *children[2];	 // 0 sau 1
	struct route_table_entry *route; // ruta din tabel asociata cu nodul
};
struct trie_node *trie_node_create()
{
	struct trie_node *node = malloc(sizeof(struct trie_node));
	if (!node)
	{
		return NULL; // verificare eroare alocare
	}
	node->children[0] = node->children[1] = NULL;
	node->route = NULL;
	return node;
}
void trie_insert(struct trie_node *root, uint32_t prefix, uint32_t mask, struct route_table_entry *route)
{
	struct trie_node *current = root;
	for (int i = 31; i >= 0; i--)
	{
		if (!(mask & (1 << i)))
		{
			// daca bitul i din masca este 0, atunci nu mai am ce sa fac
			break;
		}
		int bit = (prefix >> i) & 1;
		if (current->children[bit] == NULL)
		{
			current->children[bit] = trie_node_create();
		}
		current = current->children[bit];
	}
	current->route = route; // asociez ruta cu nodul curent
}
struct route_table_entry *trie_search(struct trie_node *root, uint32_t ip)
{
	struct trie_node *current = root;
	struct route_table_entry *best_route = NULL;
	for (int i = 31; i >= 0; i--)
	{
		int bit = (ip >> i) & 1;
		if (current->children[bit] == NULL)
		{
			break; // nu mai am unde sa merg
		}
		current = current->children[bit];
		if (current->route)
		{
			best_route = current->route; // am gasit o ruta noua mai buna
		}
	}
	return best_route; // returnez cea mai buna ruta gasita
}
void trie_free(struct trie_node *root)
{
	if (!root)
	{
		return;
	}
	for (int i = 0; i < 2; i++)
	{
		trie_free(root->children[i]);
	}
	free(root);
}

struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	/* Varianta iterativa pentru LPM */
	struct route_table_entry *best = NULL;
	for (int i = 0; i < rtable_size; i++)
	{
		if ((ip_dest & rtable[i].mask) == rtable[i].prefix)
		{

			if (best == NULL)
				best = &rtable[i];
			else if (ntohl(best->mask) < ntohl(rtable[i].mask))
			{
				best = &rtable[i];
			}
		}
	}

	return best;
}
/* ZONA PENTRU ICMP */
void send_icmp_error(uint32_t ip_dest, char *packet, int interface, uint8_t type, uint8_t code)
{
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Vreau sa copiez primii 64 de biti (8 octeti) din payload-ul original in zona de date a pachetului ICMP
	// parantezele sunt pentru a proteja suma in sine, pentru a nu aduna ceva cu sizeof si dupa 8, in loc de ceva cu (sizeof + 8)
	ssize_t primii_64_biti = (sizeof(struct iphdr) + 8);
	memcpy((uint8_t *)icmp_hdr + sizeof(struct icmphdr), ip_hdr, primii_64_biti);

	// Am 2 tipuri de mesaje ICMP: Destination Unreachable (3, 0) si Time Exceeded (11, 0)
	icmp_hdr->type = type;
	icmp_hdr->code = code;

	// Resetare checksum pentru recalculare
	icmp_hdr->checksum = 0;

	// Recalcularea checksum-ului
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + primii_64_biti);

	// Ajustarea header-ului IP
	// lungimea acum include atat antetul ICMP cat si primii 64 de biti din payload-ul original
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + primii_64_biti);
	// Pentru ca vreau sa trimit inapoi la sender, interschimb adresele IP
	ip_hdr->daddr = ip_hdr->saddr;
	// Pachetul va veni de la router
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = 64;
	// Nu as completa protocolul ca nu ma intereseaza, dar altfel din motive greu de inteles nu merge
	ip_hdr->protocol = IPPROTO_ICMP;
	// Resetare checksum pentru recalculare
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	// Trimit pachetul cu informatii despre eroare
	send_to_link(interface, packet, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
}
void send_icmp_echo_reply(uint32_t ip_src, char *packet, int interface)
{
	struct ether_header *eth_hdr = (struct ether_header *)packet;
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Seteaza tipul ICMP ca Echo Reply (0, 0)
	icmp_hdr->type = 0;
	icmp_hdr->code = 0;

	icmp_hdr->checksum = 0; // Resetare checksum pentru recalculare

	// Recalcularea checksum-ului
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));

	// Pentru ca vreau sa trimit inapoi la sender, interschimb adresele IP
	uint32_t aux_ip = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux_ip;

	// Salvez MAC-ul sender-ului pentru a-l folosi ca destinatie
	uint8_t interface_mac_sender[6];
	memcpy(interface_mac_sender, eth_hdr->ether_shost, 6);
	// Adresa MAC sursa devine adresa MAC a routerului
	get_interface_mac(interface, eth_hdr->ether_shost);

	// Adresa MAC destinatie devine adresa MAC a sender-ului
	memcpy(eth_hdr->ether_dhost, interface_mac_sender, 6);

	// Trimit pachetul cu informatii pe care le-a cerut sender-ul
	send_to_link(interface, packet, sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
}

/* ZONA UNDE VERIFIC ADRESELE IP */
// Initializez array-ul cu adrese IP ale router-elor
// Cred ca orice router ar tine astfel de informatii
// intr-un cache pentru a nu face request-uri inutile
void initialize_router_ips()
{
	// ifconfig pentru router 0
	router_ips[0] = inet_addr("192.168.0.1"); // r0
	router_ips[1] = inet_addr("192.168.1.1"); // r1
	router_ips[2] = inet_addr("192.0.1.1");	  // r0-r1
	// ifconfig pentru router 1
	router_ips[3] = inet_addr("192.168.2.1"); // r0
	router_ips[4] = inet_addr("192.168.3.1"); // r1
	router_ips[5] = inet_addr("192.0.1.2");	  // r0-r1
}
bool is_router_ip(uint32_t dest_ip)
{
	for (int i = 0; i < 6; i++)
	{
		if (dest_ip == router_ips[i])
		{
			return true;
		}
	}
	return false;
}

/* ZONA PENTRU ARP */
// structura pentru pachet care asteapta raspuns la ARP request
struct arp_packet
{
	uint32_t ip_dest;
	int interface;
	char *packet;
	size_t len;
};
// creez queue pentru pachetele care asteapta raspuns la ARP request
queue q;

void send_arp_request(int interface, uint32_t target_ip)
{
	// ARP REQUEST : Cerere de adresa MAC pentru o anumita adresa IP

	// se trimite de catre router pentru a afla adresa MAC a unui host
	// sender = router, target = host

	// marime pachet ARP = dimensiunea antetului Ethernet + dimensiunea antetului ARP
	uint8_t buf[sizeof(struct ether_header) + sizeof(struct arp_header)];
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// Completez antetul Ethernet
	memset(eth_hdr->ether_dhost, 0xff, 6);				// Adresa MAC de broadcast
	get_interface_mac(interface, eth_hdr->ether_shost); // Adresa MAC a interfetei routerului
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);
	// Completez antetul ARP
	arp_hdr->htype = htons(1); // Ethernet
	arp_hdr->ptype = htons(ETHERTYPE_IP);
	arp_hdr->hlen = 6;							// lungimea adresei MAC
	arp_hdr->plen = 4;							// lungimea adresei IP
	arp_hdr->op = htons(1);						// ARP Request
	get_interface_mac(interface, arp_hdr->sha); // Adresa MAC a senderului (routerului)
	printf("Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arp_hdr->sha[0], arp_hdr->sha[1], arp_hdr->sha[2], arp_hdr->sha[3], arp_hdr->sha[4], arp_hdr->sha[5]);
	arp_hdr->spa = inet_addr(get_interface_ip(interface));
	printf("Sender IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->spa));
	// Adresa IP a senderului (routerului)
	memset(arp_hdr->tha, 0, 6); // Adresa MAC target este necunoscuta (vrem sa o aflam)
	arp_hdr->tpa = target_ip;	// Adresa IP target
	printf("Sending ARP request for IP: %s\n", inet_ntoa(*(struct in_addr *)&target_ip));
	// Trimite pachetul ARP pe interfata specificata de best_route (nu pe interface-ul de pe care venea pachetul initial, cum faceam inainte)
	send_to_link(interface, (char *)buf, sizeof(buf));
}
void enqueue_packet(uint32_t ip_dest, int interface, char *packet, size_t len)
{
	struct arp_packet *queued_packet = malloc(sizeof(struct arp_packet));
	queued_packet->ip_dest = ip_dest;
	queued_packet->interface = interface;
	queued_packet->packet = malloc(len);
	memcpy(queued_packet->packet, packet, len);
	queued_packet->len = len;
	// Adaug pachetul in coada
	queue_enq(q, queued_packet);
}
struct arp_table_entry *find_arp_entry(uint32_t ip)
{
	// Caut in cache-ul ARP adresa IP specificata
	for (int i = 0; i < arptable_size; ++i)
	{
		if (arptable[i].ip == ip)
		{
			return &arptable[i];
		}
	}
	return NULL; // Nu a fost gasita adresa IP in cache-ul ARP
}
void update_arp_cache(uint32_t ip, uint8_t *mac)
{
	for (int i = 0; i < arptable_size; ++i)
	{
		if (arptable[i].ip == ip)
		{
			// Daca exista deja in cache, actualizam adresa MAC
			memcpy(arptable[i].mac, mac, 6);
			return;
		}
	}

	// Daca nu exista adaug in cache
	if (arptable_size < MAX_ARP_ENTRIES)
	{
		arptable[arptable_size].ip = ip;
		memcpy(arptable[arptable_size].mac, mac, 6);
		arptable_size++;
	}
	else
	{
		// Cazul foarte improbabil in care cache-ul ARP este plin
		// Mai ales pentru faptul ca MAX_ARP_ENTRIES este destul de mare
		// pentru tipul de retea pe care o avem
		printf("ARP cache is full\n");
	}
}
void process_arp_queue(uint32_t resolved_ip)
{
	// Creez o coada temporara pentru a retine pachetele care asteapta raspuns la ARP request si care nu sunt pentru IP-ul primit
	queue temp_q = queue_create();
	printf("Looking for packets waiting for IP: %s\n", inet_ntoa(*(struct in_addr *)&resolved_ip));
	while (!queue_empty(q))
	{
		struct arp_packet *packet = (struct arp_packet *)queue_deq(q);
		if (packet->ip_dest == resolved_ip)
		{
			// Verific daca adresa MAC este acum in cache
			struct arp_table_entry *entry = find_arp_entry(packet->ip_dest);
			if (entry != NULL)
			{
				// daca este in cache, continui cu trimiterea pachetului
				printf("Found MAC address for IP: %s\n", inet_ntoa(*(struct in_addr *)&packet->ip_dest));
				printf("The MAC address is: %02x:%02x:%02x:%02x:%02x:%02x\n", entry->mac[0], entry->mac[1], entry->mac[2], entry->mac[3], entry->mac[4], entry->mac[5]);
				// Avem adresa MAC, asa ca putem sa trimitem pachetul
				// Actualizez adresa MAC a destinatarului
				memcpy(((struct ether_header *)packet->packet)->ether_dhost, entry->mac, 6);
				send_to_link(packet->interface, packet->packet, packet->len);
				// Eliberam memoria alocata pentru pachet
				free(packet->packet);
				free(packet);
			}
			else
			{
				// Daca nu am primit inca raspuns la ARP request, pachetul este pus in coada temporara
				// Daca totusi ip = resolved_ip, deobicei este updatat cache-ul dar se poate intampla sa nu fie
				queue_enq(temp_q, packet);
			}
		}
		else
		{
			// Daca pachetul nu asteapta un raspuns de la IP-ul rezolvat, il punem in coada temporara
			queue_enq(temp_q, packet);
		}
	}

	// Punem inapoi pachetele care nu au fost trimise
	while (!queue_empty(temp_q))
	{
		queue_enq(q, queue_deq(temp_q));
	}
}

void send_arp_reply(int interface, uint32_t sender_ip, uint8_t *sender_mac, uint32_t target_ip)
{
	// ARP REPLY : Raspuns al router-ului la un pachet ARP request (trimis de alt host)
	// destinatar = sender, sender = router

	// Marimea pachetului ARP = dimensiunea antetului Ethernet + dimensiunea antetului ARP
	uint8_t buf[sizeof(struct ether_header) + sizeof(struct arp_header)];
	struct ether_header *eth_hdr = (struct ether_header *)buf;
	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// Configurez antetul Ethernet
	memcpy(eth_hdr->ether_dhost, sender_mac, 6);		// Adresa MAC a sender-ului
	get_interface_mac(interface, eth_hdr->ether_shost); // Adresa MAC a interfetei routerului
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);			// Tipul pachetului Ethernet

	// Configurez antetul ARP
	arp_hdr->htype = htons(1);					// Ethernet
	arp_hdr->ptype = htons(ETHERTYPE_IP);		// IPv4
	arp_hdr->hlen = 6;							// Lungimea adresei MAC
	arp_hdr->plen = 4;							// Lungimea adresei IP
	arp_hdr->op = htons(2);						// ARP Reply
	get_interface_mac(interface, arp_hdr->sha); // Adresa MAC a routerului
	arp_hdr->spa = target_ip;					// Adresa IP a routerului
	memcpy(arp_hdr->tha, sender_mac, 6);		// Adresa MAC a sender-ului
	arp_hdr->tpa = sender_ip;					// Adresa IP a sender-ului

	printf("Sending ARP reply to IP: %s\n", inet_ntoa(*(struct in_addr *)&sender_ip));
	// Trimit raspunsul ARP pe interfata specificata
	send_to_link(interface, (char *)buf, sizeof(buf));
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Citesc tabela de rutare
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "malloc");
	// Verific ce tabela de rutare am : router0 sau router1
	rtable_size = read_rtable(argv[1], rtable);

	// initializez tabela ARP (cache-ul ARP)
	arptable = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arptable == NULL, "malloc");
	arptable_size = 0; // initial nu am nicio intrare in tabela ARP

	// Creez trie tree pentru a cauta in tabela de rutare
	trie_root = trie_node_create();
	for (int i = 0; i < rtable_size; i++)
	{
		// inserare in trie tree
		trie_insert(trie_root, htonl(rtable[i].prefix), htonl(rtable[i].mask), &rtable[i]);
	}
	printf("Finished creating the trie\n");

	// Initializez adresele IP ale routerelor
	initialize_router_ips();

	// Creez coada pentru pachetele care asteapta raspuns la ARP request
	q = queue_create();

	while (1)
	{

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// Verific daca pachetul este ceva relevant
		// Am doar pachete de tipul IPv4 sau ARP
		if (eth_hdr->ether_type != htons(ETHERTYPE_IP) && eth_hdr->ether_type != htons(ETHERTYPE_ARP))
		{
			printf("Not an IPv4/ARP packet ! Not interested !\n");
			continue;
		}
		if (eth_hdr->ether_type == htons(ETHERTYPE_IP))
		{
			printf("IPV4 packet\n");
		}
		// verific daca am pachet ARP
		if (eth_hdr->ether_type == htons(ETHERTYPE_ARP))
		{
			printf("ARP packet - check if it's for the router\n");
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			// Afisez informatii despre pachetul ARP
			printf("ARP packet type: %d\n", ntohs(arp_hdr->op));
			printf("ARP packet sender IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->spa));
			printf("ARP packet target IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->tpa));

			// Verific ca adresa IP de destinatie sa fie una din adresele routerului
			if (is_router_ip(arp_hdr->tpa))
			{
				printf("ARP packet for router\n");
				// Verific daca este un pachet de tip request
				if (ntohs(arp_hdr->op) == 1)
				{
					printf("ARP packet type = request\n");

					printf("ARP request for IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->tpa));
					// trimit un pachet ARP reply
					send_arp_reply(interface, arp_hdr->spa, eth_hdr->ether_shost, arp_hdr->tpa);
					continue;
				} // Sau daca este un pachet de tip reply
				else if (ntohs(arp_hdr->op) == 2)
				{
					printf("ARP packet type = reply\n");
					printf("ARP reply for IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_hdr->spa));
					// updatam tabela ARP -> adaugam adresa MAC in cache
					update_arp_cache(arp_hdr->spa, arp_hdr->sha);
					// procesam pachetele din coada
					process_arp_queue(arp_hdr->spa);
					continue;
				}
			}
			else
			{
				printf("ARP packet not for router\n");
				struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
				// Pentru ca nu este un pachet ARP pentru router, il ignor
				// prin a-l trimite mai departe pe interfata corespunzatoare
				struct route_table_entry *best_route = trie_search(trie_root, htonl(arp_hdr->tpa));
				if (!best_route)
				{
					// Trimit un mesaj ICMP Destination Unreachable (3, 0) inapoi catre sender
					printf("No route found\n");
					send_icmp_error(ip_hdr->saddr, buf, interface, 3, 0);
					continue;
				}
				printf("Found best route : %d\n", best_route->interface);
				// Trimit pachetul mai departe
				printf("Sending packet to link\n");
				send_to_link(best_route->interface, buf, len);
				continue;
			}
		}
		// Verificam checksum - daca este corect, pachetul este procesat
		uint16_t old_checksum = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t new_checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		if (old_checksum != new_checksum)
		{
			// Altfel se ignora pachetul
			printf("Checksum invalid\n");
			continue;
		}
		printf("Checksum valid\n");

		// Verificam TTL-ul - daca este 0, trimitem un mesaj ICMP Time Exceeded
		printf("TTL: %d\n", ip_hdr->ttl);
		if (ip_hdr->ttl <= 1)
		{
			printf("TTL expired\n");
			// Trimit un mesaj ICMP Time Exceeded (11, 0) inapoi catre sender
			send_icmp_error(ip_hdr->saddr, buf, interface, 11, 0);
			continue;
		}
		printf("TTL not expired\n");
		// uint16_t old_ttl = ip_hdr->ttl;
		ip_hdr->ttl--;
		// Actualizare checksum
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		// sau ca in lab : ip_hdr->check = ~(~old_checksum + ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

		// Verificam daca pachetul este unul ICMP Echo Request (8, 0) si daca adresa IP a destinatiei este una din adresele routerului
		struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
		if (icmp_hdr->type == 8 && is_router_ip(ip_hdr->daddr))
		{
			// Trimit un mesaj ICMP Echo Reply inapoi catre sender
			send_icmp_echo_reply(ip_hdr->saddr, buf, interface);
			printf("ICMP Echo Request\n");
			continue;
		}

		// Caut in tabela de rutare adresa IP a destinatiei
		printf("Searching for best route\n");
		struct route_table_entry *best_route = trie_search(trie_root, htonl(ip_hdr->daddr));
		if (!best_route)
		{
			// Trimite un mesaj ICMP Destination Unreachable inapoi (3, 0) catre sender
			send_icmp_error(ip_hdr->saddr, buf, interface, 3, 0);
			continue;
		}

		// Caut adresa MAC a urmatorului hop in tabela ARP
		struct arp_table_entry *arp_entry = NULL;
		for (int i = 0; i < arptable_size; i++)
		{
			if (arptable[i].ip == best_route->next_hop)
			{
				arp_entry = &arptable[i];
				break;
			}
		}
		if (!arp_entry)
		{
			// Daca nu am gasit intrarea in tabela ARP
			// Trimit un pachet ARP request si astept raspuns pentru a trimite pachetul
			// Pachetul este pus in coada
			printf("Mac address not found in ARP table\n");
			printf("Sending ARP request\n");
			printf("Next hop: %s\n", inet_ntoa(*(struct in_addr *)&best_route->next_hop));
			send_arp_request(best_route->interface, best_route->next_hop);
			enqueue_packet(best_route->next_hop, best_route->interface, buf, len);
			continue;
		}
		// Altfel, daca am gasit adresa MAC in tabela ARP, trimit pachetul
		memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
		get_interface_mac(best_route->interface, eth_hdr->ether_shost);
		send_to_link(best_route->interface, buf, len);
	}
	// Eliberez memoria alocata
	trie_free(trie_root);
}
