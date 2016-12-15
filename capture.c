#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <regex.h>

#define tofind "^\\s*$"

void got_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_data(const u_char *, int, unsigned char *);


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int size_ethhdr = header->len;
	struct sockaddr_in source, dest;
	
	struct iphdr *iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	unsigned short size_iphdr = iph->ihl*4;

	struct tcphdr *tcph = (struct tcphdr*)(packet + size_iphdr + sizeof(struct ethhdr));

	int header_size = sizeof(struct ethhdr) + size_iphdr + tcph->doff*4;

	printf("Source: %s:%u\n", inet_ntoa(source.sin_addr), ntohs(tcph->source));
	printf("Dest: %s:%u\n", inet_ntoa(dest.sin_addr), ntohs(tcph->dest));

	int size = size_ethhdr - header_size;

	unsigned char stringao[size];

	print_data(packet + header_size, size_ethhdr - header_size, &stringao);

	//Contagem de acessos ao proc;
	if (strstr(stringao, "GET "))
		if (strstr(stringao, "/processo.php?proc="))
			printf("Stringao: \n%s\n", stringao);

}

void print_data(const u_char *data, int size, unsigned char *stringao) {
	int i;
	
	for (i = 0; i < size; i++) {
		if (data[i] >= 32 && data[i] <= 128) {
			//printf("%c", (unsigned char)data[i]);
			stringao[i] = (unsigned char)data[i];
		}
		else
			//printf(".");
			stringao[i] = (unsigned char)'.';
	}

}

int main(int argc, char *argv[]) {
	

	bpf_u_int32 mask;
	bpf_u_int32 net;
	char *dev, errbuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet;
	u_char *user;
	pcap_t *handle;
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	//char *filter_exp;
	regex_t re;
	int retval = 0, i;


	if (argc != 2) {
		fprintf(stderr, "Chamada invalida!\nDigitar: ./captura \"filtro tcpdump\"\n");
		return(2);
	}

	if (regcomp(&re, tofind, REG_EXTENDED) != 0) {
		fprintf(stderr, "Falha em compilar a regex \'%s\'\n", tofind);
		return(2);
	}

	strcpy(filter_exp, argv[1]);

	if ((retval = regexec(&re, filter_exp, 0, NULL, 0)) == 0) {
		fprintf(stderr, "Expressao de entrada vazia. Digitar o filtro entre \"\"\n");
		return(2);
	}

	dev = pcap_lookupdev(errbuff);

	if (dev == NULL) {
		fprintf(stderr, "Nao foi possivel encontrar o dispositivo: %s\n", errbuff);
		return(2);
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuff) == -1) {
		fprintf(stderr, "Nao foi possivel obter a mascara para o dispositivo: %s: %s\n", dev, errbuff);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuff);

	if (handle == NULL) {
		fprintf(stderr, "Nao e possivel abrir o dispositivo: %s: %s\n", errbuff);
		return(2);
	}

	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "O dispositivo %s nao possui cabecalhos ethernet\n", dev);
		return(2);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Nao foi possivel parsear o filtro \'%s: %s\'\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Nao foi possivel instalar o filtro \'%s: %s\'\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	pcap_loop(handle, 10, got_packet, user);

	pcap_close(handle);

	return(0);
}