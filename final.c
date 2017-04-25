#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
GtkWidget *tvOutput;
GtkWidget *HTTPno;
GtkWidget *DNSno;
GtkWidget *TCPno;
GtkWidget *UDPno;
GtkWidget *IPno;
GtkWidget *ARPno;

GtkWidget *totalPacketInput;
GtkWidget *noPacketInput;
GObject * buttonStart;
GObject * buttonPacketNo;
GObject * buttonTCP;
GObject * buttonHTTP;
GObject * buttonDNS;
GObject * buttonIP;
GObject * buttonARP;
GObject * buttonUDP;
GObject * buttonClear;
GtkTextBuffer *buff;
GtkTextBuffer *buffHTTP;
GtkTextBuffer *buffDNS;
GtkTextBuffer *buffTCP;
GtkTextBuffer *buffUDP;
GtkTextBuffer *buffIP;
GtkTextBuffer *buffARP;
GtkTextBuffer *no;
GtkTextIter tvstart, tvend, nostart,noend;
int noPacketsToAnalyse;
char* fileName;
FILE* httpfp;
FILE* dnsfp;
FILE* tcpfp;
FILE* ipfp;
FILE* arpfp;
FILE* udpfp;

int currHTTP=0;
int currDNS=0;
int currIP=0;
int currUDP=0;
int currTCP=0;
int currARP=0;

#define T_A 1
#define T_NS 2 
#define T_CNAME 5
#define T_SOA 6 
#define T_PTR 12 
#define T_MX 15
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> 
#include<stdlib.h>    
#include<string.h>    
 
#include<netinet/ip_icmp.h>   
#include<netinet/udp.h>   
#include<netinet/tcp.h>   
#include<netinet/ip.h>    
#include<netinet/if_ether.h> 
#include<net/ethernet.h>  
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

#define hardware_len 6
#define protocol_len 4

#define tcp_switch 6
#define udp_switch 17

#define bufferLen 65536

FILE * httpLog;
FILE * dnsLog;
FILE * tcpLog;
FILE * udpLog;
FILE * ipLog;
FILE * arpLog;


struct arp {
    uint16_t headerType;
    unsigned char headerLength;

    unsigned char protocolLength;
    uint16_t protocolType;

    uint16_t oper;

    unsigned char sender_hardware_address[hardware_len];
    unsigned char target_hardware_address[hardware_len];

    unsigned char sender_protocol_address[protocol_len];
    unsigned char target_protocol_address[protocol_len];
};
 
void evaluatePacket(unsigned char* , int);
void evaluateIPHeader(unsigned char* , int);
void evaluateTCPpacket(unsigned char * , int );
void evaluateUDPpacket(unsigned char * , int );
void printFinalHTTP (unsigned char* , int, FILE* );
void printFinalARP(struct arp *arp_hdr);
 
void printNew()
{
    int a = 3;
    while(a--)
    {
        int sum = a +3;
    }
} 

//Function Prototypes
void printDns (unsigned char* , int);
unsigned char* getRealName (unsigned char*,unsigned char*,int*);
 
//DNS header structure

//cite DNS headers
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};
 

void getSame()
{
    int isThre= 2;
    int i =0 ;
    for(i = 0;i<5;i++)
    {
        isThre += i;
    }
} 
//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;
 
struct sockaddr_in source,dest;
int http = 0, dns = 0, tcp=0,udp=0,ip = 0,arp = 0, total = 0, others = 0; 

int httpPrinted = 0;
int dnsPrinted = 0;

void printDns(unsigned char *buf , int query_type)
{
    if(!dnsPrinted)
        fprintf(dnsLog , "\n\n***********************DNS Packets*************************\n");  

    dnsPrinted = 1;
    dns++;  

    fprintf(dnsLog , "\nPacket Number:%d\n\n",dns);


    unsigned char *qname,*reader;
    int i , j , stop , s;
 
    struct sockaddr_in a;

    printNew();
 
    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;
 
    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
 
    dns = (struct DNS_HEADER*) buf;
 
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    fprintf(dnsLog, "\nThe response contains : ");
    fprintf(dnsLog, "\n %d Questions.",ntohs(dns->q_count));
    fprintf(dnsLog, "\n %d Answers.",ntohs(dns->ans_count));
    fprintf(dnsLog, "\n %d Authoritative Servers.",ntohs(dns->auth_count));
    fprintf(dnsLog, "\n %d Additional records.\n\n",ntohs(dns->add_count));
 
    stop=0;
 
    printNew();

    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=getRealName(reader,buf,&stop);
        reader = reader + stop;
 

 //cite DNS headers
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = getRealName(reader,buf,&stop);
            reader = reader + stop;
        }

        //cite DNS headers
    }
    getSame();
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=getRealName(reader,buf,&stop);
        reader+=stop;
    printNew();
 

 //cite DNS headers
        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
 
        auth[i].rdata=getRealName(reader,buf,&stop);
        reader+=stop;
    }

    //cite DNS headers
 
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=getRealName(reader,buf,&stop);
        reader+=stop;
 

 //cite DNS headers
        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);
        printNew();
 
        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];
 
            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=getRealName(reader,buf,&stop);
            reader+=stop;
        }
    printNew();

        //cite DNS headers
    }
 
    fprintf(dnsLog, "\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printNew();

        fprintf(dnsLog, "Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            printNew();

            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            fprintf(dnsLog, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            fprintf(dnsLog, "has alias name : %s",answers[i].rdata);
            getSame();

        }
        printNew();

 
        fprintf(dnsLog, "\n");
    }
 
    fprintf(dnsLog, "\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {
        printNew();
         
        fprintf(dnsLog, "Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            fprintf(dnsLog, "has nameserver : %s",auth[i].rdata);
            getSame();

        }
        fprintf(dnsLog, "\n");
    }
 
    fprintf(dnsLog, "\nAdditional Records : %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        printNew();

        fprintf(dnsLog, "Name : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            fprintf(dnsLog, "has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
        fprintf(dnsLog, "\n");
    }
    fprintf(dnsLog, "**********************************************************\n" );
    getSame();

        // fprintf(dnsLog , "\n\n****************************************************************\n");  

    return;
}
 
u_char* getRealName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char * name;

    //cite DNS headersname;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        printNew();

        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
        getSame();

 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    getSame();

    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
    printNew();
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        getSame();

        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

int startPacketCapture(int noPacketsToAnalyse)
{
    httpLog=fopen("http.txt","w");
    dnsLog=fopen("dns.txt","w");
    printNew();
    tcpLog=fopen("tcp.txt","w");
    udpLog=fopen("udp.txt","w");
    ipLog=fopen("ip.txt","w");
    arpLog=fopen("arp.txt","w");

    unsigned char *buffer = (unsigned char *) malloc(bufferLen);

    int saddr_size , data_size;
    struct sockaddr saddr;
        
    getSame();

    printNew();
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    if(sock_raw < 0)
    {
        perror("Socket Error");
        return 1;
    }
    
    // printf("here\n");
    while(1)
    {
        saddr_size = sizeof saddr;
    
        data_size = recvfrom(sock_raw , buffer , bufferLen , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return 1;
        }
        //Now process the packet
        evaluatePacket(buffer , data_size);

        if(total > noPacketsToAnalyse)
            break;

    }
    // fclose(httpLog);
    // fclose(dnsLog);
    // fclose(tcpLog);
    // fclose(udpLog);
    // fclose(arpLog);
    // fclose(ipLog);
    // close(sock_raw);
    printf("\nFinished");
    return 0;
}
 
void evaluatePacket(unsigned char* buffer, int size)
{
    struct arp* arp_hdr;
    arp_hdr = (struct arp *)(buffer+14);
    printFinalARP(arp_hdr);

    getSame();

    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) 
    {         
        case tcp_switch:
            ++total;
            evaluateTCPpacket(buffer , size);
            break;
         
        case udp_switch:
            ++total;
            printNew();
            evaluateUDPpacket(buffer , size);
            break;
         
        default:
            ++others;
            break;
    }
    printf("Total Packets: %d \r", total);
    getSame();

}
void evaluateIPHeader(unsigned char* Buffer, int Size)
{

    if(!ip)
    fprintf(ipLog , "\n\n***********************IP Packets*************************\n");  

    ip++;  
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    getSame();



    fprintf(ipLog , "\n");
    fprintf(ipLog , "Packet Number %d\n", ip);


    fprintf(ipLog , "Header\n");
    fprintf(ipLog , "IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(ipLog , "IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    printNew();
    fprintf(ipLog , "Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(ipLog , "IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(ipLog , "Identification    : %d\n",ntohs(iph->id));
    fprintf(ipLog , "TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(ipLog , "Protocol : %d\n",(unsigned int)iph->protocol);
    printNew();
    fprintf(ipLog , "Checksum : %d\n",ntohs(iph->check));
    fprintf(ipLog , "Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(ipLog , "Destination IP   : %s\n",inet_ntoa(dest.sin_addr));

    fprintf(ipLog , "\n");

    fprintf(ipLog, "**********************************************************\n" );

    getSame();

    // fprintf(tcpLog , "                        DATA Dump                         ");


}

void print_http_packet(unsigned char* a, int b, FILE* logg)
{
    http++;
    fprintf(httpLog , "Packet Number: %d\n", http);    
    printFinalHTTP(a , b , logg);
    fprintf(httpLog , "\n\n");    
}
 
void evaluateTCPpacket(unsigned char* Buffer, int Size)
{
    if(!tcp)
    fprintf(tcpLog , "\n\n***********************TCP Packets*************************\n");  

    ++tcp;

    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
    getSame();
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
     
         
    evaluateIPHeader(Buffer,Size);
         
    fprintf(tcpLog , "\n");
    fprintf(tcpLog , "Packet Number %d\n", tcp);

    fprintf(tcpLog , "Header\n");
    fprintf(tcpLog , "Source Port      : %u\n",ntohs(tcph->source));
    fprintf(tcpLog , "Destination Port : %u\n",ntohs(tcph->dest));
    printNew();
    fprintf(tcpLog , "Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(tcpLog , "Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(tcpLog , "Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(tcpLog , "Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    getSame();
    fprintf(tcpLog , "Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(tcpLog , "Push Flag            : %d\n",(unsigned int)tcph->psh);
    printNew();
    fprintf(tcpLog , "Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(tcpLog , "Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(tcpLog , "Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(tcpLog , "Window         : %d\n",ntohs(tcph->window));
    getSame();
    fprintf(tcpLog , "Checksum       : %d\n",ntohs(tcph->check));
    fprintf(tcpLog , "Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(tcpLog , "\n");
    fprintf(tcpLog , "\n");
         
    if(ntohs(tcph->dest) == 80)
    {
        if(!httpPrinted)
            fprintf(httpLog , "\n\n***********************HTTP Packets*************************\n");  

        httpPrinted = 1;


        if((Size - header_size)>50)
        {
            print_http_packet(Buffer + header_size, Size - header_size, httpLog);
        }
    }
                         
    fprintf(tcpLog, "**********************************************************\n" );

}
 
void evaluateUDPpacket(unsigned char *Buffer , int Size)
{

    if(!udp)
    fprintf(udpLog , "\n\n***********************UDP Packets*************************\n");

    ++udp;

     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     
     
    evaluateIPHeader(Buffer,Size);           
    fprintf(udpLog , "Packet Number %d\n", udp); 
    fprintf(udpLog , "\nHeader\n");
    getSame();
    fprintf(udpLog , "Source Port      : %d\n" , ntohs(udph->source));
    printNew();
    fprintf(udpLog , "Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(udpLog , "UDP Length       : %d\n" , ntohs(udph->len));
    getSame();
    fprintf(udpLog , "UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(udpLog , "\n");
    if(ntohs(udph->source)==53 || ntohs(udph->dest)==53)
    {
        printDns(Buffer + header_size,0);
    }

    fprintf(udpLog, "\n\n" );

    fprintf(udpLog, "**********************************************************\n" );

     
}
void printFinalHTTP (unsigned char* data , int Size, FILE* logfile)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {

        if( i!=0 && i%16==0)
        {
            printNew();
               int temp = 0;
            for(j=i-16 ; j<i ; j++)
            {
                getSame();
                if(data[j]>=32 && data[j]<=128)
                {
                    if(data[j] != '\n'){
                        fprintf(logfile , "%c",(unsigned char)data[j]); 
                        temp ++;
                    }
                        
            
                }
                else if(temp>5) fprintf(logfile , "\n"); 
                getSame();
            
            }
        } 
    }
            fprintf(logfile ,  "\n" );

    fprintf(logfile, "**********************************************************\n" );

}
void printFinalARP(struct arp *arp_hdr)
{
    if(!arp)
        fprintf(arpLog , "\n\n***********************ARP Packets*************************\n\n");


    arp++;

    fprintf(arpLog, "Packet Number:%d\n\n", arp);

    getSame();

    uint16_t headerType = ntohs(arp_hdr->headerType);
    uint16_t protocolType = ntohs(arp_hdr->protocolType);
    uint16_t oper = ntohs(arp_hdr->oper);
    switch(headerType)
    {
        case 0x0001:
            fprintf(arpLog, "HTYPE: Ethernet(0x%04X)\n", headerType);
            break;
        default:
            fprintf(arpLog, "HYPE: 0x%04X\n", headerType);
            break;
    }
    switch(protocolType)
    {
        case 0x0800:
            fprintf(arpLog, "PTYPE: IPv4(0x%04X)\n", protocolType);
            break;
        default:
            fprintf(arpLog, "PTYPE: 0x%04X\n", protocolType);
            break;
    }
    fprintf(arpLog, "HLEN: %d\n", arp_hdr->headerLength);
    fprintf(arpLog, "PLEN: %d\n", arp_hdr->protocolLength);
    switch(oper)
    {
        case 0x0001:
            fprintf(arpLog, "OPER: Request(0x%04X)\n", oper);
            break;
        case 0x0002:
            fprintf(arpLog, "OPER: Response(0x%04X)\n", oper);
            break;
        default:
            fprintf(arpLog, "OPER: 0x%04X\n", oper);
            break;
    }
    fprintf(arpLog, "Sender HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_hdr->sender_hardware_address[0],arp_hdr->sender_hardware_address[1],arp_hdr->sender_hardware_address[2],
           arp_hdr->sender_hardware_address[3], arp_hdr->sender_hardware_address[4], arp_hdr->sender_hardware_address[5]);
    fprintf(arpLog, "Sender PA: %d.%d.%d.%d\n", arp_hdr->sender_protocol_address[0],
           arp_hdr->sender_protocol_address[1], arp_hdr->sender_protocol_address[2], arp_hdr->sender_protocol_address[3]);
    fprintf(arpLog, "Target HA: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp_hdr->target_hardware_address[0],arp_hdr->target_hardware_address[1],arp_hdr->target_hardware_address[2],
           arp_hdr->target_hardware_address[3], arp_hdr->target_hardware_address[4], arp_hdr->target_hardware_address[5]);
    fprintf(arpLog, "Target PA: %d.%d.%d.%d\n", arp_hdr->target_protocol_address[0],
           arp_hdr->target_protocol_address[1], arp_hdr->target_protocol_address[2], arp_hdr->target_protocol_address[3]);


    fprintf(arpLog, "\n\n" );
    fprintf(arpLog, "**********************************************************\n" );

}


void onStartClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter (no, &nostart);
    gtk_text_buffer_get_end_iter (no, &noend);
    char* packetsToAnalyse = gtk_text_buffer_get_text (no, &nostart, &noend, FALSE);
    noPacketsToAnalyse = atoi(packetsToAnalyse);
    startPacketCapture(noPacketsToAnalyse);
}

void onClearClicked()
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    
    if(httpfp==0)
        return ;
    char output[10000];
    while(fgets (output, 10000, httpfp))
    {
       if(strcmp(output,"**********************************************************\n")==0)
           break;
        gtk_text_buffer_insert(buff,&tvstart,output,-1);
    }
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);
    
}

void onHTTPClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    
    if(httpfp==0)
        return ;
    char output[10000];
    while(fgets (output, 10000, httpfp))
    {
       if(strcmp(output,"**********************************************************\n")==0)
           break;
        gtk_text_buffer_insert(buff,&tvstart,output,-1);
    }
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);
    currHTTP++;
    gtk_text_buffer_get_start_iter(buffHTTP,&tvstart);
    char no[10];
    sprintf(no, "%d", currHTTP);
    gtk_text_buffer_insert(buffHTTP,&tvstart,no,-1);
    gtk_text_buffer_get_end_iter(buffHTTP,&tvend);
    gtk_text_buffer_delete(buffHTTP,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buffHTTP,&tvstart);

}

void onDNSClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    gtk_text_buffer_insert(buff,&tvstart,"",-1);
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);


}

void onTCPClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    if(tcpfp==NULL)
        return ;
    char output[10000];
    while(fgets (output, 10000, tcpfp))
    {
        if(strcmp(output,"**********************************************************\n")==0)
            break ;
        gtk_text_buffer_insert(buff,&tvstart,output,-1);
    }
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);


    currTCP++;
    gtk_text_buffer_get_start_iter(buffTCP,&tvstart);
    char no[10];
    sprintf(no, "%d", currTCP);
    gtk_text_buffer_insert(buffTCP,&tvstart,no,-1);
    gtk_text_buffer_get_end_iter(buffTCP,&tvend);
    gtk_text_buffer_delete(buffTCP,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buffTCP,&tvstart);
}

void onIPClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    if(ipfp==NULL)
        return ;
    char output[10000];
    while(fgets (output, 10000, ipfp))
    {
        if(strcmp(output,"**********************************************************\n")==0)
            break;
        gtk_text_buffer_insert(buff,&tvstart,output,-1);
    }
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);


    currIP++;
    gtk_text_buffer_get_start_iter(buffIP,&tvstart);
    char no[10];
    sprintf(no, "%d", currIP);
    gtk_text_buffer_insert(buffIP,&tvstart,no,-1);
    gtk_text_buffer_get_end_iter(buffIP,&tvend);
    gtk_text_buffer_delete(buffIP,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buffIP,&tvstart);
}

void onARPClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    if(arpfp==NULL)
        return ;
    char output[10000];
    while(fgets (output, 10000, arpfp))
    {
        if(strcmp(output,"**********************************************************\n")==0)
            break;
        gtk_text_buffer_insert(buff,&tvstart,output,-1);
    }
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);


    currARP++;
    gtk_text_buffer_get_start_iter(buffARP,&tvstart);
    char no[10];
    sprintf(no, "%d", currARP);
    gtk_text_buffer_insert(buffARP,&tvstart,no,-1);
    gtk_text_buffer_get_end_iter(buffARP,&tvend);
    gtk_text_buffer_delete(buffARP,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buffARP,&tvstart);
}

void onUDPClicked(GtkWidget* widget)
{
    gtk_text_buffer_get_start_iter(buff,&tvstart);
    if(udpfp==NULL)
        return ;
    char output[10000];
    while(fgets (output, 10000, udpfp))
    {
        if(strcmp(output,"**********************************************************\n")==0)
            break;
        gtk_text_buffer_insert(buff,&tvstart,output,-1);
    }
    gtk_text_buffer_get_end_iter(buff,&tvend);
    gtk_text_buffer_delete(buff,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buff,&tvstart);

    currUDP++;
    gtk_text_buffer_get_start_iter(buffUDP,&tvstart);
    char no[10];
    sprintf(no, "%d", currUDP);
    gtk_text_buffer_insert(buffUDP,&tvstart,no,-1);
    gtk_text_buffer_get_end_iter(buffUDP,&tvend);
    gtk_text_buffer_delete(buffUDP,&tvstart,&tvend);
    gtk_text_buffer_get_end_iter(buffUDP,&tvstart);
}

void on_window_main_destroy()
{
    gtk_main_quit();
}

int main(int argc, char *argv[])
{
    GtkBuilder      *builder; 
    GtkWidget       *window;
 
    gtk_init(&argc, &argv);
 
    builder = gtk_builder_new();
    gtk_builder_add_from_file (builder, "Unsaved 1.glade", NULL);
 
    window = GTK_WIDGET(gtk_builder_get_object(builder, "window1"));
    gtk_builder_connect_signals(builder, NULL);

    tvOutput = GTK_WIDGET(gtk_builder_get_object(builder, "tvOutput"));
    HTTPno = GTK_WIDGET(gtk_builder_get_object(builder, "HTTPno"));
    DNSno = GTK_WIDGET(gtk_builder_get_object(builder, "DNSno"));
    TCPno = GTK_WIDGET(gtk_builder_get_object(builder, "TCPno"));
    UDPno = GTK_WIDGET(gtk_builder_get_object(builder, "UDPno"));
    IPno = GTK_WIDGET(gtk_builder_get_object(builder, "IPno"));
    ARPno = GTK_WIDGET(gtk_builder_get_object(builder, "ARPno"));

    totalPacketInput = GTK_WIDGET(gtk_builder_get_object(builder, "noPacketsToScan"));

    buttonStart = gtk_builder_get_object(builder, "startButton");
    buttonPacketNo = gtk_builder_get_object(builder, "packetButton");
    buttonUDP = gtk_builder_get_object(builder, "UDPbutton");
    buttonARP = gtk_builder_get_object(builder, "ARPbutton");
    buttonIP = gtk_builder_get_object(builder, "IPbutton");
    buttonTCP = gtk_builder_get_object(builder, "TCPbutton");
    buttonHTTP = gtk_builder_get_object(builder, "HTTPbutton");
    buttonDNS = gtk_builder_get_object(builder, "DNSbutton");
    buttonClear = gtk_builder_get_object(builder, "clearButton");

    g_signal_connect(buttonStart, "clicked", G_CALLBACK(onStartClicked), NULL);
    g_signal_connect(buttonHTTP, "clicked", G_CALLBACK(onHTTPClicked), NULL);
    g_signal_connect(buttonDNS, "clicked", G_CALLBACK(onDNSClicked), NULL);
    g_signal_connect(buttonTCP, "clicked", G_CALLBACK(onTCPClicked), NULL);
    g_signal_connect(buttonIP, "clicked", G_CALLBACK(onIPClicked), NULL);
    g_signal_connect(buttonARP, "clicked", G_CALLBACK(onARPClicked), NULL);
    g_signal_connect(buttonUDP, "clicked", G_CALLBACK(onUDPClicked), NULL);
    g_signal_connect(buttonClear, "clicked", G_CALLBACK(onClearClicked), NULL);


   
    httpfp = fopen("http.txt","r");
    dnsfp = fopen("dns.txt","r");
    tcpfp = fopen("tcp.txt","r");
    udpfp = fopen("udp.txt","r");
    ipfp = fopen("ip.txt","r");
    arpfp = fopen("arp.txt","r");

    
    buff = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tvOutput));
    no = gtk_text_view_get_buffer(GTK_TEXT_VIEW(totalPacketInput));
    buffHTTP = gtk_text_view_get_buffer(GTK_TEXT_VIEW(HTTPno));
    buffDNS = gtk_text_view_get_buffer(GTK_TEXT_VIEW(DNSno));
    buffTCP  = gtk_text_view_get_buffer(GTK_TEXT_VIEW(TCPno));
    buffUDP  = gtk_text_view_get_buffer(GTK_TEXT_VIEW(UDPno));
    buffIP = gtk_text_view_get_buffer(GTK_TEXT_VIEW(IPno));
    buffARP  = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ARPno));
 
    g_object_unref(builder);
 
    gtk_widget_show(window);                
    gtk_main();
 
    return 0;
}

