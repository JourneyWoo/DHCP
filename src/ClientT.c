#include<sys/socket.h>
#include<sys/ioctl.h>
#include<stdio.h>
#include<stdlib.h>
#include<net/if.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>

#define clntPort 68
#define servPort 67
#define optionLen 32
#define bufferSize 2048
#define lt 7


struct dhcp{
//char -> 1 byte
	//Message Type
	uint8_t  mtype;
	//Hardware Type
	uint8_t  htype;
	//Hardware address length
	uint8_t  hlen;
	//hops
    	uint8_t  hops;
	//transaction id
    //	uint32_t  xid;
	uint32_t xid;
	//seconds elapsed
    	uint16_t  secs;
	//bootp flags
    	uint16_t  flags;
	//client ip address
    	uint32_t  ciaddr;
	//your ip address
    	uint32_t  yiaddr;
	//server ip address
    	uint32_t  siaddr;
	//router ip address
    	uint32_t  giaddr;
	//client hardware address find by ifconfig!
    	char  chaddr[6];
	//Client hardware address padding
	char  padding[10];
	//server host name(64)
    	char  bp_sname[64];
	//boot file name
    	char        bp_file[128];
	//Magic cookie
	char  mcookie[4];
	//options
    	char  options[255];
};
struct dhcp sendDHCP;
struct dhcp recvDHCP;
int sockClient;
char recvBuffer [bufferSize];
//int sockDiscover;
//int sockRelease;

unsigned char reqbuffer[bufferSize];

void * leaseThread (void * i);
void * leaseThread1 (void * i);
struct sockaddr_in clntAddr;
struct sockaddr_in servAddr;
int logprint(int l);
int DHCPDiscover();
int DHCPRelease();
int DHCPRequest();
int DHCPInform();
int clockFlag ;
int leaseTime;
char* getIP();
char * getServIP();
int getLeaseTime(int l);
int main(int argc, char*argv[]){
	clockFlag = 1;
		
	clntAddr.sin_family = AF_INET;
//clnt ip adress 0.0.0.0
	clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	clntAddr.sin_port = htons(clntPort);
	
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	servAddr.sin_port = htons(servPort);
	
	bzero(&recvBuffer,bufferSize);
	bzero(&recvDHCP,sizeof(recvDHCP));

	int i;
	struct ifreq if_eth1;
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);	
	if((sockClient = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
		perror("Socket error\n");
	}

//allow socket to broadcast

	if(setsockopt(sockClient,SOL_SOCKET,SO_REUSEADDR|SO_BROADCAST,&i,len)<0){
		perror("allow broadcast failed\n");
	}
	
//set socket to inferface eth1	
	if(setsockopt(sockClient,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
		perror("bind socket to eth1 error\n");
	}
	//bind socket to set client ip address to 0.0.0.0
	if((bind(sockClient,(struct sockaddr *)&clntAddr,sizeof(clntAddr)))<0){
		perror("bind() failed init\n");
	}

if(argc == 1){
	
	char* IP = (char * )malloc(sizeof(char)*20);

	IP = getIP();
	
	printf("HEADER IP: %s\n",IP);
	if(IP!=NULL){
		DHCPRelease(IP);
		settingIP(0);
	}else{
		printf("No IP\n");
	}
	DHCPDiscover();
	char OfferOption[3] = {0x35,0x01,0x02};	
	char AckOption[3] = {0x35,0x01,0x05};
	int recvfromBytes;

	for(;;){
	printf("\nstart recvfrom\n");
		int servAddrLen = sizeof(servAddr);
		recvfromBytes = recvfrom(sockClient,recvBuffer,bufferSize,0,(struct sockaddr *)&servAddr,&servAddrLen);
		clntAddr.sin_family = AF_INET;
	
		clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		clntAddr.sin_port = htons(clntPort);
	
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		servAddr.sin_port = htons(servPort);

        
		if(recvfromBytes<0){
			perror("recvFrom()");
		}else{
			memcpy (&recvDHCP,&recvBuffer,sizeof(recvDHCP)); 

			
			if(memcmp(OfferOption,recvDHCP.options,3)==0){
				printf("DHCPOffer Received\n");
				leaseTime = getLeaseTime(50);
				DHCPRequest("0.0.0.0","255.255.255.255",NULL);	
			}else if(memcmp(AckOption,recvDHCP.options,3)==0){
				printf("DHCPACK Received\n");
				settingIP(1);
				int sleepTime = 0.5*leaseTime/1000;
				printf("sleep %d\n",sleepTime);
				sleep(sleepTime);
			//	sleep(2);
				printf("\ntime!\n");
				char* servIP = (char *) malloc(sizeof(char)*20);
				char* clntIP = (char *) malloc(sizeof(char)*20);
				strcpy(servIP,getServIP());
				strcpy(clntIP,getIP());
				printf("\nservIP: %s\n",servIP);
				printf("\nclntIP: %s\n",clntIP);
				DHCPRequest(clntIP,servIP,clntIP);	

			}else{
				printf("No category\n");
			}
		}
	}

}else{
		clntAddr.sin_family = AF_INET;
		//clnt ip adress 0.0.0.0
		clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		clntAddr.sin_port = htons(clntPort);
	
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		servAddr.sin_port = htons(servPort);
	
	if(strcmp(argv[1],"release")==0){
		//default
		char* IP = (char * )malloc(sizeof(char)*20);

		IP = getIP();
		
		printf("HEADER IP: %s\n",IP);
		if(IP!=NULL){
			DHCPRelease(IP);
			settingIP(0);
		}else{
			printf("No IP\n");
		}
			


	}else if(strcmp(argv[1],"inform")==0){
		char* clntIP1 = (char *) malloc(sizeof(char)*20);
		strcpy(clntIP1,getIP());
		printf("clntIP: %s\n",clntIP1);
		if(clntIP1!=NULL){			
			DHCPInform(clntIP1);
		}else{
			printf("ERROR CLNT IP IS NULL\n");
		}	
		int recvfromBytes;
		int servAddrLen = sizeof(servAddr);
		while(1){
			recvfromBytes = recvfrom(sockClient,recvBuffer,bufferSize,0,(struct sockaddr *)&servAddr,&servAddrLen);
			
		char ACKOption[3] = {0x35,0x01,0x05};
			if(recvfromBytes<0){
				perror("recvFrom()");
			}else{
				printf("RACKrecvBytes%d\n",recvfromBytes);	
				memcpy (&recvDHCP,&recvBuffer,sizeof(recvDHCP)); 
				char AckOption[3] = {0x35,0x01,0x05};
		
			if(memcmp(ACKOption,recvDHCP.options,3)==0){
				printf("RACK recved %X\n",recvDHCP.options[8]);
				int renewTime = getLeaseTime(5);
				printf("RACK renew time:%d\n",renewTime/1000);
				int rebindTime = getLeaseTime(11);

				printf("RACK rebind time: %d\n",rebindTime/1000);
			}
			}
		}	
	}
	else if(strcmp(argv[1],"request")==0){
		char* reqIP2 = argv[2];
		char* clntIP2 = (char *) malloc(sizeof(char)*20);
		int servAddrLen = sizeof(servAddr);
		int recvfromBytes;
		strcpy(clntIP2,getIP());
		printf("\nclntIP: %s\n",clntIP2);
		if(clntIP2!=NULL){			
			DHCPRequest(clntIP2,"192.168.56.1",reqIP2);
		}else{
			printf("ERROR CLNT IP IS NULL\n");
		}
		pthread_t tid;
		if(( pthread_create(&tid,NULL,leaseThread,NULL)!=0)){
				perror("Error thread\n");
		}
		
		recvfromBytes = recvfrom(sockClient,recvBuffer,bufferSize,0,(struct sockaddr *)&servAddr,&servAddrLen);
			if(recvfromBytes<0){
				printf("Error Recvfrom\n");
			}else{
				printf("recved %d",recvfromBytes);
			}
			char NAKOption[3] = {0x35,0x01,0x06};
			char OfferOption[3] = {0x35,0x01,0x02};	
			char AckOption[3] = {0x35,0x01,0x05};
		
			memcpy(&recvDHCP,&recvBuffer,sizeof(recvDHCP));
			if(memcmp(NAKOption,recvDHCP.options,3)==0){
				clockFlag = 0;
				clntAddr.sin_family = AF_INET;
				//clnt ip adress 0.0.0.0
				clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
				clntAddr.sin_port = htons(clntPort);
	
				servAddr.sin_family = AF_INET;
				servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
				servAddr.sin_port = htons(servPort);
					
				DHCPDiscover();
				for(;;){
				printf("\nstart recvfrom\n");
				recvfrom(sockClient,recvBuffer,bufferSize,0,(struct sockaddr *)&servAddr,&servAddrLen);
					clntAddr.sin_family = AF_INET;
					//clnt ip adress 0.0.0.0
					clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
					clntAddr.sin_port = htons(clntPort);
	
					servAddr.sin_family = AF_INET;
					servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
					servAddr.sin_port = htons(servPort);
					//initSocket();
				memcpy (&recvDHCP,&recvBuffer,sizeof(recvDHCP)); 
				if(memcmp(OfferOption,recvDHCP.options,3)==0){
					printf("DHCPOffer Received\n");
					leaseTime = getLeaseTime(50);
					DHCPRequest("0.0.0.0","255.255.255.255",NULL);	
				}else if(memcmp(AckOption,recvDHCP.options,3)==0){
					printf("DHCPACK Received\n");
					settingIP(1);
					int sleepTime = (leaseTime/2)/1000;
					sleep(sleepTime);
					printf("time!\n");
					char* servIP2 = (char *) malloc(sizeof(char)*20);
					char* clntIP2 = (char *) malloc(sizeof(char)*20);
					strcpy(servIP2,getServIP());
					strcpy(clntIP2,getIP());
					printf("\nservIP: %s\n",servIP2);
					printf("\nclntIP: %s\n",clntIP2);
					DHCPRequest(clntIP2,servIP2,clntIP2);	

				}else{
					printf("No category\n");
				}
			}							
			}
		

	}
	}
}
char * getIP(){
	int testsock;
	struct sockaddr_in sin;
	struct ifreq ifr;
	
	testsock = socket(AF_INET,SOCK_DGRAM,0);
	if(testsock<0){
		perror("testsock");
		exit(1);	
	}
	strcpy(ifr.ifr_name,"eth1");
	int ipFlag;
	char * ipBuffer;
	ipFlag = ioctl(testsock,SIOCGIFADDR,&ifr);
	if(ipFlag == 0){
		memcpy(&sin,&ifr.ifr_addr,sizeof(ifr.ifr_addr));
		ipBuffer = inet_ntoa(sin.sin_addr);
		printf("There is an existing ip: %s\n\n",ipBuffer);

	return ipBuffer;
	}else{
		printf("there is no existing IP\n");
		return NULL;
	}
}

int settingIP(int flag){

	struct in_addr ipaddr;
	ipaddr.s_addr = recvDHCP.yiaddr;
	char * ipBuffer;
	ipBuffer = inet_ntoa(ipaddr);

	char command[100];
	if(flag == 0){
		strcpy(command,"ifconfig eth1 0.0.0.0");
		if(system(command)<0){
			perror("System Error\n");
		}else{
			printf("Eth1 IP has been set to 0.0.0.0\n");
		
		}
	}
	else if(flag == 1){
		strcpy(command,"ifconfig eth1 ");
		strcat(command,ipBuffer);
		strcat(command," netmask 255.255.255.0");
		if(system(command)<0){
			perror("System Error\n");
		}else{
			printf("Eth1 IP has been set to %s\n",ipBuffer);
		
		}
	}
}
int init(){
		
	clntAddr.sin_family = AF_INET;
//clnt ip adress 0.0.0.0
	clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	clntAddr.sin_port = htons(clntPort);
	
	servAddr.sin_family = AF_INET;
	servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	servAddr.sin_port = htons(servPort);
	
initSocket();
bzero(&recvBuffer,bufferSize);
	bzero(&recvDHCP,sizeof(recvDHCP));
}
int initSocket(){
	int i;
	struct ifreq if_eth1;
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);	
	if((sockClient = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
		perror("Socket error\n");
	}

//allow socket to broadcast

	if(setsockopt(sockClient,SOL_SOCKET,SO_REUSEADDR|SO_BROADCAST,&i,len)<0){
		perror("allow broadcast failed\n");
	}
	
//set socket to inferface eth1	
	if(setsockopt(sockClient,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
		perror("bind socket to eth1 error\n");
	}
	//bind socket to set client ip address to 0.0.0.0


}
int DHCPDiscover(){
	logprint(1);
	int i=0;
	socklen_t len = sizeof(i);	

    
    unsigned char buffer[bufferSize];
	int sendtoBytes;

	
	bzero(&sendDHCP,sizeof(sendDHCP));
	//itoa can change int to char[]
	sendDHCP.mtype = 0x01;
	sendDHCP.htype = 0x01;
	sendDHCP.hlen = 0x06;
	sendDHCP.hops = 0;
	sendDHCP.xid = htonl(0xf4d82700);
	sendDHCP.secs = 0x0000;


	char chaddrBuffer[6] = {0x08,0x00,0x27,0xa9,0x67,0xa3};	
	memcpy(&sendDHCP.chaddr,&chaddrBuffer,sizeof(chaddrBuffer));
	
	uint32_t mcookieBuffer = htonl(0x63825363);
	memcpy(&(sendDHCP.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));
	
	char * p = &sendDHCP.options[0];
	
	char optionBuffer1 [3] = {0x35,0x01,0x01}; 
	
	memcpy(p,optionBuffer1,sizeof(optionBuffer1));	
	p+=sizeof(optionBuffer1);
	

	memset(p,0,6);

	p+=6;
	
	char optionBuffer3 [8] = {0x0c,0x06,0x42,0x55,0x50,0x54,0x49,0x41};
	memcpy(p,optionBuffer3,sizeof(optionBuffer3));	
	p+=sizeof(optionBuffer3);

	char optionBuffer4 [15] = {0x37,0x0d,0x01,0x1c,0x02,0x03,0x0f,0x06,0x77,0x0c,0x2c,0x2f,0x1a,0x79,0x2a};
	memcpy(p,optionBuffer4,sizeof(optionBuffer4));	
	p+=sizeof(optionBuffer4);

	char optionBuffer5  = 0xff;
	memcpy(p,&optionBuffer5,sizeof(optionBuffer5));	
	p+=sizeof(optionBuffer5);
	
	memset(&buffer,0,bufferSize);
	memcpy(&buffer,&sendDHCP,sizeof(sendDHCP));


	//  dhcp
	if((sendtoBytes = sendto(sockClient,buffer,bufferSize,0,(struct sockaddr*) &servAddr, sizeof(servAddr))) != bufferSize){
			perror("sendto() failed Discover\n");
	}else
		printf("DHCPDiscover sendtoBytes: %d\n",sendtoBytes);
	
	

}
int DHCPInform(char * clntIP){
	logprint(6);
	unsigned char buffer[bufferSize];
	int sendtoBytes;

	
	bzero(&sendDHCP,sizeof(sendDHCP));
	//itoa can change int to char[]
	sendDHCP.mtype = 0x01;
	sendDHCP.htype = 0x01;
	sendDHCP.hlen = 0x06;
	sendDHCP.hops = 0;
	sendDHCP.xid = htonl(0xbc1ae078);
	sendDHCP.secs = 0x0000;

	struct in_addr ciaddr_in;
	char* currentIP = (char *) malloc(sizeof(char)*20);		 strcpy(currentIP,getIP());
	inet_aton(currentIP,&ciaddr_in);
	memcpy(&sendDHCP.ciaddr,&ciaddr_in,sizeof(ciaddr_in)); 


	char chaddrBuffer[6] = {0x08,0x00,0x27,0xa9,0x67,0xa3};	
	memcpy(&sendDHCP.chaddr,&chaddrBuffer,sizeof(chaddrBuffer));
	
	uint32_t mcookieBuffer = htonl(0x63825363);
	memcpy(&(sendDHCP.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));
	
	char * p = &sendDHCP.options[0];
//option:53	
	char optionBuffer1 [3] = {0x35,0x01,0x08}; 
	
	memcpy(p,optionBuffer1,sizeof(optionBuffer1));	
	p+=sizeof(optionBuffer1);
//client identifier	
	char optionBuffer2 [3] = {0x3d,0x07,0x01}; 
	memcpy(p,optionBuffer2,sizeof(optionBuffer2));	
	p+=sizeof(optionBuffer2);
	
	memcpy(p,chaddrBuffer,sizeof(chaddrBuffer));
	p+=sizeof(chaddrBuffer);
//host name
	char optionBuffer3 [9] = {0x0c,0x07,0x4c,0x69,0x2d,0x42,0x55,0x50,0x54};
	memcpy(p,optionBuffer3,sizeof(optionBuffer3));	
	p+=sizeof(optionBuffer3);
//vendor class identifier
	char optionBuffer4 [10]  = {0x3c,0x08,0x4d,0x53,0x46,0x54,0x20,0x35,0x2e,0x30};
	memcpy(p,&optionBuffer4,sizeof(optionBuffer4));	
	p+=sizeof(optionBuffer4);
//parameter request list
	char optionBuffer5 [15] = {0x37,0x0d,0x01,0x0f,0x03,0x06,0x2c,0x2e,0x2f,0x1f,0x21,0x79,0xf9,0x2b,0xfc};
	memcpy(p,&optionBuffer5,sizeof(optionBuffer5));	
	p+=sizeof(optionBuffer5);
	char optionBuffer6[1] = {0xff};
	memcpy(p,&optionBuffer6,sizeof(optionBuffer6));	
	p+=sizeof(optionBuffer6);


	memset(&buffer,0,bufferSize);
	memcpy(&buffer,&sendDHCP,sizeof(sendDHCP));

	struct sockaddr_in fromAddr;
	struct sockaddr_in toAddr;
	
	fromAddr.sin_family = AF_INET;
	inet_aton(clntIP,&fromAddr.sin_addr);	

	fromAddr.sin_port = htons(clntPort);
	
	toAddr.sin_family = AF_INET;

	inet_aton("192.168.56.1",&toAddr.sin_addr);
	toAddr.sin_port = htons(servPort);
	
	int i;
	int sockInform;
	struct ifreq if_eth1;
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);	

	if((sockInform = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
		perror("Socket error\n");
	}

//set socket to inferface eth1	
	if(setsockopt(sockInform,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
		perror("bind socket to eth1 error\n");
	}
	if(setsockopt(sockInform,SOL_SOCKET,SO_REUSEADDR|SO_BROADCAST,&i,len)<0){
                perror("allow broadcast failed\n");
        
	}

	if((sendtoBytes = sendto(sockInform,buffer,bufferSize,0,(struct sockaddr*) &toAddr, sizeof(toAddr))) != bufferSize){
			perror("sendto() failed Inform\n");
	}else
		printf("DHCPInform: sendtoBytes: %d\n",sendtoBytes);
	//close(sockInform);	

}

int DHCPRelease(char * clntIP){
	logprint(0);
	unsigned char buffer[bufferSize];
	int sendtoBytes;

	
	bzero(&sendDHCP,sizeof(sendDHCP));
	//itoa can change int to char[]
	sendDHCP.mtype = 0x01;
	sendDHCP.htype = 0x01;
	sendDHCP.hlen = 0x06;
	sendDHCP.hops = 0;
	sendDHCP.xid = htonl(0xbc1ae078);
	sendDHCP.secs = 0x0000;

	struct in_addr ciaddr_in;
	char* currentIP = (char *) malloc(sizeof(char)*20);		 strcpy(currentIP,getIP());
	inet_aton(currentIP,&ciaddr_in);
	memcpy(&sendDHCP.ciaddr,&ciaddr_in,sizeof(ciaddr_in)); 


	char chaddrBuffer[6] = {0x08,0x00,0x27,0xa9,0x67,0xa3};	
	memcpy(&sendDHCP.chaddr,&chaddrBuffer,sizeof(chaddrBuffer));
	
	uint32_t mcookieBuffer = htonl(0x63825363);
	memcpy(&(sendDHCP.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));
	
	char * p = &sendDHCP.options[0];
//option:53	
	char optionBuffer1 [3] = {0x35,0x01,0x07}; 
	
	memcpy(p,optionBuffer1,sizeof(optionBuffer1));	
	p+=sizeof(optionBuffer1);
	
	char optionBuffer2 [6] = {0x36,0x04,0x0a,0x00,0x02,0x02}; 
	memcpy(p,optionBuffer2,sizeof(optionBuffer2));	
	p+=sizeof(optionBuffer2);
	
	char optionBuffer3 [8] = {0x0c,0x06,0x42,0x55,0x50,0x54,0x49,0x41};
	memcpy(p,optionBuffer3,sizeof(optionBuffer3));	
	p+=sizeof(optionBuffer3);

	char optionBuffer5  = 0xff;
	memcpy(p,&optionBuffer5,sizeof(optionBuffer5));	
	p+=sizeof(optionBuffer5);
	
	memset(&buffer,0,bufferSize);
	memcpy(&buffer,&sendDHCP,sizeof(sendDHCP));


	
	clntAddr.sin_family = AF_INET;
	inet_aton(clntIP,&clntAddr.sin_addr);	

	clntAddr.sin_port = htons(clntPort);
	
	servAddr.sin_family = AF_INET;
	inet_aton("192.168.56.1",&servAddr.sin_addr);
	servAddr.sin_port = htons(servPort);
	
	int i;
	int sockRelease;
	struct ifreq if_eth1;
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);	

	if((sockRelease = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
		perror("Socket error\n");
	}

//set socket to inferface eth1	
	if(setsockopt(sockRelease,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
		perror("bind socket to eth1 error\n");
	}

	
	if((sendtoBytes = sendto(sockRelease,buffer,bufferSize,0,(struct sockaddr*) &servAddr, sizeof(servAddr))) != bufferSize){
			perror("sendto() failed Release\n");
	}else
		printf("DHCPRelease: sendtoBytes: %d\n",sendtoBytes);
	//close(sockRelease);	

}

int DHCPRequest(char * fromIP, char * toIP, char *requestIP){
	logprint(3);
	//flag 0 means broadcast
	//flag 1 means unicast
	int flag = 1;
	if(strcmp(fromIP,"0.0.0.0")==0){
		flag = 0;
	}
	
	struct sockaddr_in fromAddr;
	struct sockaddr_in toAddr;

	fromAddr.sin_family = AF_INET;
	inet_aton(fromIP,&fromAddr.sin_addr);
	fromAddr.sin_port = htons(clntPort);
	
	toAddr.sin_family = AF_INET;
	inet_aton(toIP,&toAddr.sin_addr);
	toAddr.sin_port = htons(servPort);
	
	int sendtoBytes;

	struct dhcp dhcpReq;
	bzero(&dhcpReq,sizeof(dhcpReq));
	
	dhcpReq.mtype = 0x01;
	dhcpReq.htype = 0x01;
	dhcpReq.hlen = 0x06;
	dhcpReq.hops = 0;
	memcpy(&dhcpReq.xid,&recvDHCP.xid,sizeof(&sendDHCP.xid));
	if(recvDHCP.xid==0)
		dhcpReq.xid = htonl(0xf4d83700);
	dhcpReq.secs = 0x0000;

	//dhcpReq.ciaddr
	if(flag == 1){
		struct in_addr ciaddr_in;
		inet_aton(fromIP, &ciaddr_in);
		memcpy(&dhcpReq.ciaddr,&ciaddr_in,sizeof(dhcpReq.ciaddr));
	}


	memcpy(&dhcpReq.chaddr,&recvDHCP.chaddr,sizeof(sendDHCP.chaddr));	
	uint32_t mcookieBuffer = htonl(0x63825363);
	memcpy(&(dhcpReq.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));
	
	char * p = &dhcpReq.options[0];
//option 53
	char optionBuffer1 [3] = {0x35,0x01,0x03};
	
	memcpy(p,optionBuffer1,sizeof(optionBuffer1));	
	p+=sizeof(optionBuffer1);
//option 54
//server identifier 
	char optionBuffer2 [6] = {0x36,0x04,0x0a,0x00,0x02,0x02};
	memcpy(p,optionBuffer2,sizeof(optionBuffer2));	
	p+=sizeof(optionBuffer2);
//option 50 requested ip address
	//header & length
	if(flag == 0){
		char optionBuffer31 [2] = {0x32,0x04};
		memcpy(p,optionBuffer31,sizeof(optionBuffer31));	
		p+=sizeof(optionBuffer31);
		//ip address
		memcpy(p,&recvDHCP.yiaddr,sizeof(recvDHCP.yiaddr));
		p+=sizeof(recvDHCP.yiaddr);
	}else{
		char * temp = (char *) malloc(sizeof(char)*20);
		strcpy(temp,requestIP);
		struct in_addr requestIPBuf;
		inet_aton(temp,&requestIPBuf);
	
		char optionBuffer31 [2] = {0x32,0x04};
		memcpy(p,optionBuffer31,sizeof(optionBuffer31));	
		p+=sizeof(optionBuffer31);
		//ip address
		memcpy(p,&requestIPBuf,sizeof(recvDHCP.yiaddr));
		p+=sizeof(recvDHCP.yiaddr);
	}

		
	
//option 12 host name
	char optionBuffer4 [8] = {0x0c,0x06,0x42,0x55,0x50,0x54,0x49,0x41};
	memcpy(p,optionBuffer4,sizeof(optionBuffer4));	
	p+=sizeof(optionBuffer4);

	char optionBuffer5 [15] = {0x37,0x0d,0x01,0x1c,0x02,0x03,0x0f,0x06,0x77,0x0c,0x2c,0x2f,0x1a,0x79,0x2a};
	memcpy(p,&optionBuffer5,sizeof(optionBuffer5));	
	p+=sizeof(optionBuffer5);
	
	char optionBuffer6  = 0xff;
	memcpy(p,&optionBuffer6,sizeof(optionBuffer6));	
	p+=sizeof(optionBuffer6);
	
	memset(&reqbuffer,0,bufferSize);
	memcpy(&reqbuffer,&dhcpReq,sizeof(dhcpReq));
if(flag ==1 ){
	//close(sockClient);
	int i = 0;
        int sockRequest;
        struct ifreq if_eth1;
        strcpy(if_eth1.ifr_name,"eth1");
        socklen_t len = sizeof(i);

        if((sockRequest = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
                perror("Socket error\n");
        }

//set socket to inferface eth1  
        if(setsockopt(sockRequest,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
                perror("bind socket to eth1 error\n");
        }
	
	if(setsockopt(sockRequest,SOL_SOCKET,SO_REUSEADDR|SO_BROADCAST,&i,len)<0){
                perror("allow broadcast failed\n");
        
	}

	// for dhcp

	if((sendtoBytes = sendto(sockRequest,reqbuffer,bufferSize,0,(struct sockaddr*) &toAddr, sizeof(toAddr))) != bufferSize){
			perror("sendto() failed Request\n");
	}else{
		printf("DHCPRequest sendtoBytes: %d",sendtoBytes);
	}
	//close(sockRequest);
//	init();
}else{
	if((sendtoBytes = sendto(sockClient,reqbuffer,bufferSize,0,(struct sockaddr*) &servAddr, sizeof(servAddr))) != bufferSize){
                        perror("sendto() failed Discover\n");
        }else
                printf("DHCPDiscover sendtoBytes: %d",sendtoBytes);

}
	return 0;
}

int getLeaseTime(int loc){
	char leaseTime[4] = {0};

	memcpy(&leaseTime[0],&recvDHCP.options[loc],4);
	int i = 0;
	char  hexBuffer[8] = {0};
        int hex[8];
	int testInt;
for(i = 0 ;i<4;i++){
        char s[2];
        sprintf(s,"%02X",(unsigned char)leaseTime[i]);

        strncat (hexBuffer,s,sizeof(s));
        testInt = strtol(hexBuffer,NULL,16);
}
	return testInt;

}
char *  getServIP(){
	char * servIP = (char *)malloc(sizeof(char)*17); 
	struct in_addr servIPBuffer;
	memcpy(&servIPBuffer,&recvDHCP.options[50],4);
	servIP = inet_ntoa(servIPBuffer);
	return servIP;
}
void *leaseThread(void *leaseTime){
	int l = lt;
	int i = 0;
	while(1){
		if(clockFlag ==0)
			break;
		sleep(1);
		printf("A %d\n",i);
		i++;
		if(i==l){
			break;
		}
	}
	if(clockFlag == 1){
		char* servIP = (char *) malloc(sizeof(char)*20);
		char* clntIP = (char *) malloc(sizeof(char)*20);
		strcpy(servIP,getServIP());
		strcpy(clntIP,getIP());
		DHCPRequest(clntIP,servIP,clntIP);
		pthread_t tid;
		int err;
		if((err = pthread_create(&tid,NULL,leaseThread1,NULL)!=0)){
			perror("Error thread\n");
				}	
	
	}
	return;

}

void * leaseThread1(void *leaseTime1){
	int l = 10-lt;
	int i = 0;
	while(1){
		if(clockFlag ==0)
			break;
		sleep(1);
		printf("B %d\n",i);
		i++;
		if(i==l){
			break;
		}
	}
	if(clockFlag == 1){
		clntAddr.sin_family = AF_INET;
		//clnt ip adress 0.0.0.0
		clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);
		clntAddr.sin_port = htons(clntPort);
	
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		servAddr.sin_port = htons(servPort);
		close(sockClient);
		initSocket();		
		DHCPDiscover();

	}
	return ;
}
int logprint(int flag){

	FILE *fp = fopen("log.log","a+");
	char *release = "DHCP RELEASE";
	char *discover = "DHCP DISCOVER";
	char *offer = "DHCP OFFER";
	char *request = "DHCP REQUEST";
	char *ack = "DHCP ACK";
	char *nak = "DHCP NAK";
	char *inform = "DHCP INFORM";
	if(flag==1){
		fprintf(fp,"%s\n",discover);
	}else if(flag==2){
		fprintf(fp,"%s\n",offer);
	}else if(flag==0){
		fprintf(fp,"%s\n",release);
	}else if(flag==3){
		fprintf(fp,"%s\n",request);
	}else if(flag==4){
		fprintf(fp,"%s\n",ack);
	}else if(flag==5){
		fprintf(fp,"%s\n",nak);
	}else if(flag==6){
		fprintf(fp,"%s\n",inform);
	}
	fclose(fp);
}

