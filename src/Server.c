#include<sys/socket.h>
#include<sys/ioctl.h>
#include<stdio.h>
#include<stdlib.h>
#include<net/if.h>
#include<string.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<netinet/in.h>
#define clntPort 68
#define servPort 67
#define optionLen 32
#define bufferSize 2048


struct dhcp sendOffer;
struct dhcp recvDHCP;
int sockServer;
int sockOffer;
struct in_addr allocIP;
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
        //  uint32_t  xid;
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
        //client hardware address find by ifconfig
        char chaddr[6];
        //Client hardware address padding
        char padding[10];
        //server host name(64)
        char p_sname[64];
        //boot file name
        char bp_file[128];
        //Magic cookie
	    char mcookie[4];
        //options
        char options[255];
};


char * dec2hex(int i);
int hex2dec(char * c);
struct in_addr * getavailableIP();
int judgeReply();
int judgeIP();
int delavailableIP(char * ip);
int DHCPNAK();
int DHCPRACK(int f);
int main(){
	init();
	char recvBuffer[bufferSize] = {0};
	struct sockaddr_in clntAddr;
	struct sockaddr_in servAddr;
	int recvfromBytes;
	//follow pdf
	memset(&servAddr,0,sizeof(servAddr));
	memset(&clntAddr,0,sizeof(clntAddr));
	//servAddr is to addr
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(servPort);
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	//broadcast addr from here
	clntAddr.sin_family = AF_INET;
	clntAddr.sin_port = htons(clntPort);
	//clntAddr.sin_addr.s_addr = inet_addr(broadcastIP);
	clntAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	int clntAddrLen = sizeof(clntAddr);
	
//allow a socket to broadcast and bind the socket to interface eth1

//bind socket
	if((bind(sockServer,(struct sockaddr * )&servAddr, sizeof(servAddr)))<0){
		perror("bind() \n");
		printf("bind() \n");
	}

    //	DHCPOffer(recvDHCP);
	for(;;){
	//init();
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(servPort);
	servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	//broadcast addr from here
	clntAddr.sin_family = AF_INET;
	clntAddr.sin_port = htons(clntPort);
	//clntAddr.sin_addr.s_addr = inet_addr(broadcastIP);
	clntAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	
        int clntAddrLen = sizeof(clntAddr);
		bzero(&recvBuffer,bufferSize);
		bzero(&recvDHCP,sizeof(recvDHCP));
		printf("\nstart recvfrom\n");
		//receive packet from client and wirte bytes into DHCP struct
		int servAddrLen=sizeof(clntAddr);
		recvfromBytes = recvfrom(sockServer,recvBuffer,bufferSize,0,(struct sockaddr *)&clntAddr,&clntAddrLen);
		if(recvfromBytes < 0 ){
			perror("recvfrom()");
		} else{
			
			memcpy(&recvDHCP,&recvBuffer,sizeof(recvDHCP));
			printf("recv Bytes: %d\n",recvfromBytes);
			recvBuffer[recvfromBytes] = '\0';
			int count;
			printf("htype: %X\n",recvDHCP.htype);
			char DiscoverOption[3] = {0x35,0x01,0x01};
			char ReleaseOption[3] = {0x35,0x01,0x07};
			char RequestOption[3] = {0x35,0x01,0x03};		
			char InformOption[3] = {0x35,0x01,0x08};
			char mtypeBuffer[3];
			memcpy(mtypeBuffer,recvDHCP.options,3);
			int mtypeCount = 0;
			for(mtypeCount = 0; mtypeCount<3;mtypeCount++){
				printf("mtype: %X",mtypeBuffer[mtypeCount]);
				printf("  compareType: %X\n",DiscoverOption[mtypeCount]);
			}
			if(memcmp(DiscoverOption,recvDHCP.options,3)==0){
				printf("DHCPDiscover Received \n");
				DHCPOffer();
			}else if (memcmp(ReleaseOption,recvDHCP.options,3)==0){
				printf("DHCPRelease Received\n");
				char *delIP;
				struct in_addr delIP_in;
				memcpy(&delIP_in,&recvDHCP.ciaddr,sizeof(recvDHCP.ciaddr));
				delIP = inet_ntoa(delIP_in);
				delavailableIP(delIP);
				
			}else if (memcmp(RequestOption, recvDHCP.options,3)==0){
				judgeReply();
			
				printf("DHCPRequest Received\n");
				
			}else if(memcmp(InformOption, recvDHCP.options,3)==0){
				DHCPRACK(1);
	
			}else{
				printf("No category\n");
			}
		
		}
	}		


}
int init(){

	
	if((sockServer = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
                perror("Socket error\n");
		printf("socket error\n");
        }
	
	int i = 1; 
	struct ifreq if_eth1;
	strcpy(if_eth1.ifr_name,"eth1");
	socklen_t len = sizeof(i);
	if(setsockopt(sockServer,SOL_SOCKET,SO_BROADCAST,&i,len)<0){
		perror("set boradcast error\n");
		printf("set broadcast err\n");
	}
	
	if(setsockopt(sockServer,SOL_SOCKET,SO_BINDTODEVICE,(char* )&if_eth1,sizeof(if_eth1))<0){
		perror("bind socket to eth1 error");
		printf("set to eth1 error");
	}

	sockOffer = sockServer;
	

}

int DHCPOffer(){
	struct dhcp dhcpDiscover = recvDHCP;
	unsigned char buffer[bufferSize];
        struct sockaddr_in clntAddr;
        struct sockaddr_in servAddr;
        int sendtoBytes;


        bzero(&sendOffer,sizeof(sendOffer));
        sendOffer.mtype = 0x01;
        sendOffer.htype = 0x01;
        sendOffer.hlen = 0x06;
        sendOffer.hops = 0;
	memcpy(&sendOffer.xid,&dhcpDiscover.xid,sizeof(sendOffer.xid));
        sendOffer.secs = 0x0000;

	
	struct in_addr * availableIP;
	availableIP = (struct in_addr*)malloc(sizeof(struct in_addr ));
	availableIP = (struct in_addr*)getavailableIP();
	memcpy(&allocIP,availableIP,sizeof(struct in_addr));
	
       	printf("alloc ip:%s",inet_ntoa(allocIP));
	

	memcpy(&sendOffer.yiaddr,&allocIP,sizeof(sendOffer.yiaddr));  
	    

        memcpy(&sendOffer.chaddr,&(dhcpDiscover.chaddr),sizeof(dhcpDiscover.chaddr));

        uint32_t mcookieBuffer = htonl(0x63825363);
        memcpy(&(sendOffer.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));

        char * p = &sendOffer.options[0];
//option:53
        char optionBuffer1 [3] = {0x35,0x01,0x02};
//memcpy(&(sendOffer.options),optionBuffer1,sizeof(optionBuffer1));      
        memcpy(p,optionBuffer1,sizeof(optionBuffer1));
        p+=sizeof(optionBuffer1);


        memset(p,0,6);

        p+=6;
//option:1
        char optionBuffer3 [6] = {0x01,0x04,0xff,0xff,0xff,0x00};
        memcpy(p,optionBuffer3,sizeof(optionBuffer3));
        p+=sizeof(optionBuffer3);
//option:3
        char optionBuffer4 [6] = {0x03,0x04,0x0a,0x00,0x02,0x02};
        memcpy(p,optionBuffer4,sizeof(optionBuffer4));
        p+=sizeof(optionBuffer4);
//option:6
        char optionBuffer5 [14] = {0x06,0x0c,0x0a,0x03,0x09,0x05,0x0a,0x03,0x09,0x04,0x0a,0x03,0x09,0x06};
        memcpy(p,&optionBuffer5,sizeof(optionBuffer5));
        p+=sizeof(optionBuffer5);
//option:15
        char optionBuffer6 [13] = {0x0f,0x0b,0x62,0x75,0x70,0x74,0x2e,0x65,0x64,0x75,0x2e,0x63,0x6e};
        memcpy(p,&optionBuffer6,sizeof(optionBuffer6));
        p+=sizeof(optionBuffer6);
//option:51
//lease time is here

        char optionBuffer7 [6] = {0x33,0x04,0x00,0x00,0x4e,0x20};
	memcpy(p,&optionBuffer7,sizeof(optionBuffer7));
        p+=sizeof(optionBuffer7);
//option:54

 	char optionBuffer8 [2] = {0x36,0x04};
        memcpy(p,&optionBuffer8,sizeof(optionBuffer8));
        p+=sizeof(optionBuffer8);
	char* ipIden = "192.168.56.1";
	struct in_addr ipIdenAdd  ;
	inet_aton(ipIden,&ipIdenAdd);
	memcpy(p,&ipIdenAdd,sizeof(ipIdenAdd));
	p+=sizeof(ipIdenAdd);

//255 END
	char optionBuffer9  = 0xff;
        memcpy(p,&optionBuffer9,sizeof(optionBuffer9));
        p+=sizeof(optionBuffer9);
 
        memset(&buffer,0,bufferSize);
        memcpy(&buffer,&sendOffer,sizeof(sendOffer));

        clntAddr.sin_family = AF_INET;
        //clnt ip adress 0.0.0.0
        clntAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        clntAddr.sin_port = htons(68);

        servAddr.sin_family = AF_INET;

         servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
         servAddr.sin_port = htons(67);

         if((sendtoBytes = sendto(sockOffer,buffer,bufferSize,0,(struct sockaddr*) &clntAddr, sizeof(clntAddr))) != bufferSize){
                        perror("sendto() failed Discover\n");
        }


}

int DHCPRACK(int flag){


	struct dhcp dhcpRequest = recvDHCP;
	unsigned char buffer[bufferSize];
        struct sockaddr_in clntAddr;
        struct sockaddr_in servAddr;
        int sendtoBytes;


        bzero(&sendOffer,sizeof(sendOffer));

        sendOffer.mtype = 0x02;
        sendOffer.htype = 0x01;
        sendOffer.hlen = 0x06;
        sendOffer.hops = 0;
	memcpy(&sendOffer.xid,&dhcpRequest.xid,sizeof(sendOffer.xid));

        sendOffer.secs = 0x0000;


	if(flag == 0 ){
		memcpy(&sendOffer.yiaddr,&allocIP,sizeof(sendOffer.yiaddr));  
	}else{
		memcpy(&sendOffer.yiaddr,&dhcpRequest.ciaddr,sizeof(sendOffer.yiaddr));
	} 

    
        memcpy(&sendOffer.chaddr,&(dhcpRequest.chaddr),sizeof(dhcpRequest.chaddr));

        uint32_t mcookieBuffer = htonl(0x63825363);
        memcpy(&(sendOffer.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));

        char * p = &sendOffer.options[0];
//option:53
        char optionBuffer1 [3] = {0x35,0x01,0x05};
//memcpy(&(sendOffer.options),optionBuffer1,sizeof(optionBuffer1));      
        memcpy(p,optionBuffer1,sizeof(optionBuffer1));
        p+=sizeof(optionBuffer1);
//option:58
        char optionBuffer58[6] = {0x3a,0x04,0x00,0x00,0x27,0x10};
        memcpy(p,&optionBuffer58,sizeof(optionBuffer58));
        p+=sizeof(optionBuffer58);
//option:59
        char optionBuffer59[6] = {0x3b,0x04,0x00,0x00,0x44,0x5c};
        memcpy(p,&optionBuffer59,sizeof(optionBuffer59));
        p+=sizeof(optionBuffer59);

//255 END
	char optionBuffer8  = 0xff;
        memcpy(p,&optionBuffer8,sizeof(optionBuffer8));
        p+=sizeof(optionBuffer8);
 
        memset(&buffer,0,bufferSize);
        memcpy(&buffer,&sendOffer,sizeof(sendOffer));
if(flag == 0){
        clntAddr.sin_family = AF_INET;
        //clnt ip adress 0.0.0.0

        clntAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        clntAddr.sin_port = htons(68);

        servAddr.sin_family = AF_INET;
 
         servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
         servAddr.sin_port = htons(67);

         if((sendtoBytes = sendto(sockOffer,buffer,bufferSize,0,(struct sockaddr*) &clntAddr, sizeof(clntAddr))) != bufferSize){
                        perror("sendto() failed Discover\n");
        }

}else{
	struct sockaddr_in fromAddr;
        struct sockaddr_in toAddr;

        fromAddr.sin_family = AF_INET;
     inet_aton("192.168.56.1",&fromAddr.sin_addr);
        fromAddr.sin_port = htons(servPort);

        toAddr.sin_family = AF_INET;
 	memcpy(&toAddr.sin_addr,&dhcpRequest.ciaddr,sizeof(dhcpRequest.ciaddr));
   	    toAddr.sin_port = htons(clntPort);
	
        int i = 0;
        int sockACK;
        struct ifreq if_eth1;
        strcpy(if_eth1.ifr_name,"eth1");
        socklen_t len = sizeof(i);

        if((sockACK = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
                perror("Socket error\n");
        }

//set socket to inferface eth1  
        if(setsockopt(sockACK,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
                perror("bind socket to eth1 error\n");
        }

        // hcp  l

        if((sendtoBytes = sendto(sockACK,buffer,bufferSize,0,(struct sockaddr*) &toAddr, sizeof(toAddr))) != bufferSize){
                        perror("sendto() failed ACK\n");
        }else{
                printf("DHCPACK sendtoBytes: %d",sendtoBytes);
        }

	}
}

int DHCPACK(int flag){


	struct dhcp dhcpRequest = recvDHCP;
	unsigned char buffer[bufferSize];
        struct sockaddr_in clntAddr;
        struct sockaddr_in servAddr;
        int sendtoBytes;


        bzero(&sendOffer,sizeof(sendOffer));
        //itoa can change int to char[]
        sendOffer.mtype = 0x02;
        sendOffer.htype = 0x01;
        sendOffer.hlen = 0x06;
        sendOffer.hops = 0;
	memcpy(&sendOffer.xid,&dhcpRequest.xid,sizeof(sendOffer.xid));

        sendOffer.secs = 0x0000;


	if(flag == 0 ){
		memcpy(&sendOffer.yiaddr,&allocIP,sizeof(sendOffer.yiaddr));  
	}else{
		memcpy(&sendOffer.yiaddr,&dhcpRequest.ciaddr,sizeof(sendOffer.yiaddr));

        memcpy(&sendOffer.chaddr,&(dhcpRequest.chaddr),sizeof(dhcpRequest.chaddr));

        uint32_t mcookieBuffer = htonl(0x63825363);
        memcpy(&(sendOffer.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));

        char * p = &sendOffer.options[0];
//option:53
        char optionBuffer1 [3] = {0x35,0x01,0x05};
     
        memcpy(p,optionBuffer1,sizeof(optionBuffer1));
        p+=sizeof(optionBuffer1);
//option:1
        char optionBuffer2 [6] = {0x01,0x04,0xff,0xff,0xff,0x00};
        memcpy(p,optionBuffer2,sizeof(optionBuffer2));  
   
        p+=sizeof(optionBuffer2);
  
//option:3
        char optionBuffer3 [6] = {0x03,0x04,0x0a,0x00,0x02,0x02};
        memcpy(p,optionBuffer3,sizeof(optionBuffer3));
        p+=sizeof(optionBuffer3);
//option:6
        char optionBuffer4 [14] = {0x06,0x0c,0x0a,0x03,0x09,0x05,0x0a,0x03,0x09,0x04,0x0a,0x03,0x09,0x06};
        memcpy(p,&optionBuffer4,sizeof(optionBuffer4));
        p+=sizeof(optionBuffer4);
//option:15
        char optionBuffer5 [13] = {0x0f,0x0b,0x62,0x75,0x70,0x74,0x2e,0x65,0x64,0x75,0x2e,0x63,0x6e};
        memcpy(p,&optionBuffer5,sizeof(optionBuffer5));
        p+=sizeof(optionBuffer5);
//option:51
//lease time is here
        char optionBuffer6 [6] = {0x33,0x04,0x00,0x00,0x4e,0x20};
	memcpy(p,&optionBuffer6,sizeof(optionBuffer6));
        p+=sizeof(optionBuffer6);
//option:54
	char optionBuffer7 [2] = {0x36,0x04};
        memcpy(p,&optionBuffer7,sizeof(optionBuffer7));
        p+=sizeof(optionBuffer7);
	char* ipIden = "192.168.56.1";
	struct in_addr ipIdenAdd  ;
	inet_aton(ipIden,&ipIdenAdd);
	memcpy(p,&ipIdenAdd,sizeof(ipIdenAdd));
	p+=sizeof(ipIdenAdd);
//255 END
	char optionBuffer8  = 0xff;
        memcpy(p,&optionBuffer8,sizeof(optionBuffer8));
        p+=sizeof(optionBuffer8);
 
        memset(&buffer,0,bufferSize);
        memcpy(&buffer,&sendOffer,sizeof(sendOffer));
if(flag == 0){
        clntAddr.sin_family = AF_INET;
        //clnt ip adress 0.0.0.0

        clntAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
        clntAddr.sin_port = htons(68);

        servAddr.sin_family = AF_INET;

         servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
         servAddr.sin_port = htons(67);

         if((sendtoBytes = sendto(sockOffer,buffer,bufferSize,0,(struct sockaddr*) &clntAddr, sizeof(clntAddr))) != bufferSize){
                        perror("sendto() failed Discover\n");
        }

}else{
	struct sockaddr_in fromAddr;
        struct sockaddr_in toAddr;

        fromAddr.sin_family = AF_INET;
     inet_aton("192.168.56.1",&fromAddr.sin_addr);
        fromAddr.sin_port = htons(servPort);

        toAddr.sin_family = AF_INET;
 	memcpy(&toAddr.sin_addr,&dhcpRequest.ciaddr,sizeof(dhcpRequest.ciaddr));
   	    toAddr.sin_port = htons(clntPort);
	
        int i = 0;
        int sockACK;
        struct ifreq if_eth1;
        strcpy(if_eth1.ifr_name,"eth1");
        socklen_t len = sizeof(i);

        if((sockACK = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
                perror("Socket error\n");
        }

//set socket to inferface eth1  
        if(setsockopt(sockACK,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
                perror("bind socket to eth1 error\n");
        }


        // dhcp  l

        if((sendtoBytes = sendto(sockACK,buffer,bufferSize,0,(struct sockaddr*) &toAddr, sizeof(toAddr))) != bufferSize){
                        perror("sendto() failed ACK\n");
        }else{
                printf("DHCPACK sendtoBytes: %d",sendtoBytes);
        }

	}
}
	
int DHCPNAK(){
	struct dhcp dhcpRequest = recvDHCP;
	unsigned char buffer[bufferSize];
        int sendtoBytes;

        //itoa can change int to char[]
        sendOffer.mtype = 0x02;
        sendOffer.htype = 0x01;
        sendOffer.hlen = 0x06;
        sendOffer.hops = 0;
	memcpy(&sendOffer.xid,&dhcpRequest.xid,sizeof(sendOffer.xid));

        sendOffer.secs = 0x0000;


        memcpy(&sendOffer.chaddr,&(dhcpRequest.chaddr),sizeof(dhcpRequest.chaddr));

        uint32_t mcookieBuffer = htonl(0x63825363);
        memcpy(&(sendOffer.mcookie),&mcookieBuffer,sizeof(mcookieBuffer));

        char * p = &sendOffer.options[0];
//option:53
        char optionBuffer1 [3] = {0x35,0x01,0x06};
        memcpy(p,optionBuffer1,sizeof(optionBuffer1));
        p+=sizeof(optionBuffer1);
//option:51
//lease time
        char optionBuffer6 [6] = {0x33,0x04,0x00,0x00,0x4e,0x20};
	memcpy(p,&optionBuffer6,sizeof(optionBuffer6));
        p+=sizeof(optionBuffer6);
//option:54
	char optionBuffer7 [2] = {0x36,0x04};
        memcpy(p,&optionBuffer7,sizeof(optionBuffer7));
        p+=sizeof(optionBuffer7);
	char* ipIden = "192.168.56.1";
	struct in_addr ipIdenAdd  ;
	inet_aton(ipIden,&ipIdenAdd);
	memcpy(p,&ipIdenAdd,sizeof(ipIdenAdd));
	p+=sizeof(ipIdenAdd);
//255 END
	char optionBuffer8  = 0xff;
        memcpy(p,&optionBuffer8,sizeof(optionBuffer8));
        p+=sizeof(optionBuffer8);
 
        memset(&buffer,0,bufferSize);
        memcpy(&buffer,&sendOffer,sizeof(sendOffer));

	struct sockaddr_in fromAddr;
        struct sockaddr_in toAddr;

        fromAddr.sin_family = AF_INET;
     inet_aton("192.168.56.1",&fromAddr.sin_addr);
        fromAddr.sin_port = htons(servPort);

        toAddr.sin_family = AF_INET;
 	memcpy(&toAddr.sin_addr,&dhcpRequest.ciaddr,sizeof(dhcpRequest.ciaddr));
   	    toAddr.sin_port = htons(clntPort);
	
        int i = 0;
        int sockNAK;
        struct ifreq if_eth1;
        strcpy(if_eth1.ifr_name,"eth1");
        socklen_t len = sizeof(i);

        if((sockNAK = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP))<0){
                perror("Socket error\n");
        }

//set socket to inferface eth1  
        if(setsockopt(sockNAK,SOL_SOCKET,SO_BINDTODEVICE,(char *)&if_eth1,sizeof(if_eth1))<0){
                perror("bind socket to eth1 error\n");
        }


        // dhcp  l

        if((sendtoBytes = sendto(sockNAK,buffer,bufferSize,0,(struct sockaddr*) &toAddr, sizeof(toAddr))) != bufferSize){
                        perror("sendto() failed ACK\n");
        }else{
                printf("DHCPACK sendtoBytes: %d",sendtoBytes);
        }
    
}
	
struct in_addr* getavailableIP(){
	char lineBuffer[20][100];
        char * buffer2;
        buffer2 = (char *)malloc(20);
        //set address struct
        struct in_addr dynamicAddr;

        //open file
        FILE *fp = fopen("ipbase.txt","r+");
        FILE *fp2 = fopen("ipused.txt","a");
        //set line count
        int i = 0;
        while((fgets(lineBuffer[i],20,fp)!=NULL)){
                if(i==0){
                        //read the first line as ip address
                        buffer2 = lineBuffer[0];
                        //write the ip into ipused.txt
                        fprintf(fp2,"%s",buffer2);
                   //     printf("*************************");
                        i++;
                        continue;
                }else{

                        i++;
                }
        }
        fclose(fp);
        fclose(fp2);
	FILE *fp_new = fopen("ipbase.txt","w");
        int j;
        //update ipbase file without first line
        for(j=1;j<i;j++){
                fprintf(fp_new,"%s",lineBuffer[j]);
        }
        fclose(fp_new);

        //convert to ip format
        dynamicAddr.s_addr = inet_addr(buffer2);

	
	struct in_addr * p = &dynamicAddr;
	return p;
}
	
int delavailableIP(char * delIP){
        //open file
	int flag = 1;
        FILE *fp = fopen("ipbase.txt","a");
       
	FILE *fp2 = fopen("ipused.txt","w");
	fclose(fp2);
	
	flag = fprintf(fp,"%s\n",delIP);
	fclose(fp);

	return flag;
}

int judgeReply(){
	struct dhcp dhcpReply = recvDHCP;	
	
	struct in_addr recvciaddrBuffer;
	memcpy(&recvciaddrBuffer,&dhcpReply.ciaddr,sizeof(dhcpReply.ciaddr));
	char * recvciaddr = inet_ntoa(recvciaddrBuffer);
	if(strcmp(recvciaddr,"0.0.0.0")==0){
		printf("this is a init process\n");
		DHCPACK(0);
	}else{
	//renew
		struct in_addr requestedIP_in;
		memcpy(&requestedIP_in,&dhcpReply.options[11],4);
		char *requestedIPBuffer = (char* )malloc(sizeof(char)*20);
		requestedIPBuffer =  inet_ntoa(requestedIP_in);
		printf("requestedIPBuffer%s\n",requestedIPBuffer);
		int judgeflag = judgeIP(requestedIPBuffer);
		printf("JUDGE FLAG %d\n",judgeflag) ;
	//unicast
		if(judgeflag == 1){
			DHCPACK(1);
		}else if(judgeflag == 2){
			DHCPACK(1);
		}else if(judgeflag == 3){
			DHCPNAK();
		}
	} 

}
char * dec2hex(int dec){

	char *s;
	sprintf(s, "%x",dec); 
   	printf("dec2hex %s\n", s);


	return s;
}
int hex2dec(char * str){
  
    int i = 0;
    sscanf(str, "%x", &i);
    printf("hex2dec %d\n", i);

    return i;
}
int judgeIP(char * ip){
	
	char *end = "\n";

	char lineBuffer[20][100];
	char usedBuffer[20];
	char baseBuffer[20];
	
	char * buffer2;
	buffer2 = (char *)malloc(20);
	int allFlag =3;
	//set address struct
	struct in_addr dynamicAddr;
	//open file
	FILE *fp = fopen("ipbase.txt","r+");
	FILE *fp2 = fopen("ipused.txt","a+");
	//set line count
	int i = 0;
	int flag_used = 1;
	int flag_base = 1;
	int count = 0;
	printf("request ip %s",ip);
	while((fgets(usedBuffer,20,fp2)!=NULL)){
		if(usedBuffer[strlen(usedBuffer)-1]=='\n'){
			usedBuffer[strlen(usedBuffer)-1]='\0';
		}
		if(strcmp(ip,usedBuffer)==0){
			printf("match in used\n");
			flag_used = strcmp(ip,usedBuffer);
		}
	
		count++;
	}
	count = 0;
	while((fgets(baseBuffer,20,fp)!=NULL)){
		if(baseBuffer[strlen(baseBuffer)-1]=='\n'){
			baseBuffer[strlen(baseBuffer)-1]='\0';
		}
		if(strcmp(ip,baseBuffer)==0){

			flag_base = strcmp(ip,baseBuffer);	
		}
		
		count++;
	}
	
	//check the purpose
	if((flag_used==0)&&(flag_base!=0)){
		
		allFlag = 1;
	}else if((flag_used!=0)&&(flag_base==0)){
		//request a new ip, response ACK
		allFlag = 2;
	}else if((flag_used!=0)&&(flag_base!=0)){
		//invalid address, response NAK
		allFlag = 3;
	}
	printf("all flag:%d",allFlag);
	printf("----------");
	fclose(fp);
	//if it request a new ip
	FILE *fp3 = fopen("ipbase.txt","rw");
	if(allFlag==2){
		while((fgets(lineBuffer[i],20,fp3)!=NULL)){
			if(i==0){
				//read the first line as ip address
				buffer2 = lineBuffer[0];	
				//write the ip into ipused.txt
				fprintf(fp2,"%s",buffer2);
				printf("the first line: %s",buffer2);
				i++;
				continue;
			}else{
				printf("this is all:%s",lineBuffer[i]);
				i++;
			}
		}
		fclose(fp3);
		fclose(fp2);
		FILE *fp_new = fopen("ipbase.txt","w");
		int j;
		//update ipbase file without first line
		for(j=1;j<i;j++){
			fprintf(fp_new,"%s",lineBuffer[j]);
		}
		fclose(fp_new);
		printf("buffer ip:%s",buffer2);
		//convert to ip format
		dynamicAddr.s_addr = inet_addr(buffer2);
		printf("this is ip:%s",inet_ntoa(dynamicAddr));
	
	
	}
	return allFlag;
}
