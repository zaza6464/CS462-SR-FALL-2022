
/* */
/* Filename : Kamke_Kranich_Mahan_client.h */
/* Team :  */
/* */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <string>

void executeSAWProtocol(void);
void executeGBNProtocol(void);
void executeSRProtocol(void);

void generateRandomSituationalErrors(char* buff, uint16_t seq, int bsRead);
	
void setMarkForRetransmit(uint16_t seq, int numPackets);		
void doDoneStuff();
void readPacketsFromFile(int);
void sendPackets(int, uint16_t startSN);
int getPacketIndexBySN(uint16_t);
void slideWindow(int, uint16_t);
int isInSlidingWindow(uint16_t, uint16_t);

void DisplayPacketSendMess(int packetNum);
void DisplayPacketRetransMess(int packetNum);
void DisplayAckReceived(int packetNum);
void DisplayNakReceived(int packetNum);
void DisplayPacketTimedout(int packetNum);
void setMarkForRetransmit(uint16_t seq);

