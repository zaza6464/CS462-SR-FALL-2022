
/* */
/* Filename : client.h */
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
void setSinglePacketForRetransmit(uint16_t seq);
void checkAllPacketsForTimeout();
void doDoneStuff();
void readPacketsFromFile(int);
bool sendPackets(int, uint16_t startSN);
int getPacketIndexBySN(uint16_t);
void slideWindow(int, uint16_t);
void printQueue(std::ostream &console, std::ostream &log, int slidingWS, int seq, int rangeOfSeqNum);

void DisplayPacketSendMess(int packetNum);
void DisplayPacketRetransMess(int packetNum);
void DisplayAckReceived(int packetNum);
void DisplayNakReceived(int packetNum);
void DisplayPacketTimedout(int packetNum);
void setMarkForRetransmit(uint16_t seq);

