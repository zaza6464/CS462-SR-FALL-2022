/* CS-462 Project : Implementation of Sliding Windows Protocol for efficient file transfer. */
/* */
/* Starting with a minimal server shell in the internet domain (https://www.linuxhowtos.org/C_C++/socket.htm) */
/* */
/* This is the SERVER (which receives the packets and sends an acknowledgement  based on 3 protocols). */
/* */
/* Complile with this command: g++ -o server.out server.cpp common.cpp -std=c++11 */
/* */
/* Filename : server.cpp */
/* Team :  */
/* */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <fstream>
#include "common.h"
#include "packet_struct.h"


int sock;
int length;
int numCharsReceived;
int numSent;
int packets_received = 0;
int crcError = 0;
int numChecksumFailed = 0;
int numOutOfSequence = 0;
int numOriginalPackets = 0;
int rangeOfSequenceNumbers = 100; //ex. (sliding window size = 3) [1, 2, 3] -> [2, 3, 4] -> [3, 4, 5], range = 5
int situationalErrors = 0; //none (0), randomly generated (1), or user-specified (2)
std::string ipAddress = "172.23.0.11"; //IP address of the target server
int protocolType = 1; //0 for S&W, 1 for GBN, 2 for SR
std::string filePath = "temp"; //path to file to be sent
int slidingWindowSize = 1; //ex. [1, 2, 3, 4, 5, 6, 7, 8], size = 8
int done = 0;
int full_packet_size = 0;
uint16_t sequenceNum = 0;
uint16_t lastAckedSeqNum;
uint16_t receivedSeqNum;
char response_buff[MAX_BUF_SIZE];

    
std::ofstream fileOutputStream;
std::ofstream logFile;

socklen_t fromlen;
struct sockaddr_in server;
struct sockaddr_in from;

char buffer[MAX_BUF_SIZE];
int portNum = 6789; //port number of the target server

void executeGBNProtocol(void);
void executeSRProtocol(void);
void doDoneStuff(void);

int main(int argc, char *argv[]) {

    ipAddress = ipAddressPrompt();
    portNum = portNumPrompt();
    protocolType = protocolTypePrompt();
    filePath = filePathPrompt();
    if (protocolType != 0) {
        slidingWindowSize = slidingWindowSizePrompt();
    } else {
        slidingWindowSize = 1;
    }
    
    rangeOfSequenceNumbers = rangeOfSequenceNumbersPrompt(slidingWindowSize);

	situationalErrors = situationalErrorsPrompt();
    
    //create a stream to the log file
    logFile.open("output/server_log.log", std::ios_base::in | std::ios_base::app);
    if (!logFile.is_open()) {
        error_and_exit(logFile, "Log file not opened successfully!!");
    }

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) error_and_exit(logFile, "Opening socket error");
    length = sizeof(server);
    bzero(&server, length);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(portNum);

    if (bind(sock, (struct sockaddr *) &server, length) < 0)
        error_and_exit(logFile, "Binding socket error");
    fromlen = sizeof(struct sockaddr_in);

    fileOutputStream.open(filePath, std::ios_base::out | std::ios_base::app);
    if (!fileOutputStream.is_open()) {
        error_and_exit(logFile, "Write file not opened successfully!!");
    }


    displayMessage(std::cout, logFile, "******************** START OF NEW TEST ********************");
    if (protocolType == 0) {
        displayMessage(std::cout, logFile, "Protocol Type: Stop and Wait");
    } else if (protocolType == 1) {
        displayMessage(std::cout, logFile, "Protocol Type: Go-Back-N");
    } else if (protocolType == 2) {
        displayMessage(std::cout, logFile, "Protocol Type: Selective Repeat");
    }
    displayIntDataMessage(std::cout, logFile, "Range of Sequence Numbers: ", rangeOfSequenceNumbers, "");
    displayIntDataMessage(std::cout, logFile, "Window Size: ", slidingWindowSize, "");
    if (situationalErrors == 0) {
        displayMessage(std::cout, logFile, "Situational Errors: None");
    } else if (situationalErrors == 1) {
        displayMessage(std::cout, logFile, "Situational Errors: Randomly Generated");
    } else if (situationalErrors == 2) {
        displayMessage(std::cout, logFile, "Situational Errors: User Generated");
    }
    std::cout << std::endl;

    while (!done) {
		
		switch (protocolType) {
			case 0:
			case 1:
				executeGBNProtocol();
				break;
			case 2:
				executeSRProtocol();
				break;
			default:
				error_and_exit(logFile, "Exit, Invalid protocol type!");
				break;
		}
    }
    return 0;
}


void executeGBNProtocol(void)
{
	printWindow(std::cout, logFile, slidingWindowSize, sequenceNum, rangeOfSequenceNumbers);
	numCharsReceived = recvfrom(sock, buffer, MAX_BUF_SIZE, 0, (struct sockaddr *) &from, &fromlen);
	packets_received++;
	uint16_t tempSeqNum = MakeINT16(buffer);


	if (numCharsReceived < 0) {
		error_and_exit(logFile, "recvfrom Error");
	} else if (numCharsReceived > 0) {

		if (packets_received == 1) {
			full_packet_size = numCharsReceived;
		}

		//This is a special thing to know we are done so server doesn't hang
		if (tempSeqNum == 30000) {
			// fileOutputStream.close();
			// error_and_exit(logFile, "Test Completion");
			doDoneStuff();
			return;
		} else
		{
			receivedSeqNum = tempSeqNum;
		}


		displayIntDataMessage(std::cout, logFile, "Packet ", receivedSeqNum, " received");
		displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], numCharsReceived - WRAPPER_SIZE);


		//First we need to verify the checksum
		//calculating and adding crc checksum
		uint16_t calc_CRC = crc16((uint8_t *) buffer, numCharsReceived - START_DATA_INDEX);
		uint16_t rec_CRC = MakeINT16(&buffer[numCharsReceived - START_DATA_INDEX]);
		if (calc_CRC == rec_CRC) {
			displayMessage(std::cout, logFile, "Checksum OK");
			crcError = 0;
		} else {
			displayMessage(std::cout, logFile, "Checksum failed");
			crcError = 1;
			numChecksumFailed++;
		}
	}


	if (!crcError) {
		if (receivedSeqNum == sequenceNum) {
			//this is if we got the expected sequence number in order
			//we will write and ack

			//10% the ack won't be sent
//                if (situationalErrors == 1 && !(numOriginalPackets % 10)) {
			BreakINT16(response_buff, receivedSeqNum);
			response_buff[START_DATA_INDEX] = (char) ACK;
			numSent = sendto(sock, response_buff, START_DATA_INDEX + 1,
							 0, (struct sockaddr *) &from, fromlen);
			if (numSent < 0) {
				error_and_exit(logFile, "sendto Error");
			}
//                }
			fileOutputStream.write(&buffer[START_DATA_INDEX], numCharsReceived - WRAPPER_SIZE);
			
			// std::cout << "WRITING TO FILE. receivedSeqNum: ";
			// std::cout << receivedSeqNum;
			// std::cout << std::endl;
		
			lastAckedSeqNum = sequenceNum;
			numOriginalPackets++;
			sequenceNum++;
			sequenceNum = sequenceNum % rangeOfSequenceNumbers;
			displayIntDataMessage(std::cout, logFile, "Ack ", receivedSeqNum, " sent");
			std::cout << std::endl;
		} else if (receivedSeqNum < sequenceNum) {
			//this is if we already acked and saved this packet
			//we will ack it again and not save
			/*
			BreakINT16(response_buff, lastAckedSeqNum);
			response_buff[START_DATA_INDEX] = (char) ACK;
			numSent = sendto(sock, response_buff, START_DATA_INDEX + 1,
							 0, (struct sockaddr *) &from, fromlen);
			if (numSent < 0) {
				error_and_exit(logFile, "sendto Error");
			}
			displayIntDataMessage(std::cout, logFile, "Ack ", lastAckedSeqNum , " sent");
			std::cout << std::endl;
			*/
			numOutOfSequence++;
		} else if (receivedSeqNum > sequenceNum && sequenceNum > 0) {
//                //we can't accept this packet because a previous packet hasn't came yet
//                //for stop and wait we need to send an acknowledgement for the last packet we saved
//                BreakINT16(response_buff, sequenceNum - 1);
//                response_buff[START_DATA_INDEX] = (char) ACK;
//                numSent = sendto(sock, response_buff, START_DATA_INDEX + 1,
//                                 0, (struct sockaddr *) &from, fromlen);
//                if (numSent < 0) {
//                    error_and_exit(logFile, "sendto");
//                }
//                std::cout << "Ack ";
//                std::cout << sequenceNum - 1;
//                std::cout << " sent" << std::endl;
			numOutOfSequence++;
		}

		if (numCharsReceived > 0 && numCharsReceived != full_packet_size) {
			// doDoneStuff();
		}
	}
}

void executeSRProtocol(void)
{
	executeGBNProtocol();
}

void doDoneStuff(void)
{
	displayIntDataMessage(std::cout, logFile, "Last packet seq# received:", receivedSeqNum, "");
	std::cout << std::endl;
	displayIntDataMessage(std::cout, logFile, "Number of original packets received:   ", numOriginalPackets, "");
	std::cout << std::endl;
	displayIntDataMessage(std::cout, logFile, "Number of retransmitted packets received: ", numOutOfSequence, "");
	std::cout << std::endl;
	
	displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    

//                std::cout << "number of checksums that failed: ";
//                std::cout << numChecksumFailed << std::endl;
//                std::cout << "total packets received: ";
//                std::cout << packets_received << std::endl;
//                std::cout << "total out of sequence: ";
//                std::cout << numOutOfSequence << std::endl;

	fileOutputStream.close();
	done = 1;
}
