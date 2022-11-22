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
int connsock;
int length;
int numCharsReceived;
int numSent;
int packets_received = 0;
int crcError = 0;
int numChecksumFailed = 0;
int numOutOfSequence = 0;
int numOriginalPackets = 0;
int rangeOfSequenceNumbers = 1000; //ex. (sliding window size = 3) [1, 2, 3] -> [2, 3, 4] -> [3, 4, 5], range = 5
int situationalErrors = 0; //none (0), randomly generated (1), or user-specified (2)
int noAckPackets[MAX_USER_ENTERED_PACKETS];
int iNumNoAckPackets = 0;
// std::string ipAddress = "172.23.0.2"; //IP address of the target server
std::string ipAddress = "172.23.0.2";  // "172.23.0.2"; //IP address of the target server
int protocolType = 0; //0 for S&W, 1 for GBN, 2 for SR
std::string filePath = "test"; //path to file to be sent
int slidingWindowSize = 5; //ex. [1, 2, 3, 4, 5, 6, 7, 8], size = 8
int done = 0;
int packetSize = 100; //specified size of packets to be sent
int full_packet_size = 0;
int bytes_to_read = 0;
uint16_t sequenceNum = 0;
uint16_t lastAckedSeqNum;
uint16_t receivedSeqNum;
uint16_t baseSeqNum = 0; //This is the sequence number at the start of the window
char response_buff[MAX_BUF_SIZE];

packetClass packets[MAX_WINDOW_SIZE];


std::ofstream fileOutputStream;
std::ofstream logFile;

socklen_t fromlen;
struct sockaddr_in server;
struct sockaddr_in from;

char buffer[MAX_BUF_SIZE];
char readBuffer[MAX_BUF_SIZE];
int portNum = 6789; //port number of the target server

void executeGBNProtocol(void);

void executeSRProtocol(void);

void sendAck(int seqNum);

void sendNak(int seqNum);

void doDoneStuff(void);

void writeToFile(int seq, char *buff, int charsToWrite);

void incrementSequenceNum(void);

void printQueue(std::ostream &console, std::ostream &log, int slidingWS, int seq, int rangeOfSeqNum);

int main(int argc, char *argv[]) {

    // create the CRC lookup table so we can use it later.
    crcTableInit();

    for (int i = 0; i < slidingWindowSize; i++) {
        packets[i].freeUp();
    }
    //ipAddress = ipAddressPrompt(ipAddress);
    //portNum = portNumPrompt(portNum);
    packetSize = packetSizePrompt(packetSize);
    bytes_to_read = packetSize + WRAPPER_SIZE;
    
    protocolType = protocolTypePrompt(protocolType);
    if (protocolType != 0) {
        slidingWindowSize = slidingWindowSizePrompt(slidingWindowSize);
    } else {
        slidingWindowSize = 1;
    }

    //rangeOfSequenceNumbers = rangeOfSequenceNumbersPrompt(slidingWindowSize);

    situationalErrors = situationalErrorsPrompt(situationalErrors);

    if (situationalErrors == 2) {
        iNumNoAckPackets = dropAcksPrompt(&noAckPackets[0]);
    }

    filePath = filePathPrompt(filePath);

    //create a stream to the log file
    logFile.open("output/server_log.log", std::ios_base::in | std::ios_base::app);
    if (!logFile.is_open()) {
        error_and_exit(logFile, "Log file not opened successfully!!");
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


    //sock = socket(AF_INET, SOCK_DGRAM, 0);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_and_exit(logFile, "Opening socket error");
    length = sizeof(server);
    bzero(&server, length);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(portNum);

    if (bind(sock, (struct sockaddr *) &server, length) < 0)
        error_and_exit(logFile, "Binding socket error");
    if (DEBUGEVERYTHINGELSE) std::cout << "past bind";
    if ((listen(sock, 5)) != 0) {
        error_and_exit(logFile, "Listening failed, exiting server");
    }
    if (DEBUGEVERYTHINGELSE) std::cout << "past listen";
    fromlen = sizeof(struct sockaddr_in);

    connsock = accept(sock, (struct sockaddr *) &from, &fromlen);
    if (DEBUGEVERYTHINGELSE) std::cout << "past accept";
    if (connsock < 0) {
        error_and_exit(logFile, "Accept failed, exiting server");
    }

    fileOutputStream.open(filePath, std::ios_base::out | std::ios_base::app);
    if (!fileOutputStream.is_open()) {
        error_and_exit(logFile, "Write file not opened successfully!!");
    }


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
    close(connsock);
    close(sock);
    return 0;
}


void executeGBNProtocol(void) {

//    printWindow(std::cout, logFile, slidingWindowSize, sequenceNum, rangeOfSequenceNumbers);
//    numCharsReceived = recvfrom(connsock, readBuffer, packetSize + WRAPPER_SIZE, 0, (struct sockaddr *) &from, &fromlen);
//    memcpy(buffer, readBuffer, numCharsReceived);
//    //numCharsReceived = read(connsock, buffer, MAX_BUF_SIZE);
//
//    if(numCharsReceived <= 0){
//        error_and_exit(logFile, "Read error, exiting server");
//    }
//    packets_received++;
//    uint16_t tempSeqNum = MakeINT16(buffer);
//
//
//    if (numCharsReceived < 0) {
//        error_and_exit(logFile, "recvfrom Error");
//    } else if (numCharsReceived > 0) {
//
//        if (packets_received == 1) {
//            full_packet_size = numCharsReceived;
//        }
//
//        //This is a special thing to know we are done so server doesn't hang
//        if (tempSeqNum == 30000) {
//            // fileOutputStream.close();
//            // error_and_exit(logFile, "Test Completion");
//            doDoneStuff();
//            return;
//        } else {
//            receivedSeqNum = tempSeqNum;
//        }
//
//
//        displayIntDataMessage(std::cout, logFile, "Packet ", receivedSeqNum, " received");
//        displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], numCharsReceived - WRAPPER_SIZE);
//
//
//        //First we need to verify the checksum
//        //calculating and adding crc checksum
//        // MAKE SURE THIS WORKS **********************************
//        crc rec_CRC = MakeINT32(&buffer[numCharsReceived - CRCBYTES]);
//        if (DEBUGCRC) {
//            std::cout << "in server crc received is: " << rec_CRC << std::endl;
//            char myBuff[5];
//            BreakINT32(&myBuff[0], rec_CRC);
//            for (int i = 0; i < 4; i++) {
//                std::cout << "in server crc received as bytes: " << int(myBuff[i]) << std::endl;
//            }
//        }
//        crc calc_CRC = crcFun((uint8_t *) buffer, numCharsReceived - CRCBYTES);
//        //displayIntDataMessage(std::cout, logFile, "Calculated CRC: ", calc_CRC, "");
//        //displayIntDataMessage(std::cout, logFile, "Sent CRC: ", rec_CRC, "");
//        if (calc_CRC == rec_CRC) {
//            displayMessage(std::cout, logFile, "Checksum OK");
//            crcError = 0;
//        } else {
//            //displayMessage(std::cout, logFile,"Checksum failed. Bytes read: ");
//            displayIntDataMessage(std::cout, logFile, "Checksum failed. Bytes read: ", numCharsReceived, "");
//            //crcTableInit();
//
//            crcError = 1;
//            numChecksumFailed++;
//        }
//    }
//
//
//    if (!crcError) {
//        if (receivedSeqNum == sequenceNum) {
//            //this is if we got the expected sequence number in order
//            //we will write and ack
//
//            //10% the ack won't be sent
////                if (situationalErrors == 1 && !(numOriginalPackets % 10)) {
//            BreakINT16(response_buff, receivedSeqNum);
//            response_buff[START_DATA_INDEX] = (char) ACK;
//            numSent = sendto(connsock, response_buff, START_DATA_INDEX + 1,
//                             0, (struct sockaddr *) &from, fromlen);
//            if (numSent < 0) {
//                error_and_exit(logFile, "sendto Error");
//            }
////                }
//            fileOutputStream.write(&buffer[START_DATA_INDEX], numCharsReceived - WRAPPER_SIZE);
//
//            // std::cout << "WRITING TO FILE. receivedSeqNum: ";
//            // std::cout << receivedSeqNum;
//            // std::cout << std::endl;
//
//            lastAckedSeqNum = sequenceNum;
//            numOriginalPackets++;
//            sequenceNum++;
//            sequenceNum = sequenceNum % rangeOfSequenceNumbers;
//            displayIntDataMessage(std::cout, logFile, "Ack ", receivedSeqNum, " sent");
//            std::cout << std::endl;
//        } else if (receivedSeqNum < sequenceNum) {
//            //this is if we already acked and saved this packet
//            //we will ack it again and not save
//            /*
//            BreakINT16(response_buff, lastAckedSeqNum);
//            response_buff[START_DATA_INDEX] = (char) ACK;
//            numSent = sendto(sock, response_buff, START_DATA_INDEX + 1,
//                             0, (struct sockaddr *) &from, fromlen);
//            if (numSent < 0) {
//                error_and_exit(logFile, "sendto Error");
//            }
//            displayIntDataMessage(std::cout, logFile, "Ack ", lastAckedSeqNum , " sent");
//            std::cout << std::endl;
//            */
//            numOutOfSequence++;
//        } else if (receivedSeqNum > sequenceNum && sequenceNum > 0) {
////                //we can't accept this packet because a previous packet hasn't came yet
////                //for stop and wait we need to send an acknowledgement for the last packet we saved
////                BreakINT16(response_buff, sequenceNum - 1);
////                response_buff[START_DATA_INDEX] = (char) ACK;
////                numSent = sendto(sock, response_buff, START_DATA_INDEX + 1,
////                                 0, (struct sockaddr *) &from, fromlen);
////                if (numSent < 0) {
////                    error_and_exit(logFile, "sendto");
////                }
////                std::cout << "Ack ";
////                std::cout << sequenceNum - 1;
////                std::cout << " sent" << std::endl;
//            numOutOfSequence++;
//        }
//
//        if (numCharsReceived > 0 && numCharsReceived != full_packet_size) {
//            // doDoneStuff();
//        }
//    }
}

void executeSRProtocol(void) {
	
    printWindow(std::cout, logFile, slidingWindowSize, baseSeqNum, rangeOfSequenceNumbers);
    if (DEBUGEVERYTHINGELSE) printQueue(std::cout, logFile, slidingWindowSize, baseSeqNum, rangeOfSequenceNumbers);
    
    numCharsReceived = recvfrom(connsock, readBuffer, bytes_to_read, 0, (struct sockaddr *) &from,
                                &fromlen);
    memcpy(buffer, readBuffer, numCharsReceived);

    if (DEBUGEVERYTHINGELSE) std::cout << "bytes received: " << numCharsReceived << std::endl;
    //numCharsReceived = read(connsock, buffer, MAX_BUF_SIZE);
    if (numCharsReceived <= 0) {
        error_and_exit(logFile, "Read error, exiting server");
    }
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
            //we no longer want to count this as a packet received, for stats reasons
            packets_received--;
            // fileOutputStream.close();
            // error_and_exit(logFile, "Test Completion");
            doDoneStuff();
            return;
        } else {
            receivedSeqNum = tempSeqNum;
        }


        displayIntDataMessage(std::cout, logFile, "Packet ", receivedSeqNum, " received");
        displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], numCharsReceived - WRAPPER_SIZE);


        //First we need to verify the checksum
        //calculating and adding crc checksum
        // MAKE SURE THIS WORKS **********************************
        crc rec_CRC = MakeINT32(&buffer[numCharsReceived - CRCBYTES]);
        if (DEBUGCRC) {
            std::cout << "in server crc received is: " << rec_CRC << std::endl;
            char myBuff[5];
            BreakINT32(&myBuff[0], rec_CRC);
            for (int i = 0; i < 4; i++) {
                std::cout << "in server crc received as bytes: " << int(myBuff[i]) << std::endl;
            }
        }
        crc calc_CRC = crcFun((uint8_t *) buffer, numCharsReceived - CRCBYTES);
        //displayIntDataMessage(std::cout, logFile, "Calculated CRC: ", calc_CRC, "");
        //displayIntDataMessage(std::cout, logFile, "Sent CRC: ", rec_CRC, "");
        if (calc_CRC == rec_CRC) {
            displayMessage(std::cout, logFile, "Checksum OK");
            crcError = 0;
        } else {
            //displayMessage(std::cout, logFile,"Checksum failed. Bytes read: ");
            displayIntDataMessage(std::cout, logFile, "Checksum failed. Bytes read: ", numCharsReceived, "");
            //crcTableInit();

            crcError = 1;
        }
    }


    if (!crcError) {
		// reset this because we know we aren't getting parts of a packet.
		bytes_to_read = packetSize + WRAPPER_SIZE;
		
        int slideFactor = isInSlidingWindow(baseSeqNum, receivedSeqNum, slidingWindowSize, rangeOfSequenceNumbers);
        if (slideFactor > 0) {
            if (DEBUGEVERYTHINGELSE) std::cout << "Slidefactor: " << slideFactor << std::endl;
            if (receivedSeqNum == baseSeqNum) {
                //this is if we got the expected sequence number in order
                //we will write and ack
				
				bool dropAck = false;
                if (situationalErrors == 2) {
                    for (int i = 0; i < iNumNoAckPackets; i++) {
                        if (DEBUGEVERYTHINGELSE) std::cout << noAckPackets[i] << std::endl;
                        if (DEBUGEVERYTHINGELSE) std::cout << packets_received << std::endl;
                        if (noAckPackets[i] == packets_received) {
                            dropAck = true;
							break;
                        }
                    }
                } 
                
                
				// 5% the ack won't be sent if random, or user specified this packet #
				if (((situationalErrors == 1) && !((packets_received + rand() % 10 + 1) % 20)) || dropAck) {
					if (DEBUGEVERYTHINGELSE) std::cout << "Intentionally not sending ack packet (packets_received = " << packets_received << ")" << std::endl;

				} else {
					sendAck(receivedSeqNum);
					writeToFile(receivedSeqNum, &buffer[START_DATA_INDEX], numCharsReceived - WRAPPER_SIZE);
					incrementSequenceNum();

					bool slideWindow = true;
					while (slideWindow) {
						//Shift sliding window
						for (int i = 0; i < slidingWindowSize - 1; i++) {
							packets[i] = packets[i + 1];
						}
						packets[slidingWindowSize - 1].freeUp();
						//We have shifted our sliding window, but we need to check if the next packet has already been received
						if (packets[0].isUsed()) {
							if (DEBUGEVERYTHINGELSE) std::cout << "Shifted queue, writing base" << std::endl;
							writeToFile(packets[0].getSN(), &packets[0].buffer[START_DATA_INDEX],
										packets[0].packet_bytes_read);
							incrementSequenceNum();

						} else {
							slideWindow = false;
						}
					}
				}

            } else {
                if (DEBUGEVERYTHINGELSE) std::cout << "Saving out of order packet, received seqNum: " << receivedSeqNum << std::endl;
                packets[slideFactor - 1].loadPacket(receivedSeqNum, numCharsReceived - WRAPPER_SIZE,
                                                    &buffer[START_DATA_INDEX]);
                sendAck(receivedSeqNum);
            }
        } else if (isInPreviousWindow(baseSeqNum, receivedSeqNum, slidingWindowSize)) {
            sendAck(receivedSeqNum);
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
    } else {
        // this is the CRC error logic.  We should send a NAK
        sendNak(receivedSeqNum);
        numChecksumFailed++;
        
        // Since we are waiting for packet_size + WRAPPER_SIZE bytes, if we ever get a short packet, we will have
        // a partial packet at the start of the next buffer read.  This could cause an infinite loop of NAKs. 
        // Special code to read until there is a break and don't put a packet size on it ONLY when the sequence
        // number is beyond its range.  This will get set back to the correct packet size on the next good CRC.
        if (receivedSeqNum > rangeOfSequenceNumbers)
        {
			bytes_to_read = MAX_BUF_SIZE;
		}
        
    }
}

void sendAck(int seqNum) {
    BreakINT16(response_buff, seqNum);
    response_buff[START_DATA_INDEX] = (char) ACK;
    numSent = sendto(connsock, response_buff, START_DATA_INDEX + 1,
                     0, (struct sockaddr *) &from, fromlen);
    if (numSent < 0) {
        error_and_exit(logFile, "sendto Error");
    }

    displayIntDataMessage(std::cout, logFile, "\r\nAck ", seqNum, " sent\r\n");
    std::cout << std::endl;
}

void sendNak(int seqNum) {
    BreakINT16(response_buff, seqNum);
    response_buff[START_DATA_INDEX] = (char) NAK;
    numSent = sendto(connsock, response_buff, START_DATA_INDEX + 1,
                     0, (struct sockaddr *) &from, fromlen);
    if (numSent < 0) {
        error_and_exit(logFile, "sendto Error");
    }

    displayIntDataMessage(std::cout, logFile, "\r\nNak ", seqNum, " sent\r\n");
    std::cout << std::endl;
}

void writeToFile(int seq, char *buff, int charsToWrite) {
    fileOutputStream.write(buff, charsToWrite);

    if (DEBUGEVERYTHINGELSE) 
    {
		std::cout << "WRITING TO FILE. seq: ";
		std::cout << seq;
		std::cout << std::endl;
	}
}

void incrementSequenceNum() {
    lastAckedSeqNum = baseSeqNum;
    numOriginalPackets++;
    baseSeqNum++;
    baseSeqNum = baseSeqNum % rangeOfSequenceNumbers;
}

void printQueue(std::ostream &console, std::ostream &log, int slidingWS, int seq, int rangeOfSeqNum) {

    console << "Current queue = [";
    log << "Current queue = [";
    int i = 0;
    for (i = 0; i < slidingWS - 1; i++) {
        console << packets[i].getSN() << ", ";
        log << packets[i].getSN() << ", ";
    }
    console << packets[i].getSN();
    log << packets[i].getSN();
    console << "]" << std::endl;
    log << "]" << std::endl;

}

void doDoneStuff(void) {
    if (DEBUGEVERYTHINGELSE) displayIntDataMessage(std::cout, logFile, "Last packet seq# received:", receivedSeqNum, "");
    std::cout << std::endl;
    displayIntDataMessage(std::cout, logFile, "Number of original packets received:   ", numOriginalPackets, "");
    std::cout << std::endl;
    displayIntDataMessage(std::cout, logFile, "Number of retransmitted packets received: ", packets_received - numOriginalPackets, "");
    std::cout << std::endl;

    displayIntDataMessage(std::cout, logFile, "Number of checksums that failed:  ", numChecksumFailed, "");
    std::cout << std::endl;
    displayIntDataMessage(std::cout, logFile, "Number of out of sequence packets:  ", numOutOfSequence, "");
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
