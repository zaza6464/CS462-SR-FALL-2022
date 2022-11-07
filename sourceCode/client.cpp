/* CS-462 Project : Implementation of Sliding Windows Protocol for efficient file transfer. */
/* */
/* Starting with a minimal client shell in the internet domain (https://www.linuxhowtos.org/C_C++/socket.htm) */
/* */
/* This is the CLIENT (which opens the file and sends the data in packets based on 3 protocols). */
/* */
/* Complile with this command: g++ -o client.out client.cpp common.cpp -std=c++11 */
/* */
/* Filename : client.cpp */
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
#include <fstream>
#include <chrono>
#include "client.h"
#include "common.h"
#include "packet_struct.h"


std::chrono::steady_clock::time_point start_test_ticks;
std::chrono::steady_clock::time_point end_test_ticks;
clock_t start_packet_ticks;
clock_t end_packet_ticks;
time_t myTime;
std::ofstream logFile;
//create ifstream object
std::ifstream fileInputStream;
// Data for sockets
int sock;
int num_bytes = 0;
int packet_bytes_read;
uint32_t sendCheckSum;
uint32_t receiveCheckSum;
uint16_t sequenceNum = 0;
uint16_t nextSeqNum = 0;
uint16_t lastSeqNum = 0;

int outOfOrders = 0;
int packets_sent = 0;
int packets_failed = 0;
int originalPackets = 0;
int retransmittedPackets = 0;
long int totalBytesRead = 0;
long int totalBytesSent = 0;
unsigned int length;
struct sockaddr_in client;
struct sockaddr_in from;
struct hostent *hp;
// Get a large buffer to read file data into
char buffer[MAX_BUF_SIZE];
char rec_buffer[MAX_BUF_SIZE];
// User supplied variables
std::string filePath = "/data/users/kranicac1696/src/1M"; //path to file to be sent
std::string ipAddress = "172.23.0.3"; //IP address of the target server
int portNum = 6789; //port number of the target server
int timeoutIntervalus = DEFAULT_TIMEOUT_US; //user-specified (0+) or ping calculated (-1)
int protocolType = 0; //0 for S&W, 1 for GBN, 2 for SR
int packetSize = 100; //specified size of packets to be sent
int slidingWindowSize = 1; //ex. [1, 2, 3, 4, 5, 6, 7, 8], size = 8
int rangeOfSequenceNumbers = 5; //ex. (sliding window size = 3) [1, 2, 3] -> [2, 3, 4] -> [3, 4, 5], range = 5
int situationalErrors = 0; //none (0), randomly generated (1), or user-specified (2)
int readNewData = 1;
int numPacketsToRead = slidingWindowSize;
int at_end_of_file = 0;
bool simulateLost = false;
bool gotLastAck = false;
//char test[12] = {0,0,'t','h','i','s',' ','i','s',' ','a','n'};

packetClass packets[MAX_WINDOW_SIZE];

int main(int argc, char *argv[]) {

    // create the CRC lookup table so we can use it later.
    crcTableInit();

    //crc testcrc = crcFun((uint8_t *)test, 12);
    //std::cout << "the crc of our test string is: " << testcrc << std::endl;


    //prompt user for each of the following fields
    ipAddress = ipAddressPrompt(ipAddress);
    portNum = portNumPrompt(portNum);
    packetSize = packetSizePrompt(packetSize);
    timeoutIntervalus = timeoutIntervalPrompt();

    protocolType = protocolTypePrompt(protocolType);

    if (protocolType != 0) {
        slidingWindowSize = slidingWindowSizePrompt(slidingWindowSize);
    } else {
        slidingWindowSize = 1;
    }

    rangeOfSequenceNumbers = rangeOfSequenceNumbersPrompt(slidingWindowSize);


    situationalErrors = situationalErrorsPrompt(situationalErrors);

    filePath = filePathPrompt(filePath);



    //open file at filepath in read and binary modes
    fileInputStream.open(filePath, std::ios_base::in | std::ios_base::binary);
    if (!fileInputStream.is_open()) {
        error_and_exit(logFile, "Read file not opened successfully!!");
    }

    //create a stream to the log file

    logFile.open("output/client_log.log", std::ios_base::in | std::ios_base::app);
    if (!logFile.is_open()) {
        error_and_exit(logFile, "Log file not opened successfully!!");
    }

    //navigate to section of file beginning at (sequenceNumber * packetSize) offset from beginning
    //std::cout << "halfway through writefile" << std::endl;


//  set global packet struct sequence number
//  myPacket.sequenceNumber = sequenceNumber;
//  clear the current contents of the global packet struct char vector
//  myPacket.contents.clear();
//  copy the contents of the array to the global packet struct char vector
//  std::copy(&contents[0], &contents[packetSize], back_inserter(myPacket.contents));
//  fileInputStream.close();
//  std::cout << "end of writefile" << std::endl;


    // First, just make sure we can create the socket
    //sock = socket(AF_INET, SOCK_DGRAM, 0);
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) error_and_exit(logFile, "Exit, failed to create socket.");
    bzero(&client, sizeof(client));

    // Next, check that we can "see" the host ipaddress (by name or ipv4 xxx.xxx.xxx.xxx numbers)
    client.sin_family = AF_INET;
    hp = gethostbyname(ipAddress.c_str());
    if (hp == 0) error_and_exit(logFile, "Exit, Couldn't find Server/Host");

    // Set the port number the server is expecting data on.
    bcopy((char *) hp->h_addr, (char *) &client.sin_addr, hp->h_length);
    client.sin_port = htons(portNum);

    length = sizeof(struct sockaddr_in);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = timeoutIntervalus;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *) &tv, sizeof tv);

    if(connect(sock, (struct sockaddr*)&client, sizeof(client)) != 0){
        error_and_exit(logFile, "Connection with server failed, exiting client");
    }
    // For testing, get user input and store it in the buffer.
    //printf("Enter a string to send to the server for testing:\r\n");
    //bzero(buffer, 256);
    //fgets(buffer, 255, stdin);


    start_test_ticks = std::chrono::steady_clock::now();


    myTime = time(NULL);


    displayMessage(std::cout, logFile, "******************** START OF NEW TEST ********************");
    displayMessage(std::cout, logFile, ctime(&myTime));
    if (protocolType == 0) {
        displayMessage(std::cout, logFile, "Protocol Type: Stop and Wait");
    } else if (protocolType == 1) {
        displayMessage(std::cout, logFile, "Protocol Type: Go-Back-N");
    } else if (protocolType == 2) {
        displayMessage(std::cout, logFile, "Protocol Type: Selective Repeat");
    }
    displayIntDataMessage(std::cout, logFile, "Packet Size: ", packetSize, "");
    displayIntDataMessage(std::cout, logFile, "Timeout Interval: ", timeoutIntervalus, "");
    displayIntDataMessage(std::cout, logFile, "Range of Sequence Numbers: ", rangeOfSequenceNumbers, "");
    displayIntDataMessage(std::cout, logFile, "Window Size: ", slidingWindowSize, "");
    if (situationalErrors == 0) {
        displayMessage(std::cout, logFile, "Situational Errors: None");
    } else if (situationalErrors == 1) {
        displayMessage(std::cout, logFile, "Situational Errors: Randomly Generated");
    } else if (situationalErrors == 2) {
        displayMessage(std::cout, logFile, "Situational Errors: User Generated");
    }



    while (!at_end_of_file || !gotLastAck) {
        // while (!at_end_of_file) {
        switch (protocolType) {
            case 0:
                // executeSAWProtocol();
                // break;
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

    doDoneStuff();
    return 0;
}


/*
void executeSAWProtocol(void) {
    if (readNewData) {
        bzero(buffer, MAX_BUF_SIZE);
        fileInputStream.read(&buffer[START_DATA_INDEX], packetSize);
        packet_bytes_read = fileInputStream.gcount();
        totalBytesRead += packet_bytes_read;
        originalPackets++;
        displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], packet_bytes_read);
        if (packet_bytes_read == -1) {
            error_and_exit("Could not open file for reading");
        } else if (packet_bytes_read < packetSize) {
            //We know we must have read the last bit of data
            at_end_of_file = 1;
        }
    }


//        //inserting sequence # into buffer
//        BreakINT16(buffer, sequenceNum);
    printWindow(std::cout, logFile, slidingWindowSize, sequenceNum);

    // Add the seq num and crc to the buffer to send
    BreakINT16(buffer, sequenceNum);
    uint16_t CRC = crc16((uint8_t *) buffer, packet_bytes_read + START_DATA_INDEX);
    BreakINT16(&buffer[packet_bytes_read + START_DATA_INDEX], CRC);

    if (situationalErrors == 1) generateRandomSituationalErrors(buffer, sequenceNum, packet_bytes_read);

    if (simulateLost) {
        // Dont send
        simulateLost = false;
    } else {
        //sending now
        sendto(sock, buffer,
               packet_bytes_read + WRAPPER_SIZE, 0, (const struct sockaddr *) &server, length);
        totalBytesSent += packet_bytes_read + WRAPPER_SIZE;
    }

    DisplayPacketSendMess(sequenceNum);
    displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], packet_bytes_read);
    packets_sent++;


    //waiting for response
    num_bytes = recvfrom(sock, rec_buffer, MAX_BUF_SIZE, 0, (struct sockaddr *) &from, &length);

    if (num_bytes < 0) {
//            error_and_exit("recvfrom");
        DisplayPacketTimedout(sequenceNum);
        DisplayPacketRetransMess(sequenceNum);
        readNewData = 0;
        retransmittedPackets++;
    } else if (num_bytes > 0) {
        int16_t receivedSeqNum = MakeINT16(rec_buffer);
        //10% of the time we will simulate not getting an ACK
        if (situationalErrors == 1 && !((packets_sent + rand() % 10 + 1) % 10)) {
//                rec_buffer[START_DATA_INDEX] = NAK;
		}
		if (rec_buffer[START_DATA_INDEX] == ACK) {
			if (sequenceNum == receivedSeqNum) {
				if (at_end_of_file) gotLastAck = true;
				sequenceNum++;
				if (sequenceNum >= rangeOfSequenceNumbers) {
					sequenceNum = 0;
				}
				DisplayAckReceived(receivedSeqNum);
//                        bzero(buffer, MAX_BUF_SIZE);
//                        fileInputStream.read(&buffer[START_DATA_INDEX], packetSize);
//                        packet_bytes_read = fileInputStream.gcount();
//                        totalBytesRead += packet_bytes_read;
                readNewData = 1;
//                        if (packet_bytes_read > 0) {
//                            originalPackets++;
//                            //We know we must have read the last bit of data
//                        } else {
//                            at_end_of_file = 1;
//                        }
                //displayBuffer(std::cout, buffer, packet_bytes_read);
            } else {
                //we are getting an ack for a future or past packet
                //since this isn't what we want we won't do anything
                DisplayPacketRetransMess(sequenceNum);
                retransmittedPackets++;
                outOfOrders++;
                readNewData = 0;
            }
        } else {
            // We should never get a response that isn't an ACK
            DisplayNakReceived(receivedSeqNum);
            DisplayPacketRetransMess(sequenceNum);
            readNewData = 0;
            packets_failed++;
            retransmittedPackets++;
        }

    } else {
        //This has to be the case where num_bytes is 0
        DisplayPacketTimedout(sequenceNum);
        retransmittedPackets++;
        readNewData = 0;
    }

}
*/

void executeGBNProtocol(void) {
    if (readNewData) {
        readPacketsFromFile(numPacketsToRead);
    }

    printWindow(std::cout, logFile, slidingWindowSize, sequenceNum, rangeOfSequenceNumbers);

    //sending now
    sendPackets(numPacketsToRead, sequenceNum);

    //waiting for response
    num_bytes = recvfrom(sock, rec_buffer, MAX_BUF_SIZE, 0, (struct sockaddr *) &from, &length);

    //displayIntDataMessage(std::cout, logFile, "Number of bytes of response:", num_bytes, "");
    if (num_bytes <= 0) {
        //WE TIMED OUT!!!!!!!!
        //crcTableInit();
        DisplayPacketTimedout(sequenceNum);
        setMarkForRetransmit(sequenceNum, slidingWindowSize);

    } else if (num_bytes > 0) {

        //WE GOT SOME DATA
        int16_t receivedSeqNum = MakeINT16(rec_buffer);


        if (rec_buffer[START_DATA_INDEX] == ACK) {

            DisplayAckReceived(receivedSeqNum);

            int slideFactor = isInSlidingWindow(sequenceNum, receivedSeqNum);
            if (slideFactor > 0) {
                //This means we got an ack on our first window so we only shift our window by one
                slideWindow(slideFactor, receivedSeqNum);

                readNewData = 1;

                if (at_end_of_file && (receivedSeqNum == lastSeqNum)) gotLastAck = true;

            } else {
                //we are getting an ack for a future or past packet thats not in our window
                //since this isn't what we want we won't do anything
                setMarkForRetransmit(sequenceNum, slidingWindowSize);
                outOfOrders++;
            }
        } else {
            // We should never get a response that isn't an ACK
            DisplayNakReceived(receivedSeqNum);
            setMarkForRetransmit(sequenceNum, slidingWindowSize);
            packets_failed++;
        }
    }
}

void executeSRProtocol(void) {
    executeGBNProtocol();
}

void setMarkForRetransmit(uint16_t seq, int numPackets) {
    int num = 0;
    for (int i = 0; i < numPackets; i++) {

        uint16_t tempSeq = seq + i;
        tempSeq = tempSeq % rangeOfSequenceNumbers;

        int index = getPacketIndexBySN(tempSeq);

        // std::cout << "In setMarkForRetransmit. index : ";
        // std::cout << index;
        // std::cout << std::endl;

        if (index >= 0) {
            if (packets[index].getSent() == true) {
                retransmittedPackets++;
            }
            packets[index].setSent(false);
            DisplayPacketRetransMess(tempSeq);
            num++;
        }
        readNewData = 0;
    }

    numPacketsToRead = num;

}


// if this doesn't work, double check START_DATA_INDEX is correct,
// also check to make sure I didn't mess up changing crc from 16 to 32
void generateRandomSituationalErrors(char *buff, uint16_t seq, int bsRead) {
    // Don't do more than one of these errors at a time!

    //10% of the time the packet will be out of order
    if (!(packets_sent % 10)) {
        //inserting sequence # into buffer
        BreakINT16(buff, seq + rand() % 10 + 1);

        // If we mutate the sequence number, we still need a good CRC so recalculate it
        uint32_t CRC = crcFun((uint8_t *) buff, bsRead + START_DATA_INDEX);
        BreakINT32(&buff[bsRead + START_DATA_INDEX], CRC);

    } else if (!((packets_sent + rand() % 10 + 1) % 10)) {
        //10% of the time we will send a bad crc
        //inducing bad crc
        uint32_t CRC = rand() % 10 + 1;
        BreakINT32(&buff[bsRead + START_DATA_INDEX], CRC);
    } else if (!((packets_sent + rand() % 10 + 1) % 10)) {
        //10% the packet will appear to be sent, but will be not actually be send/ it will be lost
        simulateLost = true;
    }
}


int getUnusedPacketIndex() {
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        if (packets[i].isUsed() == false) {
            return i;
        }
    }
    return -1;
}

int getUnsentPacketIndex() {
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        if ((packets[i].isUsed() == true) && (packets[i].getSent() == false)) {
            return i;
        }
    }
    return -1;
}

int getPacketIndexBySN(uint16_t sn) {
    for (int i = 0; i < MAX_WINDOW_SIZE; i++) {
        if ((packets[i].isUsed() == true) && (packets[i].getSN() == sn)) {
            return i;
        }
    }
    return -1;
}


void readPacketsFromFile(int nPacks) {
    char lBuff[MAX_BUF_SIZE];
    int lBytesRead = 0;

    if (nPacks <= 0 || nPacks > MAX_WINDOW_SIZE) return;

    for (int i = 0; i < nPacks; i++) {

        int packIndex = getUnusedPacketIndex();
        if (packIndex > -1) {
            bzero(lBuff, MAX_BUF_SIZE);
            fileInputStream.read(lBuff, packetSize);
            lBytesRead = fileInputStream.gcount();

            if (lBytesRead == -1) error_and_exit(logFile, "Could not open file for reading");

            if (lBytesRead == 0) {
                at_end_of_file = 1;
                return;
            } else if (lBytesRead < packetSize) {
                //We know we must have read the last bit of data
                at_end_of_file = 1;
            }
            totalBytesRead += lBytesRead;
            originalPackets++;
            packets[packIndex].loadPacket(nextSeqNum, lBytesRead, lBuff);
            lastSeqNum = nextSeqNum;
            nextSeqNum++;
            nextSeqNum = nextSeqNum % rangeOfSequenceNumbers;


        } else {
            error_and_exit(logFile, "Ran out of packet buffers");
        }
    }
}

void sendPackets(int nPacks, uint16_t startSN) {
    // std::cout << "In sendPackets. nPacks : ";
    // std::cout << nPacks;
    // std::cout << std::endl;

    for (int i = 0; i < nPacks; i++) {

        uint16_t tempSeq = startSN + i;
        tempSeq = tempSeq % rangeOfSequenceNumbers;

        int packIndex = getPacketIndexBySN(tempSeq);

        // int packIndex = getUnsentPacketIndex();

        // std::cout << "In sendPackets. packIndex : ";
        // std::cout << packIndex;
        // std::cout << std::endl;

        if ((packIndex > -1) && (packets[packIndex].getSent() == false)) {


            // use a temporary buffer so original seq num doesn't get permanently changed when we are
            // simulating errors.
            bzero(buffer, MAX_BUF_SIZE);
            memcpy(buffer, packets[packIndex].getBuffPoint(), packets[packIndex].packet_bytes_read + WRAPPER_SIZE);

            if (situationalErrors == 1 && !at_end_of_file) {
                generateRandomSituationalErrors(buffer, packets[packIndex].getSN(),
                                                packets[packIndex].packet_bytes_read);

                // displayBuffer(std::cout, &buffer[START_DATA_INDEX], packets[packIndex].packet_bytes_read);
            }

            if (simulateLost) {
                // Dont send
                simulateLost = false;
            } else {
                //sending now
                sendto(sock, buffer,
                       packets[packIndex].packet_bytes_read + WRAPPER_SIZE, 0,
                       (const struct sockaddr *) &client, length);
                //write(sock, buffer,packets[packIndex].packet_bytes_read + WRAPPER_SIZE);
                totalBytesSent += packets[packIndex].packet_bytes_read + WRAPPER_SIZE;

                DisplayPacketSendMess(packets[packIndex].getSN());
                displayBuffer(std::cout, logFile, &buffer[START_DATA_INDEX], packets[packIndex].packet_bytes_read);
                displayEntirePacket(std::cout, logFile, &buffer[0], packets[packIndex].packet_bytes_read + WRAPPER_SIZE);
                packets[packIndex].setSent(true);
                // gotLastAck = false;
            }

            packets_sent++;
        }
    }
}

void slideWindow(int slideFactor, uint16_t recSN) {
    //We are acknowledging 1 or more packets have been acked by accepting the last sequence number

    for (int i = 0; i < slideFactor; i++) {
        int packIndex = getPacketIndexBySN(sequenceNum);
        if (packIndex > -1) {
            packets[packIndex].freeUp();
        }

        sequenceNum++;
        sequenceNum = sequenceNum % rangeOfSequenceNumbers;
    }
    numPacketsToRead = slideFactor;
}

//this returns 0 if its not in the window and if it is it returns how many to slide
int isInSlidingWindow(uint16_t sn, uint16_t recsn) {
    for (int i = 0; i < slidingWindowSize; i++) {
        if (recsn == (sn + i) % rangeOfSequenceNumbers) {
            return i + 1;
        }
    }
    return 0;
}


void DisplayPacketSendMess(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Packet ", packetNum, " sent");
}

void DisplayPacketRetransMess(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Packet ", packetNum, " Re-transmitted");
}

void DisplayAckReceived(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Ack ", packetNum, " received");
}

void DisplayNakReceived(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Nak ", packetNum, " received");
}

void DisplayPacketTimedout(int packetNum) {
    displayIntDataMessage(std::cout, logFile, "Packet ", packetNum, " *****Timed Out *****");
}

void doDoneStuff() {
    //we're done but to be safe we will send command to server to close the file
    //30,000 is a special sequence number close file code
    BreakINT16(buffer, 30000);
    uint32_t CRC = crcFun((uint8_t *) buffer, START_DATA_INDEX);
    BreakINT32(&buffer[START_DATA_INDEX], CRC);
    sendto(sock, buffer,
           WRAPPER_SIZE, 0, (const struct sockaddr *) &client, length);

    // Close socket, inputstream, and exit
    fileInputStream.close();
    close(sock);

    end_test_ticks = std::chrono::steady_clock::now();


    myTime = time(NULL);
    // ctime() used to give the present time

    displayMessage(std::cout, logFile, ctime(&myTime));

    double total_test_us = std::chrono::duration_cast<std::chrono::microseconds>(end_test_ticks - start_test_ticks).count();

    displayMessage(std::cout, logFile, "Session Successfully terminated");
    std::cout << std::endl;
    logFile << std::endl;

    displayIntDataMessage(std::cout, logFile, "Number of original packets sent: ", originalPackets, "");

    displayIntDataMessage(std::cout, logFile, "Number of retransmitted packets: ", retransmittedPackets, "");

    displayDoubleDataMessage(std::cout, logFile, "Total elapsed time (ms): ", total_test_us / 1000.0, "");
    displayDoubleDataMessage(std::cout, logFile, "Total throughput (Mbps) : ", (totalBytesSent * 8.0) / total_test_us,
                             "");
    displayDoubleDataMessage(std::cout, logFile, "Effective throughput: ", (totalBytesRead * 8.0) / total_test_us, "");

    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");
    displayMessage(std::cout, logFile, "");

//    std::cout << "Number of out of order acks: ";
//    std::cout << outOfOrders << std::endl;

    logFile.close();
}
