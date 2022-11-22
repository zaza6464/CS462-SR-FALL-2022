/* */
/* Filename : common.cpp */
/* Team :  */
/* */

#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <time.h>
#include <cstring>

#include "common.h"


/* used for crc algorithm */
#define CRCWIDTH (8 * sizeof(crc))
#define CRCTOPBIT (1 << (CRCWIDTH - 1))


crc crcTable[256];


int slidingWindowSizePrompt(int defaultWinSize) {

    std::cout << "Size of sliding window: (Press Enter to accept default of " << defaultWinSize << ")" << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    int winSize = 0;
    if (responseString.length() <= 0) {
        winSize = defaultWinSize;
    } else {
        winSize = std::stoi(responseString);
    }
    return winSize;

}

int situationalErrorsPrompt(int defaultSituationalErrors) {

    std::cout << "Situational errors; none (0), randomly generated (1), or user-specified (2):" << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);

    int situationalErrors;
    if (responseString.length() <= 0) {
        situationalErrors = defaultSituationalErrors;
    } else {
        situationalErrors = std::stoi(responseString);
    }
    return situationalErrors;
}

int outOfOrderPacketsPrompt(int* numberArray) {
    std::cout << "Enter the numbers of the packets you want to become out of order (delimit using a space): "
              << std::endl;
    return getNumbersFromUserInput(numberArray);
}

int dropPacketsPrompt(int* numberArray) {
    std::cout << "Enter the numbers of the packets you want to drop (delimit using a space): " << std::endl;
    return getNumbersFromUserInput(numberArray);
}

int corruptPacketsPrompt(int* numberArray) {
    std::cout << "Enter the numbers of the packets you want to corrupt (delimit using a space): " << std::endl;
    return getNumbersFromUserInput(numberArray);
}

int dropAcksPrompt(int* numberArray) {
    std::cout << "Enter the numbers of the ACKs you want to drop (delimit using a space): " << std::endl;
    return getNumbersFromUserInput(numberArray);
}

int getNumbersFromUserInput(int* numberArray) {
    std::string responseString;
    std::getline(std::cin, responseString);

    if (DEBUGUSERERRORS) std::cout << "before chararray declaration" << std::endl;
    char charArray[MAX_USER_ENTERED_PACKETS*5];
    const char delimiter[2] = " ";
    std::strcpy(charArray, responseString.c_str());
    if (DEBUGUSERERRORS) std::cout << "string length" << responseString.length() << std::endl;
    if (DEBUGUSERERRORS) std::cout << "chararray: " << charArray << std::endl;
    
    char *temp = strtok(charArray, delimiter);
    if (DEBUGUSERERRORS) std::cout << temp << std::endl;
    int iNums = 0;
    if (DEBUGUSERERRORS) std::cout << "before while loop" << std::endl;
    
    while((temp != NULL) && (iNums < (MAX_USER_ENTERED_PACKETS-1)))
    {
       numberArray[iNums++] = atoi(temp);
       temp = strtok(NULL, delimiter);
    }

    if (DEBUGUSERERRORS) std::cout << "out of while loop" << std::endl;
    return iNums;
}

int portNumPrompt(int defaultPortNum) {

    std::cout << "Port number: (Press Enter to accept default of " << defaultPortNum << ")" << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    int portNum = 0;
    if (responseString.length() <= 0) {
        portNum = defaultPortNum;
    } else {
        portNum = std::stoi(responseString);
    }
    return portNum;
}

std::string filePathPrompt(std::string defaultPath) {

    std::cout << "Path of file to be transferred: " << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    std::string filePath;
    if (responseString.length() <= 0) {
        filePath = defaultPath;
    } else {
        filePath = responseString;
    }
    return filePath;

}

std::string ipAddressPrompt(std::string defaultIpAddress) {

    std::cout << "IP Address of other instance: (Press Enter to accept default of " << defaultIpAddress << ")"
              << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    std::string ipAddress;
    if (responseString.length() <= 0) {
        ipAddress = defaultIpAddress;
    } else {
        ipAddress = responseString;
    }
    return ipAddress;

}

int protocolTypePrompt(int defaultProtocolType) {

    std::cout << "Type of protocol, S&W (0), GBN (1), or SR (2):" << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    int protocolType;
    if (responseString.length() <= 0) {
        protocolType = defaultProtocolType;
    } else {
        protocolType = std::stoi(responseString);
    }

    return protocolType;

}

int packetSizePrompt(int defaultPacketSize) {

    std::cout << "Packet size (Max of " << MAX_PACKET_SIZE << " bytes: (Press Enter to accept default of "
              << defaultPacketSize << ")" << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    int packetSize;
    if (responseString.length() <= 0) {
        packetSize = defaultPacketSize;
    } else {
        packetSize = std::stoi(responseString);
        if (packetSize > MAX_PACKET_SIZE) {
            packetSize = MAX_PACKET_SIZE;
        }
    }
    return packetSize;
}

//    if (ps < 100) {
//        ps = 100;
//        std::cout << "Setting Packet Size to a minimum of 100" << std::endl;
//    } else if (ps > MAX_BUF_SIZE - 1000) {
//        ps = MAX_BUF_SIZE - 1000;
//        std::cout << "Setting Packet Size to buffer limit" << std::endl;
//    }

int timeoutIntervalPrompt() {

    std::cout << "Timeout interval in microseconds (µs); user-specified or press enter for ping calculated default:"
              << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);

    int timeout;
    if (responseString.length() <= 0) {
        timeout = DEFAULT_TIMEOUT_US;
    } else {
        timeout = std::stoi(responseString);
    }
    return timeout;
}

int rangeOfSequenceNumbersPrompt(int defaultWinSize) {

    std::cout << "Range of sequence numbers: (Press Enter to accept default of " << defaultWinSize << ")" << std::endl;

    std::string responseString;
    std::getline(std::cin, responseString);
    int sequenceNumbers = 0;
    if (responseString.length() == 0) {
        sequenceNumbers = defaultWinSize;
    } else {
        sequenceNumbers = std::stoi(responseString);
    }
    if (sequenceNumbers < ((defaultWinSize * 2) + 1)) {
        std::cout << "Invalid range, setting to value compatible with window size" << std::endl;
        sequenceNumbers = (defaultWinSize * 2) + 1;
    }
    return sequenceNumbers;

}

int isInSlidingWindow(uint16_t sn, uint16_t recsn, int slidingWindowSize, int rangeOfSequenceNumbers) {
    for (int i = 0; i < slidingWindowSize; i++) {
        if (recsn == (sn + i) % rangeOfSequenceNumbers) {
            return i + 1;
        }
    }
    return 0;
}

int isInPreviousWindow(uint16_t sn, uint16_t recsn, int slidingWindowSize) {
    for (int i = 0; i < slidingWindowSize; i++) {
        int tempSN = sn - (i + 1);
        if (tempSN < 0) {
            tempSN = slidingWindowSize + tempSN;
        }
        if (recsn == tempSN) {
            return i + 1;
        }
    }
    return 0;
}

void displayMessage(std::ostream &console, std::ostream &log, std::string mess) {
    console << mess << std::endl;
    log << mess << std::endl;
}

void displayIntDataMessage(std::ostream &console, std::ostream &log, std::string pre, int data, std::string post) {
    console << pre << data << post << std::endl;
    log << pre << data << post << std::endl;
}

void
displayDoubleDataMessage(std::ostream &console, std::ostream &log, std::string pre, double data, std::string post) {
    console << pre << data << post << std::endl;
    log << pre << data << post << std::endl;
}


void displayBuffer(std::ostream &console, std::ostream &log, char *buf, int num_bytes) {
#if SHOW_BUFFER
    console << "buffer: ";
    log << "buffer: ";
    // write(1, buf, num_bytes);
    for (int i = 0; i < num_bytes; i++) {
        console << buf[i];
        log << buf[i];
    }
    console << std::endl;
    log << std::endl;
#endif
}

void displayEntirePacket(std::ostream &console, std::ostream &log, char *buf, int num_bytes) {
#if SHOW_ENTIRE_PACKET
    console << "buffer: ";
    log << "buffer: ";
    // write(1, buf, num_bytes);
    for (int i = 0; i < num_bytes; i++) {
        console << buf[i];
        log << buf[i];
    }
    console << std::endl;
    log << std::endl;
#endif
}

void printWindow(std::ostream &console, std::ostream &log, int slidingWS, int seq, int rangeOfSeqNum) {

    console << "Current window = [";
    log << "Current window = [";
    int i = 0;
    for (i = seq; i < (seq + slidingWS - 1); i++) {
        console << i % rangeOfSeqNum << ", ";
        log << i % rangeOfSeqNum << ", ";
    }
    console << i % rangeOfSeqNum;
    log << i % rangeOfSeqNum;
    console << "]" << std::endl;
    log << "]" << std::endl;

}

void error_and_exit(std::ostream &log, const char *msg) {
    log << msg;
    perror(msg);
    exit(0);
}


char *GetTimeStamp(char *timeStamp) {
// declaring argument of time()
    time_t my_time = time(NULL);

    // ctime() used to give the present time
    sprintf(timeStamp, "%s", ctime(&my_time));

    return timeStamp;
}

/* crcTableInit() creates the crc lookup table.
 * Only needs to be run once.
 */
void crcTableInit() {
    crc remainder;
    int dividend;
    unsigned char bit;

// calculate the remainder of all possible dividends
    for (dividend = 0; dividend < 256; ++dividend) {

        // start with dividend followed by zeroes
        remainder = dividend << (CRCWIDTH - 8);

        // division, bit by bit
        for (bit = 8; bit > 0; --bit) {
            if (remainder & CRCTOPBIT) { // current bit divides
                remainder = (remainder << 1) ^ POLYNOMIAL;
            } else {                     // current bit doesn't divide
                remainder = (remainder << 1);
            }
        }

        crcTable[dividend] = remainder;
    }
    if (DEBUGCRC) {
        for (int i = 0; i < 64; ++i) {
            std::cout << std::hex << crcTable[i * 4] << ", " << std::hex << crcTable[i * 4 + 1] << ", " << std::hex
                      << crcTable[i * 4 + 2] << ", " << std::hex << crcTable[i * 4 + 3] << ", " << std::endl;
        }
    }
} /* crcTableInit() */


/* crcFun() calculates the crc value of a message and returns it. */
crc crcFun(unsigned char const message[], int nBytes) {
    crc remainder = INITIAL_REMAINDER; // in case we get a packet which starts with a lot of zeroes
    unsigned char data;
    int byte;

// divide the message by the polynomial, one byte at a time.
    for (byte = 0; byte < nBytes; ++byte) {
        data = message[byte] ^ (remainder >> (CRCWIDTH - 8));
        remainder = crcTable[data] ^ (remainder << 8);
    }

    if (DEBUGCRC) {
        std::cout << "crcFun returning: " << remainder << std::endl;
        char myBuff[5];
        BreakINT32(&myBuff[0], remainder);
        for (int i = 0; i < 4; i++) {
            std::cout << "crcFun returning as bytes: " << int(myBuff[i]) << std::endl;
        }
    }
// the remainder is the crc
    return remainder;

} /* crcFun() */



// The following functions seem unnecessary, but we don't want to assume we know the
// order of bytes in an integer on all systems, so force a specific order.

/* creates a 16 bit value from the first 2 indices of the array */
int16_t MakeINT16(char buff[]) {
    return (
            (((int16_t) buff[0]) & 0x00FF) |
            (((int16_t) buff[1] << 8) & 0xFF00)
    );
}

/* takes a 16 bit value and stores it in the first 2 indices of the array */
void BreakINT16(char buff[], int16_t i) {
    buff[0] = (char) (i & 0x00FF);
    buff[1] = (char) ((i & 0xFF00) >> 8);
}

/* creates a 32 bit value from the first 4 indices of the array */
int32_t MakeINT32(char buff[]) {
    return (
            (((int32_t) buff[0]) & 0x000000FF) |
            (((int32_t) buff[1] << 8) & 0x0000FF00) |
            (((int32_t) buff[2] << 16) & 0x00FF0000) |
            (((int32_t) buff[3] << 24) & 0xFF000000)
    );
}

/* takes a 32 bit value and stores it in the first 4 indices of the array  */
void BreakINT32(char buff[], int32_t i) {
    buff[0] = (char) (i & 0x000000FF);
    buff[1] = (char) ((i & 0x0000FF00) >> 8);
    buff[2] = (char) ((i & 0x00FF0000) >> 16);
    buff[3] = (char) ((i & 0xFF000000) >> 24);
}
