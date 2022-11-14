/* */
/* Filename : common.cpp */
/* Team :  */
/* */

#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <time.h>

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

int isInPreviousWindow(uint16_t sn, uint16_t recsn, int slidingWindowSize){
    for (int i = 0; i < slidingWindowSize; i++) {
        int tempSN = sn - (i + 1);
        if(tempSN < 0){
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




/*/
// Table of CRC values for high–order byte 
static uint8_t auchCRCHi[] = {
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
        0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
        0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
        0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81,
        0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0,
        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
        0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
        0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
        0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01,
        0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
        0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0,
        0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01,
        0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
        0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81,
        0x40
};


// Table of CRC values for low–order byte 
static uint8_t auchCRCLo[] = {
        0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7, 0x05, 0xC5, 0xC4,
        0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E, 0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09,
        0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9, 0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD,
        0x1D, 0x1C, 0xDC, 0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
        0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32, 0x36, 0xF6, 0xF7,
        0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D, 0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A,
        0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38, 0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE,
        0x2E, 0x2F, 0xEF, 0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
        0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1, 0x63, 0xA3, 0xA2,
        0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4, 0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F,
        0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB, 0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB,
        0x7B, 0x7A, 0xBA, 0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
        0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0, 0x50, 0x90, 0x91,
        0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97, 0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C,
        0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E, 0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88,
        0x48, 0x49, 0x89, 0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
        0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83, 0x41, 0x81, 0x80,
        0x40
};


// The function returns the CRC as a unsigned short type 
uint16_t crc16(uint8_t *data, int len) {
    uint8_t uchCRCHi = 0xFF; // high byte of CRC initialized 
    uint8_t uchCRCLo = 0xFF; // low byte of CRC initialized 
    int index; // will index into CRC lookup table 
    while (len--) {
        index = uchCRCLo ^ *data++; // calculate the CRC 
        uchCRCLo = uchCRCHi ^ auchCRCHi[index];
        uchCRCHi = auchCRCLo[index];
    }
    return (uchCRCHi << 8 | uchCRCLo);
}


//*/


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
