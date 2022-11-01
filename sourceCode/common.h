/* */
/* Filename : common.h */
/* Team :  */
/* */

#ifndef CS_462_PROJECT_COMMON_H
#define CS_462_PROJECT_COMMON_H

#define ACK 0x06
#define NAK 0x15
#define SHOW_BUFFER 0
#define MAX_WINDOW_SIZE 25
#define DEFAULT_TIMEOUT_US 1000
#define MAX_BUF_SIZE 11000

//error
void error_and_exit(std::ostream& log, const char *msg);

// user input prompts
int slidingWindowSizePrompt();
int situationalErrorsPrompt();
int portNumPrompt();
std::string filePathPrompt();
std::string ipAddressPrompt();
int protocolTypePrompt();
int packetSizePrompt();
int timeoutIntervalPrompt();
int rangeOfSequenceNumbersPrompt(int);

// diplay/log output
void displayMessage(std::ostream& console, std::ostream& log, std::string mess);
void displayIntDataMessage(std::ostream& console, std::ostream& log, std::string pre, int data, std::string post);
void displayDoubleDataMessage(std::ostream &console, std::ostream &log, std::string pre, double data, std::string post);
void displayBuffer(std::ostream& console, std::ostream& log, char *buf, int num_bytes);
void printWindow(std::ostream& console, std::ostream& log, int slidingWS, int seq, int rangeOfSeqNum);

char *GetTimeStamp(char *timeStamp);

/*
 * CRC generation code is copied from the Modbus specification.
 */
uint16_t crc16(uint8_t *data, int len);
int16_t MakeINT16(char buff[]);
void BreakINT16(char buff[], int16_t i);

#endif //CS_462_PROJECT_COMMON_H
