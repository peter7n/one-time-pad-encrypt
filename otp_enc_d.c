/*********************************************************************
 ** Program Filename: otp_enc_d.c
 ** Author: Peter Nguyen
 ** Date: 3/14/16
 ** CS 344-400, Program 4
 ** Description: Daemon that performs one-time pad encryption
 *********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>

const int ASCII_SPACE = 32;
const int BUFF_SIZE = 70000;
const int MIN_PORT = 50000;
const int MAX_PORT = 65535;

// Function prototypes
void error(const char *msg);
void readSock(int sockfd, char* buffer, int size);
void writeSock(int sockfd, char* buffer);
char* encrypt(char* plaintext, char* key);

int main(int argc, char *argv[])
{
  int sockfd,
      newsockfd,
      portno,
      receivedNum = 0, // int representing the data size sent
      returnStatus,    // value returned from read or write
      dataSizeNum,
      convertedNum,
      randPort,
      childExitStatus = 0;
  socklen_t clilen;    // size of client address
  char txtBuffer[BUFF_SIZE],
       keyBuffer[BUFF_SIZE];
  char* ciphertext;
  struct sockaddr_in serv_addr,
         cli_addr;
  pid_t childPID;


  // Check if user provided a port
  if (argc < 2)
  {
    fprintf(stderr,"ERROR, no port provided\n");
    exit(1);
  }

  // Open the socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("ERROR opening socket");

  // Set server address and port number
  bzero((char *) &serv_addr, sizeof(serv_addr)); // reset to zero's
  portno = atoi(argv[1]);
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(portno);
  serv_addr.sin_addr.s_addr = INADDR_ANY;

  // Bind socket to address and start listening
  if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    error("ERROR on initial binding");
  listen(sockfd, 5);

  /******** Accept a client and get new socket file descriptor ********/

  // Loop infinitely in the parent process to accept clients
  // Loop ends in child when process completes successfully
  while (childExitStatus == 0)
  {
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0)
      error("ERROR on accept");
    else
    {
      // Send valid identifier to otp_enc
      dataSizeNum = 1;
      convertedNum = htonl(dataSizeNum);
      returnStatus = write(newsockfd, &convertedNum, sizeof(convertedNum));
    }

    /******** Fork a new process ********/

    childPID = fork();

    switch (childPID)
    {
      case -1: // Fork failure
        printf("fork failed\n");
        fflush(stdout);
        exit(1);
        break;

      case 0: // Child: Connect to client and exchange data
        // Restart on new port and wait for client

        // Generate new random port number for client
        srand(time(NULL));
        randPort = rand() % (MAX_PORT + 1 - MIN_PORT) + MIN_PORT;

        // Open the socket
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
          error("ERROR opening socket");
        // Set server address and port number
        bzero((char *) &serv_addr, sizeof(serv_addr));
        portno = randPort;  // set to new random port number
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(portno);
        serv_addr.sin_addr.s_addr = INADDR_ANY;

        // Bind socket to address and start listening
        while (bind(sockfd, (struct sockaddr *) &serv_addr,
               sizeof(serv_addr)) < 0)
        {
          randPort = rand() % (MAX_PORT + 1 - MIN_PORT) + MIN_PORT;
          bzero((char *) &serv_addr, sizeof(serv_addr));
          portno = randPort;  // set to new random port number
          serv_addr.sin_family = AF_INET;
          serv_addr.sin_port = htons(portno);
          serv_addr.sin_addr.s_addr = INADDR_ANY;
        }

        // Send new port number to client
        convertedNum = htonl(randPort);
        returnStatus = write(newsockfd, &convertedNum, sizeof(convertedNum));
        if (returnStatus < 0)
          error("ERROR sending port number to client");

        listen(sockfd, 1); // allow 1 client only
        // Accept client and get new socket file descriptor
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0)
          error("ERROR on accept");

        /******** Start data exchange ********/

        // Read data size of plaintext
        returnStatus = read(newsockfd, &receivedNum, sizeof(receivedNum));
        if (returnStatus > 0)
          receivedNum = ntohl(receivedNum);
        else
          error("ERROR reading data size");
        // Read the plaintext from socket
        readSock(newsockfd, txtBuffer, receivedNum);

        // Read data size of key
        returnStatus = read(newsockfd, &receivedNum, sizeof(receivedNum));
        if (returnStatus > 0)
        {
          receivedNum = ntohl(receivedNum);
        }
        else
          error("ERROR reading data size");
        // Read key from socket
        readSock(newsockfd, keyBuffer, receivedNum);

        // Perform the encryption
        ciphertext = encrypt(txtBuffer, keyBuffer);

        // Write the data size of ciphertext back to the socket
        dataSizeNum = strlen(ciphertext);
        convertedNum = htonl(dataSizeNum);
        returnStatus = write(newsockfd, &convertedNum, sizeof(convertedNum));
        if (returnStatus < 0)
          error("ERROR writing data size");
        // Write ciphertext back to the socket
        writeSock(newsockfd, ciphertext);

        close(newsockfd);
        close(sockfd);
        childExitStatus = 1;
        break;

      default: // Parent: Continue the loop
        break;
    }
  }

  return 0;
}

/*********************************************************************
 ** readSock
 ** Description: Reads data from the specified socket to the specified
 ** buffer. Takes the total data size to be read as a parameter
 ** Parameters: int sockfd, char* buffer, int size
 *********************************************************************/
void readSock(int sockfd, char* buffer, int size)
{
  char tempBuffer[BUFF_SIZE];
  int bytesRead;

  // Read data from socket
  bzero(buffer, BUFF_SIZE);

  do
  {
    bzero(tempBuffer, BUFF_SIZE);
    // Continue reading into temp buffer until buffer length = size
    bytesRead = read(sockfd, tempBuffer, size);
    if (bytesRead < 0)
      error("ERROR reading from socket");

    strcat(buffer, tempBuffer);
  }
  while (strlen(buffer) != size);
}

/*********************************************************************
 ** writeSock
 ** Description: Writes data to the specified socket from the
 ** specified buffer in "chunks" of 1000 bytes.
 ** Parameters: int sockfd, char* buffer
 *********************************************************************/
void writeSock(int sockfd, char* buffer)
{
  int bytesWrit,
      totalBytesWrit = 0,
      dataRemaining = strlen(buffer),
      index,
      tempIndex;
  char tempBuffer[BUFF_SIZE];

  bytesWrit = write(sockfd, buffer, strlen(buffer));
  if (bytesWrit < 0)
    error("ERROR writing to socket");
  else if (bytesWrit < strlen(buffer))
  {
    // Continue to write until all data has been sent
    while (totalBytesWrit != strlen(buffer))
    {
      totalBytesWrit += bytesWrit;
      index = totalBytesWrit + 1;
      tempIndex = 0;
      do
      // Copy remaining data to be written into temp buffer
      {
        tempBuffer[tempIndex] = buffer[index];
        index++;
        tempIndex++;
      } while (buffer[index] != '\0');

      bytesWrit = write(sockfd, tempBuffer, strlen(tempBuffer));
    }
  }
}

/*********************************************************************
 ** encrypt
 ** Description: Encryption is based on 27 possible values: A-Z and
 ** space. Converts ASCII values to values from 0-26.
 ** Parameters: char* plaintext, char* key
 *********************************************************************/
char* encrypt(char* plaintext, char* key)
{
  int plainVal,     // plainVal and keyVal are the ASCII values - 65
      keyVal,       // so values are 0-26 (space = 26)
      encryptedChar,
      index = 0;

  plaintext[strlen(plaintext) - 1] = '\0'; // remove newline

  while (plaintext[index] != '\0')
  {
    // Convert ASCII numbers into vals from 0-26 (space = 26)
    if (plaintext[index] == ASCII_SPACE)
      plainVal = 26;
    else
      plainVal = plaintext[index] - 65;

    if (key[index] == ASCII_SPACE)
      keyVal = 26;
    else
      keyVal = key[index] - 65;

    if (plainVal + keyVal > 27)
      encryptedChar = plainVal + keyVal - 27;
    else
      encryptedChar = (plainVal + keyVal) % 27;
    // Write over the plaintext array with encrypted chars
    // that are converted back into ASCII values
    if (encryptedChar == 26)
      plaintext[index] = ASCII_SPACE;
    else
      plaintext[index] = encryptedChar + 65;

    index++;
  }

  // Add newline back onto string and print result
  int strLength = strlen(plaintext);
  plaintext[strLength] = '\n';
  plaintext[strLength + 1] = '\0';

  return plaintext;
}

/*********************************************************************
 ** error
 ** Description: Displays an error message
 ** Parameters: const char *msg
 *********************************************************************/
void error(const char *msg)
{
  perror(msg);
  exit(1);
}
