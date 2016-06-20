/*********************************************************************
 ** Program Filename: otp_dec_d.c
 ** Author: Peter Nguyen
 ** Date: 3/14/16
 ** CS 344-400, Program 4
 ** Description: Daemon that performs one-time pad decryption
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
char* decrypt(char* cyphertext, char* key);

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
  char* plaintext;
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
    error("ERROR on binding");
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
      // Send valid identifier to otp_dec
      dataSizeNum = 2;
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

        // Read data size of ciphertext
        returnStatus = read(newsockfd, &receivedNum, sizeof(receivedNum));
        if (returnStatus > 0)
          receivedNum = ntohl(receivedNum);
        else
          error("ERROR reading data size");
        // Read the ciphertext from socket
        readSock(newsockfd, txtBuffer, receivedNum);

        // Read data size of key
        returnStatus = read(newsockfd, &receivedNum, sizeof(receivedNum));
        if (returnStatus > 0)
          receivedNum = ntohl(receivedNum);
        else
          error("ERROR reading data size");
        // Read key from socket
        readSock(newsockfd, keyBuffer, receivedNum);

        // Perform the decryption
        plaintext = decrypt(txtBuffer, keyBuffer);

        // Write the data size of plaintext back to the socket
        dataSizeNum = strlen(plaintext);
        convertedNum = htonl(dataSizeNum);
        returnStatus = write(newsockfd, &convertedNum, sizeof(convertedNum));
        if (returnStatus < 0)
          error("ERROR writing data size");
        // Write plaintext back to the socket
        writeSock(newsockfd, plaintext);

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
      // Copy remaining data to be written until temp buffer
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
 ** decrypt
 ** Description: Encryption is based on 27 possible values: A-Z and
 ** space. Converts ASCII values to values from 0-26.
 *********************************************************************/
char* decrypt(char* ciphertext, char* key)
{
  int cipherVal,     // cipherVal and keyVal are the ASCII values - 65
      keyVal,        // so values are 0-26 (space = 26)
      decryptedChar,
      index = 0;

  ciphertext[strlen(ciphertext) - 1] = '\0'; // remove newline

  while (ciphertext[index] != '\0')
  {
    // Convert ASCII numbers into vals from 0-26 (space = 26)
    if (ciphertext[index] == ASCII_SPACE)
      cipherVal = 26;
    else
      cipherVal = ciphertext[index] - 65;

    if (key[index] == ASCII_SPACE)
      keyVal = 26;
    else
      keyVal = key[index] - 65;

    if (cipherVal - keyVal < 0)
      decryptedChar = cipherVal - keyVal + 27;
    else
      decryptedChar = (cipherVal - keyVal) % 27;
    // Write over the ciphertext array with decrypted chars
    // that are converted back into ASCII values
    if (decryptedChar == 26)
      ciphertext[index] = ASCII_SPACE;
    else
      ciphertext[index] = decryptedChar + 65;

    index++;
  }

  // Add newline back onto string and print result
  int strLength = strlen(ciphertext);
  ciphertext[strLength] = '\n';
  ciphertext[strLength + 1] = '\0';

  return ciphertext;
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
