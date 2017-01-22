#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include "analysis.h"


pthread_mutex_t muxlock = PTHREAD_MUTEX_INITIALIZER;  //Initializing a mutex lock to ensure thread safety
pthread_t threads[10]; //Creating a persistent pool of 10 threads
int i = 0; //A global int used to ensure that the threads are only initialized on the first call to dispatch
int verb;

//A global persistent queue of work for the thread pool (non-initialized)
struct linked_list * queue;

/*In order to make use of a persistent thread pool a queue must be used to store the work for the threads.
 * A linked list can be used to implement a queue by adding elements to the tail and only removing the header (LILO format)
 * In this case the queue contains all the packet data needed for the analyse function.
 * Once an element has been analysed each thread will wait for the next packet before it is designated to one.
 * If the queue is non-empty the packet data is added to the end of the queue.
 * */

//A structure used to store all packet data used by analyse that will be added to the queue
struct arg_struct {
 struct pcap_pkthdr *hdr;
 const unsigned char *pkt;
};

//To implement a linked list the below element structure is used to specify what is held within the linked list along with a pointer to the next element
struct element {
 struct element * next;
 struct arg_struct data; 
};

//A structure to define the linked list. All that is required is a pointer to the head, as the head will contain a pointer to the next element of the list.
struct linked_list {
 struct element * head;
};

//The addData() function is used to add an element to the head of the list if the list is empty, and to the tail otherwise
void addData(struct linked_list * inQueue, struct arg_struct inData){ //Inputs are the list the element is to be added to and the element data
  struct element * newData = malloc(sizeof(struct element)); //Initializing a new element structure
  newData->data = inData; //Adding the input data to the structure
  newData->next = NULL;
  pthread_mutex_lock(&muxlock); //Mutex lock to ensure thread safety
  if (inQueue->head == NULL){ //If the list is empty then add the new element as the head
   inQueue->head = newData; 
  }
  else {
    struct element * currEle = inQueue->head; //Otherwise cycle through the list until the tail is found
    while (currEle->next != NULL){
      currEle = currEle->next; 
    }
    currEle->next = newData; //Add a pointer to the new data at the tail of the list
  }
  pthread_mutex_unlock(&muxlock); //Unlock & continue
}

//The removeHead() function is used when a thread takes a packet to be analysed. When this occurs the head of the list is changed to be the next element in the list
//As a slight optimisation the removeHead also returns the current head of the list before altering it
struct arg_struct removeHead(struct linked_list * inQueue){
   struct arg_struct temp = inQueue->head->data; //Temp structure to be returned
   inQueue->head = inQueue->head->next; //Change head of list
   return temp; //Return old head
}

/*The analysisthread function is used by the threads to create a persistent cycle of checking the queue and removing elements to be analysed.
 * The threads initially create a structure to contain the current head of the queue before entering a continuous cycle.
 * The cycle checks if the head is empty, if so then the thread sleeps for one seconds before checking again.
 * If the head contains packet data then this is passed to the analyse function.
 * Mutex locks are used to ensure thread safety.*/

void *analysisthread(void *arguments){
 struct arg_struct qHead; //Structure to hold queue head
 while(1){ //While(1) creates a continuous cycle
   pthread_mutex_lock(&muxlock); //Mutex lock to ensure thread safety
   if (queue->head == NULL){ //If the head is empty then the thread unlocks the mutex lock and sleeps
    pthread_mutex_unlock(&muxlock);
    printf("\nWaiting...Thread: %d", (int) pthread_self());
    sleep(1);
   }
   else{ //Otherwise the head of the queue is analysed
    qHead = removeHead(queue);
    pthread_mutex_unlock(&muxlock);
    printf("\nOn...Thread: %d", (int) pthread_self());
    analyse(qHead.hdr, qHead.pkt, verb);
   }
  }
}

//The initThreads function is used to initialize the thread pool along with the global queue
void initThreads(){
 int j;
 queue = malloc(sizeof(struct linked_list)); 
 for (j = 0; j < 10; j++){
   pthread_create(&threads[j], NULL, &analysisthread, (void *)&queue); 
 }
}

// The dispatch function itself is used to add a packet to the queue
void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  if (i == 0){ //Upon the first call of the dispatch function the threads and the queue are initialized
   initThreads();
   i++; //Incrementing the global int variable to ensure the threads/queue are only initialized once
   verb = verbose;
  }
  //To avoid packet data being corrupted, possibly by threads, a copy of the packet data is created before being added to an arg_struct to be added to the queue
  struct pcap_pkthdr * header_cpy = malloc(sizeof(struct pcap_pkthdr));
  memcpy(header_cpy, header, sizeof(struct pcap_pkthdr));
  unsigned char* pkt_cpy = malloc(header->caplen);
  memcpy(pkt_cpy, packet, header->caplen);
  
  //Next the arg_struct is created before being added to the queue
  struct arg_struct pktargs;
  pktargs.hdr = header_cpy;
  pktargs.pkt = pkt_cpy;
  
  addData(queue, pktargs);
}


