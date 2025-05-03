#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 13
#define NOTINUSE (-1)

static int windowcount;
static int windowfirst;

static struct pkt buffer[WINDOWSIZE];
static int windowlast;
static int A_nextseqnum;
static bool A_ack_status[WINDOWSIZE];

static int expectedseqnum;
static struct pkt B_rcv_buffer[WINDOWSIZE];
static bool B_received_status[WINDOWSIZE];


int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;
  checksum = packet.seqnum;
  checksum += packet.acknum;
  for (i = 0; i < 20; i++) checksum += (int)(packet.payload[i]);
  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet)) return (false);
  else return (true);
}


bool is_in_window(int seq_num, int win_base, int seq_space, int win_size) {
    int seq_after_window;
    bool is_sender_check = (win_size == WINDOWSIZE && win_base == windowfirst);

    if (is_sender_check && windowcount == 0) return false;
    if (!is_sender_check && win_size == 0 && expectedseqnum == win_base) return false;


    seq_after_window = (win_base + win_size) % seq_space;
    if (win_base < seq_after_window) { 
        return (seq_num >= win_base && seq_num < seq_after_window);
    } else { 
        return (seq_num >= win_base || seq_num < seq_after_window);
    }
}

int get_sender_buffer_index(int seqnum) {
    int i;
    int current_index;
    for (i = 0; i < windowcount; i++) {
        current_index = (windowfirst + i) % WINDOWSIZE;
        if (buffer[current_index].seqnum == seqnum) {
            return current_index;
        }
    }
    return -1;
}

int get_receiver_buffer_index(int seqnum, int win_base_seq, int seq_space, int win_size_arr) {
    int offset = (seqnum - win_base_seq + seq_space) % seq_space;
    if (offset >= 0 && offset < win_size_arr) {
        return offset;
    }
    return -1;
}


/********* Sender (A) functions ************/

void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;
  int insert_index;

  if (windowcount < WINDOWSIZE)
  {
    if (TRACE > 1) printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    insert_index = (windowfirst + windowcount) % WINDOWSIZE;
    buffer[insert_index] = sendpkt;
    A_ack_status[insert_index] = false;
    windowlast = insert_index;
    windowcount++;
    if (TRACE > 0) printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);
    if (windowcount == 1) {
        if (TRACE > 1) printf("          START TIMER: starting timer\n");
        starttimer(A, RTT);
    }
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  else
  {
    if (TRACE > 0) printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

void A_input(struct pkt packet)
{
    int index;

    if (!IsCorrupted(packet))
    {
        if (TRACE > 0) printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
        total_ACKs_received++;
        if (is_in_window(packet.acknum, buffer[windowfirst].seqnum, SEQSPACE, WINDOWSIZE))
        {
            index = get_sender_buffer_index(packet.acknum);
            if (index != -1 && !A_ack_status[index])
            {
                if (TRACE > 0) printf("----A: ACK %d is not a duplicate\n", packet.acknum);
                new_ACKs++;
                A_ack_status[index] = true;
                if (index == windowfirst)
                {
                    if (TRACE > 1) printf("          STOP TIMER: stopping timer\n");
                    stoptimer(A);
                    while (windowcount > 0 && A_ack_status[windowfirst])
                    {
                        A_ack_status[windowfirst] = false;
                        windowfirst = (windowfirst + 1) % WINDOWSIZE;
                        windowcount--;
                    }
                    if (windowcount > 0)
                    {
                        if (TRACE > 1) printf("          START TIMER: starting timer\n");
                        starttimer(A, RTT);
                    }
                }
            }
            else if (index != -1 && A_ack_status[index])
            {
                if (TRACE > 0) printf("----A: duplicate ACK received, do nothing!\n");
            }
            else
            {
                if (TRACE > 0) printf("----A: duplicate ACK received, do nothing!\n");
            }
        }
        else
        {
            if (TRACE > 0) printf("----A: duplicate ACK received, do nothing!\n");
        }
    }
    else if (TRACE > 0)
    {
        printf("----A: corrupted ACK is received, do nothing!\n");
    }
}

void A_timerinterrupt(void)
{
    int oldest_packet_index;

    if (windowcount > 0) {
        oldest_packet_index = windowfirst;
        if (TRACE > 0) {
            printf("----A: time out,resend packets!\n");
            printf("---A: resending packet %d\n", buffer[oldest_packet_index].seqnum);
        }
        tolayer3(A, buffer[oldest_packet_index]);
        packets_resent++;
        starttimer(A, RTT);
        if (TRACE > 1) printf("          START TIMER: starting timer\n");
    }
}

void A_init(void)
{
  int i;
  A_nextseqnum = 0;
  windowfirst = 0;
  windowlast = -1;
  windowcount = 0;
  for (i = 0; i < WINDOWSIZE; i++) {
      A_ack_status[i] = false;
  }
}


/********* Receiver (B) functions ************/

void B_input(struct pkt packet)
{
  struct pkt ackpkt;
  int i;
  int buffer_index;

  ackpkt.seqnum = NOTINUSE;
  for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';

  if (IsCorrupted(packet)) {
    if (TRACE > 1) printf("----B: packet corrupted, discarding\n");
    return;
  }

  if (is_in_window(packet.seqnum, expectedseqnum, SEQSPACE, WINDOWSIZE))
  {
      buffer_index = get_receiver_buffer_index(packet.seqnum, expectedseqnum, SEQSPACE, WINDOWSIZE);
      if (buffer_index != -1) {
          ackpkt.acknum = packet.seqnum;
          ackpkt.checksum = ComputeChecksum(ackpkt);
          tolayer3(B, ackpkt);
          if (TRACE > 0) printf("----B: packet %d received, sent ACK %d.\n", packet.seqnum, packet.seqnum);

          if (!B_received_status[buffer_index]) {
              B_rcv_buffer[buffer_index] = packet;
              B_received_status[buffer_index] = true;
              packets_received++;
              if (TRACE > 1) printf("----B: Buffered packet %d at index %d.\n", packet.seqnum, buffer_index);
          } else {
               if (TRACE > 1) printf("----B: Duplicate packet %d received (already buffered).\n", packet.seqnum);
          }

          while (B_received_status[0]) {
              if (TRACE > 0) printf("----B: Delivering packet %d (seq %d) from buffer to layer 5.\n", B_rcv_buffer[0].seqnum, expectedseqnum);
              tolayer5(B, B_rcv_buffer[0].payload);
              B_received_status[0] = false;
              expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
              memmove(&B_rcv_buffer[0], &B_rcv_buffer[1], sizeof(struct pkt) * (WINDOWSIZE - 1));
              memmove(&B_received_status[0], &B_received_status[1], sizeof(bool) * (WINDOWSIZE - 1));
              B_received_status[WINDOWSIZE - 1] = false;
              if (TRACE > 1) printf("----B: Advanced receive window base to %d.\n", expectedseqnum);
          }
      } else {
            if (TRACE > 0) printf("----B: Error calculating buffer index for in-window packet %d\n", packet.seqnum);
      }
  }
  else if (is_in_window(packet.seqnum, (expectedseqnum - WINDOWSIZE + SEQSPACE) % SEQSPACE, SEQSPACE, WINDOWSIZE))
  {
     if (TRACE > 0) printf("----B: Received old packet %d (expected base %d), resending ACK %d.\n", packet.seqnum, expectedseqnum, packet.seqnum);
     ackpkt.acknum = packet.seqnum;
     ackpkt.checksum = ComputeChecksum(ackpkt);
     tolayer3(B, ackpkt);
  }
  else
  {
     if (TRACE > 1) printf("----B: Received out-of-window packet %d (expected base %d), discarding.\n", packet.seqnum, expectedseqnum);
  }
}

void B_init(void)
{
  int i;
  expectedseqnum = 0;
  for (i = 0; i < WINDOWSIZE; i++) {
      B_received_status[i] = false;
  }
}

void B_output(struct msg message) { }
void B_timerinterrupt(void) { }