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


static struct pkt buffer[WINDOWSIZE];
static int windowfirst, windowlast;
static int windowcount;
static int A_nextseqnum;
static bool A_ack_status[WINDOWSIZE];
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

bool is_in_send_window(int seq_num, int win_base_seq, int seq_space, int win_size)
{
  if (windowcount == 0)
  {
    return false;
  }
  int next_slot_seq = (win_base_seq + win_size) % seq_space;
  if (win_base_seq < next_slot_seq)
  {
    return (seq_num >= win_base_seq && seq_num < next_slot_seq);
  }
  else
  {
    return (seq_num >= win_base_seq || seq_num < next_slot_seq);
  }
}


/********* Sender (A) variables and functions ************/

static struct pkt buffer[WINDOWSIZE];
static int windowfirst, windowlast;
static int A_nextseqnum;
static int ack_status[WINDOWSIZE];

int get_sender_buffer_index(int seqnum)
{
  int i;
  for (i = 0; i < windowcount; i++)
  {
    int current_index = (windowfirst + i) % WINDOWSIZE;
    if (buffer[current_index].seqnum == seqnum)
    {
      return current_index;
    }
  }
  return -1;
}


void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  if (windowcount < WINDOWSIZE)
  {
    if (TRACE > 1) printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    sendpkt.seqnum = A_nextseqnum;

    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    windowlast = (windowfirst + windowcount) % WINDOWSIZE;
    buffer[windowlast] = sendpkt;
    ack_status[windowlast] = 0;
    windowcount++;

    if (TRACE > 0) printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    if (windowcount == 1) {
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
  if (!IsCorrupted(packet))
  {
    if (TRACE > 0) printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++;

    if (is_in_send_window(packet.acknum, buffer[windowfirst].seqnum, SEQSPACE, WINDOWSIZE))
    {
      int index = get_sender_buffer_index(packet.acknum);

      if (index != -1 && ack_status[index] == 0)
      {
        if (TRACE > 0) printf("----A: ACK %d is not a duplicate\n", packet.acknum);
        new_ACKs++;
        ack_status[index] = 1;
        if (index == windowfirst)
        {
          stoptimer(A);

          while (windowcount > 0 && ack_status[windowfirst] == 1)
          {
            ack_status[windowfirst] = 0;
            windowfirst = (windowfirst + 1) % WINDOWSIZE;
            windowcount--;
          }

          if (windowcount > 0)
          {
            starttimer(A, RTT);
          }
        }
      }
      else if (index != -1 && ack_status[index] == 1)
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
  else
  {
    if (TRACE > 0) printf("----A: corrupted ACK is received, do nothing!\n");
  }
}

/* called when A's timer goes off */
void A_timerinterrupt(void)
{
  if (windowcount > 0) {
    int oldest_packet_index = windowfirst;

    if (TRACE > 0) {
        printf("----A: time out,resend packets!\n");
        printf("---A: resending packet %d\n", buffer[oldest_packet_index].seqnum);
    }
    tolayer3(A, buffer[oldest_packet_index]);
    packets_resent++;
    starttimer(A, RTT);
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
      ack_status[i] = 0;
  }
}


/********* Receiver (B) variables and procedures - REVERTED TO GBN ************/

static int expectedseqnum;
static int B_nextseqnum;

/* Reverted to original GBN B_input */
void B_input(struct pkt packet)
{
  struct pkt sendpkt;
  int i;

  if ((!IsCorrupted(packet)) && (packet.seqnum == expectedseqnum))
  {
    if (TRACE > 0) printf("----B: packet %d is correctly received, send ACK!\n", packet.seqnum);
    packets_received++;
    tolayer5(B, packet.payload);
    sendpkt.acknum = expectedseqnum;
    expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
  }
  else
  {
    if (TRACE > 0) printf("----B: packet corrupted or not expected sequence number, resend ACK!\n");
    if (expectedseqnum == 0) sendpkt.acknum = SEQSPACE - 1;
    else sendpkt.acknum = expectedseqnum - 1;
  }

  sendpkt.seqnum = B_nextseqnum;
  B_nextseqnum = (B_nextseqnum + 1) % 2;
  for (i = 0; i < 20; i++) sendpkt.payload[i] = '0';
  sendpkt.checksum = ComputeChecksum(sendpkt);
  tolayer3(B, sendpkt);
}

/* Reverted to original GBN B_init */
void B_init(void)
{
  expectedseqnum = 0;
  B_nextseqnum = 1;
}

/******************************************************************************
 * The following functions need be completed only for bi-directional messages *
 *****************************************************************************/

void B_output(struct msg message) { }

/* Reverted to original (buggy) B_timerinterrupt */
void B_timerinterrupt(void)
{
  int i;
  if (TRACE > 0) printf("----A: time out,resend packets!\n");
  for (i = 0; i < windowcount; i++)
  {
    if (TRACE > 0) printf("---A: resending packet %d\n", (buffer[(windowfirst + i) % WINDOWSIZE]).seqnum); 
    tolayer3(A, buffer[(windowfirst + i) % WINDOWSIZE]);
    packets_resent++;
    if (i == 0) starttimer(B, RTT);
  }
}
