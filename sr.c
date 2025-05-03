#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "gbn.h"
#include <string.h>
/* ******************************************************************
   Selective Repeat protocol.  Adapted from J.F.Kurose
   ALTERNATING BIT AND GO-BACK-N NETWORK EMULATOR: VERSION 1.2

   Network properties:
   - one way network delay averages five time units (longer if there
   are other messages in the channel for GBN), but can be larger
   - packets can be corrupted (either the header or the data portion)
   or lost, according to user-defined probabilities
   - packets will be delivered in the order in which they were sent
   (although some can be lost).

   Modifications:
   - removed bidirectional GBN code and other code not used by prac.
   - fixed C style to adhere to current programming style
   - added Selective Repeat implementation
**********************************************************************/

#define RTT 16.0      /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6  /* the maximum number of buffered unacked packet */
#define SEQSPACE 13   /* the min sequence space for SR must be at least 2*windowsize */
#define NOTINUSE (-1) /* used to fill header fields that are not being used */

/* generic procedure to compute the checksum of a packet.  Used by both sender and receiver
   the simulator will overwrite part of your packet with 'z's.  It will not overwrite your
   original checksum.  This procedure must generate a different checksum to the original if
   the packet is corrupted.
*/
int ComputeChecksum(struct pkt packet)
{
  int checksum = 0;
  int i;

  checksum = packet.seqnum;
  checksum += packet.acknum;
  for (i = 0; i < 20; i++)
    checksum += (int)(packet.payload[i]);

  return checksum;
}

bool IsCorrupted(struct pkt packet)
{
  if (packet.checksum == ComputeChecksum(packet))
    return (false);
  else
    return (true);
}

/********* Sender (A) variables and functions ************/

static struct pkt buffer[WINDOWSIZE];  /* array for storing packets waiting for ACK */
static int windowfirst, windowlast;    /* array indexes of the first/last packet awaiting ACK */
static int windowcount;                /* the number of packets currently awaiting an ACK */
static int A_nextseqnum;               /* the next sequence number to be used by the sender */
static int ack_status[WINDOWSIZE];     /* tracks which packets have been ACKed */
static int timer_status[WINDOWSIZE];   /* tracks which packets have active timers */

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

bool is_in_window(int seq_num, int win_base_seq, int seq_space, int win_size)
{
  int next_slot_seq;
  
  if (windowcount == 0)
  {
    return false;
  }
  next_slot_seq = (win_base_seq + win_size) % seq_space;
  if (win_base_seq < next_slot_seq)
  {
    return (seq_num >= win_base_seq && seq_num < next_slot_seq);
  }
  else
  {
    return (seq_num >= win_base_seq || seq_num < next_slot_seq);
  }
}

int get_receiver_buffer_index(int seqnum, int win_base, int seq_space, int win_size_arr) {
  int offset = (seqnum - win_base + seq_space) % seq_space;
  if (offset >= 0 && offset < win_size_arr) {
      return offset;
  }
  return -1;
}

/* called from layer 5 (application layer), passed the message to be sent to other side */
void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;

  /* if not blocked waiting on ACK */
  if (windowcount < WINDOWSIZE)
  {
    if (TRACE > 1)
      printf("----A: New message arrives, send window is not full, send new messge to layer3!\n");

    /* create packet */
    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = A_nextseqnum;
    for (i = 0; i < 20; i++)
      sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    /* put packet in window buffer */
    windowlast = (windowfirst + windowcount) % WINDOWSIZE;
    buffer[windowlast] = sendpkt;
    ack_status[windowlast] = 0;
    timer_status[windowlast] = 1;
    windowcount++;

    /* send out packet */
    if (TRACE > 0)
      printf("Sending packet %d to layer 3\n", sendpkt.seqnum);
    tolayer3(A, sendpkt);

    /* start timer for this packet */
    starttimer(A, RTT);

    /* get next sequence number, wrap back to 0 */
    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  /* if blocked,  window is full */
  else
  {
    if (TRACE > 0)
      printf("----A: New message arrives, send window is full\n");
    window_full++;
  }
}

/* called from layer 3, when a packet arrives for layer 4
   In this practical this will always be an ACK as B never sends data.
*/
void A_input(struct pkt packet)
{
  /* if received ACK is not corrupted */
  if (!IsCorrupted(packet))
  {
    if (TRACE > 0)
      printf("----A: uncorrupted ACK %d is received\n", packet.acknum);
    total_ACKs_received++; 

    if (is_in_window(packet.acknum, buffer[windowfirst].seqnum, SEQSPACE, WINDOWSIZE))
    {
      int index = get_sender_buffer_index(packet.acknum);

      if (index != -1 && !ack_status[index])
      {
        if (TRACE > 0)
          printf("----A: ACK %d is not a duplicate\n", packet.acknum);
        new_ACKs++;
        ack_status[index] = true;
        
        /* Stop timer for this specific packet */
        if (timer_status[index]) {
          stoptimer(A);
          timer_status[index] = 0;
        }

        /* If this is the oldest unacknowledged packet, slide window */
        if (index == windowfirst)
        {
          /* Slide window up to the first unACKed packet */
          while (windowcount > 0 && ack_status[windowfirst])
          {
            ack_status[windowfirst] = false;
            timer_status[windowfirst] = 0;
            windowfirst = (windowfirst + 1) % WINDOWSIZE;
            windowcount--;
          }
          
          /* Restart timer if there are still packets in the window */
          if (windowcount > 0)
          {
            int i;
            /* Find first unacked packet with no timer and start its timer */
            for (i = 0; i < windowcount; i++) {
              int idx = (windowfirst + i) % WINDOWSIZE;
              if (!ack_status[idx] && !timer_status[idx]) {
                timer_status[idx] = 1;
                starttimer(A, RTT);
                break;
              }
            }
          }
        }
      }
      else if (index != -1 && ack_status[index])
      {
        if (TRACE > 0)
          printf("----A: duplicate ACK received, do nothing!\n");
      }
      else
      {
        if (TRACE > 0)
          printf("----A: duplicate ACK received, do nothing!\n");
      }
    }
    else
    { 
      if (TRACE > 0)
        printf("----A: duplicate ACK received, do nothing!\n");
    }
  }
  else
  {
    if (TRACE > 0)
      printf("----A: corrupted ACK is received, do nothing!\n");
  }
}
/* called when A's timer goes off */
void A_timerinterrupt(void)
{
  if (windowcount > 0) {
    /* Find the packet whose timer expired (first unACKed packet) */
    int i;
    for (i = 0; i < windowcount; i++) {
      int idx = (windowfirst + i) % WINDOWSIZE;
      if (!ack_status[idx] && timer_status[idx]) {
        if (TRACE > 0) {
          printf("----A: time out,resend packets!\n");
          printf("---A: resending packet %d\n", buffer[idx].seqnum);
        }
        
        /* Resend just this packet */
        tolayer3(A, buffer[idx]);
        packets_resent++;
        
        /* Restart timer for this packet */
        timer_status[idx] = 1;
        starttimer(A, RTT);
        break;
      }
    }
  }
}

/* the following routine will be called once (only) before any other */
/* entity A routines are called. You can use it to do any initialization */
void A_init(void)
{
  int i;
  A_nextseqnum = 0;
  windowfirst = 0;
  windowlast = -1;
  windowcount = 0;
  for (i = 0; i < WINDOWSIZE; i++) {
      ack_status[i] = false;
  }
}

static int expectedseqnum;
static struct pkt B_rcv_buffer[WINDOWSIZE];
static bool B_received_status[WINDOWSIZE];

void B_input(struct pkt packet)
{
  struct pkt ackpkt;
  int i;
  int buffer_index;

  ackpkt.seqnum = NOTINUSE;
  for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';

  if (IsCorrupted(packet)) {
    if (TRACE > 0) printf("----B: packet corrupted, do nothing\n");
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
     if (TRACE > 0) printf("----B: Received out-of-window packet %d (expected base %d), discarding.\n", packet.seqnum, expectedseqnum);
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
