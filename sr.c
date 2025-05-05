#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "emulator.h"
#include "sr.h"

#define RTT 16.0
#define WINDOWSIZE 6
#define SEQSPACE 20
#define NOTINUSE (-1)

static struct pkt A_send_buffer[SEQSPACE];
static bool A_acked_status[SEQSPACE];
static int send_base;
static int A_nextseqnum;

static int expectedseqnum;
static struct pkt B_recv_buffer[SEQSPACE];

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

bool is_seq_in_window(int seq_num, int win_base, int win_size, int seq_space) {
    int win_end = (win_base + win_size) % seq_space;
    if (win_base < win_end) {
        return (seq_num >= win_base && seq_num < win_end);
    } else {
        return (seq_num >= win_base || seq_num < win_end);
    }
}

void A_init(void)
{
  int i;
  A_nextseqnum = 0;
  send_base = 0;
  for (i = 0; i < SEQSPACE; i++) {
      A_acked_status[i] = false;
  }
}

void A_output(struct msg message)
{
  struct pkt sendpkt;
  int i;
  int buffered_count = (A_nextseqnum - send_base + SEQSPACE) % SEQSPACE;

  if (buffered_count < WINDOWSIZE)
  {
    if (TRACE > 1) printf("----A: New message arrives, send window is not full, send new messge to layer3!\n"); // Keep: From A

    sendpkt.seqnum = A_nextseqnum;
    sendpkt.acknum = NOTINUSE;
    for (i = 0; i < 20; i++) sendpkt.payload[i] = message.data[i];
    sendpkt.checksum = ComputeChecksum(sendpkt);

    A_send_buffer[A_nextseqnum % SEQSPACE] = sendpkt;
    A_acked_status[A_nextseqnum % SEQSPACE] = false;

    if (TRACE > 0) printf("Sending packet %d to layer 3\n", sendpkt.seqnum); // Keep: From A
    tolayer3(A, sendpkt);

    if (send_base == A_nextseqnum) {
        starttimer(A, RTT);
    }

    A_nextseqnum = (A_nextseqnum + 1) % SEQSPACE;
  }
  else
  {
    if (TRACE > 0) printf("----A: New message arrives, send window is full\n"); // Keep: From A
    window_full++;
  }
}

void A_input(struct pkt packet)
{
    if (IsCorrupted(packet))
    {
       if (TRACE > 0) printf ("----A: corrupted ACK is received, do nothing!\n"); // Keep: From A
       return;
    }

    if (TRACE > 0) printf("----A: uncorrupted ACK %d is received\n", packet.acknum); // Keep: From A
    total_ACKs_received++;

    bool in_window = false;
    if (send_base <= A_nextseqnum) {
        in_window = (packet.acknum >= send_base && packet.acknum < A_nextseqnum);
    } else {
        in_window = (packet.acknum >= send_base || packet.acknum < A_nextseqnum);
    }

    if (!in_window) {
        return;
    }

    int ack_index = packet.acknum % SEQSPACE;

    if (A_acked_status[ack_index]) {
       if (TRACE > 0) printf ("----A: duplicate ACK %d received, do nothing!\n"); // Keep: From A
       return;
    }

    if (TRACE > 0) printf("----A: ACK %d is not a duplicate\n", packet.acknum); // Keep: From A
    A_acked_status[ack_index] = true;
    new_ACKs++;

    if (packet.acknum == send_base) {
        stoptimer(A);

        while (send_base != A_nextseqnum && A_acked_status[send_base % SEQSPACE] == true) {
            A_acked_status[send_base % SEQSPACE] = false;
            send_base = (send_base + 1) % SEQSPACE;
        }

        if (send_base != A_nextseqnum) {
            starttimer(A, RTT);
        }
    }
}


void A_timerinterrupt(void)
{
    if (send_base == A_nextseqnum) {
         return;
    }

    int base_index = send_base % SEQSPACE;
    struct pkt base_packet = A_send_buffer[base_index];

    if (TRACE > 0) {
        printf("----A: time out, resend packets!\n"); // Keep: From A
        printf("---A: resending packet %d\n", base_packet.seqnum); // Keep: From A
    }

    tolayer3(A, base_packet);
    packets_resent++;

    starttimer(A, RTT);
}

void B_init(void)
{
  int i;
  expectedseqnum = 0;
  for (i = 0; i < SEQSPACE; i++) {
      B_recv_buffer[i].seqnum = NOTINUSE;
  }
}

void B_input(struct pkt packet)
{
  struct pkt ackpkt;
  int i;

  if (IsCorrupted(packet)) {
    return;
  }

  if (TRACE > 0) printf("----B: packet %d is correctly received, send ACK!\n",packet.seqnum); // Keep: From A
  packets_received++;

  bool in_recv_window = is_seq_in_window(packet.seqnum, expectedseqnum, WINDOWSIZE, SEQSPACE);
  bool in_lower_window = is_seq_in_window(packet.seqnum, (expectedseqnum - WINDOWSIZE + SEQSPACE) % SEQSPACE, WINDOWSIZE, SEQSPACE);

  if (in_recv_window) {

      ackpkt.seqnum = NOTINUSE;
      ackpkt.acknum = packet.seqnum;
      for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
      ackpkt.checksum = ComputeChecksum(ackpkt);
      tolayer3(B, ackpkt);

      int buffer_index = packet.seqnum % SEQSPACE;
      if (B_recv_buffer[buffer_index].seqnum == NOTINUSE) {
          B_recv_buffer[buffer_index] = packet;

          while (B_recv_buffer[expectedseqnum % SEQSPACE].seqnum != NOTINUSE) {
              tolayer5(B, B_recv_buffer[expectedseqnum % SEQSPACE].payload);
              B_recv_buffer[expectedseqnum % SEQSPACE].seqnum = NOTINUSE;
              expectedseqnum = (expectedseqnum + 1) % SEQSPACE;
          }
      }
      return;
  }

  if (in_lower_window) {
      ackpkt.seqnum = NOTINUSE;
      ackpkt.acknum = packet.seqnum;
      for (i = 0; i < 20; i++) ackpkt.payload[i] = '0';
      ackpkt.checksum = ComputeChecksum(ackpkt);
      tolayer3(B, ackpkt);
      return;
  }

  return;
}

void B_output(struct msg message)
{
}

void B_timerinterrupt(void)
{
}