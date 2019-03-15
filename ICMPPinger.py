from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
ERROR_CODES = {
    "3": [ # Type=3 Destination Unreachable Codes
        "Net is unreachable", # Code=0
        "Host is unreachable", # 1
        "Protocol is unreachable", # 2
        "Port is unreachable", # 3
        "Fragmentation is needed", # 4
        "Source route failed", # 5
        "Destination network is unknown", # 6
        "Destination host is unknown", # 7
        "Source host is isolated", # 8
        "Communication with destination network is administratively prohibited", # 9
        "Communication with destination host is administratively prohibited", # 10
        "Destination network is unreachable for type of service", # 11
        "Destination host is unreachable for type of service", # 12
        "Communication is administratively prohibited", # 13
        "Host precedence violation", # 14
        "Precedence cutoff is in effect" # 15
        ]
}

def checksum(string): 
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(string[count+1]) * 256 + ord(string[count]) 
        csum = csum + thisVal 
        csum = csum & 0xffffffff  
        count = count + 2
    
    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff 
    
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum 
    answer = answer & 0xffff 
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
    
def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    
    icmp = []
    while 1: 
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            icmp.append("Request timed out.")
            return icmp
    
        timeReceived = time.time() 
        recPacket, addr = mySocket.recvfrom(1024)
        
        #Fill in start
        #Fetch the ICMP header from the IP packet
        
        icmp_header = recPacket[20:28]
        # type, code, checksum, packet_id, sequence
        icmp = list(struct.unpack('bbHHh', icmp_header))

        if(icmp[0] != 8 and icmp[1] != 0):
            try:
                icmp.append(ERROR_CODES[str(icmp[0])][icmp[1]])
            except Exception:
                icmp.append("Unknown error Type+Code")
            return icmp
        elif icmp[3] == ID:
            bytes_as_dbl = struct.calcsize('d')
            time_sent = struct.unpack('d', recPacket[28:28 + bytes_as_dbl])[0]
            icmp.append(timeReceived - time_sent)
            return icmp
        else:
            icmp.append('Different ID')
            return icmp


        #Fill in end
        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            icmp.append("Request timed out.")
            return icmp
    
def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    
    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(str(header + data))
    
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff     
    else:
        myChecksum = htons(myChecksum)
        
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    
    mySocket.sendto(packet, (destAddr, 1)) # AF_INET address must be tuple, not str
    # Both LISTS and TUPLES consist of a number of objects
    # which can be referenced by their position number within the object.
    
def doOnePing(destAddr, timeout): 
    icmp = getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details:   
#    http://sock-raw.org/papers/sock_raw

    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    
    myID = os.getpid() & 0xFFFF  # Return the current process i
    sendOnePing(mySocket, destAddr, myID)
    icmp_results = receiveOnePing(mySocket, myID, timeout, destAddr)
    print(icmp_results)
    mySocket.close()
    return icmp_results[-1]

def calcRTTStats(rtt):
    '''
    calculates the min, max, average, mdev of RTT times
    '''
    minimum = 1.0
    maximum = 0.0
    average = 0.0
    total = 0.0
    valid_count = len(rtt)

    for triptime in rtt:
        try:
            float(triptime)
        except ValueError:
            valid_count -= 1
            continue
        minimum = min(minimum, triptime)
        maximum = max(maximum, triptime)
        total += triptime
    if valid_count:
        average = total/valid_count

    print("RTT min / max / avg / packetloss")
    print("{} / {} / {} / {} %".format(minimum, maximum, average,
        ((valid_count-len(rtt))/len(rtt))))
    
def ping(host, timeout=1, count=10):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:")
    # Send ping requests to a server separated by approximately one second
    # while 1 :
    #     delay = doOnePing(dest, timeout)
    #     print(delay)
    #     time.sleep(1)# one second
    # return delay
    
    rtt = []
    for i in range(count):
        delay = doOnePing(dest, timeout)
        # print(delay)
        rtt.append(delay)
        time.sleep(1)

    calcRTTStats(rtt)
    

tests = {
    "local": "localhost",
    "Google": "google.com",
    "UK": "bbc.co.uk",
    "Japan": "rakuten.co.jp",
    "Australia": "commbank.com.au",
    "Africa": "lol.co.za"
}

for name,test in tests.items():
    print("")
    print(name+": "+test)
    ping(test)
print("")
