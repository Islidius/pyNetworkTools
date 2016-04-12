# a graphic view for pings ( you need root right to create the icmp socket)
# usage: python graphic_ping.pyw ipadress ipadress ...
# eg. : python graphic_ping.pyw 134.10.12.3 8.8.8.8 123.5.6.2
# command line arguments -t=timeout , -m=maxElements (no space)
# eg. : python graphic_ping.paw 134.10.21.3 -t=10 -m=20


# created by Fabian (Islidius)

# the scale is orientated after the max elements

# Advise:
# Dont call with more than 3 ipadresses (doesnt fit the 1080 pixel)

# TODO:
# add command line arguments to change ping parameters

from Tkinter import *
import os,sys,socket,struct,select,time
from thread import start_new_thread,allocate_lock

pings = [] # ping array for all connections dim = 2
names = [] # name array for connections

maxDelay = 0 # for scale
yHeight = 190 # height of the basrs
yOffset = 30 # space between the graphs
yGlobalOffset = 10 # offset from border

xOffset = 20 # offset from border
xShift = 20 # additional space from left border
xWidth = 2 # width of one bar

maxElements = 460 # maximal count of elements

timeoutGlobal = 1 # the timeout in secs

running = True
runninglock = allocate_lock()

printlock = allocate_lock()

def getTime():
    return time.clock()

def calcChecksum(string):
    csum = 0
    endlen = len(string)- len(string)%2 # even out count
    count = 0
    while count < endlen: # add up 16 bits 
        csum += (ord(string[count + 1]) << 8) + ord(string[count])
        count = count + 2

    if len(string)%2 != 0: # not even count
        csum += ord(string[len(string) - 1])

    csum = (csum >> 16)  +  (csum & 0xFFFF) # shift add
    answer =( ~(csum + (csum >> 16))) & 0xFFFF # shift add and complements

    return answer

def receivePings(sock,osId,timeout):
    timeleft = timeout # set the time left to timeout
    delays = []
    for i in range(len(names)): #init delays
        delays.append(-1)

        
    while True:
        starttime = getTime()
        ready = select.select([sock],[],[],timeleft) # wait for packet
        timepassed = getTime() - starttime

        if ready[0] == []: # timeout
            return delays

        timereceived = getTime()
        packet , addr = sock.recvfrom(1024)

        if not addr[0] in names: # for bugs
            continue
        
        icmpType , code, checksum , packetID , sequence = struct.unpack("bbHHh",packet[20 : 28])

        if not calcChecksum(packet[20 : 28 + 9]) == 0: # wrong checksum
            continue 

        if icmpType == 0 and packetID == osId: # echo reply imcpType == 0
            timesent, addrId = struct.unpack("db",packet[28 : 28 + 9]) #data
            delays[addrId] = timereceived - timesent

        timeleft = timeleft - timepassed
        if timeleft <= 0: # timeout
           return delays

def sendPings(sock, addresses,osId):
    for addrId in range(len(addresses)): # iterate the adrresses

        header = struct.pack("bbHHh",8,0,0,osId,1) # chechsum is 0
        data = struct.pack("db",getTime(),addrId,) # set time and id

        checksum = calcChecksum(header + data)

        header = struct.pack("bbHHh",8,0,checksum,osId,1) # new header
        sock.sendto(header + data,(addresses[addrId],1))

def pingAndReceive(addresses,timeout):
    icmp_proto = socket.getprotobyname("icmp")
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,icmp_proto)
    except:
        raise

    osID = os.getpid() & 0xFFFF

    sendPings(sock,addresses,osID)
    delays = receivePings(sock,osID,1)

    sock.close()
    return delays

def display():
    w.delete(ALL)

    x = xOffset + xShift
    y = yGlobalOffset
    off = 0

    printlock.acquire()
    for arr in pings:
        y += yHeight
        x = xOffset + xShift

        w.create_text(x-4,y - yHeight,text = "{:.1f}".format(maxDelay * 1000),anchor = E)
        w.create_text(x-4,y - yHeight / 2,text = "{:.1f}".format(maxDelay * 500),anchor = E)
        w.create_text(x-4,y,text = "0.0",anchor = E)

        w.create_text(x + maxElements * xWidth,y + 1,text = "{:.1f} min".format(timeoutGlobal * maxElements/60),anchor = NE)
        
        w.create_text(x,y,text = names[off],anchor = NW) # text
        w.create_line(x,y,x + maxElements * xWidth,y) # base line
        w.create_line(x,y,x,y - yHeight)
        
        for i in arr:
            if i != -1:
                w.create_rectangle(x , y , x + xWidth -2 , y - (i / maxDelay) * yHeight,fill = "black")
            else:
                w.create_rectangle(x , y , x + xWidth -2, y - yHeight,fill = "red",outline = "red")
            x += xWidth
        y += yOffset
        off += 1
    printlock.release()

def init():
    global timeoutGlobal,maxElements
    count = len(sys.argv) - 1
    for i in range(count): # get the arguments
        command = sys.argv[i + 1]
        if command.startswith("-t="):
            timeoutGlobal = float(command[3:]) # timeout command
        elif command.startswith("-m="):
            maxElements = int(command[3:]) # max Elements command
        else:
            names.append(sys.argv[i + 1])
            pings.append([])

def threadloop():
    global val,pings,names,maxDelay

    timeout = timeoutGlobal
    st = getTime()

    while(True):
        de = getTime()
        try:
            delays = pingAndReceive(names,timeout) # ping
        except socket.gaierror, e:
            print "ERROR"

        if timeout - (getTime() - de) > 0:
            time.sleep(timeout - (getTime() - de)) # time lock
        #time.sleep(timeout - (getTime() - de))
        #print getTime() - de

        printlock.acquire()
        
        for i in range(len(names)):
            pings[i].append(delays[i])

            if len(pings[i]) > maxElements: # shift
                pings[i] = pings[i][1:]

        maxDelay = 0
        for i in pings:
            for j in i:
                maxDelay = max(maxDelay,j) # get max Delay for scale
                
        printlock.release()

        runninglock.acquire()
        if(not running):
            break
        runninglock.release()

    runninglock.release()
    
def loop(): # refresh the canvas
    display()
    tk.after(100,loop)
    
def onClose(): #close window and thread
    runninglock.acquire()
    running = False
    runninglock.release()
    tk.destroy()

init()

tk = Tk()

title = "Pings for: "
for s in names:
    title += s +"   "

tk.wm_title(title)

tk.protocol("WM_DELETE_WINDOW",onClose)

w = Canvas(tk,width = maxElements * xWidth + 2 * xOffset + xShift, height = len(names) * (yOffset + yHeight) + yGlobalOffset)
w.pack()

start_new_thread(threadloop,())

loop()

mainloop()
