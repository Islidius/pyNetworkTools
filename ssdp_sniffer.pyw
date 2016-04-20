# SSDP passive Sniffer
# scanns the Lan for SSDP notify packets and shows the information
# in a Tree (it will show Location , Devices , Services)
#
# it does not need root privilges to run
#
# Created by Fabian (Islidius)
#
# TODO:
#  - Scroll Pane
#  - making the parser safe


import socket,struct
from thread import start_new_thread,allocate_lock
from Tkinter import *
import ttk

MCAST_GRP = '239.255.255.250'
MCAST_PORT = 1900

record = {}
trec = {}

running = True
runninglock = allocate_lock()

def parseFields(lines,out): # making key value pairs
    for l in lines:
        if not l == "":
            if l.count(":") >= 1:
                com,arg = l.split(":",1)
                out[1][com.lower()] = arg.lstrip()

def parsePacket(s): # parse a complete packet
    lines = s.split("\n")
    if lines[0].startswith("M-SEARCH"):
        out = ("search",{})
    elif lines[0].startswith("NOTIFY"):
        out = ("notify",{})

    parseFields(lines[1:],out)
    
    return out


def parseNTurn(urn):
    diff = urn.split(":")
    return ("urn",diff[len(diff) - 3],diff[len(diff) - 2])

def parseNTuuid(uuid):
    diff = uuid.split(":")
    return ("uuid",diff[len(diff) - 2],diff[len(diff) - 1])

def parseNTupnp(upnp):
    return ("upnp","rootdevice")

def parseNT(nt): # parse the NT field
    if nt.startswith("urn"):
        return parseNTurn(nt)
    elif nt.startswith("uuid"):
        return parseNTuuid(nt)
    elif nt.startswith("upnp"):
        return parseNTupnp(nt)
    else:
        return "FAIL"

def getuuid(packet): # extract uuid form usn
    return packet[1]["usn"].split(":")[1].rstrip()


def listen(): # listen and add to tree
    global record,runninglock
    while True:
        s = sock.recv(10240)
        packet = parsePacket(s)
        if packet[0] == "notify": # only parse notify packets
            uuid = getuuid(packet)
            if not uuid in record.keys(): # first time this uuid
                record[uuid] = {} # needed for further features
                record[uuid]["device"] = [] 
                record[uuid]["service"] = []
                record[uuid]["location"] = packet[1]["location"]

                i = tree.insert("","end",text = uuid) # build the tree
                tree.insert(i,"end",text = "Location: " + packet[1]["location"])
                d = tree.insert(i,"end",text = "device")
                s = tree.insert(i,"end",text = "service")

                trec[uuid] = {} # safe link to the tree
                trec[uuid]["device"] = d
                trec[uuid]["service"] = s
                
            nt = parseNT(packet[1]["nt"])

            if nt[0] == "urn": # only parse urn
                if not nt[2] in record[uuid][nt[1]]: # eliminate doubles
                    tree.insert(trec[uuid][nt[1]],"end",text = nt[2])
                    record[uuid][nt[1]].append(nt[2])

        runninglock.acquire()
        if(not running): # check if closed
            break
        runninglock.release()
        
    runninglock.release()

        
def render(): # update loop
    tree.update()

    root.after(100,render)

def onClose(): #close window and thread
    global running,runninglock
    runninglock.acquire()
    running = False
    runninglock.release()
    root.destroy()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.bind(('', MCAST_PORT))

mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

root = Tk()
root.wm_title("SSDP sniffer")
root.protocol("WM_DELETE_WINDOW",onClose)

tree = ttk.Treeview()
tree.pack(expand = True,fill = "both")

start_new_thread(listen,()) # start listen thread
render() # start update loop

mainloop()
