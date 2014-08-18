import SocketServer
import re
import string
import socket
import threading
import sys
import time

rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_cancel = re.compile("^CANCEL")
rx_cancel_cseq = re.compile("CANCEL")
rx_bye = re.compile("^BYE")
rx_bye_cseq = re.compile("BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_from = re.compile("^From:")
rx_to = re.compile("^To:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
rx_addrport = re.compile("([^:]*):(.*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_invalid = re.compile("^192\.168")
rx_invalid2 = re.compile("^10\.")
rx_cseq = re.compile("^CSeq:")
rx_callid = re.compile("Call-ID: (.*)$")
#rx_rr = re.compile("^Record-Route:")
# Linphone bug
#rx_rr = re.compile("^Record-.oute:")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_via = re.compile("^Via:")
rx_branch = re.compile(";branch=([^;]*)")

# global dictionnary
recordroute = ""
registrar = {}
#context = {}

def hexdump( chars, sep, width ):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust( width, '\000' )
        print "%s%s%s" % ( sep.join( "%02x" % ord(c) for c in line ),sep, quotechars( line ))

def quotechars( chars ):
	return ''.join( ['.', c][c.isalnum()] for c in chars )

def showtime():
    print time.strftime("(%H:%M:%S)", time.localtime())

class UDPHandler(SocketServer.BaseRequestHandler):   
    
    def debugRegister(self):
        print "\n*** REGISTRAR ***"
        print "*****************"
        for key in registrar.keys():
            print "%s -> %s" % (key,registrar[key][0])
        print "*****************"
        
    def uriToAddress(self,uri):
        addr = ""
        port = 0
        addrport, socket, client_addr = registrar[uri]
        md = rx_addrport.match(addrport)
        if md:
            addr = md.group(1)
            port = int(md.group(2))
        else:
            addr = addrport
            port = 5060
        return (addr,port,socket, client_addr)
        
                    
    def parseRequest(self):
        destination = ""
        origin = ""
        callid = ""
        branch = ""
        for line in self.data:
            if rx_via.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
            if rx_to.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" %(md.group(1),md.group(2))
            if rx_from.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = "%s@%s" %(md.group(1),md.group(2))
            md = rx_callid.search(line)
            if md:
                callid = md.group(1)
        return (origin, destination, callid, branch)
        
    def sendResponse(self,code):
        request_uri = "SIP/2.0 " + code
        self.data[0]= request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line):
                if not rx_tag.search(line):
                    data[index] = "%s%s" % (line,";tag=123456")
            if rx_contentlength.search(line):
                data[index]="Content-Length: 0"
            index += 1
            if line == "":
                break
        data.append("")
        text = string.join(data,"\r\n")
        self.socket.sendto(text,self.client_address)
        showtime()
        print "---\n<< server send [%d]:\n%s\n---" % (len(text),text)
        
    def processRegister(self):
        fromm = ""
        contact = ""
        size = len(self.data)
        for line in self.data:
            if rx_to.search(line):
               md = rx_uri.search(line)
               if md:
                    fromm = "%s@%s" % (md.group(1),md.group(2))
            if rx_contact.search(line):
               md = rx_uri.search(line)
               if md:
                    contact = md.group(2)
               else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)     
           
        if rx_invalid.search(contact) or rx_invalid2.search(contact):
            if registrar.has_key(fromm):
                del registrar[fromm]
            self.sendResponse("488 Not Acceptable Here")
        else:
            print "From: %s - Contact: %s" % (fromm,contact)
            print "Client address: %s:%s" % self.client_address
            registrar[fromm]=[contact,self.socket,self.client_address]
            self.debugRegister()
            self.sendResponse("200 0K")
        
    def processInvite(self):
        print "-----------------"
        print " INVITE received "
        print "-----------------"
        origin,destination,callid,branch = self.parseRequest()
        if len(destination) > 0:
            print "destination %s" % destination
            if registrar.has_key(destination):
                addr,port,socket,claddr = self.uriToAddress(destination)
                print "Send INVITE to %s:%s" %(addr,port)
                # change request uri
                #md = rx_request_uri.search(self.data[0])
                #if md:
                #    method = md.group(1)
                #    uri = md.group(2)
                #    if registrar.has_key(uri):
                #        uri = "sip:%s" % registrar[uri]
                #        self.data[0] = "%s %s SIP/2.0" % (method,uri)
                # delete Route
                data = []
                for line in self.data:
                    if not rx_route.search(line):
                        data.append(line)
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                showtime()
                print "---\n<< server send [%d]:\n%s\n---" % (len(text),text)
                
            else:
                self.sendResponse("480 Temporarily Unavailable")
                
    def processAck(self):
        print "--------------"
        print " ACK received "
        print "--------------"
        origin,destination,callid,branch = self.parseRequest()
        if len(destination) > 0:
            print "destination %s" % destination
            if registrar.has_key(destination):
                addr,port,socket,claddr = self.uriToAddress(destination)
                # delete Route
                data = []
                for line in self.data:
                    if not rx_route.search(line):
                        data.append(line)
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                showtime()
                print "---\n<< server send [%d]:\n%s\n---" % (len(text),text)
                
    def processCancel(self):
        print "-----------------"
        print " CANCEL received "
        print "-----------------"
        origin,destination,callid,branch = self.parseRequest()
        if len(destination) > 0:
            print "destination %s" % destination
            if registrar.has_key(destination):
                addr,port,socket,claddr = self.uriToAddress(destination)
               # delete Route
                data = []
                for line in self.data:
                    if not rx_route.search(line):
                        data.append(line)
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                showtime()
                print "---\n<< server send [%d]:\n%s\n---" % (len(text),text)
                return
        self.sendResponse("404 Not Found")
                
    def processTransaction(self):
        print "----------------------"
        print " Transaction received "
        print "----------------------"
        origin,destination,callid,branch = self.parseRequest()
        if len(destination) > 0:
            print "destination %s" % destination
            if registrar.has_key(destination):
                addr,port,socket,claddr = self.uriToAddress(destination)
                print "Send Transaction to %s:%s" %(addr,port)
                # change request uri
                # md = rx_request_uri.search(self.data[0])
                # if md:
                # method = md.group(1)
                # uri = md.group(2)
                # if registrar.has_key(uri):
                # uri = "sip:%s" % registrar[uri]
                # self.data[0] = "%s %s SIP/2.0" % (method,uri)
                # delete Route
                data = []
                for line in self.data:
                    if not rx_route.search(line):
                        data.append(line)
                #insert Record-Route
                data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text , claddr)
                showtime()
                print "---\n<< server send [%d]:\n%s\n---" % (len(text),text)    
            else:
                self.sendResponse("406 Not Acceptable")
                
    def processCode(self):
        origin,destination,callid,branch = self.parseRequest()
        if len(origin) > 0:
            print "origin %s" % origin
            if registrar.has_key(origin):
                addr,port,socket,claddr = self.uriToAddress(origin)
                # delete Route
                data = []
                for line in self.data:
                    if not rx_route.search(line):
                        data.append(line)
                #data.insert(1,recordroute)
                text = string.join(data,"\r\n")
                socket.sendto(text,claddr)
                showtime()
                print "---\n<< server send [%d]:\n%s\n---" % (len(text),text)
                
    def processRequest(self):
        #print "processRequest"
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                self.processRegister()
            elif rx_invite.search(request_uri):
                self.processInvite()
            elif rx_ack.search(request_uri):
                self.processAck()
            elif rx_bye.search(request_uri):
                self.processTransaction()
            elif rx_cancel.search(request_uri):
                self.processCancel()
            elif rx_options.search(request_uri):
                self.processTransaction()
            elif rx_info.search(request_uri):
                self.processTransaction()
            elif rx_message.search(request_uri):
                self.processTransaction()
            elif rx_refer.search(request_uri):
                self.processTransaction()
            elif rx_subscribe.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                self.processCode()
                #print "unexpected code: %s" % request_uri
            else:
                print "request_uri %s"     % request_uri          
                #print "message %s unknown" % self.data

    """
    def setup(self):
        pass
        #print "setup"
    """
    
    def handle(self):
        #print "handle"
        #print self.server
        #socket.setdefaulttimeout(120)
        data = self.request[0]
        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            showtime()
            print "---\n>> server received [%d]:\n%s\n---" %  (len(data),data)
            self.processRequest()
        else:
            if len(data) != 4:
                showtime()
                print "---\n>> server received [%d]:" % len(data)
                hexdump(data,' ',16)
                print "---"

    """
    def finish(self):
        pass
        #print "finish"
        #self.socket.close()
    """
if __name__ == "__main__":    
    print time.strftime("%a, %d %b %Y %H:%M:%S ", time.localtime())
    #HOST, PORT = "127.0.0.1", 5060
    hostname = socket.gethostname()
    print hostname
    ipaddress = socket.gethostbyname(hostname)
    if ipaddress == "127.0.0.1":
        ipaddress = sys.argv[1]
    print ipaddress
    HOST, PORT = '0.0.0.0', 5060
    recordroute = "Record-Route: <sip:%s:%d;lr>" % (ipaddress,PORT)
    server = SocketServer.UDPServer((HOST, PORT), UDPHandler)
    server.serve_forever()
