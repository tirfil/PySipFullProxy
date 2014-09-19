SIP Full Proxy
==============

Motivations
-----------
Enable communication between SIP phones (softphone or hardphone) throught Internet.

History
-------
Formal version was an "half" SIP proxy i.e. only establishing SIP dialog message uses the proxy.

Unfortenately, this kind of proxy is not compliant to use throught Internet.
Actually, Internet providers uses a box to connect a local network to Internet. This router includes a NAT.
This is generally a Port Restricted Cone NAT. This means that the remote socket MUST respond using same port and ip address as local socket resquest.

I tried also to use a redirect proxy. Unfortenately open source or free cost SIP softphone I use (Linphone,Ekiga,XLite ...) doesn't process redirection (3xx) correctly.

Last possibility is to use a Full SIP proxy i.e all SIP requests and responses use the proxy.

Features
--------
The SIP proxy provides routing features and using a registrar is neccessary.
Then, this project includes also a registrar. 

I notice also some attacks from "security" software (like SIPvicious). To avoid issues like growing registrar data, I include a simple authentication mechanisms for registration and check the validity of URIs used in SIP messages.

 
