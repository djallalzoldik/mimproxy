#setup

Mitmproxy: 10.1.6 binary

Python:    3.12.0

OpenSSL:   OpenSSL 3.1.4 24 Oct 2023

Platform:  macOS-10.14.6-x86_64-i386-64bit



How to for word traffic from mitmproxy to burp suite

1 go to burp suite and export certificate.der and privately.der

And convert them to .pem file

Convert burp_cert.der to burp_cert.pem

openssl x509 -inform DER -in burp_certificate.der -out burp_certificate.pem

Convert burp_key.der to burp_key.pem

openssl rsa -inform DER -in privatekey.der -outform PEM -out privatekey.pem


#combined them in one pem file

cat burp_certificate.pem burp_private_key.pem > combined_burp.pem



Now :
Move combined_burp.pem to “/.mitmproxy” folder , and make the default mitmproxy_certaficate to backup , use this command 

`mv mitmproxy-ca.pem backup-mitmproxy-ca.pem`

Now , you can mv the combined_burp.pem to mitmproxy-ca.pem



Next:
Go to browser and in the trusted certificate section import the combined_burp.pem to the browser

Go and use foxy proxy make the listener port for the mitmproxy at the port 8080,

And make the burp suite listen on the port 8181


Now you can use this command `mitmproxy --mode upstream:http://127.0.0.1:8181 --ssl-insecure`



If you have server

You can upload the new mitmproxy-ca.pem to the server in the .mitmproxy folder and replace it with same certificate in there ,

