

#setup

if you want to using mitmproxy with headless browser you should install the certaficates of the mitmproxy in the trusted Root

```
Copy the Certificate to the Trusted Store:

    The location of the trusted store can vary, but a common path is /usr/local/share/ca-certificates/ for Debian-based systems, or /etc/pki/ca-trust/source/anchors/ for RedHat-based systems.
    Use the cp command to copy your PEM file to this directory.

Update the Certificate Store:

    On Debian-based systems (like Ubuntu), run:

    sql

sudo update-ca-certificates

On RedHat-based systems (like CentOS), run:

sql

        sudo update-ca-trust extract

For Windows Systems

    Open Command Prompt as Administrator.

    Use certutil to Add the Certificate:
        If your certificate is in PEM format, you need to convert it to a DER format (.cer or .crt):

        arduino

        certutil -addstore -f "ROOT" yourcert.cer

        This adds the certificate to the trusted root certification authorities store.

For macOS

    Open Terminal.

    Use the security Command to Add the Certificate:
        Add the certificate to the system keychain:

        csharp

        sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain yourcert.cer

        This command adds the certificate to the trusted root store.

Important Notes

    Always ensure you have the necessary permissions to install certificates on the system.
    Be cautious with certificate handling to prevent security risks.
    The exact commands and paths might vary depending on your system's configuration and the certificate format.

For specific instructions tailored to your exact scenario, you might need to refer to the documentation of your operating system or the certificate authority that issued your certificate.
```
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

