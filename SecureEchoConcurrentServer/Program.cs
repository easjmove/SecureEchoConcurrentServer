using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SecureConcurrentEchoServer
{
    class Program
    {
        //Creating these values as class variables in order for us to be able to us them in both methods

        //local path and filename of your generated certificate
        private static string serverCertificateFile = "c:/certificates/ServerSSL1.pfx";
        //if the server should ask the client for a certificate (note according to the documentation, if the client doesn't provide one, it will still work)
        private static bool clientCertificateRequired = false;
        //checking if the certificate is still valid (not passed it's end date)
        private static bool checkCertificateRevocation = true;
        private static bool leaveInnerStreamOpen = false;
        //Which TLS/SSL version to use, a rule of thumb is always use the newest, unless you have a good reason (new version usually means more secure)
        private static SslProtocols enabledSSLProtocols = SslProtocols.Tls13;
        //a variable to hold the certificate after it has been read from the local path
        private static X509Certificate serverCertificate;

        static void Main(string[] args)
        {
            //Writing to the console to be able to differentiate what is running
            Console.WriteLine("Secure Server:");

            //Reads the certicate and stores it in the variable, this is done here, so we can reuse the certificate several times
            //Notice the second parameter, this is the password specified for the .pfx file, not the .pkv or .cer
            serverCertificate = new X509Certificate(serverCertificateFile, "mysecret");

            //Creates a listener able to listen for connections incoming on port 7 only on the loopback adapter
            //loopback adapter is only used for connections on the local machine
            TcpListener listener = new TcpListener(IPAddress.Loopback, 7);

            //Actually starts the listener
            listener.Start();

            //In order for the server to be able to handle more than one client a while loop is needed.
            //here it is while true, because we don't have something that tells it to stop
            while (true)
            {
                //Here the code will wait, until a client connects and then returns an instance of the TcpClient class
                TcpClient socket = listener.AcceptTcpClient();

                //Because TCP holds the connection open, in order to handle several clients at the same time
                //it starts a new thread for each client
                //instead of having all the code here, it is moved (refactored) to a seperate method HandleClient
                Task.Run(() => HandleClient(socket));

                //the while loop ends here, after the server closes the socket connected to the client
                //but before the server stops listening.
            }

            //this line will never be reached because of the while loop
            //instead it will only stop when the program is stopped
            listener.Stop();
        }

        //New method to keep the code more maintenance friendly
        public static void HandleClient(TcpClient socket)
        {
            //Gets the stream object from the socket. The stream object is able to recieve and send data
            //Renamed this to unsecureStream, so we always know, that if we're using this stream, it sends it unencrypted
            NetworkStream unsecureStream = socket.GetStream();

            //Here we wrap our unsecureStream in a SslStream, which has the capacity to encrypt data sent, therefor we call this one secureStream
            SslStream secureStream = new SslStream(unsecureStream, leaveInnerStreamOpen);

            //Here we tell the stream to use our certificate we initialized in the main method (reused for every client)
            //The parameters are commented next to their definitions (class variables)
            secureStream.AuthenticateAsServer(serverCertificate, clientCertificateRequired, enabledSSLProtocols, checkCertificateRevocation);

            //The StreamReader is an easier way to read data from a Stream, it uses the secureStream
            StreamReader reader = new StreamReader(secureStream);
            //The StreamWriter is an easier way to write data to a Stream, it uses the secureStream
            StreamWriter writer = new StreamWriter(secureStream);

            //Here it reads all data send until a line break (cr lf) is received; notice the Line part of the ReadLine
            string message = reader.ReadLine();
            //Here it writes the received data to the Console
            //this is only for testing purposes, to verify that the server recieves the data
            Console.WriteLine(message);
            //Here it writes the data back to the client and appends a line break (cr lf); notice the line part of WriteLine
            writer.WriteLine(message);
            //Makes sure that the message isn't buffered somewhere, and actually send to the client
            //Always remember to flush after you
            writer.Flush();

            //Because it doesn't expect more messages from the client, it closes the socket/connection
            socket.Close();
        }
    }
}
