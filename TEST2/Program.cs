using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ReceiverApp
{
    class Program
    {
        static void Main(string[] args)
        {
            //Same address and port as senders
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            int port = 12345;

            using (Socket receiver = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
            {
                //Wait for a message and signature to be received
                receiver.Bind(new IPEndPoint(ipAddress, port));
                receiver.Listen(1);

                Console.WriteLine("Waiting for connection...");

                using (Socket client = receiver.Accept())
                {
                    Console.WriteLine("Connected!");

                    byte[] buffer = new byte[1024];

                    byte[] message = null;
                    byte[] signature = null;

                    //Receive public key
                    byte[] publicKeyLengthBytes = new byte[4];
                    client.Receive(publicKeyLengthBytes);

                    int publicKeyLength = BitConverter.ToInt32(publicKeyLengthBytes, 0);
                    byte[] publicKeyBytes = new byte[publicKeyLength];

                    int bytesReceived = client.Receive(publicKeyBytes, 0, publicKeyLength, SocketFlags.None);
                    if (bytesReceived != publicKeyLength)
                    {
                        Console.WriteLine("Error receiving public key.");
                        return;
                    }

                    //Receive message
                    byte[] messageLengthBytes = new byte[4];
                    client.Receive(messageLengthBytes);

                    int messageLength = BitConverter.ToInt32(messageLengthBytes, 0);
                    message = new byte[messageLength];

                    bytesReceived = client.Receive(message, 0, messageLength, SocketFlags.None);
                    if (bytesReceived != messageLength)
                    {
                        Console.WriteLine("Error receiving message.");
                        return;
                    }

                    //Receive signature
                    byte[] signatureLengthBytes = new byte[4];
                    client.Receive(signatureLengthBytes);

                    int signatureLength = BitConverter.ToInt32(signatureLengthBytes, 0);
                    signature = new byte[signatureLength];

                    bytesReceived = client.Receive(signature, 0, signatureLength, SocketFlags.None);
                    if (bytesReceived != signatureLength)
                    {
                        Console.WriteLine("Error receiving signature.");
                        return;
                    }

                    // Convert public key bytes to RSAParameters object
                    string publicKeyString = Encoding.UTF8.GetString(publicKeyBytes);
                    string[] publicKeyParts = publicKeyString.Split('|');
                    RSAParameters publicKey = new RSAParameters();
                    publicKey.Modulus = Convert.FromBase64String(publicKeyParts[0]);
                    publicKey.Exponent = Convert.FromBase64String(publicKeyParts[1]);

                    //Test verification
                    //Test(message, signature);

                    //Verify the digital signature using the received public key
                    RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();
                    rsaPublic.ImportParameters(publicKey);

                    Console.WriteLine("Received message: {0}", Encoding.ASCII.GetString(message));
                    Console.WriteLine("Received signature: {0}", Convert.ToBase64String(signature));

                    bool isVerified = rsaPublic.VerifyData(message, CryptoConfig.MapNameToOID("SHA256"), signature);

                    string verificationResult = isVerified ? "Digital signature is verified." : "Digital signature is not verified.";
                    Console.WriteLine(verificationResult);

                }
            }
        }
        public static void Test(byte[] message, byte[] signature) {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            RSAParameters publicKey2 = rsa.ExportParameters(false);
            rsa.ImportParameters(publicKey2);
            bool isVerified = rsa.VerifyData(message, CryptoConfig.MapNameToOID("SHA256"), signature);
            string verificationResult = isVerified ? "Digital signature is verified." : "Digital signature is not verified.";
            Console.WriteLine(verificationResult);
        }

    }
}

