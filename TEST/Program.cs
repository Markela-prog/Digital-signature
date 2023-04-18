using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace SenderApp
{
    class Program
    {
        
        static void Main(string[] args)
        {
                //Generate a public and private keys
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                RSAParameters publicKey = rsa.ExportParameters(false);
                RSAParameters privateKey = rsa.ExportParameters(true);

                //Create a message to sign
                byte[] message = Encoding.UTF8.GetBytes("Kazkoks message");

                //Create a digital signature
                RSACryptoServiceProvider rsaPrivate = new RSACryptoServiceProvider();
                rsaPrivate.ImportParameters(privateKey);
                byte[] signature = rsaPrivate.SignData(message, new SHA256CryptoServiceProvider());

                
                IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
                int port = 12345;


                using (Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
                {
                    sender.Connect(new IPEndPoint(ipAddress, port));

                    //Send public key
                    byte[] publicKeyBytes = Encoding.UTF8.GetBytes(Convert.ToBase64String(publicKey.Modulus) + "|" + Convert.ToBase64String(publicKey.Exponent));
                    byte[] publicKeyLengthBytes = BitConverter.GetBytes(publicKeyBytes.Length);
                    sender.Send(publicKeyLengthBytes);
                    sender.Send(publicKeyBytes);

                    //Send message
                    byte[] messageLengthBytes = BitConverter.GetBytes(message.Length);
                    sender.Send(messageLengthBytes);
                    sender.Send(message);

                    //Send signature
                    byte[] signatureLengthBytes = BitConverter.GetBytes(signature.Length);
                    sender.Send(signatureLengthBytes);
                    sender.Send(signature);
                }

                Console.WriteLine("Sent message: {0}", Encoding.ASCII.GetString(message));
                Console.WriteLine("Sent signature: {0}", Convert.ToBase64String(signature));
                
            }
        }
        
    }
