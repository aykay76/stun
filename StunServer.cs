using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Stun
{
    public class StunServer
    {
        private StunServerOptions options;

        // TODO: add some form of transaction ID list to keep track of uniqueness across messages
        // TODO: server MUST support TCP and UDP - so add TCP listener
        // TODO: need to keep track of known clients and their state

        // keep track of sessions on server
        // TODO: prolly change this to a dictionary
        List<StunSession> sessions;
        
        public StunServer Configure(StunServerOptions options)
        {
            this.options = options;
            return this;
        }

        public string GenerateNonce()
        {
            string nonce = "obMatJos2";

            // TODO: need to prefix per section 9.2, add the security field
            // then generate the rest of the nonce based on 5-tuple or something

            byte[] securityFeatureSet = new byte[3];
            nonce += Convert.ToBase64String(securityFeatureSet);

            return nonce;
        }

        public void Start()
        {
            // TODO: add a TcpClient for handling incoming requests over TCP
            UdpClient client = new UdpClient(new IPEndPoint(IPAddress.Parse(options.ListenAddress), options.ListenPort));

            // TODO: this is taken from an console app I used for UDP testing, refactor
            Task t = Task.Run(async () =>
            {
                while (true)
                {
                    UdpReceiveResult result = await client.ReceiveAsync();

                    // TODO: store this somewhere for future reference
                    IPEndPoint remoteEndpoint = result.RemoteEndPoint;

                    // TODO: add some validation of magic number, 32-bit alignment etc.
                    byte[] buffer = result.Buffer;
                    StunMessage message = new StunMessage(buffer);

                    // TODO: Move this to another method to avoid one big method
                    // TODO: check section 9.1.3 for additional authn checks
                    // 9.2.4                    
                    if (message.IsRequest())
                    {
                        if (message.HasMessageIntegrity() == false || message.HasMessageIntegritySHA256() == false)
                        {
                            // TODO: prepare 401 response
                            //       MUST include a nonce (see section 9.2, MUST be prepended)
                            //       MAY include PASSWORD_ALGORITHMS (probably just stick with SHA256 though)
                            StunMessage response = new StunMessage((StunMethod)message.Method(), StunClass.Error)
                                .AddErrorCode(401, "Not authenticated.")
                                .AddRealm(options.Realm);
                            
                            // TODO: send the response over the same transport as the message was received on
                        }

                        if (message.HasMessageIntegrity() || message.HasMessageIntegritySHA256())
                        {
                            if (message.HasUsername() == false || message.HasUserhash() == false ||
                                message.HasRealm() == false || message.HasNonce() == false)
                            {
                                // TODO: prepare 400 response
                            }
                        }

                        if (message.HasNonce())
                        {
                            if (message.NonceMatchesCookie() && message.SecurityFeaturePasswordAlgorithms())
                            {
                                if (message.HasPasswordAlgorithms() == false && message.HasPasswordAlgorithm() == false)
                                {
                                    // TODO: set password algorithm to MD5 somewhere
                                }
                                else
                                {
                                    // TODO: do some more checks that might result in 400
                                }
                            }
                        }

                        // TODO: check username or userhash (against what?!) to see if they are valid - could result in a 401

                        if (message.HasMessageIntegritySHA256())
                        {
                            // TODO: compute the hash for the message and check against what's in the message
                            //       if they don't match return 401 MUST include REALM and NONCE
                        }

                        // TODO: proceed to check request and send a response...
                    }
                    else if (message.IsIndication())
                    {
                        // See section 6.3.2
                        // Since the only method supported is Binding and there is no further processing
                        // there is nothing to do here other than refresh the binding
                    }
                }
            });

            Console.WriteLine("Press any key to quit it");
            Console.ReadKey();
        }
    }
}