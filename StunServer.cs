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
        private List<StunSession> sessions = new List<StunSession>();
        
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

        public void ProcessMessage(StunMessage message)
        {
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

        public void Start()
        {
            TcpListener tcpServer = new TcpListener(IPAddress.Parse(options.ListenAddress), options.TcpPort);
            UdpClient udpClient = new UdpClient(new IPEndPoint(IPAddress.Parse(options.ListenAddress), options.UdpPort));
            Task[] tasks = new Task[2]; // UDP receive, TCP accept
            List<Task> tcpReceiveTasks = new List<Task>();

            // TODO: this is taken from an console app I used for UDP testing, refactor
            // Task t = Task.Run(async () =>
            // {
                while (true)
                {
                    // TODO: need to add logic to manage tasks for when UDP and/or TCP requests come in
                    // if the tasks are not already outstanding (i.e. awaiting from a previous loop) then
                    // add, otherwise just check for completion

                    // if task is already outstanding there is nothing to do but check if it's complete
                    if (tasks[0] == null)
                    {
                        tasks[0] = udpClient.ReceiveAsync();
                    }

                    if (tasks[1] == null)
                    {
                        tasks[2] = tcpServer.AcceptSocketAsync();
                    }

                    // check for any new connections
                    int task = Task.WaitAny(tasks, 5);
                    if (task == 0)
                    {
                        // UDP client sent a request
                        UdpReceiveResult result = ((Task<UdpReceiveResult>)tasks[0]).Result;

                        // done with the task so null it ready for next loop iteration
                        tasks[0] = null;

                        // TODO: store this somewhere for future reference
                        IPEndPoint remoteEndpoint = result.RemoteEndPoint;

                        // TODO: add some validation of magic number, 32-bit alignment etc.
                        byte[] buffer = result.Buffer;
                        StunMessage message = new StunMessage(buffer);
                    }
                    else if (task == 1)
                    {
                        // TODO: move socket and buffer to object to track connections - probably need some form of state enum too (Connected, Receiving, Pending, Sending blah blah blah)
                        Socket socket = ((Task<Socket>)tasks[1]).Result;

                        // done with the task so null it ready for next loop iteration
                        tasks[1] = null;

                        byte[] buffer = new byte[500];

                        // add task to receive TCP packet
                        tcpReceiveTasks.Add(socket.ReceiveAsync(buffer, SocketFlags.None));
                    }

                    // check for any messages on TCP connections
                    task = Task.WaitAny(tcpReceiveTasks.ToArray());
                    if (task != -1)
                    {
                        // TODO: process the incoming data
                        //       check length is at least 4 bytes to get the length, then check length against buffer
                        //       if we have a full message process it otherwise receive again
                        //       when we have a full message remove the socket from the list so that it doesn't get checked next time around
                    }
                }
            // });

            // Console.WriteLine("Press any key to quit it");
            // Console.ReadKey();
        }
    }
}