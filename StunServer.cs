using System;
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
        
        public StunServer Configure(StunServerOptions options)
        {
            this.options = options;
            return this;
        }

        public void Start()
        {
            UdpClient client = new UdpClient(new IPEndPoint(IPAddress.Parse(options.ListenAddress), options.ListenPort));

            // TODO: this is taken from an console app I used for UDP testing, refactor
            Task t = Task.Run(async () =>
            {
                while (true)
                {
                    UdpReceiveResult result = await client.ReceiveAsync();
                    IPEndPoint remoteEndpoint = result.RemoteEndPoint;

                    // TODO: add some validation of magic number, 32-bit alignment etc.
                    byte[] buffer = result.Buffer;
                    StunMessage message = new StunMessage(buffer);
                    
                    // TODO: this is where we process the incoming message
                    //       check whether it's a request or an indication, authentication etc. etc.
                    //       first time we're probably going to just return a 401 error to force authentication

                }
            });

            Console.WriteLine("Press any key to quit it");
            Console.ReadKey();
        }
    }
}