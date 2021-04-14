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
                    byte[] buffer = result.Buffer;
                    IPEndPoint remoteEndpoint = result.RemoteEndPoint;
                    
                    // TODO: this is where we process the incoming message
                }
            });

            Console.WriteLine("Press any key to quit it");
            Console.ReadKey();
        }
    }
}