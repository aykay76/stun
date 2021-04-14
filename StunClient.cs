using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace Stun
{
    public class StunClient
    {
        private StunClientOptions options;

        // TODO: need to keep track of transaction IDs used, and probably other stuff :)

        // TODO: Per 6.2 of the RFC should limit self to 10 outstanding transactions with a server
        // so keep track of what is in progress with each server

        // TODO: Per 6.2.1 need to keep track of retries with exponential backoff - max 7 retries

        // TODO: add some methods to do basic binding request and process the response
        //       this will simplify adding attributes like SOFTWARE and USERNAME etc.
        public StunClient()
        {

        }

        public StunClient Configure(StunClientOptions options)
        {
            this.options = options;
            return this;
        }

        public async Task<int> BindingRequest()
        {
            StunMessage m = new StunMessage(StunMethod.Binding, StunClass.Request)
                .AddSoftware(options.SoftwareAgent);
            // TODO: add some attributes

            UdpClient sender = new UdpClient();

            // TODO: encode message - need to add ToBytes() method to message to finalise length and return buffer
            byte[] datagram = m.GetBytes();
            int t = await sender.SendAsync(datagram, datagram.Length, new IPEndPoint(IPAddress.Parse(options.ServerAddress), options.ServerPort));

            // TODO: process the response

            return t;
        }
    }
}