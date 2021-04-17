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

        // TODO: Per 9.2.3.1 - need to keep track of servers we have authenticated with
        //                     first request contains no attributes, to get the REALM and NONCE back
        //                     then we authenticate and proceed

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

            // TODO: move this to a general loop that will process incoming datagrams and 
            //       check association with servers etc. to know state of authentication against different servers
            UdpReceiveResult result = await sender.ReceiveAsync();
            byte[] buffer = result.Buffer;
            StunMessage message = new StunMessage(buffer);

            // TODO: see section 9.1.4 for more checks related to authn

            if (message.IsSuccessResponse())
            {
                // TODO: check for XOR_MAPPED_ADDRESS attribute
            }
            else if (message.IsErrorResponse())
            {
                if (message.ErrorCode >= 300 && message.ErrorCode < 400)
                {
                    // TODO: check for ALTERNATE_SERVER attribute
                }
                else if (message.ErrorCode >= 400 && message.ErrorCode < 500)
                {
                    // TODO: Section 9.2.5 - check 401 otherwise it's probably a fail
                    // TODO: if 420 look for UNKNOWN_ATTRIBUTES and report
                }
                else if (message.ErrorCode >= 500 && message.ErrorCode < 600)
                {
                    // TODO: implement retry mechanism
                }
            }
            

            return t;
        }
    }
}