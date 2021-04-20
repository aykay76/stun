using System.Net;
using System.Net.Sockets;

namespace Stun
{
    public class StunSession
    {
        // the 96-bit transaction id for the session
        public byte[] TransactionId { get; set; }

        // reflexive transport address of the client
        public IPEndPoint ClientEndpoint { get; set; }

        public Socket TcpSocket { get; set; }

        public byte[] SocketBuffer { get; set; }
        public byte[] MessageBuffer { get; set; }
        public int Position { get; set; }

        public StunSession()
        {
            TransactionId = new byte[12];
            SocketBuffer = new byte[500];
            Position = 0;
        }
    }
}