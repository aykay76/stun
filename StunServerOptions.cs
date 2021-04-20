namespace Stun
{
    public class StunServerOptions
    {
        public string ListenAddress { get; set; }
        public int UdpPort { get; set; }
        public int TcpPort { get; set; }
        public string Realm { get; set; }
    }
}