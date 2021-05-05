using System;

namespace Stun
{
    class Program
    {
        static void Main(string[] args)
        {
            // TODO: move these to a proper test
            // CRC32 test vectors from https://stackoverflow.com/questions/20963944/test-vectors-for-crc32c
            // CRC32 crc = new CRC32(0x82F63B78);
            // uint check = crc.DoCRC32(System.Text.Encoding.UTF8.GetBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"));

            StunClient client = new StunClient().Configure(
                new StunClientOptions {
                    ServerAddress = "127.0.0.1",
                    ServerPort = 3478,
                    SoftwareAgent = "Example Stun Client v1.0.0"
                }
            );

            int temp = client.BindingRequest().GetAwaiter().GetResult();

            new StunServer()
                .Configure(new StunServerOptions {
                    ListenAddress = "0.0.0.0",
                    UdpPort = 3478,
                    TcpPort = 3478
                })
                .Start();
        }
    }
}
