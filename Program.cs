using System;

namespace Stun
{
    class Program
    {
        static void Main(string[] args)
        {
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
                    ListenPort = 3478
                })
                .Start();
        }
    }
}
