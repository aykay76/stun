using System;

namespace Stun
{
    class Program
    {
        static void Main(string[] args)
        {
            StunMessage m = new StunMessage(StunMethod.Binding, StunClass.Request);

            new StunServer()
                .Configure(new StunServerOptions {
                    ListenAddress = "0.0.0.0",
                    ListenPort = 3478
                })
                .Start();
        }
    }
}
