namespace Stun
{
    public class StunSession
    {
        // the 96-bit transaction id for the session
        byte[] transactionId;

        // reflexive transport address of the client
        IPEndPoint sourceEndpoint;

        // TODO: use this for client and server to track session information
    }
}