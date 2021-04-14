using System;
using System.Net;

namespace Stun
{
    public class StunAttribute
    {
        public ushort Type { get; set; }
        public ushort Length { get; set; }
        public byte[] Value { get; set; }

        public bool ComprehensionRequired()
        {
            return (Type < (ushort)0x8000);
        }

        public static StunAttribute MappedAddress(IPEndPoint endpoint)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0001;

            // TODO: need to check endianness of this
            byte[] address = endpoint.Address.GetAddressBytes();
            attribute.Length = (ushort)(4 + address.Length);
            attribute.Value = new byte[attribute.Length];

            // set the family based on whether the address is IPv4 or IPv6
            if (address.Length == 4)
            {
                attribute.Value[1] = 1;
            }
            else
            {
                attribute.Value[1] = 2;
            }

            Array.Copy(BitConverter.GetBytes(endpoint.Port), 0, attribute.Value, 2, 2);
            Array.Copy(address, 0, attribute.Value, 4, address.Length);

            return attribute;
        }
    }
}