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

        public static StunAttribute XorMappedAddress(IPEndPoint endpoint, byte[] magicCookie, byte[] transactionId)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0020;

            // TODO: need to check endianness of this
            byte[] address = endpoint.Address.GetAddressBytes();
            attribute.Length = (ushort)(4 + address.Length);
            attribute.Value = new byte[attribute.Length];

            // set the family based on whether the address is IPv4 or IPv6
            if (address.Length == 4)
            {
                attribute.Value[1] = 1;
                for (int i = 0; i < 4; i++)
                {
                    address[i] ^= magicCookie[i];
                }
            }
            else
            {
                attribute.Value[1] = 2;
                
                for (int i = 0; i < 4; i++)
                {
                    address[i] ^= magicCookie[i];
                }
                for (int i = 4; i < 16; i++)
                {
                    address[i] ^= transactionId[i - 4];
                }
            }

            Array.Copy(BitConverter.GetBytes(endpoint.Port ^ 0x2112), 0, attribute.Value, 2, 2);
            Array.Copy(address, 0, attribute.Value, 4, address.Length);

            return attribute;
        }

        public static StunAttribute Username(string username)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0006;

            // TODO: i'm sure there's some work to do here to comply with OpaqueString profile in RFC8265
            byte[] value = System.Text.UTF8Encoding.UTF8.GetBytes(username);
            attribute.Length = (ushort)value.Length;

            // ensure value is aligned to 32-bit boundary
            if (attribute.Length % 4 != 0)
            {
                attribute.Length = (ushort)(((attribute.Length / 4) + 1) * 4);
            }

            // allocate
            attribute.Value = new byte[attribute.Length];

            // copy 
            Array.Copy(value, attribute.Value, value.Length);

            // return
            return attribute;
        }
    }
}