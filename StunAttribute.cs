using System;
using System.Net;
using System.Security.Cryptography;
using System.Text.Unicode;

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

        public static StunAttribute Userhash(string username, string realm)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x001e;

            // fixed length because SHA256
            attribute.Length = 32;

            // SHA the "{username}:{realm}"
            // TODO: i'm sure there's some work to do here to comply with OpaqueString profile in RFC8265
            string combined = $"{username}:{realm}";
            attribute.Value = SHA256.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(combined));

            // return
            return attribute;
        }

        public static StunAttribute MessageIntegrity()
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0008;

            // fixed length because SHA1
            attribute.Length = 20;

            // TODO: work out how to do this based on credential mechanism used
            //       see section 14.5 of RFC

            // return
            return attribute;
        }

        public static StunAttribute MessageIntegritySHA256()
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x001c;

            // TODO: work out how to do this based on credential mechanism used
            //       see section 14.6 of RFC

            // return
            return attribute;
        }

        public static StunAttribute Fingerprint()
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x8028;

            // TODO: dig out CRC32 code
            //       munge message to remove fingerprint attribute
            //       CRC32 and ^ with 0x5354554e
            //       see section 14.7

            // return
            return attribute;
        }

        public static StunAttribute ErrorCode(int errorCode, string reason)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0009;

            if (errorCode < 300 || errorCode > 699)
            {
                throw new InvalidOperationException("Error code must be between 300 and 699");
            }

            if (reason.Length >= 128)
            {
                throw new InvalidOperationException("Reason phrase must be fewer than 128 characters");
            }

            // align length to 32-bit boundary
            attribute.Length = (ushort)(reason.Length + 4);
            if (attribute.Length % 4 != 0)
            {
                attribute.Length = (ushort)(((attribute.Length / 4) + 1) * 4);
            }

            attribute.Value = new byte[attribute.Length];

            attribute.Value[0] = 0;
            attribute.Value[1] = 0;
            attribute.Value[3] = (byte)(errorCode / 100);
            attribute.Value[4] = (byte)(errorCode % 100);

            byte[] reasonBytes = System.Text.Encoding.UTF8.GetBytes(reason);
            Array.Copy(reasonBytes, 0, attribute.Value, 4, reasonBytes.Length);

            // return
            return attribute;
        }

        public static StunAttribute Realm(string realm)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0014;

            if (realm.Length >= 128)
            {
                throw new InvalidOperationException("Realm must be fewer than 128 characters");
            }

            // align length to 32-bit boundary
            attribute.Length = (ushort)(realm.Length + 4);
            if (attribute.Length % 4 != 0)
            {
                attribute.Length = (ushort)(((attribute.Length / 4) + 1) * 4);
            }

            attribute.Value = new byte[attribute.Length];

            byte[] realmBytes = System.Text.Encoding.UTF8.GetBytes(realm);
            Array.Copy(realmBytes, 0, attribute.Value, 4, realmBytes.Length);

            // return
            return attribute;
        }

        public static StunAttribute Nonce(string nonce)
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x0015;

            if (nonce.Length >= 128)
            {
                throw new InvalidOperationException("Nonce must be fewer than 128 characters");
            }

            // align length to 32-bit boundary
            attribute.Length = (ushort)(nonce.Length + 4);
            if (attribute.Length % 4 != 0)
            {
                attribute.Length = (ushort)(((attribute.Length / 4) + 1) * 4);
            }

            attribute.Value = new byte[attribute.Length];

            byte[] nonceBytes = System.Text.Encoding.UTF8.GetBytes(nonce);
            Array.Copy(nonceBytes, 0, attribute.Value, 4, nonceBytes.Length);

            // return
            return attribute;
        }

        // TODO: add PASSWORD-ALGORITHMS from section 14.11

        // TODO: add enum for MD5 or SHA256 and encode that into the attribute value
        public static StunAttribute PasswordAlgorithm()
        {
            StunAttribute attribute = new StunAttribute();
            attribute.Type = 0x001D;

            attribute.Length = 4;

            // fixed length - assuming SHA256 and no parameters
            attribute.Value = new byte[4];
            attribute.Value[1] = 2;

            return attribute;
        }
    }
}