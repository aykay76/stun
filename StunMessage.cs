using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Stun
{
    public class StunMessage
    {
        // because of the big-endian/little-endian transformation it makes sense to keep a copy
        // of some key header fields here
        private ushort type;
        private ushort length;
        private byte[] transactionID;
        private List<StunAttribute> attributes;

        private byte[] buffer;

        public bool IsRequest()
        {
            return (((type) & 0x0110) == 0x0000);
        }

        public bool IsIndication()
        {
            return (((type) & 0x0110) == 0x0010);
        }

        public bool IsSuccessResponse()
        {
            return (((type) & 0x0110) == 0x0100);
        }

        public bool IsErrorResponse()
        {
            return (((type) & 0x0110) == 0x0110);
        }

        public ushort Method()
        {
            return (ushort)((type & 0x3E00) >> 2 | (type & 0x00E0) >> 1 | (type & 0x000F));
        }

        public ushort Class()
        {
            return (ushort)((type & 0x0100) >> 7 | (type & 0x0010) >> 4);
        }

        private void StuffBuffer(byte[] bytes, int sourceOffset, byte[] destination, int offset, int count)
        {
            if (BitConverter.IsLittleEndian)
            {
                byte[] reversed = new byte[bytes.Length];
                Array.Copy(bytes, reversed, bytes.Length);
                Array.Reverse(reversed);
                Array.Copy(reversed, sourceOffset, destination, offset, count);
            }
            else
            {
                Array.Copy(bytes, sourceOffset, destination, offset, count);
            }
        }

        private void AppendToBuffer(byte[] bytes)
        {
            byte[] newBuffer = new byte[buffer.Length + bytes.Length];

            Array.Copy(buffer, 0, newBuffer, 0, buffer.Length);
            Array.Copy(bytes, 0, newBuffer, buffer.Length, bytes.Length);

            buffer = newBuffer;
        }

        private ushort ExtractShort(byte[] bytes, int offset)
        {
            byte[] s = new byte[2];
            Array.Copy(bytes, offset, s, 0, 2);

            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(s);
            }

            return BitConverter.ToUInt16(s, 0);
        }

        // Construct a message from a received byte array
        public StunMessage(byte[] bytes)
        {
            // TODO: do we need to copy? or just take ownership of the bytes...
            buffer = new byte[bytes.Length];
            Array.Copy(bytes, buffer, bytes.Length);

            // extract some often used fields
            type = ExtractShort(buffer, 0);
            length = ExtractShort(buffer, 2);
        }

        public StunMessage(StunMethod method, StunClass cls)
        {
            ushort m = (ushort)method;
            ushort c = (ushort)cls;
            ushort type = (ushort)((m & 0x1F80) << 2 | (m & 0x0070) << 1 | (m & 0x000F) | (c & 0x0002) << 7 | (c & 0x0001) << 4);

            // buffer starts with STUN header that is always 20 bytes
            // this will grow with each attribute that gets added
            buffer = new byte[20];
            // start stuffing the buffer
            StuffBuffer(BitConverter.GetBytes(type), 0, buffer, 0, 2);

            // we will backfill the length later when we have all the informations

            // add the magic cookie to the header
            bool little = BitConverter.IsLittleEndian;
            StuffBuffer(BitConverter.GetBytes((uint)0x2112a442), 0, buffer, 4, 4);

            // create a transaction ID and add it to the buffer
            RNGCryptoServiceProvider csp = new RNGCryptoServiceProvider();
            csp.GetBytes(buffer, 8, 12);
        }

        public void AddAttribute(StunAttribute attribute)
        {
            if (attributes == null)
            {
                attributes = new List<StunAttribute>();
            }

            // TODO: MUST handle the case for Fingerprint() being the last attribute here.
            //       So probably want a method AddFingerprint() which will just compute the fingerprint then add it :)

            attributes.Add(attribute);
        }
        
        public StunMessage AddSoftware(string agent)
        {
            ushort length = (ushort)(agent.Length + 4);
            if (length % 4 != 0)
            {
                length = (ushort)(((length / 4) + 1) * 4);
            }

            // encode the TLV
            byte[] bytes = new byte[length];
            StuffBuffer(BitConverter.GetBytes((ushort)0x8022), 0, bytes, 0, 2);
            StuffBuffer(BitConverter.GetBytes(length), 0, bytes, 2, 2);
            Array.Copy(System.Text.Encoding.UTF8.GetBytes(agent), 0, bytes, 4, agent.Length);

            AppendToBuffer(bytes);

            return this;
        }

        public StunMessage AddFingerprint()
        {
            StunAttribute fingerprint = new StunAttribute();
            fingerprint.Type = 0x8028;

            // TODO: dig out CRC32 code
            //       munge message to remove fingerprint attribute
            //       CRC32 and ^ with 0x5354554e
            //       see section 14.7

            // this must be the final attribute, so could return a different type?
            attributes.Add(fingerprint);

            // return self for fluid style 
            return this;
        }

        public byte[] GetBytes()
        {
            // final length is the whole message minus the 20 byte fixed header
            length = (ushort)(buffer.Length - 20);

            // stuff that into the buffer
            StuffBuffer(BitConverter.GetBytes(length), 0, buffer, 2, 2);

            // and return the buffer
            return buffer;
        }
    }
}