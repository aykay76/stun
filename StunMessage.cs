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
        
        
        // TODO: should remove this when apt
        private List<StunAttribute> attributes;

        private string nonce;
        private byte[] securityFeatureSet;

        private byte[] buffer;

        private List<StunAttributeType> availableAttributes;

        public int ErrorCode { get; }
        public string ErrorReason { get; }

        public bool HasUsername()
        {
            return availableAttributes.Contains(StunAttributeType.USERNAME);
        }

        public bool HasMessageIntegrity()
        {
            return availableAttributes.Contains(StunAttributeType.MESSAGE_INTEGRITY);
        }

        public bool HasMessageIntegritySHA256()
        {
            return availableAttributes.Contains(StunAttributeType.MESSAGE_INTEGRITY_SHA256);
        }

        public bool HasUserhash()
        {
            return availableAttributes.Contains(StunAttributeType.USERHASH);
        }

        public bool HasRealm()
        {
            return availableAttributes.Contains(StunAttributeType.REALM);
        }

        public bool HasNonce()
        {
            return availableAttributes.Contains(StunAttributeType.NONCE);
        }

        public bool HasPasswordAlgorithms()
        {
            return availableAttributes.Contains(StunAttributeType.PASSWORD_ALGORITHMS);
        }

        public bool HasPasswordAlgorithm()
        {
            return availableAttributes.Contains(StunAttributeType.PASSWORD_ALGORITHM);
        }

        public bool HasAttribute(StunAttributeType attribute)
        {
            return availableAttributes.Contains(attribute);
        }

        public bool NonceMatchesCookie()
        {
            if (nonce.StartsWith("obMatJos2")) return true;

            return false;
        }

        public bool SecurityFeaturePasswordAlgorithms()
        {
            return (securityFeatureSet[2] & 0x01) == 0x01;
        }

        public bool SecurityFeatureUsernameAnonymity()
        {
            return (securityFeatureSet[2] & 0x02) == 0x02;
        }

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

        // whack some bytes into the buffer based on the endianness of the platform this is running on
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

        // append some bytes to the buffer, reallocating and resizing as appropriate
        private void AppendToBuffer(byte[] bytes)
        {
            byte[] newBuffer = new byte[buffer.Length + bytes.Length];

            Array.Copy(buffer, 0, newBuffer, 0, buffer.Length);
            Array.Copy(bytes, 0, newBuffer, buffer.Length, bytes.Length);

            buffer = newBuffer;
        }

        // grab an unsigned short from the buffer based on endianness
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
            // take a copy of the bytes as we can't assume that ownership is transferred
            buffer = new byte[bytes.Length];
            Array.Copy(bytes, buffer, bytes.Length);

            // extract some often used fields
            type = ExtractShort(buffer, 0);
            length = ExtractShort(buffer, 2);
            transactionID = new byte[12];
            Array.Copy(bytes, 8, transactionID, 0, 12);

            // scan through the rest of the buffer to build a list of available attributes
            availableAttributes = new List<StunAttributeType>();
            int pos = 20;
            while (pos < buffer.Length)
            {
                StunAttributeType type = (StunAttributeType)ExtractShort(buffer, pos);
                availableAttributes.Add(type);
                pos += 2;

                ushort length = ExtractShort(buffer, pos);
                pos += 2;

                // TODO: it might just be easier to get all the values too, especially the nonce which needs some special processing
                // when getting the nonce, check for the cookie, base64 decode the next 4 bytes and deconstruct the bit field
                if (type == StunAttributeType.NONCE)
                {
                    byte[] value = new byte[length];
                    Array.Copy(buffer, pos, value, 0, length);
                    nonce = System.Text.Encoding.UTF8.GetString(value);

                    if (NonceMatchesCookie())
                    {
                        securityFeatureSet = Convert.FromBase64String(nonce.Substring(9, 4));
                    }
                }
                else if (type == StunAttributeType.ERROR_CODE)
                {
                    ErrorCode = buffer[pos + 2] * 100 + buffer[pos + 3];
                    ErrorReason = System.Text.Encoding.UTF8.GetString(buffer, 4, length - 4);
                }

                pos += length;
            }
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
            ushort length = (ushort)(agent.Length);
            if (length % 4 != 0)
            {
                length = (ushort)(((length / 4) + 1) * 4);
            }

            // encode the TLV
            byte[] bytes = new byte[length + 4];
            StuffBuffer(BitConverter.GetBytes((ushort)0x8022), 0, bytes, 0, 2);
            StuffBuffer(BitConverter.GetBytes(length), 0, bytes, 2, 2);
            Array.Copy(System.Text.Encoding.UTF8.GetBytes(agent), 0, bytes, 4, agent.Length);

            AppendToBuffer(bytes);

            return this;
        }

        public StunMessage AddRealm(string realm)
        {
            ushort length = (ushort)(realm.Length);
            if (length % 4 != 0)
            {
                length = (ushort)(((length / 4) + 1) * 4);
            }

            // encode the TLV, allocate L + 4 bytes for T&L
            byte[] bytes = new byte[length + 4];
            StuffBuffer(BitConverter.GetBytes((ushort)0x0014), 0, bytes, 0, 2);
            StuffBuffer(BitConverter.GetBytes(length), 0, bytes, 2, 2);
            Array.Copy(System.Text.Encoding.UTF8.GetBytes(realm), 0, bytes, 4, realm.Length);

            AppendToBuffer(bytes);

            return this;
        }

        public StunMessage AddErrorCode(int errorCode, string reason)
        {
            if (errorCode < 300 || errorCode > 699)
            {
                throw new InvalidOperationException("Error code must be between 300 and 699");
            }

            if (reason.Length >= 128)
            {
                throw new InvalidOperationException("Reason phrase must be fewer than 128 characters");
            }

            // align length to 32-bit boundary
            ushort length = (ushort)(reason.Length);
            if (length % 4 != 0)
            {
                length = (ushort)(((length / 4) + 1) * 4);
            }

            byte[] value = new byte[length + 4];

            value[0] = 0;
            value[1] = 0;
            value[3] = (byte)(errorCode / 100);
            value[4] = (byte)(errorCode % 100);

            // type
            StuffBuffer(BitConverter.GetBytes((ushort)0x0009), 0, value, 0, 2);

            // length
            StuffBuffer(BitConverter.GetBytes(length - 4), 0, value, 2, 2);

            // value
            byte[] reasonBytes = System.Text.Encoding.UTF8.GetBytes(reason);
            Array.Copy(reasonBytes, 0, value, 4, reasonBytes.Length);

            AppendToBuffer(value);

            return this;
        }

        public StunMessage AddFingerprint()
        {
            StunAttribute fingerprint = new StunAttribute();
            fingerprint.Type = 0x8028;

            byte[] value = new byte[8];

            // Type
            StuffBuffer(BitConverter.GetBytes((ushort)0x0009), 0, value, 0, 2);

            // Length
            StuffBuffer(BitConverter.GetBytes(4), 0, value, 2, 2);

            // Value
            //       munge message to remove fingerprint attribute
            //       CRC32 and ^ with 0x5354554e
            //       see section 14.7
            CRC32 crc = new CRC32();
            uint checksum = crc.DoCRC32(buffer);
            checksum ^= 0x5354554e;
            StuffBuffer(BitConverter.GetBytes(checksum), 0, value, 4, 0);

            AppendToBuffer(value);

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

        // TODO: add methods to investigate attributes and know what's available (and extract the values)
        //       maybe an initial scan when constructing the message to see which attributes are available
        //       Check section 9.2.4
    }
}