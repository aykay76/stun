using System.Collections.Generic;

namespace Stun
{
    public class StunMessage
    {
        private ushort type;
        private ushort length;
        private uint magicCookie = 0x2112a442;
        private byte[] transactionID;
        private List<StunAttribute> attributes;

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

        public StunMessage(ushort method, ushort cls)
        {
            type = (ushort)((method & 0x1F80) << 2 | (method & 0x0070) << 1 | (method & 0x000F) | (cls & 0x0002) << 7 | (cls & 0x0001) << 4);
            attributes = new List<StunAttribute>();
        }
    }
}