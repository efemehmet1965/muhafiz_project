using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Muhafiz.Agent.Utils
{
    public static class AdsReader
    {
        private const string ZONE_IDENTIFIER = ":Zone.Identifier";

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string fileName,
            [MarshalAs(UnmanagedType.U4)] FileAccess fileAccess,
            [MarshalAs(UnmanagedType.U4)] FileShare fileShare,
            IntPtr securityAttributes,
            [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
            int flags,
            IntPtr template);

        public static string? GetZoneIdentifierUrl(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return null;

            // Appending the stream name to the file path
            var streamPath = filePath + ZONE_IDENTIFIER;

            // GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING
            using var handle = CreateFile(streamPath, FileAccess.Read, FileShare.Read, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);

            if (handle.IsInvalid)
            {
                // This is not an error, it just means the file doesn't have the Zone.Identifier stream
                // (i.e., it wasn't downloaded from the internet).
                return null;
            }

            try
            {
                using var fs = new FileStream(handle, FileAccess.Read);
                using var reader = new StreamReader(fs, Encoding.UTF8);
                var content = reader.ReadToEnd();
                return ParseHostUrl(content);
            }
            catch (Exception)
            {
                // Something went wrong reading the stream
                return null;
            }
        }

        private static string? ParseHostUrl(string iniContent)
        {
            if (string.IsNullOrWhiteSpace(iniContent)) return null;

            using var reader = new StringReader(iniContent);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.StartsWith("HostUrl=", StringComparison.OrdinalIgnoreCase))
                {
                    return line.Substring("HostUrl=".Length).Trim();
                }
            }

            return null;
        }
    }
}
