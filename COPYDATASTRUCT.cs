using System;
using System.Runtime.InteropServices;

namespace PageantPlugin
{
    [StructLayout (LayoutKind.Sequential)]
    internal struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
}