using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;

using IPAddr = System.UInt32;
using IPMask = System.UInt32;
using System.Data;
using System.Diagnostics;

namespace Create_IpSec_Policies
{
    class NativeMethods
    {
        protected static class Handleapi
        {
            [DllImport("Kernel32", SetLastError = true)]
            public static extern bool CloseHandle(IntPtr handle);
            [DllImport("Kernel32", SetLastError = true)]
            public static extern bool FreeLibrary(IntPtr hLibModule);
        }
        protected static class Ipsec
        {
            public struct IPSEC_FILTER
            {
                IPAddr SrcAddr;
                IPMask SrcMask;
                IPAddr DestAddr;
                IPMask DestMask;
                IPAddr TunnelAddr;
                uint Protocol;
                byte SrcPort;
                byte DestPort;
                bool TunnelFilter;
                unsafe fixed char Pad[1];
                ushort Flags;
            }
        }
        protected static class Libloaderapi
        {
            [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
            public static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
        }
        protected class Nshipsec : IDisposable
        {
            private IntPtr handle = Libloaderapi.LoadLibraryA(@"C:\Windows\System32\nshipsec.dll");
            private delegate WinError.SeverityCode CreateNewFilterListDelegate(IntPtr handle, [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string desc);

            public WinError.SeverityCode CreateNewFilterList(IntPtr policyStoreHandle, [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string description)
            {
                if (handle == IntPtr.Zero)
                    return WinError.SeverityCode.ERROR_INVALID_HANDLE;

                return ((CreateNewFilterListDelegate)Marshal.GetDelegateForFunctionPointer(handle + (int)FunctionOffsets.CREATE_FILTER_LIST_OFFSET, typeof(CreateNewFilterListDelegate))).Invoke(policyStoreHandle, name, description);
            }
            public enum FunctionOffsets
            {
                //Pattern
                //E8 CF 57 02 00
                CREATE_FILTER_LIST_OFFSET = 0xF6B0,
            }

            #region IDisposable Support
            private bool disposedValue = false;

            protected virtual void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    if (disposing)
                    {
                    }
                    Handleapi.FreeLibrary(handle);
                    handle = IntPtr.Zero;

                    disposedValue = true;
                }
            }
             ~Nshipsec()
             {
               Dispose(false);
             }

            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(true);
            }
            #endregion

        }
        protected class Polstore : IDisposable
        {
            #region variables
            private IntPtr hPolstore = Libloaderapi.LoadLibraryA(@"C:\Windows\System32\polstore.dll");
            public IntPtr hPolicyStore;
            #endregion

            #region imports
            [DllImport("polstore", SetLastError = true)]
            public static extern WinError.SeverityCode IPSecOpenPolicyStore([MarshalAs(UnmanagedType.LPWStr)]string machineName, TypeOfStore typeOfStore, [MarshalAs(UnmanagedType.LPWStr)]string fileName, out IntPtr policyStoreHandle);
            [DllImport("polstore", SetLastError = true)]
            public static extern WinError.SeverityCode IPSecClosePolicyStore(IntPtr hPolicyStore);
            [DllImport("polstore", SetLastError = true)]
            private static extern WinError.SeverityCode IPSecGetFilterData(IntPtr hPolicyStore, Guid filterGuid, IntPtr ppIpsecFilterData);
            [DllImport("polstore", SetLastError = true)]
            private static extern WinError.SeverityCode IPSecDeleteFilterData(IntPtr hPolicyStore, Guid filterIdentifier);
            #endregion

            #region methods
            public WinError.SeverityCode IPSecGetFilter(IntPtr hPolicyStore, Guid filterGuid, IntPtr ppIpsecFilterData)
            { 
                if (hPolstore == IntPtr.Zero)
                    return WinError.SeverityCode.ERROR_INVALID_HANDLE;

                return IPSecGetFilterData(hPolicyStore, filterGuid, ppIpsecFilterData);
            }
            public WinError.SeverityCode IPSecDeleteFilter(IntPtr hPolicyStore, Guid filterIdentifier)
            {
                if (hPolstore == IntPtr.Zero)
                    return WinError.SeverityCode.ERROR_INVALID_HANDLE;

                return IPSecDeleteFilterData(hPolicyStore, filterIdentifier);
            }
            #endregion

            #region classes
            public static class Polstructs
            {
                public struct IPSEC_FILTER_SPEC
                {
                    [MarshalAs(UnmanagedType.LPWStr)] string srcDNSName;
                    [MarshalAs(UnmanagedType.LPWStr)] string destDNSName;
                    [MarshalAs(UnmanagedType.LPWStr)] string description;
                    Guid filterSpecGUID;
                    uint dwMirrorFlag;
                    Ipsec.IPSEC_FILTER filter;
                }
                public struct IPSEC_FILTER_DATA
                {
                    public Guid filterIdentifier;
                    public uint numFilterSpecs;
                    public IntPtr filterSpecs; //PIPSEC_FILTER_SPEC * ppFilterSpecs;
                    public uint whenChanged;
                    [MarshalAs(UnmanagedType.LPWStr)] public string ipsecName;
                    [MarshalAs(UnmanagedType.LPWStr)] public string ipsecDescription;
                }
            }
            #endregion

            #region enums
            public enum TypeOfStore : int
            {
                IPSEC_REGISTRY_PROVIDER = 0,
                IPSEC_DIRECTORY_PROVIDER = 1,
                IPSEC_FILE_PROVIDER = 2,
            }
            #endregion

            #region IDisposable Support
            private bool disposedValue = false;

            protected virtual void Dispose(bool disposing)
            {
                if (!disposedValue)
                {
                    if (disposing)
                    {
                    }
                    Handleapi.FreeLibrary(hPolstore);
                    hPolstore = IntPtr.Zero;
                    IPSecClosePolicyStore(hPolicyStore);
                    disposedValue = true;
                }
            }

             ~Polstore()
             {
               Dispose(false);
             }
            public void Dispose()
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
            #endregion

        }
        public static class WinError
        {
            public enum SeverityCode : uint
            {
                ERROR_SUCCESS = 0x0,
                ERROR_FILE_NOT_FOUND = 0x2,
                ERROR_ACCESS_DENIED = 0x5,
                ERROR_INVALID_HANDLE = 0x6,
                ERROR_INVALID_DATA = 0xD,
                ERROR_OUTOFMEMORY = 0xE,
                ERROR_INVALID_PARAMETER = 0x57,
                ERROR_INVALUD_PARAMETER = 0x80070057,

            }
        }
    }
}
