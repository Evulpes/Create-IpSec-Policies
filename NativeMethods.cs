using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;

namespace Create_IpSec_Policies
{
    class NativeMethods
    {
        public static class Libloaderapi
        {
            [DllImport("Kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
            public static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

        }
        public static class Nshipsec
        {
            private delegate WinError.SeverityCode CreateNewFilterListDelegate(IntPtr handle, [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string desc);

            /// <summary>
            /// 
            /// </summary>
            /// <param name="policyStoreHandle"></param>
            /// <param name="name"></param>
            /// <param name="description"></param>
            /// <returns></returns>
            public static WinError.SeverityCode CreateNewFilterList(IntPtr policyStoreHandle, [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string description)
            {

                IntPtr handle = Libloaderapi.LoadLibraryA(@"C:\Windows\System32\nshipsec.dll");

                if (handle == IntPtr.Zero)
                    return WinError.SeverityCode.ERROR_INVALID_HANDLE;

                CreateNewFilterListDelegate function = (CreateNewFilterListDelegate)(Marshal.GetDelegateForFunctionPointer((handle + (int)FunctionOffsets.CREATE_FILTER_LIST_OFFSET), typeof(CreateNewFilterListDelegate)));

                return function.Invoke(policyStoreHandle, name, description);
            }
            public enum FunctionOffsets
            {
                CREATE_FILTER_LIST_OFFSET = 0xF6B0,
            }

        }
        public static class Polstore
        {
            /// <summary>
            /// 
            /// </summary>
            /// <param name="hkeyHandle">An open handle to the policy store.</param>
            /// <param name="guid">The GUID of the policy to assign.</param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern WinError.SeverityCode IPSecAssignPolicy(IntPtr hkeyHandle, Guid guid);

            /// <summary>
            /// 
            /// </summary>
            /// <param name="hkeyHandle">An open handle to the policy store.</param>
            /// <param name="activePolicyGuid">A pointer to the GUID of the Active Policy.</param>
            /// <returns>A Windows Severity Code.</returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern WinError.SeverityCode IPSecGetAssignedPolicyData(IntPtr hkeyHandle, out IntPtr activePolicyGuid);

            /// <summary>
            /// 
            /// </summary>
            /// <param name="hostname">The hostname of the device to open the key on.</param>
            /// <param name="handleType">Appears to be the type of handle to open.</param>
            /// <param name="a3">Unknown.</param>
            /// <param name="hkeyHandle">A handle to the policy store.</param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern WinError.SeverityCode IPSecOpenPolicyStore([MarshalAs(UnmanagedType.LPWStr)] string hostname, HandleType handleType, int a3, out IntPtr hkeyHandle);

            /// <summary>
            /// 
            /// </summary>
            /// <param name="hkeyHandle">An open handle to the policy store.</param>
            /// <param name="policyGuid">A pointer to the GUID of the active policy..</param>
            /// <returns></returns>
            [DllImport("polstore", SetLastError = true)]
            public static extern WinError.SeverityCode IPSecUnassignPolicy(IntPtr hkeyHandle, IntPtr policyGuid);

            public enum HandleType : uint
            {
                HKEY = 0x0,
                Unknown = 0x1,
                ETWRegistration1 = 0x2,
                ETWRegistration2 = 0x3,
                ETWRegistration3 = 0x5,

            }

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
                The_Parameter_Is_Incorrect = 0x80070057,
            }
        }
    }
}
