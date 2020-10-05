using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Create_IpSec_Policies
{
    class Program : NativeMethods
    {
        static readonly Polstore hPolStoreLib = new Polstore();
        static void Main(string[] args)
        {


            if(OpenPolicyStore(out hPolStoreLib.hPolicyStore))
            {
                Console.WriteLine($"Failed to open policy store with error: {Marshal.GetLastWin32Error()}");
                Environment.Exit(0);
            }


            if (GetFilterData(hPolStoreLib.hPolicyStore, new Guid("{43a24ceb-e7ce-4b40-978f-9e0b6fd90d45}"), out Polstore.Polstructs.IPSEC_FILTER_DATA ipsecFilterData))
                Console.WriteLine($"Failed to get filter data with error: {Marshal.GetLastWin32Error()}");
            
            else
            {
                Console.WriteLine
                (
                    $"Filter Details:\n" +
                    $"Filter GUID:       {ipsecFilterData.filterIdentifier}\n" +
                    $"Filter Specs Ptr:  0x{ipsecFilterData.filterSpecs}\n" +
                    $"IPSec Description: {ipsecFilterData.ipsecDescription}\n" +
                    $"IPSec Name:        {ipsecFilterData.ipsecName}\n" +
                    $"Filter Specs:      {ipsecFilterData.numFilterSpecs}\n" +
                    $"When changed:      {ipsecFilterData.whenChanged:x}\n"
                );
            }

            if (DeleteFilterData(hPolStoreLib.hPolicyStore, new Guid("{43a24ceb-e7ce-4b40-978f-9e0b6fd90d45}")))
                Console.WriteLine("Failed to delete policy.");

            Console.WriteLine("Policy Deleted");

            hPolStoreLib.Dispose();

            Console.ReadLine();
        }
        private static bool OpenPolicyStore(out IntPtr hPolicyStore)
        {
            return Convert.ToBoolean(Polstore.IPSecOpenPolicyStore("", Polstore.TypeOfStore.IPSEC_REGISTRY_PROVIDER, "", out hPolicyStore));
        }
        private static bool ClosePolicyStore(IntPtr hPolicyStore)
        {
            return Convert.ToBoolean(Polstore.IPSecClosePolicyStore(hPolicyStore));
        }
        private static bool DeleteFilterData(IntPtr hPolicyStore, Guid guid)
        {
            return Convert.ToBoolean(hPolStoreLib.IPSecDeleteFilter(hPolicyStore, guid));
        }
        private static bool GetFilterData(IntPtr hPolicyStore, Guid guid, out Polstore.Polstructs.IPSEC_FILTER_DATA ipsecFilterData)
        {
            IntPtr ipsecFilterDataPtr = Marshal.AllocHGlobal(0x8);
            ipsecFilterData = new Polstore.Polstructs.IPSEC_FILTER_DATA();

            Marshal.StructureToPtr(ipsecFilterData, ipsecFilterDataPtr, false);

            if (Convert.ToBoolean(hPolStoreLib.IPSecGetFilter(hPolicyStore, guid, ipsecFilterDataPtr)))
                return true;

            ipsecFilterData = (Polstore.Polstructs.IPSEC_FILTER_DATA)Marshal.PtrToStructure((IntPtr)Marshal.ReadInt64(ipsecFilterDataPtr), typeof(Polstore.Polstructs.IPSEC_FILTER_DATA));

            return false;
        }
    }

}
