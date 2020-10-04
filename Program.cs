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
        static unsafe void Main(string[] args)
        {


            if(OpenPolicyStore(out IntPtr hPolicyStore))
            {
                Console.WriteLine($"Failed to open policy store with error: {Marshal.GetLastWin32Error()}");
                Environment.Exit(0);
            }


            if (GetFilterData(hPolicyStore, new Guid("56FB8D2D-7E61-40B5-B9A3-904C1F43AD5F"), out Polstore.Polstructs.IPSEC_FILTER_DATA ipsecFilterData))
                Console.WriteLine($"Failed to get filter data with error: {Marshal.GetLastWin32Error()}");
            
            else
            {
                Console.WriteLine
                (
                    $"Filter Details:\n" +
                    $"Filter GUID:       {ipsecFilterData.filterIdentifier}\n" +
                    $"Filter Specs Ptr:  0x{Marshal.ReadInt64(ipsecFilterData.filterSpecs):X}\n" +
                    $"IPSec Description: {ipsecFilterData.ipsecDescription}\n" +
                    $"IPSec Name:        {ipsecFilterData.ipsecName}\n" +
                    $"Filter Specs:      {ipsecFilterData.numFilterSpecs}\n" +
                    $"When changed:      {ipsecFilterData.whenChanged:x}\n"
                );
            }

            int me = 5;
            Console.WriteLine("hello");
            Console.ReadLine();
        }
        private static bool OpenPolicyStore(out IntPtr hPolicyStore)
        {
            return Convert.ToBoolean(Polstore.IPSecOpenPolicyStore("", Polstore.TypeOfStore.IPSEC_REGISTRY_PROVIDER, "", out hPolicyStore));
        }
        private static bool GetFilterData(IntPtr hPolicyStore, Guid guid, out Polstore.Polstructs.IPSEC_FILTER_DATA ipsecFilterData)
        {
            IntPtr ipsecFilterDataPtr = Marshal.AllocHGlobal(0x8);
            ipsecFilterData = new Polstore.Polstructs.IPSEC_FILTER_DATA();

            Marshal.StructureToPtr(ipsecFilterData, ipsecFilterDataPtr, false);

            if (Convert.ToBoolean(hPolStoreLib.IPSecGetFilterData(hPolicyStore, guid, ipsecFilterDataPtr)))
                return true;

            ipsecFilterData = (Polstore.Polstructs.IPSEC_FILTER_DATA)Marshal.PtrToStructure((IntPtr)Marshal.ReadInt64(ipsecFilterDataPtr), typeof(Polstore.Polstructs.IPSEC_FILTER_DATA));

            return false;
        }
    }

}
