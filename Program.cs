using System;
using System.Collections.Generic;
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

        static void Main(string[] args)
        {

            //netsh ipsec
            Polstore.IPSecOpenPolicyStore(null, Polstore.HandleType.HKEY, 0, out IntPtr policyHandle);


            //netsh ipsec static add policy Example Policy
            

            //netsh ipsec static add filterlist ExampleFilterList
            Nshipsec.CreateNewFilterList(policyHandle, "ExampleFilterList", "ExampleFilterListDescription");

            //netsh ipsec static add filter filterlist=lag srcaddr=any dstaddr=any protocol=tcp dstport=8080

            //netsh ipsec static add filteraction ExampleLagAction action=block


            //netsh ipsec static add rule name=ExampleRule policy=ExamplePolicy filterlist=ExampleFilterList filteraction=ExampleLagAction


            //netsh ipsec static set policy NAME_OF_POLICY assign=y
            //Locate GUID for policy to assign
            Polstore.IPSecAssignPolicy(policyHandle, Guid.NewGuid());

            //netsh ipsec static set policy lag assign=n
            throw new NotImplementedException();
        }
    }
    public class IpSecPolicy
    {
        public const int IPSEC_DATA_TYPE_256 = 256;
        public const string IPSEC_POLICY_STORE_REGISTRY_KEY = @"SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\";

        public static RegistryKey ipSecStoreKey = Registry.LocalMachine;

        static IpSecPolicy() =>
            ipSecStoreKey = ipSecStoreKey.OpenSubKey(IPSEC_POLICY_STORE_REGISTRY_KEY, true);

        public class IpsecFilter
        {
            public RegistryKey ipsecFilterKey;
            public Guid ipsecFilterGUID = Guid.NewGuid();



        }

        public static void WriteRegistryEntries(RegistryKey location, object[,] values)
        {
            for (int i = 0; i < values.GetLength(0); i++)
                location.SetValue((string)values[i, 0], values[i,1], (RegistryValueKind)values[i ,2]);
        }
        public static string GetUnixTimeStamp() => ((int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds)).ToString();
    }

}
