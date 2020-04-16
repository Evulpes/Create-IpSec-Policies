using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace Create_IpSec_Policies
{
    class Program
    {

        static void Main(string[] args)
        {

            //netsh ipsec static add policy Example Policy
            IpSecPolicy.Policy policy = new IpSecPolicy.Policy("ExamplePolicy", "ExamplePolicyDescription");

            //netsh ipsec static add filterlist ExampleFilterList
            IpSecPolicy.FilterList filterList = new IpSecPolicy.FilterList("ExampleFilterList", "ExampleFilterList Description");

            //netsh ipsec static add filter filterlist=lag srcaddr=any dstaddr=any protocol=tcp dstport=8080
            IpSecPolicy.Filter filter = new IpSecPolicy.Filter(filterList);

            //netsh ipsec static add filteraction ExampleLagAction action=block
            IpSecPolicy.FilterAction filterAction = new IpSecPolicy.FilterAction();

            //netsh ipsec static add rule name=ExampleRule policy=ExamplePolicy filterlist=ExampleFilterList filteraction=ExampleLagAction
            throw new NotImplementedException();

            //netsh ipsec static set policy lag assign=y
            throw new NotImplementedException();

            //netsh ipsec static set policy lag assign=y
            throw new NotImplementedException();
        }
    }
    public class IpSecPolicy
    {
        public const int IPSEC_DATA_TYPE_256 = 256;
        public const string IPSEC_POLICY_STORE_REGISTRY_KEY = @"SOFTWARE\Policies\Microsoft\Windows\IPSec\Policy\Local\";

        public static RegistryKey IpSecStoreKey = Registry.LocalMachine;

        static IpSecPolicy() =>
            IpSecStoreKey = IpSecStoreKey.OpenSubKey(IPSEC_POLICY_STORE_REGISTRY_KEY, true);


        public class Filter
        {
            public Filter(FilterList fList)
            {
                byte[] ipsecData = (byte[])fList.filterListSubKey.GetValue("ipsecData");

                //Byte 20 = filter count.
                ipsecData[20] = 0x01;

                byte[] newIpsecData = ipsecData.Concat(new byte[] 
                {
                    0x02,0x00,0x00,0x00,0x00,0x00,0x02,0x00,
                    0x00,0x00,0x00,0x00,0x12,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x8a,0xe6,0x50,0xd5,0xbc,0xa1,
                    0x5b,0x48,0x93,0x58,0x2b,0x47,0x5e,0xb0,
                    0xae,0x2f,0x01,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,
                    0xac,0xaa,0x00,0x00,0x00,0x00

                }).ToArray();
                //byte 104 and 105 = port (little endian).
                newIpsecData[104] = 0x90;
                newIpsecData[105] = 0x1F;
                fList.filterListSubKey.SetValue("ipsecData", newIpsecData, RegistryValueKind.Binary);
                fList.filterListSubKey.SetValue("whenChanged", GetUnixTimeStamp(), RegistryValueKind.DWord);
            }
        }
        public class FilterAction
        {
            RegistryKey filterActionKey;

            public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";
            public string name = "ipsecNegotiationPolicy";

            public FilterAction()
            {
                name += ipSecID;

                IpSecStoreKey.CreateSubKey(name);

                filterActionKey = IpSecStoreKey.OpenSubKey(name, true);

                CreateFilterAction("ExampleLagAction");

            }
            public void CreateFilterAction(string ipsecName)
            {
                WriteRegistryEntries(filterActionKey, new object[,]
                {
                    {"className", "ipsecNegotiationPolicy", RegistryValueKind.String },
                    {"ipsecData",  new byte[]
                    {
                        0xb9, 0x20, 0xdc, 0x80, 0xc8, 0x2e, 0xd1, 0x11,
                        0xa8, 0x9e, 0x00, 0xa0, 0x24, 0x8d, 0x30, 0x21,
                        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00
                    }, RegistryValueKind.Binary },
                    {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord },
                    {"ipsecID",  ipSecID, RegistryValueKind.String},
                    {"ipsecName", ipsecName, RegistryValueKind.String },
                    {"ipsecNegotiationPolicyAction", "{3f91a819-7647-11d1-864d-d46a00000000}", RegistryValueKind.String },
                    {"ipsecNegotiationPolicyType", "{62f49e10-6c37-11d1-864c-14a300000000}", RegistryValueKind.String },
                    {"name", name, RegistryValueKind.String},
                    {"whenChanged",  GetUnixTimeStamp(), RegistryValueKind.DWord}
                }); ;
            }
        }
        public class FilterList : IpSecPolicy
        {
            //Filterlist Registry Key Properties.
            public RegistryKey filterListSubKey;

            public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";
            public string name = "ipsecFilter";

            public FilterList(string filterName, string filterDescription)
            { 
                //Append the GUID to the name to match the correct format.
                name += ipSecID;

                //Create a subkey for the FilterList
                IpSecStoreKey.CreateSubKey(name);

                //Open the subkey as writable.
                filterListSubKey = IpSecStoreKey.OpenSubKey(name, true);

                //Populate the registry entries
                CreateFilterListKey(filterName, filterDescription);
            }
            public void CreateFilterListKey(string filterName, string filterDescription) =>
                WriteRegistryEntries(filterListSubKey, new object[,]
                {
                    {"className", "ipsecFilter", RegistryValueKind.String },
                    {"description", filterDescription, RegistryValueKind.String },
                    {"ipsecData",  new byte[]
                    {
                        0xB5, 0x20, 0xDC, 0x80, 0xC8, 0x2E, 0xD1, 0x11,
                        0xA8, 0x9E, 0x0, 0xA0, 0x24, 0x8D, 0x30, 0x21,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    }, RegistryValueKind.Binary },
                    {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord },
                    {"ipsecID",  ipSecID, RegistryValueKind.String},
                    {"ipsecName", filterName, RegistryValueKind.String },
                    {"name", name, RegistryValueKind.String},
                    {"whenChanged",  GetUnixTimeStamp(), RegistryValueKind.DWord}
                });
            
        }
        public class Policy : IpSecPolicy
        {
            //Filterlist Registry Key Properties.
            public RegistryKey policySubKey;

            public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";
            public string name = "ipsecPolicy";

            public Policy(string policyName, string policyDescription)
            {
                //Append the GUID to the name.
                name += ipSecID;
     
                //Create a subkey for the FilterList.
                IpSecStoreKey.CreateSubKey(name);

                //Open the subkey as writable.
                policySubKey = IpSecStoreKey.OpenSubKey(name, true);

                //Create the policy keys.
                CreatePolicyKey(policyName, policyDescription);

                //Create the ISAKMP Policy and keys.
                IpsecISAKMPPolicy ipsecISAKMPPolicy = new IpsecISAKMPPolicy(this);
                ipsecISAKMPPolicy.CreateISAKMPPolicyKey();

                IpsecNFA ipsecNfaPolicy = new IpsecNFA(this);
                ipsecNfaPolicy.CreateIpsecNFAKey();

                IpsecNegotiationPolicy ipsecNegPol = new IpsecNegotiationPolicy(ipsecNfaPolicy);
                ipsecNegPol.CreateIpsecNegPolicy();


            }

            public void CreatePolicyKey(string policyName, string policyDescription) =>
                WriteRegistryEntries(policySubKey, new object[,]
                {
                    {"className", "ipsecPolicy", RegistryValueKind.String},
                    {"description",  policyDescription, RegistryValueKind.String},
                    {"ipsecData",  new byte[]
                    {
                        0x63, 0x21, 0x20, 0x22, 0x4C, 0x4F, 0xD1, 0x11,
                        0x86, 0x3B, 0x00, 0xA0, 0x24, 0x8D, 0x30, 0x21,
                        0x04, 0x00, 0x00, 0x00, 0x30, 0x2A, 0x00, 0x00,
                        0x00,
                    }, RegistryValueKind.Binary },
                    {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord},
                    {"ipSecID", ipSecID, RegistryValueKind.String },
                    {"ipsecName", policyName,  RegistryValueKind.String},
                    {"name", name, RegistryValueKind.String },
                    {"whenChanged", GetUnixTimeStamp(), RegistryValueKind.DWord }
                });

            public class IpsecISAKMPPolicy
            {
                public RegistryKey isakmpKey;
                public string className = "ipsecISAKMPPolicy";
                public byte[] ipsecData = new byte[]
                {
                    0xB8,0x20,0xDC,0x80,0xC8,0x2E,0xD1,0x11,
                    0xA8,0x9E,0x0,0xA0,0x24,0x8D,0x30,0x21,
                    0xC0,0x0,0x0,0x0,0xEC,0xEC,0xA,0xFE,
                    0xCE,0x22,0x1A,0x4A,0x99,0xAA,0xB2,0xB,
                    0xE3,0x58,0xFD,0xFE,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x80,0x70,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x3,0x0,0x0,0x0,0x40,0x0,0x0,0x0,
                    0x8,0x0,0x0,0x0,0x2,0x0,0x0,0x0,
                    0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x80,0x70,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x3,0x0,0x0,0x0,0x40,0x0,0x0,0x0,
                    0x8,0x0,0x0,0x0,0x2,0x0,0x0,0x0,
                    0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x80,0x70,0x0,0x0,
                    0x0,0x0,0x0,0x0,0x0,
                };
                public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";

                //Owned by policy
                public readonly string[] ipsecOwnersReference;
                public readonly string name = "ipsecISAKMPPolicy";
                public string whenChanged;

                public IpsecISAKMPPolicy(Policy policy)
                {
                    ipsecOwnersReference = new string[] 
                    {
                        policy.policySubKey.Name.Substring(policy.policySubKey.Name.IndexOf("\\")).Remove(0,1)
                    };

                    name += ipSecID;

                    IpSecStoreKey.CreateSubKey(name);
                    isakmpKey = IpSecStoreKey.OpenSubKey(name, true);
                    policy.policySubKey.SetValue("ipsecISAKMPReference", isakmpKey.Name.Substring(isakmpKey.Name.IndexOf("\\")).Remove(0, 1), RegistryValueKind.String);
                }

                //netsh ipsec static add policy policyName
                public void CreateISAKMPPolicyKey() =>
                    WriteRegistryEntries(isakmpKey, new object[,]
                    {
                        {"className","ipsecISAKMPPolicy", RegistryValueKind.String },
                        {"ipsecData", new byte[]
                        {
                            0xB8,0x20,0xDC,0x80,0xC8,0x2E,0xD1,0x11,
                            0xA8,0x9E,0x0,0xA0,0x24,0x8D,0x30,0x21,
                            0xC0,0x0,0x0,0x0,0xEC,0xEC,0xA,0xFE,
                            0xCE,0x22,0x1A,0x4A,0x99,0xAA,0xB2,0xB,
                            0xE3,0x58,0xFD,0xFE,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x80,0x70,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x3,0x0,0x0,0x0,0x40,0x0,0x0,0x0,
                            0x8,0x0,0x0,0x0,0x2,0x0,0x0,0x0,
                            0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x80,0x70,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x3,0x0,0x0,0x0,0x40,0x0,0x0,0x0,
                            0x8,0x0,0x0,0x0,0x2,0x0,0x0,0x0,
                            0x40,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x2,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x80,0x70,0x0,0x0,
                            0x0,0x0,0x0,0x0,0x0,
                        }, RegistryValueKind.Binary },
                        {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord },
                        {"ipsecID", ipSecID, RegistryValueKind.String },
                        {"ipsecOwnersReference", ipsecOwnersReference, RegistryValueKind.MultiString },
                        {"name", name, RegistryValueKind.String },
                        {"whenChanged", GetUnixTimeStamp(), RegistryValueKind.DWord }

                    }); 
            }

            public class IpsecNegotiationPolicy
            {
                public RegistryKey ipsecNegPolicyKey;
                public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";

                //Owned by NFA
                public string[] ipsecOwnerReference;
                public string name = "ipsecNegotiationPolicy";

                public IpsecNegotiationPolicy(IpsecNFA policy)
                {

                    ipsecOwnerReference = new string[]
                    {
                        policy.ipsecNFAPolicyKey.Name.Substring(policy.ipsecNFAPolicyKey.Name.IndexOf("\\")).Remove(0,1)
                    };

                    name += ipSecID;
                    IpSecStoreKey.CreateSubKey(name);
                    ipsecNegPolicyKey = IpSecStoreKey.OpenSubKey(name, true);

                    policy.ipsecNFAPolicyKey.SetValue("ipsecNegotiationPolicyReference", ipsecNegPolicyKey.Name.Substring(ipsecNegPolicyKey.Name.IndexOf("\\")).Remove(0, 1), RegistryValueKind.String);
                    
                }

                //netsh ipsec static add policy policyName
                public void CreateIpsecNegPolicy()
                {
                    WriteRegistryEntries(ipsecNegPolicyKey, new object[,]
                    {
                        {"className", "ipsecNegotiationPolicy", RegistryValueKind.String },
                        { "ipsecData", new byte[]
                        {
                            0xb9, 0x20, 0xdc, 0x80, 0xc8, 0x2e, 0xd1, 0x11,
                            0xa8, 0x9e, 0x00, 0xa0, 0x24, 0x8d, 0x30, 0x21,
                            0xa4, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                            0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00
                        }, RegistryValueKind.Binary},
                        {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord },
                        {"ipsecID", ipSecID, RegistryValueKind.String },
                        {"ipsecNegotiationPolicyAction", "{8a171dd3-77e3-11d1-8659-a04f00000000}", RegistryValueKind.String },
                        {"ipsecNegotiationPolicyType", "{62f49e13-6c37-11d1-864c-14a300000000}", RegistryValueKind.String },
                        {"ipsecOwnersReference",  ipsecOwnerReference, RegistryValueKind.MultiString},
                        {"name", name, RegistryValueKind.String },
                        {"whenChanged", GetUnixTimeStamp(), RegistryValueKind.DWord }
                    });

                }

            }

            public class IpsecNFA
            {
                public RegistryKey ipsecNFAPolicyKey;

                public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";
                public string[] ipsecOwnersReference;
                public string name = "ipsecNFA";


                public IpsecNFA(Policy policy)
                {
                    name += ipSecID;
                    ipsecOwnersReference = new string[] { policy.policySubKey.Name.Substring(policy.policySubKey.Name.IndexOf("\\")).Remove(0, 1) };

                    IpSecStoreKey.CreateSubKey(name);
                    ipsecNFAPolicyKey = IpSecStoreKey.OpenSubKey(name, true);

                    policy.policySubKey.SetValue("ipsecNFAReference", new string[] { ipsecNFAPolicyKey.Name.Substring(ipsecNFAPolicyKey.Name.IndexOf("\\")).Remove(0, 1) });

                }
                public void CreateIpsecNFAKey() =>
                    WriteRegistryEntries(ipsecNFAPolicyKey, new object[,]
                    {
                        {"className", "ipsecNFA", RegistryValueKind.String},
                        {"ipsecData", new byte[]
                        {
                            0x00, 0xac, 0xbb, 0x11, 0x8d, 0x49, 0xd1, 0x11,
                            0x86, 0x39, 0x00, 0xa0, 0x24, 0x8d, 0x30, 0x21,
                            0x2a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                            0x05, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x02, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
                            0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                            0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00
                        }, RegistryValueKind.Binary },
                        {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord },
                        {"ipsecID", ipSecID, RegistryValueKind.String },
                        {"ipsecOwnerReference", ipsecOwnersReference, RegistryValueKind.MultiString },
                        {"name", name, RegistryValueKind.String },
                        {"whenChanged", GetUnixTimeStamp(), RegistryValueKind.DWord }

                    });
                
            }
        }
        public class Rule
        {
            public RegistryKey ruleSubKey;

            public readonly string ipSecID = "{" + Guid.NewGuid().ToString() + "}";
            public string name = "ipsecNFA";

            public Rule()
            {
                name += ipSecID;

                IpSecStoreKey.CreateSubKey(name);

                ruleSubKey = IpSecStoreKey.OpenSubKey(name, true);

            }
            public void CreateRuleKey(string ipsecName, Policy.IpsecNegotiationPolicy ipsecNegPol, FilterList ipsecFilterList, IpSecPolicy.Policy ipsecPolicy) =>
                WriteRegistryEntries(ruleSubKey, new object[,]
                {
                    {"className", "ipsecNFA", RegistryValueKind.String},
                    {"ipsecData",  new byte[]
                    {
   
                    }, RegistryValueKind.Binary },
                    {"ipsecDataType", IPSEC_DATA_TYPE_256, RegistryValueKind.DWord},
                    {"ipsecFilterReference", new string[] { ipsecFilterList.filterListSubKey.Name.Substring(ipsecFilterList.filterListSubKey.Name.IndexOf("\\")).Remove(0, 1) }, RegistryValueKind.MultiString },
                    {"ipsecID", ipSecID, RegistryValueKind.String },
                    {"ipsecName", ipsecName, RegistryValueKind.String },


 
                });
        }
        public static void WriteRegistryEntries(RegistryKey location, object[,] values)
        {
            for (int i = 0; i < values.GetLength(0); i++)
                location.SetValue((string)values[i, 0], values[i,1], (RegistryValueKind)values[i ,2]);
        }
        public static string GetUnixTimeStamp() => ((int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds)).ToString();
    }

}
