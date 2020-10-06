# IpSec-Extraction
## Introduction - You Document Nothing, Jon Snow
This is (currently) an ongoing project where I try to extract netsh ipsec commands from their relative DLLs and create a wrapper to use them. Currently, there is no documented way to create IPSec filters via .Net or C++ without calling on the Windows Shell or using the WFP. 
As this is a progressive project, I have decided to do a write-up as I go, so when I come back to it I'm not lost in progress.
## What's The Point?
The point is that ipsec rules differ in how they are handled from the Windows Firewall. For example, when a Windows Firewall is created that blocks port 443, any open connection that uses 443 is immediately terminated. When a rule is created using an ipsec filter, the connection remains in place but is blocked, and will continue to try and reconnect until it times out.
## Identifying The DLLs
To identify the DLLs required for this job, we'll first need to work out what functions netsh ipsec is calling when it executes it's various commands. To do this, we're going to use an [API Monitor](http://www.rohitab.com/apimonitor).

By spinning up a netsh prompt and attaching API Monitor we're able to see what functions and DLLs are called to:
<p align="center">
  <img src="https://i.imgur.com/k4DCtwE.png"/>
</p>

Straight away, we can see that calls to NSHIPSEC.DLL and POLSTORE.DLL are made. Furthermore, we can also see that there are enumerations of registry keys, so it's likely that the policy information is actually stored in the registry.

For context normally creating, and assigning, a simple ipsec policy via the command line goes like this:
1. netsh ipsec static add policy ExamplePolicy
2. netsh ipsec static add filterlist ExampleFilterList
3. netsh ipsec static add filter filterlist=ExampleFilterList srcaddr=any dstaddr=any protocol=tcp dstport=8080
4. netsh ipsec static add filteraction ExampleFilterAction action=block
5. netsh ipsec static add rule name=ExampleRule policy=ExamplePolicy filterlist=ExampleFilterList filteraction=ExampleFilterAction
6. netsh ipsec static set policy ExamplePolicy assign=y

With this in mind, we can execute each function and have a gander at APIMonitor further:
<p align="center">
  <img src="https://i.imgur.com/7ijDcqU.png"/>
</p>

Straight away we can see that attributes for the policy are created, and that there is more registry activity. By searching the registry for these attributes, we can indeed confirm that the details of the policy are written:

<p align="center">
  <img src="https://i.imgur.com/4H1tXAi.png"/>
</p>

While this isn't overly important, it's handy to know.

Anyway, as M&M said once, snap back to reality and lets have a look in these DLLs.

## Nshipsec
### DeletePolicy
```
__int64 __fastcall DeletePolicy(struct _IPSEC_POLICY_DATA *a1, void *a2)
```
#### Param 1
Param 1 takes a IPSEC_POLICY_DATA struct, which doesn't seem to be documented anywhere. During runtime, upon calling the function with at least one valid policy in place, we can observe that the struct is a representation of the registry information for the policy.
As it's running as x64, the first parameter, being an integer, is passed to RCX:

<p align="center">
  <img src="https://i.imgur.com/m4teMNm.png"/>
</p>

## Leakages
At this point, I realised that the Windows XP Source Code had recently leaked online and the struct definitions would be present there.
