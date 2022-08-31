# Powershell4Tenable

Tenable for Powershell is a Powershell module that adds a variety of controls and reporting to the Tenable.io cloud, allowing users to import data into Tenable for scans, export data from Tenable and correlate information across systems.

You must set the following variables

Very few of these powershell functions have great failsafe processes, so please beware. This is not an elegent solution. 

PS C:\> Import-Module .\TenablePowershell.psm1

You need to variables set up. the $apikey and the $defaultScannerID. This is an example of what they should look like. 

$apikey = "accessKey=XXXX;secretKey=a246bf07a405d6c8bds5af5616516512110190f7a9a22a1c0257"

$defaultScannerID = "12345678-9abc-defg-1234-56789abcdefg"

I set up my $defaultScannerID to my scan group that is used the most. 

