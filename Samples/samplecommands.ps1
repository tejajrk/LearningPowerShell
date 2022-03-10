
pwsh
$data = Get-Service | Where-Object Status -eq 'Stopped' | Select-Object Name,Status
$data | Out-File .\services.csv
$data | Export-Csv .\services2.csv
 
# Get-Content .\services2.csv | more
 
#notepad.exe .\services.csv
 
$PSVersionTable
(get-command).count
 
#Verb-Noun
 
#Get-Verb
 
#Get-Service -ComputerName Client01
#Get-Service | format-list
Get-Service | Where-Object Status -eq "stopped" | format-list | more
Get-Verb -Group Security | Format-List
 
Get-Alias  | More
Get-Alias -Definition *service*
 
Get-Command
Get-Help
Get-Member
 
Get-Command -Verb Get -Noun *DNS*
Get-Command -Name *Fire* -CommandType Function
 
Get-Command -Noun File*
Get-Command -Verb Get -Noun File*
Get-Help -Name Get-Command -Detailed
Get-Help -Name *DNS*
 
Get-Help -Name Get-FileHash
help Get-FileHash
 
update-help
 
Update-Help -UICulture en-US
 
help Get-Service -Examples
 
Get-Process -Name 'name-of-process' | Get-Member
 
Get-Process
 
Get-Command -ParameterType Process
Get-Process | Sort-Object -Descending -Property Name
 
Get-Process 'some process' | Sort-Object -Property @{Expression = "Name"; Descending = $True}, @{Expression = "CPU"; Descending = $False}
 
Get-Process | Where-Object CPU -gt 2
Get-Process | Where-Object CPU -gt 2 | Sort-Object CPU -Descending
Get-Process | Where-Object CPU -gt 2 | Sort-Object CPU -Descending | Select-Object -First 3
 
#Formatting from left is a good practice
Get-Process | Select-Object Name | Where-Object Name -eq 'name-of-process'
 
Get-Process | Where-Object Name -eq name-of-process | Select-Object Name
 
Get-Process -Name name-of-process | Select-Object Name
 
#Formatting from right destroys the object.
 
Get-Process 'some process' | Select-Object Name, CPU | Get-Member
Get-Process 'some process' | Format-Table Name,CPU | Get-Member
 
#above command give below result instead of values.
 
TypeName: Microsoft.PowerShell.Commands.Internal.Format.FormatStartData
TypeName: Microsoft.PowerShell.Commands.Internal.Format.GroupStartData
TypeName: Microsoft.PowerShell.Commands.Internal.Format.FormatEntryData
TypeName: Microsoft.PowerShell.Commands.Internal.Format.GroupEndData
 
Get-Process 'some process' | Select-Object Name, Cpu
 
#Formatting first doesn't help.
 
Get-Process 'some process' | Format-Table Name,CPU | Select-Object Name, CPU
 
"a string" | Get-Member
"a string" | Get-Member | Format-List
 
New-Item HelloWorld.ps1
code HelloWorld.ps1
 
# Write-Output -InputObject 'Hello World!'
 
$name = Read-Host -Prompt "Please enter your name"
Write-Output "Congratulations $name! You have written your first code with PowerShell!"
 
Get-Service |
  Where-Object {$_.DependentServices} |
    Format-List -Property Name, DependentServices, @{
      Label="NoOfDependentServices"; Expression={$_.dependentservices.count}
    }
 
Get-Service | Where-Object {$_.DisplayName -like "*Extensible Auth*"} | Format-List -Property DisplayName, Status
Get-Service | Where-Object {($_.DisplayName -like "*Extensible Auth*") -or ($_.DisplayName -like "*Runtime_d9dae*")} | ForEach-Object { $_.DisplayName + ',' + $_.Status }
 
Get-Service "s*" | Sort-Object status
 
help Get-Service -Full
 
Get-Command -CommandType Function | measure-object
 
Get-History
 
Invoke-History -id 24
 
Get-History
 
Clear-History
 
Get-History | Format-Table -property CommandLine
Get-History | Format-Table -property CommandLine  -HideTableHeaders | Out-File .\sample.ps1
 
Start-Transcript -path .\logfile
Stop-Transcript
 
Notepad .\logfile
 
Get-Service | Get-Member
 
Get-Service | Where-Object status -eq "Stopped" | Start-Service
 
Get-Command -Name get-*Fire*
 
help Get-NetFirewallRule
 
Get-NetFirewallRule | Get-Member
 
Get-NetFirewallRule  -Name *RemoteDesktop* | Format-Table
 
#-whatif will not actually run the command but just gives output as what would have happened.
Get-NetFirewallRule -Name *RemoteDesktop* | Set-NetFirewallRule -Enabled 'True' -WhatIf
 
Get-NetFirewallRule -Name *RemoteDesktop* | Set-NetFirewallRule -Enabled 'True'
 
#Windows Management Instrumentation (WMI) - Legacy
Get-WmiObject
 
#Common information Model (CIM) - Future
Get-CimInstance
 
help Get-Counter
Get-Counter -ListSet *memory*
Get-Counter -ListSet Memory
Get-Counter -ListSet Memory | Select-Object -Expand Counter
 
Get-Counter -Counter "\Memory\Pages/sec", "\Memory\Committed Bytes" | Format-Table
 
Get-WmiObject -List *
Get-CimClass -ClassName *
 
Get-CimClass -ClassName *Memory*
 
Get-WmiObject -class Win32_PhysicalMemory
Get-CimInstance -ClassName Win32_PhysicalMemory
 
Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object Tag,Capacity
 
#Not true powershell commands. So they wont result any objects
ipconfig |Get-member
 
Get-Command Get-NetIP*
 
Get-NetIPAddress
 
Get-Command get-DNS*
GCM get-DNS*
GCM get-DNSClient*
 
Get-DnsClient
 
New-SmbMapping -LocalPath w: -RemotePath \\DC01\Share
 
get-command get-*Event*
 
help Get-EventLog -Examples
 
Get-EventLog -LogName System | Get-Member
 
#Works in powershell 5 and not in 7+
Get-EventLog -log System -newest 1000 | Where-Object {$_.eventid -eq '1074'} | Format-Table machinename, username, timegenerated -AutoSize
 
#works in both old and new
Get-WinEvent -FilterHashtable @{logname = 'System'; id = 1074} | Format-Table -wrap
Get-WinEvent -FilterHashtable @{logname = 'System'; id = 1074} -MaxEvents 1| Format-Table -wrap
 
Get-ComputerInfo
 
Get-ComputerInfo -Property *Memory*
 
help Get-ChildItem
 
Get-ChildItem -Path w:\ -Recurse
 
Get-ChildItem -Path w:\ -Recurse | Get-Member
Get-ChildItem -Path w:\ -Recurse | Where-Object Extension -EQ '.png' | Format-Table Directory,Name,LastWriteTime
 
Copy-Item w:\ -Destination c:\CopiedFolder -Recurse -Verbose
Move-Item c:\CopiedFolder -Destination c:\MovedFolder -verbose
 
Rename-Item C:\MovedFolder -NewName c:\RenamedFolder


# Variables
 
Get-ChildItem ENV: | more
# below are built into windows
$env:ComputerName
$env:PATH
# below is how to access variables built into powershell script
Get-Variable | more
$PSVersionTable
 
$RemoteComputerName = "Client02"
 
Write-Output "The name of remote computer is $RemoteComputerName"
Write-Output 'The name of remote computer is $RemoteComputerName'
 
#opens up a prompt to enter username password on powershell 5. On Powershell core/7 you have to manually enter credentials on command prompt
$credential = Get-Credential
 
$credential
 
Get-Variable -Name c*
 
Get-Service -ComputerName $RemoteComputerName
# PS commands to run remotely accept below parameter.
-ComputerName
#interactive session on remote machine
-PSSession
#you may not have the tool/command locally but to invoke it on remote server use below
Invoke-Command
 
# for powershell 3 or above for commands where -ComputerName doesn't work.
New-CimSession
 
# Examples
Get-Service -ComputerName $RemoteComputerName | Select-Object Name, Status
 
# PS session examples
Get-Command *-PSSession
 
$credential = Get-Credential
New-PSSession -ComputerName $RemoteComputerName -Credential $credential
Enter-PSSession -Name WinRM1
$env:ComputerName
exit
Get-PSSession
Enter-PSHostProcess -id 1
$env:ComputerName
exit
Remove-PSSession  -id 1
Get-PSSession
 
#Invoke-Command
 
help Invoke-Command
 
#below command won't work as we $RemoteComputerName variable is local and doesn't get passed to remote server
Invoke-Command -ComputerName $RemoteComputerName -Credential $credential -ScriptBlock {
  Get-Service -ComputerName $RemoteComputerName
}
 
#Below is the workaround for above problem
Invoke-Command -ComputerName $RemoteComputerName -Credential $credential -ScriptBlock {
  Get-Service -ComputerName $using:RemoteComputerName
}
 
$data = Invoke-Command -ComputerName $RemoteComputerName -Credential $credential -ScriptBlock {
  Get-Service -ComputerName $using:RemoteComputerName
}
 
$data | Get-Member
 
# Powershell 7
 
Invoke-Command -ComputerName $RemoteComputerName -cred (Get-Credential) -ScriptBlock {Get-ADUser -Identity flexib | Format-List}
 
help New-CimSession
$cimsession = New-CimSession -ComputerName $RemoteComputerName -Credential $credential
$cimsession
 
Get-CimSession
 
Get-DnsClientServerAddress -CimSession $cimsession
 
# set Permissions to scripts
 
.\View-StoppedService.ps1
 
Get-ExecutionPolicy
 
Hep Set-ExecutionPolicy -parameter ExecutionPolicy
 
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
.\View-StoppedService.ps1
 
# To read input
 
$hostname = Read-Host "Enter Computer Name: "
Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $hostname |
Select-Object -Property CSName,LastBootUpTime


$response = Invoke-RestMethod $url
$response.result | Where-Object running_state -eq "running"
$response.result | Where-Object running_state -eq "running" | Format-Table inst_name,running_state,full_gc_count
$response.result | Where-Object running_state -eq "running" | Format-Table inst_name,running_state,full_gc_count -HideTableHeaders







=====================================================
#Get-SErviceStatus.ps1 - Script displays the status of services running on a specified machine
 
#creates a mandatory parameter for ComputerName and for Service Status
 
Param(
    [Parameter(Mandatory=$true)]
    [String[]]  $ComputerName    #Additional [] after string denotes this parameter accespts multiple inputs
         #Note this is same as the variable used in your code below
)
 
foreach ($target in $ComputerName) {
 
#Creates a variable for Get-SErvice Object
#As it can hold multiple objects, refered to as an array
Write-Output "====================================================="
$Services = Get-Service -ComputerName $target
 
#User foreach construct to perform action on each object in $services
 
Foreach ($service in $Services) {
    #create Variable containing status and displayname using member enumeration
   
    $ServiceStatus = $service.Status  #decimal notation(.) allows access to properties of each object
    $ServiceDisplayName = $service.DisplayName
 
    if ($ServiceStatus -eq 'Running'){
        Write-Output "Service OK - Status of $ServiceDisplayName is $ServiceStatus"
    }
    else {
        Write-Output "Check Service - Status of $ServiceDisplayName is $ServiceStatus"
    }
}
}



=======================================
#sample function

function Get-Greeting {
  "Hello world"
}

Get-Greeting

function Write-Greeting {

  param (
  [Parameter(Mandatory, Position=0)]
  [String]  $name,
  [Parameter(Mandatory, Position=1)]
  [int] $age)

  "Hello $name, you are $age years old"
}

Write-Greeting -name "Teja" -age 35