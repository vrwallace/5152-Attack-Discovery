####################################
# Program: 5152attackdiscovery.ps1
# By: Von Wallace
# To run add the following to the login script
# powershell.exe –Noninteractive –Noprofile –Command "C:\support\5152attackdiscovery.ps1"
# Writes selected events to a file in the C:\support folder does reverse lookup on IP addresses and DNS names and writes to the file c:\support\geoinfop.txt
###################################


$IPStackkey="ENTER YOUR IPSTACK KEY HERE"

$events = Get-EventLog -Log Security | Where-Object {$_.InstanceID -eq 5152}
$events | ForEach-Object {$_.message -match "Source Address:\s+(\S+)">$null;$_ | Add-Member -membertype noteproperty -name "SrcIP" -value $matches[1]}
$events | ForEach-Object {$_.message -match "Destination Address:\s+(\S+)">$null;$_ | Add-Member -membertype noteproperty -name "DstIP" -value $matches[1]}
$events | ForEach-Object {$_.message -match "Source Port:\s+(\S+)">$null;$_ | Add-Member -membertype noteproperty -name "SrcPort" -value $matches[1]}
$events | ForEach-Object {$_.message -match "Destination Port:\s+(\S+)">$null;$_ | Add-Member -membertype noteproperty -name "DstPort" -value $matches[1]}
$events | ForEach-Object {$_.message -match "Application Name:\s+(\S+)">$null;$_ | Add-Member -membertype noteproperty -name "AppName" -value $matches[1]}
$events | select-object SrcIP, SrcPort, DstIP, DstPort, AppName |  Export-Csv -Path c:\support\5152log.csv -NoTypeInformation


#{"ip":"8.8.8.8","type":"ipv4","continent_code":"NA","continent_name":"North America","country_code":"US","country_name":"United States","region_code":"CA","region_name":"California","city":"Mountain View","zip":"94041","latitude":37.38801956176758,"longitude":-122.07431030273438,"location":{"geoname_id":5375480,"capital":"Washington D.C.","languages":[{"code":"en","name":"English","native":"English"}],"country_flag":"http:\/\/assets.ipstack.com\/flags\/us.svg","country_flag_emoji":"\ud83c\uddfa\ud83c\uddf8","country_flag_emoji_unicode":"U+1F1FA U+1F1F8","calling_code":"1","is_eu":false},"time_zone":{"id":"America\/Los_Angeles","current_time":"2021-03-09T08:24:04-08:00","gmt_offset":-28800,"code":"PST","is_daylight_saving":false},"currency":{"code":"USD","name":"US Dollar","plural":"US dollars","symbol":"$","symbol_native":"$"},"connection":{"asn":15169,"isp":"Google LLC"}}


# Ensures that Invoke-WebRequest uses TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


$file = Import-CSV c:\support\5152log.csv


foreach ($row in $file) {
    if ($row.SrcIP -ne "") {


$IP=$row.SrcIP
$SrcPort=$row.SrcPort
$DstIP=$row.DstIP
$DstPort=$row.DstPort
$AppName=$row.AppName

$request="http://api.ipstack.com/"+$ip+"?access_key="+$IPStackkey

$j = Invoke-WebRequest $request | ConvertFrom-Json
try{
$dnsRecord = Resolve-DnsName -Name $ip -ErrorAction Stop| Select-Object -ExpandProperty namehost
}
catch{ $dnsRecord="NA"} 
$info=$ip+"  DNS:"+$dnsRecord+ "  SrcPort:"+$SrcPort+"  DstIP:"+$DstIP+"  DstPort:"+$DstPort+"  AppName:"+$AppName+"  "+$j.connection.isp+"  "+$j.country_name+" "+$j.city+" "+$j.region_name+"  "+$j.zip+"  "+$row.UserIds+"    "+$row.CreationDate+"   "+$row.Operations
write-host $info


Set-Content -Path c:\support\geoinfop.txt -Value $info
    }
}
