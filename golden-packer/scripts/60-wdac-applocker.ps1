$ProgressPreference='SilentlyContinue'
Set-Service AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
Start-Service AppIDSvc -ErrorAction SilentlyContinue
New-Item -Force -ItemType Directory C:\prov | Out-Null
$xml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly">
    <FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="All in Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="a61c8b2c-a319-4cd0-9690-d2177cad7b51" Name="All in Windows" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%WINDIR%\*"/></Conditions></FilePathRule>
    <FilePathRule Id="fd686d83-a829-4351-8ff4-27c7de5755d2" Name="Admins all" Description="" UserOrGroupSid="S-1-5-32-544" Action="Allow"><Conditions><FilePathCondition Path="*"/></Conditions></FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
'@
Set-Content C:\prov\applocker.xml $xml -Encoding utf8
try { Set-AppLockerPolicy -XmlPolicy C:\prov\applocker.xml -ErrorAction Stop; $rc=(Get-AppLockerPolicy -Effective).RuleCollections.Count } catch { $rc="err:$_" }
"AppIDSvc=$((Get-Service AppIDSvc).Status); applocker_collections=$rc (AuditOnly golden profile)"
'60-wdac-applocker OK'
