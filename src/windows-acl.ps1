$ErrorActionPreference = 'Stop'
$principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
# Set-Acl in Windows PowerShell can request SeSecurityPrivilege for audit metadata.
# Apply only the DACL, using WRITE_DAC on this operator-owned application object.
# Owner, group and SACL are never changed by this operation.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ExposureDeskDacl {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool SetFileSecurity(string file, uint information, byte[] descriptor);
}
'@
$targets = ConvertFrom-Json -InputObject $env:EXPOSURE_ACL_TARGETS
foreach ($item in $targets) {
$current = Get-Acl -LiteralPath $item.target
if ($current.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $principal.Value) { throw 'OWNER_MISMATCH' }
$security = $current
$security.SetAccessRuleProtection($true, $false)
foreach ($existing in @($security.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) { $security.RemoveAccessRuleSpecific($existing) }
$inheritance = if ($item.directory) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', $inheritance, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
$security.AddAccessRule($rule)
if (![ExposureDeskDacl]::SetFileSecurity($item.target, [uint32]2147483652, $security.GetSecurityDescriptorBinaryForm())) { throw ('DACL_WIN32_' + [Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
$verify = Get-Acl -LiteralPath $item.target
if (!$verify.AreAccessRulesProtected) { throw 'ACL_UNPROTECTED' }
foreach ($grant in $verify.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  if ($grant.AccessControlType -eq 'Allow' -and $grant.IdentityReference.Value -ne $principal.Value) { throw 'ACL_BROAD' }
}
}
