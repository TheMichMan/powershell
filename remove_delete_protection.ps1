$OU = 'OU=People,DC=contoso,DC=local'

$list = Get-ADOrganizationalUnit -SearchBase $OU -SearchScope Subtree -Filter * | Select-Object -ExpandProperty DistinguishedName
foreach ($i in $list)
{
Get-ADOrganizationalUnit $i | Set-ADObject -ProtectedFromAccidentalDeletion:$false -Verbose
}