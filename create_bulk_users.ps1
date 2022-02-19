function New-RandomUser {
    <#
        .SYNOPSIS
            Generate random user data from Https://randomuser.me/.
        .DESCRIPTION
            This function uses the free API for generating random user data from https://randomuser.me/
        .EXAMPLE
            Get-RandomUser 10
        .EXAMPLE
            Get-RandomUser -Amount 25 -Nationality us,gb 
        .LINK
            https://randomuser.me/
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [ValidateRange(1,500)]
        [int] $Amount,

        [Parameter()]
        [ValidateSet('Male','Female')]
        [string] $Gender,

        # Supported nationalities: AU, BR, CA, CH, DE, DK, ES, FI, FR, GB, IE, IR, NL, NZ, TR, US
        [Parameter()]
        [string[]] $Nationality,

        [Parameter()]
        [ValidateSet('json','csv','xml')]
        [string] $Format = 'json',

        # Fields to include in the results.
        # Supported values: gender, name, location, email, login, registered, dob, phone, cell, id, picture, nat
        [Parameter()]
        [string[]] $IncludeFields,

        # Fields to exclude from the the results.
        # Supported values: gender, name, location, email, login, registered, dob, phone, cell, id, picture, nat
        [Parameter()]
        [string[]] $ExcludeFields
    )

    $rootUrl = "http://api.randomuser.me/?format=$($Format)"

    if ($Amount) {
        $rootUrl += "&results=$($Amount)"
    }

    if ($Gender) {
        $rootUrl += "&gender=$($Gender)"
    }

    if ($Nationality) {
        $rootUrl += "&nat=$($Nationality -join ',')"
    }

    if ($IncludeFields) {
        $rootUrl += "&inc=$($IncludeFields -join ',')"
    }

    if ($ExcludeFields) {
        $rootUrl += "&exc=$($ExcludeFields -join ',')"
    }
    Invoke-RestMethod -Uri $rootUrl
}

$fqdn = Get-ADDomain
$fulldomain = $fqdn.DNSRoot
$domain = $fulldomain.split(".")
$Dom = $domain[0]
$Ext = $domain[1]
$userPassword = '1qaz@WSX3edc'
$FirstOU ="Contoso Users"

New-ADOrganizationalUnit -Name $FirstOU -Description $FirstOU  -Path "DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false

#Development
$Services = ("Development")

$Employees = New-RandomUser -Amount 20 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 2 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
      }

     
#Product
$Services = ("Product")

$Employees = New-RandomUser -Amount 8 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 1 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
         }

#Marketing
$Services = ("Marketing")

$Employees = New-RandomUser -Amount 6 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 1 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
}

#Help Desk

$Services = ("Help Desk")

$Employees = New-RandomUser -Amount 4 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 1 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
}

#HR

$Services = ("HR")

$Employees = New-RandomUser -Amount 2 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 1 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
}

#IT

$Services = ("IT")

$Employees = New-RandomUser -Amount 2 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 1 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
}

#Support

$Services = ("Support")

$Employees = New-RandomUser -Amount 6 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results
$Directors = New-RandomUser -Amount 1 -Nationality us -IncludeFields name,dob,phone,cell -ExcludeFields picture | Select-Object -ExpandProperty results

foreach  ($Serv in $Services)
{
New-ADOrganizationalUnit -Name $Serv -Description "$Serv"  -Path "OU=$FirstOU,DC=$Dom,DC=$EXT" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "$Services" -SamAccountName $Services -GroupCategory Security -GroupScope Global -DisplayName $Services -Path "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT" -Description "Members of this group are Production Users"
    foreach ($user in $Employees)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Employees"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           
           Try{ New-ADUser @newUserProperties}
           catch{}

        }

        foreach ($user in $Employees)
        {
         $newGroupProperties = @{
         Members = $($user.name.first).Substring(0,1)+$($user.name.last)
         Identity = $Services
         
         }

           Try{ Add-ADGroupMember @newGroupProperties}
           catch{}

        }

        foreach ($user in $Directors)
        {
          $newUserProperties = @{
        Name = "$($user.name.first) $($user.name.last)"
        City = "$S"
        GivenName = $user.name.first
        Surname = $user.name.last
        Path = "OU=$Serv,OU=$FirstOU,dc=$Dom,dc=$EXT"
        title = "Directors"
        department="$Serv"
        OfficePhone = $user.phone
        MobilePhone = $user.cell
        Company="$Dom"
        EmailAddress="$($user.name.first).$($user.name.last)@$($fulldomain)"
        AccountPassword = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        SamAccountName = $($user.name.first).Substring(0,1)+$($user.name.last)
        UserPrincipalName = "$(($user.name.first).Substring(0,1)+$($user.name.last))@$($fulldomain)"
        Enabled = $true
    }

           Try{ New-ADUser @newUserProperties}
           catch{}

        }
}