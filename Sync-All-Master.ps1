<#	
	.NOTES
	===========================================================================
	 .SYNOPSIS
     Forest Sync
     .DESCRIPTION
     Sync's OU', Groups, Users and group memberships

	 Created on:   	4/21/2017 8:34 AM
	 Created by:   	JB027934
	 Organization: 	CWx
	 Filename:      Sync-All-Master.ps1 
     Modified: 
     Version: 1.0
    
	
	

   ===========================================================================
#>

$SourceDomainController = Read-Host "Enter Source Domain Controller - Example DC1.sourceforest.net"
$DestinationDomainController = Read-Host "Enter Destination Domain Controller - Example - dc1.destinationforest.net"


$ClientOUDN = Read-Host "Enter Client OU DN - Example OU=LCAH_NCR,OU=Clients,DC=sourceforest,DC=net"
$ClientUsersDN = Read-Host "Enter Client Users OU DN - Example OU=Users,OU=cleintname,OU=Clients,DC=sourceforest,DC=net"




$pdceSource = (Get-ADDomainController -Server "$SourceDomainController" -Filter {OperationMasterRoles -like 'PDCEmulator'}).hostname
$ADNameSource = (Get-ADDomain -Server "$pdceSource" ).name
$pdceDestination = (Get-ADDomainController -Server "$DestinationDomainController" -Filter {OperationMasterRoles -like 'PDCEmulator'}).hostname
$ADNameDestination = (Get-ADDomain -Server "$pdceDestination").name
$credentialForestSource = (Get-Credential)
$credentialForestDestination = (Get-Credential)





#Sync OU's
Function SyncOU{

$OFS = ','
$DNSourceDomain = (get-addomain -Server $pdceSource -Credential $credentialForestSource).Distinguishedname
$DNDesinationDomain = (get-addomain -Server $pdceDestination -Credential $credentialForestDestination).Distinguishedname

[Array]$data = ""
[array]$data = (Get-ADOrganizationalUnit -SearchBase $DNSourceDomain -filter * -Server $pdceSource -Credential $credentialForestSource ).Distinguishedname
[array]::Reverse($data)

foreach($line in $data){
Write-host $line
[Array]$splitmereverse = $line -split $OFS
[array]::Reverse($splitmereverse)
#Write-host $line.OU -ForegroundColor Yellow
        for($i = $splitmereverse.GetLowerBound(0); $i -le $splitmereverse.GetUpperBound(0)) 
        { 
            
            $i++

                    if($i -eq 2) #Start at array postion 2
                        {
                            $outarget = $splitmereverse[$i].replace("OU=",'')

                            Try{
                                    $oucheck = $splitmereverse[$i]+","+$DNDesinationDomain
                                    Write-verbose $oucheck -Verbose
                                    Get-ADOrganizationalUnit $oucheck -ErrorAction Ignore -Server $pdceDestination -Credential $credentialForestDestination
                                }

                                Catch {
                                        Write-host " OU $outarget is being created in path $DNDesinationDomain" -ForegroundColor Yellow
                                        New-ADOrganizationalUnit -Name $outarget -Path $DNDesinationDomain -Server $pdceDestination -Credential $credentialForestDestination
                                        Write-host " OU $outarget has been created  in path $DNDesinationDomain" -ForegroundColor Cyan
                                        }



            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){
                                                        $outarget = $splitmereverse[$i].replace("OU=",'')
                                $path =  $splitmereverse[2] + "," + $DNDesinationDomain 
                                $oucheck = $splitmereverse[$i]+","+$splitmereverse[2] + "," + $DNDesinationDomain
                            Try{
                                     Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore 
                                     }

                                Catch {
                                        Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                        New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                        Write-host " OU $outarget has been created in path $path"-ForegroundColor Cyan
                                        }





                        } #postion 3

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){

                                $outarget = $splitmereverse[$i].replace("OU=",'')
                                $path = $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                                $oucheck = $splitmereverse[$i]+","+ $path

                            Try{
                                    Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                                    }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }


                        } #postion 4

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){

                                $outarget = $splitmereverse[$i].replace("OU=",'')
                                $path = $splitmereverse[4] + "," + $splitmereverse[3] +"," + $splitmereverse[2] + "," + $DNDesinationDomain 
                                $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                                Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                                }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 5

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                                $outarget = $splitmereverse[$i].replace("OU=",'')
                                $path = $splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                                $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                                Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                                }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 6

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                               $outarget = $splitmereverse[$i].replace("OU=",'')
                               $path = $splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                               $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                                Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                                }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 7

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 8

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 9

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[9] +"," + $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 10

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[10] +"," + $splitmereverse[9] +"," + $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 11

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[11] +"," + $splitmereverse[10] +"," + $splitmereverse[9] +"," + $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 12

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[12] +"," + $splitmereverse[11] +"," + $splitmereverse[10] +"," + $splitmereverse[9] +"," + $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 13

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[13] +"," + $splitmereverse[12] +"," + $splitmereverse[11] +"," + $splitmereverse[10] +"," + $splitmereverse[9] +"," + $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 14

            $i++

                    if (($i -eq $splitmereverse.GetUpperBound(0))  -or ($i -lt  $splitmereverse.GetUpperBound(0))){ 

                            $outarget = $splitmereverse[$i].replace("OU=",'')
                            $path = $splitmereverse[14] +"," + $splitmereverse[13] +"," + $splitmereverse[12] +"," + $splitmereverse[11] +"," + $splitmereverse[10] +"," + $splitmereverse[9] +"," + $splitmereverse[8] +"," + $splitmereverse[7] +"," +$splitmereverse[6] +"," +$splitmereverse[5] +"," + $splitmereverse[4] + "," + $splitmereverse[3] + "," + $splitmereverse[2] + "," + $DNDesinationDomain 
                            $oucheck = $splitmereverse[$i]+","+ $path


                            Try{
                            Get-ADOrganizationalUnit $oucheck -Server $pdceDestination -Credential $credentialForestDestination -ErrorAction Ignore
                            }

                            Catch {
                                    Write-host " OU $outarget is being created in path $path" -ForegroundColor Yellow
                                    New-ADOrganizationalUnit -Name $outarget -Path $path -Server $pdceDestination -Credential $credentialForestDestination
                                    Write-host " OU $outarget has been created in path $path" -ForegroundColor Cyan
                                    }

                        } #postion 15




#Endig loop
else
{}

} # End of First IF

} #ending for

} #Ending Foreach



}



Function SyncGroupsbyOU{
$groups = (get-adgroup -SearchBase $ClientOUDN -Filter * -server $pdceSource -Credential $credentialForestSource)


foreach($group in $groups){
$groupname = $group.Name
$groupDN = $group.distinguishedname
$groupDN = $groupDN.Replace($ADNameSource ,$ADNameDestination)
$groupDN = $groupDN.Replace("CN=$groupname,","")

$groupGroupCategory = $group.GroupCategory
$groupScope = $group.GroupScope



Try{

get-adgroup -Identity $groupname -server $pdceDestination -Credential $credentialForestDestination



}

Catch{
Write-Verbose "Creating Group named $groupname in OU $groupDN" -Verbose
New-ADGroup -Name $Groupname -Path $groupDN -GroupScope $groupScope -GroupCategory $groupGroupCategory -Server $pdceDestination -Credential $credentialForestDestination

}



}


}



Function SyncUsersbyOU{
$users = (get-aduser -SearchBase $ClientUsersDN -Filter * -server $pdceSource -Credential $credentialForestSource)


    foreach($user in $users)
    {
        $givenname = $user.GivenName
        $surname = $user.Surname
        $Dn = $user.DistinguishedName
        $DN = $DN.Replace($ADNameSource ,$ADNameDestination)
        $OU = $DN.Replace("CN=$surname\, $givenname,","")
        $SamAccountName = $user.SamAccountName
        $name = $user.Name
        $userprop = get-aduser $user -Properties * -server $pdceSource -Credential $credentialForestSource
        $EDIPI = $userprop.EDIPI
        $displayname = $userprop.DisplayName
        $mail = $userprop.EmailAddress

            Try{
                get-aduser -Identity $SamAccountName -server $pdceDestination -Credential $credentialForestDestination
                }

            Catch{
                Write-Verbose "Creating User named $SamAccountName in OU $OU" -Verbose
                New-ADUser  -SamAccountName $SamAccountName -AccountPassword (ConvertTo-SecureString -AsPlainText 'P@$$w0rdP@ssw0rd1' -Force) -Name $name -Instance $user -Path $OU -Server $pdceDestination -Credential $credentialForestDestination
                Set-ADUser -identity $SamAccountName  -Server $pdceDestination -SmartcardLogonRequired $true -Credential $credentialForestDestination
                Set-ADUser -Identity $SamAccountName -DisplayName $displayname -EmailAddress $mail -Server $pdceDestination -Credential $credentialForestDestination
                Enable-ADAccount -Identity $SamAccountName -Server $pdceDestination  -Credential $credentialForestDestination 

                if($EDIPI){
                    Write-Verbose " Setting EDIPI on user $displayname" -verbose
                    Set-ADUser $SamAccountName -replace @{EDIPI=$EDIPI} -Server $pdceDestination -Credential $credentialForestDestination
                            }


                }


    }

}


Function SyncGroupMembership{

$groups = (get-adgroup -SearchBase $ClientOUDN -Filter * -server $pdceSource -Credential $credentialForestSource)

foreach($group in $groups){
$group = $group.Name

$members = (Get-ADGroupMember -Identity $group -server $pdceSource -Credential $credentialForestSource)




foreach($member in $members){

$member = $member.SamAccountName



Add-ADGroupMember $group -Members $member -Server $pdceDestination -Credential $credentialForestDestination  -ErrorAction SilentlyContinue 


}


}


}
