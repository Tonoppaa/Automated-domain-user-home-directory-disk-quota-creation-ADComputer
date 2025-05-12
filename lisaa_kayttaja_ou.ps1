# Skripti, jonka avulla luetaan käyttäjät tiedostosta ja lisätään automaattisesti käyttäjä "Huipputiimi" OU:n, jos sitä ei ole siellä
# Tämä skripti sisältää harjoitus 2a (käyttäjän lisäys autom. toimialueelle) ja 2b (kotihakemiston ja quotan määritys toimialueen käyttäjälle)
# Tässä skriptissä myös tehdään alustus harjoitukseen 3: Työaseman liittäminen toimialueelle luomalla ADComputers

# Luodaan automaattinen ajastus, joka lukee käyttäjät kahdesti päivässä New-ScheduledTaskTrigger-komennon avulla
$toimAjankohtaAamu = New-ScheduledTaskTrigger -Daily -At "11:00"
$toimAjankohtaIlta = New-ScheduledTaskTrigger -Daily -At "01:00"

# Tiedostopolku, josta käyttäjät luetaan
$tiedostoPolku = "C:\Käyttäjätiedostot\kayttajat.txt"

#Tiedostopolku, jossa automaattisesti käyttäjiä OU:n lisäävä skripti sijaitsee
$suoritaSkriptiPolku = "C:\Users\Administrator\Desktop\2a\lisaa_kayttaja_ou.ps1"

# Muuttuja tämän skriptin suorittamiselle
$suoritaSkripti = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File $suoritaSkriptiPolku"

# Määritellään käyttäjän lisäystapahtumille muuttujat
$taskNameAamu = "KayttajaLisaysAamu"
$taskNameIlta = "KayttajaLisaysIlta"

# Tehdään tarkistus, onko ajastettu tehtävä jo rekisteröity
# -ErrorAction SilentlyContinue-komennon avulla ohjelma jatkaa ilman virheilmoituksen esilletuontia
if(-not(Get-ScheduledTask -TaskName $taskNameAamu -ErrorAction SilentlyContinue))
{
    Register-ScheduledTask -TaskName $taskNameAamu -Trigger $toimAjankohtaAamu -Action $suoritaSkripti
}

if(-not(Get-ScheduledTask -TaskName $taskNameIlta -ErrorAction SilentlyContinue))
{
    Register-ScheduledTask -TaskName $taskNameIlta -Trigger $toimAjankohtaIlta -Action $suoritaSkripti
}

# Tarkistetaan, onko tiedosto olemassa
$tiedostoPolku = "C:\Käyttäjätiedostot\kayttajat.txt"

if (Test-Path -Path $tiedostoPolku) {
    # Luetaan tekstitiedosto rivi kerrallaan ja käsitellään käyttäjät "kayttajat.txt"-tiedostosta
    Get-Content $tiedostoPolku | ForEach-Object {
	    $kayttaja = $_ -split ","
        # Write-Output "kayttaja $kayttaja kasitelty"
	    $etuNimi = $kayttaja[0]
        # Write-Output "etunimi $etuNimi kasitelty"
        $sukuNimi = $kayttaja[1]
        # Write-Output "sukunimi $sukuNimi kasitelty"
        $samAccountName = $kayttaja[2]
        # Write-Output "samaccountname $samAccountName kasitelty"
        $userPrincipalName = $kayttaja[3]
        # Write-Output "userprincipalname $userPrincipalName kasitelty"
        $testiSalasana = $kayttaja[4]
        # Write-Output "salasana on $testiSalasana"
        $salaSana = ConvertTo-SecureString $kayttaja[4] -AsPlainText -Force
	
	    # Organisaatioyksikkö
	    $OU = 'OU=Huipputiimi,DC=testimetsa24,DC=EDU'

        # Organisaatioyksikön käyttäjä
	    $ADUser = Get-ADUser -Filter "SamAccountName -eq '$($samAccountName)'" -SearchBase $OU

	    # Luodaan tarkistus SamAccountName:n mukaan; verrataan onko kayttajat.txt-käyttäjä jo organisaatioyksikössä
	    if($ADUser -eq $null)
	    {
		    # Luo uusi käyttäjä Huipputiimi-organisaatioyksikköön, jos kyseistä käyttäjää ei ole
            New-ADUser -Name "$etuNimi $sukuNimi" -GivenName $etuNimi -Surname $sukuNimi -SamAccountName $samAccountName `
            -UserPrincipalName $userPrincipalName -AccountPassword $salaSana -Path $OU -Enabled $true
	    }

#----------------------------------------Uudelle käyttäjälle kotihakemiston ja Quotan määrittäminen----------------------------------------------

        #Tarkistus, onko kotihakemistokansio jo määritetty
        $kotihakemistoPolku = "C:\Huipputiimin kotihakemisto"
        Write-OutPut "Määritetään kotihakemistopolku: "$kotihakemistoPolku

        #Jos ei ole määritetty, luodaan uusi
        if(-not (Test-Path -Path $kotihakemistoPolku)) {
	        New-Item -Path $kotihakemistoPolku -ItemType Directory
        }

        #Huipputiimin kotihakemistokansion jakaminen
        $toimialueKayttajat = "testimetsa24\Huipputiimi"
        Write-OutPut "Toimialuekäyttäjät: "$toimialueKayttajat
        $toimialueAdmins = "testimetsa24\Users\Domain Admins"
        Write-OutPut "Toimialueen adminit: "$toimialueAdmins
        $kaikkiToimialueenKayttajat = Get-ADUser -Filter "SamAccountName -eq '$($samAccountName)'" -SearchBase $OU
        Write-OutPut "Kaikki toimialueen käyttäjät: "$kaikkiToimialueenKayttajat

        #Tarkistetaan, onko huipputiimin kotihakemistokansio jo jaettu
        if(-not (Get-SmbShare -Name "Huipputiimin kotihakemisto" -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name "Huipputiimin kotihakemisto" -Path $kotihakemistoPolku
            Write-OutPut "Luotiin uusi jako polkuun: "$kotihakemistoPolku

            #Käyttöoikeuksien jako käyttäjille, jotka ovat Huipputiimi OU:ssa
            foreach($kayttaja in $kaikkiToimialueenKayttajat) {
                $samAccountName = $kayttaja.SamAccountName
                Write-OutPut "Muuttuja samAccountName arvo on: "$samAccountName
                Grant-SmbShareAccess -Name "Huipputiimin kotihakemisto" -AccountName "testimetsa24\$samAccountName" -AccessRight Full -Force
                Write-OutPut "Luotiin jako käyttäjälle "$samAccountName
            }

            #Käyttöoikeuksien jako Domain Admins
            #Tällä hetkellä ainoa Domain Admin on Administrator
            $nykyisetOikeudetDomainAdmin = Get-SmbShareAccess -Name "Huipputiimi" -ErrorAction SilentlyContinue | Where-Object {$_.AccountName -eq "testimetsa24\Users\Domain Admins"}
            Write-OutPut "Haettiin käyttöoikeudet Domain Admins: "$nykyisetOikeudetDomainAdmin
            #Oikeuksien myöntäminen, jos ne puuttuvat      
            if(-not $nykyisetOikeudetDomainAdmin) {
                Grant-SmbShareAccess -Name "Huipputiimin kotihakemisto" -AccountName "testimetsa24\Users\Domain Admins" -AccessRight Full -Force
                Write-OutPut "Luotiin käyttöoikeudet Domains Admins:"$nykyisetOikeudetDomainAdmin
            }

            #Käyttöoikeuksien jako Administrator
            $nykyisetOikeudetAdmin = Get-SmbShareAccess -Name "Huipputiimi" -ErrorAction SilentlyContinue | Where-Object {$_.AccountName -eq "testimetsa24\Users\Administrator"}
            Write-OutPut "Nykyiset oikeudet Administrator: "$nykyisetOikeudetAdmin
            #Oikeuksien myöntäminen, jos ne puuttuvat      
            if(-not $nykyisetOikeudetAdmin) {
                Grant-SmbShareAccess -Name "Huipputiimin kotihakemisto" -AccountName "testimetsa24\Users\Administrator" -AccessRight Full -Force
                Write-OutPut "Myönnettiin oikeudet Administratorille: "$nykyisetOikeudetAdmin
            }
        }

        #Tarkistus, onko käyttäjällä kotihakemistokansio jo määritetty
        $kotihakemistoPolkuKayttaja = "C:\Huipputiimin kotihakemisto\$samAccountName"

        # Jos käyttäjällä ei ole omaa kotihakemisto-kansiota, luodaan uusi
        if(-not (Test-Path -Path $kotihakemistoPolkuKayttaja)) {
	        New-Item -Path $kotihakemistoPolkuKayttaja -ItemType Directory
        }

        # Luodaan kotihakemisto käyttäjille, jotka ovat Huipputiimi organisaatioyksikössä
        Set-ADUser -Identity $samAccountName -HomeDirectory "C:\Huipputiimin kotihakemisto\$samAccountName" -HomeDrive "M"

        #Hankitaan käyttäjän kansion käyttöoikeudet
        $acl = Get-Acl $kotihakemistoPolkuKayttaja
        Write-OutPut "Muuttuja acl on "$acl

        #Poistetaan periytyneet oikeudet ja estetään niiden palautuminen
        $acl.SetAccessRuleProtection($true, $false)

        $toimialueKayttoOikeus = "testimetsa24\$samAccountName"

        #Täydet oikeudet käyttäjälle omaan kotihakemisto-kansioon
        $kayttoOikeusKayttaja = New-Object System.Security.AccessControl.FileSystemAccessRule($toimialueKayttoOikeus, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        Write-OutPut "Käyttöoikeus toimialueen käyttäjälle: "$kayttoOikeusKayttaja
        $acl.AddAccessRule($kayttoOikeusKayttaja)
        Write-OutPut "Oikeus lisätty"

        #Täydet oikeudet järjestelmänvalvojille
        $kayttoOikeusAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule("testimetsa24\Administrator", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        Write-OutPut "Käyttöoikeus järjestelmänvalvojille: "$kayttoOikeusAdmin
        $acl.AddAccessRule($kayttoOikeusAdmin)
        Write-OutPut "Oikeus lisätty"

        #Päivitetään Huipputiimin kotihakemisto-kansio
        Set-Acl $kotihakemistoPolkuKayttaja -AclObject $acl

        Write-OutPut "Oikeus Huipputiimi-organisaatioyksikköön on myönnetty oikeus:" $toimialueKayttoOikeus

        #Määritetään levykiintiön koko eli Disk Quota käyttäjälle (lähtökohtaisesti sama kaikille)
        if(-not (Get-FsrmQuota -Path $kotihakemistoPolkuKayttaja -ErrorAction SilentlyContinue)) {
	        New-FsrmQuota -Path $kotihakemistoPolkuKayttaja -Size 500MB -SoftLimit
            Write-OutPut "Lisätty levykiintiön koko käyttäjälle: "$kotihakemistoPolkuKayttaja
        }

#-----------------------Työaseman eli tietokoneen liittäminen toimialueelle alustus-------------------------

        # ADComputer luominen toimialueelle

        #Tarkistus, onko toimialueella tietokonetiliä
        $tyoasemaPolkuToimialue = "DC=testimetsa24,DC=edu"
        Write-OutPut "Työasemapolku toimialue: "$tyoasemaPolkuToimialue

        # Luodaan juokseva nimien luonti ADComputer
        $tyoasemaKayttajanTietokoneNimiToimialue = "ht"
        $juoksevaNumerointiTietokone = 1
        $taydellinenTietokoneNimi = ""
        
        Write-Output "Tarkistetaan, onko ADComputer jo luotu käyttäjälle $samAccountName ..."
        $tarkistaTietokone = Get-ADComputer -Filter "Description -eq 'Työasema käyttäjälle $samAccountName'" -SearchBase $tyoasemaPolkuToimialue
        if($tarkistaTietokone -ne $null) {
            Write-Output "Käyttäjälle $samAccountName on jo luotu ADCOmputer."
        } else {

        do {
                Write-OutPut "Työaseman käyttäjän tietokoneen nimi (toimialue): "$tyoasemaKayttajanTietokoneNimiToimialue
                Write-Output "Juokseva numero: "$juoksevaNumerointiTietokone
                $taydellinenTietokoneNimi = "$tyoasemaKayttajanTietokoneNimiToimialue-{0:D3}" -f $juoksevaNumerointiTietokone
                Write-Output "Tietokoneen täydellinen nimi: "$taydellinenTietokoneNimi
                $toimialueTietokone = Get-ADComputer -Filter "Name -eq '$taydellinenTietokoneNimi'" -SearchBase $tyoasemaPolkuToimialue
                Write-OutPut "Haetaan, onko tietokone toimialueella, arvo on: "$toimialueTietokone

                # Jos nimi löytyy, numeroa kasvatetaan
                if ($toimialueTietokone) {
                    $juoksevaNumerointiTietokone++
                }
        
            } while ($toimialueTietokone) # Toistetaan, kunnes vapaa nimi löytyy

        # Kun vapaa nimi löytyy, uusi ADComputer luodaan
        New-ADComputer -Name $taydellinenTietokoneNimi -Path $tyoasemaPolkuToimialue -Description "Työasema käyttäjälle $samAccountName" -Enabled $true

        # Siirretään ADComputer Computers-kansioon
        $computersKansio = "CN=Computers,DC=testimetsa24,DC=edu"
        $adObjekti = Get-ADComputer -Identity $taydellinenTietokoneNimi
        Move-ADObject -Identity $adObjekti.DistinguishedName -TargetPath $computersKansio
        Write-OutPut "Uusi ADComputer '$taydellinenTietokoneNimi' luotu käyttäjälle $samAccountName kohteeseen $computersKansio"
        }
Write-Output "Valmis."