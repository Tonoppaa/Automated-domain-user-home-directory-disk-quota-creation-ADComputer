# Tämä skripti liittyy harjoitus 2a: Toimialueen käyttäjät

Write-Output "Tämän skriptin avulla lisätään käyttäjiä tiedostoon."

#Alla olevia rivejä suoritetaan niin kauan, kunnes käyttäjä vastaa ohjelman lopussa "e"
while ($true)
{
    $muutettuVastaus = ""
    #Aluksi käyttäjä lisää käyttäjän, jonka jälkeen käyttäjä valitsee, lisätäänkö vielä käyttäjä
    # Jos käyttäjä valitsee "k", käyttäjiä voidaan lisätä, jos "e", ohjelma päättyy

        $etuNimi = Read-Host "Anna käyttäjän etunimi"
        $muokattuEtunimi = $etuNimi.ToLower()
        $sukuNimi = Read-Host "Anna käyttäjän sukunimi"
        $muokattuSukunimi = $sukuNimi.ToLower()
        $samAccountName = $muokattuEtuNimi+"."+$muokattuSukuNimi
        $userPrincipalName = $samAccountName+"@testimetsa24.edu"

        # Tarkistetaan, onko käyttäjän antama salasana riittävän vahva
        do {
            $salaSana = Read-Host "Anna käyttäjälle salasana (pitää sisältää isoja/pieniä kirjaimia, numeroita ja erikoismerkkejä) sekä pituus väh. 8 merkkiä"
            $tarkistaPituus = $salaSana.Length -ge 8
            $tarkistaPieniKirjain = $salaSana -match '[a-z]'
            $tarkistaIsoKirjain = $salaSana -match '[A-Z]'
            $tarkistaNumero = $salaSana -match '[0-9]'
            $tarkistaErikoismerkki = $salaSana -match '[^a-zA-Z0-9]'

            if($tarkistaPituus -and $tarkistaPieniKirjain -and $tarkistaIsoKirjain -and $tarkistaNumero -and $tarkistaErikoismerkki) {
                Write-Host "Salasanan luonti onnistui, riittävän turvallinen salasana."
                break
            } else {
                Write-Host "Antamasi salasana ei ollut riittävän turvallinen (puuttui pieni/iso kirjain, numero, erikoismerkki tai salasana oli liian lyhyt)"
            }

        } while ($true)

        # Nimien tallentaminen tiedostoon
        Add-Content -Path "C:\Käyttäjätiedostot\kayttajat.txt" -Value "$etuNimi,$sukuNimi,$samAccountName,$userPrincipalName,$salaSana"
        Write-Output "Käyttäjä luotu."

        while($muutettuVastaus -ne "k" -and $muutettuVastaus -ne "e") {

        $vastaus = Read-Host "Luodaanko vielä uusi käyttäjä? k=kyllä, e=ei"
        $muutettuVastaus = $vastaus.ToLower()

        #"k"-kirjaimella lisätään uusi käyttäjä
        if($muutettuVastaus -eq "k")
        {
	        Write-Host "Luodaan vielä uusi käyttäjä."
        }
        #"e"-kirjaimella ohjelman suorittaminen päättyy
        elseif($muutettuVastaus -eq "e")
        {
	        break
        }
        #Jos käyttäjä syöttää jonkun muun kuin "k" tai "e"-kirjaimen, ohjelma huomauttaa siitä
        else {
	        Write-Output "Virheellinen syöte. Syötteeksi kelpaa vain k tai e"
            $vastaus = Read-Host "Luodaanko vielä uusi käyttäjä? k=kyllä, e=ei"
            $muutettuVastaus = $vastaus.ToLower()
       }
    }

    # Jos käyttäjä vastasi "e", ohjelman suoritus päättyy
    if($muutettuVastaus -eq "e") {
        Write-Output "Käyttäjien lisääminen lopetettu."
        break
    }
}