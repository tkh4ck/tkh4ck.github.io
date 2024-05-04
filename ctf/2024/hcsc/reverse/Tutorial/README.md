# HCSC 2024 - Tutorial

## Description

**Kérlek olvass el figyelmesen!**

Annak érdekében, hogy a jövőben még érdekesebb challengeket tudjunk gyártani, szeretnénk egy új feladattípusban gondolkozni, ahol mindenki a saját, egyéni konténerben tud eljutni a megoldásig. Idén jutott el a projekt arra a szintre, hogy tesztelhető, ezért arra gondoltunk, hogy kísérleti jelleggel készítünk egy extra reverse challenget Patch Adams néven, ami már az új technológiát használja. Elég friss a dolog, szóval ha valami nem megy, legyetek türelmesek és bátran keressetek minket.

### Tudnivalók:
- Konténert létrehozni a *Start Your Instance* megnyomásával tudtok
- Ha bármi oknál fogva beakad a challenge, akkor a *Stop Instance* segítségével le lehet állítani, majd lehet újat csinálni
- Egyszerre egy konténer futhat userenként
- Egy konténer terheléstől függően min. 2 óráig él, de bármikor lehet újat csinálni
- VPN nem szükséges az eléréshez
- Sikeres megoldáskor a konténer nem lesz többé elérhető, de lehet újat csinálni writeup készítés céljából. **Viszont ilyen esetben, a már nem használt konténereket kéretik eltávolítani!**
- **Port scannelés nem szükséges és kifejezetten tiltott, ilyen feladatok esetében csak azok a portok fognak kelleni, amiket az elérési adatoknál ír a felület!**


### A feladat

Indítsd el a konténert és nyisd meg böngészőben a kapott IP címet és portot. Kapnod kell egy flaget. Ezt add meg, ha sikeres. Ha nem és úgy gondolod, hibás valami, akkor jelezd.

**Flag formátum**: `HCSC24{...}`

*By MJ*

## Metadata

- Tags: `docker`
- Points: `0`
- Number of solvers: `204`
- Filename: -

## Solution

If we start the container, we get an IP and a port:

```bash
~ curl http://193.225.251.158:37733
HCSC24{just_a_simple_test_challenge} 
```

The official write-up by `MJ` is available at: <https://github.com/NIK-SOC/hcsc_2024_mj/tree/main/ctf-tutorial>

Flag: `HCSC24{just_a_simple_test_challenge}`