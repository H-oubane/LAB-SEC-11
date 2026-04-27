# Lab 11 Frida — Bypass Root Detection & Password Extraction
## OWASP Uncrackable Level 1

### Objectifs du lab

-Comprendre comment les apps Android détectent le root (Java et natif).

-Utiliser Frida pour neutraliser ces détections via des hooks Java et, si nécessaire, natifs.

-Lancer l’app cible sous Frida, vérifier que la détection est contournée, et diagnostiquer les échecs.

> **Avertissement éthique** : ces techniques sont réservées à un cadre d'audit autorisé ou d'exercice pédagogique officiel.

---

## Environnement

| Élément | Valeur |
|---|---|
| Appareil | Genymotion AVD (192.168.56.102:5555) |
| Architecture CPU | x86_64 |
| Frida | 17.9.1 |
| Application cible | `owasp.mstg.uncrackable1` |

---

## Workflow

### Étape 1 — Vérifier la connexion ADB

```bash
adb devices
```
Résultat attendu :
```
192.168.56.102:5555    device
```

---

<img width="621" height="187" alt="image" src="https://github.com/user-attachments/assets/f7e624b2-ebaf-4690-82b0-b323c5cdbbf2" />

### Étape 2 — Identifier l'architecture CPU

```bash
adb shell getprop ro.product.cpu.abi
```

Résultat : `x86_64`

---
<img width="835" height="147" alt="image" src="https://github.com/user-attachments/assets/7f7fc9f7-f106-4a4d-b643-da0c7ac26753" />

### Étape 3 — Pousser et lancer frida-server

```bash
adb push frida-server/frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell "/data/local/tmp/frida-server &"
```
<img width="1202" height="216" alt="image" src="https://github.com/user-attachments/assets/6db606ae-b6ea-407c-b10f-f097bab730dd" />

Vérification :
```bash
adb shell "ps | grep frida"
```

---
<img width="1192" height="127" alt="image" src="https://github.com/user-attachments/assets/b80bd839-fe29-4b83-a615-e660979e76c4" />

### Étape 4 — Forwarder les ports Frida

```bash
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043
```

---
<img width="776" height="206" alt="image" src="https://github.com/user-attachments/assets/3cc89c3e-fa66-407b-b018-4fb9a9435b2b" />

### Étape 5 — Vérifier que Frida voit l'AVD

```bash
frida-ps -U
```

---
<img width="1070" height="448" alt="image" src="https://github.com/user-attachments/assets/4ad0395c-115a-4275-8cce-c9400cda0c7f" />

### Étape 6 — Installer l'APK cible

```bash
adb install C:\Users\houda\Downloads\UnCrackable-Level1.apk
```
<img width="1017" height="138" alt="image" src="https://github.com/user-attachments/assets/46dc9c42-caee-40e9-9776-880cbce72caf" />

Vérifier le package :
```bash
adb shell pm list packages | findstr uncrackable
```

Résultat : `package:owasp.mstg.uncrackable1`

---
<img width="1037" height="120" alt="image" src="https://github.com/user-attachments/assets/26f09c5f-9aa1-4d1e-9f05-65cab1f6101d" />

### Étape 7 — Analyser l'APK avec jadx

Ouvrir `jadx-gui` et charger `UnCrackable-Level1.apk`.

Classes identifiées :

| Classe | Rôle |
|---|---|
| `sg.vantagepoint.a.c` | Détection root (`a()`, `b()`, `c()`) |
| `sg.vantagepoint.a.b` | Détection debug |
| `sg.vantagepoint.uncrackable1.a` | Vérification du mot de passe (AES/ECB) |
| `sg.vantagepoint.uncrackable1.MainActivity` | Activité principale |
---


<img width="1366" height="732" alt="image" src="https://github.com/user-attachments/assets/e5cc78c2-75aa-4ac3-86a1-ee464c4d2650" />

---


Code clé trouvé dans `sg.vantagepoint.uncrackable1.a` :
```java
bArrA = sg.vantagepoint.a.a.a(
    b("8d127684cbc37c17616d806cf50473cc"),
    Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0)
);
return str.equals(new String(bArrA));
```

---
<img width="1366" height="723" alt="image" src="https://github.com/user-attachments/assets/2e8ef623-f5bb-4935-b8c8-93923e228ede" />

### Étape 8 — Créer le script de bypass (`bypass_uncrackable.js`)

```javascript
Java.perform(function () {

    // Bloquer System.exit() pour empêcher la fermeture
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(code) {
        console.log("[BLOCKED] System.exit bloque");
    };

    // Bypass root detection
    var rootClass = Java.use("sg.vantagepoint.a.c");
    rootClass.a.implementation = function () { return false; };
    rootClass.b.implementation = function () { return false; };
    rootClass.c.implementation = function () { return false; };

    // Bypass debug detection
    var b = Java.use("sg.vantagepoint.a.b");
    b.a.overloads.forEach(function(o) {
        o.implementation = function() { return false; };
    });
});
```

---
<img width="1600" height="811" alt="image" src="https://github.com/user-attachments/assets/abc9a986-8652-4f9d-9ed5-4b3ee0b40120" />

### Étape 9 — Lancer l'application avec Frida

```bash
frida -U -f owasp.mstg.uncrackable1 -l bypass_uncrackable.js 
```

Console Frida :
```
[BLOCKED] System.exit bloque
```

---
<img width="1600" height="810" alt="image" src="https://github.com/user-attachments/assets/63c05fc0-c344-48c4-a29a-18fc03a4d0a8" />

### Étape 10 — Extraire le mot de passe depuis la console Frida

Coller directement dans la console Frida :

```javascript
Java.perform(function(){
    var k = Java.use("sg.vantagepoint.uncrackable1.a").b("8d127684cbc37c17616d806cf50473cc");
    var d = Java.use("android.util.Base64").decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0);
    var p = Java.use("java.lang.String").$new(Java.use("sg.vantagepoint.a.a").a(k, d));
    console.log("[PASSWORD]: " + p);
});
```

Résultat dans la console :
```
[PASSWORD]: I want to believe
```

---
<img width="1600" height="810" alt="image" src="https://github.com/user-attachments/assets/8317a10e-5dcc-4358-89fa-9c5305c61f1a" />

### Étape 11 — Validation

Entrer `I want to believe` dans le champ de l'application et cliquer **VERIFY**.

Résultat :
```
Success! This is the correct secret.
```

---
<img width="1600" height="855" alt="image" src="https://github.com/user-attachments/assets/49161ae0-435f-44ae-ab11-211a9d47d3be" />

## Résumé des hooks utilisés

| Hook | Effet |
|---|---|
| `java.lang.System.exit()` | Empêche la fermeture de l'app |
| `sg.vantagepoint.a.c.a/b/c()` | Retourne `false` pour les checks root |
| `sg.vantagepoint.a.b.a()` | Retourne `false` pour le check debug |
| `sg.vantagepoint.a.a.a()` | Décryptage AES/ECB du mot de passe |

---

## Mot de passe

```
I want to believe
```
<img width="1600" height="110" alt="image" src="https://github.com/user-attachments/assets/768dd236-c648-426e-856f-33012327d7f0" />


## Auteur
**H-oubane**
