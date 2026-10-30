# Documentation Technique et d'Utilisation — EXPERTY Recette Système

## 1. Présentation Générale

L'application **EXPERTY - Recette des Postes Déployés** (v2026.1) est un outil d'audit, de vérification de conformité et de remédiation automatisée destiné aux techniciens réseau et système. 

Développée en Python, l'application s'appuie sur une interface graphique Tkinter pour permettre :
* La validation de la conformité d'un poste de travail Windows par rapport à un **profil JSON spécifique** (nommage, mémoire, sécurité, logiciels, etc.).
* La correction automatique des écarts identifiés lorsque cela est possible.
* La génération d'un **Procès-Verbal de recette officiel (PV)** au format PDF à l'aide de la bibliothèque `FPDF2`.

---

## 2. Architecture et Structure du Code

Le fichier `main.py` est découpé en plusieurs modules logiques :

| Module / Classe | Rôle / Description |
| :--- | :--- |
| `AppConfig` | Charge le fichier `config.ini` et initialise les répertoires nécessaires (`profils`, `pv_recette`, `logs`, `C:\BitLockerKeys`). |
| `ProfileLoader` | Lit et valide la structure des fichiers de profil JSON (avec vérification de l'empreinte SHA-256). |
| `run_powershell()` | Helper exécutant des requêtes PowerShell en arrière-plan sans affichage de console, avec gestion du timeout et encodage UTF-8. |
| `SystemProbes` | Ensemble de méthodes statiques qui exécutent des sondes (PowerShell, WMI, Registre Windows) pour auditer l'état du système. |
| `SystemRemediations` | Méthodes statiques déclenchant les actions de correction automatisées (changement de nom, activation de services, modification de registre, installation via `winget`, etc.). |
| `PDFReportGenerator` / `generate_pdf_pv` | Moteur de génération des Procès-Verbaux de recette en PDF avec tables comparatives, logos/en-têtes et zones de signatures. |
| `CATALOG` | Référentiel global listant l'ensemble des points de contrôle (Identité, Matériel, Système, Sécurité, Logiciels, Environnement, Journaux). |
| `ExpertyAuditApp` | Application GUI Tkinter gérant le multithreading, la mise à jour dynamique de l'interface, la gestion des menus et les interactions utilisateur. |

---

## 3. Prérequis et Configuration

### Prérequis Système
* **Système d'exploitation** : Windows 10 / Windows 11 (droits administrateur recommandés pour exécuter la majorité des sondes et corrections).
* **Dépendances Python** : `fpdf2` (`pip install fpdf2`).

### Structure des Dossiers
À l'exécution, l'application génère ou utilise les dossiers suivants :
* `config.ini` : Fichier de configuration principal.
* `profils/` : Contient les fichiers profil au format JSON (ex: `POSTE-COMPTABLE.json`).
* `pv_recette/` : Dossier de sortie des rapports PDF générés.
* `logs/` : Traces d'exécution horodatées de l'application.

---

## 4. Catalogue des Contrôles

Le système évalue les contrôles sous plusieurs domaines :

1. **Identité (`ID`)** : Format du nom de machine (`PC-EXP-nnn`), vérification des comptes administrateurs locaux et détection de comptes non autorisés.
2. **Matériel (`HW`)** : Quantité de RAM, espace disque libre `C:`, santé S.M.A.R.T. et type de support (SSD/HDD).
3. **Système (`SYS`)** : Édition Windows (Pro/Enterprise), statut d'activation, synchronisation NTP, configuration DHCP.
4. **Sécurité (`SEC`)** : État de l'antivirus, fraîcheur des bases Defender, chiffrement BitLocker, Pare-feu, service `wuauserv` et mises à jour en attente.
5. **Logiciels (`SW`)** : Détection des applications obligatoires (socle `winget`), recherche de logiciels interdits et état des services.
6. **Environnement (`ENV`)** : Pavé numérique au démarrage (NumLock), affichage des fichiers cachés/extensions, page d'accueil Google Chrome et présence d'imprimantes.
7. **Journaux (`LOG`)** : Analyse du journal d'événements `System` sur les 24 dernières heures.

---

## 5. Guide d'Utilisation

### Lancement de l'Exécutable

L'application est compilée sous la forme d'un exécutable autonome (ex: `main.exe` ou `experty.exe`) via **PyInstaller**.

Afin de permettre l'exécution correcte des sondes système, des requêtes WMI et des scripts de remédiation :

1. Assurez-vous que les répertoires et fichiers indispensables (`profils/`, `config.ini`) sont présents dans le **même répertoire** que l'exécutable.
2. Lancez l'application en effectuant un clic droit sur l'exécutable et en choisissant **"Exécuter en tant qu'administrateur"**.

### Étapes d'une Recette

1. **Sélection du profil** : Choisissez le profil cible dans la liste déroulante du bandeau supérieur (ex: `POSTE-COMPTABLE.json`). L'application charge dynamiquement les fichiers JSON présents dans le dossier `profils/`.
2. **Saisie de l'opérateur** : Indiquez le nom ou l'identifiant du technicien effectuant la recette.
3. **Lancement de l'audit** : Cliquez sur **"Lancer la recette"**. Les sondes s'exécutent en arrière-plan via un système multithread et mettent à jour en temps réel la barre de progression ainsi que les indicateurs d'onglets.
4. **Analyse des Écarts** :
* Les éléments conformes apparaissent en **Vert**.
* Les écarts ou non-conformités apparaissent en **Rouge**.
* Les éléments dont l'état est indéterminé apparaissent en **Orange**.


5. **Remédiation** :
* Sélectionnez un contrôle en écart dans la liste détaillée.
* Si le contrôle est éligible à une correction automatisée, le bouton **"Corriger"** devient actif.
* Cliquez sur **"Corriger"** et confirmez l'action dans la boîte de dialogue contextuelle.
* La sonde associée est automatiquement réévaluée immédiatement après la tentative de correction.


6. **Génération du Procès-Verbal (PV)** :
* Une fois le verdict global établi (*CONFORME*, *CONFORME AVEC RESERVES* ou *NON CONFORME*), accédez au menu supérieur : `Recette` → `Éditer le procès-verbal (PDF)`.
* Le rapport PDF officiel est généré et stocké dans le dossier `pv_recette/` créé à la racine de l'exécutable.

---

## 6. Règles de Gestion Rédhibitoires & Verdicts

* **CONFORME** : Tous les contrôles requis sont validés.
* **CONFORME AVEC RESERVES** : Présence d'écarts uniquement sur des contrôles de sévérité *Mineur*.
* **NON CONFORME** : Présence d'au moins un écart sur un contrôle de sévérité *Majeur* ou *Bloquant*, ou présence d'évaluations *Indéterminées*.
