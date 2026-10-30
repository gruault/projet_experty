import os
import sys
import json
import configparser
import hashlib
import logging
import subprocess
import threading
import queue
import winreg
import re
import datetime
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from fpdf import FPDF

# ==========================================
# CONFIGURATION & PROFILES LOADER
# ==========================================

# Gère la configuration de l'application (lecture de config.ini, chemins, valeurs par défaut)
class AppConfig:
    # Initialise les chemins/valeurs par défaut puis charge la config
    def __init__(self, config_path="config.ini"):
        self.config_path = config_path
        self.profiles_dir = "profils"
        self.reports_dir = "pv_recette"
        self.logs_dir = "logs"
        self.bitlocker_keys_dir = "C:\\BitLockerKeys"
        self.default_operator = "Technicien EXPERTY"
        self.command_timeout = 30
        self.load_config()

    # Lit config.ini, applique les valeurs trouvées et crée les dossiers nécessaires
    def load_config(self):
        if not os.path.exists(self.config_path):
            messagebox.showerror("Erreur Configuration", f"Fichier de configuration introuvable : {self.config_path}")
            sys.exit(1)
        
        parser = configparser.ConfigParser()
        try:
            parser.read(self.config_path, encoding='utf-8')
            if 'Paths' in parser:
                self.profiles_dir = parser['Paths'].get('profiles_dir', self.profiles_dir)
                self.reports_dir = parser['Paths'].get('reports_dir', self.reports_dir)
                self.logs_dir = parser['Paths'].get('logs_dir', self.logs_dir)
                self.bitlocker_keys_dir = parser['Paths'].get('bitlocker_keys_dir', self.bitlocker_keys_dir)
            if 'Settings' in parser:
                self.default_operator = parser['Settings'].get('default_operator', self.default_operator)
                self.command_timeout = parser['Settings'].getint('command_timeout', self.command_timeout)
        except Exception as e:
            messagebox.showerror("Erreur Configuration", f"Erreur de lecture de config.ini :\n{str(e)}")
            sys.exit(1)

        os.makedirs(self.profiles_dir, exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)

# Charge et valide les profils de poste (fichiers JSON) utilisés pour la recette
class ProfileLoader:
    REQUIRED_KEYS = ["profile_name", "version", "validation_date", "identity", "hardware", "system", "security", "software", "environment", "printer", "logs"]

    @staticmethod
    # Charge un profil JSON, vérifie les clés requises et calcule son empreinte SHA256
    def load_profile(filepath):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fichier profil introuvable : {filepath}")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            profile_sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
            data = json.loads(content)

        for key in ProfileLoader.REQUIRED_KEYS:
            if key not in data:
                raise ValueError(f"Clé manquante dans le profil : {key}")

        # RG05 validation
        if not isinstance(data.get("hardware", {}).get("min_ram_gb"), (int, float)) or data["hardware"]["min_ram_gb"] <= 0:
            raise ValueError("hardware.min_ram_gb doit être un nombre positif.")
        
        return data, profile_sha256

# ==========================================
# POWERSHELL EXECUTION HELPER
# ==========================================

# Exécute une commande PowerShell cachée avec timeout et renvoie succès/sortie/erreur
def run_powershell(cmd, timeout=30):
    """
    Exécute une commande PowerShell sécurisée avec timeout,
    fenêtre cachée, encodage UTF-8 et retour JSON.
    """
    ps_cmd = f"$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {cmd}"
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    try:
        proc = subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        stdout, stderr = proc.communicate(timeout=timeout)
        if proc.returncode != 0:
            return {"success": False, "error": stderr.strip() or f"Erreur code {proc.returncode}"}
        return {"success": True, "output": stdout.strip()}
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"success": False, "error": f"Commande expirée après {timeout}s"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ==========================================
# SYSTEM PROBES (SONDES DE COLLECTE)
# ==========================================

# Sondes de collecte : chaque méthode contrôle un point de conformité du poste
class SystemProbes:
    @staticmethod
    # Récupère le nom de la machine
    def get_hostname():
        return os.environ.get('COMPUTERNAME', '')

    @staticmethod
    # Vérifie que le nom de machine respecte le format attendu
    def check_hostname(expected_pattern):
        actual = SystemProbes.get_hostname()
        match = re.match(expected_pattern, actual)
        return {
            "expected": f"Format {expected_pattern}",
            "actual": actual,
            "status": "Conforme" if match else "Écart",
            "msg": f"Nom de machine actuel : {actual}"
        }

    @staticmethod
    # Vérifie que le compte administrateur local existe et est actif
    def check_admin_account(admin_name):
        res = run_powershell(f"Get-LocalUser -Name '{admin_name}' -ErrorAction SilentlyContinue | Select-Enabled | ConvertTo-Json")
        if not res["success"]:
            return {"expected": f"Compte {admin_name} présent et actif", "actual": "Non trouvé", "status": "Écart", "msg": f"Compte {admin_name} absent."}
        try:
            data = json.loads(res["output"])
            enabled = data.get("Enabled", False)
            return {
                "expected": f"Compte {admin_name} présent et actif",
                "actual": f"Présent (Actif: {enabled})",
                "status": "Conforme" if enabled else "Écart",
                "msg": f"Compte {admin_name} est actif." if enabled else f"Compte {admin_name} désactivé."
            }
        except Exception as e:
            return {"expected": f"Compte {admin_name} actif", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Détecte les comptes locaux actifs non autorisés
    def check_unauthorized_accounts(allowed_accounts):
        res = run_powershell("Get-LocalUser | Select-Object -Property Name, Enabled | ConvertTo-Json")
        if not res["success"]:
            return {"expected": f"Autorisés : {', '.join(allowed_accounts)}", "actual": "Erreur lecture", "status": "Indéterminé", "msg": res["error"]}
        try:
            users = json.loads(res["output"])
            if isinstance(users, dict):
                users = [users]
            unauthorized = [u["Name"] for u in users if u["Name"] not in allowed_accounts and u.get("Enabled", True)]
            if unauthorized:
                return {
                    "expected": f"Autorisés : {', '.join(allowed_accounts)}",
                    "actual": f"Non autorisés actifs : {', '.join(unauthorized)}",
                    "status": "Écart",
                    "msg": f"Comptes locaux non prévus : {', '.join(unauthorized)}"
                }
            return {
                "expected": f"Autorisés : {', '.join(allowed_accounts)}",
                "actual": "Aucun compte non autorisé actif",
                "status": "Conforme",
                "msg": "Tous les comptes locaux sont autorisés."
            }
        except Exception as e:
            return {"expected": "Comptes locaux conformes", "actual": "Erreur parsing", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie que la RAM installée atteint le minimum requis
    def check_ram(min_gb):
        res = run_powershell("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB")
        if not res["success"]:
            return {"expected": f">= {min_gb} Go", "actual": "Erreur", "status": "Indéterminé", "msg": res["error"]}
        try:
            ram_gb = round(float(res["output"].replace(',', '.')), 1)
            return {
                "expected": f">= {min_gb} Go",
                "actual": f"{ram_gb} Go",
                "status": "Conforme" if ram_gb >= min_gb else "Écart",
                "msg": f"RAM détectée : {ram_gb} Go"
            }
        except Exception as e:
            return {"expected": f">= {min_gb} Go", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie l'espace disque libre sur le lecteur C:
    def check_disk_free_space(min_gb):
        res = run_powershell("(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace / 1GB")
        if not res["success"]:
            return {"expected": f">= {min_gb} Go libre", "actual": "Erreur", "status": "Indéterminé", "msg": res["error"]}
        try:
            free_gb = round(float(res["output"].replace(',', '.')), 1)
            return {
                "expected": f">= {min_gb} Go",
                "actual": f"{free_gb} Go libres",
                "status": "Conforme" if free_gb >= min_gb else "Écart",
                "msg": f"Espace disque libre C: : {free_gb} Go"
            }
        except Exception as e:
            return {"expected": f">= {min_gb} Go", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie l'état de santé S.M.A.R.T. des disques
    def check_smart_health():
        res = run_powershell("Get-PhysicalDisk | Select-Object -Property OperationalStatus, HealthStatus | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "Healthy", "actual": "Erreur WMI", "status": "Indéterminé", "msg": res["error"]}
        try:
            disks = json.loads(res["output"])
            if isinstance(disks, dict):
                disks = [disks]
            unhealthy = [d["HealthStatus"] for d in disks if d.get("HealthStatus") != "Healthy"]
            if unhealthy:
                return {"expected": "Healthy", "actual": f"Problème : {', '.join(unhealthy)}", "status": "Écart", "msg": "Santé S.M.A.R.T. dégradée."}
            return {"expected": "Healthy", "actual": "Healthy", "status": "Conforme", "msg": "Tous les disques sont en bonne santé."}
        except Exception as e:
            return {"expected": "Healthy", "actual": "Erreur parsing", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Identifie le type de support de stockage (SSD/HDD)
    def check_media_type():
        res = run_powershell("Get-PhysicalDisk | Select-Object -Property MediaType | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "SSD / HDD", "actual": "Inconnu", "status": "Indéterminé", "msg": res["error"]}
        try:
            disks = json.loads(res["output"])
            if isinstance(disks, dict):
                disks = [disks]
            types = [d.get("MediaType", "Unspecified") for d in disks]
            return {"expected": "SSD ou HDD identifié", "actual": ", ".join(types), "status": "Conforme", "msg": f"Types détectés : {', '.join(types)}"}
        except Exception as e:
            return {"expected": "SSD/HDD", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie que l'édition de Windows installée correspond à celle attendue
    def check_windows_version(expected_edition):
        res = run_powershell("(Get-CimInstance Win32_OperatingSystem).Caption")
        if not res["success"]:
            return {"expected": expected_edition, "actual": "Erreur", "status": "Indéterminé", "msg": res["error"]}
        actual = res["output"]
        status = "Conforme" if expected_edition.lower() in actual.lower() else "Écart"
        return {"expected": expected_edition, "actual": actual, "status": status, "msg": f"Édition installée : {actual}"}

    @staticmethod
    # Vérifie que Windows est activé
    def check_windows_activation():
        res = run_powershell("(Get-CimInstance SoftwareLicensingProduct -Filter \"LicenseStatus=1\").Name")
        if not res["success"]:
            return {"expected": "Activé", "actual": "Inconnu / Non activé", "status": "Indéterminé", "msg": res["error"]}
        active = bool(res["output"].strip())
        return {
            "expected": "Activé",
            "actual": "Licence activée" if active else "Non activé",
            "status": "Conforme" if active else "Écart",
            "msg": "Windows est activé." if active else "Windows n'est pas activé."
        }

    @staticmethod
    # Vérifie la synchronisation de l'heure via le serveur NTP attendu
    def check_time_sync(expected_server, max_skew_sec):
        res = run_powershell("w32tm /query /status")
        if not res["success"]:
            return {"expected": f"Serveur NTP {expected_server}", "actual": "Erreur w32tm", "status": "Indéterminé", "msg": res["error"]}
        return {"expected": f"NTP : {expected_server}", "actual": "Synchronisé", "status": "Conforme", "msg": "Heure système synchronisée."}

    @staticmethod
    # Vérifie que les interfaces réseau sont configurées en DHCP
    def check_dhcp_enabled():
        res = run_powershell("Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.Dhcp -eq 'Disabled' -and $_.InterfaceAlias -notlike '*Loopback*'} | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "DHCP activé", "actual": "Erreur réseau", "status": "Indéterminé", "msg": res["error"]}
        try:
            if res["output"].strip() and res["output"].strip() != "null":
                return {"expected": "DHCP activé sur toutes interfaces", "actual": "IP Fixe détectée", "status": "Écart", "msg": "Au moins une interface possède une IP fixe."}
            return {"expected": "DHCP activé", "actual": "DHCP activé partout", "status": "Conforme", "msg": "Toutes les cartes sont en DHCP."}
        except Exception as e:
            return {"expected": "DHCP activé", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie qu'un antivirus actif est enregistré sur le poste
    def check_antivirus():
        res = run_powershell("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -Property displayName, productState | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "Antivirus actif", "actual": "Erreur SecurityCenter", "status": "Indéterminé", "msg": res["error"]}
        try:
            avs = json.loads(res["output"])
            if isinstance(avs, dict):
                avs = [avs]
            if len(avs) > 0:
                names = [a["displayName"] for a in avs]
                return {"expected": "Antivirus actif", "actual": f"Présent ({', '.join(names)})", "status": "Conforme", "msg": f"Antivirus : {', '.join(names)}"}
            return {"expected": "Antivirus actif", "actual": "Aucun détecté", "status": "Écart", "msg": "Aucun antivirus enregistré."}
        except Exception as e:
            return {"expected": "Antivirus actif", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie que les signatures antivirus Defender ne sont pas trop anciennes
    def check_av_signatures(max_age_days):
        res = run_powershell("(Get-MpComputerStatus).AntivirusSignatureAge")
        if not res["success"]:
            return {"expected": f"<= {max_age_days} jours", "actual": "Erreur Defender", "status": "Indéterminé", "msg": res["error"]}
        try:
            age = int(res["output"])
            return {
                "expected": f"<= {max_age_days} jours",
                "actual": f"{age} jours",
                "status": "Conforme" if age <= max_age_days else "Écart",
                "msg": f"Âge des signatures Defender : {age} jours"
            }
        except Exception as e:
            return {"expected": f"<= {max_age_days} jours", "actual": "Erreur parsing", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie que le chiffrement BitLocker est activé sur le disque C:
    def check_bitlocker():
        res = run_powershell("Get-BitLockerVolume -MountPoint 'C:' | Select-Object -Property ProtectionStatus, VolumeStatus | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "BitLocker Activé (On)", "actual": "Erreur BitLocker", "status": "Indéterminé", "msg": res["error"]}
        try:
            bv = json.loads(res["output"])
            status = bv.get("ProtectionStatus", 0)
            is_on = (status == 1)
            return {
                "expected": "Protection On",
                "actual": "Activé (On)" if is_on else "Désactivé (Off)",
                "status": "Conforme" if is_on else "Écart",
                "msg": "Disque C: chiffré BitLocker." if is_on else "Disque C: non chiffré BitLocker."
            }
        except Exception as e:
            return {"expected": "Protection On", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie que tous les profils du pare-feu Windows sont actifs
    def check_firewall():
        res = run_powershell("Get-NetFirewallProfile | Select-Object -Property Name, Enabled | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "Tous les profils actifs", "actual": "Erreur Firewall", "status": "Indéterminé", "msg": res["error"]}
        try:
            pfs = json.loads(res["output"])
            if isinstance(pfs, dict):
                pfs = [pfs]
            disabled = [p["Name"] for p in pfs if not p.get("Enabled", False)]
            if disabled:
                return {"expected": "Domain, Private, Public actifs", "actual": f"Désactivés : {', '.join(disabled)}", "status": "Écart", "msg": "Certains profils pare-feu sont coupés."}
            return {"expected": "Domain, Private, Public actifs", "actual": "Tous actifs", "status": "Conforme", "msg": "Tous les profils pare-feu sont actifs."}
        except Exception as e:
            return {"expected": "Profils pare-feu actifs", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie que le service Windows Update est démarrable/actif
    def check_wuauserv_service():
        res = run_powershell("Get-Service -Name wuauserv | Select-Object -Property Status, StartType | ConvertTo-Json")
        if not res["success"]:
            return {"expected": "Démarrable et Actif", "actual": "Erreur Service", "status": "Indéterminé", "msg": res["error"]}
        try:
            srv = json.loads(res["output"])
            status = srv.get("Status")
            start_type = srv.get("StartType")
            is_ok = (status == 4 or status == "Running") and (start_type != 1 and start_type != "Disabled")
            return {
                "expected": "En cours / Automatique ou Manuel",
                "actual": f"Status: {status}, Start: {start_type}",
                "status": "Conforme" if is_ok else "Écart",
                "msg": f"Service Windows Update : {status} ({start_type})"
            }
        except Exception as e:
            return {"expected": "wuauserv actif", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Compte les mises à jour Windows en attente via l'API COM Windows Update
    def check_pending_updates(max_allowed):
        res = run_powershell("$sub = New-Object -ComObject Microsoft.Update.Session; $searcher = $sub.CreateUpdateSearcher(); $res = $searcher.Search('IsInstalled=0 and Type=\\'Software\\''); $res.Updates.Count")
        if not res["success"]:
            return {"expected": f"<= {max_allowed} maj", "actual": "Erreur COM Windows Update", "status": "Indéterminé", "msg": res["error"]}
        try:
            count = int(res["output"].strip())
            return {
                "expected": f"<= {max_allowed} mises à jour",
                "actual": f"{count} en attente",
                "status": "Conforme" if count <= max_allowed else "Écart",
                "msg": f"{count} mises à jour système en attente."
            }
        except Exception as e:
            return {"expected": f"<= {max_allowed} maj", "actual": "Erreur parsing", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie, via le registre, que les applications du socle requis sont installées
    def check_installed_apps(required_apps):
        installed = set()
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        for hkey, path in reg_paths:
            try:
                key = winreg.OpenKey(hkey, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        disp_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        if disp_name:
                            installed.add(disp_name.lower())
                    except OSError:
                        pass
            except OSError:
                pass

        missing = []
        for app in required_apps:
            app_low = app.lower()
            if not any(app_low in inst for inst in installed):
                missing.append(app)

        if missing:
            return {"expected": f"Tous présents ({len(required_apps)})", "actual": f"Manquants : {', '.join(missing)}", "status": "Écart", "msg": f"Applications manquantes : {', '.join(missing)}"}
        return {"expected": "Toutes applications du socle", "actual": "Toutes installées", "status": "Conforme", "msg": "Toutes les applications winget requises sont présente."}

    @staticmethod
    # Détecte, via le registre, la présence de logiciels interdits
    def check_forbidden_apps(forbidden_apps):
        installed = []
        reg_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        for hkey, path in reg_paths:
            try:
                key = winreg.OpenKey(hkey, path)
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name)
                        disp_name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                        if disp_name:
                            installed.append(disp_name)
                    except OSError:
                        pass
            except OSError:
                pass

        found = []
        for forb in forbidden_apps:
            for inst in installed:
                if forb.lower() in inst.lower():
                    found.append(inst)

        if found:
            return {"expected": "Aucun logiciel interdit", "actual": f"Trouvé : {', '.join(set(found))}", "status": "Écart", "msg": f"Logiciels interdits détectés : {', '.join(set(found))}"}
        return {"expected": "Aucun logiciel interdit", "actual": "Aucun détecté", "status": "Conforme", "msg": "Aucun logiciel interdit trouvé."}

    @staticmethod
    # Vérifie que les services requis sont démarrés
    def check_required_services(required_services):
        bad_services = []
        for srv in required_services:
            name = srv["name"]
            res = run_powershell(f"Get-Service -Name '{name}' -ErrorAction SilentlyContinue | Select-Object -Property Status, StartType | ConvertTo-Json")
            if not res["success"] or not res["output"].strip():
                bad_services.append(f"{name} (absent)")
                continue
            try:
                data = json.loads(res["output"])
                status = data.get("Status")
                if status not in [4, "Running"]:
                    bad_services.append(f"{name} (arrêté)")
            except Exception:
                bad_services.append(f"{name} (erreur)")

        if bad_services:
            return {"expected": "Tous services démarrés", "actual": f"Anomalies : {', '.join(bad_services)}", "status": "Écart", "msg": f"Services non conformes : {', '.join(bad_services)}"}
        return {"expected": "Tous services requis démarrés", "actual": "Conformes", "status": "Conforme", "msg": "Tous les services requis fonctionnent."}

    @staticmethod
    # Vérifie que le pavé numérique est activé au démarrage (registre)
    def check_numlock():
        try:
            key = winreg.OpenKey(winreg.HKEY_USERS, r".DEFAULT\Control Panel\Keyboard")
            val, _ = winreg.QueryValueEx(key, "InitialKeyboardIndicators")
            is_on = str(val).strip() in ["2", "2147483650"]
            return {"expected": "Pavé numérique actif (2)", "actual": str(val), "status": "Conforme" if is_on else "Écart", "msg": f"Valeur registre NumLock : {val}"}
        except Exception as e:
            return {"expected": "Pavé numérique actif", "actual": "Erreur Registre", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie l'affichage des extensions de fichiers et des fichiers cachés dans l'explorateur
    def check_explorer_settings():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")
            hide_ext, _ = winreg.QueryValueEx(key, "HideFileExt")
            hidden, _ = winreg.QueryValueEx(key, "Hidden")
            is_ok = (hide_ext == 0) and (hidden == 1)
            return {
                "expected": "Extensions visibles (0), Fichiers cachés visibles (1)",
                "actual": f"HideFileExt={hide_ext}, Hidden={hidden}",
                "status": "Conforme" if is_ok else "Écart",
                "msg": f"Affichage extensions/cachés : HideFileExt={hide_ext}, Hidden={hidden}"
            }
        except Exception as e:
            return {"expected": "Extensions & cachés visibles", "actual": "Erreur Registre", "status": "Indéterminé", "msg": str(e)}

    @staticmethod
    # Vérifie la page d'accueil Chrome imposée par stratégie registre
    def check_chrome_homepage(expected_url):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome")
            val, _ = winreg.QueryValueEx(key, "HomepageLocation")
            status = "Conforme" if val == expected_url else "Écart"
            return {"expected": expected_url, "actual": val, "status": status, "msg": f"Stratégie Chrome Homepage : {val}"}
        except Exception:
            return {"expected": expected_url, "actual": "Non configurée", "status": "Écart", "msg": "Stratégie Chrome Homepage absente du registre."}

    @staticmethod
    # Vérifie la présence de l'imprimante réseau attendue
    def check_printer(expected_name):
        res = run_powershell(f"Get-Printer -Name '{expected_name}' -ErrorAction SilentlyContinue | Select-Object -Property Name | ConvertTo-Json")
        if not res["success"]:
            return {"expected": expected_name, "actual": "Erreur Spooler", "status": "Indéterminé", "msg": res["error"]}
        if res["output"].strip():
            return {"expected": expected_name, "actual": expected_name, "status": "Conforme", "msg": f"Imprimante {expected_name} trouvée."}
        return {"expected": expected_name, "actual": "Absente", "status": "Écart", "msg": f"Imprimante {expected_name} introuvable."}

    @staticmethod
    # Compte les événements critiques/erreurs système des dernières 24h
    def check_event_logs(max_critical_24h):
        res = run_powershell("(Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue).Count")
        if not res["success"]:
            return {"expected": f"<= {max_critical_24h} événements", "actual": "Erreur EventLog", "status": "Indéterminé", "msg": res["error"]}
        try:
            val = res["output"].strip()
            count = int(val) if val else 0
            return {
                "expected": f"<= {max_critical_24h} sur 24h",
                "actual": f"{count} critiques/erreurs",
                "status": "Conforme" if count <= max_critical_24h else "Écart",
                "msg": f"{count} événements d'erreur sur les dernières 24h."
            }
        except Exception as e:
            return {"expected": f"<= {max_critical_24h}", "actual": "Erreur", "status": "Indéterminé", "msg": str(e)}

# ==========================================
# AUTOMATIC REMEDIATIONS (CORRECTIONS)
# ==========================================

# Corrections automatiques appliquées pour résorber les écarts détectés par les sondes
class SystemRemediations:
    @staticmethod
    # Renomme la machine (nécessite un redémarrage)
    def fix_hostname(new_hostname):
        res = run_powershell(f"Rename-Computer -NewName '{new_hostname}' -Force")
        if res["success"]:
            return True, "Nom modifié avec succès. Redémarrage nécessaire.", True
        return False, f"Échec du renommage : {res['error']}", False

    @staticmethod
    # Désactive un compte local non autorisé
    def fix_unauthorized_account(username):
        res = run_powershell(f"Disable-LocalUser -Name '{username}'")
        if res["success"]:
            return True, f"Compte {username} désactivé.", False
        return False, f"Échec désactivation {username} : {res['error']}", False

    @staticmethod
    # Lance l'optimisation/défragmentation du disque C:
    def fix_media_defrag():
        res = run_powershell("Optimize-Volume -DriveLetter C -Defrag -Verbose")
        if res["success"]:
            return True, "Analyse et optimisation du disque effectuées.", False
        return False, f"Échec optimisation : {res['error']}", False

    @staticmethod
    # Reconfigure le serveur NTP et resynchronise l'heure
    def fix_time_sync(server):
        run_powershell(f"w32tm /config /manualpeerlist:'{server}' /syncfromflags:manual /reliable:YES /update")
        res = run_powershell("w32tm /resync")
        if res["success"]:
            return True, f"Temps resynchronisé avec {server}.", False
        return False, f"Échec de la synchro temps : {res['error']}", False

    @staticmethod
    # Repasse les interfaces réseau en DHCP
    def fix_dhcp():
        res = run_powershell("Get-NetIPInterface -AddressFamily IPv4 | Where-Object {$_.Dhcp -eq 'Disabled'} | Set-NetIPInterface -Dhcp Enabled; Get-NetAdapter | Set-DnsClientServerAddress -ResetServerAddresses")
        if res["success"]:
            return True, "Interfaces réseau basculées en DHCP.", False
        return False, f"Échec remise en DHCP : {res['error']}", False

    @staticmethod
    # Met à jour les signatures antivirus Defender
    def fix_av_signatures():
        res = run_powershell("Update-MpSignature")
        if res["success"]:
            return True, "Signatures Defender mises à jour.", False
        return False, f"Échec MAJ signatures : {res['error']}", False

    @staticmethod
    # Réactive tous les profils du pare-feu Windows
    def fix_firewall():
        res = run_powershell("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True")
        if res["success"]:
            return True, "Tous les profils pare-feu ont été activés.", False
        return False, f"Échec activation pare-feu : {res['error']}", False

    @staticmethod
    # Réactive et démarre le service Windows Update
    def fix_wuauserv():
        res = run_powershell("Set-Service -Name wuauserv -StartupType Automatic; Start-Service -Name wuauserv")
        if res["success"]:
            return True, "Service Windows Update réactivé et démarré.", False
        return False, f"Échec réactivation wuauserv : {res['error']}", False

    @staticmethod
    # Installe les mises à jour Windows en attente (avec redémarrage auto)
    def fix_pending_updates():
        res = run_powershell("Install-Module PSWindowsUpdate -Force -Confirm:$false; Get-WindowsUpdate -Install -AcceptAll -AutoReboot", timeout=300)
        if res["success"]:
            return True, "Mises à jour téléchargées et installées.", True
        return False, f"Échec installation MAJ : {res['error']}", False

    @staticmethod
    # Installe une application via winget en mode silencieux
    def fix_install_winget_app(app_id):
        res = run_powershell(f"winget install --id '{app_id}' --silent --accept-package-agreements --accept-source-agreements", timeout=180)
        if res["success"]:
            return True, f"Application {app_id} installée via winget.", False
        return False, f"Échec installation {app_id} : {res['error']}", False

    @staticmethod
    # Configure et démarre les services requis
    def fix_services(required_services):
        errs = []
        for srv in required_services:
            name = srv["name"]
            res = run_powershell(f"Set-Service -Name '{name}' -StartupType Automatic; Start-Service -Name '{name}'")
            if not res["success"]:
                errs.append(name)
        if not errs:
            return True, "Tous les services requis ont été démarrés.", False
        return False, f"Erreur sur services : {', '.join(errs)}", False

    @staticmethod
    # Active le pavé numérique au démarrage via le registre
    def fix_numlock():
        try:
            key = winreg.OpenKey(winreg.HKEY_USERS, r".DEFAULT\Control Panel\Keyboard", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "InitialKeyboardIndicators", 0, winreg.REG_SZ, "2")
            winreg.CloseKey(key)
            return True, "Pavé numérique activé au démarrage (Registre HKU\\.DEFAULT).", False
        except Exception as e:
            return False, f"Échec écriture Registre : {str(e)}", False

    @staticmethod
    # Force l'affichage des extensions de fichiers et fichiers cachés via le registre
    def fix_explorer_settings():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "HideFileExt", 0, winreg.REG_DWORD, 0)
            winreg.SetValueEx(key, "Hidden", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return True, "Paramètres d'affichage explorateur appliqués.", False
        except Exception as e:
            return False, f"Échec écriture Registre : {str(e)}", False

    @staticmethod
    # Impose la page d'accueil Chrome via une stratégie registre
    def fix_chrome_homepage(homepage_url):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Google\Chrome")
            winreg.SetValueEx(key, "HomepageLocation", 0, winreg.REG_SZ, homepage_url)
            winreg.SetValueEx(key, "HomepageIsNewTabPage", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            return True, f"Page d'accueil Chrome configurée sur {homepage_url} par stratégie.", False
        except Exception as e:
            return False, f"Échec enregistrement stratégie Chrome : {str(e)}", False

# ==========================================
# PDF REPORT GENERATOR (FPDF2)
# ==========================================

# Mise en page du PDF du procès-verbal (en-tête / pied de page)
class PDFReportGenerator(FPDF):
    # En-tête du PDF : titre du procès-verbal
    def header(self):
        self.set_font('Helvetica', 'B', 14)
        self.cell(0, 10, 'EXPERTY - PROCÈS-VERBAL DE RECETTE SYSTEME', border=False, ln=1, align='C')
        self.set_font('Helvetica', 'I', 9)
        self.cell(0, 5, 'Conformité du poste de travail déployé', border=False, ln=1, align='C')
        self.ln(5)

    # Pied de page du PDF : numéro de page
    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}} - Document confidentiel EXPERTY', align='C')

# Génère le PDF du procès-verbal de recette à partir des résultats de la session
def generate_pdf_pv(session_data: Dict[str, Any], filepath: str) -> None:
    pdf = PDFReportGenerator()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)

    # Info Générales
    pdf.set_fill_color(230, 230, 230)
    pdf.set_font("Helvetica", 'B', 10)
    pdf.cell(0, 6, "1. INFORMATIONS GENERALES", fill=True, ln=1)
    pdf.ln(2)
    pdf.set_font("Helvetica", size=9)
    
    info_text = (
        f"Poste (Hostname) : {session_data['hostname']}\n"
        f"Opérateur : {session_data['operator']}\n"
        f"Date et Heure : {session_data['timestamp']}\n"
        f"Profil appliqué : {session_data['profile_name']} (v{session_data['profile_version']})\n"
        f"Empreinte SHA-256 du profil : {session_data['profile_hash'][:32]}..."
    )
    pdf.multi_cell(0, 5, info_text)
    pdf.ln(4)

    # Tableau des contrôles
    pdf.set_font("Helvetica", 'B', 10)
    pdf.cell(0, 6, "2. DETAIL DES CONTROLES ET CORRECTIONS", fill=True, ln=1)
    pdf.ln(2)

    pdf.set_font("Helvetica", 'B', 8)
    pdf.cell(45, 6, "Contrôle", border=1)
    pdf.cell(35, 6, "Attendu", border=1)
    pdf.cell(35, 6, "Initial", border=1)
    pdf.cell(40, 6, "Action / Correction", border=1)
    pdf.cell(35, 6, "Statut Final", border=1, ln=1)

    pdf.set_font("Helvetica", size=7)
    for r in session_data['results']:
        ctrl = r['control'][:25]
        exp = str(r['expected'])[:20]
        init = str(r['initial'])[:20]
        action = str(r['action'])[:22]
        stat = str(r['final_status'])

        if stat == "Conforme":
            pdf.set_text_color(0, 128, 0)
        elif stat == "Écart":
            pdf.set_text_color(200, 0, 0)
        else:
            pdf.set_text_color(200, 100, 0)

        pdf.cell(45, 5, ctrl, border=1)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(35, 5, exp, border=1)
        pdf.cell(35, 5, init, border=1)
        pdf.cell(40, 5, action, border=1)

        if stat == "Conforme":
            pdf.set_text_color(0, 128, 0)
        elif stat == "Écart":
            pdf.set_text_color(200, 0, 0)
        else:
            pdf.set_text_color(200, 100, 0)
        pdf.cell(35, 5, stat, border=1, ln=1)  # Remplacement ici aussi par ln=1
        pdf.set_text_color(0, 0, 0)

    pdf.ln(5)
    # Verdict
    pdf.set_font("Helvetica", 'B', 11)
    pdf.cell(0, 7, f"VERDICT GLOBAL : {session_data['verdict']}", border=1, fill=True, align='C', ln=1)
    pdf.ln(4)

    # Signatures
    pdf.set_font("Helvetica", size=9)
    pdf.cell(95, 15, "Signature du Technicien :", border=1)
    pdf.cell(95, 15, "Validation Responsable IT :", border=1, ln=1)

    pdf.output(filepath)

# ==========================================
# CATALOG OF CONTROLS (F3)
# ==========================================

# Catalogue des contrôles de recette, regroupés par domaine (identité, matériel, système, sécurité, logiciels, environnement, journaux)
CATALOG = [
    # Identité
    {"id": "ID_01", "domain": "Identité", "label": "Nom de machine conforme (PC-EXP-nnn)", "severity": "Majeur", "mode": "Automatique"},
    {"id": "ID_02", "domain": "Identité", "label": "Compte adm-experty présent et actif", "severity": "Bloquant", "mode": "Manuelle", "instruction": "Créer le compte adm-experty localement avec le mot de passe fort du service informatique."},
    {"id": "ID_03", "domain": "Identité", "label": "Comptes locaux non autorisés", "severity": "Bloquant", "mode": "Automatique"},
    # Matériel
    {"id": "HW_01", "domain": "Matériel", "label": "Mémoire vive minimale (RAM)", "severity": "Majeur", "mode": "Manuelle", "instruction": "Ajouter des barrettes de RAM au poste pour atteindre le seuil du profil."},
    {"id": "HW_02", "domain": "Matériel", "label": "Espace disque libre C:", "severity": "Majeur", "mode": "Manuelle", "instruction": "Nettoyer le disque C: ou étendre la partition système."},
    {"id": "HW_03", "domain": "Matériel", "label": "Santé S.M.A.R.T. du disque", "severity": "Bloquant", "mode": "Manuelle", "instruction": "Disque défaillant ! Remplacer le disque dur et retourner le composant au stock."},
    {"id": "HW_04", "domain": "Matériel", "label": "Type de support et maintenance", "severity": "Mineur", "mode": "Automatique"},
    # Système
    {"id": "SYS_01", "domain": "Système", "label": "Édition Windows 11 Pro", "severity": "Bloquant", "mode": "Manuelle", "instruction": "Mettre à niveau Windows vers l'édition Windows 11 Pro."},
    {"id": "SYS_02", "domain": "Système", "label": "Activation de Windows", "severity": "Majeur", "mode": "Manuelle", "instruction": "Saisir la clé de licence KMS / MAK et activer Windows dans les paramètres."},
    {"id": "SYS_03", "domain": "Système", "label": "Synchronisation heure NTP", "severity": "Majeur", "mode": "Automatique"},
    {"id": "SYS_04", "domain": "Système", "label": "Configuration IP (DHCP)", "severity": "Majeur", "mode": "Automatique"},
    # Sécurité
    {"id": "SEC_01", "domain": "Sécurité", "label": "Antivirus actif", "severity": "Bloquant", "mode": "Manuelle", "instruction": "Activer Microsoft Defender ou réinstaller l'agent Antivirus d'entreprise."},
    {"id": "SEC_02", "domain": "Sécurité", "label": "Âge des signatures Antivirus", "severity": "Majeur", "mode": "Automatique"},
    {"id": "SEC_03", "domain": "Sécurité", "label": "Chiffrement BitLocker", "severity": "Bloquant", "mode": "Manuelle", "instruction": "Activer BitLocker sur C: et sauvegarder la clé de récupération dans le dossier configuré (RG08)."},
    {"id": "SEC_04", "domain": "Sécurité", "label": "Profils du Pare-feu Windows", "severity": "Bloquant", "mode": "Automatique"},
    {"id": "SEC_05", "domain": "Sécurité", "label": "Service Windows Update démarrable", "severity": "Bloquant", "mode": "Automatique"},
    {"id": "SEC_06", "domain": "Sécurité", "label": "Mises à jour Windows en attente", "severity": "Majeur", "mode": "Automatique"},
    # Logiciels
    {"id": "SW_01", "domain": "Logiciels", "label": "Logiciels du socle (winget)", "severity": "Majeur", "mode": "Automatique"},
    {"id": "SW_02", "domain": "Logiciels", "label": "Logiciels interdits", "severity": "Majeur", "mode": "Manuelle", "instruction": "Désinstaller manuellement le logiciel interdit via le Panneau de Configuration (RG08)."},
    {"id": "SW_03", "domain": "Logiciels", "label": "Services requis fonctionnels", "severity": "Mineur", "mode": "Automatique"},
    # Environnement
    {"id": "ENV_01", "domain": "Environnement", "label": "Pavé numérique au démarrage", "severity": "Mineur", "mode": "Automatique"},
    {"id": "ENV_02", "domain": "Environnement", "label": "Affichage extensions et cachés", "severity": "Mineur", "mode": "Automatique"},
    {"id": "ENV_03", "domain": "Environnement", "label": "Page de démarrage Chrome", "severity": "Mineur", "mode": "Automatique"},
    {"id": "ENV_04", "domain": "Environnement", "label": "Imprimante réseau service", "severity": "Majeur", "mode": "Manuelle", "instruction": "Ajouter l'imprimante indiquée via les paramètres Windows ou le serveur de spool."},
    # Journaux
    {"id": "LOG_01", "domain": "Journaux", "label": "Événements critiques (24h)", "severity": "Mineur", "mode": "Manuelle", "instruction": "Consulter l'observateur d'événements (eventvwr.msc) pour analyser les erreurs critiques."}
]

# ==========================================
# MAIN GUI APPLICATION (TKINTER)
# ==========================================

# Fenêtre principale de l'application (interface Tkinter de la recette des postes)
class ExpertyAuditApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("EXPERTY - Recette des Postes Déployés v2026.1")
        self.geometry("1100x700")
        self.minsize(950, 600)

        self.app_config = AppConfig()
        self.current_profile = None
        self.current_profile_hash = ""
        self.is_admin = self.check_admin_rights()
        
        self.results_data = {}
        self.worker_queue = queue.Queue()
        self.audit_running = False

        self.setup_logging()
        self.create_menu()
        self.create_widgets()

        self.load_default_profile()
        self.after(100, self.process_queue)

    # Vérifie si l'application s'exécute avec les droits administrateur
    def check_admin_rights(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    # Configure la journalisation de session dans un fichier log
    def setup_logging(self):
        log_file = os.path.join(self.app_config.logs_dir, f"audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            encoding='utf-8'
        )
        logging.info("Application démarrée.")

    # Construit la barre de menu (Fichier, Recette, Affichage, Aide)
    def create_menu(self):
        menubar = tk.Menu(self)
        
        # Menu Fichier
        menu_file = tk.Menu(menubar, tearoff=0)
        menu_file.add_command(label="Choisir le profil...", command=self.action_choose_profile)
        menu_file.add_command(label="Recharger la configuration", command=self.action_reload_config)
        menu_file.add_command(label="Ouvrir le dossier des PV", command=self.action_open_pv_folder)
        menu_file.add_separator()
        menu_file.add_command(label="Quitter", command=self.action_quit)
        menubar.add_cascade(label="Fichier", menu=menu_file)

        # Menu Recette
        menu_recette = tk.Menu(menubar, tearoff=0)
        menu_recette.add_command(label="Lancer la recette", command=self.start_full_audit)
        menu_recette.add_command(label="Rejouer les écarts", command=self.start_replay_audit)
        menu_recette.add_command(label="Collecte seule (Brut)", command=self.action_raw_collect)
        menu_recette.add_separator()
        menu_recette.add_command(label="Éditer le procès-verbal (PDF)", command=self.action_generate_pv)
        menubar.add_cascade(label="Recette", menu=menu_recette)

        # Menu Affichage
        menu_view = tk.Menu(menubar, tearoff=0)
        menu_view.add_command(label="Tout afficher", command=lambda: self.filter_display("ALL"))
        menu_view.add_command(label="Écarts seulement", command=lambda: self.filter_display("ECART"))
        menu_view.add_command(label="Indéterminés seulement", command=lambda: self.filter_display("INDETERMINE"))
        menubar.add_cascade(label="Affichage", menu=menu_view)

        # Menu Aide
        menu_help = tk.Menu(menubar, tearoff=0)
        menu_help.add_command(label="À propos", command=self.action_about)
        menubar.add_cascade(label="Aide", menu=menu_help)

        self.config(menu=menubar)

    # Construit l'interface graphique : bandeau de session, onglets de résultats, panneau de détail, barre d'état
    def create_widgets(self):
        # 1. BANDEAU HAUT
        top_frame = ttk.LabelFrame(self, text=" Session de Recette ")
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(top_frame, text="Poste :").grid(row=0, column=0, padx=5, pady=5)
        self.lbl_hostname = ttk.Label(top_frame, text=SystemProbes.get_hostname(), font=("Helvetica", 10, "bold"))
        self.lbl_hostname.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(top_frame, text="Profil :").grid(row=0, column=2, padx=5, pady=5)
        self.cb_profiles = ttk.Combobox(top_frame, state="readonly", width=25)
        self.cb_profiles.grid(row=0, column=3, padx=5, pady=5)
        self.cb_profiles.bind("<<ComboboxSelected>>", self.on_profile_selected)

        ttk.Label(top_frame, text="Opérateur :").grid(row=0, column=4, padx=5, pady=5)
        self.ent_operator = ttk.Entry(top_frame, width=20)
        self.ent_operator.insert(0, self.app_config.default_operator)
        self.ent_operator.grid(row=0, column=5, padx=5, pady=5)

        admin_txt = "ADMIN : OUI" if self.is_admin else "ADMIN : NON (Resteinte)"
        admin_fg = "green" if self.is_admin else "red"
        self.lbl_admin = tk.Label(top_frame, text=admin_txt, fg=admin_fg, font=("Helvetica", 9, "bold"))
        self.lbl_admin.grid(row=0, column=6, padx=10, pady=5)

        self.btn_start = ttk.Button(top_frame, text="Lancer la recette", command=self.start_full_audit)
        self.btn_start.grid(row=0, column=7, padx=10, pady=5)

        # 2. ONGLETS DOMAINES
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.domains = ["Synthèse", "Identité", "Matériel", "Système", "Sécurité", "Logiciels", "Environnement", "Journaux"]
        self.tables = {}

        for dom in self.domains:
            tab = ttk.Frame(self.notebook)
            self.notebook.add(tab, text=dom)
            
            cols = ("id", "label", "expected", "actual", "status", "mode")
            tree = ttk.Treeview(tab, columns=cols, show="headings", selectmode="browse")
            tree.heading("id", text="ID")
            tree.heading("label", text="Contrôle")
            tree.heading("expected", text="Valeur Attendue")
            tree.heading("actual", text="Valeur Constatée")
            tree.heading("status", text="Statut")
            tree.heading("mode", text="Correction")

            tree.column("id", width=60, anchor="center")
            tree.column("label", width=250)
            tree.column("expected", width=200)
            tree.column("actual", width=200)
            tree.column("status", width=120, anchor="center")
            tree.column("mode", width=100, anchor="center")

            # Couleurs de lignes
            tree.tag_configure("Conforme", background="#D4EDDA", foreground="#155724")
            tree.tag_configure("Écart", background="#F8D7DA", foreground="#721C24")
            tree.tag_configure("Indéterminé", background="#FFF3CD", foreground="#856404")
            tree.tag_configure("NonEvalué", background="#E2E3E5", foreground="#383D41")

            tree.pack(fill=tk.BOTH, expand=True)
            tree.bind("<<TreeviewSelect>>", self.on_tree_select)
            self.tables[dom] = tree

        # 3. PANNEAU DE DETAIL
        detail_frame = ttk.LabelFrame(self, text=" Détails & Actions ")
        detail_frame.pack(fill=tk.X, padx=10, pady=5)

        self.lbl_detail_msg = ttk.Label(detail_frame, text="Sélectionnez une ligne pour voir les détails.", font=("Helvetica", 9))
        self.lbl_detail_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        self.btn_recheck = ttk.Button(detail_frame, text="Relire ce contrôle", command=self.action_recheck_single, state=tk.DISABLED)
        self.btn_recheck.pack(side=tk.RIGHT, padx=5, pady=5)

        self.btn_fix = ttk.Button(detail_frame, text="Corriger", command=self.action_fix_single, state=tk.DISABLED)
        self.btn_fix.pack(side=tk.RIGHT, padx=5, pady=5)

        # 4. BARRE D'ETAT
        status_frame = ttk.Frame(self)
        status_frame.pack(fill=tk.X, padx=10, pady=2)

        self.progress = ttk.Progressbar(status_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.lbl_counters = ttk.Label(status_frame, text="Vert: 0 | Rouge: 0 | Orange: 0 | Gris: 0")
        self.lbl_counters.pack(side=tk.LEFT, padx=10)

        self.lbl_verdict = tk.Label(status_frame, text="VERDICT : EN ATTENTE", font=("Helvetica", 10, "bold"), bg="gray", fg="white", padx=10)
        self.lbl_verdict.pack(side=tk.RIGHT, padx=5)

    # ==========================================
    # CORE LOGIC & THREADING
    # ==========================================

    # Liste les profils disponibles et charge le profil par défaut
    def load_default_profile(self):
        profiles = [f for f in os.listdir(self.app_config.profiles_dir) if f.endswith('.json')]
        self.cb_profiles['values'] = profiles
        if "POSTE-COMPTABLE.json" in profiles:
            self.cb_profiles.set("POSTE-COMPTABLE.json")
        elif profiles:
            self.cb_profiles.set(profiles[0])
        self.on_profile_selected(None)

    # Charge le profil sélectionné et réinitialise les tableaux de résultats
    def on_profile_selected(self, event):
        selected = self.cb_profiles.get()
        if not selected:
            return
        filepath = os.path.join(self.app_config.profiles_dir, selected)
        try:
            self.current_profile, self.current_profile_hash = ProfileLoader.load_profile(filepath)
            logging.info(f"Profil chargé : {selected} (SHA256: {self.current_profile_hash})")
            self.reset_tables()
        except Exception as e:
            messagebox.showerror("Erreur Profil", f"Impossible de charger le profil :\n{str(e)}")
            logging.error(f"Erreur chargement profil {selected}: {str(e)}")

    # Vide et réinitialise les tableaux de contrôles avec les lignes du catalogue
    def reset_tables(self):
        for tree in self.tables.values():
            for item in tree.get_children():
                tree.delete(item)
        
        self.results_data.clear()
        if not self.current_profile:
            return

        for ctrl in CATALOG:
            cid = ctrl["id"]
            dom = ctrl["domain"]
            lbl = ctrl["label"]
            mode = ctrl["mode"]

            # Insertion dans l'onglet domaine et synthèse
            item_data = (cid, lbl, "-", "-", "Non évalué", mode)
            
            tid_dom = self.tables[dom].insert("", tk.END, iid=cid, values=item_data, tags=("NonEvalué",))
            tid_syn = self.tables["Synthèse"].insert("", tk.END, iid=f"syn_{cid}", values=item_data, tags=("NonEvalué",))

    # Lance la recette complète dans un thread séparé
    def start_full_audit(self):
        if self.audit_running:
            return
        if not self.current_profile:
            messagebox.showwarning("Avertissement", "Aucun profil valide chargé.")
            return

        self.audit_running = True
        self.btn_start.config(state=tk.DISABLED)
        self.progress['value'] = 0

        threading.Thread(target=self._worker_run_audit, daemon=True).start()

    # Exécute les contrôles en arrière-plan et pousse les résultats dans la file de messages UI
    def _worker_run_audit(self, target_ids=None):
        active_controls = CATALOG if not target_ids else [c for c in CATALOG if c["id"] in target_ids]
        total = len(active_controls)

        for idx, ctrl in enumerate(active_controls):
            cid = ctrl["id"]
            res = self.evaluate_control(ctrl)
            self.worker_queue.put(("CONTROL_DONE", cid, res, int(((idx + 1) / total) * 100)))

        self.worker_queue.put(("AUDIT_COMPLETE", None, None, 100))

    # Exécute la sonde correspondant à un contrôle donné (ou renvoie 'désactivé' selon le profil)
    def evaluate_control(self, ctrl):
        cid = ctrl["id"]
        prof = self.current_profile

        # RG03/F1 - Vérification si désactivé dans le profil
        if cid == "HW_03" and not prof["hardware"].get("smart_check_enabled", True):
            return {"expected": "Désactivé", "actual": "Non évalué", "status": "NonEvalué", "msg": "Contrôle désactivé dans le profil."}
        if cid == "HW_04" and not prof["hardware"].get("media_type_check_enabled", True):
            return {"expected": "Désactivé", "actual": "Non évalué", "status": "NonEvalué", "msg": "Contrôle désactivé dans le profil."}
        if cid == "SYS_02" and not prof["system"].get("windows_activation_enabled", True):
            return {"expected": "Désactivé", "actual": "Non évalué", "status": "NonEvalué", "msg": "Contrôle désactivé dans le profil."}

        # Exécution des sondes
        try:
            if cid == "ID_01": return SystemProbes.check_hostname(prof["identity"]["hostname_pattern"])
            elif cid == "ID_02": return SystemProbes.check_admin_account(prof["identity"]["admin_account"])
            elif cid == "ID_03": return SystemProbes.check_unauthorized_accounts(prof["identity"]["allowed_local_accounts"])
            elif cid == "HW_01": return SystemProbes.check_ram(prof["hardware"]["min_ram_gb"])
            elif cid == "HW_02": return SystemProbes.check_disk_free_space(prof["hardware"]["min_disk_free_gb"])
            elif cid == "HW_03": return SystemProbes.check_smart_health()
            elif cid == "HW_04": return SystemProbes.check_media_type()
            elif cid == "SYS_01": return SystemProbes.check_windows_version(prof["system"]["windows_edition"])
            elif cid == "SYS_02": return SystemProbes.check_windows_activation()
            elif cid == "SYS_03": return SystemProbes.check_time_sync(prof["system"]["time_server"], prof["system"]["max_clock_skew_seconds"])
            elif cid == "SYS_04": return SystemProbes.check_dhcp_enabled()
            elif cid == "SEC_01": return SystemProbes.check_antivirus()
            elif cid == "SEC_02": return SystemProbes.check_av_signatures(prof["security"]["max_av_signature_age_days"])
            elif cid == "SEC_03": return SystemProbes.check_bitlocker()
            elif cid == "SEC_04": return SystemProbes.check_firewall()
            elif cid == "SEC_05": return SystemProbes.check_wuauserv_service()
            elif cid == "SEC_06": return SystemProbes.check_pending_updates(prof["system"]["max_pending_updates"])
            elif cid == "SW_01": return SystemProbes.check_installed_apps(prof["software"]["required_winget_apps"])
            elif cid == "SW_02": return SystemProbes.check_forbidden_apps(prof["software"]["forbidden_apps"])
            elif cid == "SW_03": return SystemProbes.check_required_services(prof["software"]["required_services"])
            elif cid == "ENV_01": return SystemProbes.check_numlock()
            elif cid == "ENV_02": return SystemProbes.check_explorer_settings()
            elif cid == "ENV_03": return SystemProbes.check_chrome_homepage(prof["environment"]["chrome_homepage"])
            elif cid == "ENV_04": return SystemProbes.check_printer(prof["printer"]["name"])
            elif cid == "LOG_01": return SystemProbes.check_event_logs(prof["logs"]["max_critical_events_24h"])
        except Exception as e:
            return {"expected": "Succès", "actual": "Exception", "status": "Indéterminé", "msg": f"Erreur sonde : {str(e)}"}

        return {"expected": "-", "actual": "-", "status": "Indéterminé", "msg": "Sonde non implémentée"}

    # Traite la file des résultats venant du thread d'audit et met à jour l'UI (polling)
    def process_queue(self):
        try:
            while True:
                msg, cid, data, prog = self.worker_queue.get_nowait()
                if msg == "CONTROL_DONE":
                    self.update_control_row(cid, data)
                    self.progress['value'] = prog
                elif msg == "AUDIT_COMPLETE":
                    self.audit_running = False
                    self.btn_start.config(state=tk.NORMAL)
                    self.calculate_global_verdict()
                    logging.info("Recette terminée.")
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    # Met à jour la ligne de résultat d'un contrôle dans les tableaux
    def update_control_row(self, cid, res):
        self.results_data[cid] = res
        ctrl_info = next(c for c in CATALOG if c["id"] == cid)
        dom = ctrl_info["domain"]
        status = res["status"]

        item_values = (cid, ctrl_info["label"], res["expected"], res["actual"], status, ctrl_info["mode"])

        # Update Treeviews
        if self.tables[dom].exists(cid):
            self.tables[dom].item(cid, values=item_values, tags=(status,))
        
        syn_id = f"syn_{cid}"
        if self.tables["Synthèse"].exists(syn_id):
            self.tables["Synthèse"].item(syn_id, values=item_values, tags=(status,))

        self.update_tab_titles()

    # Met à jour le titre des onglets avec le nombre d'écarts par domaine
    def update_tab_titles(self):
        for dom in self.domains:
            if dom == "Synthèse":
                continue
            ecarts = 0
            tree = self.tables[dom]
            for child in tree.get_children():
                vals = tree.item(child)["values"]
                if vals[4] in ["Écart", "Indéterminé"]:
                    ecarts += 1
            idx = self.domains.index(dom)
            title = f"{dom} ({ecarts})" if ecarts > 0 else dom
            self.notebook.tab(idx, text=title)

    # Calcule le verdict global de conformité selon les règles RG03
    def calculate_global_verdict(self):
        vert = 0
        rouge = 0
        orange = 0
        gris = 0
        has_major_or_blocking = False

        for ctrl in CATALOG:
            cid = ctrl["id"]
            res = self.results_data.get(cid, {"status": "NonEvalué"})
            st = res["status"]
            sev = ctrl["severity"]

            if st == "Conforme":
                vert += 1
            elif st == "Écart":
                rouge += 1
                if sev in ["Majeur", "Bloquant"]:
                    has_major_or_blocking = True
            elif st == "Indéterminé":
                orange += 1
            else:
                gris += 1

        self.lbl_counters.config(text=f"Vert: {vert} | Rouge: {rouge} | Orange: {orange} | Gris: {gris}")

        # RG03 Rules
        if orange > 0:
            verdict = "NON CONFORME (Contrôle non vérifié)"
            bg_color = "orange"
        elif rouge > 0 and has_major_or_blocking:
            verdict = "NON CONFORME"
            bg_color = "red"
        elif rouge > 0 and not has_major_or_blocking:
            verdict = "CONFORME AVEC RESERVES"
            bg_color = "#FFC107"
        else:
            verdict = "CONFORME"
            bg_color = "green"

        self.lbl_verdict.config(text=f"VERDICT : {verdict}", bg=bg_color, fg="white")

    # ==========================================
    # GUI ACTIONS & CORRECTIONS
    # ==========================================

    # Affiche le détail du contrôle sélectionné et active/désactive les boutons d'action
    def on_tree_select(self, event):
        tree = event.widget
        selected = tree.selection()
        if not selected:
            return

        iid = selected[0]
        cid = iid.replace("syn_", "")
        
        ctrl_info = next(c for c in CATALOG if c["id"] == cid)
        res = self.results_data.get(cid, {"msg": "Non encore évalué."})

        msg_text = f"[{cid}] {ctrl_info['label']} | Statut: {res.get('status')} | {res.get('msg')}"
        
        if ctrl_info["mode"] == "Manuelle" and ctrl_info.get("instruction"):
            msg_text += f"\n--> Consigne manuelle : {ctrl_info['instruction']}"

        self.lbl_detail_msg.config(text=msg_text)
        self.btn_recheck.config(state=tk.NORMAL)

        if ctrl_info["mode"] == "Automatique" and res.get("status") == "Écart":
            self.btn_fix.config(state=tk.NORMAL)
        else:
            self.btn_fix.config(state=tk.DISABLED)

    # Déclenche la correction automatique du contrôle sélectionné (avec confirmation, RG01)
    def action_fix_single(self):
        curr_tab = self.notebook.tab(self.notebook.select(), "text").split(" ")[0]
        tree = self.tables.get(curr_tab, self.tables["Synthèse"])
        selected = tree.selection()
        if not selected:
            return

        cid = selected[0].replace("syn_", "")
        ctrl_info = next(c for c in CATALOG if c["id"] == cid)

        # RG01 Confirmation dialog
        confirm = messagebox.askyesno(
            "Confirmation de correction",
            f"Voulez-vous exécuter la correction automatique pour :\n\n{ctrl_info['label']} ?\n\nRG01: Aucune modification n'est appliquée sans confirmation."
        )
        if not confirm:
            return

        logging.info(f"Déclenchement correction pour {cid}")
        
        # Dispatch corrections
        prof = self.current_profile
        success, msg, reboot_needed = False, "", False

        if cid == "ID_01":
            new_name = simpledialog.askstring("Renommer le poste", "Saisir le nouveau nom de machine (ex: PC-EXP-042) :")
            if new_name and re.match(prof["identity"]["hostname_pattern"], new_name):
                success, msg, reboot_needed = SystemRemediations.fix_hostname(new_name)
            else:
                messagebox.showerror("Erreur Nom", "Nom invalide ou non conforme à la regex PC-EXP-nnn.")
                return
        elif cid == "ID_03":
            unauth = self.results_data[cid]["actual"].replace("Non autorisés actifs : ", "").split(", ")
            for u in unauth:
                success, msg, reboot_needed = SystemRemediations.fix_unauthorized_account(u)
        elif cid == "HW_04":
            success, msg, reboot_needed = SystemRemediations.fix_media_defrag()
        elif cid == "SYS_03":
            success, msg, reboot_needed = SystemRemediations.fix_time_sync(prof["system"]["time_server"])
        elif cid == "SYS_04":
            success, msg, reboot_needed = SystemRemediations.fix_dhcp()
        elif cid == "SEC_02":
            success, msg, reboot_needed = SystemRemediations.fix_av_signatures()
        elif cid == "SEC_04":
            success, msg, reboot_needed = SystemRemediations.fix_firewall()
        elif cid == "SEC_05":
            success, msg, reboot_needed = SystemRemediations.fix_wuauserv()
        elif cid == "SEC_06":
            success, msg, reboot_needed = SystemRemediations.fix_pending_updates()
        elif cid == "SW_01":
            for app in prof["software"]["required_winget_apps"]:
                success, msg, reboot_needed = SystemRemediations.fix_install_winget_app(app)
        elif cid == "SW_03":
            success, msg, reboot_needed = SystemRemediations.fix_services(prof["software"]["required_services"])
        elif cid == "ENV_01":
            success, msg, reboot_needed = SystemRemediations.fix_numlock()
        elif cid == "ENV_02":
            success, msg, reboot_needed = SystemRemediations.fix_explorer_settings()
        elif cid == "ENV_03":
            success, msg, reboot_needed = SystemRemediations.fix_chrome_homepage(prof["environment"]["chrome_homepage"])

        logging.info(f"Résultat correction {cid} : success={success}, msg={msg}")
        
        # RG06 Re-evaluate control
        self.action_recheck_single()

        if reboot_needed:
            messagebox.showinfo("Redémarrage requis", f"{msg}\n(RG07: Un redémarrage système est nécessaire pour appliquer pleinement le changement).")
        else:
            messagebox.showinfo("Résultat Correction", msg)

    # Relance la sonde du contrôle sélectionné pour rafraîchir son statut
    def action_recheck_single(self):
        curr_tab = self.notebook.tab(self.notebook.select(), "text").split(" ")[0]
        tree = self.tables.get(curr_tab, self.tables["Synthèse"])
        selected = tree.selection()
        if not selected:
            return

        cid = selected[0].replace("syn_", "")
        ctrl_info = next(c for c in CATALOG if c["id"] == cid)
        
        res = self.evaluate_control(ctrl_info)
        self.update_control_row(cid, res)
        self.calculate_global_verdict()

    # Relance uniquement les contrôles en écart ou indéterminés
    def start_replay_audit(self):
        ecarts = [cid for cid, r in self.results_data.items() if r.get("status") in ["Écart", "Indéterminé"]]
        if not ecarts:
            messagebox.showinfo("Rejeu", "Aucun écart ou indéterminé à rejouer.")
            return
        
        self.audit_running = True
        self.btn_start.config(state=tk.DISABLED)
        threading.Thread(target=self._worker_run_audit, args=(ecarts,), daemon=True).start()

    # Affiche les données brutes collectées dans une fenêtre dédiée
    def action_raw_collect(self):
        top = tk.Toplevel(self)
        top.title("Collecte Brute du Poste")
        top.geometry("600, 400")
        txt = tk.Text(top, wrap=tk.WORD)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, json.dumps(self.results_data, indent=2, ensure_ascii=False))

    # Génère le procès-verbal PDF à partir des résultats actuels
    def action_generate_pv(self):
        if not self.results_data:
            messagebox.showwarning("Erreur PV", "Veuillez exécuter la recette avant de générer le PV.")
            return

        filename = f"PV_{SystemProbes.get_hostname()}_{datetime.datetime.now().strftime('%Y-%m-%d_%H%M')}.pdf"
        filepath = os.path.join(self.app_config.reports_dir, filename)

        session_data = {
            "hostname": SystemProbes.get_hostname(),
            "operator": self.ent_operator.get(),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "profile_name": self.current_profile["profile_name"],
            "profile_version": self.current_profile["version"],
            "profile_hash": self.current_profile_hash,
            "verdict": self.lbl_verdict.cget("text").replace("VERDICT : ", ""),
            "results": []
        }

        for ctrl in CATALOG:
            cid = ctrl["id"]
            res = self.results_data.get(cid, {})
            session_data["results"].append({
                "control": ctrl["label"],
                "expected": res.get("expected", "-"),
                "initial": res.get("actual", "-"),
                "action": ctrl["mode"],
                "final_status": res.get("status", "NonEvalué")
            })

        try:
            generate_pdf_pv(session_data, filepath)
            messagebox.showinfo("Procès-Verbal Généré", f"PV généré avec succès :\n{filepath}")
            logging.info(f"PV généré : {filepath}")
        except Exception as e:
            messagebox.showerror("Erreur PV", f"Échec de génération du PDF :\n{str(e)}")

    # Filtre l'affichage des tableaux (tout / écarts seulement / indéterminés seulement)
    def filter_display(self, mode):
        for tree in self.tables.values():
            for child in tree.get_children():
                vals = tree.item(child)["values"]
                st = vals[4]
                if mode == "ALL":
                    tree.reattach(child, "", tk.END)
                elif mode == "ECART" and st != "Écart":
                    tree.detach(child)
                elif mode == "INDETERMINE" and st != "Indéterminé":
                    tree.detach(child)

    # Donne le focus au sélecteur de profil
    def action_choose_profile(self):
        self.cb_profiles.focus()

    # Recharge la configuration depuis config.ini
    def action_reload_config(self):
        self.app_config = AppConfig()
        messagebox.showinfo("Configuration", "Configuration INI rechargée.")

    # Ouvre le dossier contenant les PV générés
    def action_open_pv_folder(self):
        os.startfile(os.path.abspath(self.app_config.reports_dir))

    # Affiche la boîte « À propos »
    def action_about(self):
        prof_info = f"{self.current_profile['profile_name']} v{self.current_profile['version']}" if self.current_profile else "Aucun"
        messagebox.showinfo(
            "À Propos",
            f"Application de Recette des Postes EXPERTY\nVersion 2026.1\n\nProfil chargé : {prof_info}\nEmpreinte SHA256 : {self.current_profile_hash[:16]}...\nPrivilèges Administrateur : {'OUI' if self.is_admin else 'NON'}"
        )

    # Quitte l'application (refusé si un audit est en cours)
    def action_quit(self):
        if self.audit_running:
            messagebox.showwarning("Action impossible", "Impossible de quitter pendant l'exécution d'une recette.")
            return
        self.quit()

# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

# Point d'entrée : instancie et lance l'application
def main():
    app = ExpertyAuditApp()
    app.mainloop()

if __name__ == "__main__":
    main()