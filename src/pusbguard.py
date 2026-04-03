# Copyright (c) 2026 Nikolay Chotrov
# Licensed under the MIT License.
# See LICENSE file in the project root for full license information.

import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, scrolledtext, filedialog
import subprocess, os, sys, winreg, pystray, hashlib, ctypes, threading, time
from PIL import Image, ImageDraw, ImageTk
import keyring, requests, hashlib, secrets
import winsound, datetime, re


# --- CONSTANTS ---
APP_NAME = "PUSBGuard_V1.0"
ROOT_DIR = r"C:\PUSBGuard"
WHITELIST_FILE = os.path.join(ROOT_DIR, "whitelist.txt")
LOG_FILE = os.path.join(ROOT_DIR, "blocked_attempts.log")
PS_SCRIPT_FILE = os.path.join(ROOT_DIR, "PUSBEnforcer.ps1")
TASK_NAME = "PUSBGuard_Enforcer"
GUI_TASK_NAME = "PUSBGuard_GUI"
REG_PATH = r"SOFTWARE\PUSBGuard"
FLAG_NAME, HID_FLAG, WIFI_FLAG = "Armed", "BlockHID", "BlockWiFi"
TRAY_FLAG = "StartToTray"
CREATE_NO_WINDOW = 0x08000000 

APP_MUTEX_NAME = "Global\\PUSBGuard_V1_SingleInstance_Mutex"
ERROR_ALREADY_EXISTS = 183

NTFY_ENABLED, NTFY_URL = "NtfyEnabled", "NtfyUrl"
TG_ENABLED = "TgEnabled"
PO_ENABLED = "PoEnabled"


def is_already_running():
    import ctypes
    kernel32 = ctypes.windll.kernel32
    mutex = kernel32.CreateMutexW(None, False, APP_MUTEX_NAME)
    if kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        print("!!! [MUTEX ALERT] Another instance is already running. Exiting.")
        return True
    return False

class PUSBGuardApp:
    def __init__(self, root):
        self.root = root
        
        
        self.root.geometry("800x900")
        self.root.title(f"{APP_NAME} - Secure Port Guard")
        self.root.geometry("900x1000")
        self.root.protocol('WM_DELETE_WINDOW', self.hide_window)
        
        if not os.path.exists(ROOT_DIR): os.makedirs(ROOT_DIR, exist_ok=True)
        for f in [WHITELIST_FILE, LOG_FILE]: 
            if not os.path.exists(f): open(f, "a", encoding="utf-8-sig").close()
        
        try:
            self.secure_root_folder()
        except Exception as e:
            print(f"Security Shield failed to engage: {e}")

        self.last_auth_time = 0
        self.notified_devices = {}  # Tracks { "Device Name": last_notify_time }
        self.pc_name = os.environ.get('COMPUTERNAME', 'Unknown-PC')
        self.user_name = os.environ.get('USERNAME', 'Unknown-User')
        
        self.ensure_registry_initialized()
        self.enable_pnp_auditing()
        self.autoscan_baseline() 
        self.setup_ui()
        self.setup_tasks()
        
        self.tray = None
        self.start_tray()
        
        threading.Thread(target=self.log_monitor, daemon=True).start()
        self.update_status_ui()
        self.refresh_all()
        
        # Initial check for Start to Tray
        if self.get_reg(TRAY_FLAG) == 1 or "--tray" in sys.argv:
            self.root.withdraw()
            
        
        
            
    def secure_set_reg(self, flag, var):
        """Verifies password and returns True if the registry was updated."""
        # 1. Get current value from registry as a backup
        old_val = self.get_reg(flag)

        # 2. Verify password before allowing the change
        if self.verify_password():
            # RETURN the result of set_reg (True/False)
            return self.set_reg(flag, var.get())
        else:
            # 3. If password fails, revert the UI to the actual registry value
            # This works for both Checkboxes (Booleans) and Entry fields (Ints)
            var.set(old_val)
            return False
        
    def is_enforcer_healthy(self):
        """Checks if the Task Scheduler enforcer exists and is enabled."""
        try:
            cmd = f'Get-ScheduledTask -TaskName "{TASK_NAME}" | Select-Object -ExpandProperty State'
            result = subprocess.run(
                ["powershell", "-Command", cmd], 
                capture_output=True, text=True, creationflags=CREATE_NO_WINDOW
            )
            # Returns True if task is 'Ready' or 'Running'
            return result.returncode == 0 and "Disabled" not in result.stdout
        except:
            return False
            
    def save_logs_to_file(self):
        # Retrieve all text from the log ScrolledText widget
        log_content = self.log_area.get("1.0", tk.END).strip()
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        default_name = f"pusbguard_log_{date_str}.txt"
    
        if not log_content:
            messagebox.showwarning("Empty Logs", "There are no logs to save.")
            return

        # Open a "Save As" dialog
        file_path = filedialog.asksaveasfilename(
                initialfile=default_name,
                defaultextension=".txt",
                filetypes=[],
                title="Save Audit Logs"
                )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(log_content)
                messagebox.showinfo("Success", f"Logs saved successfully to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")
            
    def secure_root_folder(self):
        folder = ROOT_DIR
    
        # 1. Hide the folder immediately
        subprocess.run(["attrib", "+h", "+s", folder], capture_output=True, creationflags=CREATE_NO_WINDOW)

        # 2. Use SIDs instead of names to avoid language errors
        # *S-1-5-32-544 = Administrators
        # *S-1-5-18 = SYSTEM
        cmd = [
            "icacls", folder, 
            "/inheritance:r", 
            "/grant:r", "*S-1-5-32-544:(OI)(CI)F", 
            "/grant:r", "*S-1-5-18:(OI)(CI)F"
            ]
    
        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
    
        # Debug: If it still fails, this will tell  why in the console
        if result.returncode != 0:
            print(f"Lockdown Error: {result.stderr}")

    def ensure_registry_initialized(self):
        # 1. Initialize Registry Keys
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, 
                               winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY) as k:
            for flag, default in [(FLAG_NAME, 0), (HID_FLAG, 0), (WIFI_FLAG, 0), (TRAY_FLAG, 0), (NTFY_ENABLED, 0), (TG_ENABLED, 0), (PO_ENABLED, 0),
                                  ("MaxTries", 5),
                                  ("LockoutMins", 15),
                                  ("FailCount", 0),
                                  ("LockoutUntil", 0)
                                  ]:
                try: 
                    winreg.QueryValueEx(k, flag)
                except: 
                    winreg.SetValueEx(k, flag, 0, winreg.REG_DWORD, default)
            strings = [
            (NTFY_URL, "https://ntfy.sh"),
                ]
            for name, default in strings:
                try:
                    winreg.QueryValueEx(k, name)
                except:
                    winreg.SetValueEx(k, name, 0, winreg.REG_SZ, default)

        # 2. "Negotiate" with Windows Defender (Exclusions)
        def_dir_cmd = f'Add-MpPreference -ExclusionPath "{ROOT_DIR}" -ErrorAction SilentlyContinue'
        def_proc_cmd = f'Add-MpPreference -ExclusionProcess "{os.path.basename(sys.executable)}" -ErrorAction SilentlyContinue'
        
        subprocess.run(["powershell", "-Command", def_dir_cmd], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["powershell", "-Command", def_proc_cmd], capture_output=True, creationflags=CREATE_NO_WINDOW)

        # 3. Enable Driver Framework Logging
        subprocess.run("wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true", 
                       shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
        
    def _hash_value(self, value, salt=None):
        """Centralized PBKDF2 hashing for consistency."""
        iterations = 100000
        if salt is None:
            salt = os.urandom(16)
        else:
            salt = bytes.fromhex(salt)
    
        # Normalize input: trim and uppercase for recovery codes
        clean_val = value.strip().upper() if "-" in value or len(value) < 15 else value.strip()
    
        pw_hash = hashlib.pbkdf2_hmac('sha256', clean_val.encode(), salt, iterations)
        return f"{salt.hex()}:{pw_hash.hex()}"
    
    def save_security_settings(self):
        """
        Saves the lockout thresholds from the UI to the Registry.
        Uses secure_set_reg to ensure password verification.
        """
        try:
            
            # 1. Update Max Attempts
            success_max = self.secure_set_reg("MaxTries", self.max_tries_var)
        
            # 2. Update Lockout Duration
            if success_max:
                self.secure_set_reg("LockoutMins", self.lockout_mins_var)
                messagebox.showinfo("Saved", "Security thresholds updated successfully.")
            
        except Exception as e:
            messagebox.showerror("Registry Error", f"Could not update settings: {e}")
    
    def trim_logs(self, max_lines=1000):
        """Trims the log file to keep it light (approx 100KB - 200KB)."""
        if not os.path.exists(LOG_FILE): return
    
        try:
            # Read the clean lines (stripping the BOM if it exists)
            with open(LOG_FILE, "r", encoding="utf-8-sig", errors="ignore") as f:
                lines = f.readlines()

            # Only rewrite if we actually exceed the limit
            if len(lines) > max_lines:
                # Keep the most recent 1,000 lines
                with open(LOG_FILE, "w", encoding="utf-8-sig") as f:
                    f.writelines(lines[-max_lines:])
        except Exception as e:
            # Silently fail if the file is locked by the Enforcer; we'll try again in 20s
            pass


    def enable_pnp_auditing(self):
        subprocess.run('auditpol /set /subcategory:"Plug and Play Events" /success:enable', shell=True, capture_output=True, creationflags=CREATE_NO_WINDOW)
        
    def generate_recovery_logic(self, force_new=False):
        """
        Generates a new recovery code, copies it to clipboard, 
        and saves the hash to the Windows Keyring.
        """
        # 1. Identity Check: Skip if this is a first-time setup 
        if not force_new:
            if not self.verify_password():
                return
    
        # 2. Generate a secure random code (e.g., ABCD-1234-EFGH)
        raw_code = "-".join([secrets.token_hex(2).upper() for _ in range(3)])

        # 3. Automatically copy to clipboard for convenience
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(raw_code)
        except:
            pass # Fallback if clipboard is busy

        # 4. Show to User 
        simpledialog.askstring(
            "RECOVERY CODE GENERATED", 
            "The code has been COPIED to your clipboard.\n"
            "Paste it (Ctrl+V) somewhere safe or write it down:", 
            initialvalue=raw_code, 
            parent=self.root
        )

        # 5. Hash it before saving (Never store the raw code!)
        salt = os.urandom(16)
        iterations = 100000
        combined = self._hash_value(raw_code) 

        # 6. Save to Keyring
        keyring.set_password(APP_NAME, "recovery_hash", combined)
    
        if not force_new:
            messagebox.showinfo("Success", "New recovery code has been secured.")
    
    def test_recovery_code(self):
        """Verifies if a typed code matches the stored recovery hash."""
        stored_recovery = keyring.get_password(APP_NAME, "recovery_hash")
        if not stored_recovery:
            messagebox.showerror("Error", "No recovery code found. Generate one first!")
            return

        inp = simpledialog.askstring("TEST RECOVERY", "Enter your Recovery Code to test:")
        if not inp: return

        try:
            # 1. Split the stored string into salt and hash
            rs_hex, rh_hex = stored_recovery.split(":")
        
            # 2. Use your internal helper to hash the input using the stored salt
            calculated_combined = self._hash_value(inp, rs_hex)
        
            # 3. Extract just the hash part from the helper's result
            calculated_hash = calculated_combined.split(":")[1]

            # 4. Compare
            if calculated_hash == rh_hex:
                messagebox.showinfo("Success", "Code is VALID! Your recovery system is working.")
            else:
                messagebox.showerror("Failed", "Invalid Code. The hash does not match.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Validation Error: {e}")


    def verify_password(self):
        # 1. Immediate Session Check (Don't pause monitor if already logged in)
        if time.time() - getattr(self, 'last_auth_time', 0) < 300:
            return True

        # 2. Start the Pause
        self.is_authenticating = True
    
        try: 
            # --- LOCKOUT PRE-CHECK ---
            lock_until = self.get_reg("LockoutUntil", default=0)
            if time.time() < lock_until:
                mins_left = int((lock_until - time.time()) / 60)
                messagebox.showerror("Security Lockout", f"Too many attempts. Try in {max(1, mins_left)}m.")
                return False

            stored_data = keyring.get_password(APP_NAME, "admin_hash")
            stored_recovery = keyring.get_password(APP_NAME, "recovery_hash")

            # --- FIRST TIME SETUP ---
            if not stored_data:
                p = simpledialog.askstring("PUSBGuard", "Set Admin Password:", show='*', parent=self.root)
                if p:
                    keyring.set_password(APP_NAME, "admin_hash", self._hash_value(p))
                    self.generate_recovery_logic(force_new=True)
                    self.last_auth_time = time.time()
                    return True
                return False

            # --- NORMAL PROMPT ---
            inp = simpledialog.askstring("Security", "Enter Password or Recovery Code:", show='*', parent=self.root)
            if not inp: return False

            # --- VALIDATION LOGIC ---
            success = False
            s_hex, h_hex = stored_data.split(":")
            if self._hash_value(inp, s_hex).split(":")[1] == h_hex:
                success = True

            if not success and stored_recovery:
                rs_hex, rh_hex = stored_recovery.split(":")
                if self._hash_value(inp, rs_hex).split(":")[1] == rh_hex:
                    success = True
                    messagebox.showinfo("Bypass", "Recovery Code Accepted.")

            if success:
                self.set_reg("FailCount", 0)
                self.last_auth_time = time.time()
                return True
            else:
                fails = self.get_reg("FailCount", default=0) + 1
                max_allowed = int(self.get_reg("MaxTries", default=5)) 
                if fails >= max_allowed:
                    duration = int(self.get_reg("LockoutMins", default=15)) * 60
                    self.set_reg("LockoutUntil", int(time.time() + duration))
                    self.set_reg("FailCount", 0)
                    messagebox.showerror("CRITICAL", "Maximum attempts reached. Locked.")
                else:
                    self.set_reg("FailCount", fails)
                    messagebox.showwarning("Access Denied", f"Invalid Credentials. {fails}/{max_allowed}")
                return False

        finally:
            # 3. END THE PAUSE (This runs no matter which 'return' was hit above)
            self.is_authenticating = False

    
    def auth_and_restore(self):
        self.root.after(0, lambda: self.root.deiconify() or self.root.lift() or self.root.focus_force() if self.verify_password() else None)

    def setup_ui(self):
        self.ntfy_on = tk.BooleanVar(value=bool(self.get_reg(NTFY_ENABLED)))
        self.tg_on = tk.BooleanVar(value=bool(self.get_reg(TG_ENABLED)))
        self.po_on = tk.BooleanVar(value=bool(self.get_reg(PO_ENABLED)))
        
        
        style = ttk.Style()
        # 'clam' is the most customizable built-in theme for styling tabs
        style.theme_use('clam') 

        # 1. Style the Notebook (The container)
        style.configure("TNotebook", background="#f0f0f0", borderwidth=0)

        # 2. Style the Tabs (The buttons)
        style.configure("TNotebook.Tab",
                    padding=[15, 5],      # [horizontal, vertical] padding
                    background="#d9d9d9", # Unselected tab color
                    foreground="#333333", # Text color
                    font=("Segoe UI", 10), 
                    borderwidth=0)        # Removes the "button" border

        # 3. Style the Selected Tab (Highlighting)
        style.map("TNotebook.Tab",
              background=[("selected", "#ffffff")], # White background when active
              focuscolor=[("selected", "#ffffff")]) # Removes the dotted focus line

        
        
        self.nb = ttk.Notebook(self.root)
        
        self.nb = ttk.Notebook(self.root); self.nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.t1 = tk.Frame(self.nb); self.nb.add(self.t1, text="🛡️ Dashboard")
        self.status_lbl = tk.Label(self.t1, text="", font=("Arial", 16, "bold")); self.status_lbl.pack(pady=10)
        
        f_top = tk.Frame(self.t1); f_top.pack(pady=5)
        tk.Button(f_top, text="Toggle Guard", command=self.toggle_guard, width=18, height=2, bg="#e8f5e9").pack(side=tk.LEFT, padx=5)
        tk.Button(f_top, text="Emergency Unblock", command=self.emergency_unblock, width=18, height=2, fg="white", bg="#d32f2f").pack(side=tk.LEFT, padx=5)
        
        f_adv = tk.LabelFrame(self.t1, text="Advanced Blocking Options", padx=10, pady=10)
        f_adv.pack(fill=tk.X, padx=15, pady=10)
        
        self.hid_var = tk.BooleanVar(value=bool(self.get_reg(HID_FLAG)))
        tk.Checkbutton(f_adv, text="Block HID (Keyboard/Mouse/Ducky)", variable=self.hid_var, command=lambda: self.secure_set_reg(HID_FLAG, self.hid_var)).pack(anchor="w")
        
        self.wifi_var = tk.BooleanVar(value=bool(self.get_reg(WIFI_FLAG)))
        tk.Checkbutton(f_adv, text="Block WiFi & Bluetooth Dongles", variable=self.wifi_var, command=lambda: self.secure_set_reg(WIFI_FLAG, self.wifi_var)).pack(anchor="w")

        # ADDED: Start to Tray Checkbox
        self.tray_var = tk.BooleanVar(value=bool(self.get_reg(TRAY_FLAG)))
        tk.Checkbutton(f_adv, text="Start Application Minimized to Tray", variable=self.tray_var, command=lambda: self.secure_set_reg(TRAY_FLAG, self.tray_var)).pack(anchor="w")
        
        tk.Label(self.t1, text="Detected USB Devices:", font=("Arial", 10, "bold")).pack(anchor="w", padx=15)
        f_tree = tk.Frame(self.t1); f_tree.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
        self.tree = ttk.Treeview(f_tree, columns=("Name", "ID"), show='headings', height=8)
        self.tree.heading("Name", text="Device Name"); self.tree.heading("ID", text="Hardware ID")
        self.tree.column("Name", width=250, stretch=tk.NO); self.tree.column("ID", width=650, stretch=tk.NO)
        
        tree_scrolly = ttk.Scrollbar(f_tree, orient="vertical", command=self.tree.yview)
        tree_scrollx = ttk.Scrollbar(f_tree, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scrolly.set, xscrollcommand=tree_scrollx.set)
        self.tree.grid(row=0, column=0, sticky='nsew'); tree_scrolly.grid(row=0, column=1, sticky='ns'); tree_scrollx.grid(row=1, column=0, sticky='ew')
        f_tree.grid_columnconfigure(0, weight=1); f_tree.grid_rowconfigure(0, weight=1)
        tree_scrolly.config(command=self.tree.yview)
        tree_scrollx.config(command=self.tree.xview)

        f_tree_btns = tk.Frame(self.t1); f_tree_btns.pack(fill=tk.X, padx=15)
        tk.Button(f_tree_btns, text="Whitelist & Enable Selection", command=self.add_to_white, bg="#bbdefb", height=1).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)
        tk.Button(f_tree_btns, text="Copy ID", command=self.copy_id_from_tree, bg="#f5f5f5", height=1).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=2)

        tk.Label(self.t1, text="Authorized Whitelist:", font=("Arial", 10, "bold")).pack(anchor="w", padx=15, pady=(10,0))
        f_white = tk.Frame(self.t1); f_white.pack(fill=tk.X, padx=15, pady=5)
        self.lb_white = tk.Listbox(f_white, height=5)
        white_scrolly = ttk.Scrollbar(f_white, orient="vertical", command=self.lb_white.yview)
        white_scrollx = ttk.Scrollbar(f_white, orient="horizontal", command=self.lb_white.xview)
        self.lb_white.configure(yscrollcommand=white_scrolly.set, xscrollcommand=white_scrollx.set, bg="lightgreen")
        white_scrolly.config(command=self.lb_white.yview)
        self.lb_white.grid(row=0, column=0, sticky='nsew')
        white_scrolly.grid(row=0, column=1, sticky='ns')
        white_scrollx.grid(row=1, column=0, sticky='ew')
        f_white.grid_columnconfigure(0, weight=1)
             
        f_bot = tk.Frame(self.t1); f_bot.pack(pady=5)
        tk.Button(f_bot, text="Remove Selected", command=self.remove_from_white, fg="red", width=15).pack(side=tk.LEFT, padx=5)
        tk.Button(f_bot, text="Refresh List", command=self.refresh_all, width=15).pack(side=tk.LEFT, padx=5)

        self.t2 = tk.Frame(self.nb); self.nb.add(self.t2, text=" 📜 Security Audit ")
        self.log_area = scrolledtext.ScrolledText(
          self.t2, 
          state='disabled', 
          bg="#1e1e1e", 
          fg="#00ff00", 
          font=("Consolas", 10),
          spacing1=2,
          spacing3=2,
          padx=10,
          pady=10
        )
        
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        f_log_btns = tk.Frame(self.t2)
        f_log_btns.pack(pady=5)
        
        # Pack "Clear Logs"
        tk.Button(f_log_btns, text="Clear Logs", 
          command=self.clear_logs, width=15).pack(side=tk.LEFT, padx=5)

        # Pack "Save Logs" 
        tk.Button(f_log_btns, text="Save Logs to File", 
          command=self.save_logs_to_file, bg="#0e79d1", fg="white", 
          width=15).pack(side=tk.LEFT, padx=5)
        
        tk.Button(f_log_btns, text="Manual Refresh", 
          command=self.refresh_logs, bg="#4caf50", fg="white", 
          width=15).pack(side=tk.LEFT, padx=5)
        
        
        # --- Tab 3: Notifications ---
        self.t3 = tk.Frame(self.nb)
        self.nb.add(self.t3, text="🔔 Notifications")

        # 1. ntfy Section
        f1 = tk.LabelFrame(self.t3, text="ntfy.sh / Custom Server", padx=10, pady=10)
        f1.pack(fill="x", padx=10, pady=5)

        tk.Checkbutton(f1, text="Enable ntfy", variable=self.ntfy_on).grid(row=0, column=0, columnspan=2, sticky="w")
        # --- STATUS LABEL 1 ---
        self.ntfy_status = tk.Label(f1, text="", font=("Arial", 9, "bold"))
        self.ntfy_status.grid(row=0, column=1, sticky="w", padx=10)

        tk.Label(f1, text="Server URL:").grid(row=1, column=0, sticky="e", pady=2)
        self.ent_ntfy_url = tk.Entry(f1, width=45)
        self.ent_ntfy_url.grid(row=1, column=1, padx=5)
        self.ent_ntfy_url.insert(0, self.get_reg(NTFY_URL))

        tk.Label(f1, text="Topic Name:").grid(row=2, column=0, sticky="e", pady=2)
        self.ent_ntfy_topic = tk.Entry(f1, width=45, show="*")
        self.ent_ntfy_topic.grid(row=2, column=1, padx=5)
        self.ent_ntfy_topic.insert(0, keyring.get_password(APP_NAME, "ntfy_topic") or "")
        # Add Toggle Button
        tk.Button(f1, text="👁", width=3, command=lambda: self.toggle_visibility(self.ent_ntfy_topic)).grid(row=2, column=2)

        tk.Label(f1, text="Access Token:").grid(row=3, column=0, sticky="e", pady=2)
        self.ent_ntfy_token = tk.Entry(f1, width=45, show="*")
        self.ent_ntfy_token.grid(row=3, column=1, padx=5)
        # Add Toggle Button
        tk.Button(f1, text="👁", width=3, command=lambda: self.toggle_visibility(self.ent_ntfy_token)).grid(row=3, column=2)

        # 2. Telegram Section
        f2 = tk.LabelFrame(self.t3, text="Telegram", padx=10, pady=10)
        f2.pack(fill="x", padx=10, pady=5)

        tk.Checkbutton(f2, text="Enable Telegram", variable=self.tg_on).grid(row=0, column=0, columnspan=2, sticky="w")
        # --- STATUS LABEL 2 ---
        self.tg_status = tk.Label(f2, text="", font=("Arial", 9, "bold"))
        self.tg_status.grid(row=0, column=1, sticky="w", padx=(100, 10))

        tk.Label(f2, text="Chat ID:").grid(row=1, column=0, sticky="e", pady=2)
        self.ent_tg_chat_id = tk.Entry(f2, width=45, show="*")
        self.ent_tg_chat_id.grid(row=1, column=1, padx=5)
        self.ent_tg_chat_id.insert(0, keyring.get_password(APP_NAME, "tg_chat_id") or "")
        tk.Button(f2, text="👁", width=3, 
          command=lambda: self.toggle_visibility(self.ent_tg_chat_id)).grid(row=1, column=2)

        tk.Label(f2, text="Bot Token:").grid(row=2, column=0, sticky="e", pady=2)
        self.ent_tg_token = tk.Entry(f2, width=45, show="*")
        self.ent_tg_token.grid(row=2, column=1, padx=5)
        tk.Button(f2, text="👁", width=3, 
          command=lambda: self.toggle_visibility(self.ent_tg_token)).grid(row=2, column=2)

        # 3. Pushover Section
        f3 = tk.LabelFrame(self.t3, text="Pushover", padx=10, pady=10)
        f3.pack(fill="x", padx=10, pady=5)

        tk.Checkbutton(f3, text="Enable Pushover", variable=self.po_on).grid(row=0, column=0, columnspan=2, sticky="w")
        # --- STATUS LABEL 3 ---
        self.po_status = tk.Label(f3, text="", font=("Arial", 9, "bold"))
        self.po_status.grid(row=0, column=1, sticky="w", padx=(100, 10))

        tk.Label(f3, text="User Key:").grid(row=1, column=0, sticky="e", pady=2)
        self.ent_po_user_key = tk.Entry(f3, width=45, show="*")
        self.ent_po_user_key.grid(row=1, column=1, padx=5)
        self.ent_po_user_key.insert(0, keyring.get_password(APP_NAME, "po_user_key") or "")
        # Toggle Button for Pushover
        tk.Button(f3, text="👁", width=3, 
          command=lambda: self.toggle_visibility(self.ent_po_user_key)).grid(row=1, column=2)

        tk.Label(f3, text="App Token:").grid(row=2, column=0, sticky="e", pady=2)
        self.ent_po_app_token = tk.Entry(f3, width=45, show="*")
        self.ent_po_app_token.grid(row=2, column=1, padx=5)
        # Toggle Button for Pushover
        tk.Button(f3, text="👁", width=3, 
          command=lambda: self.toggle_visibility(self.ent_po_app_token)).grid(row=2, column=2)

        # Control Buttons
        tk.Button(self.t3, text="Save All Notification Settings", 
          command=self.save_notif_settings, bg="#e3f2fd", height=2).pack(pady=10)
        tk.Button(self.t3, text="🚀 Send Universal Test Alert", 
          command=lambda: self.send_notifications("System Test: All enabled services working!")).pack()
        
        # --- Tab 4: Settings ---
        self.t4 = tk.Frame(self.nb)
        self.nb.add(self.t4, text="⚙️ Settings")

        # Example: Adding a section for General Application Settings
        f_gen = tk.LabelFrame(self.t4, text="General Settings", padx=10, pady=10)
        f_gen.pack(fill="x", padx=10, pady=5)

        # Example Setting: A button to reset the Master Password
        tk.Button(f_gen, text="Reset Master Password", 
          command=self.reset_password_logic).pack(anchor="w", pady=5)
        
        # NEW: Recovery Code Button
        tk.Button(f_gen, text="Generate New Recovery Code", 
          command=self.generate_recovery_logic, 
          fg="#1565c0").pack(anchor="w", pady=5)
        
        tk.Button(f_gen, text="Test Existing Recovery Code", 
         command=self.test_recovery_code, 
         fg="#2e7d32").pack(anchor="w", pady=5)
        
        # Login Security
        f_lock = tk.LabelFrame(self.t4, text="Login Security", padx=10, pady=10)
        f_lock.pack(fill="x", padx=10, pady=5)

        # 1. Initialize variables using the CORRECT existing method: self.get_reg
        # These will automatically populate the Entry fields via 'textvariable'
        self.max_tries_var = tk.IntVar(value=int(self.get_reg("MaxTries", default=5)))
        self.lockout_mins_var = tk.IntVar(value=int(self.get_reg("LockoutMins", default=15)))
        self.fail_count_var = tk.IntVar(value=int(self.get_reg("FailCount", default=0)))

        # 2. Max Failed Attempts Row
        tk.Label(f_lock, text="Max Failed Attempts:").grid(row=0, column=0, sticky="w")
        self.ent_max_tries = tk.Entry(f_lock, textvariable=self.max_tries_var, width=10)
        self.ent_max_tries.grid(row=0, column=1, padx=5, pady=5)

        # 3. Lockout Duration Row
        tk.Label(f_lock, text="Lockout Duration (mins):").grid(row=1, column=0, sticky="w")
        self.ent_lock_time = tk.Entry(f_lock, textvariable=self.lockout_mins_var, width=10)
        self.ent_lock_time.grid(row=1, column=1, padx=5, pady=5)

        # 4. Save Button (Calls the fixed save method below)
        tk.Button(f_lock, text="Save Security Settings", 
          command=self.save_security_settings, 
          bg="#4caf50", fg="white", width=20).grid(row=2, column=0, columnspan=2, pady=10)
        
        tk.Button(self.t4, text="UNINSTALL PROGRAM", command=self.run_uninstaller, fg="white", bg="#333333", font=("Arial", 8)).pack(side=tk.BOTTOM, pady=10)



        self.root.update_idletasks()
        
    def toggle_visibility(self, entry_widget):
        """Toggles the masking of a specific entry field between '*' and plain text."""
        if entry_widget.cget('show') == '*':
            if self.verify_password():
                entry_widget.config(show='')
        else:
            entry_widget.config(show='*')
            
    def reset_password_logic(self):
        # First, verify the current password for security
        if not self.verify_password():
            return

        # Prompt for a new password
        new_p = simpledialog.askstring("Reset Password", "Set New Master Admin Password:", show='*', parent=self.root)
    
        if new_p:
            # Generate new salt and hash (matching the logic on Page 3 of your PDF)
            iterations = 100000
            salt = os.urandom(16)
            pw_hash = hashlib.pbkdf2_hmac('sha256', new_p.encode(), salt, iterations)
            combined = f"{salt.hex()}:{pw_hash.hex()}"
        
            # Save to Windows Credential Manager
            keyring.set_password(APP_NAME, "admin_hash", combined)
        
            # Reset the session timer so they have to 're-login' next time
            self.last_auth_time = 0 
            messagebox.showinfo("Success", "Master Password has been updated.")

                
    def send_notifications(self, message, title="PUSBGuard Alert"):
        """
        Sends alerts to all enabled services and provides 
        temporary UI feedback (5s) for each connection attempt.
        """
    
        # --- INTERNAL HELPER FOR TEMPORARY FEEDBACK ---
        def show_feedback(label, success, status_code=""):
            if success:
                label.config(text="✅ CONNECTED", fg="#2e7d32") # Dark Green
            else:
                # Show "CONN_ERR" for timeouts or specific HTTP codes (401, 404, etc)
                label.config(text=f"❌ FAILED ({status_code})", fg="#d32f2f") # Red
        
            # Schedule the label to clear itself after 5000ms (5 seconds)
            self.root.after(5000, lambda: label.config(text=""))

        # 1. ntfy.sh
        if self.get_reg(NTFY_ENABLED):
            url = self.get_reg(NTFY_URL, default="https://ntfy.sh").rstrip('/')
            topic = keyring.get_password(APP_NAME, "ntfy_topic")
        
            if topic:
                full_url = f"{url}/{topic}"
                token = keyring.get_password(APP_NAME, "ntfy_token")
                headers = {"Title": title, "Priority": "5", "Tags": "shield,warning"}
                if token and token.strip():
                    headers["Authorization"] = f"Bearer {token.strip()}"
            
                try: 
                    response = requests.post(full_url, data=message.encode('utf-8'), 
                                         headers=headers, timeout=5)
                    show_feedback(self.ntfy_status, response.status_code == 200, response.status_code)
                except Exception: 
                    show_feedback(self.ntfy_status, False, "CONN_ERR")
            else:
                show_feedback(self.ntfy_status, False, "NO_TOPIC")

        # 2. Telegram
        if self.get_reg(TG_ENABLED):
            token = keyring.get_password(APP_NAME, "tg_token")
            chat_id = keyring.get_password(APP_NAME, "tg_chat_id")
        
            if token and chat_id:
                tg_url = f"https://api.telegram.org/bot{token}/sendMessage"
                try:
                    r = requests.post(tg_url, json={"chat_id": chat_id, "text": f"{title}\n{message}"}, timeout=5)
                    show_feedback(self.tg_status, r.status_code == 200, r.status_code)
                except Exception:
                    show_feedback(self.tg_status, False, "CONN_ERR")
            else:
                show_feedback(self.tg_status, False, "MISSING_CRED")

        # 3. Pushover
        if self.get_reg(PO_ENABLED):
            token = keyring.get_password(APP_NAME, "po_app_token")
            user = keyring.get_password(APP_NAME, "po_user_key")
        
            if token and user:
                try: 
                    r = requests.post("https://api.pushover.net/1/messages.json", 
                                  data={"token": token, "user": user, "message": message, "title": title}, timeout=5)
                    show_feedback(self.po_status, r.status_code == 200, r.status_code)
                except Exception: 
                    show_feedback(self.po_status, False, "CONN_ERR")
            else:
                show_feedback(self.po_status, False, "MISSING_CRED")


    def save_notif_settings(self):
        if not self.verify_password(): return
        self.set_reg(NTFY_ENABLED, self.ntfy_on.get())
        self.set_reg_sz(NTFY_URL, self.ent_ntfy_url.get().strip())
        if self.ent_ntfy_token.get(): keyring.set_password(APP_NAME, "ntfy_token", self.ent_ntfy_token.get())
        if self.ent_ntfy_topic.get(): keyring.set_password(APP_NAME, "ntfy_topic", self.ent_ntfy_topic.get())
        
        self.set_reg(TG_ENABLED, self.tg_on.get())
        if self.ent_tg_token.get(): keyring.set_password(APP_NAME, "tg_token", self.ent_tg_token.get())
        if self.ent_tg_chat_id.get(): keyring.set_password(APP_NAME, "tg_chat_id", self.ent_tg_chat_id.get())

        self.set_reg(PO_ENABLED, self.po_on.get())
        if self.ent_po_app_token.get(): keyring.set_password(APP_NAME, "po_app_token", self.ent_po_app_token.get())
        if self.ent_po_user_key.get(): keyring.set_password(APP_NAME, "po_user_key", self.ent_po_user_key.get())
        
        messagebox.showinfo("Saved", "Notification settings updated.")
 
        
    def run_uninstaller(self):
        if not self.verify_password(): return
        if not messagebox.askyesno("Uninstall", "Completely remove PUSBGuard?"): return
        uninstaller_content = f'''@echo off
:: --- Admin Elevation ---
>nul 2>&1 "%SYSTEMROOT%\\system32\\cacls.exe" "%SYSTEMROOT%\\system32\\config\\system"
if '%errorlevel%' NEQ '0' ( goto UACPrompt ) else ( goto gotAdmin )
:UACPrompt
 echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\\getadmin.vbs"
 echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\\getadmin.vbs"
 "%temp%\\getadmin.vbs" & exit /B
:gotAdmin
 if exist "%temp%\\getadmin.vbs" ( del "%temp%\\getadmin.vbs" )

echo [1/8] Stopping PUSBGuard Processes...
taskkill /F /T /IM "%~nx0" >nul 2>&1
taskkill /F /T /IM {os.path.basename(sys.executable)} >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/8] Re-enabling all USB Devices...
powershell -Command "Get-PnpDevice | Where-Object {{ $_.InstanceId -match 'USB' }} | Enable-PnpDevice -Confirm:$false" >nul 2>&1

echo [3/8] Removing Scheduled Tasks (Event ID Triggers)...
schtasks /delete /tn "{TASK_NAME}" /f >nul 2>&1
schtasks /delete /tn "{GUI_TASK_NAME}" /f >nul 2>&1

echo [4/8] Removing Windows Defender Exclusions...
powershell -Command "Remove-MpPreference -ExclusionPath '{ROOT_DIR}'" >nul 2>&1
powershell -Command "Remove-MpPreference -ExclusionProcess '{os.path.basename(sys.executable)}'" >nul 2>&1

echo [5/8] Disabling Logging Modules and Audit Policies...
:: Disables the PnP Security Audit (Event 6416)
auditpol /set /subcategory:"Plug and Play Events" /success:disable >nul 2>&1
:: Disables the DriverFrameworks Operational Log (Events 10000, 2003, 2101)
wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:false >nul 2>&1

echo [6/8] Cleaning Registry Configuration...
reg delete "HKLM\\{REG_PATH}" /f >nul 2>&1

echo [7/8] Deleting Application Files...
if exist "{ROOT_DIR}" ( rd /s /q "{ROOT_DIR}" )

echo [8/8] Delete the Credential Manager entry
cmdkey /delete:{APP_NAME} >nul 2>&1
:: This loop finds any credential containing your APP_NAME and deletes it
for /F "tokens=1,2 delims= " %%G in ('cmdkey /list ^| findstr "@PUSBGuard_V1.0"') do (
    echo Deleting %%H...
    cmdkey /delete:%%H >nul 2>&1
)

echo.
echo PUSBGuard has been completely removed from your system.
pause & exit
'''
        path = os.path.join(os.environ['TEMP'], "PUSBGuard_Remover.bat")
        with open(path, "w") as f: f.write(uninstaller_content)
        os.startfile(path); self.quit_app()

    def copy_id_from_tree(self):
        sel = self.tree.selection()
        if sel:
            hw_id = str(self.tree.item(sel)['values'][1]).strip()
            self.root.clipboard_clear(); self.root.clipboard_append(hw_id)
            messagebox.showinfo("Copied", f"ID Copied to Clipboard:\n{hw_id}")
  
    def autoscan_baseline(self):
       # Only scan if the whitelist is currently empty (initial setup)
        if os.path.exists(WHITELIST_FILE) and os.path.getsize(WHITELIST_FILE) > 0:
          return

        # PowerShell command to find present USB devices and grab their IDs
        scan_cmd = f'''
        Get-PnpDevice -PresentOnly | Where-Object {{ 
           $_.InstanceId -match "^USB" -and 
           ($_.Class -match "DiskDrive|Keyboard|Mouse|Net|HIDClass|Bluetooth")
        }} | Select-Object -ExpandProperty InstanceId | Out-File -FilePath "{WHITELIST_FILE}" -Encoding utf8
        '''
        # Run the command silently in the background
        subprocess.run(["powershell", "-Command", scan_cmd], creationflags=0x08000000) 
        
        scan_cmd = f'''
        Get-PnpDevice -PresentOnly | Where-Object {{ 
          $_.InstanceId -match "^USB" -and 
          ($_.Class -match "DiskDrive|Keyboard|Mouse|Net|HIDClass|Bluetooth")
        }} | Select-Object -ExpandProperty InstanceId | Out-File -FilePath "{WHITELIST_FILE}" -Encoding utf8
        '''
        subprocess.run(["powershell", "-Command", scan_cmd], creationflags=CREATE_NO_WINDOW) 
    
    def setup_tasks(self):
        ps_code = f'''
$Reg = Get-ItemProperty -Path "HKLM:\\{REG_PATH}" -ErrorAction SilentlyContinue
if ($Reg.{FLAG_NAME} -ne 1) {{ exit }}

# 1. Faster Whitelist Loading (Using a Set for O(1) lookups)
$Whitelist = @()
if (Test-Path "{WHITELIST_FILE}") {{
    $Whitelist = Get-Content "{WHITELIST_FILE}" | ForEach-Object {{ $_.Trim() }} | Where-Object {{ $_ }}
}}

# 2. Optimized Filtering (Wildcards are faster than Regex for simple matches)
$TargetClasses = @("DiskDrive", "Net", "Bluetooth", "HIDClass", "Keyboard", "Mouse", "SmartCardReader")
$Targets = Get-PnpDevice -PresentOnly -Class $TargetClasses | Where-Object {{ $_.InstanceId -like "*USB*" }}

# 3. Fast-Path Enforcement (No nested loop)
foreach ($Dev in $Targets) {{
    # Use '-notin' for high-speed list membership check
    if ($Dev.InstanceId -notin $Whitelist) {{
        try {{
            Disable-PnpDevice -InstanceId $Dev.InstanceId -Confirm:$false -ErrorAction Stop
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - BLOCKED: $($Dev.FriendlyName) ($($Dev.Class))" | Out-File -FilePath "{LOG_FILE}" -Append -Encoding utf8
        }} catch {{
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - REBOOT REQ/FAILED: $($Dev.FriendlyName)" | Out-File -FilePath "{LOG_FILE}" -Append -Encoding utf8
        }}
    }}
}}
'''
    
        with open(PS_SCRIPT_FILE, "w") as f: f.write(ps_code)
        
        enforcer_cmd = f'''
    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"{PS_SCRIPT_FILE}`""
    $CIM = Get-CimClass -Namespace root/Microsoft/Windows/TaskScheduler -ClassName MSFT_TaskEventTrigger
    
    # Trigger 1: USB Storage (Event 2101)
    $T1 = New-CimInstance -CimClass $CIM -ClientOnly
    $T1.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-DriverFrameworks-UserMode/Operational"><Select Path="Microsoft-Windows-DriverFrameworks-UserMode/Operational">*[System[EventID=2101]]</Select></Query></QueryList>'
    $T1.Enabled = $True

    # Trigger 2: Universal PnP Config (Event 400 - WiFi/BT)
    $T2 = New-CimInstance -CimClass $CIM -ClientOnly
    $T2.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-Kernel-PnP/Configuration"><Select Path="Microsoft-Windows-Kernel-PnP/Configuration">*[System[EventID=400]]</Select></Query></QueryList>'
    $T2.Enabled = $True

    # Settings for "Instant" stability
    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew

    Register-ScheduledTask -TaskName "{TASK_NAME}" -Action $Action -Trigger @($T1, $T2) -Settings $Settings -User "SYSTEM" -RunLevel Highest -Force
    '''

        gui_cmd = f'Register-ScheduledTask -TaskName "{GUI_TASK_NAME}" -Action (New-ScheduledTaskAction -Execute "{sys.executable}" -Argument "{"--tray" if self.get_reg(TRAY_FLAG) == 1 else ""}") -Trigger (New-ScheduledTaskTrigger -AtLogOn) -RunLevel Highest -Force'
        subprocess.run(["powershell","-ExecutionPolicy", "Bypass", "-Command", enforcer_cmd], capture_output=True, creationflags=CREATE_NO_WINDOW)
        subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", gui_cmd], capture_output=True, creationflags=CREATE_NO_WINDOW)

    def start_tray(self):
        color = (0, 180, 0) if self.get_reg(FLAG_NAME) == 1 else (200, 0, 0)
        menu = pystray.Menu(pystray.MenuItem("Open Panel", self.auth_and_restore), pystray.MenuItem("Exit", self.quit_app))
        self.tray = pystray.Icon(APP_NAME, self.create_tray_icon(color), APP_NAME, menu=menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

    def create_tray_icon(self, color):
        img = Image.new('RGB', (64, 64), (255, 255, 255))
        d = ImageDraw.Draw(img); d.ellipse((5, 5, 59, 59), fill=color, outline="white", width=4)
        return img

    def add_to_white(self):
        sel = self.tree.selection()
        if sel:
            item_vals = self.tree.item(sel)['values']
            if len(item_vals) > 1:
                hw_id = str(item_vals[1]).strip()
                existing = []
                if os.path.exists(WHITELIST_FILE):
                    with open(WHITELIST_FILE, "r", encoding="utf-8-sig") as f: existing = [line.strip() for line in f]
                if hw_id not in existing:
                    with open(WHITELIST_FILE, "a", encoding="utf-8-sig") as f: f.write(hw_id + "\n")
                subprocess.run(["powershell", "-Command", f'Get-PnpDevice -InstanceId "{hw_id}" | Enable-PnpDevice -Confirm:$false'], capture_output=True, creationflags=CREATE_NO_WINDOW)
                self.refresh_all(); messagebox.showinfo("Success", f"Device Whitelisted & Resurrected:\n{hw_id}")


    def hide_window(self): self.root.withdraw()
    
    def get_reg(self, name, default=0):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                val, _ = winreg.QueryValueEx(k, name)
                return val
        except: return default

    def set_reg(self, name, val):
        """Sets REG_DWORD (Integers)"""
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(val))
            self.setup_tasks()
            if name == FLAG_NAME and self.tray: 
                self.tray.icon = self.create_tray_icon((0, 180, 0) if val == 1 else (200, 0, 0))
            return True
        except: return False

    def set_reg_sz(self, name, val):
        """Sets REG_SZ (Strings)"""
        try:
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, REG_PATH, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, str(val))
            return True
        except: return False


    import re

    def log_monitor(self):
        last_size = os.path.getsize(LOG_FILE) if os.path.exists(LOG_FILE) else 0
        recent_alerts = {}  # { "DeviceID": timestamp }
        health_check_counter = 0

        while True:
            try:
                if not getattr(self, 'is_authenticating', False):
                    # --- 1. LOG MONITORING (Every 2s) ---
                    if os.path.exists(LOG_FILE):
                        curr_size = os.path.getsize(LOG_FILE)
                
                        if curr_size > last_size:
                            with open(LOG_FILE, "r", encoding="utf-8-sig", errors="ignore") as f:
                                f.seek(last_size)
                                new_content = f.read().strip()
                    
                            last_size = curr_size
                            self.root.after(0, self.refresh_logs)

                            if "BLOCKED:" in new_content:
                                device_info = new_content.split("BLOCKED:")[-1].strip()
                                now = time.time()

                                # ANTI-SPAM: Skip Telegram if alerted for this device in last 5 mins (300s)
                                if now - recent_alerts.get(device_info, 0) > 300:
                                    alert_msg = (
                                        f"--------------------------\n"
                                        f"🖥️ PC: {self.pc_name}\n"
                                        f"👤 User: {self.user_name}\n"
                                        f"🚫 Blocked: {device_info}\n"
                                        f"📅 Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                                        )
                                    if self.tray: self.tray.notify(f"Blocked: {device_info}", APP_NAME)
                                    self.send_notifications(alert_msg)
                                    recent_alerts[device_info] = now
                
                        elif curr_size < last_size: # Handle manual log clearing
                            last_size = curr_size

                    # --- 2. HEALTH HEARTBEAT (Every 20s) ---
                    health_check_counter += 1
                    if health_check_counter >= 10:
                        self.root.after(0, self.update_status_ui)
                        self.trim_logs()
                        health_check_counter = 0

            except Exception as e:
                print(f"Monitor Error: {e}")
            time.sleep(2)

    def refresh_all(self):
        self.tree.delete(*self.tree.get_children())
        cmd = "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -match 'USB' } | ForEach-Object { $_.FriendlyName + '|' + $_.InstanceId }"
        p = subprocess.run(["powershell", "-Command", cmd], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        for line in p.stdout.strip().split('\n'):
            if '|' in line:
                pts = line.split('|'); self.tree.insert("", tk.END, values=(pts[0], pts[1]))
        self.lb_white.delete(0, tk.END)
        if os.path.exists(WHITELIST_FILE):
            with open(WHITELIST_FILE, "r", encoding="utf-8-sig") as f:
                for line in f: 
                    if line.strip(): self.lb_white.insert(tk.END, line.strip())
        self.refresh_logs()

    def refresh_logs(self):
        self.log_area.config(state='normal'); self.log_area.delete('1.0', tk.END)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8-sig", errors="ignore") as f: self.log_area.insert(tk.END, f.read())
        self.log_area.config(state='disabled'); self.log_area.see(tk.END)

    def toggle_guard(self):
        curr = self.get_reg(FLAG_NAME)
        if self.set_reg(FLAG_NAME, 0 if curr == 1 else 1): self.update_status_ui()

    def update_status_ui(self):
        """Checks health and auto-repairs while logging sabotage attempts."""
        reg_armed = (self.get_reg(FLAG_NAME) == 1)
        task_healthy = self.is_enforcer_healthy()
    
        if reg_armed:
            if task_healthy:
                self.status_lbl.config(text="GUARD ACTIVE", fg="green")
                tab_title = "🛡️ Dashboard"
            else:
                # --- 🛠️ REPAIR TRIGGERED ---
                self.status_lbl.config(text="REPAIRING...", fg="orange")
                tab_title = "‼ Dashboard"
                self.root.update_idletasks()

                # 1. LOG TO AUDIT TAB
                try:
                    with open(LOG_FILE, "a", encoding="utf-8-sig") as f:
                        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        f.write(f"{ts} - [SYSTEM] Enforcer task missing/stopped! Repairing...\n")
                except: pass

                # 2. SEND URGENT ALERT
                repair_msg = (
                    f"🛠️ *PUSBGuard Self-Repair* 🛠️\n"
                    f"🖥️ PC: {self.pc_name}\n"
                    f"⚠️ Status: Guard Enforcer was sabotaged!\n"
                    f"✅ Action: Task recreated successfully."
                )
                self.send_notifications(repair_msg)
                if self.tray: self.tray.notify(f"⚠️ Enforcer task missing/stopped! Repairing...", APP_NAME)

                # 3. DO THE REPAIR
                self.setup_tasks()
        
                if self.is_enforcer_healthy():
                    self.status_lbl.config(text="GUARD ACTIVE (REPAIRED)", fg="green")
                    tab_title = "🛡️ Dashboard"
                else:
                    self.status_lbl.config(text="GUARD ERROR", fg="red")
                    tab_title = "‼ Dashboard"
        else:
            self.status_lbl.config(text="GUARD DISABLED", fg="red")
            tab_title = "⚠️ Dashboard"

        try:
            self.nb.tab(0, text=tab_title)
        except:
            pass


    def remove_from_white(self):
        sel = self.lb_white.curselection()
        if sel and self.verify_password():
            val = self.lb_white.get(sel)
            # Use utf-8-sig to automatically strip the ï»¿ characters during read
            with open(WHITELIST_FILE, "r", encoding="utf-8-sig") as f:
                lines = f.readlines()
            
            with open(WHITELIST_FILE, "w", encoding="utf-8-sig") as f:
                for l in lines:
                    if l.strip() != val: 
                        f.write(l)
            self.refresh_all()

    def emergency_unblock(self):
        if self.verify_password():
            self.set_reg(FLAG_NAME, 0)
            subprocess.run(["powershell", "-Command", "Get-PnpDevice | Where-Object { $_.InstanceId -match 'USB' } | Enable-PnpDevice -Confirm:$false"], creationflags=CREATE_NO_WINDOW)
            self.update_status_ui(); self.refresh_all()

    def clear_logs(self):
        if self.verify_password(): open(LOG_FILE, "w").close(); self.refresh_logs()

    def quit_app(self, icon=None, item=None):
        if self.verify_password():
            if self.tray: self.tray.stop()
            self.root.destroy(); sys.exit(0)

if __name__ == "__main__":
    import ctypes
    import sys
    import time # Needed for the small delay

    #  Handle High-DPI Awareness
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    # Check for Admin Elevation FIRST
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # This spawns the Admin process and then THIS non-admin process exits
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    
    # This gives the previous "parent" process time to die and release the Mutex
    time.sleep(1)

    
    # This prevents the elevated process from "tripping" over its own parent
    if is_already_running():
        sys.exit(0)

    #  Initialize Hidden Root and App
    root = tk.Tk()
    root.withdraw() 
    app = PUSBGuardApp(root)
    
    #  Immediate Authentication
    if app.verify_password():
        is_tray = (app.get_reg("StartToTray") == 1 or "--tray" in sys.argv)
        if not is_tray:
            root.deiconify() 
            root.focus_force()
        root.mainloop()
    else:
        root.destroy()
        sys.exit(0)
