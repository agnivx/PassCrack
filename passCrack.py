import json

def parse_hashcat_json(line):
    try:
        return json.loads(line)
    except:
        return None

"""
PassCrack — GUI wrapper that uses Hashcat for GPU/CPU cracking

Features:
- Uses Hashcat (CLI) as the cracking engine for GPU acceleration
- Auto-detects devices via `hashcat -I` and shows device selection (CPU/GPU)
- Supports Brute-force (mask) and Dictionary (wordlist) attacks
- Supports confirmed-position hints (generates Hashcat mask with literals)
- Falls back to local Python hashing for algorithms Hashcat doesn't support (e.g., base64)
- Streams Hashcat stdout/stderr to the GUI log, supports Abort
- Saves results to PassCrack_Results.txt

Requirements:
- Python 3.9+
- customtkinter: pip install customtkinter
- bcrypt: pip install bcrypt
- Hashcat installed and available in PATH (https://hashcat.net/hashcat/)

"""

import os
import sys
import subprocess
import threading
import tempfile
import time
import shlex
import json
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog, messagebox

# === FORCE HASHCAT PATH ===
HASHCAT_PATH = r"INSERT FILE PATH TO HASHCAT EXECUTABLE HERE"  # e.g., r"C:\hashcat\hashcat.exe" or "/usr/bin/hashcat"

# --------------------------- SUPPORTED CHARSETS ----------------------------
CHARSETS = {
    "Alphabetic (a-z)": "?l",
    "Alphabetic (A-Z)": "?u",
    "Alphabetic (a-z,A-Z)": "?l?u",
    "Numeric (0-9)": "?d",
    "Alphanumeric": "?l?u?d",
    "Alphanumeric + Special": "?l?u?d?s",
    "HEX": "?h"
}

CHARSET_MAP = {
    "Alphabetic (a-z)": "abcdefghijklmnopqrstuvwxyz",
    "Alphabetic (A-Z)": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "Alphabetic (a-z,A-Z)": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "Numeric (0-9)": "0123456789",
    "Alphanumeric": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "Alphanumeric + Special": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:',.<>/?|`~",
    "HEX": "0123456789abcdef"
}

# ----------------------------
# Mapping local algos to Hashcat modes
# modes are hashcat -m values (common ones)
# ----------------------------
HASHCAT_MODES = {
    'md4': '900',          # MD4
    'md5': '0',            # MD5
    'ripemd160': '600',    # RIPEMD160
    'sha1': '100',         # SHA1
    'sha256': '1400',      # SHA256
    'sha512': '1700',      # SHA512
}

# Algos we support in the GUI (either via Hashcat or local fallback)
SUPPORTED_ALGOS = list(HASHCAT_MODES.keys())
# ----------------------------
# Helpers: detect hashcat and devices
# ----------------------------

def find_hashcat_executable():
    """Force using explicit HASHCAT_PATH."""
    return HASHCAT_PATH if os.path.isfile(HASHCAT_PATH) else None


def shutil_which(name):
    # fallback to custom which to avoid extra imports in some envs
    for p in os.environ.get('PATH', '').split(os.pathsep):
        exe = Path(p) / name
        if exe.exists() and os.access(str(exe), os.X_OK):
            return str(exe)
    return None


def run_hashcat_info(hashcat_path=None):
    if not os.path.isfile(HASHCAT_PATH):
        return None
    try:
        proc = subprocess.run([HASHCAT_PATH, "-I"], capture_output=True, text=True, timeout=10, cwd=os.path.dirname(HASHCAT_PATH))
        return proc.stdout + proc.stderr
    except Exception:
        return None


def parse_hashcat_devices(info_text):
    """Parse the output of `hashcat -I` and return a list of device dicts.
    Each dict: {'id': int, 'name': str, 'type': 'GPU'/'CPU'}
    If parsing fails, return empty list.
    """
    devices = []
    if not info_text:
        return devices

    # naive parser: look for lines with 'Backend Device' or lines with 'Device #'
    # We'll parse lines containing 'Device #' or 'Platform ID' blocks.
    lines = info_text.splitlines()
    cur_id = 0
    for ln in lines:
        ln = ln.strip()
        if ln.startswith('Device #') or ln.startswith('Device  #'):
            # example: "Device #1: GeForce RTX 3060 Mobile"
            try:
                # split on ':'
                parts = ln.split(':', 1)
                left = parts[0]
                right = parts[1].strip() if len(parts) > 1 else ''
                # get id
                num = ''.join(ch for ch in left if ch.isdigit())
                if num:
                    cur_id = int(num)
                    devices.append({'id': cur_id, 'name': right, 'type': 'GPU'})
            except Exception:
                continue
        # fallback: lines mentioning 'CPU' or 'NVIDIA' etc
        elif 'CPU' in ln and 'Device' in ln and not devices:
            devices.append({'id': 0, 'name': ln, 'type': 'CPU'})
    return devices

# ----------------------------
# Mask generator for confirmed positions
# ----------------------------

def build_hashcat_mask_from_confirmed(length, confirmed_positions, charset):
    """Return (mask_string, custom_charset_args)
    - mask_string: e.g. 'hel?1?1?1'
    - custom_charset_args: list like ['-1', 'abc...'] or []

    Strategy: use custom-charset1 (-1) with the full charset provided; for every unknown position use ?1; for confirmed positions inject the literal char (escaped if needed).
    This keeps mask simple and flexible.
    """
    # sanitize charset for hashcat: remove characters hashcat treats specially? We'll pass raw.
    custom_args = []
    if charset:
        custom_args = ['-1', charset]
        token = '?1'
    else:
        token = '?a'

    mask_parts = []
    for i in range(length):
        ch = confirmed_positions.get(i)
        if ch:
            # If character is a special mask character for hashcat, wrap in single quotes
            # hashcat mask literals: to place a literal you can just include it; spaces need escaping
            if ch == ' ':
                mask_parts.append("\u0020")
            else:
                # for safety, if char is one of ?\ we escape
                if ch in ['?', '\\']:
                    mask_parts.append('\\' + ch)
                else:
                    mask_parts.append(ch)
        else:
            mask_parts.append(token)
    mask = ''.join(mask_parts)
    return mask, custom_args

# ----------------------------
# Runner for Hashcat process
# ----------------------------

def run_hashcat_async(hashcat_path, mode_m, attack_mode, hashfile, mask_or_dict, custom_charset_args, device_arg, out_path, log_callback, stop_flag):
    """Run hashcat in a background thread. Stream output lines to log_callback(line).
    stop_flag: threading.Event() to request termination
    Returns subprocess exitcode or None on fail.
    """
    cmd = [HASHCAT_PATH, '-m', str(mode_m), '-a', str(attack_mode)]

    # add outfile
    if out_path:
        cmd += ['-o', out_path, '--outfile-format=2']  # format 2: plain? adjust as needed

    # add device selection: device_arg may be None or '-d N'
    if device_arg:
        # device_arg expected like '1' or 'all'
        cmd += ['-d', str(device_arg)]

    # include custom charset args
    if custom_charset_args:
        cmd += custom_charset_args

    # hash file + mask/dict
    cmd += [hashfile, mask_or_dict]

    # add status and machine-readable output if available
    # use --status --status-json to allow monitoring (if hashcat build supports it)
    cmd += ['--status', '--status-timer=1']

    # disable potfile if you want fresh results only
    # cmd += ['--potfile-disable']

    # launch
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=os.path.dirname(HASHCAT_PATH))
    except FileNotFoundError:
        log_callback('ERROR: Hashcat executable not found. Ensure hashcat is installed and in PATH.')
        return None
    except Exception as e:
        log_callback(f'ERROR: Failed to launch hashcat: {e}')
        return None

    # reader loop
    try:
        for line in proc.stdout:
            if stop_flag.is_set():
                try:
                    proc.terminate()
                except Exception:
                    pass
                log_callback('Hashcat: termination requested.')
                break
            log_callback(line.rstrip('\n'))
        proc.wait()
        return proc.returncode
    except Exception as e:
        log_callback(f'ERROR while running hashcat: {e}')
        try:
            proc.kill()
        except Exception:
            pass
        return None

# ----------------------------
# Local fallback for algorithms not supported in hashcat (e.g., base64)
# This is CPU-only and slow; used only when necessary.
# ----------------------------
import hashlib
import base64 as _base64

def local_check_base64(target_hash, charset, max_len, salt, confirmed_positions, abort_flag, progress_cb=None):
    """Simple brute-forc e attempt for base64 by generating candidates up to max_len. Very slow; only for demo."""
    tried = 0
    t0 = time.time()
    for length in range(1, max_len+1):
        # generate with confirmed positions
        base = [None] * length
        for pos, ch in confirmed_positions.items():
            if 0 <= pos < length:
                base[pos] = ch
        unknown_positions = [i for i in range(length) if base[i] is None]
        if len(unknown_positions) > 8:
            if progress_cb:
                progress_cb(f'Skipping length {length}: too many unknowns ({len(unknown_positions)})')
            continue
        for tup in itertools.product(charset, repeat=len(unknown_positions)):
            if abort_flag.is_set():
                return None
            temp = base[:]
            for idx, ch in zip(unknown_positions, tup):
                temp[idx] = ch
            guess = ''.join(temp)
            tried += 1
            # base64 compare: candidate encoded -> base64 string
            val = _base64.b64encode((salt + guess).encode()).decode()
            if val == target_hash:
                return guess
            if progress_cb and tried % 1000 == 0:
                elapsed = time.time() - t0
                rate = tried / max(1e-9, elapsed)
                rem = 0  # unknown
                progress_cb(f'Tried: {tried}, Rate: {int(rate)} /s')
    return None

# ----------------------------
# GUI
# ----------------------------
class PassCrackHashcatGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode('dark')
        ctk.set_default_color_theme('dark-blue')
        self.title('PassCrack')
        self.geometry('980x720')

        # hashcat path and devices
        self.hashcat_path = find_hashcat_executable()
        self.devices = []
        self.stop_event = threading.Event()
        self.current_proc_thread = None

        # UI variables
        self.var_hash = ctk.StringVar()
        self.var_algo = ctk.StringVar(value=SUPPORTED_ALGOS[0])
        self.var_attack = ctk.StringVar(value='Brute-Force')
        self.var_charset = ctk.StringVar(value='Alphanumeric')
        self.var_maxlen = ctk.IntVar(value=8)
        self.var_threads = ctk.StringVar(value='8')
        self.var_salt = ctk.StringVar(value='')
        self.var_dict = ctk.StringVar(value='')
        self.var_device = ctk.StringVar(value='Auto (hashcat)')

        self._build_ui()
        self._detect_hashcat_and_devices()

    def _build_ui(self):
        # header
        header = ctk.CTkLabel(self, text='PassCrack', font=('Segoe UI', 32, 'bold'), text_color="#5505AA" )
        header.pack(pady=(12,6))

        main = ctk.CTkFrame(self)
        main.pack(fill='x', padx=12)

        # Row: Hash + Algo
        row1 = ctk.CTkFrame(main, fg_color='transparent')
        row1.pack(fill='x', pady=6)
        ctk.CTkLabel(row1, text='  Hash Value').grid(row=0,column=0,sticky='w')
        ctk.CTkEntry(row1, textvariable=self.var_hash, width=700).grid(row=1,column=0,columnspan=3,padx=6,pady=4)
        ctk.CTkLabel(row1, text='  Algorithm').grid(row=0,column=3, sticky='w')
        ctk.CTkOptionMenu(row1, values=SUPPORTED_ALGOS, variable=self.var_algo).grid(row=1,column=3,padx=6)

        # Row: attack, charset, maxlen
        row2 = ctk.CTkFrame(main, fg_color='transparent')
        row2.pack(fill='x', pady=6)
        ctk.CTkLabel(row2, text='  Attack Type').grid(row=0,column=0,sticky='w')
        ctk.CTkOptionMenu(row2, values=['Brute-Force','Dictionary'], variable=self.var_attack, command=self._toggle_attack_mode).grid(row=1,column=0,padx=6)

        ctk.CTkLabel(row2, text='  Charset').grid(row=0,column=1,sticky='w')
        ctk.CTkOptionMenu(row2, values=list(CHARSETS.keys()), variable=self.var_charset).grid(row=1,column=1,padx=6)

        ctk.CTkLabel(row2, text='Max Length (1-14)').grid(row=0,column=2,sticky='w')
        ctk.CTkEntry(row2, textvariable=self.var_maxlen, width=80).grid(row=1,column=2,padx=6)

        ctk.CTkLabel(row2, text='   Threads (4/8/12)').grid(row=0,column=3,sticky='w')
        ctk.CTkOptionMenu(row2, values=['4','8','12'], variable=self.var_threads).grid(row=1,column=3,padx=6)

        ctk.CTkLabel(row2, text='  Salt (optional)').grid(row=0,column=4,sticky='w')
        ctk.CTkEntry(row2, textvariable=self.var_salt, width=160).grid(row=1,column=4,padx=6)

        # Row: dict file and device selection
        row3 = ctk.CTkFrame(main, fg_color='transparent')
        row3.pack(fill='x', pady=6)
        ctk.CTkLabel(row3, text='  Dictionary File').grid(row=0,column=0,sticky='w')
        self.entry_dict = ctk.CTkEntry(row3, textvariable=self.var_dict, width=520)
        self.entry_dict.grid(row=1,column=0,padx=6)
        ctk.CTkButton(row3, text='Browse', command=self._browse_dict, width=100).grid(row=1,column=1,padx=6)

        ctk.CTkLabel(row3, text='  Device').grid(row=0,column=2, sticky='w')
        self.device_menu = ctk.CTkOptionMenu(row3, values=['Auto (hashcat)'], variable=self.var_device)
        self.device_menu.grid(row=1,column=2,padx=6)

        # controls
        ctrl = ctk.CTkFrame(self)
        ctrl.pack(fill='x', padx=12, pady=(8,6))
        ctk.CTkButton(ctrl, text='▶ Start', command=self._start_attack, width=120, fg_color='#1BDB22').grid(row=0,column=0,padx=6)
        ctk.CTkButton(ctrl, text='⛔ Abort', command=self._abort_attack, width=120, fg_color='#c91f1f').grid(row=0,column=1,padx=6)

        # log box
        logf = ctk.CTkFrame(self)
        logf.pack(fill='both', expand=True, padx=12, pady=(6,12))
        ctk.CTkLabel(logf, text='Logs').pack(anchor='w', padx=8)
        self.log_box = ctk.CTkTextbox(logf, font=('Consolas',11))
        self.log_box.pack(fill='both', expand=True, padx=8, pady=8)
        self.log_box.configure(state='disabled')

    def _toggle_attack_mode(self, mode):
        is_dict = (mode == 'Dictionary')
        self.entry_dict.configure(state='normal' if is_dict else 'disabled')

    def _browse_dict(self):
        path = filedialog.askopenfilename(title='Select dictionary file')
        if path:
            self.var_dict.set(path)

    def _log(self, text):
        # append read-only
        self.log_box.configure(state='normal')
        self.log_box.insert('end', f"[{time.strftime('%H:%M:%S')}] {text}\n")
        self.log_box.see('end')
        self.log_box.configure(state='disabled')
        self.update_idletasks()

    def _detect_hashcat_and_devices(self):
        # find hashcat
        self.hashcat_path = HASHCAT_PATH
        if not os.path.isfile(HASHCAT_PATH):
            self._log(f'Hashcat not found at: {HASHCAT_PATH}')
            self.devices = []
            self.device_menu.configure(values=['Auto (hashcat)'])
        return

        self._log(f'Using Hashcat at: {HASHCAT_PATH}')

        self.devices = []
        self.device_menu.configure(values=['Auto (hashcat)'])
        return
        self._log(f'Found hashcat at: {self.hashcat_path}')
        info = run_hashcat_info(self.hashcat_path)
        devs = parse_hashcat_devices(info)
        if not devs:
            # fallback: present CPU option
            devs = [{'id': 'cpu', 'name': 'CPU (hashcat)'}]
        self.devices = devs
        values = ['Auto (hashcat)', 'CPU'] + [f"#{d['id']}: {d['name']}" for d in devs]
        self.device_menu.configure(values=values)
        # keep selection
        self.var_device.set(values[0])
        self._log('Devices refreshed.')

    def _start_attack(self):
        # validate inputs
        if not self.var_hash.get().strip():
            messagebox.showerror('Error', 'Please enter the hash value.')
            return
        algo = self.var_algo.get()
        attack = self.var_attack.get()
        charset_name = self.var_charset.get()
        charset = CHARSETS.get(charset_name, CHARSETS['Alphanumeric'])
        max_len = int(self.var_maxlen.get())
        if max_len < 1 or max_len > 14:
            messagebox.showerror('Error', 'Max length must be between 1 and 14.')
            return
        salt = self.var_salt.get()
        device_sel = self.var_device.get()

        # prepare confirmed positions if needed
        confirmed = {}
        if max_len > 8:
            confirmed = self._prompt_confirmed_positions(max_len)
            if confirmed is None:
                return
            unknowns = max_len - sum(1 for i in range(max_len) if i in confirmed)
            if unknowns > 8:
                messagebox.showerror('Too many unknowns', f'Unknown positions: {unknowns}. Max 8 unknowns allowed.')
                return

        # prepare target hash file
        tf = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8', suffix='.hash')
        tf.write(self.var_hash.get().strip())
        tf.close()
        hashfile = tf.name

        # prepare out file
        out_path = os.path.join(os.getcwd(), 'PassCrack_Results.txt')

        # Decide whether to use hashcat or fallback
        use_local = (algo == 'base64') or (algo not in HASHCAT_MODES)

        if use_local:
            self._log('Using local CPU fallback (algorithm not supported by hashcat). This will be slow.')
            # run local brute force (only base64 fallback implemented)
            self.stop_event.clear()
            t = threading.Thread(target=self._run_local_fallback, args=(algo, self.var_hash.get().strip(), charset, max_len, salt, confirmed, out_path))
            t.daemon = True
            t.start()
            self.current_proc_thread = t
            return

        # Build hashcat arguments
        mode_m = HASHCAT_MODES[algo]
        if attack == 'Dictionary':
            attack_mode = 0
            mask_or_dict = self.var_dict.get().strip()
            if not mask_or_dict:
                messagebox.showerror('Error', 'Please select a dictionary file for Dictionary attack.')
                return
        else:
            attack_mode = 3  # mask (brute-force)
            # build mask from confirmed positions
            mask, custom_args = build_hashcat_mask_from_confirmed(max_len, confirmed, charset)
            mask_or_dict = mask

        # device arg mapping
        device_arg = None
        if device_sel == 'CPU':
            device_arg = 1  # hashcat device id 1 often CPU - depends on system; leaving to user selection recommended
        elif device_sel.startswith('#'):
            # parse id
            try:
                device_arg = int(device_sel.split(':',1)[0].lstrip('#'))
            except Exception:
                device_arg = None
        else:
            device_arg = None

        # start hashcat in background thread
        self.stop_event.clear()
        def log_cb(line):
            self._log(line)
            # try parse progress lines for ETA/tried counts (simple heuristic)
            if '%' in line and '\\' not in line:
                # example progress line may contain: Progress... (23%)
                try:
                    if '%' in line:
                        pct = line.split('%')[0].split()[-1]
                        # attempt to set progress if numeric
                        pct_f = float(pct.strip().strip('%')) / 100.0
                        self.progress.set(min(max(pct_f,0.0),1.0))
                except Exception:
                    pass

        t = threading.Thread(target=run_hashcat_async, args=(HASHCAT_PATH, mode_m, attack_mode, hashfile, mask_or_dict, custom_args if attack=='Brute-Force' else [], device_arg, out_path, log_cb, self.stop_event))
        t.daemon = True
        t.start()
        self.current_proc_thread = t

    def _run_local_fallback(self, algo, target_hash, charset, max_len, salt, confirmed, out_path):
        self._log('Local fallback started...')
        res = None
        if algo == 'base64':
            res = local_check_base64(target_hash, charset, max_len, salt, confirmed, self.stop_event, progress_cb=self._log)
        # if found
        if res:
            save_results(target_hash, algo, res, salt)
            self._log(f'SUCCESS — Password found: {res} (saved to {out_path})')
            messagebox.showinfo('PassCrack', f'Password cracked: {res}\nSaved to {out_path}')
        else:
            if not self.stop_event.is_set():
                self._log('Finished — No password found with local fallback.')

    def _abort_attack(self):
        self.stop_event.set()
        self._log('Abort requested — attempting to stop background worker.')

    def _prompt_confirmed_positions(self, length: int):
        dlg = ctk.CTkToplevel(self)
        dlg.title('Confirmed Positions (0-index)')
        dlg.geometry('640x360')
        ctk.CTkLabel(dlg, text=f'Provide known characters for positions 0 … {length-1}. Leave as "?" (default) for unknown.', font=('Segoe UI', 12)).pack(pady=(10,6))
        frame = ctk.CTkScrollableFrame(dlg, width=600, height=220)
        frame.pack(padx=8, pady=6, fill='both', expand=True)
        entries = []
        for i in range(length):
            cell = ctk.CTkFrame(frame, fg_color='transparent')
            cell.pack(fill='x', pady=2)
            lbl = ctk.CTkLabel(cell, text=f'Pos {i}', width=70)
            lbl.pack(side='left', padx=6)
            ent = ctk.CTkEntry(cell, width=80)
            ent.pack(side='left', padx=6)
            ent.insert(0, '?')
            entries.append((i, ent))
        btn_frame = ctk.CTkFrame(dlg)
        btn_frame.pack(pady=8)
        result = {'ok': False, 'confirmed': {}}
        def on_confirm():
            confirmed = {}
            for idx, ent in entries:
                v = ent.get().strip()
                if v and v != '?':
                    confirmed[idx] = v[0]
            result['ok'] = True
            result['confirmed'] = confirmed
            dlg.destroy()
        def on_cancel():
            dlg.destroy()
        ctk.CTkButton(btn_frame, text='Confirm Positions', width=160, command=on_confirm).grid(row=0, column=0, padx=8)
        ctk.CTkButton(btn_frame, text='Cancel', width=120, fg_color='#555555', command=on_cancel).grid(row=0, column=1, padx=8)
        dlg.grab_set()
        self.wait_window(dlg)
        if not result['ok']:
            return None
        return result['confirmed']

# ----------------------------
# Save results function
# ----------------------------

def save_results(hash_value: str, algo: str, password: str, salt: str):
    path = os.path.join(os.getcwd(), 'PassCrack_Results.txt')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(f'Hash: {hash_value}\n')
        f.write(f'Algorithm: {algo}\n')
        if salt:
            f.write(f'Salt: {salt}\n')
        f.write(f'Password: {password}\n')

# ----------------------------
# Run GUI
# ----------------------------
if __name__ == '__main__':
    import shutil
    # ensure hashcat path detection uses shutil.which fallback
    if not find_hashcat_executable():
        # try shutil.which
        if shutil.which('hashcat'):
            pass
    app = PassCrackHashcatGUI()
    app.mainloop()