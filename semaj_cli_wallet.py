#!/usr/bin/env python3
#
# A helper CLI tool to generate a solana address - Semaj.Gnehz 2026/05/29
# pip3 install qrcode solders mnemonic solana base58 chinese_converter
#

import io
import os
import sys
import time
import hashlib
import qrcode
import base64
from base58 import b58decode
from getpass import getpass
from chinese_converter import to_simplified
from mnemonic import Mnemonic

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.message import MessageV0
from solders.transaction import VersionedTransaction

from solana.rpc.types import TokenAccountOpts
from solana.rpc.types import TxOpts
from solana.rpc.api import Client
from spl.token.constants import TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID
from spl.token.instructions import (
    transfer_checked,
    TransferCheckedParams,
    create_associated_token_account,
    get_associated_token_address
)

# Hardcoded Known Token Registry
KNOWN_TOKEN_DICT = {
    ### TOKEN ADDESS : NAME len() MUST BE <= 20 & USE UPPER CASE ONLY
    "So11111111111111111111111111111111111111112"  : "WSOL",
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" : "USDC",
    "cbbtcf3aa214zXHbiAZQwf4122FBYbraNdFqgw4iMij"  : "CBBTC",
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" : "USDT",
    "J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn" : "JITOSOL",
    "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"  : "JUP",
    "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn"  : "PUMP",
    "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R" : "RAY",
    "HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3" : "PYTH",
    "3NZ9JMVBmGAqocybic2c7LQCJScmgsAZ6vQqTDzcqmJh" : "WBTC",
    "7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs" : "WETH",
    "6p6xgHyF7AeE6TZkSmFsko444wqoP15icUSqi2jfGiPN" : "TRUMP",
}
KNOWN_TOKEN_DICT_REVERSE = {v.upper(): k for k, v in KNOWN_TOKEN_DICT.items()}

USE_MINIMAL_FEE = True

RPC_URL = "https://api.mainnet-beta.solana.com"
LAMPORTS_PER_SOL = 1_000_000_000

# ###
# Wallet Type              Derivation Path Format          Default First Account
# Phantom                  m/44'/501'/{index}'/0'          m/44'/501'/0'/0'
# Ledger                   m/44'/501'/{index}'             m/44'/501'/0'
# Solflare                 m/44'/501'/{index}'             m/44'/501'/0'
# Solana CLI (Raw Default) m/44'/501'                      m/44'/501'
# Solana CLI (With Flag)   m/44'/501'/{index}'/{change}'  m/44'/501'/0'/0'

DERIVATION_PATHS={
    "SOLANACLI"     : "m/44'/501'",
    "SOLANACLIFLAG" : "m/44'/501'/{index}'/{change}'",
    "SOLFLARE"      : "m/44'/501'/{index}'",
    "LEDGER"        : "m/44'/501'/{index}'",
    "PHANTOM"       : "m/44'/501'/{index}'/0'",
    "CUSTOM"        : "m/44'/501'/0'/0'",  # Placeholder for your own type
}
SEMAJ_ENCRYPTION_ADDON = r"%Semaj'sFancy&SimpleSolanaWallet%"

def int2bin     (i,     n) : return bin(i         )[2:].zfill(n)
def hex2bin     (h,     n) : return bin(int(h, 16))[2:].zfill(n)
def to2048      (n       ) : return ([] if n == 0 else to2048(n // 2048) + [n % 2048]) if n else []
def from2048    (idxs    ) : return sum(c * (2048 ** i) for i, c in enumerate(reversed(idxs)))
def wd2effwd    (s,   wdl) : return ([          i.lower()  for i in s if i.lower() in wdl] * 24) [:24]
def wd2idxs     (s,   wdl) : return ([wdl.index(i.lower()) for i in s if i.lower() in wdl] * 24) [:24]
def sha256i     (s       ) : return int(hashlib.sha256(str(s).encode('utf8')).hexdigest(), 16)
def idxs2eng    (idxs,wdl) : return ' '.join(wdl[i] for i in idxs)
def bits2idxs   (bits    ) : return [int(bits[i:i+11], 2) for i in range(0, len(bits), 11)]
def checksum    (i,     n) : return hex2bin(hashlib.sha256((i%2**n).to_bytes(n//8, byteorder='big')).hexdigest(), 256)[:n//32]  #bip-39
def ient2idxs   (i,     n) : return bits2idxs(int2bin(i%2**n,n)+checksum(i%2**n,n))
def getwordlist (        ) : return Mnemonic("english").wordlist
def int2seedphs (i,     n) : return idxs2eng(ient2idxs(i%2**n,n), getwordlist())
def int2b58     (i,     n) : return base58_encode((i%2**n).to_bytes(n//8, byteorder='big'))
def int2b36     (i       ) : return '0' if i == 0 else int2b36(i // 36).lstrip('0') + '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[i % 36]
def strhash2b58 (s       ) : return int2b58(sha256i(s), 256)
def splitstr    (s,     n) : return [s[i*n:(i+1)*n] for i in range(len(s)//n + 1)]
def dedup       (s       ) : return (lambda x=set(): ''.join(c for c in s if not (c in x or x.add(c))))()
def cn2int      (cn      ) : return from2048(wd2idxs(cn, Mnemonic('chinese_simplified').wordlist))
def iscn        (s       ) : return any('\u4e00' <= c <= '\u9fff' for c in str(s))
def xyz         (      *x) : return sum([(cn2int(to_simplified(s))>>8) if iscn(s) else sha256i(s) for s in x]) 

def seed2int(words, lang='english'):
    n_words = len(words)
    n = {12:128, 24:256}[n_words]
    mw = Mnemonic(lang)
    i_words = from2048(wd2idxs(words, mw.wordlist))
    i_ent = i_words >> (n_words * 11 - n)  # remove checksum
    return i_ent

def base58_encode(data: bytes) -> str:
    _b58_alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    encode_chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        encode_chars.append(_b58_alphabet[rem])
    n_pad = 0
    for c in data:
        if c == 0:
            n_pad += 1
        else:
            break
    return ( _b58_alphabet[0:1] * n_pad + bytes(reversed(encode_chars)) ).decode("ascii")

def b36_checksum(bitstring):
    bit_string_b36 = int2b36(sha256i(bitstring)) # use the last 4 b36 as image convert checksum
    bit_string_b36_checksum = ''.join(sorted(dedup(bit_string_b36)[:4]))
    return bit_string_b36_checksum 

def print_qr_terminal(*strings):
    # Filter out empty inputs
    inputs = [s for s in strings if s]

    if not inputs:
        print("No input strings provided.")
        return

    # Generate text-based QR codes into lists of lines
    qr_outputs = []
    for text in inputs[:2]:  # Limit to a maximum of 2 strings
        qr = qrcode.QRCode(version=1, box_size=1, border=1)
        qr.add_data(text)
        qr.make(fit=True)

        f = io.StringIO()
        qr.print_ascii(out=f, invert=True)
        qr_outputs.append(f.getvalue().splitlines())

    # Get dynamic terminal width (fallback to 80 if running in a headless environment)
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        terminal_width = 80

    # Case 1: Only 1 string provided
    if len(qr_outputs) == 1:
        print(strings[0])
        for line in qr_outputs[0]:
            print(line)

    # Case 2: 2 strings provided
    elif len(qr_outputs) == 2:
        print(strings[0])
        lines1, lines2 = qr_outputs[0], qr_outputs[1]

        # Calculate maximum widths of each individual QR block
        width_qr1 = max(len(l) for l in lines1) if lines1 else 0
        width_qr2 = max(len(l) for l in lines2) if lines2 else 0
        gap = 4

        # Total horizontal characters needed to print side-by-side
        total_required_width = width_qr1 + gap + width_qr2

        # Check if the terminal has enough room
        if total_required_width <= terminal_width:
            # Print side-by-side
            max_height = max(len(lines1), len(lines2))
            for i in range(max_height):
                l1 = lines1[i] if i < len(lines1) else ""
                l2 = lines2[i] if i < len(lines2) else ""
                print(f"{l1.ljust(width_qr1)}{' ' * gap}{l2}")
        else:
            # Fallback: Print one after another (vertically) with a separator line
            print("--- Terminal too narrow! Printing sequentially ---")
            for line in lines1:
                print(line)
            print("\n" + "-" * width_qr1 + "\n")  # Visual break between QR codes
            for line in lines2:
                print(line)
        print(strings[1])

def derive_key(passcode: str, salt: bytes) -> bytes:
    """Uses Argon2id to securely derive a 256-bit AES key."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536
    )
    return kdf.derive(passcode.encode())

def encrypt_workflow():
    """Prompts for input, encrypts it, and displays a compact text-based QR code."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plain_text = input("Enter text to encrypt: ").strip()
    if not plain_text:
        print("Error: Input text cannot be empty.")
        sys.exit(1)
        
    passcode = getpass("Enter a strong passcode (hidden typing): ")
    passcode = f"{SEMAJ_ENCRYPTION_ADDON}+{passcode}"

    # Generate cryptographically secure random values
    salt = os.urandom(16)   
    nonce = os.urandom(12)  

    # Encrypt via authenticated AES-GCM
    key = derive_key(passcode, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode(), None)
    
    # Bundle into a single payload string
    payload = f"{base64.b64encode(salt).decode()}.{base64.b64encode(nonce).decode()}.{base64.b64encode(ciphertext).decode()}"
    payload = f"#!decrypt(\"{payload}\")"
    print("\n=== Encryption Successful ===")
    print("Secure Payload String:")
    print(payload)
    
    # --- Compact QR Code Addon ---
    print("\nScan this QR Code to read the encrypted payload:")
    
    # Minimized border to 1 block for extra space savings
    qr = qrcode.QRCode(version=1, box_size=1, border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    
    # CRITICAL: Using 'print_ascii(invert=True)' prints ultra-compact half-blocks
    # This shrinks the height by 50% so it easily fits the command prompt window
    qr.print_ascii(invert=True)

    print("") # Empty spacer line
    save_choice = input("Would you like to generate a QR PNG file? (y/n): ").strip().lower()

    if save_choice in ['y', 'yes']:
        filename = "qr_payload.png"

        # Re-generate with a larger box_size for a clean, crisp PNG image
        img_qr = qrcode.QRCode(version=1, box_size=10, border=4)
        img_qr.add_data(payload)
        img_qr.make(fit=True)

        # Create and write image to disk
        qr_image = img_qr.make_image(fill_color="black", back_color="white")
        qr_image.save(filename)
        print(f"Success! High-resolution QR code saved as: {os.path.abspath(filename)}")
    else:
        print("Skipped PNG image generation.")

def decrypt(payload: str, passcode=None):
    """Unbundles the components, prompts for password, and decrypts."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        salt_b64, nonce_b64, cipher_b64 = payload.split(".", 2)
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(cipher_b64)
    except Exception:
        print("Error: Invalid payload format.")
        sys.exit(1)
        
    passcode = passcode if passcode != None else getpass("Enter the decryption password (hidden typing): ")
    passcode = f"{SEMAJ_ENCRYPTION_ADDON}+{passcode}"
    
    try:
        key = derive_key(passcode, salt)
        aesgcm = AESGCM(key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        msg = decrypted_bytes.decode('utf-8')
        print("\n=== Decryption Successful ===")
        print(f"Decrypted Message: {msg[:3]}...")
        return msg
        
    except Exception:
        print("\nError: Decryption failed. Incorrect password or tampered payload.")
        sys.exit(1)

def get_camera_index():
    """
    Scans indexes 0 through 3 to find active cameras on your Mac,
    then presents an interactive menu to choose which one to use.
    """
    import cv2
    print("\n" + "-" * 50)
    print(" [Camera Device Scanner]")
    print(" Checking for connected video devices...")
    print("-" * 50)

    available_cameras = []

    # Check indexes 0-3 for active cameras
    for i in range(4):
        cap = cv2.VideoCapture(i)
        if cap.isOpened():
            # Quick check to ensure a frame can be read
            ret, _ = cap.read()
            if ret:
                available_cameras.append(i)
            cap.release()

    if not available_cameras:
        print("[!] No working video cameras found on this system.")
        return 0 # Fallback to default index 0

    if len(available_cameras) == 1:
        # Only one camera found, use it automatically without prompting
        return available_cameras[0]

    # Multiple cameras found (e.g., MacBook Webcam and iPhone Continuity Camera)
    print("\n Multiple cameras found! Please select one:")
    for idx, cam_id in enumerate(available_cameras):
        # A simple fallback name label since OpenCV raw bindings don't expose system device strings easily
        device_label = "Primary/Built-in Webcam" if cam_id == 0 else f"Secondary/iPhone Camera (Device #{cam_id})"
        print(f"  {idx + 1}. {device_label}")

    while True:
        try:
            choice = input(f"\nSelect a camera option (1-{len(available_cameras)}): ").strip()
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(available_cameras):
                selected_index = available_cameras[choice_idx]
                print(f"[✓] Initializing device index #{selected_index}...")
                return selected_index
        except ValueError:
            pass
        print(f"[!] Invalid selection. Please choose a number between 1 and {len(available_cameras)}.")

def scan_qr_from_camera():
    """
    Detects available cameras, lets the user select one, and scans for a QR code.
    """
    # 1. Ask user to pick which camera to use
    import cv2
    camera_idx = get_camera_index()

    print("\n" + "=" * 60)
    print(" [QR Code Scanner Active]")
    print(" -> A camera window will now open.")
    print(" -> Hold your QR code up to your selected camera frame.")
    print(" -> Press the 'q' key on your keyboard to cancel and exit.")
    print("=" * 60)

    # 2. Open the selected camera device index
    cap = cv2.VideoCapture(camera_idx)

    qr_detector = cv2.QRCodeDetector()
    detected_address = None

    if not cap.isOpened():
        print(f"[!] ERROR: Could not access camera device index {camera_idx}.")
        print("    Go to System Settings -> Privacy & Security -> Camera")
        print("    Ensure your Terminal application has camera permissions enabled.")
        return None

    while True:
        ret, frame = cap.read()
        if not ret:
            print("[!] Failed to grab camera feed frame.")
            break

        data, bbox, _ = qr_detector.detectAndDecode(frame)
        if data:
            detected_address = data.strip()
            print(f"\n[✓] QR Code Detected Successfully! Address: {detected_address}")
            break

        cv2.putText(frame, "Align QR Code Here (Press 'q' to Cancel)", (30, 50),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 0), 2)

        cv2.imshow("Solana CLI - Scan Recipient QR Code", frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            print("\n[!] QR Scanning canceled by user.")
            break

    cap.release()
    cv2.destroyAllWindows()
    cv2.waitKey(1)

    return detected_address

def get_solana_balance(pubkey_obj: Pubkey) -> str:
    """Connects to the Solana Mainnet RPC to check a public key balance."""
    try:
        client = Client(RPC_URL)
        response = client.get_balance(pubkey_obj)
        lamports = response.value
        sol_balance = lamports / LAMPORTS_PER_SOL
        return f"{sol_balance:.4f} SOL"
    except Exception as error:
        return f"Error checking balance: {str(error)}"

def process_to_keypair(input_raw, wallet_path_name):
    """Parses inputs, converts binary entropy to mnemonics, and derives keys."""
    input_refined = str(input_raw).strip()

    while input_refined.startswith('#'):
        if input_refined.startswith('#$'):
            _step1 = input_refined[2:]
            _step2 = _step1.replace(","," ").replace("  "," ").replace("  "," ").split(" ")
            _step3 = seed2int(_step2)
            input_refined = str(_step3)

        if input_refined.startswith('#!'):
            _step1 = eval(input_refined[2:])
            input_refined = str(_step1)

    if not input_refined.isdigit(): # upto here all must be digit otherwise hash to int
        input_refined = str(sha256i(input_refined))

    input_int = int(input_refined)

    show_secret = False if 'decrypt' in input_raw else True
    if show_secret:
        print(f"💡 Evaluated Input : {input_refined}")
    print(f"💡 --> b36 Checksum:{b36_checksum(int2bin(input_int, 256))}")

    input_b58 = int2b58(int(input_refined), 256)
    input_seedphrases = int2seedphs(int(input_refined), 256)
    if show_secret:
        print(f"💡 Your Input: {input_raw}")
        print(f"   - In b58: {input_b58}")
        print(f"   - Translated Into Seed Phrases : {input_seedphrases}")

    e_mnemo = Mnemonic("english")

    try:
        if len(input_seedphrases.split()) in [12, 15, 18, 21, 24]:
            if not e_mnemo.check(input_seedphrases):
                print("❌ Invalid BIP39 mnemonic phrase check failed.")
                return
            master_seed = e_mnemo.to_seed(input_seedphrases)
        else:
            print("❌ Unsupported input string format structure.")
            return

        # 2. DEFINE DERIVATION PATH LAYOUTS : _ic for index and change
        _path_ic = (wallet_path_name+"_0_0").split('_')  # default to use the first wallet - 0
        derivation_path = DERIVATION_PATHS[_path_ic[0]].replace('{index}', _path_ic[1]).replace('{change}', _path_ic[2])

        # 3. DERIVE KEYPAIRS AND FETCH LIVE BALANCES
        the_keypair = Keypair.from_seed_and_derivation_path(master_seed, derivation_path)

        the_pubkey = the_keypair.pubkey()
        the_priv_b58key = str(the_keypair)

        print("⏳ Fetching blockchain balances...")
        the_balance = get_solana_balance(the_pubkey)

        # Display Comprehensive Outputs
        print("\n" + "="*60)
        print(f"🔒 {wallet_path_name} WALLET STRUCTURE")
        print(f"   Derivation Path : {derivation_path}")
        if show_secret:
            print(f"   Private b58 String : {the_priv_b58key}")
        print(f"   Public Address  : {the_pubkey}")
        print(f"   Live Balance    : {the_balance}")
        print("="*60)
        print_qr_terminal(f"https://solscan.io/account/{the_pubkey}", the_pubkey)
        return the_priv_b58key 

    except Exception as e:
        print(f"❌ Cryptographic processing failure: {str(e)}")

def get_valid_recipient_address(client, initial_address):
    """
    Validates a recipient address. If it is invalid or a token mint, 
    loops interactively to prompt the user for a correct address instead of crashing.
    """
    current_address = initial_address.strip()
    
    while True:
        # 1. Length & Format Check
        addr_len = len(current_address)
        if addr_len < 32 or addr_len > 44:
            print("\n" + "!" * 70)
            print(f" [!] INVALID ADDRESS LENGTH: {addr_len} characters.")
            print(f"     Pasted Value: {current_address}")
            print("     Solana public keys must be between 32 and 44 characters long.")
            print(" " + "!" * 70)
            current_address = input("\nPlease paste a CORRECT Solana Wallet Address (or type 'exit'): ").strip()
            if current_address.lower() == 'exit':
                raise Exception("Transaction canceled by user.")
            continue

        # 2. Token Mint Address Intercept Check
        try:
            pubkey = Pubkey.from_string(current_address)
            # If this RPC call succeeds, it means the address is a token mint, NOT a wallet!
            response = client.get_token_supply(pubkey)
            if response.value is not None:
                print("\n" + "!" * 70)
                print(" [!] CRITICAL WARNING: THE TARGET ADDRESS IS A TOKEN MINT CONTRACT!")
                print(f"     Target Input: {current_address}")
                print("     You must send funds to a user's WALLET address, not a token contract.")
                print(" " + "!" * 70)
                
                current_address = input("\nPlease paste a CORRECT Solana Wallet Address (or type 'exit'): ").strip()
                if current_address.lower() == 'exit':
                    raise Exception("Transaction canceled by user.")
                continue
        except Exception as e:
            # If get_token_supply fails, it's NOT a mint contract. This means it is safe to use as a recipient wallet!
            if "Transaction canceled" in str(e):
                raise e
            break  # Address is valid, break out of the loop

    return current_address

def verify_token_mint(client, token_mint_addr):
    """
    Verifies that a token mint address is valid and exists on the Solana network.
    Throws a clean exception immediately if it doesn't.
    """
    try:
        mint_pubkey = Pubkey.from_string(token_mint_addr)
        # Attempt to fetch token details to confirm its legitimacy
        mint_account_info = client.get_account_info(mint_pubkey).value
        if mint_account_info is None:
            raise Exception("Account does not exist.")
            
        # Ensure the owner program is either standard SPL or Token-2022
        program_id = mint_account_info.owner
        if program_id not in [TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID]:
            raise Exception("Account is not owned by a token program.")
            
        return mint_pubkey, mint_account_info
    except Exception as e:
        print("\n" + "!" * 70)
        print(" [!] INVALID TOKEN MINT ADDRESS")
        print(f"     The mint address '{token_mint_addr}' is invalid or does not exist on-chain.")
        print(" " + "!" * 70)
        raise Exception(f"Validation Error: Invalid token mint address ({e}).")

def transfer_sol(to_sol_addr, amount_in_sol, sender_pubkey, sender):
    print("=" * 60 + "\nSolana Transfer Script\n" + "=" * 60)
    
    print("[1/7] Connecting RPC...")
    client = Client(RPC_URL)
    print("      RPC connected")
    
    print("[2/7] Running safety checks on destination...")
    # Safe interactive loop update
    validated_to_addr = get_valid_recipient_address(client, to_sol_addr)
    
    print("[3/7] Loading wallet...")
    print(f"      Sender: {sender_pubkey}")
    print(f"      Receiver: {validated_to_addr}")
    
    print("[4/7] Fetching wallet balance...")
    balance = client.get_balance(sender_pubkey).value
    balance_sol = balance / LAMPORTS_PER_SOL
    print(f"      Balance: {balance:,} lamports\tBalance: {balance_sol:.9f} SOL")
    
    print("[5/7] Fetching latest blockhash...")
    blockhash = client.get_latest_blockhash().value.blockhash
    print(f"      Blockhash: {blockhash}")
    
    if USE_MINIMAL_FEE:
        print("[6/7] Setting transaction fee...")
        fee = 5000
        print(f"      Using Minimal Protocol Fee: {fee} lamports ({fee / LAMPORTS_PER_SOL:.9f} SOL)")
    else:
        print("[6/7] Estimating transaction fee dynamically...")
        # 1. Build dummy components only if dynamic estimation is needed
        dummy_ix = transfer(TransferParams(
            from_pubkey=sender_pubkey,
            to_pubkey=Pubkey.from_string(validated_to_addr),
            lamports=1
        ))
        dummy_msg = MessageV0.try_compile(sender_pubkey, [dummy_ix], [], blockhash)

        # 2. Run the safe RPC query block with indentation fixes applied
        try:
            fee = client.get_fee_for_message(dummy_msg).value
            if fee is None or fee == 0:
                fee = 5000  # Safe protocol floor fallback
        except Exception:
            fee = 5000  # Resilient network fallback

        print(f"      Using Fee: {fee} lamports ({fee / LAMPORTS_PER_SOL:.9f} SOL)")

    max_sendable = balance - fee
    if max_sendable <= 0:
        raise Exception("Insufficient balance for fee")
        
    requested_lamports = int(float(amount_in_sol) * LAMPORTS_PER_SOL)
    if requested_lamports >= max_sendable:
        send_amount = max_sendable
        print("      Requested amount exceeds max\tUsing MAX transferable amount!")
    else:
        send_amount = requested_lamports
        print("      Using requested amount")
        
    print("[7/7] Building + sending transaction...")
    ix = transfer(TransferParams(
        from_pubkey=sender_pubkey, 
        to_pubkey=Pubkey.from_string(validated_to_addr), 
        lamports=send_amount
    ))
    msg = MessageV0.try_compile(sender_pubkey, [ix], [], blockhash)
    tx = VersionedTransaction(msg, [sender])
    resp = client.send_transaction(tx, opts=TxOpts(skip_preflight=False))
    signature = resp.value
    
    print("\n|" + "=" * 10 + "\t> TRANSFER SUCCESS!")
    print(f"Signature: {signature}")
    print(f"https://solscan.io/tx/{signature}")
    print("=" * 60)
    return signature

def transfer_spl_token(to_sol_addr, token_mint_addr, amount, sender_pubkey, sender):
    print("=" * 60 + "\nSolana Token Transfer Script (SPL & Token-2022)\n" + "=" * 60)

    print("[1/7] Connecting RPC...")
    client = Client(RPC_URL)
    print("      RPC connected")

    print("[2/7] Running safety checks on token mint...")
    mint_pubkey, mint_account_info = verify_token_mint(client, token_mint_addr)

    print("[3/7] Running safety checks on destination wallet...")
    validated_to_addr = get_valid_recipient_address(client, to_sol_addr)

    print("[4/7] Loading wallet configurations...")
    receiver_pubkey = Pubkey.from_string(validated_to_addr)

    program_id = mint_account_info.owner
    standard_name = "Token-2022" if program_id == TOKEN_2022_PROGRAM_ID else "Standard SPL"
    print(f"      Detected Token Standard: {standard_name}")

    mint_info = client.get_token_supply(mint_pubkey).value
    decimals = mint_info.decimals

    sender_ata = get_associated_token_address(sender_pubkey, mint_pubkey, token_program_id=program_id)
    receiver_ata = get_associated_token_address(receiver_pubkey, mint_pubkey, token_program_id=program_id)

    try:
        token_balance_resp = client.get_token_account_balance(sender_ata).value
        sender_token_balance = int(token_balance_resp.amount)
        print(f"      Sender Token Balance: {token_balance_resp.ui_amount}")
    except Exception:
        raise Exception("Sender does not own an active token account for this mint.")

    print("[5/7] Preparing Instructions & Blockhash...")
    blockhash = client.get_latest_blockhash().value.blockhash
    instructions = []

    receiver_account_info = client.get_account_info(receiver_ata).value
    if receiver_account_info is None:
        print("      Receiver token account missing. Generating creation instruction...")
        create_ata_ix = create_associated_token_account(
            payer=sender_pubkey,
            owner=receiver_pubkey,
            mint=mint_pubkey,
            token_program_id=program_id
        )
        instructions.append(create_ata_ix)

    raw_amount = int(float(amount) * (10 ** decimals))
    if raw_amount > sender_token_balance:
        raise Exception(f"Insufficient token balance. Available: {token_balance_resp.ui_amount}")

    transfer_ix = transfer_checked(
        TransferCheckedParams(
            program_id=program_id,
            source=sender_ata,
            mint=mint_pubkey,
            dest=receiver_ata,
            owner=sender_pubkey,
            amount=raw_amount,
            decimals=decimals
        )
    )
    instructions.append(transfer_ix)

    # ------------------ RESTORED FEE STEP HANDLING HERE ------------------
    if USE_MINIMAL_FEE:
        print("[6/7] Setting transaction fee...")
        fee = 5000
        print(f"      Using Minimal Protocol Fee: {fee} lamports ({fee / LAMPORTS_PER_SOL:.9f} SOL)")
    else:
        print("[6/7] Estimating transaction fee dynamically...")
        dummy_msg = MessageV0.try_compile(
            payer=sender_pubkey,
            instructions=instructions,
            address_lookup_table_accounts=[],
            recent_blockhash=blockhash,
        )
        try:
            fee = client.get_fee_for_message(dummy_msg).value
            if fee is None or fee == 0:
                fee = 5000
        except Exception:
            fee = 5000
        print(f"      Using Fee: {fee} lamports ({fee / LAMPORTS_PER_SOL:.9f} SOL)")

    # Explicitly check native SOL balance to cover the fee
    sol_balance = client.get_balance(sender_pubkey).value
    if sol_balance < fee:
        raise Exception(f"Insufficient SOL balance for fees. Required: {fee} lamports, Available: {sol_balance} lamports")
    # ----------------------------------------------------------------------

    print("[7/7] Building + sending transaction...")
    msg = MessageV0.try_compile(sender_pubkey, instructions, [], blockhash)
    tx = VersionedTransaction(msg, [sender])
    resp = client.send_transaction(tx, opts=TxOpts(skip_preflight=False))
    signature = resp.value

    print("\n|" + "=" * 10 + "\t> TOKEN TRANSFER SUCCESS!")
    print(f"Signature: {signature}")
    print(f"https://solscan.io/tx/{signature}") # Also fixed your solscan URL formatting string error here
    print("=" * 60)
    return signature

def list_spl_balances(sender_pubkey):
    token_list = []
    print("=" * 60 + "\nSolana Portfolio Inventory (Full Token Balance Scan)\n" + "=" * 60)

    # Standardize dictionary keys to lowercase for foolproof comparisons
    known_tokens_lower = {mint.lower(): name for mint, name in KNOWN_TOKEN_DICT.items()}

    print("[1/2] Connecting RPC...")
    client = Client(RPC_URL)

    print(f"      Wallet: {sender_pubkey}")
    print("[2/2] Scanning decentralized token registries...")

    # 2. Setup structural grid table layouts
    print("\n" + "-" * 115)
    print(f"{'Token Name':<12} | {'Token Type':<12} | {'Balance':<18} | {'Token Mint Address'}")
    print("-" * 115)

    # 3. Pull Native SOL Asset Balance
    try:
        native_sol_lamports = client.get_balance(sender_pubkey).value
        native_sol_balance = native_sol_lamports / LAMPORTS_PER_SOL
        print(f"{'SOL':<12} | {'Native':<12} | {native_sol_balance:<18.6f} | {'N/A (Native Blockchain Currency)'}")
        token_list.append({"name":'SOL', "mint": 'Native', "balance":native_sol_balance, "type":"Native"})
    except Exception as e:
        print(f"[!] Warning: Failed to parse native SOL tracking data: {e}")

    # 4. Pull both Standard SPL and Token-2022 Accounts
    program_targets = [
        {"id": TOKEN_PROGRAM_ID, "label": "SPL"},
        {"id": TOKEN_2022_PROGRAM_ID, "label": "Token-2022"}
    ]

    has_tokens = False
    for target in program_targets:
        try:
            opts = TokenAccountOpts(program_id=target["id"])
            resp = client.get_token_accounts_by_owner(sender_pubkey, opts).value

            if resp:
                for account in resp:
                    try:
                        # Extract data layout parameters cleanly
                        parsed_info = client.get_account_info_json_parsed(account.pubkey).value.data.parsed
                        mint_addr = parsed_info['info']['mint']
                        ui_amount = float(parsed_info['info']['tokenAmount']['uiAmount'] or 0)

                        # Only report assets currently held in the specific account address
                        if ui_amount > 0:
                            has_tokens = True

                            # Perform case-safe name lookups using the mapping dictionary
                            token_name = known_tokens_lower.get(mint_addr.lower(), "UNKNOWN")
                            token_type = target["label"]

                            print(f"{token_name:<12} | {token_type:<12} | {ui_amount:<18.6f} | {mint_addr}")
                            token_list.append({"name":token_name, "mint": mint_addr, "balance":ui_amount, "type":token_type})

                    except Exception:
                        continue
        except Exception as err:
            print(f"[!] Warning: Failed to query account metadata for {target['label']}: {err}")

    if not has_tokens:
        print(f"{' ':20} [ No active SPL or Token-2022 sub-accounts detected ]")

    print("-" * 115)
    print("=" * 60)
    return token_list

def create_keypair(user_input_raw, user_derive_path):
    # 1. Safe credential handling
    if user_input_raw == "#":
        input_raw = scan_qr_from_camera()
        if not input_raw:
            print("[!] No QR Code detected!")
            sys.exit(1)
    else: 
        input_raw = user_input_raw

    priv_key_b58 = process_to_keypair(input_raw, user_derive_path or "LEDGER")

    if not priv_key_b58:
        print("[!] Private key cannot be empty.")
        sys.exit(1)
        
    return Keypair.from_bytes(b58decode(priv_key_b58))


def main():
    print("=" * 60)
    print("        Semaj's SOLANA WALLET INTERACTIVE CLI MANAGER")
    print("=" * 60)
    
    if len(sys.argv) > 1 and sys.argv[1].upper() == 'ENCRYPT':
        print("*" * 60)
        print("        For string encryption only!")
        print("*" * 60)
        encrypt_workflow()
        exit(0)

    user_derive_path = None
    if len(sys.argv) > 1 and 'path=' in sys.argv[1]:
        # NOTE: format : "path=PHANTOM" or "path=PHANTOM_1" for 2nd, _2 for 3rd
        user_derive_path = sys.argv[1][5:]

    user_input_raw = input('Enter An Integer, or "#" for Scanning a QR Code, or #${English words} for Seed Phrases, or #!{input} to eval({input}) :\n')

    sender = create_keypair(user_input_raw, user_derive_path)
    sender_pubkey = sender.pubkey()
    print(f"[✓] Wallet Loaded: {sender_pubkey}\n")
    
    while True:
        print("\n" + "=" * 50)
        print(" SELECT AN ACTION:")
        print(" 1. List all SPL Token Balances")
        print(" 2. Transfer SOL [Manual Input]")
        print(" 3. Transfer SOL [Scan Camera QR Code]")
        print(" 4. Transfer SPL Tokens [Manual Input]")
        print(" 5. Transfer SPL Tokens [Scan Camera QR Code]")
        print(" 0. Exit")
        print("=" * 50)

        choice = input("Enter option (0-5): ").strip()

        if choice == "1":
            list_spl_balances(sender_pubkey)

        elif choice in ["2", "3"]:
            print("\n" + "+" * 60)
            print(" INITIATING NATIVE SOL TRANSFER")
            print("+" * 60)

            # Dynamic choice evaluation hook handles input routing
            if choice == "3":
                target_sol_address = scan_qr_from_camera()
                if not target_sol_address:
                    print("[!] No valid address extracted from QR scan. Aborting.")
                    continue
            else:
                target_sol_address = input('Enter the TARGET SOLANA ADDRESS:\n').strip()

            if not target_sol_address:
                print("[!] Target address cannot be empty.")
                continue

            try:
                requested_amount_sol = float(input('Enter the AMOUNT in SOL:\n').strip())
                if requested_amount_sol <= 0:
                    print("[!] Amount must be greater than 0.")
                    continue
            except ValueError:
                print("[!] Invalid amount entered.")
                continue

            print("\n" + "!" * 60)
            print(f" REVIEW TRANSACTION:")
            print(f"  - Action: Sending SOL")
            print(f"  - Amount: {requested_amount_sol} SOL")
            print(f"  - Target: {target_sol_address}")
            print(" " + "!" * 60)
            print("!!! This step CANNOT be undone, PLEASE double check details !!!")
            
            yes_or_no = input("Type 'yes' to confirm and execute: ").strip().lower()
            if yes_or_no == "yes":
                try:
                    transfer_sol(target_sol_address, requested_amount_sol, sender_pubkey, sender)
                except Exception as e:
                    print(f"\n[!] Execution Error: {e}")
            else:
                print("Transaction Cancelled!")
                
        elif choice in ["4", "5"]:
            print("\n" + "+" * 60)
            print(" INITIATING SPL TOKEN TRANSFER")
            print("+" * 60)

            # Dynamic choice evaluation hook handles input routing
            if choice == "5":
                target_sol_address = scan_qr_from_camera()
                if not target_sol_address:
                    print("[!] No valid address extracted from QR scan. Aborting.")
                    continue
            else:
                target_sol_address = input("Enter the RECIPIENT's Main SOLANA WALLET ADDRESS:\n").strip()

            if not target_sol_address:
                print("[!] Target address cannot be empty.")
                continue

            # Create a user-friendly string for the prompt: "USDC,CBBTC,USDT,JitoSOL,WSOL"
            known_tokens_prompt = ','.join(KNOWN_TOKEN_DICT_REVERSE.keys())

            token_mint_addr_input = input(f'Enter the SPL TOKEN MINT ADDRESS or Token Name ({known_tokens_prompt}):\n').strip()

            if not token_mint_addr_input:
                print("[!] Token Mint address cannot be empty.")
                continue

            # Check if input is likely a shortcut name or a full public key address
            if len(token_mint_addr_input) <= 20:
                # Force user input to UPPERCASE to guarantee a match against your keys
                token_mint_addr = KNOWN_TOKEN_DICT_REVERSE.get(token_mint_addr_input.upper(), token_mint_addr_input)
            else:
                # Safely assign the raw address if the string is long (over 20 characters)
                token_mint_addr = token_mint_addr_input

            try:
                requested_amount_tokens = float(input('Enter the AMOUNT of tokens:\n').strip())
                if requested_amount_tokens <= 0:
                    print("[!] Amount must be greater than 0.")
                    continue
            except ValueError:
                print("[!] Invalid amount entered.")
                continue
                
            print("\n" + "!" * 60)
            print(f" REVIEW TRANSACTION:")
            print(f"  - Action: Sending SPL Token")
            print(f"  - Mint:   {token_mint_addr}")
            print(f"  - Amount: {requested_amount_tokens}")
            print(f"  - Target: {target_sol_address} (System will resolve ATA automatically)")
            print(" " + "!" * 60)
            print("!!! This step CANNOT be undone, PLEASE double check details !!!")
            
            yes_or_no = input("Type 'yes' to confirm and execute: ").strip().lower()
            if yes_or_no == "yes":
                try:
                    transfer_spl_token(target_sol_address, token_mint_addr, requested_amount_tokens, sender_pubkey, sender)
                except Exception as e:
                    print(f"\n[!] Execution Error: {e}")
            else:
                print("Transaction Cancelled!")
                
        elif choice == "0":
            print("\nExiting. Goodbye!")
            break
        else:
            print("[!] Invalid option selected. Please enter a choice between 0 and 5.")

if __name__ == "__main__":
    main()

