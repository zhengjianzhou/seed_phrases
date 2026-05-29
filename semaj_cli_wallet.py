#!/usr/bin/env python3
#
# A helper CLI tool to generate a solana address - Semaj.Gnehz 2026/05/29
#
import io
import os
import sys
import hashlib
import qrcode
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from mnemonic import Mnemonic
from solana.rpc.api import Client

from solders.system_program import transfer, TransferParams
from solders.message import MessageV0
from solders.transaction import VersionedTransaction
from solana.rpc.types import TxOpts
from base58 import b58decode

RPC_URL = "https://api.mainnet-beta.solana.com"
LAMPORTS_PER_SOL = 1_000_000_000

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
def int2b58     (i,     n) : return base58_encode(i.to_bytes(n//8, byteorder='big'))
def int2b36     (i       ) : return '0' if i == 0 else int2b36(i // 36).lstrip('0') + '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[i % 36]
def strhash2b58 (s       ) : return int2b58(sha256i(s), 256)
def splitstr    (s,     n) : return [s[i*n:(i+1)*n] for i in range(len(s)//n + 1)]
def dedup       (s       ) : return (lambda x=set(): ''.join(c for c in s if not (c in x or x.add(c))))()
def cn2int      (cn      ): return from2048(wd2idxs(cn, Mnemonic('chinese_simplified').wordlist))

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

def process_to_keypairs(user_input, derivation_paths={"LEDGER": "m/44'/501'/0'", "PHANTOM": "m/44'/501'/0'/0'"}):
    wallet_priv_b58s = {}
    """Parses inputs, converts binary entropy to mnemonics, and derives keys."""
    cleaned_input = str(user_input).strip()
    if cleaned_input.startswith('#!'):
        cleaned_input = str(eval(cleaned_input[2:]))
        print(f"💡 Evaluated Input : {cleaned_input}")
    if cleaned_input.isdigit():
        cleaned_input = int2seedphs(int(cleaned_input), 256)
        print(f"💡 Translated Into Seed Phrases : {cleaned_input}")
    mnemo = Mnemonic("english")

    try:
        if len(cleaned_input.split()) in [12, 15, 18, 21, 24]:
            if not mnemo.check(cleaned_input):
                print("❌ Invalid BIP39 mnemonic phrase check failed.")
                return
            master_seed = mnemo.to_seed(cleaned_input)
        else:
            print("❌ Unsupported input string format structure.")
            return

        # 2. DEFINE DERIVATION PATH LAYOUTS
        for wallet_name, derivation_path in derivation_paths.items():

            # 3. DERIVE KEYPAIRS AND FETCH LIVE BALANCES
            the_keypair = Keypair.from_seed_and_derivation_path(master_seed, derivation_path)

            the_pubkey = the_keypair.pubkey()
            the_priv_b58key = str(the_keypair)
            wallet_priv_b58s[wallet_name] = the_priv_b58key 

            print("⏳ Fetching blockchain balances...")
            the_balance = get_solana_balance(the_pubkey)

            # Display Comprehensive Outputs
            print("\n" + "="*60)
            print(f"🔒 {wallet_name} WALLET STRUCTURE")
            print(f"   Derivation Path : {derivation_path}")
            print(f"   Private b58 String : {the_priv_b58key}")
            print(f"   Public Address  : {the_pubkey}")
            print(f"   Live Balance    : {the_balance}")
            print("="*60)
            print_qr_terminal(f"https://solscan.io/account/{the_pubkey}", the_pubkey)
        return wallet_priv_b58s

    except Exception as e:
        print(f"❌ Cryptographic processing failure: {str(e)}")

def transfer_sol(to_account, amount_in_sol, priv_key_b58):
    print("=" * 60 + "\nSolana Transfer Script\n" + "=" * 60)
    print("[1/7] Connecting RPC...")
    client = Client(RPC_URL)
    print("      RPC connected")
    print("[2/7] Loading wallet...")
    sender = Keypair.from_bytes(b58decode(priv_key_b58))
    sender_pubkey = sender.pubkey()
    print(f"      Sender: {sender_pubkey}")

    print("[3/7] Fetching wallet balance...")
    balance = client.get_balance(sender_pubkey).value
    balance_sol = balance / LAMPORTS_PER_SOL
    print(f"      Balance: {balance:,} lamports\tBalance: {balance_sol:.9f} SOL")

    print("[4/7] Fetching latest blockhash...")
    blockhash = client.get_latest_blockhash().value.blockhash
    print(f"      Blockhash: {blockhash}")

    print("[5/7] Estimating transaction fee...")
    dummy_ix = transfer(TransferParams(from_pubkey=sender_pubkey, to_pubkey=Pubkey.from_string(TO_ADDRESS), lamports=1,))
    dummy_msg = MessageV0.try_compile(payer=sender_pubkey, instructions=[dummy_ix], address_lookup_table_accounts=[], recent_blockhash=blockhash,)
    fee = client.get_fee_for_message(dummy_msg).value
    print(f"      Estimated Fee: {fee} lamports\tEstimated Fee: {fee / LAMPORTS_PER_SOL:.9f} SOL")
    max_sendable = balance - fee
    if max_sendable <= 0: raise Exception("Insufficient balance for fee")

    requested_lamports = int(REQUESTED_AMOUNT_SOL * LAMPORTS_PER_SOL)
    print("[6/7] Determining transfer amount...")
    if requested_lamports >= max_sendable:
        send_amount = max_sendable
        print("      Requested amount exceeds max\tUsing MAX transferable amount!")
    else:
        send_amount = requested_lamports
        print("      Using requested amount")
    print(f"      Sending: {send_amount:,} lamports\tSending: {send_amount / LAMPORTS_PER_SOL:.9f} SOL")
    
    remaining = balance - send_amount - fee
    print(f"      Remaining after tx: {remaining} lamports")
    
    print("[7/7] Building + sending transaction...")
    ix = transfer(TransferParams(from_pubkey=sender_pubkey, to_pubkey=Pubkey.from_string(TO_ADDRESS), lamports=send_amount,))
    msg = MessageV0.try_compile(payer=sender_pubkey, instructions=[ix], address_lookup_table_accounts=[], recent_blockhash=blockhash,)
    tx = VersionedTransaction(msg, [sender])
    
    resp = client.send_transaction(tx, opts=TxOpts(skip_preflight=False))
    signature = resp.value
    
    print("\n|" + "=" * 10 + "\t> TRANSFER SUCCESS!")
    print(f"Signature: {signature}")
    print(f"https://solscan.io/tx/{signature}")
    print("=" * 60)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # PRINT OUT KEY/ADDRESS ONLY
        user_input = input('Enter Seed Phrases, An Integer, or #!{input} to eval({input}) :\n')
        priv_key_b58s = process_to_keypairs(user_input, {"LEDGER": "m/44'/501'/0'", "PHANTOM": "m/44'/501'/0'/0'"})
        exit(0)
    
    if len(sys.argv) == 2 and sys.argv[1].lower() in ["transfersol", "soltransfer"]:
        # PRINT OUT KEY/ADDRESS AND DO SOL TRANSFER
        user_input = input('Enter Seed Phrases, An Integer, or #!{input} to eval({input}) :\n')
        PRIVATE_KEY_B58 = process_to_keypairs(user_input, {"LEDGER": "m/44'/501'/0'"})["LEDGER"]
        print("\n" + "+"*60)
        TO_ADDRESS = input('Enter the TARGET SOLANA-ADDRESS :\n').strip()
        REQUESTED_AMOUNT_SOL = input('Enter the AMOUNT in SOL :\n').strip()
        yes_or_no = input(f"Transferring {REQUESTED_AMOUNT_SOL} SOL to Address: {TO_ADDRESS}\n!!! This step CANNOT be undone, PLEASE double check before proceed !!!\nPlease type 'yes' to continue: ").strip()
 
        if yes_or_no == "yes":
            REQUESTED_AMOUNT_SOL = REQUESTED_AMOUNT_SOL
            transfer_sol(TO_ADDRESS, REQUESTED_AMOUNT_SOL, PRIVATE_KEY_B58)
        else:
            print("Transaction Cancelled!")
        exit(0)


    if len(sys.argv) == 2 and sys.argv[1].lower() in ["other", "manual"]:
        # DO SOL TRANSFER WITH A B58 KEY
        print("\n" + "="*60)
        PRIVATE_KEY_B58 = "YOUR_BASE58_PRIVATE_KEY"
        TO_ADDRESS = "TARGET_SOL_ADDRESS"
        REQUESTED_AMOUNT_SOL = 0.001
        transfer_sol(TO_ADDRESS, REQUESTED_AMOUNT_SOL, PRIVATE_KEY_B58)
        exit(0)

    if len(sys.argv) >= 2:
        print("\n" + "="*60)
        print("Usage examples:")
        print(f"python3 {sys.argv[0]}              # for Key/Address generation only")
        print(f"python3 {sys.argv[0]} soltransfer  # for Key/Address generation and SOL transfer!!!")
        print(f"python3 {sys.argv[0]} manual       # for manually hardcoded address/amount SOL transfer!!!")
        print("\n" + "="*60)
        exit(0)

### eval example
#! (cn2int("爱在人海")>>8) + sha256i("ABC") ###etc. +{whatever number you want it to be!}
