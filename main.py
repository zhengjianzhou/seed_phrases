#!/usr/bin/env python3
# -*- coding: utf-8 -*-

### requirements.txt
# pip3 install mnemonic qrcode pillow kivy pynacl
#
### To make an App on macOS / Windows using pyinstaller
# pip3 install pyinstaller
# pyinstaller --onefile --windowed --icon=icon.icns --add-data "main.py:." main.py
#
### To use buildozer for android
# buildozer android debug
#
### To use kivy-ios for iOS
# brew install autoconf automake libtool pkg-config
# pip install kivy-ios
# toolchain build python3 kivy
# more steps on ChatGPT

import sys, os, math
from io import BytesIO
import hashlib
import hmac
import binascii
import struct
from mnemonic import Mnemonic
import qrcode
from datetime import datetime
from nacl.signing import SigningKey

DICT_DERIVATIONS = {
    "Ledger" : "44'/501'/0'",
    "Phantom" : "44'/501'/0'/0'",
}

def generate_qrcode(text: str) -> None:
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=1, border=1)
    qr.add_data(text)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    rows = len(matrix)
    for y in range(0, rows, 2):
        top = matrix[y]
        bottom = matrix[y + 1] if y + 1 < rows else [False] * len(top)
        line = ""
        for t, b in zip(top, bottom):
            if t and b:
                line += "█"   # Full block
            elif t and not b:
                line += "▀"   # Upper half block
            elif not t and b:
                line += "▄"   # Lower half block
            else:
                line += " "   # Space
        print(line)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic_norm = mnemonic.strip().encode("utf-8")
    salt = b"mnemonic" + passphrase.encode("utf-8")
    seed = hashlib.pbkdf2_hmac("sha512", mnemonic_norm, salt, 2048)
    return seed  # 64 bytes

def slip10_derive_master_key(seed: bytes) -> (bytes, bytes):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def slip10_derive_child(parent_key: bytes, parent_pub_key: bytes, parent_chain_code: bytes, index: int, hardened: bool) -> (bytes, bytes):
    assert 0 <= index < 2**31, "Index must be in [0, 2^31)"
    if hardened:
        h_index = index + (1 << 31)
        data = b"\x00" + parent_key + h_index.to_bytes(4, "big")
    else:
        h_index = index
        data = parent_pub_key + h_index.to_bytes(4, "big")
    I = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    return I[:32], I[32:]

_q = 2**255 - 19
_d = (-121665 * pow(121666, _q - 2, _q)) % _q
_Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_By = 46316835694926478169428394003475163141307993866256225615783033603165251855960
_I = pow(2, (_q - 1) // 4, _q)

def _edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom_x = (1 + (_d * x1 * x2 * y1 * y2) % _q) % _q
    denom_y = (1 - (_d * x1 * x2 * y1 * y2) % _q) % _q
    inv_denom_x = pow(denom_x, _q - 2, _q)
    inv_denom_y = pow(denom_y, _q - 2, _q)
    x3 = ( (x1 * y2 + x2 * y1) * inv_denom_x ) % _q
    y3 = ( (y1 * y2 + x1 * x2) * inv_denom_y ) % _q
    return (x3, y3)

def _scalar_mult(P, e: int):
    if e == 0:
        return (0, 1)
    Q = _scalar_mult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q

def _point_compress(P):
    x, y = P
    y_bytes = y.to_bytes(32, "little")
    x_bit = x & 1
    y_list = bytearray(y_bytes)
    y_list[31] |= x_bit << 7
    return bytes(y_list)

def ed25519_publickey_from_secret(seed32: bytes) -> bytes:
    h = hashlib.sha512(seed32).digest()
    a_bytes = bytearray(h[:32])
    # Clamp:
    a_bytes[0]  &= 248
    a_bytes[31] &= 63
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")

    # Basepoint:
    B = (_Bx, _By)
    A = _scalar_mult(B, a)
    return _point_compress(A)

_b58_alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(data: bytes) -> str:
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

def derive_solana_keypair_from_mnemonic(mnemonic: str, passphrase: str, derivation_path) -> (str, str):
    # Phantom Default: "44'/501'/0'/0'" ### but Phantom can scan and find Ledger's account, while Ledger will not. Hence default to Ledger's
    # Ledger Default: "44'/501'/0'/0"
    # Ledger Default: derivation_path = [(44, True), (501, True), (0, True), (0, False)]
    p_indices = [(int(i.split("'")[0]), i.endswith("'")) for i in derivation_path.split(r'/')]
    seed_bytes = mnemonic_to_seed(mnemonic, passphrase)  # 64 bytes
    sk_master, cc_master = slip10_derive_master_key(seed_bytes)
    sk, cc = sk_master, cc_master
    signing_key = SigningKey(sk)
    parent_pub_key = signing_key.verify_key.encode()
    for idx, hardened in p_indices:
        sk, cc = slip10_derive_child(sk, parent_pub_key, cc, idx, hardened)
    privkey_seed = sk
    pubkey_bytes = ed25519_publickey_from_secret(privkey_seed)  # 32 bytes
    priv_key_expanded = privkey_seed + pubkey_bytes  # 64 bytes, if you want the full keypair
    pubkey_b58 = base58_encode(pubkey_bytes)

    return priv_key_expanded.hex(), pubkey_b58

global OUTPUT_SEED_LANG
OUTPUT_SEED_LANG = 'english'
LANG_LIST = ('CHINESE_SIMPLIFIED', 'CHINESE_TRADITIONAL', 'CZECH', 'JAPANESE', 'FRENCH', 'ENGLISH', 'SPANISH', 'ITALIAN', 'PORTUGUESE', 'KOREAN')

THE_SYMBOLS = '─│┌┐└┘├┤┬┴┼╱╲╳╵╷'
#THE_SYMBOLS = ' ▀▄█▌▐▖▗▘▙▚▛▜▝▞▟'
HEX_SYMBOL_DICT = dict(zip('0123456789ABCDEF', THE_SYMBOLS))
SYMBOL_HEX_DICT = dict(zip(THE_SYMBOLS, '0123456789ABCDEF'))

def hex2line    (h       ) : return ''.join([HEX_SYMBOL_DICT[i] for i in h])
def line2hex    (l       ) : return ''.join([SYMBOL_HEX_DICT[i] for i in l])
def int2bin     (i,     n) : return bin(i         )[2:].zfill(n)
def hex2bin     (h,     n) : return bin(int(h, 16))[2:].zfill(n)
def to2048      (n       ) : return ([] if n == 0 else to2048(n // 2048) + [n % 2048]) if n else []
def from2048    (idxs    ) : return sum(c * (2048 ** i) for i, c in enumerate(reversed(idxs)))
def wd2effwd    (s,   wdl) : return ([          i.lower()  for i in s if i.lower() in wdl] * 24) [:24]
def wd2idxs     (s,   wdl) : return ([wdl.index(i.lower()) for i in s if i.lower() in wdl] * 24) [:24]
def sha256i     (s       ) : return int(hashlib.sha256(s.encode('utf8')).hexdigest(), 16)
def idxs2eng    (idxs,wdl) : return ' '.join(wdl[i] for i in idxs)
def bits2idxs   (bits    ) : return [int(bits[i:i+11], 2) for i in range(0, len(bits), 11)]
def checksum    (i,     n) : return hex2bin(hashlib.sha256((i%2**n).to_bytes(n//8, byteorder='big')).hexdigest(), 256)[:n//32]  #bip-39
def ient2idxs   (i,     n) : return bits2idxs(int2bin(i%2**n,n)+checksum(i%2**n,n))
def getwordlist (        ) : return Mnemonic(OUTPUT_SEED_LANG).wordlist
def int2seedphs (i,     n) : return idxs2eng(ient2idxs(i%2**n,n), getwordlist())
def int2b58     (i,     n) : return base58_encode(i.to_bytes(n//8, byteorder='big'))
def int2b36     (i       ) : return '0' if i == 0 else int2b36(i // 36).lstrip('0') + '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'[i % 36]
def strhash2b58 (s       ) : return int2b58(sha256i(s), 256)
def splitstr    (s,     n) : return [s[i*n:(i+1)*n] for i in range(len(s)//n + 1)]
def dedup       (s       ) : return (lambda x=set(): ''.join(c for c in s if not (c in x or x.add(c))))()

def b36_checksum(bitstring):
    bit_string_b36 = int2b36(sha256i(bitstring)) # use the last 4 b36 as image convert checksum
    bit_string_b36_checksum = ''.join(sorted(dedup(bit_string_b36)[:4]))
    return bit_string_b36_checksum 

def get256randnum():
    entropy_bytes = os.urandom(32) # Generate 32 bytes (256 bits) of entropy
    entropy_bin = bin(int.from_bytes(entropy_bytes, 'big'))[2:].zfill(256)
    return entropy_bytes, entropy_bin

def seed2entropy(words, n, lang):
    n_words = len(words)
    mw = Mnemonic(lang)
    i_words = from2048(wd2idxs(words, mw.wordlist))
    i_ent = i_words >> (n_words * 11 - n)  # remove checksum
    ent = int2bin(i_ent, n)
    return ent

def genseed(words, s='', additional_int=0, n=256, lang='chinese_simplified', use23wordsonly=False):
    mw = Mnemonic(lang)
    i_words = from2048(wd2idxs(words, mw.wordlist))
    i_words = i_words >> 8  # ">>8" remove part of the last word - only 3 bits needed for 256bit entropy
    i_hash  = (sha256i(s) if s else 0)
    if use23wordsonly:
        i_words = i_words >> 3 << 3  # ">>3<<3" erase remaining 3bit of the 24th word - replace with 000
        i_hash  = i_hash       << 3  # "<<3" to add 000 - to make up for 23word only seedgen logic
    return int2seedphs(i_words + i_hash + additional_int, n)

def process_image(image_path):
    from PIL import Image
    image_size = 16
    img = Image.open(image_path)
    img_bw = img.resize((image_size, image_size), Image.BOX).convert('L').convert('1')
    bits = ''.join('1' if pixel else '0' for pixel in img_bw.getdata())
    return bits

def print_seed_grid(seed_phrase):
    words = seed_phrase.split(' ')
    NCOLS = 5
    nrows = math.ceil(len(words) / 5)
    cols = [str(i) for i in range(1, NCOLS+1)]
    
    max_len = max(len(word) for word in words)
    col_width = max(max_len, NCOLS)  # minimum width
    
    # Box drawing characters
    TL = '┌'  # top left
    TR = '┐'  # top right
    BL = '└'  # bottom left
    BR = '┘'  # bottom right
    HL = '─'  # horizontal line
    VL = '│'  # vertical line
    TJ = '┬'  # top junction
    BJ = '┴'  # bottom junction
    LJ = '├'  # left junction
    RJ = '┤'  # right junction
    CJ = '┼'  # center junction
    
    # Build top border with column labels above it
    col_headers = '    ' + ''.join(f' {c.center(col_width)} ' for c in cols)
    print(col_headers)
    
    # Top border
    top_border = TL + (HL * (col_width + 2))
    for _ in range(NCOLS-1):
        top_border += TJ + (HL * (col_width + 2))
    top_border += TR
    print(top_border)
    
    # Print rows
    for r_idx in range(nrows):
        # Row with labels and words
        row_words = words[r_idx * NCOLS : (r_idx + 1) * NCOLS]
        row_line = f'{VL}'
        for w in row_words:
            row_line += f' {w.center(col_width)} {VL}'
        print(row_line)
        
        # Print separator line after every row except last
        if r_idx < nrows - 1:
            sep_line = LJ + (HL * (col_width + 2))
            for _ in range(NCOLS-1):
                sep_line += CJ + (HL * (col_width + 2))
            sep_line += RJ
            print(sep_line)

    # Bottom border
    bottom_border = BL + (HL * (col_width + 2))
    for _ in range(NCOLS-1):
        bottom_border += BJ + (HL * (col_width + 2))
    bottom_border += BR
    print(bottom_border)

def cli_draw_16x16(bitstring):
    if any(c not in ('0', '1') for c in bitstring):
        raise ValueError("Input string must contain only '0' and '1'.")

    bit_string_b36_checksum = b36_checksum(bitstring)

    black_block, white_block = '⬛', '⬜'
    print("-"*32)
    print("|  "+f'0:{black_block} | 1:{white_block } | Checksum:{bit_string_b36_checksum}'+" |")
    print("-"*32)
    for row in range(16):
        segment = bitstring[row * 16 : (row + 1) * 16]
        line = ''.join(white_block if bit == '1' else black_block for bit in segment)
        print(line)
    print("-"*32)

def cli_get_solana_addr(seed_phrases, passphrase, derivation_path):
    priv_hex, sol_address = derive_solana_keypair_from_mnemonic(seed_phrases, passphrase, derivation_path)
    print(f'==================================')
    print(f'|Address with ' + (f'Passphrase {passphrase}|' if passphrase else 'No passphrase -----|'))
    generate_qrcode(sol_address)
    print(f'Solana Address: {sol_address}')
    print('====== Check Balance on Solscan ======')
    solscan_addr = f'https://solscan.io/account/{sol_address}'
    generate_qrcode(solscan_addr)
    print(solscan_addr)

def main_cli(interactive=False):
    if '-h' in sys.argv or '--help' in sys.argv:
        print(f'Usage:\npython3 {__file__.split(r"/")[-1]} "YourWords" "YourPasscode" "RawBits(upto 256bits)" "nbits", "LanguageOfWords"')
        print(f'Example 1:\npython3 {__file__.split(r"/")[-1]} "我的字符串" "PassCodeX12" 0110011111000000000 256 Chinese_Simplified')
        print(f'Example 2:\npython3 {__file__.split(r"/")[-1]} "abandon good" "PassCdXAB" 0110011111000000000 256 English')
    else:
        if interactive or '-c' in sys.argv or '--cli' in sys.argv:
            nbit = input('Please enter number of bits: Enter for 256:') or '256'
            lang = input('Please enter the source text language: Enter for Simplified_Chinese:') or 'chinese_simplified'
            words = input(f'Please enter the source text (in {lang}): Enter for None:')
            passcode = input('Please enter passcode to be sha256-ed and to be added-on: Enter for None:')
            bit_string = input('Please enter a bitstring (upto 256bit) to be added-on: Enter for None:')
        else:
            args = (sys.argv[1:] + ['', '', '', '', ''])[:5]
            words, passcode, bit_string, nbit, lang = args[:5]
        image_int = int(bit_string,2) if bit_string else 0
        nbit = int(nbit) if nbit else 256
        lang = lang.lower() if lang else 'chinese_simplified'
        words = words if lang.startswith('chinese') else words.split(' ')
        words_eff = wd2effwd(words, Mnemonic(lang).wordlist)
        print( "---> INPUT:", ' '.join(words_eff), passcode, bit_string, nbit, lang)
        print( "BitString Checksum:", b36_checksum(bit_string))
        seed_phrases_old = genseed(words, passcode, image_int, nbit, lang, True )
        seed_phrases_new = genseed(words, passcode, image_int, nbit, lang, False)
        print( "OLD Version->", seed_phrases_old)
        print( "NEW SEED   ->", seed_phrases_new)
        print_seed_grid(seed_phrases_new)
        seed_ent = seed2entropy(seed_phrases_new.split(' '), nbit, 'english')
        print( "NEW SEED Entropy ->", seed_ent)
        cli_draw_16x16(seed_ent)
        pass_hash_b58 = strhash2b58(passcode) if passcode else ''
        pass_hash_b58_sp = splitstr(pass_hash_b58, 8)
        pass_hash_b58_sp_joined = ' '.join(pass_hash_b58_sp)
        print(f"Suggested Passphrase: Passcode.SHA256.Base58: {pass_hash_b58} => {pass_hash_b58_sp_joined}")
        passphrases = input('Please enter 0-5 to show the QRCode for target Solana address (e.g. "0", or "0,1,3", Enter for address with no passphrase):')
        derivation_path = input("Please enter derivation_path to get Solana address (e.g. Ledger:44'/501'/0' Phantom:44'/501'/0'/0' | Enter for default:Ledger) :")
        derivation_path = derivation_path if derivation_path else "44'/501'/0'"
        if passphrases:
            for p in passphrases.replace(',', ' ').split(' '):
                if p.isnumeric() and int(p) in range(len(pass_hash_b58_sp)):
                    cli_get_solana_addr(seed_phrases_new, pass_hash_b58_sp[int(p)], derivation_path)
        else:
            cli_get_solana_addr(seed_phrases_new, '', derivation_path)

if __name__ == "__main__":
    if len(sys.argv[1:]) >= 1:
        main_cli()
    else:
        try:
            import kivy
            from kivy.app import App
            from kivy.uix.boxlayout import BoxLayout
            from kivy.uix.label import Label
            from kivy.uix.textinput import TextInput
            from kivy.uix.dropdown import DropDown
            from kivy.uix.popup import Popup
            from kivy.uix.button import Button
            from kivy.uix.spinner import Spinner
            from kivy.graphics import Color, Rectangle
            from kivy.uix.widget import Widget
            from kivy.core.window import Window
            from kivy.properties import StringProperty
            from kivy.utils import platform
            from kivy.core.image import Image as CoreImage
            from kivy.uix.image import Image as KivyImage
            Window.clearcolor = (1, 1, 1, 1)  # White background
            Window.softinput_mode = 'pan'
            if platform.lower() not in ['android', 'ios']:
                Window.size = (800, 1240)
                Window.left = 200
                Window.top = 0
            import logging
            from kivy.logger import Logger
            from kivy.metrics import dp, sp
            Logger.setLevel(logging.CRITICAL + 1)

            from kivy.core.text import LabelBase, DEFAULT_FONT # Add code
            font_path = r'NotoSansCJK.ttc'
            LabelBase.register(DEFAULT_FONT,font_path)
            from PIL import Image as PILImage
            class PixelPad(Widget):
            
                bitstring = StringProperty('0' * 256)
                seed_phrases = ''
            
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
                    self.rows = 16
                    self.cols = 16
                    self.pixels = [0] * 256
                    self.bind(pos=self.update_canvas, size=self.update_canvas)
                    self.bind(bitstring=self.update_from_string)
            
                def on_size(self, *args):
                    self.height = self.width  # Keep square aspect
            
                def on_touch_down(self, touch):
                    self.handle_touch(touch)
            
                def on_touch_move(self, touch):
                    self.handle_touch(touch)
            
                def handle_touch(self, touch):
                    if not self.collide_point(*touch.pos):
                        return
                    x, y = touch.pos
                    i = int((x - self.x) / (self.width / self.cols))
                    j = int((y - self.y) / (self.height / self.rows))
                    idx = (15-j) * self.cols + i  # left to right, top to bottom
                    if 0 <= idx < 256:
                        self.pixels[idx] = 1 - self.pixels[idx]
                        self.update_canvas()
                        self.bitstring = ''.join(str(b) for b in self.pixels)
            
                def update_canvas(self, *args):
                    self.canvas.clear()
                    with self.canvas:
                        for j in range(self.rows):
                            for i in range(self.cols):
                                idx = j * self.cols + i  # left to right, top to bottom
                                Color(1, 1, 1) if self.pixels[idx] == 1 else Color(0, 0, 0)
                                Rectangle(pos=(self.x + i * self.width / self.cols,
                                               self.y + (15-j) * self.height / self.rows),
                                          size=(self.width / self.cols, self.height / self.rows))
            
                def update_from_string(self, instance, value):
                    if len(value) == 256:
                        self.pixels = [int(ch) for ch in value]
                        self.update_canvas()
            
                def save_image(self):
                    img = PILImage.new('1', (16, 16))
                    img.putdata(self.pixels)
                    img.save('pixel_image.png')
            
                def load_image(self):
                    try:
                        img = PILImage.open('pixel_image.png').convert('1')
                        data = list(img.getdata())
                        self.pixels = [0 if pixel == 0 else 1 for pixel in data]
                        self.bitstring = ''.join(str(b) for b in self.pixels)
                        self.update_canvas()
                    except Exception as e:
                        print("Error loading image:", e)
            
                def clear_image(self):
                    self.pixels = [0] * 256
                    self.bitstring = '0' * 256
                    self.update_canvas()
            
                def generate_random(self):
                    random_bits = bin(int.from_bytes(os.urandom(32), 'big'))[2:].zfill(256)
                    self.bitstring = random_bits
            
            class MainUI(BoxLayout):
                def __init__(self, **kwargs):
                    super().__init__(orientation='vertical', **kwargs)
                    root = BoxLayout(orientation='vertical')
            
                    # Image Input Section
                    box_section = BoxLayout(size_hint=(1, None))
                    box_section.height = Window.width  # Make height equal to width
                    self.pad = PixelPad()
                    box_section.add_widget(self.pad)
                    root.add_widget(box_section)
                    image_box = BoxLayout(orientation='vertical')
                    right_panel = BoxLayout(orientation='vertical')
                    buttons_column = BoxLayout(orientation='horizontal')
                    buttons_column.add_widget(Button(text='Save', on_press=lambda x: self.pad.save_image()))
                    buttons_column.add_widget(Button(text='Load', on_press=lambda x: self.pad.load_image()))
                    buttons_column.add_widget(Button(text='Clear', on_press=lambda x: self.pad.clear_image()))
                    buttons_column.add_widget(Button(text='Random', on_press=lambda x: self.pad.generate_random()))
                    right_panel.add_widget(buttons_column)
                    self.bitstring_input = TextInput(text=self.pad.bitstring, multiline=False)
                    self.bitstring_input.bind(text=self.on_bitstring_change)
                    self.pad.bind(bitstring=self.update_textinput_from_pad)
                    right_panel.add_widget(self.bitstring_input)
                    image_box.add_widget(right_panel)
                    root.add_widget(image_box)

                    # Options (1/4 of width)
                    options_box = BoxLayout(orientation='horizontal')
                    self.nwords_spinner = Spinner(text="24 Words", values=("12 Words", "23 Words(* 24-1)", "24 Words"))
                    self.ilang_spinner = Spinner(text='INPUT: CHINESE_SIMPLIFIED', values=['INPUT: '+l for l in LANG_LIST])
                    self.olang_spinner = Spinner(text='OUTPUT: ENGLISH', values=['OUTPUT: '+l for l in LANG_LIST])
                    options_box.add_widget(self.nwords_spinner)
                    options_box.add_widget(self.ilang_spinner)
                    options_box.add_widget(self.olang_spinner)
                    root.add_widget(options_box)
                    # Text Inputs
                    text_input_box = BoxLayout(orientation='vertical')
                    self.text_phrases = TextInput(hint_text='Text Phrases', multiline=False, font_name=r"NotoSansCJK.ttc", size_hint_y=None, height=dp(24))
                    text_input_box.add_widget(self.text_phrases)
                    self.text_passcode = TextInput(hint_text='Passcode', multiline=False, font_name=r"NotoSansCJK.ttc", size_hint_y=None, height=dp(24))
                    text_input_box.add_widget(self.text_passcode)
                    root.add_widget(text_input_box)
                    generate_box = BoxLayout(orientation='horizontal')
                    generate_box.add_widget(Button(text='Generate Seed Phrases', on_press=self.generate_output))
            
                    # Dropdown setup
                    self.dropdown = DropDown()
                    self.soladdr_select = Button(text='SOL Address')
                    self.soladdr_select.bind(on_release=self.dropdown.open)
                    generate_box.add_widget(self.soladdr_select)
                    root.add_widget(generate_box)
                    
                    # Output Section
                    self.output0 = TextInput(readonly=True, hint_text='Checksum', multiline=False, size_hint_y=None, height=dp(24))
                    self.output1 = TextInput(readonly=True, hint_text='Input Text Phrases', multiline=False, font_name=r"NotoSansCJK.ttc", size_hint_y=None, height=dp(24))
                    self.output2 = TextInput(readonly=True, hint_text='Seed / Entropy', multiline=False, size_hint_y=None, height=dp(24))
                    self.output3 = TextInput(readonly=True, hint_text='Seed Phrases', multiline=True, font_name=r"NotoSansCJK.ttc", size_hint_y=None, height=dp(54))
                    self.output4 = TextInput(readonly=True, hint_text='Seed Phrases Indexed', multiline=True, font_name=r"NotoSansCJK.ttc", size_hint_y=None, height=dp(70))
                    self.output5 = TextInput(readonly=True, hint_text='Pass Phrases', multiline=False, font_name=r"NotoSansCJK.ttc", size_hint_y=None, height=dp(24), halign="center")
                    root.add_widget(self.output0)
                    root.add_widget(self.output1)
                    root.add_widget(self.output2)
                    root.add_widget(self.output3)
                    root.add_widget(self.output4)
                    root.add_widget(self.output5)

                    self.add_widget(root)
            
                def generate_options(self, instance, pass_phrases=''):
                    if pass_phrases:
                        pass_phrases = ' ' + pass_phrases
                    self.dropdown.clear_widgets()
                    self.options =  [i + "|Ledger"  for i in pass_phrases.split(' ')]+[i + "|Phantom" for i in pass_phrases.split(' ')]
                    for opt in self.options:
                        btn = Button(text=opt, size_hint_y=None, height=44)
                        btn.bind(on_release=lambda btn: self.option_selected(btn.text))
                        self.dropdown.add_widget(btn)

                    self.soladdr_select.text = 'SOL Address'

                def option_selected(self, text):
                    self.soladdr_select.text = text
                    self.dropdown.dismiss()
                    self.show_qr_popup(text)

                def show_qr_popup(self, pass_deriv):
                    pass_phrase, device = pass_deriv.split('|')
                    derivation_path = DICT_DERIVATIONS[device]
                    layout = BoxLayout(orientation='vertical')
                    if self.seed_phrases:
                        _, sol_address = derive_solana_keypair_from_mnemonic(self.seed_phrases, pass_phrase, derivation_path)
                        qr1 = self.create_qr_image(sol_address)
                        solscan_addr = f'https://solscan.io/account/\n{sol_address}'
                        qr2 = self.create_qr_image(solscan_addr)

                        layout.add_widget(Label(text=f"Address:\n{sol_address}"))
                        layout.add_widget(KivyImage(texture=qr1.texture))
                        url_label = Label(text=f"Check Balance:\n{solscan_addr}")
                        layout.add_widget(url_label)
                        layout.add_widget(KivyImage(texture=qr2.texture))

                        title_msg = f"Solana Address for {pass_deriv}"
                        popup = Popup(title=title_msg, content=layout,
                                      size_hint=(0.9, 0.9))
                        popup.open()

                def create_qr_image(self, data):
                    qr = qrcode.QRCode(box_size=40, border=2)
                    qr.add_data(data)
                    qr.make(fit=True)
                    img = qr.make_image(fill_color="black", back_color="white")

                    # Convert PIL image to Kivy Image
                    buffer = BytesIO()
                    img.save(buffer, format='PNG')
                    buffer.seek(0)
                    core_img = CoreImage(buffer, ext='png')
                    return core_img

                def on_bitstring_change(self, instance, value):
                    if len(value) == 256 and set(value).issubset({'0', '1'}):
                        self.pad.bitstring = value
            
                def update_textinput_from_pad(self, instance, value):
                    self.bitstring_input.text = value
            
                def generate_output(self, instance):
                    image_bit = self.pad.bitstring
                    word_input_raw = self.text_phrases.text
                    passcode_str_raw = self.text_passcode.text
                    seed_length = self.nwords_spinner.text.split(' ')[0]
                    input_lang = self.ilang_spinner.text.lower().split(' ')[-1]
            
                    global OUTPUT_SEED_LANG 
                    OUTPUT_SEED_LANG = self.olang_spinner.text.lower().split(' ')[-1]
            
                    image_int = int(image_bit,2) if image_bit else 0
            
                    words = word_input_raw.strip().replace(',',' ')
                    for c in [chr(i) for i in range(33, 127) if not chr(i).isalpha()]:
                        words = words.replace(c, ' ')
                    words = words.replace('  ', ' ').replace('  ', ' ')
                    words = words if input_lang.startswith('chinese') else words.split(' ')
                    words_eff = ''.join(wd2effwd(words, Mnemonic(input_lang).wordlist))
                    passcode = passcode_str_raw.strip()
                    nbit = {12:128, 23:256, 24:256}[int(seed_length)]
            
                    if int(seed_length) == 23:
                        self.seed_phrases = genseed(words, passcode, image_int, nbit, input_lang, True)
                    else:
                        self.seed_phrases = genseed(words, passcode, image_int, nbit, input_lang, False)
            
                    pass_hash_b58 = strhash2b58(passcode) if passcode else ''
                    pass_hash_b58_sp = ' '.join(splitstr(pass_hash_b58, 8))
                    indexed_seed_phrases = dict([(i+1, s) for i, s in enumerate(self.seed_phrases.split(' '))])
            
                    bit_string_b36_checksum = b36_checksum(image_bit)
                    self.output0.text = "Image Checksum: "+bit_string_b36_checksum

                    self.output1.text = words_eff
                    eff_entropy = seed2entropy(self.seed_phrases.split(' '), nbit, OUTPUT_SEED_LANG)
                    self.output2.text = eff_entropy
                    self.output3.text = self.seed_phrases
                    self.output4.text = f'{indexed_seed_phrases}'
                    self.output5.text = pass_hash_b58_sp
                    self.generate_options(instance, pass_hash_b58_sp)

            class MyApp(App):
                def build(self):
                    self.title = "Semaj's Seed Phrase Generator"
                    return MainUI()
            
            MyApp().run()
        except:
            main_cli(True)

