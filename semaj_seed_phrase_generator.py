#!/usr/bin/env python3
# -*- coding: utf-8 -*-

### To make it a runnable file on Mac / Windows using pyinstaller
# pip3 install mnemonic base58 base36 pillow pyinstaller
# pyinstaller --onefile --windowed --icon=icon.icns --add-data "semaj_seed_phrase_generator.py:." semaj_seed_phrase_generator.py

import hashlib, mnemonic, base58, base36, sys, os, math
from datetime import datetime

global OUTPUT_SEED_LANG
OUTPUT_SEED_LANG = 'english'

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
def getwordlist (        ) : return mnemonic.Mnemonic(OUTPUT_SEED_LANG).wordlist
def int2seedphs (i,     n) : return idxs2eng(ient2idxs(i%2**n,n), getwordlist())
def int2b58     (i       ) : return base58.b58encode_int(i).decode('utf-8')
def int2b36     (i       ) : return base36.dumps(i).upper()
def strhash2b58 (s       ) : return int2b58(sha256i(s))
def splitstr    (s,     n) : return [s[i*n:(i+1)*n] for i in range(len(s)//n + 1)]
def dedup       (s       ) : return (lambda x=set(): ''.join(c for c in s if not (c in x or x.add(c))))()

def get256randnum():
    entropy_bytes = os.urandom(32) # Generate 32 bytes (256 bits) of entropy
    entropy_bin = bin(int.from_bytes(entropy_bytes, 'big'))[2:].zfill(256)
    return entropy_bytes, entropy_bin

def seed2entropy(words, n, lang):
    n_words = len(words)
    mw = mnemonic.Mnemonic(lang)
    i_words = from2048(wd2idxs(words, mw.wordlist))
    i_ent = i_words >> (n_words * 11 - n)  # remove checksum
    ent = int2bin(i_ent, n)
    return ent

def genseed(words, s='', additional_int=0, n=256, lang='chinese_simplified', use23wordsonly=False):
    mw = mnemonic.Mnemonic(lang)
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

    bit_string_b36 = int2b36(sha256i(bitstring)) # use the last 4 b58 as image convert checksum
    bit_string_b36_checksum = ''.join(sorted(dedup(bit_string_b36)[:4]))

    black_block, white_block = '⬛', '⬜'
    print("-"*32)
    print("|  "+f'0:{black_block} | 1:{white_block } | Checksum:{bit_string_b36_checksum}'+" |")
    print("-"*32)
    for row in range(16):
        segment = bitstring[row * 16 : (row + 1) * 16]
        line = ''.join(white_block if bit == '1' else black_block for bit in segment)
        print(line)
    print("-"*32)

def main_cli():
    if '-h' in sys.argv or '--help' in sys.argv:
        print(f'Usage:\npython3 {__file__.split(r"/")[-1]} "YourWords" "YourPasscode" "RawBits(upto 256bits)" "nbits", "LanguageOfWords"')
        print(f'Example 1:\npython3 {__file__.split(r"/")[-1]} "我的字符串" "PassCodeX12" 0110011111000000000 256 Chinese_Simplified')
        print(f'Example 2:\npython3 {__file__.split(r"/")[-1]} "abandon good" "PassCdXAB" 0110011111000000000 256 English')
    else:
        if '-c' in sys.argv or '--cli' in sys.argv:
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
        words_eff = wd2effwd(words, mnemonic.Mnemonic(lang).wordlist)
        print( "---> INPUT:", ' '.join(words_eff), passcode, bit_string, nbit, lang)
        seed_phrases_old = genseed(words, passcode, image_int, nbit, lang, True )
        seed_phrases_new = genseed(words, passcode, image_int, nbit, lang, False)
        print( "OLD Version->", seed_phrases_old)
        print( "NEW SEED   ->", seed_phrases_new)
        print_seed_grid(seed_phrases_new)
        seed_ent = seed2entropy(seed_phrases_new.split(' '), nbit, 'english')
        print( "NEW SEED Entropy ->", seed_ent)
        cli_draw_16x16(seed_ent)
        pass_hash_b58 = strhash2b58(passcode) if passcode else ''
        pass_hash_b58_sp = ' '.join(splitstr(pass_hash_b58, 8))
        print(f"Suggested Passphrase: Passcode.SHA256.Base58: {pass_hash_b58} => {pass_hash_b58_sp}")

def main_ui():
    import tkinter as tk
    from tkinter import filedialog

    ### tkinter ui main function
    CELL_SIZE = 10
    GRID_SIZE = 16
    class DrawingPad(tk.Frame):
        def __init__(self, master=None, saved_after_func=None, **kwargs):
            super().__init__(master, **kwargs)
    
            self.saved_after_func = saved_after_func 
            self.canvas = tk.Canvas(self, width=CELL_SIZE*GRID_SIZE, height=CELL_SIZE*GRID_SIZE, bg='gray')
            self.canvas.grid(row=0, column=0, columnspan=2)
    
            self.save_button = tk.Button(self, text="Save", command=self.save_image)
            self.save_button.grid(row=1, column=0, pady=5, sticky="ew")
    
            self.clear_button = tk.Button(self, text="Clear", command=self.clear)
            self.clear_button.grid(row=1, column=1, pady=5, sticky="ew")
    
            self.pixels = [[0 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)]
    
            self.canvas.bind("<B1-Motion>", self.draw)
            self.canvas.bind("<Button-1>", self.draw)
            self.canvas.bind("<B3-Motion>", self.erase)
            self.canvas.bind("<Button-3>", self.erase)
    
            self.draw_grid()
    
        def draw_grid(self):
            for i in range(GRID_SIZE):
                for j in range(GRID_SIZE):
                    x0 = j * CELL_SIZE
                    y0 = i * CELL_SIZE
                    x1 = x0 + CELL_SIZE
                    y1 = y0 + CELL_SIZE
                    self.canvas.create_rectangle(x0, y0, x1, y1, outline='gray', fill='black')
    
        def draw(self, event):
            self.set_pixel(event, color="white", value=1)
    
        def erase(self, event):
            self.set_pixel(event, color="black", value=0)
    
        def load_all_pixel(self, image_bit_string):
            self.clear()
            pixels = [(i%16, i//16, c) for i,c in enumerate(image_bit_string)]
            for col,row,c in pixels:
                if 0 <= row < GRID_SIZE and 0 <= col < GRID_SIZE:
                    self.pixels[row][col] = int(c)
                    x0 = col * CELL_SIZE
                    y0 = row * CELL_SIZE
                    x1 = x0 + CELL_SIZE
                    y1 = y0 + CELL_SIZE
                    self.canvas.create_rectangle(x0, y0, x1, y1, outline='gray', fill=('white' if c=='1' else 'black'))
            
        def set_pixel(self, event, color, value):
            col = event.x // CELL_SIZE
            row = event.y // CELL_SIZE
            if 0 <= row < GRID_SIZE and 0 <= col < GRID_SIZE:
                self.pixels[row][col] = value
                x0 = col * CELL_SIZE
                y0 = row * CELL_SIZE
                x1 = x0 + CELL_SIZE
                y1 = y0 + CELL_SIZE
                self.canvas.create_rectangle(x0, y0, x1, y1, outline='gray', fill=color)
    
        def save_image(self):
            from PIL import Image
            filename = os.path.join(os.path.expanduser("~"), "Downloads", "SeedImage_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".png")
            img = Image.new('1', (GRID_SIZE, GRID_SIZE), color=0)
            for y in range(GRID_SIZE):
                for x in range(GRID_SIZE):
                    if self.pixels[y][x] == 1:
                        img.putpixel((x, y), 1)
            img.save(filename)
            if self.saved_after_func:
                self.saved_after_func(filename)
    
        def clear(self):
            self.pixels = [[0 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)]
            self.canvas.delete("all")
            self.draw_grid()

    def set_output_lang(*args, **kwargs):
        global OUTPUT_SEED_LANG 
        OUTPUT_SEED_LANG = langOutput_select_entry.get().lower()

    def generate_output():
        word_input_raw = word_input_entry.get()
        passcode_str_raw = passcode_entry.get()
        seed_length = seed_length_entry.get().split(' ')[0]
        lang = lang_select_entry.get().lower()
        image_bit = image_bit_text.get("1.0", tk.END).strip()
        image_int = int(image_bit,2) if image_bit else 0

        words = word_input_raw.strip().replace(',',' ')
        for c in [chr(i) for i in range(33, 127) if not chr(i).isalpha()]:
            words = words.replace(c, ' ')
        words = words.replace('  ', ' ').replace('  ', ' ')
        words = words if lang.startswith('chinese') else words.split(' ')
        words_eff = wd2effwd(words, mnemonic.Mnemonic(lang).wordlist)
        passcode = passcode_str_raw.strip()
        nbit = {12:128, 23:256, 24:256}[int(seed_length)]

        if int(seed_length) == 23:
            seed_phrases = genseed(words, passcode, image_int, nbit, lang, True)
        else:
            seed_phrases = genseed(words, passcode, image_int, nbit, lang, False)

        pass_hash_b58 = strhash2b58(passcode) if passcode else ''
        pass_hash_b58_sp = ' '.join(splitstr(pass_hash_b58, 8))
        indexed_seed_phrases = dict([(i+1, s) for i, s in enumerate(seed_phrases.split(' '))])

        eff_entropy = seed2entropy(seed_phrases.split(' '), nbit, OUTPUT_SEED_LANG)
    
        output1.config(state="normal")
        outputE.config(state="normal")
        output2.config(state="normal")
        output3.config(state="normal")
        output4.config(state="normal")

        output1.delete(1.0, tk.END)
        outputE.delete(1.0, tk.END)
        output2.delete(1.0, tk.END)
        output3.delete(1.0, tk.END)
        output4.delete(1.0, tk.END)
    
        output1.insert(tk.END, f"{' '.join(words_eff)}")
        outputE.insert(tk.END, f"{eff_entropy}")
        output2.insert(tk.END, f"{seed_phrases}")
        output3.insert(tk.END, f"{indexed_seed_phrases}")
        output4.insert(tk.END, f"{pass_hash_b58_sp}")

        output1.config(state="disabled")
        outputE.config(state="disabled")
        output2.config(state="disabled")
        output3.config(state="disabled")
        output4.config(state="disabled")

    def update_image_block(bit_string):
        image_bit_text.config(state="normal")
        image_bit_text.delete('1.0', tk.END)
        image_bit_text.insert(tk.END, bit_string.zfill(256))
        image_bit_text.config(state="disabled")
        image_hex_text.config(state="normal")
        image_hex_text.delete('1.0', tk.END)
        hex_string = hex(int(bit_string,2) if bit_string else 0)[2:].zfill(64).upper()
        image_hex_text.insert(tk.END, hex2line(hex_string))
        image_hex_text.config(state="disabled")
        pad.load_all_pixel(bit_string)

    def update_checksum(bit_string):
        bit_string_b36 = int2b36(sha256i(bit_string)) # use the last 4 b58 as image convert checksum
        bit_string_b36_checksum = ''.join(sorted(dedup(bit_string_b36)[:4]))
        checksum_label.config(text=f"Checksum: {bit_string_b36_checksum}")

    def load_and_process_image(file_path=None):
        if not file_path:
            file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")])
        if file_path:
            bit_string = process_image(file_path)
            path_label.config(text=file_path)
            update_image_block(bit_string)
            update_checksum(bit_string)
    
    def gen_random_image():
        _, bit_string = get256randnum()
        update_image_block(bit_string)
        update_checksum(bit_string)

    def load_and_process_bitstring():
        bit_string = bit_string_entry.get().strip()
        ords = [ord(i) for i in bit_string]
        if min(ords) > 9400 and max(ords) < 9700:
            hex_string = line2hex(bit_string)
            bit_string = hex2bin(hex_string, 256)
        update_image_block(bit_string)
        update_checksum(bit_string)
    
    root = tk.Tk()
    root.title("Semaj's SeedPhrase Generator")
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    seed_length_entry = tk.StringVar(root)
    seed_length_entry.set("24 Words")
    lang_select_entry = tk.StringVar(root)
    lang_select_entry.set("CHINESE_SIMPLIFIED")
    langOutput_select_entry = tk.StringVar(root)
    langOutput_select_entry.set("ENGLISH")

    dropdown_group = tk.LabelFrame(root, text="Options", padx=10, pady=5)
    dropdown_group.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
    dropdown = tk.OptionMenu(dropdown_group, seed_length_entry, "12 Words", "23 Words (24 - but last word ignored)", "24 Words")
    dropdown.config(font=("Courier", 10))
    dropdown.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
    label_lang = tk.Label(dropdown_group, text="Source Text:", font=("Courier", 12), anchor='w')
    label_lang.grid(          row=0, column=1, sticky="ew", padx=10, pady=0)
    dropdown_lang = tk.OptionMenu(dropdown_group, lang_select_entry, 'CHINESE_SIMPLIFIED', 'CHINESE_TRADITIONAL', 'CZECH', 'JAPANESE', 'FRENCH', 'ENGLISH', 'SPANISH', 'ITALIAN', 'PORTUGUESE', 'KOREAN')
    dropdown_lang.config(font=("Courier", 10))
    dropdown_lang.grid(row=0, column=2, sticky="ew", padx=10, pady=5)
    label_langOutput = tk.Label(dropdown_group, text="Output Seed Phrase:", font=("Courier", 12), anchor='w')
    label_langOutput.grid(          row=0, column=3, sticky="ew", padx=10, pady=0)
    dropdown_langOutput = tk.OptionMenu(dropdown_group, langOutput_select_entry, 'CHINESE_SIMPLIFIED', 'CHINESE_TRADITIONAL', 'CZECH', 'JAPANESE', 'FRENCH', 'ENGLISH', 'SPANISH', 'ITALIAN', 'PORTUGUESE', 'KOREAN', command=set_output_lang)
    dropdown_langOutput.config(font=("Courier", 10))
    dropdown_langOutput.grid(row=0, column=4, sticky="ew", padx=10, pady=5)

    input_group = tk.LabelFrame(root, text="Text Input", padx=10, pady=5)
    input_group.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
    input_group.grid_columnconfigure(0, weight=1)
    label1 = tk.Label(input_group, text="Enter your Source Phrases here:", font=("Courier", 12), anchor='w')
    word_input_entry = tk.Entry(input_group, font=("Courier", 14))
    label2 = tk.Label(input_group, text="Enter your Passcode here:", font=("Courier", 12), anchor='w')
    passcode_entry = tk.Entry(input_group, font=("Courier", 14))
    label1.grid(          row=0, column=0, sticky="ew", padx=10, pady=0)
    word_input_entry.grid(row=1, column=0, sticky="ew", padx=10, pady=0)
    label2.grid(          row=2, column=0, sticky="ew", padx=10, pady=0)
    passcode_entry.grid(  row=3, column=0, sticky="ew", padx=10, pady=0)
    
    image_group = tk.LabelFrame(root, text="Image Input", padx=10, pady=5)
    image_group.grid(row=3, column=0, columnspan=5, sticky="ew", padx=5, pady=5)
    image_group.grid_columnconfigure(0, weight=1)
    pad = DrawingPad(image_group, saved_after_func=load_and_process_image)
    image_bit_text = tk.Text(image_group, bg="lightgray", width=16, height=16, font=("Courier", 8))
    image_hex_text = tk.Text(image_group, bg="lightgray", width=8, height=8, font=("Courier", 17))
    load_bit_button = tk.Button(image_group, text="Load BitString↴", command=load_and_process_bitstring)
    bit_string_entry = tk.Entry(image_group, width=50, font=("Courier", 10))
    load_button = tk.Button(image_group, text="Load Image File", command=load_and_process_image)
    load_randnum_button = tk.Button(image_group, text="Generate Random Image", command=gen_random_image)
    checksum_label = tk.Label(image_group, text="", font=("Courier", 14))
    path_label = tk.Label(image_group, text="")

    pad.grid                (row=0, column=0, rowspan=6, columnspan=1, sticky="w",  padx=5, pady=5)
    image_bit_text.grid     (row=0, column=1, rowspan=6, columnspan=1, sticky="w",  padx=5, pady=5)
    image_hex_text.grid     (row=0, column=2, rowspan=6, columnspan=1, sticky="w",  padx=5, pady=5)
    load_bit_button.grid    (row=0, column=3, rowspan=1, columnspan=1, sticky="w",  padx=5, pady=5)
    bit_string_entry.grid   (row=1, column=3, rowspan=1, columnspan=4, sticky="ew", padx=5, pady=5)
    load_button.grid        (row=2, column=3, rowspan=1, columnspan=1, sticky="w",  padx=5, pady=5)
    load_randnum_button.grid(row=3, column=3, rowspan=1, columnspan=4, sticky="w",  padx=5, pady=5)
    checksum_label.grid     (row=4, column=3, rowspan=1, columnspan=4, sticky="w",  padx=5, pady=5)
    path_label.grid         (row=5, column=3, rowspan=1, columnspan=4, sticky="w",  padx=5, pady=0)

    generate_button = tk.Button(root, text="Generate Seed Phrases", font=("Courier", 16), command=generate_output)
    generate_button.grid(row=4, column=0, sticky="ew", padx=10, pady=5)
    
    output_group = tk.LabelFrame(root, text="Output", padx=10, pady=5)
    output_group.grid(row=5, column=0, sticky="ew", padx=5, pady=5)
    output_group.grid_columnconfigure(0, weight=1)
    output_group.grid_rowconfigure(0, weight=1)
    output1 = tk.Text(output_group, bg="lightgray", height=1, wrap="word", font=("Courier", 12))
    outputE = tk.Text(output_group, bg="lightgray", height=2, wrap="word", font=("Courier", 8))
    output2 = tk.Text(output_group, bg="lightgray", height=3, wrap="word", font=("Courier", 12))
    output3 = tk.Text(output_group, bg="lightgray", height=4, wrap="word", font=("Courier", 12))
    output4 = tk.Text(output_group, bg="lightgray", height=1, wrap="word", font=("Courier", 12))
    
    label3 = tk.Label(output_group, text="Your Effective Text Input:", font=("Courier", 12), anchor='w')
    labelE = tk.Label(output_group, text="Entropy of Your Seed Phrases:", font=("Courier", 12), anchor='w')
    label4 = tk.Label(output_group, text="Your Seed Phrases - Please keep them secure!", font=("Courier", 12), anchor='w')
    label5 = tk.Label(output_group, text="Your (Optional) Pass Phrases:", font=("Courier", 12), anchor='w')

    label3.grid (row=0, column=0, sticky="ew", padx=10, pady=2)
    output1.grid(row=1, column=0, sticky="ew", padx=10, pady=2)
    labelE.grid (row=2, column=0, sticky="ew", padx=10, pady=2)
    outputE.grid(row=3, column=0, sticky="ew", padx=10, pady=2)
    label4.grid (row=4, column=0, sticky="ew", padx=10, pady=2)
    output2.grid(row=5, column=0, sticky="ew", padx=10, pady=2)
    output3.grid(row=6, column=0, sticky="ew", padx=10, pady=2)
    label5.grid (row=7, column=0, sticky="ew", padx=10, pady=2)
    output4.grid(row=8, column=0, sticky="ew", padx=10, pady=2)
    
    #root.geometry("1080x900")
    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv[1:]) >= 1:
        main_cli()
    else:
        try:
            main_ui()
        except:
            main_cli()

