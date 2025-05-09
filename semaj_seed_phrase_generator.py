#!/usr/bin/env python3
# -*- coding: utf-8 -*-

### To make it a runnable file on Mac / Windows using pyinstaller
# pip3 install mnemonic base58 pillow pyinstaller
# pyinstaller --onefile --windowed --icon=icon.icns --add-data "semaj_seed_phrase_generator.py:." semaj_seed_phrase_generator.py

import hashlib, mnemonic, base58, sys, os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk

def int2bin     (i,     n) : return bin(i         )[2:].zfill(n)
def hex2bin     (h,     n) : return bin(int(h, 16))[2:].zfill(n)
def to2048      (n       ) : return ([] if n == 0 else to2048(n // 2048) + [n % 2048]) if n else []
def from2048    (idxs    ) : return sum(c * (2048 ** i) for i, c in enumerate(reversed(idxs)))
def wd2effwd    (s,   wdl) : return ([          i.lower()  for i in s if i.lower() in wdl] * 24) [:24]
def wd2idxs     (s,   wdl) : return ([wdl.index(i.lower()) for i in s if i.lower() in wdl] * 24) [:24]
def sha256i     (s       ) : return int(hashlib.sha256(s.encode('utf8')).hexdigest(), 16)
def idxs2eng    (idxs,wdl) : return ' '.join(wdl[i] for i in idxs)
def bits2idxs   (bits    ) : return [int(bits[i:i+11], 2) for i in range(0, len(bits), 11)]
def checksum    (i,     n) : return hex2bin(hashlib.sha256((i%2**n).to_bytes(n//8)).hexdigest(), 256)[:n//32]  #bip-39
def ient2idxs   (i,     n) : return bits2idxs(int2bin(i%2**n,n)+checksum(i%2**n,n))
def int2seedphs (i,     n) : return idxs2eng(ient2idxs(i%2**n,n), mnemonic.Mnemonic('english').wordlist)
def int2b58     (i       ) : return base58.b58encode_int(i).decode('utf-8')
def strhash2b58 (s       ) : return int2b58(sha256i(s))
def splitstr    (s,     n) : return [s[i*n:(i+1)*n] for i in range(len(s)//n + 1)]

def seed2entropy(words, n=256, lang='english'):
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

def process_image(image_path, scale_factor=5):
    image_size = 16
    img = Image.open(image_path)
    img_bw = img.resize((image_size, image_size), Image.BOX).convert('L').convert('1')
    img_large = img_bw.resize((image_size * scale_factor, image_size * scale_factor), Image.BOX)
    bits = ''.join('1' if pixel else '0' for pixel in img_bw.getdata())
    return img_large, bits

def main_cli():
    args = (sys.argv[1:] + ['', '', '', ''])[:4]
    words, passcode, nbit, lang = args[:4]
    nbit = int(nbit) if nbit else 256
    lang = lang if lang else 'chinese_simplified'
    words = words if lang.startswith('chinese') else words.split(' ')
    words_eff = wd2effwd(words, mnemonic.Mnemonic(lang).wordlist)
    print( "---> INPUT:", words_eff, passcode, nbit, lang)
    print( "OLD Version->", genseed(words, passcode, 0, nbit, lang, True ) )
    print( "NEW SEED   ->", genseed(words, passcode, 0, nbit, lang, False) )
    pass_hash_b58 = strhash2b58(passcode) if passcode else ''
    print(f"Suggested Passphrase: Passcode.SHA256.Base58: {pass_hash_b58} => {' '.join(splitstr(pass_hash_b58, 4))}")

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

def main_ui():
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
        pass_hash_b58_sp = ' '.join(splitstr(pass_hash_b58, 6))
        indexed_seed_phrases = dict([(i+1, s) for i, s in enumerate(seed_phrases.split(' '))])

        eff_entropy = seed2entropy(seed_phrases.split(' '), nbit)
    
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

    def load_and_process_image(file_path=None):
        if not file_path:
            file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")])
        if file_path:
            processed_img, bit_string = process_image(file_path)
            bit_string_b58 = strhash2b58(bit_string) # use the last 4 b58 as image convert checksum
            path_label.config(text=file_path + f" | checksum: {bit_string_b58[-4:]}")
            tk_img = ImageTk.PhotoImage(processed_img)
            image_label.config(image=tk_img)
            image_label.image = tk_img  # Keep reference
            image_bit_text.config(state="normal")
            image_bit_text.delete('1.0', tk.END)
            image_bit_text.insert(tk.END, bit_string)
            image_bit_text.config(state="disabled")
    
    root = tk.Tk()
    root.title("Semaj's SeedPhrase Generator")
    root.grid_columnconfigure(0, weight=1)
    root.grid_rowconfigure(0, weight=1)
    
    seed_length_entry = tk.StringVar(root)
    seed_length_entry.set("24 Words")
    lang_select_entry = tk.StringVar(root)
    lang_select_entry.set("CHINESE_SIMPLIFIED")

    dropdown_group = tk.LabelFrame(root, text="Options", padx=10, pady=5)
    dropdown_group.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
    dropdown = tk.OptionMenu(dropdown_group, seed_length_entry, "12 Words", "23 Words (24 - but last word ignored)", "24 Words")
    dropdown.config(font=("Arial", 10))
    dropdown.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
    dropdown_lang = tk.OptionMenu(dropdown_group, lang_select_entry, 'CHINESE_SIMPLIFIED', 'CHINESE_TRADITIONAL', 'CZECH', 'JAPANESE', 'FRENCH', 'ENGLISH', 'SPANISH', 'ITALIAN', 'PORTUGUESE', 'KOREAN')
    dropdown_lang.config(font=("Arial", 10))
    dropdown_lang.grid(row=0, column=1, sticky="ew", padx=10, pady=5)

    input_group = tk.LabelFrame(root, text="Text Input", padx=10, pady=5)
    input_group.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
    input_group.grid_columnconfigure(0, weight=1)
    label1 = tk.Label(input_group, text="Enter your Source Phrases here:", font=("Arial", 12), anchor='w')
    word_input_entry = tk.Entry(input_group, font=("Arial", 14))
    label2 = tk.Label(input_group, text="Enter your Passcode here - make it as long as you can remember exactly!:", font=("Arial", 12), anchor='w')
    passcode_entry = tk.Entry(input_group, font=("Arial", 14))
    label1.grid(          row=0, column=0, sticky="ew", padx=10, pady=0)
    word_input_entry.grid(row=1, column=0, sticky="ew", padx=10, pady=0)
    label2.grid(          row=2, column=0, sticky="ew", padx=10, pady=0)
    passcode_entry.grid(  row=3, column=0, sticky="ew", padx=10, pady=0)
    
    image_group = tk.LabelFrame(root, text="Image Input", padx=10, pady=5)
    image_group.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
    pad = DrawingPad(image_group, saved_after_func=load_and_process_image)
    pad.grid(row=0, column=0, padx=10, pady=10)
    image_load_group = tk.LabelFrame(image_group, text="Image Load", padx=10, pady=5)
    image_load_group.grid(row=0, column=1, columnspan=3, sticky="ew", padx=5, pady=5)

    load_button = tk.Button(image_load_group, text="Load Image", command=load_and_process_image)
    load_button.grid(row=0, column=0, rowspan=1, sticky="w", padx=10, pady=5)
    image_label = tk.Label(image_load_group)
    image_label.grid(row=0, column=1, rowspan=2, sticky="w", padx=10, pady=5)
    path_label = tk.Label(image_load_group, text="")
    path_label.grid(row=1, column=0, rowspan=1, sticky="w", padx=10, pady=5)
    image_bit_text = tk.Text(image_load_group, height=4, font=("Arial", 12))
    image_bit_text.grid(row=2, column=0, columnspan=2, sticky="ew", padx=10, pady=5)

    generate_button = tk.Button(root, text="Generate Seed Phrases", font=("Arial", 16), command=generate_output)
    generate_button.grid(row=4, column=0, sticky="ew", padx=10, pady=5)
    
    output_group = tk.LabelFrame(root, text="Output", padx=10, pady=5)
    output_group.grid(row=5, column=0, sticky="ew", padx=5, pady=5)
    output_group.grid_columnconfigure(0, weight=1)
    output_group.grid_rowconfigure(0, weight=1)
    output1 = tk.Text(output_group, height=1, wrap="word", font=("Arial", 12))
    outputE = tk.Text(output_group, height=2, wrap="word", font=("Arial", 8))
    output2 = tk.Text(output_group, height=3, wrap="word", font=("Arial", 12))
    output3 = tk.Text(output_group, height=4, wrap="word", font=("Arial", 12))
    output4 = tk.Text(output_group, height=1, wrap="word", font=("Arial", 12))
    
    label3 = tk.Label(output_group, text="Your Effective Text Input:", font=("Arial", 12), anchor='w')
    labelE = tk.Label(output_group, text="Entropy of Your Seed Phrases:", font=("Arial", 12), anchor='w')
    label4 = tk.Label(output_group, text="Your Seed Phrases - Please keep them secure!", font=("Arial", 12), anchor='w')
    label5 = tk.Label(output_group, text="Your (Optional) Pass Phrases:", font=("Arial", 12), anchor='w')

    label3.grid (row=0, column=0, sticky="ew", padx=10, pady=2)
    output1.grid(row=1, column=0, sticky="ew", padx=10, pady=2)
    labelE.grid (row=2, column=0, sticky="ew", padx=10, pady=2)
    outputE.grid(row=3, column=0, sticky="ew", padx=10, pady=2)
    label4.grid (row=4, column=0, sticky="ew", padx=10, pady=2)
    output2.grid(row=5, column=0, sticky="ew", padx=10, pady=2)
    output3.grid(row=6, column=0, sticky="ew", padx=10, pady=2)
    label5.grid (row=7, column=0, sticky="ew", padx=10, pady=2)
    output4.grid(row=8, column=0, sticky="ew", padx=10, pady=2)
    
    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv[1:]) > 1:
        main_cli()
    else:
        main_ui()
