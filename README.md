# Semaj Seed Phrases Generator
A handy seed phrases generation tool by Semaj

### minimal requirements.txt for console mode
<pre>
pip3 install mnemonic qrcode pillow
</pre>

### please unzip the font file NotoSansCJK.ttc.zip to NotoSansCJK.ttc before build or use the Kivy UI
<pre> 
unzip NotoSansCJK.ttc.zip
pip3 install kivy
</pre>

### To make an App on macOS / Windows using pyinstaller
<pre> 
pip3 install kivy pyinstaller
pyinstaller --onefile --windowed --icon=icon.icns --add-data "main.py:." main.py
</pre>

### To use buildozer for android
<pre>
unzip NotoSansCJK.ttc.zip
pip3 install kivy
buildozer android debug
</pre>

### To use kivy-ios for iOS (more steps on ChatGPT howtos)
<pre>
unzip NotoSansCJK.ttc.zip
brew install autoconf automake libtool pkg-config
pip install kivy kivy-ios
toolchain build python3 kivy
</pre>
