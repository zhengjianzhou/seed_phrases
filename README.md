# Semaj Seed Phrases Generator
A handy seed phrases generation tool by Semaj

### minimal requirements.txt
<pre>
pip3 install mnemonic qrcode pillow kivy
</pre>

### To make an App on macOS / Windows using pyinstaller
<pre> 
pip3 install pyinstaller
pyinstaller --onefile --windowed --icon=icon.icns --add-data "main.py:." main.py
</pre>

### To use buildozer for android
### please unzip the font file NotoSansCJK.ttc.zip to NotoSansCJK.ttc before build
<pre>
unzip NotoSansCJK.ttc.zip
buildozer android debug
</pre>

### To use kivy-ios for iOS
### more steps on ChatGPT
### please unzip the font file NotoSansCJK.ttc.zip to NotoSansCJK.ttc before build
<pre>
unzip NotoSansCJK.ttc.zip
brew install autoconf automake libtool pkg-config
pip install kivy-ios
toolchain build python3 kivy
</pre>
