# seed_phrases
A handy seed phrases generation tool by Semaj

### requirements.txt
# pip3 install mnemonic qrcode pillow kivy
#
### To make an App on macOS / Windows using pyinstaller
# pip3 install pyinstaller
# pyinstaller --onefile --windowed --icon=icon.icns --add-data "semaj_seed_phrase_generator.py:." semaj_seed_phrase_generator.py
#
### To use buildozer for android
### Copy a CJK font from somewhere to current folder as STHeiti.ttc
### e.g. macOS: cp /System/Library/Fonts/STHeiti\ Light.ttc ./STHeiti.ttc
# buildozer android debug
#
### To use kivy-ios for iOS
### Copy a CJK font from somewhere to current folder as STHeiti.ttc
### e.g. macOS: cp /System/Library/Fonts/STHeiti\ Light.ttc ./STHeiti.ttc
# brew install autoconf automake libtool pkg-config
# pip install kivy-ios
# toolchain build python3 kivy
# more steps on ChatGPT
