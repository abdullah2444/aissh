import sys
import base64

def copy_to_clipboard(text):
    b64 = base64.b64encode(text.encode('utf-8')).decode('utf-8')
    sys.stdout.write(f"\033]52;c;{b64}\007")
    sys.stdout.flush()

copy_to_clipboard("Hello from Python OSC 52!")
print("Sent OSC 52 sequence")
