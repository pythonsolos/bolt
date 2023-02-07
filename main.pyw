import tkinter as tk
from tkinter import ttk
import base64

root = tk.Tk()
root.title('Bolt')
root.geometry('350x210')
root.resizable('False', 'False')

global b64_message
global msg

encodingMethod = tk.StringVar()
encodeOrDecode = tk.StringVar()
stringForProgram = tk.StringVar()
statusStringVar = tk.StringVar()

morse_code_dict = {
    'a': '.-',
    'b': '-...',
    'c': '-.-.',
    'd': '-..',
    'e': '.',
    'f': '..-.',
    'g': '--.',
    'h': '....',
    'i': '..',
    'j': '.---',
    'k': '-.-',
    'l': '.-..',
    'm': '--',
    'n': '-.',
    'o': '---',
    'p': '.--.',
    'q': '--.-',
    'r': '.-.',
    's': '...',
    't': '-',
    'u': '..-',
    'v': '...-',
    'w': '.--',
    'x': '-..-',
    'y': '-.--',
    'z': '--..',
    '1': '.----',
    '2': '..---',
    '3': '...--',
    '4': '....-',
    '5': '.....',
    '6': '-....',
    '7': '--...',
    '8': '---..',
    '9': '----.',
    '0': '-----',
    '.': '.-.-.-',
    ',': '--..--',
    '?': '..--..'
}

def choose():
    method = encodingMethod.get()
    question = encodeOrDecode.get()
    mainstring = stringForProgram.get()
    if question == 'Encode':
        encode(method, mainstring)
    elif question == 'Decode':
        decode(method, mainstring)
        

def encode(type, raw):
    global b64_message
    if type == 'Base64': 
        try:
            msg_bytes = raw.encode('ascii')
            b64_bytes = base64.b64encode(msg_bytes)
            b64_message = b64_bytes.decode('ascii')
            statusStringVar.set(b64_message)
        except:
            pass
    if type == 'Binary':
        try:
            converted = ''.join(format(ord(i), '08b') for i in raw)
            statusStringVar.set(converted)
        except:
            pass
    if type == 'Morse Code':
        try:
            morse_code = ''
            for char in raw:
                if char == ' ':
                    morse_code += '  '
                else:
                    morse_code += morse_code_dict[char.lower()] + ' '
            statusStringVar.set(morse_code)
        except:
            pass

def decode(type, encry):
    global msg
    try:
        if type == 'Base64':
            b64_bytes = encry.encode('ascii')
            msg_bytes = base64.b64decode(b64_bytes)
            msg = msg_bytes.decode('ascii')
            statusStringVar.set(msg)
    except:
        pass
    if type == 'Binary':
        try:
            encry_raw = int(encry, 2);
            total = (encry_raw.bit_length() +7) // 8
            array = encry_raw.to_bytes(total, "big")
            value = array.decode()
            statusStringVar.set(value)
        except:
            pass
    if type == 'Morse Code':
        try:
            reversed = {}
            for key, value in morse_code_dict.items():
                reversed[value] = key
            english_plain_text = ''

            current_char_morse_code = ''
            i = 0
            while i < len(encry) - 1:
                if encry[i] == ' ':
                    if len(current_char_morse_code) == 0 and encry[i + 1] == ' ':
                        english_plain_text += ' '
                        i += 1
                    else:
                        english_plain_text += reversed[
                            current_char_morse_code]
                        current_char_morse_code = ''
                else:
                    current_char_morse_code += encry[i]
                i += 1

            if len(current_char_morse_code) > 0:
                english_plain_text += reversed[
                    current_char_morse_code]
            statusStringVar.set(english_plain_text)
        except:
            pass

typeLabel = ttk.Label(
    root,
    text='Type:'
)
typeBox = ttk.Combobox(
    root,
    textvariable=encodingMethod
)
questionLabel = ttk.Label(
    root,
    text='Encode or Decode:'
)
questionBox = ttk.Combobox(
    root,
    textvariable=encodeOrDecode
)
inputLabel = ttk.Label(
    root,
    text='Enter the string:'
)
inputBox = ttk.Entry(
    root,
    textvariable=stringForProgram
)
mainButton = ttk.Button(
    root,
    text='Execute',
    command=choose
)
statusLabel = ttk.Label(
    root,
    text='Output:'
)
statusEntry = tk.Entry(
    root,
    state='readonly',
    textvariable=statusStringVar,
    justify='center'
)
statusScrollbar = ttk.Scrollbar(
    root,
    orient='horizontal',
    command=statusEntry.xview
)

statusEntry['xscrollcommand'] = statusScrollbar.set
typeBox['values'] = ('Base64', 'Binary', 'Morse Code')
typeBox['state'] = 'readonly'
questionBox['values'] = ('Encode', 'Decode')
questionBox['state'] = 'readonly'

typeLabel.pack(anchor=tk.W)
typeBox.pack(ipadx=101)
questionLabel.pack(anchor=tk.W)
questionBox.pack(ipadx=101)
inputLabel.pack(anchor=tk.W)
inputBox.pack(ipadx=110)
mainButton.pack(pady=3, ipadx=20)
statusLabel.pack()
statusEntry.pack(ipadx=110)
statusScrollbar.pack(ipadx=145)

root.mainloop()