from tkinter import *
from cryptography import *
from tkinter import *

class EncryptionApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption Tool")
        self.root.configure(bg='gray12')

        #main_frame = Frame(root, padx=20, pady=20, width=1000, height=1000)
        #main_frame.grid(row=0, column=0, padx=10, pady=10, columnspan=4)
        main_frame = Frame(root, padx=100, pady=100, width=300, height=400, background='gray12')
        main_frame.grid(row=0, column=0)


        self.choice_label = Label(main_frame, text="Choose Action:", background='#1F1F1F',  font='Arial 18 bold ', foreground='white')
        self.choice_label.grid(row=0, column=0, padx=10, pady=10)

        self.choice_var = StringVar()
        self.choice_var.set("Encrypt")
        self.encrypt_button = Button(main_frame, text="Encrypt", command=self.set_encrypt , activebackground='black', activeforeground="blue", font='Arial 18 bold')
        self.encrypt_button.grid(row=0, column=1, padx=10, pady=10)

        self.decrypt_button = Button(main_frame, text="Decrypt", command=self.set_decrypt, activebackground='black', activeforeground="blue", font='Arial 18 bold' )
        self.decrypt_button.grid(row=0, column=2, padx=10, pady=10)

        self.algo_label = Label(main_frame, text="Choose Algorithm:", background='#1F1F1F',  font='Arial 18 bold ', fg='white', foreground='white')
        self.algo_label.grid(row=1, column=0, padx=10, pady=10)

        self.algo_var = StringVar()
        self.algo_var.set("Caesar Cipher")
        self.caesar_button = Button(main_frame, text="Caesar Cipher", command=self.set_caesar, activebackground='black', activeforeground="blue", font='Arial 18 bold')
        self.caesar_button.grid(row=1, column=1, padx=10, pady=10)

        self.vigenere_button = Button(main_frame, text="Vigenere Cipher", command=self.set_vigenere, activebackground='black', activeforeground="blue", font='Arial 18 bold')
        self.vigenere_button.grid(row=1, column=2, padx=10, pady=10)

        self.circular_button = Button(main_frame, text="Circular Shift + Swap", command=self.set_circular, activebackground='black', activeforeground="blue", font='Arial 18 bold')
        self.circular_button.grid(row=1, column=3, padx=10, pady=10)

        self.text_label = Label(main_frame, text="Enter Text:", background='#1F1F1F',  font='Arial 18 bold ', fg='white', foreground='white')
        self.text_label.grid(row=2, column=0, padx=10, pady=10)

        self.text_entry = Entry(main_frame, width=35, font='Arial 18', fg='blue')
        self.text_entry.grid(row=2, column=1, columnspan=3, padx=10, pady=10)

        self.shift_label = Label(main_frame, text="Shift Value/Keyword:", background='#1F1F1F',  font='Arial 18 bold ', fg='white', foreground='white')
        self.shift_label.grid(row=3, column=0, padx=10, pady=10)

        self.shift_entry = Entry(main_frame, width=35, font='Arial 18', fg='blue')
        self.shift_entry.grid(row=3, column=1, columnspan=3, padx=10, pady=10)

        self.result_label = Label(main_frame, text="Result:", background='#1F1F1F',  font='Arial 18 bold ', fg='white', foreground='white')
        self.result_label.grid(row=4, column=0, padx=10, pady=10)

        self.result_var = StringVar()
        self.result_entry = Entry(main_frame, textvariable=self.result_var, state="readonly", width=35, font='Arial 18 bold italic', fg='red')
        self.result_entry.grid(row=4, column=1, columnspan=3, padx=10, pady=10)

        self.execute_button = Button(main_frame, text="Execute", command=self.execute,activebackground='black', activeforeground="blue", font='Arial 18 bold')
        self.execute_button.grid(row=5, column=1, columnspan=3, padx=10, pady=10)




    def set_encrypt(self):
        self.choice_var.set("Encrypt")

    def set_decrypt(self):
        self.choice_var.set("Decrypt")

    def set_caesar(self):
        self.algo_var.set("Caesar Cipher")

    def set_vigenere(self):
        self.algo_var.set("Vigenere Cipher")

    def set_circular(self):
        self.algo_var.set("Circular Shift + Swap")

    def execute(self):
        choice = self.choice_var.get()
        algorithm = self.algo_var.get()
        text = self.text_entry.get()

        if choice == "Encrypt":
            if algorithm == "Caesar Cipher":
                shift = int(self.shift_entry.get())
                result = self.caesar_encrypt(text, shift)
            elif algorithm == "Vigenere Cipher":
                keyword = self.shift_entry.get()
                result = self.vigenere_encrypt(text, keyword)
            elif algorithm == "Circular Shift + Swap":
                result = self.circular_encrypt(text)
            else:
                result = "Invalid algorithm selected."
        elif choice == "Decrypt":
            if algorithm == "Caesar Cipher":
                shift = int(self.shift_entry.get())
                result = self.caesar_decrypt(text, shift)
            elif algorithm == "Vigenere Cipher":
                keyword = self.shift_entry.get()
                result = self.vigenere_decrypt(text, keyword)
            elif algorithm == "Circular Shift + Swap":
                result = self.circular_decrypt(text)
            else:
                result = "Invalid algorithm selected."
        else:
            result = "Invalid choice selected."

        self.result_var.set(result)

    def caesar_encrypt(self, text1, shift):
        self.text1 = text1
        self.shift = shift
        self.encrypted_text = ""
        self.shifted = None

        for char in self.text1:

            if char.isalpha():

                self.shifted = ord(char) + self.shift

                if char.islower():

                    self.encrypted_text += chr((self.shifted - 97) % 26 + 97).upper()

                else:

                    self.encrypted_text += chr((self.shifted - 65) % 26 + 65).upper()
            else:

                self.encrypted_text += char
        fh = open("Enc-DecHistory.txt", "at")
        fh.write(f"Encrypted text {self.encrypted_text} ,for plaintext {self.text1} ,using number of shift : {self.shift}\n")
        fh.close()

        return self.encrypted_text



    def caesar_decrypt(self, encrypted_text, shift):
        # Implement Caesar Cipher decryption logic
        self.text1 = encrypted_text
        self.shift = shift
        self.decrypted_text = ""

        for char in self.text1:

            if char.isalpha():

                shifted = ord(char) - self.shift

                if char.islower():

                    self.decrypted_text += chr((shifted - 97) % 26 + 97).upper()
                else:

                    self.decrypted_text += chr((shifted - 65) % 26 + 65).upper()
            else:
                self.decrypted_text += char
        fh = open("Enc-DecHistory.txt", "at")
        fh.write(f"Decrypted text {self.decrypted_text} ,for Cipher text  {self.text1} ,using number of shift : {self.shift}\n")
        fh.close()

        return self.decrypted_text

    def __str__(self):

        return f"Encrypted message : {self.encrypted_text} ,For plaintext : {self.text1}"



    def vigenere_encrypt(self, text2, keyword):

        self.text2 = text2
        self.keyword = keyword
        self.encrypted_text1 = ""
        extended_keyword = self.extend_keyword(self.keyword, len(self.text2))
        encrypted_char = ''

        for i in range(len(self.text2)):
            if self.text2[i].isalpha():
                shift = ord(extended_keyword[i].upper()) - ord('A')
                if self.text2[i].islower():
                    encrypted_char = chr((ord(self.text2[i]) - ord('a') + shift) % 26 + ord('a')).upper()
                    self.encrypted_text1 += encrypted_char
                else:
                    encrypted_char = chr((ord(self.text2[i]) - ord('A') + shift) % 26 + ord('A'))
                    self.encrypted_text1 += encrypted_char
            else:
                self.encrypted_text1 += self.text2[i]

        fh = open("Enc-DecHistory.txt", "at")
        fh.write( f"Encrypted text {self.encrypted_text1} ,for plaintext {self.text2} ,using keyword value  : {self.keyword}\n")
        fh.close()

        return self.encrypted_text1

    def vigenere_decrypt(self, encrypted_text, keyword_Value):
        self.encrypted_text = encrypted_text
        self.keyword_Value = keyword_Value
        self.decrypted_text = ""
        self.extended_keyword = self.extend_keyword(keyword_Value, len(encrypted_text))

        for i in range(len(self.encrypted_text)):
            if self.encrypted_text[i].isalpha():
                shift = ord(self.extended_keyword[i].upper()) - ord('A')

                if self.encrypted_text[i].islower():
                    decrypted_char = chr((ord(self.encrypted_text[i]) - ord('a') - shift) % 26 + ord('a'))
                    self.decrypted_text += decrypted_char
                else:
                    decrypted_char = chr((ord(self.encrypted_text[i]) - ord('A') - shift) % 26 + ord('A'))
                    self.decrypted_text += decrypted_char
            else:
                self.decrypted_text += self.encrypted_text[i]

        fh = open("Enc-DecHistory.txt", "at")
        fh.write(f"Decrypted text {self.decrypted_text} ,for Cipher text {self.encrypted_text} ,using keyword value  : {self.keyword_Value}\n")
        fh.close()

        return self.decrypted_text

    def extend_keyword(self, keyword1, length):

        self.keyword1 = keyword1
        self.length = length

        repeats = self.length // len(self.keyword1)
        remainder = self.length % len(self.keyword1)
        extended_keyword = self.keyword1 * repeats + self.keyword1[:remainder]

        return extended_keyword

    def circular_encrypt(self, text3):
        self.text3 = text3
        self.encrypted_text3 = ''

        for char in self.text3:
            # Circular shift by 3 positions
            shifted_char = chr((ord(char) + 3) % 128)
            self.encrypted_text3 += shifted_char

        # Swap adjacent characters
        self.encrypted_text3 = ''.join(
            [self.encrypted_text3[i + 1] + self.encrypted_text3[i] for i in range(0, len(self.encrypted_text3), 2)])
        fh = open("Enc-DecHistory.txt", "at")
        fh.write(f"Encrypted text {self.encrypted_text3} ,for plaintext {self.text3}\n")
        fh.close()

        return self.encrypted_text3

    def circular_decrypt(self, encrypted_message):
        self.encrypted_message = encrypted_message

        # Reverse circular shift by 3 positions
        self.decrypted_text3 = ''.join([chr((ord(char) - 3) % 128) for char in self.encrypted_message])

        # Reverse swap operation
        self.decrypted_text3 = ''.join(
            [self.decrypted_text3[i + 1] + self.decrypted_text3[i] for i in range(0, len(self.decrypted_text3), 2)])

        fh = open("Enc-DecHistory.txt", "at")
        fh.write(f"Decrypted text {self.decrypted_text3} ,for Cipher text {self.encrypted_message}\n")
        fh.close()

        return self.decrypted_text3

#if __name__ == "__main__":

root = Tk()
app = EncryptionApp(root)
root.mainloop()


