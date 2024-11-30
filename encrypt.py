import os
import gzip
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from telegram import Update, Bot
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

# Replace with your bot token
BOT_TOKEN = "7622955711:AAGkopqi25sUkL-wxcsnkTBLo19gECeDHCs"

# Generate a strong, random key and IV
def generate_key_iv():
    key = os.urandom(32)  # 256-bit key
    iv = os.urandom(16)   # 128-bit IV
    return key, iv

# Double-layered encryption with compression
def encrypt_file(input_path, output_path):
    key1, iv1 = generate_key_iv()
    key2, iv2 = generate_key_iv()
    temp_file = f"{output_path}.tmp"

    with open(input_path, "rb") as infile, gzip.open(temp_file, "wb") as temp:
        cipher1 = Cipher(algorithms.AES(key1), modes.CTR(iv1), backend=default_backend())
        encryptor1 = cipher1.encryptor()
        temp.write(encryptor1.update(infile.read()) + encryptor1.finalize())
    
    with open(temp_file, "rb") as infile, open(output_path, "wb") as outfile:
        cipher2 = Cipher(algorithms.AES(key2), modes.CFB(iv2), backend=default_backend())
        encryptor2 = cipher2.encryptor()
        outfile.write(encryptor2.update(infile.read()) + encryptor2.finalize())
    
    os.remove(temp_file)

# Double-layered decryption with decompression
def decrypt_file(input_path, output_path):
    key1, iv1 = generate_key_iv()
    key2, iv2 = generate_key_iv()
    temp_file = f"{output_path}.tmp"

    with open(input_path, "rb") as infile, open(temp_file, "wb") as temp:
        cipher2 = Cipher(algorithms.AES(key2), modes.CFB(iv2), backend=default_backend())
        decryptor2 = cipher2.decryptor()
        temp.write(decryptor2.update(infile.read()) + decryptor2.finalize())
    
    with gzip.open(temp_file, "rb") as infile, open(output_path, "wb") as outfile:
        cipher1 = Cipher(algorithms.AES(key1), modes.CTR(iv1), backend=default_backend())
        decryptor1 = cipher1.decryptor()
        outfile.write(decryptor1.update(infile.read()) + decryptor1.finalize())
    
    os.remove(temp_file)

# Telegram Bot Handlers
def start(update: Update, context: CallbackContext):
    update.message.reply_text("Welcome! Use /encrypt to encrypt a file or /decrypt to decrypt a file.")

def handle_encrypt(update: Update, context: CallbackContext):
    update.message.reply_text("Send me the file to encrypt.")
    context.user_data['action'] = 'encrypt'

def handle_decrypt(update: Update, context: CallbackContext):
    update.message.reply_text("Send me the file to decrypt.")
    context.user_data['action'] = 'decrypt'

def handle_document(update: Update, context: CallbackContext):
    if 'action' not in context.user_data:
        update.message.reply_text("Use /encrypt or /decrypt first.")
        return

    file = update.message.document.get_file()
    input_path = f"{file.file_id}.input"
    output_path = f"{file.file_id}.output"

    file.download(input_path)

    if context.user_data['action'] == 'encrypt':
        encrypt_file(input_path, output_path)
        update.message.reply_document(document=open(output_path, "rb"))
    elif context.user_data['action'] == 'decrypt':
        decrypt_file(input_path, output_path)
        update.message.reply_document(document=open(output_path, "rb"))

    os.remove(input_path)
    os.remove(output_path)

# Setup Telegram Bot
def main():
    updater = Updater(BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("encrypt", handle_encrypt))
    dispatcher.add_handler(CommandHandler("decrypt", handle_decrypt))
    dispatcher.add_handler(MessageHandler(Filters.document, handle_document))

    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()