"""
app_gui.py - Modern CustomTkinter GUI for MP3/MP4 Steganography
================================================================
Dark-themed desktop application with tabbed interface.
- Tab 1: MP3 Steganography (Encode / Decode)
- Tab 2: MP4 Steganography (Encode / Decode)

Each tab has:
  Encode: file picker, message textbox, password entry, encode button, save-as dialog
  Decode: file picker, password entry, extract button, result textbox
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

from audio_stego import encode_mp3, decode_mp3
from video_stego import encode_mp4, decode_mp4

# ---------------------------------------------------------------------------
# Appearance
# ---------------------------------------------------------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# Font presets
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_LABEL = ("Segoe UI", 14)
FONT_ENTRY = ("Segoe UI", 14)
FONT_TEXT  = ("Consolas", 13)
FONT_BTN   = ("Segoe UI", 14, "bold")

PAD = 12   # standard padding


# ============================= HELPER ======================================
def _pick_file(entry_var: ctk.CTkEntry, filetypes: list[tuple[str, str]]) -> None:
    """Open a file dialog and put the selected path into the entry widget."""
    path = filedialog.askopenfilename(filetypes=filetypes)
    if path:
        entry_var.delete(0, tk.END)
        entry_var.insert(0, path)


def _save_file(filetypes: list[tuple[str, str]], default_ext: str) -> str | None:
    """Open a save-as dialog and return the chosen path (or None)."""
    path = filedialog.asksaveasfilename(
        filetypes=filetypes,
        defaultextension=default_ext,
    )
    return path if path else None


# ============================= MAIN APP ====================================
class StegoApp(ctk.CTk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Steganografi MP3 & MP4  |  Metadata + Fernet Encryption")
        self.geometry("1200x800")
        self.minsize(900, 650)

        # Scaling for HiDPI
        ctk.set_widget_scaling(1.3)

        # ----- Tab view ------------------------------------------------
        self.tabview = ctk.CTkTabview(self, anchor="nw")
        self.tabview.pack(fill="both", expand=True, padx=PAD, pady=PAD)

        tab_mp3 = self.tabview.add("MP3 Steganography")
        tab_mp4 = self.tabview.add("MP4 Steganography")

        self._build_tab(tab_mp3, media="mp3")
        self._build_tab(tab_mp4, media="mp4")

    # ------------------------------------------------------------------
    # Tab builder (reused for MP3 and MP4)
    # ------------------------------------------------------------------
    def _build_tab(self, parent: ctk.CTkFrame, media: str) -> None:
        """Build encode/decode sections inside a tab."""
        ext = f".{media}"
        ft = [(f"{media.upper()} files", f"*{ext}")]

        # Two-column layout: Encode (left) | Decode (right)
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(0, weight=1)

        encode_frame = ctk.CTkFrame(parent)
        encode_frame.grid(row=0, column=0, sticky="nsew", padx=(0, PAD // 2), pady=0)

        decode_frame = ctk.CTkFrame(parent)
        decode_frame.grid(row=0, column=1, sticky="nsew", padx=(PAD // 2, 0), pady=0)

        self._build_encode(encode_frame, media, ext, ft)
        self._build_decode(decode_frame, media, ext, ft)

    # ---- Encode section -----------------------------------------------
    def _build_encode(self, frame: ctk.CTkFrame, media: str, ext: str, ft: list) -> None:
        ctk.CTkLabel(frame, text=f"Encode – {media.upper()}", font=FONT_TITLE).pack(
            pady=(PAD, PAD // 2)
        )

        # Input file
        ctk.CTkLabel(frame, text=f"Input {media.upper()} File:", font=FONT_LABEL).pack(
            anchor="w", padx=PAD
        )
        file_entry = ctk.CTkEntry(frame, font=FONT_ENTRY, placeholder_text="Select file...")
        file_entry.pack(fill="x", padx=PAD, pady=(0, 4))
        ctk.CTkButton(
            frame,
            text="Browse...",
            font=FONT_BTN,
            width=120,
            command=lambda: _pick_file(file_entry, ft),
        ).pack(anchor="e", padx=PAD)

        # Secret message
        ctk.CTkLabel(frame, text="Secret Message:", font=FONT_LABEL).pack(
            anchor="w", padx=PAD, pady=(PAD, 0)
        )
        msg_textbox = ctk.CTkTextbox(frame, font=FONT_TEXT, height=160)
        msg_textbox.pack(fill="both", expand=True, padx=PAD, pady=(0, 4))

        # Password (optional)
        ctk.CTkLabel(frame, text="Password (optional):", font=FONT_LABEL).pack(anchor="w", padx=PAD)
        pwd_entry = ctk.CTkEntry(frame, font=FONT_ENTRY, show="•", placeholder_text="Leave empty for no encryption")
        pwd_entry.pack(fill="x", padx=PAD, pady=(0, PAD))

        # Encode button
        ctk.CTkButton(
            frame,
            text=f"Encode & Save {media.upper()}",
            font=FONT_BTN,
            fg_color="#1f6f2b",
            hover_color="#28a745",
            height=44,
            command=lambda: self._do_encode(
                media, file_entry.get(), msg_textbox.get("1.0", tk.END).strip(), pwd_entry.get(), ft, ext
            ),
        ).pack(fill="x", padx=PAD, pady=(0, PAD))

    # ---- Decode section -----------------------------------------------
    def _build_decode(self, frame: ctk.CTkFrame, media: str, ext: str, ft: list) -> None:
        ctk.CTkLabel(frame, text=f"Decode – {media.upper()}", font=FONT_TITLE).pack(
            pady=(PAD, PAD // 2)
        )

        # Stego file
        ctk.CTkLabel(frame, text=f"Stego {media.upper()} File:", font=FONT_LABEL).pack(
            anchor="w", padx=PAD
        )
        file_entry = ctk.CTkEntry(frame, font=FONT_ENTRY, placeholder_text="Select stego file...")
        file_entry.pack(fill="x", padx=PAD, pady=(0, 4))
        ctk.CTkButton(
            frame,
            text="Browse...",
            font=FONT_BTN,
            width=120,
            command=lambda: _pick_file(file_entry, ft),
        ).pack(anchor="e", padx=PAD)

        # Password (optional)
        ctk.CTkLabel(frame, text="Password (optional):", font=FONT_LABEL).pack(
            anchor="w", padx=PAD, pady=(PAD, 0)
        )
        pwd_entry = ctk.CTkEntry(frame, font=FONT_ENTRY, show="•", placeholder_text="Leave empty if not encrypted")
        pwd_entry.pack(fill="x", padx=PAD, pady=(0, PAD))

        # Extract button
        result_textbox = ctk.CTkTextbox(frame, font=FONT_TEXT, height=160, state="disabled")

        ctk.CTkButton(
            frame,
            text="Extract Message",
            font=FONT_BTN,
            fg_color="#9b2335",
            hover_color="#c0392b",
            height=44,
            command=lambda: self._do_decode(
                media, file_entry.get(), pwd_entry.get(), result_textbox
            ),
        ).pack(fill="x", padx=PAD, pady=(0, 4))

        # Result
        ctk.CTkLabel(frame, text="Extracted Message:", font=FONT_LABEL).pack(
            anchor="w", padx=PAD, pady=(PAD // 2, 0)
        )
        result_textbox.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))

    # ==================================================================
    # Actions
    # ==================================================================
    def _do_encode(
        self, media: str, input_path: str, message: str, password: str,
        ft: list, ext: str,
    ) -> None:
        """Run the encode process for either MP3 or MP4."""
        if not input_path:
            messagebox.showerror("Error", "Please select an input file.")
            return
        if not message:
            messagebox.showerror("Error", "Please enter a secret message.")
            return

        output_path = _save_file(ft, ext)
        if not output_path:
            return  # user cancelled

        try:
            if media == "mp3":
                encode_mp3(input_path, output_path, message, password)
            else:
                encode_mp4(input_path, output_path, message, password)
            messagebox.showinfo(
                "Success",
                f"Message encoded successfully!\nSaved to: {output_path}",
            )
        except Exception as e:
            messagebox.showerror("Encoding Error", str(e))

    def _do_decode(
        self, media: str, stego_path: str, password: str,
        result_textbox: ctk.CTkTextbox,
    ) -> None:
        """Run the decode process for either MP3 or MP4."""
        if not stego_path:
            messagebox.showerror("Error", "Please select a stego file.")
            return

        try:
            if media == "mp3":
                plaintext = decode_mp3(stego_path, password)
            else:
                plaintext = decode_mp4(stego_path, password)

            # Display result
            result_textbox.configure(state="normal")
            result_textbox.delete("1.0", tk.END)
            result_textbox.insert("1.0", plaintext)
            result_textbox.configure(state="disabled")
            messagebox.showinfo("Success", "Message extracted successfully!")

        except ValueError as e:
            messagebox.showerror("Decryption Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))
