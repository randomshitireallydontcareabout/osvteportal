import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading

def export_codebase(target_directories, output_file_path, log_widget):
    """
    Recursively scans multiple target directories, filtering ONLY for .html, .py, .css, and .js files,
    reads their contents, and writes them into a single output text file.
    """
    output_path = Path(output_file_path).resolve()
    
    # Folders to skip
    ignored_folders = {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}
    
    # ONLY allow these specific code extensions
    allowed_extensions = {'.html', '.py', '.css', '.js'}
    
    file_count = 0
    
    try:
        log_widget.insert(tk.END, f"Starting export for {len(target_directories)} selected root folder(s)...\n")
        log_widget.insert(tk.END, f"Filtering for extensions: {', '.join(allowed_extensions)}\n\n")
        log_widget.see(tk.END)
        
        with open(output_path, 'w', encoding='utf-8', errors='ignore') as outfile:
            outfile.write("CODEBASE EXPORT REPORT (HTML, PY, CSS, JS ONLY)\n")
            outfile.write("=" * 80 + "\n\n")
            
            for target_dir in target_directories:
                target_path = Path(target_dir).resolve()
                log_widget.insert(tk.END, f"Scanning root: {target_path}\n")
                log_widget.see(tk.END)
                
                if not target_path.exists():
                    log_widget.insert(tk.END, f"  [Warning] Path does not exist, skipping.\n")
                    continue
                
                for item in sorted(target_path.rglob('*')):
                    # Skip if inside an ignored folder
                    if any(part in ignored_folders for part in item.parts):
                        continue
                    
                    if item.is_file():
                        # Only process allowed extensions
                        if item.suffix.lower() not in allowed_extensions:
                            continue
                        
                        # Prevent the script from reading its own output file if placed inside
                        if item.resolve() == output_path:
                            continue
                            
                        file_count += 1
                        relative_path = item.relative_to(target_path)
                        display_tag = f"[{target_path.name}] {relative_path}"
                        
                        log_widget.insert(tk.END, f"  [Matched] {display_tag}\n")
                        log_widget.see(tk.END)
                        
                        # Write file header marker
                        outfile.write("=" * 80 + "\n")
                        outfile.write(f"ROOT FOLDER: {target_path.name} | FILE: {relative_path}\n")
                        outfile.write("=" * 80 + "\n\n")
                        
                        # Try reading and writing file contents
                        try:
                            with open(item, 'r', encoding='utf-8', errors='ignore') as infile:
                                content = infile.read()
                                outfile.write(content)
                        except Exception as read_err:
                            outfile.write(f"[Error reading file content: {read_err}]\n")
                        
                        outfile.write("\n\n" + ("-" * 80) + "\n\n")
            
            outfile.write(f"\nEXPORT COMPLETE. Total code files processed: {file_count}\n")
            
        log_widget.insert(tk.END, f"\nSuccess! Exported {file_count} files to:\n{output_path}\n")
        log_widget.see(tk.END)
        messagebox.showinfo("Success", f"Codebase successfully exported!\n\nProcessed {file_count} files (.html, .py, .css, .js).\nSaved to: {output_path}")
        
    except Exception as e:
        log_widget.insert(tk.END, f"\nError: {e}\n")
        log_widget.see(tk.END)
        messagebox.showerror("Error", f"An error occurred:\n{e}")

class MultiFolderExporterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Folder Code Exporter (.html, .py, .css, .js)")
        self.root.geometry("650x550")
        self.root.minsize(550, 450)
        
        # Keep track of selected folders
        self.selected_folders = []
        
        # --- UI Layout ---
        title_label = tk.Label(root, text="Code Exporter (Targeted Extensions)", font=("Arial", 14, "bold"))
        title_label.pack(pady=10)
        
        # Folder Management Frame
        frame = tk.Frame(root)
        frame.pack(pady=5, padx=20, fill="both", expand=False)
        
        tk.Label(frame, text="Selected Folders to Scan:", font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 3))
        
        # Listbox + Scrollbar Frame
        list_frame = tk.Frame(frame)
        list_frame.pack(fill="x", expand=True)
        
        self.folder_listbox = tk.Listbox(list_frame, height=5, font=("Arial", 9), selectmode=tk.EXTENDED)
        self.folder_listbox.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.folder_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.folder_listbox.config(yscrollcommand=scrollbar.set)
        
        # Buttons for adding/removing folders
        btn_sub_frame = tk.Frame(frame)
        btn_sub_frame.pack(fill="x", pady=8)
        
        add_btn = tk.Button(btn_sub_frame, text="+ Add Folder", command=self.add_folder, font=("Arial", 9, "bold"), bg="#10b981", fg="white", cursor="hand2")
        add_btn.pack(side="left", padx=(0, 5))
        
        remove_btn = tk.Button(btn_sub_frame, text="- Remove Selected", command=self.remove_folder, font=("Arial", 9), bg="#ef4444", fg="white", cursor="hand2")
        remove_btn.pack(side="left")
        
        # Generate Button
        self.generate_btn = tk.Button(
            root, 
            text="Generate Code Text File", 
            command=self.start_thread, 
            font=("Arial", 11, "bold"), 
            bg="#2563eb", 
            fg="white", 
            padx=15, 
            pady=6,
            cursor="hand2"
        )
        self.generate_btn.pack(pady=10)
        
        # Log / Output Box
        tk.Label(root, text="Activity Log:", font=("Arial", 10, "bold")).pack(anchor="w", padx=20)
        self.log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 9), height=12)
        self.log_box.pack(pady=(3, 15), padx=20, fill="both", expand=True)

    def add_folder(self):
        """Allows user to pick a folder and adds it to the tracking list."""
        folder = filedialog.askdirectory()
        if folder:
            if folder not in self.selected_folders:
                self.selected_folders.append(folder)
                self.folder_listbox.insert(tk.END, folder)
            else:
                messagebox.showwarning("Duplicate", "This folder has already been added.")

    def remove_folder(self):
        """Removes the selected folder(s) from the listbox."""
        selected_indices = self.folder_listbox.curselection()
        for index in reversed(selected_indices):
            self.folder_listbox.delete(index)
            del self.selected_folders[index]

    def start_thread(self):
        """Validates inputs and spawns the background worker thread."""
        if not self.selected_folders:
            messagebox.showwarning("Missing Input", "Please add at least one folder to scan.")
            return
            
        output_file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile="code_files_export.txt",
            title="Save Combined Text File As"
        )
        
        if not output_file:
            return
            
        self.log_box.delete("1.0", tk.END)
        
        worker_thread = threading.Thread(target=export_codebase, args=(self.selected_folders, output_file, self.log_box), daemon=True)
        worker_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = MultiFolderExporterApp(root)
    root.mainloop()