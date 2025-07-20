import os
import struct
import json
import csv
import winreg
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from tkinter.scrolledtext import ScrolledText

class Win11JumpListAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Jump List Analyzer")
        self.root.geometry("1100x750")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0')
        self.style.configure('TButton', font=('Segoe UI', 9))
        
        self.create_widgets()
        self.results = []
        self.auto_detected_files = []
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left panel (file selection)
        left_panel = ttk.Frame(main_frame, width=350)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # File selection frame
        file_frame = ttk.LabelFrame(left_panel, text="File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=5)
        
        # Manual selection
        ttk.Label(file_frame, text="Manual Selection:").pack(anchor=tk.W)
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=40).pack(fill=tk.X, pady=2)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(fill=tk.X, pady=2)
        ttk.Button(file_frame, text="Analyze", command=self.analyze_manual_file).pack(fill=tk.X, pady=2)
        
        # Auto detection
        ttk.Label(file_frame, text="Auto Detection:").pack(anchor=tk.W, pady=(10, 0))
        ttk.Button(file_frame, text="Find Jump Lists", command=self.find_jump_lists).pack(fill=tk.X, pady=2)
        
        # Detected files list
        ttk.Label(file_frame, text="Detected Files:").pack(anchor=tk.W, pady=(10, 0))
        self.detected_files_list = tk.Listbox(file_frame, height=12, selectmode=tk.SINGLE)
        self.detected_files_list.pack(fill=tk.BOTH, expand=True, pady=2)
        self.detected_files_list.bind('<<ListboxSelect>>', self.select_detected_file)
        
        # Analysis controls
        control_frame = ttk.Frame(left_panel, padding=10)
        control_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(control_frame, text="Analyze Selected", command=self.analyze_selected).pack(fill=tk.X, pady=2)
        ttk.Button(control_frame, text="Analyze All", command=self.analyze_all).pack(fill=tk.X, pady=2)
        ttk.Button(control_frame, text="Clear Results", command=self.clear_results).pack(fill=tk.X, pady=2)
        
        # Right panel (results display)
        right_panel = ttk.Frame(main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Results display
        results_frame = ttk.LabelFrame(right_panel, text="Analysis Results", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for structured results
        self.tree = ttk.Treeview(results_frame, columns=('Entry', 'Target', 'File', 'User', 'Accessed'), show='headings')
        self.tree.heading('Entry', text='Entry #')
        self.tree.heading('Target', text='Target Path')
        self.tree.heading('File', text='Source File')
        self.tree.heading('User', text='User')
        self.tree.heading('Accessed', text='Last Accessed')
        self.tree.column('Entry', width=50, anchor='center')
        self.tree.column('Target', width=350)
        self.tree.column('File', width=120)
        self.tree.column('User', width=80)
        self.tree.column('Accessed', width=120)
        
        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(results_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        # Details panel
        details_frame = ttk.LabelFrame(right_panel, text="Entry Details", padding=10)
        details_frame.pack(fill=tk.BOTH, pady=5)
        
        self.details_text = ScrolledText(details_frame, height=10, wrap=tk.WORD, font=('Consolas', 9))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(right_panel, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Export buttons
        export_frame = ttk.Frame(right_panel, padding=5)
        export_frame.pack(fill=tk.X)
        
        ttk.Button(export_frame, text="Export to CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Export to JSON", command=self.export_json).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Save All Results", command=self.save_all_results).pack(side=tk.RIGHT, padx=5)
        
        # Bind tree selection
        self.tree.bind('<<TreeviewSelect>>', self.show_details)
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Jump List File",
            filetypes=[("Jump List Files", "*.automaticDestinations-ms;*.customDestinations-ms"), ("All Files", "*.*")]
        )
        if file_path:
            self.file_path.set(file_path)
    
    def analyze_manual_file(self):
        """Analyze manually selected file"""
        file_path = self.file_path.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("Error", "File not found")
            return
            
        try:
            self.update_status(f"Analyzing {os.path.basename(file_path)}...")
            self.results = self.parse_jump_list(file_path, "Manual Selection")
            self.display_results()
            messagebox.showinfo("Success", f"Found {len(self.results)} entries in file")
            self.update_status("Analysis complete")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")
            self.update_status("Analysis failed")
    
    def find_jump_lists(self):
        """Automatically detect Jump List files in Windows 11"""
        self.auto_detected_files = []
        self.detected_files_list.delete(0, tk.END)
        self.update_status("Searching for Jump List files...")
        
        # Standard Windows 11 locations
        locations = [
            os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent', 'AutomaticDestinations'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Windows', 'Recent', 'AutomaticDestinations'),
            os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent', 'CustomDestinations'),
            os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Windows', 'Recent', 'CustomDestinations'),
            os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent', 'AutomaticDestinations'),
            os.path.join(os.getenv('USERPROFILE'), 'AppData', 'Local', 'Microsoft', 'Windows', 'Recent', 'AutomaticDestinations')
        ]
        
        # Search all locations
        found_files = []
        for location in locations:
            if os.path.exists(location):
                for root, _, files in os.walk(location):
                    for file in files:
                        if file.endswith(('.automaticDestinations-ms', '.customDestinations-ms')):
                            full_path = os.path.join(root, file)
                            username = self.get_username_from_path(full_path)
                            found_files.append((full_path, username))
        
        if not found_files:
            messagebox.showinfo("Information", "No Jump List files found in standard locations")
            self.update_status("No files found")
            return
        
        self.auto_detected_files = found_files
        for path, user in found_files:
            self.detected_files_list.insert(tk.END, f"{user}: {os.path.basename(path)}")
        
        messagebox.showinfo("Information", f"Found {len(found_files)} Jump List files")
        self.update_status(f"Found {len(found_files)} files")
    
    def get_username_from_path(self, path):
        """Extract username from file path"""
        parts = path.split(os.sep)
        if 'Users' in parts:
            users_index = parts.index('Users')
            if len(parts) > users_index + 1:
                return parts[users_index + 1]
        return "System"
    
    def select_detected_file(self, event):
        """Handle selection from detected files list"""
        selection = self.detected_files_list.curselection()
        if selection:
            index = selection[0]
            file_path, _ = self.auto_detected_files[index]
            self.file_path.set(file_path)
    
    def analyze_selected(self):
        """Analyze the currently selected file"""
        selection = self.detected_files_list.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a file from the list")
            return
        
        index = selection[0]
        file_path, username = self.auto_detected_files[index]
        try:
            self.update_status(f"Analyzing selected file...")
            results = self.parse_jump_list(file_path, username)
            if results:
                self.results = results
                self.display_results()
                messagebox.showinfo("Success", f"Found {len(results)} entries in selected file")
            else:
                messagebox.showinfo("Information", "No valid entries found in selected file")
            self.update_status("Analysis complete")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")
            self.update_status("Analysis failed")
    
    def analyze_all(self):
        """Analyze all detected files"""
        if not self.auto_detected_files:
            messagebox.showerror("Error", "No files detected. Run 'Find Jump Lists' first.")
            return
            
        self.clear_results()
        all_results = []
        total_files = len(self.auto_detected_files)
        
        for i, (file_path, username) in enumerate(self.auto_detected_files, 1):
            try:
                self.update_status(f"Analyzing file {i} of {total_files}...")
                results = self.parse_jump_list(file_path, username)
                if results:
                    all_results.extend(results)
            except Exception as e:
                messagebox.showwarning("Warning", f"Failed to analyze {file_path}: {str(e)}")
                continue
        
        if all_results:
            self.results = all_results
            self.display_results()
            messagebox.showinfo("Complete", f"Analyzed {len(self.auto_detected_files)} files, found {len(all_results)} total entries")
        else:
            messagebox.showinfo("Information", "No valid entries found in any files")
        
        self.update_status(f"Analyzed {len(self.auto_detected_files)} files")
    
    def parse_jump_list(self, file_path, username):
        """Parse Jump List file with Windows 11 specific handling"""
        results = []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Check for empty file
            if len(data) < 32:
                return []
            
            # Windows 11 specific signature check
            if not (data.startswith(b'\x00\x00\x00\x00') or data[4:8] == b'\x00\x00\x00\x00'):
                return []
            
            # Parse header
            header = struct.unpack_from('<16sIIII', data, 0)
            num_entries = header[4]
            
            # Parse entries
            pos = 32
            for i in range(num_entries):
                if pos + 16 > len(data):
                    break
                    
                entry_size = struct.unpack_from('<I', data, pos)[0]
                if entry_size == 0 or pos + entry_size > len(data):
                    break
                
                entry_data = data[pos:pos+entry_size]
                
                # Parse LNK information
                if len(entry_data) >= 16:
                    lnk_offset = struct.unpack_from('<I', entry_data, 8)[0]
                    lnk_size = struct.unpack_from('<I', entry_data, 12)[0]
                    
                    if (lnk_offset > 0 and lnk_size > 20 and  # Minimum LNK size
                        lnk_offset + lnk_size <= len(data)):
                        
                        lnk_data = data[lnk_offset:lnk_offset+lnk_size]
                        parsed_lnk = self.parse_lnk_file_win11(lnk_data)
                        
                        if parsed_lnk and parsed_lnk.get('target_path'):
                            # Get last accessed time
                            accessed_time = self.get_file_access_time(file_path)
                            
                            results.append({
                                'entry_number': i,
                                'lnk_info': parsed_lnk,
                                'file_name': os.path.basename(file_path),
                                'file_path': file_path,
                                'username': username,
                                'accessed_time': accessed_time
                            })
                
                pos += entry_size
        
        except Exception as e:
            raise Exception(f"Error parsing {file_path}: {str(e)}")
        
        return results
    
    def parse_lnk_file_win11(self, lnk_data):
        """Parse LNK file structure for Windows 11"""
        if len(lnk_data) < 76 or not lnk_data.startswith(b'L\x00\x00\x00'):
            return None
        
        result = {}
        try:
            # Parse header
            header = struct.unpack('<8s16sIII', lnk_data[:36])
            result['header_signature'] = header[0].decode('ascii', errors='ignore')
            result['file_attributes'] = header[2]
            
            flags = header[3]
            pos = 76  # Start of target info
            
            # Parse shell item ID list if present
            if flags & 0x01 and pos + 2 <= len(lnk_data):
                id_list_size = struct.unpack_from('<H', lnk_data, pos)[0]
                pos += 2 + id_list_size
            
            # Parse target info for Windows 11
            if flags & 0x02 and pos < len(lnk_data):
                try:
                    # Find the target path string (UTF-16LE)
                    str_data = lnk_data[pos:]
                    null_pos = str_data.find(b'\x00\x00')
                    if null_pos != -1:
                        target_str = str_data[:null_pos + 2].decode('utf-16le', errors='ignore')
                        result['target_path'] = target_str.strip('\x00')
                except:
                    pass
            
            # Parse additional info for Windows 11
            if flags & 0x04 and pos + 4 < len(lnk_data):  # Description string
                desc_size = struct.unpack_from('<I', lnk_data, pos)[0]
                pos += 4
                if pos + desc_size <= len(lnk_data):
                    try:
                        desc_str = lnk_data[pos:pos+desc_size].decode('utf-16le', errors='ignore')
                        result['description'] = desc_str.strip('\x00')
                    except:
                        pass
            
            # Parse relative path for Windows 11
            if flags & 0x08 and pos + 4 < len(lnk_data):
                rel_path_size = struct.unpack_from('<I', lnk_data, pos)[0]
                pos += 4
                if pos + rel_path_size <= len(lnk_data):
                    try:
                        rel_path = lnk_data[pos:pos+rel_path_size].decode('utf-16le', errors='ignore')
                        result['relative_path'] = rel_path.strip('\x00')
                    except:
                        pass
            
            return result
        except Exception as e:
            print(f"Error parsing LNK: {str(e)}")
            return None
    
    def get_file_access_time(self, file_path):
        """Get the last accessed time of a file"""
        try:
            timestamp = os.path.getatime(file_path)
            return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Unknown"
    
    def display_results(self):
        """Display results in treeview"""
        self.tree.delete(*self.tree.get_children())
        
        if not self.results:
            return
            
        for result in self.results:
            target_path = result['lnk_info'].get('target_path', 'Unknown')
            # Trim long paths for better display
            if len(target_path) > 60:
                target_path = target_path[:30] + "..." + target_path[-30:]
                
            self.tree.insert('', 'end', values=(
                result['entry_number'],
                target_path,
                result['file_name'],
                result['username'],
                result.get('accessed_time', 'Unknown')
            ))
    
    def show_details(self, event):
        """Show detailed information for selected entry"""
        selected_item = self.tree.selection()
        if not selected_item:
            return
            
        item = self.tree.item(selected_item)
        entry_num = item['values'][0]
        
        result = next((r for r in self.results if r['entry_number'] == entry_num), None)
        if not result:
            return
            
        self.details_text.delete(1.0, tk.END)
        details = f"""Entry #{result['entry_number']}
File: {result['file_name']}
Path: {result['file_path']}
User: {result['username']}
Last Accessed: {result.get('accessed_time', 'Unknown')}
Target: {result['lnk_info'].get('target_path', 'Unknown')}

----- LNK File Details -----
Attributes: {result['lnk_info'].get('file_attributes', 'N/A')}
Description: {result['lnk_info'].get('description', 'N/A')}
Relative Path: {result['lnk_info'].get('relative_path', 'N/A')}
"""
        self.details_text.insert(tk.END, details)
    
    def export_csv(self):
        if not self.results:
            messagebox.showerror("Error", "No results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save as CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )
        
        if not file_path:
            return
            
        try:
            fieldnames = ['file_name', 'file_path', 'entry_number', 'target_path', 'username', 
                         'accessed_time', 'description', 'relative_path', 'file_attributes']
            
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for result in self.results:
                    row = {
                        'file_name': result['file_name'],
                        'file_path': result['file_path'],
                        'entry_number': result['entry_number'],
                        'target_path': result['lnk_info'].get('target_path', ''),
                        'username': result['username'],
                        'accessed_time': result.get('accessed_time', ''),
                        'description': result['lnk_info'].get('description', ''),
                        'relative_path': result['lnk_info'].get('relative_path', ''),
                        'file_attributes': result['lnk_info'].get('file_attributes', '')
                    }
                    writer.writerow(row)
            
            messagebox.showinfo("Success", f"Results exported to {file_path}")
            self.update_status(f"Exported to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
            self.update_status("Export failed")
    
    def export_json(self):
        if not self.results:
            messagebox.showerror("Error", "No results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save as JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(self.results, jsonfile, indent=2, default=str)
            
            messagebox.showinfo("Success", f"Results exported to {file_path}")
            self.update_status(f"Exported to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")
            self.update_status("Export failed")
    
    def save_all_results(self):
        """Save all results including detected files list"""
        if not self.results and not self.auto_detected_files:
            messagebox.showerror("Error", "No data to save")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save All Data",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")]
        )
        
        if not file_path:
            return
            
        try:
            data = {
                'detected_files': [{'path': p, 'user': u} for p, u in self.auto_detected_files],
                'analysis_results': self.results,
                'metadata': {
                    'generated_on': datetime.now().isoformat(),
                    'system': os.name,
                    'windows_version': self.get_windows_version()
                }
            }
            
            with open(file_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, default=str)
            
            messagebox.showinfo("Success", f"All data saved to {file_path}")
            self.update_status(f"Saved all data to {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {str(e)}")
            self.update_status("Save failed")
    
    def get_windows_version(self):
        """Get Windows version information"""
        try:
            import platform
            return platform.platform()
        except:
            return "Unknown Windows version"
    
    def clear_results(self):
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.update_status("Results cleared")

if __name__ == '__main__':
    root = tk.Tk()
    app = Win11JumpListAnalyzer(root)
    root.mainloop()