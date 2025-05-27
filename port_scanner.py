import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter.ttk import *
import datetime
import os

def set_dark_theme():
    colors = {
        "bg": "#2b2b2b",
        "fg": "#ffffff",
        "entry_bg": "#404040",
        "entry_fg": "#ffffff",
        "button_bg": "#404040",
        "button_fg": "#ffffff",
        "text_bg": "#1e1e1e",
        "text_fg": "#ffffff",
        "status_bg": "#2b2b2b",
        "status_fg": "#cccccc"
    }

    # Main window and frames
    root.configure(bg=colors["bg"])
    port_frame.configure(bg=colors["bg"])
    timeout_frame.configure(bg=colors["bg"])
    button_frame.configure(bg=colors["bg"])
    status_frame.configure(bg=colors["status_bg"])

    # Labels
    label1.config(bg=colors["bg"], fg=colors["fg"])
    label2.config(bg=colors["bg"], fg=colors["fg"])
    label3.config(bg=colors["bg"], fg=colors["fg"])
    label_timeout.config(bg=colors["bg"], fg=colors["fg"])
    heading1.config(bg=colors["bg"], fg=colors["fg"])
    subtitle.config(bg=colors["bg"], fg=colors["fg"])
    status_label.config(bg=colors["status_bg"], fg=colors["status_fg"])

    # Entries
    target_input.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
    start_port_input.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
    end_port_input.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
    timeout_input.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])

    # Buttons
    scan_btn.config(bg=colors["button_bg"], fg=colors["button_fg"])
    btn2.config(bg=colors["button_bg"], fg=colors["button_fg"])
    btn3.config(bg=colors["button_bg"], fg=colors["button_fg"])
    btn_about.config(bg=colors["button_bg"], fg=colors["button_fg"])

    # Update theme of result popup (if exists)
    def update_result_theme():
        try:
            result_box.config(bg=colors["text_bg"], fg=colors["text_fg"], insertbackground=colors["text_fg"])
        except:
            pass  # Only if result_box is already open
    update_result_theme()

def apply_dark_theme_to_popup(popup_window):
    """Apply dark theme to popup window and all its children"""
    colors = {
        "bg": "#2b2b2b",
        "fg": "#ffffff",
        "entry_bg": "#404040",
        "entry_fg": "#ffffff",
        "button_bg": "#404040",
        "button_fg": "#ffffff",
        "text_bg": "#1e1e1e",
        "text_fg": "#ffffff",
        "status_bg": "#2b2b2b",
        "status_fg": "#cccccc"
    }
    
    # Apply to the popup window itself
    popup_window.configure(bg=colors["bg"])
    
    # Apply to all children recursively
    def apply_to_children(widget):
        for child in widget.winfo_children():
            widget_class = child.winfo_class()
            
            try:
                if widget_class == "Label":
                    child.config(bg=colors["bg"], fg=colors["fg"])
                elif widget_class == "Entry":
                    child.config(bg=colors["entry_bg"], fg=colors["entry_fg"], insertbackground=colors["entry_fg"])
                elif widget_class == "Button":
                    child.config(bg=colors["button_bg"], fg=colors["button_fg"])
                elif widget_class == "Text":
                    child.config(bg=colors["text_bg"], fg=colors["text_fg"], insertbackground=colors["text_fg"])
                elif widget_class == "Frame":
                    child.config(bg=colors["bg"])
                elif widget_class == "Checkbutton":
                    child.config(bg=colors["bg"], fg=colors["fg"], selectcolor=colors["button_bg"])
                
                # Recursively apply to children
                apply_to_children(child)
            except tk.TclError:
                # Some widgets might not support all config options
                pass
    
    apply_to_children(popup_window)


def scan_port():
    scan_btn.config(state='disabled')

    target = target_input.get().strip()
    try:
        start_port = int(start_port_input.get().strip())
        end_port = int(end_port_input.get().strip())
        timeout = float(timeout_input.get().strip())
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
    except ValueError as e:
        if "timeout" in str(e).lower():
            messagebox.showerror("Invalid Input", "Timeout must be a positive number.")
        else:
            messagebox.showerror("Invalid Input", "Please enter valid port numbers.")
        scan_btn.config(state='normal')
        return

    if not target:
        messagebox.showerror("Missing Input", "Please enter a target.")
        scan_btn.config(state='normal')
        return

    if start_port > end_port or not(0 <= start_port <= 65535) or not (0 <= end_port <= 65535):
        messagebox.showerror("Invalid Range", "Please enter a valid port range (0-65535).")
        scan_btn.config(state='normal')
        return

    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        messagebox.showerror("Error", "Invalid Target hostname/IP address")
        scan_btn.config(state='normal')
        return

    # Create scan popup window
    scan_port_popup = tk.Toplevel(root)
    scan_port_popup.title("--- Scanning Network ---")
    scan_port_popup.geometry('500x500')

    scanning = tk.Label(scan_port_popup, text="", font=("Arial", 12))
    scanning.pack(pady=5)

    pb = Progressbar(scan_port_popup, orient='horizontal', length=200, mode='determinate', maximum=end_port - start_port + 1)
    pb.pack(pady=10)

    result_box = scrolledtext.ScrolledText(scan_port_popup, wrap=tk.WORD, width=50, height=20)
    result_box.pack(pady=10)

    chkValue = tk.BooleanVar()
    chkValue.set(False)

    save_results = tk.Checkbutton(scan_port_popup, text="Save Result", variable=chkValue)
    save_results.pack(pady=5)

    def on_done_click():
        if chkValue.get():
            try:
                # Create directory if it doesn't exist
                os.makedirs("scan_results", exist_ok=True)
                
                with open("scan_results/scan_results.txt", "a", encoding='utf-8') as f:
                    f.write(f"Scan on {target} ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}):\n")
                    f.write(result_box.get("1.0", tk.END))
                    f.write("\n" + "=" * 50 + "\n\n")
                messagebox.showinfo("Saved", "Scan results have been saved!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save results: {str(e)}")
        
        scan_port_popup.destroy()
        scan_btn.config(state='normal')

    done_btn = tk.Button(scan_port_popup, text="Done", command=on_done_click, font=("Arial", 12), width=20, height=2)
    done_btn.pack(pady=5)   
    done_btn.config(state='disabled')

    # Apply dark theme to the scan popup
    apply_dark_theme_to_popup(scan_port_popup)

    start_time = datetime.datetime.now()

    def append_result(text):
        result_box.insert(tk.END, text)
        result_box.see(tk.END)

    def scan():
        scanning.config(text="Scanning....")
        open_ports = []
        scan_results = []

        for i, port in enumerate(range(start_port, end_port + 1)):
            try:
                # Get service name
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "Unknown"

                # Test connection
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        msg = f"[+] Port {port} is OPEN ({service})\n"
                        result_box.after(0, append_result, msg)
                        open_ports.append(port)
                        scan_results.append(msg)
                        
            except socket.error as e:
                # Only show connection errors for the first few attempts to avoid spam
                if i < 5:
                    msg = f"[!] Could not connect to {target}:{port} - {str(e)}\n"
                    result_box.after(0, append_result, msg)
                continue
            except Exception as e:
                msg = f"[!] Error scanning port {port}: {str(e)}\n"
                result_box.after(0, append_result, msg)
                continue

            # Update progress bar
            pb['value'] = i + 1
            scan_port_popup.update_idletasks()

        # Calculate duration
        end_time = datetime.datetime.now()
        duration = end_time - start_time

        def on_scan_complete():
            # Remove progress bar
            pb.destroy()
            
            # Add summary
            summary = f"\n{'='*50}\n"
            summary += f"[✔] Scan complete for {target}\n"
            summary += f"Port range: {start_port}-{end_port}\n"
            summary += f"Total ports scanned: {end_port - start_port + 1}\n"
            summary += f"Open ports found: {len(open_ports)}\n"
            if open_ports:
                summary += f"Open ports: {', '.join(map(str, open_ports))}\n"
            summary += f"Scan duration: {duration}\n"
            summary += f"Timeout used: {timeout}s\n"
            summary += f"{'='*50}\n"
            
            result_box.insert(tk.END, summary)
            result_box.see(tk.END)
            
            scanning.config(text="Scan Complete!")
            done_btn.config(state='normal')
            scan_port_popup.protocol("WM_DELETE_WINDOW", scan_port_popup.destroy)  # Re-enable close button

        result_box.after(0, on_scan_complete)

    # Start scanning in a separate thread
    threading.Thread(target=scan, daemon=True).start()

def save_scans_menu():
    save_scans_popup = tk.Toplevel(root)
    save_scans_popup.title("--- Saved Scans ---")
    save_scans_popup.geometry('600x500')

    text_area = scrolledtext.ScrolledText(save_scans_popup, wrap="word", font=("Courier", 10))
    text_area.pack(expand=True, fill="both", padx=10, pady=10)

    try:
        file_path = "scan_results/scan_results.txt"
        if os.path.exists(file_path):
            with open(file_path, "r", encoding='utf-8') as f:
                content = f.read()
                if content.strip():
                    text_area.insert("1.0", content)
                else:
                    text_area.insert("1.0", "No scan results found in the file.")
        else:
            text_area.insert("1.0", "No saved scans found. Run some scans first!")
            
    except Exception as e:
        messagebox.showerror("Error", f"Could not read saved scans: {str(e)}")
        save_scans_popup.destroy()
        return

    text_area.config(state="disabled")
    
    # Button frame for better layout
    btn_frame = tk.Frame(save_scans_popup)
    btn_frame.pack(pady=5)
    
    def clear_results():
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all saved scan results?"):
            try:
                file_path = "scan_results/scan_results.txt"
                if os.path.exists(file_path):
                    open(file_path, 'w').close()  # Clear the file
                    text_area.config(state="normal")
                    text_area.delete("1.0", tk.END)
                    text_area.insert("1.0", "All scan results have been cleared.")
                    text_area.config(state="disabled")
                    messagebox.showinfo("Success", "Scan results cleared!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not clear results: {str(e)}")
    
    clear_btn = tk.Button(btn_frame, text="Clear Results", command=clear_results, font=("Arial", 10), width=15)
    clear_btn.pack(side=tk.LEFT, padx=5)
    
    done_btn = tk.Button(btn_frame, text="Done", command=save_scans_popup.destroy, font=("Arial", 10), width=15)
    done_btn.pack(side=tk.LEFT, padx=5)

    # Apply dark theme to the saved scans popup
    apply_dark_theme_to_popup(save_scans_popup)

def show_about():
    about_text = """Port Scanner v1.0

A simple network port scanner built with Python and tkinter.

Features:
• Scan single or multiple ports
• Adjustable timeout settings  
• Service identification
• Save scan results
• Progress tracking

Usage:
1. Enter target IP or domain
2. Set port range to scan
3. Adjust timeout if needed
4. Click 'Scan' to start

Created with Python 3"""
    
    messagebox.showinfo("About Port Scanner", about_text)

# Create main window
root = tk.Tk()
root.title("--- Port Scanner ---")
root.geometry('640x520')
root.resizable(True, True)

# Main heading
heading1 = tk.Label(root, text="Port Scanner", font=("Arial", 16, "bold"))
heading1.pack(pady=10)

subtitle = tk.Label(root, text="Network Port Scanning Tool", font=("Arial", 10))
subtitle.pack(pady=(0, 20))

# Target input
label1 = tk.Label(root, text="Target IP / Domain:", font=("Arial", 12))
label1.pack(pady=5)

target_input = tk.Entry(root, justify='center', font=("Arial", 11), width=30)
target_input.pack(pady=5)
target_input.insert(0, "127.0.0.1")  # Default value

# Port range inputs
port_frame = tk.Frame(root)
port_frame.pack(pady=10)

label2 = tk.Label(port_frame, text="Start Port:", font=("Arial", 12))
label2.pack(side=tk.LEFT, padx=5)

start_port_input = tk.Entry(port_frame, justify='center', font=("Arial", 11), width=10)
start_port_input.pack(side=tk.LEFT, padx=5)
start_port_input.insert(0, "1")  # Default value

label3 = tk.Label(port_frame, text="End Port:", font=("Arial", 12))
label3.pack(side=tk.LEFT, padx=5)

end_port_input = tk.Entry(port_frame, justify='center', font=("Arial", 11), width=10)
end_port_input.pack(side=tk.LEFT, padx=5)
end_port_input.insert(0, "1000")  # Default value

# Timeout input
timeout_frame = tk.Frame(root)
timeout_frame.pack(pady=10)

label_timeout = tk.Label(timeout_frame, text="Timeout (seconds):", font=("Arial", 12))
label_timeout.pack(side=tk.LEFT, padx=5)

timeout_input = tk.Entry(timeout_frame, justify='center', font=("Arial", 11), width=10)
timeout_input.pack(side=tk.LEFT, padx=5)
timeout_input.insert(0, "0.5")

# Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=20)

scan_btn = tk.Button(button_frame, text="Start Scan", command=scan_port, font=("Arial", 12, "bold"), width=15, height=2)
scan_btn.pack(pady=5)

btn2 = tk.Button(button_frame, text="View Saved Scans", command=save_scans_menu, font=("Arial", 11), width=18, height=1)
btn2.pack(pady=5)

btn_about = tk.Button(button_frame, text="About", command=show_about, font=("Arial", 11), width=18, height=1)
btn_about.pack(pady=5)

btn3 = tk.Button(button_frame, text="Exit", command=root.quit, font=("Arial", 11), width=18, height=1, )
btn3.pack(pady=5)

# Status bar
status_frame = tk.Frame(root)
status_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

status_label = tk.Label(status_frame, text="Ready to scan", font=("Arial", 9), relief=tk.SUNKEN, anchor=tk.W)
status_label.pack(fill=tk.X, padx=5)



if __name__ == '__main__':
    set_dark_theme()
    root.mainloop()