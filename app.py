from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import subprocess
import psycopg2
import base64
import os
from datetime import datetime
from scapy.all import sniff, wrpcap
import socket
import time
from werkzeug.utils import secure_filename
from io import BytesIO
from PIL import Image
from manuf import manuf
import threading


app = Flask(__name__)

# Set a secret key for session management
app.secret_key = 'your_secret_key_here'  # Change this to a unique and secret key

# Global dictionary to track progress
device_progress = {}

UPLOAD_FOLDER = '/home/research/Documents/Images'  # Set a folder for uploaded images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Global dictionary to track the packet capture status for each device
device_capture_status = {}

# Function to get the list of Connected Devices
def get_connected_devices(interface='wlan0'):
    devices = {}
    devices_list = []
    
    try:
        # Now proceed with fetching connected devices
        #subprocess.run(['sudo', 'ip', 'neigh', 'flush', 'all'], capture_output=True, text=True, check=True)
        #time.sleep(5)
        result = subprocess.run(['sudo', 'ip', 'neigh', 'show', 'dev', interface], capture_output=True, text=True)
        print(result.stdout)

        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue

                ip = parts[0]
                mac = parts[2]

                ip_type = None
                try:
                    if socket.inet_pton(socket.AF_INET, ip):
                        ip_type = 'IPv4'
                except socket.error:
                    try:
                        if socket.inet_pton(socket.AF_INET6, ip):
                            ip_type = 'IPv6'
                    except socket.error:
                        ip_type = None

                if mac not in devices:
                    devices[mac] = {'mac': mac, 'ips': {'IPv4': [], 'IPv6': []}}
                
                if ip_type == 'IPv4':
                    devices[mac]['ips']['IPv4'].append(ip)
                elif ip_type == 'IPv6':
                    devices[mac]['ips']['IPv6'].append(ip)

            devices_list = [{'mac': mac, 'ips': info['ips']} for mac, info in devices.items()]
            print("Found devices:", devices_list)
        else:
            print("Error: Command failed with return code:", result.returncode)

    except Exception as e:
        print("An error occurred while fetching connected devices:", e)

    return devices_list



# Define a function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to rename the uploaded file
def get_new_filename(device_name, mac, original_filename):
    # Get the file extension from the original file
    file_extension = original_filename.rsplit('.', 1)[1].lower()
    # Create a timestamp for the filename
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    # Generate the new filename: device_name_mac_timestamp.extension
    new_filename = f"{device_name}_{mac}_{timestamp}.{file_extension}"
    return new_filename

def update_device(ip, mac, device_name, device_description, image_path=None):
    try:
        with psycopg2.connect(
            dbname="Device Info",
            user="postgres",
            password="admin123!",
            host="localhost",
            port="5432"
        ) as conn:
            with conn.cursor() as cursor:
                sql = "SELECT COUNT(*) AS total_count FROM connected_devices WHERE mac = %s"
                val = (mac,)
                cursor.execute(sql, val)
                total_count = cursor.fetchone()[0]

                if total_count > 0:
                    if device_description=="":
                        sql = "UPDATE connected_devices SET device_name = %s WHERE mac = %s"
                        val = (device_name, mac)
                        cursor.execute(sql, val)
                    else: 
                        sql = "UPDATE connected_devices SET device_name = %s, device_desc = %s WHERE mac = %s"
                        val = (device_name, device_description, mac)
                        cursor.execute(sql, val)
                else:
                    sql = "INSERT INTO connected_devices (ip, mac, device_name, device_desc) VALUES (%s, %s, %s, %s)"
                    val = (ip, mac, device_name, device_description)
                    cursor.execute(sql, val)

    except psycopg2.Error as e:
        print("PostgreSQL error:", e)

# Flask route for updating device information
@app.route('/update_device', methods=['POST'])
def update_device_route():
    try:
        # Check if the request is multipart/form-data (for file uploads)
        if 'device_image' in request.files:
            image_file = request.files['device_image']
            if image_file and allowed_file(image_file.filename):
                # Secure the filename to prevent directory traversal
                filename = secure_filename(image_file.filename)
                
                # Get new filename with device_name, mac, and timestamp
                device_name = request.form['device_name']
                mac = request.form['mac']
                new_filename = get_new_filename(device_name, mac, filename)
                
                # Define the image path where the file will be saved
                image_path = os.path.join(UPLOAD_FOLDER, new_filename)
                # Save the file to the upload folder
                image_file.save(image_path)
            else:
                image_path = None  # Handle case where no image is uploaded or invalid file type
        else:
            image_path = None  # Handle case where no file is included

        # Get form data for device update (whether JSON or form-data)
        ip = request.form['ip']
        mac = request.form['mac']
        device_name = request.form['device_name']
        device_description = request.form['device_description']

        # Call update_device with the provided data (including image_path if available)
        update_device(ip, mac, device_name, device_description, image_path)

        # If the request is JSON, return a JSON response
        if request.is_json:
            return jsonify({"status": "Updated Successfully"}), 200

        # If the request is not JSON (likely form data), redirect with a flash message
        flash('Updated successfully!', 'success')

    except Exception as e:
        # Handle errors and send appropriate responses
        if request.is_json:
            return jsonify({"status": "Update Failed"}), 401
        else:
            flash(f'Error updating device: {str(e)}', 'error')

    # Redirect to the dashboard
    return redirect(url_for('dashboard'))

# Function for fetching Device Name from DB
def fetch_device_name(mac):
    try:
        with psycopg2.connect(
            dbname="Device Info",
            user="postgres",
            password="admin123!",
            host="localhost",
            port="5432"
        ) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT device_name FROM connected_devices WHERE mac=%s", (mac,))
                result = cursor.fetchone()
                return result[0] if result else None
    except psycopg2.Error as e:
        print("PostgreSQL error:", e)
        return None

# Function for populating device information
def populate_list():
    devices = get_connected_devices()
    print("Devices detected:", devices)
    device_list = []
    
    if not devices:
        print("No devices found!")

    for device in devices:
        fetched = fetch_device_name(device['mac'])
        # Get vendor name using MAC address
        vendor = get_vendor_from_mac(device['mac'])

        device_info = {
            'mac': device['mac'],
            'ips': device['ips'],
            'display_name': fetched if fetched is not None else None,
            'vendor': vendor
        }
        device_list.append(device_info)
    
    print("Final device list:", device_list)
    return device_list

# Function to get vendor from MAC address
def get_vendor_from_mac(mac_address):
    # Create an instance of Manf
    p = manuf.MacParser()

    # Get the vendor name associated with the MAC address
    vendor = p.get_manuf(mac_address)

    return vendor if vendor else "Unknown"  # Return "Unknown" if no vendor is found


@app.route('/')
def index():
    return redirect(url_for('login'))

# Flask route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'admin!':
            if request.is_json:
                return jsonify({"status": "success"})
            else:
                return redirect(url_for('dashboard'))
        else:
            if request.is_json:
                return jsonify({"status": "fail"}), 401
            else:
                flash('Invalid credentials', 'error')
                return redirect(url_for('index'))
    return render_template('login.html')



# Flask route for Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'GET':
        return render_template('dashboard.html', devices=None)
    elif request.method == 'POST':
        connected_devices = populate_list()
        print(connected_devices)
        if request.is_json:
            return jsonify({"connected_devices": connected_devices}), 200
        else:
            return render_template('dashboard.html', devices=connected_devices)

# Flask Route for PCAP Capture
@app.route('/capture_pcap', methods=['POST'])
def capture_pcap():
    try:
        # Check if the request's content type is application/json
        if request.is_json:
            data = request.get_json()

            # Handle multiple devices
            if 'selected_devices' in data:  
                selected_devices = data['selected_devices']
                packets = int(data['packets'])
                filename = data['filename']
                folder = "/home/research/Documents/PCAP"
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                # Validate input
                if not selected_devices or not filename or packets <= 0:
                    raise ValueError("Invalid input data")

                os.makedirs(folder, exist_ok=True)

                threads = []
                for device_mac in selected_devices:
                    file_name = f"{filename}_{device_mac}_{timestamp}.pcap"
                    # Start a new thread for each device
                    thread = threading.Thread(target=capture_device_pcap, args=(folder, file_name, "wlan0", device_mac, packets))
                    threads.append(thread)
                    thread.start()

                # Wait for all threads to finish
                for thread in threads:
                    thread.join()

                # return jsonify({'message': 'Packet capture completed successfully!'}), 200
                return

            # Handle single device
            elif 'mac' in data:
                mac = data['mac']
                packets = int(data['packets'])
                filename = data['filename']
                folder = "/home/research/Documents/PCAP"
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                file_name = f"{filename}_{mac}_{timestamp}.pcap"

                os.makedirs(folder, exist_ok=True)
                capture_and_save_pcap(folder, file_name, "wlan0", mac, packets)

                # return jsonify({'message': 'Packet capture completed successfully!'}), 200
                return

        else:  # Handle form data
            if 'selected_devices' in request.form:
                selected_devices = request.form['selected_devices'].split(',')
                packets = int(request.form['packets'])
                filename = request.form['custom_filename']
                folder = "/home/research/Documents/PCAP"
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

                # Validate Input
                if not selected_devices or not filename or packets <= 0:
                    raise ValueError("Invalid input data")
                
                # Create the folder if it doesn't exist
                os.makedirs(folder, exist_ok=True)

                threads = []
                for device_mac in selected_devices:
                    file_name = f"{filename}_{device_mac}_{timestamp}.pcap"  # Unique filename for each device
                    # Start a new thread for each device
                    thread = threading.Thread(target=capture_device_pcap, args=(folder, file_name, "wlan0", device_mac, packets))
                    threads.append(thread)
                    thread.start()

                # Wait for all threads to finish
                for thread in threads:
                    thread.join()

                flash('Packet Capture successful for selected devices!', 'success')

            else:  # Single device
                mac = request.form['mac']
                packets = int(request.form['packets'])
                filename = request.form['filename']  # Capture the filename from the form
                folder = "/home/research/Documents/PCAP"
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                file_name = f"{filename}_{mac}_{timestamp}.pcap"  # Unique filename using MAC

                os.makedirs(folder, exist_ok=True)
                capture_and_save_pcap(folder, file_name, "wlan0", mac, packets)

                flash('Packet Capture successful for the device!', 'success')

    except Exception as e:
        flash(f'Error capturing packets: {str(e)}', 'error')

    return redirect(url_for('dashboard'))



# Flask Route for Delete
@app.route('/delete_device', methods=['POST'])
def delete_device():
    try:
        if request.is_json:
            data = request.get_json()
            mac = data.get('mac')
            with psycopg2.connect(
                dbname="Device Info",
                user="postgres",
                password="admin123!",
                host="localhost",
                port="5432"
            ) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM connected_devices WHERE mac = %s", (mac,))
                    return jsonify({'message': 'Device deleted successfully!'}), 200
        else:
            mac = request.form['mac']
            with psycopg2.connect(
                dbname="Device Info",
                user="postgres",
                password="admin123!",
                host="localhost",
                port="5432"
            ) as conn:
                with conn.cursor() as cursor:
                    cursor.execute("DELETE FROM connected_devices WHERE mac = %s", (mac,))
                    flash('Device deleted successfully!', 'success')
    except Exception as e:
        flash(f'Error deleting device: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

# Function to handle packet capture for a single device
def capture_device_pcap(folder, file_name, interface, mac_address, count):
    captured_packets = []  # List to store captured packets
    progress = 0  # Track progress of packet capture
    total_packets = count  # The total number of packets to capture

    # Callback function that will be called for each captured packet
    def packet_callback(pkt):
        nonlocal captured_packets, progress
        captured_packets.append(pkt)  # Add packet to list
        progress = len(captured_packets)  # Update progress
        device_progress[mac_address] = {"progress": progress, "total_packets": total_packets}  # Store progress and total packets for this device
        print(f"Captured {progress}/{total_packets} packets for MAC address {mac_address}...")

        # Check if the stop flag for this device is set
        if device_capture_status.get(mac_address, False):
            print(f"Stopping capture for MAC address {mac_address}...")
            raise Exception("Capture stopped manually")

        # Stop sniffing once the required number of packets are captured
        if progress >= count:
            raise Exception("Desired packet capture count reached")

    # Sniffing function running in a separate thread
    def sniff_packets():
        try:
            print(f"Starting packet capture for MAC address {mac_address}...")
            sniff(iface=interface, count=count, filter=f"ether host {mac_address}", prn=packet_callback)
        except Exception as e:
            print(f"Packet capture interrupted: {e}")

    # Start the sniffing in a separate thread to allow real-time updates
    capture_thread = threading.Thread(target=sniff_packets)
    capture_thread.start()

    # Wait for the capture thread to finish
    capture_thread.join()

    # After capture is complete, save the packets to a pcap file
    print(f"Saving captured packets to {os.path.join(folder, file_name)}...")
    wrpcap(os.path.join(folder, file_name), captured_packets)
    print(f"Packets captured and saved to {os.path.join(folder, file_name)}")

    # Step 4: Clear the progress and stop flag after the capture is done
    device_progress.pop(mac_address, None)  # Remove the device from progress tracking
    device_capture_status.pop(mac_address, None)  # Remove the stop flag for the device

# Flask route to stop packet capture for a specific device
@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    try:
        # Get MAC address from the POST data
        data = request.get_json()
        mac_address = data['mac']

        # Set the stop flag for the given device
        device_capture_status[mac_address] = True
        return jsonify({"status": "Capture stopped successfully for device {}".format(mac_address)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Function for Capturing PCAP based on MAC address
def capture_and_save_pcap(folder, file_name, interface, mac_address, count):
    print(f"Capturing {count} packets for MAC address {mac_address} on interface {interface}...")

    # Start the capture process with real-time progress updates
    capture_device_pcap(folder, file_name, interface, mac_address, count)

# Function for fetching records
def fetch_records():
    try:
        with psycopg2.connect(
            dbname="Device Info",
            user="postgres",
            password="admin123!",
            host="localhost",
            port="5432"
        ) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM connected_devices")
                records = cur.fetchall()
                return records
    except psycopg2.Error as e:
        print("PostgreSQL error:", e)
        return []

# Flask route for Refresh 
@app.route('/refresh', methods=['GET', 'POST'])
def refresh():
    if request.method == 'POST':
        records = fetch_records()
        if request.is_json:
            return jsonify({"records": records}), 200
        return render_template('dashboard.html', records=records)
    else:
        return redirect(url_for('dashboard'))
    
# Flask route for fetching the progress
@app.route('/get_progress', methods=['Get', 'POST'])
def get_progress():
    try:
        # Prepare the response with the current progress of all devices
        progress_data = [
            {"mac_address": mac, "display_name": fetch_device_name(mac), "progress": progress["progress"], "total_packets": progress["total_packets"]}
            for mac, progress in device_progress.items()
        ]
        return jsonify({"progress": progress_data}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/files_name', methods=['GET', 'POST'])
def files_name():
    try:
        # Path to the directory containing .pcap files
        directory = '/home/research/Documents/PCAP'

        # Get a list of all files in the directory
        files = os.listdir(directory)

        # Filter out files that are .pcap and extract the part before the first '_'
        data = []
        for file in files:
            if file.endswith('.pcap'):
                # Get the filename before the first underscore
                file_name = file.split('_')[0]
                data.append(file_name)

        return jsonify({"FileNames": data})

    except Exception as e:
        return jsonify({"error": str(e)})
    
@app.route('/capture_progress', methods=['GET'])
def capture_progress_page():
    # Prepare the progress data
    progress_data = [
        {
            "mac_address": mac,
            "display_name": fetch_device_name(mac),
            "progress": progress["progress"],
            "total_packets": progress["total_packets"]
        }
        for mac, progress in device_progress.items()
    ]
    
    # Print the progress data to check the output
    print("Progress Data:", progress_data)

    # Return the rendered template with the progress data
    return render_template('capture_progress.html', progress=progress_data)





# Flask route for Logout
@app.route('/logout')
def logout():
    return redirect(url_for('index'))

# Main Function
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
