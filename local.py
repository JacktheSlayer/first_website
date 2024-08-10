import os
import zipfile
from flask import Flask, request, jsonify, render_template, send_file
from scapy.all import rdpcap, wrpcap, TCP, DNS, Raw
import gridfs
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from pymongo import MongoClient
import subprocess
import pandas as pd
import struct
import dns.resolver
import logging


# Initialize Flask app
app = Flask(__name__)

# MongoDB connection
mongo_uri = 'mongodb://localhost:27017/'
client = MongoClient(mongo_uri)
db = client['pcap_database']
collection = db["pcap_files"]
dns_details_collection = db["dns_details"]
pcap_data_collection = db["pcap_data"]
fs = gridfs.GridFS(db)

logging.basicConfig(level=logging.DEBUG)


UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER



def save_pcap_to_mongodb(file):
    pcap_data = file.read()
    file_id = fs.put(pcap_data, filename=secure_filename(file.filename))
    return file_id

# Utility function to resolve domain to IP addresses
def resolve_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [answer.address for answer in answers]
    except dns.resolver.NoAnswer:
        logging.error(f"No DNS answer for domain: {domain}")
        return []
    except dns.resolver.NXDOMAIN:
        logging.error(f"Domain does not exist: {domain}")
        return []
    except dns.resolver.Timeout:
        logging.error(f"DNS query timed out for domain: {domain}")
        return []
    except dns.resolver.NoNameservers:
        logging.error(f"No nameservers available for domain: {domain}")
        return []
    except Exception as e:
        logging.error(f"DNS resolution error for domain {domain}: {e}")
        return []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def split_pcap(input_pcap, output_prefix, num_files):
    packets = rdpcap(input_pcap)
    sorted_packets = sorted(packets, key=lambda pkt: len(pkt), reverse=True)
    top_packets = sorted_packets[:num_files]
    output_files = []
    for i, pkt in enumerate(top_packets):
        output_file = os.path.join(app.config['UPLOAD_FOLDER'], f'{output_prefix}_packet{i}.pcap')
        wrpcap(output_file, [pkt])
        output_files.append(os.path.basename(output_file))
    return output_files

def create_zip(files, zip_name):
    zip_path = os.path.join(app.config['UPLOAD_FOLDER'], zip_name)
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for file in files:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file)
            if os.path.exists(file_path):
                zipf.write(file_path, file)
            else:
                print(f"File {file_path} does not exist")
    return zip_path

def extract_sni(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        if payload and payload[0] == 0x16:
            try:
                record_len = struct.unpack('!H', payload[3:5])[0]
                handshake_protocol = payload[5]
                if handshake_protocol == 0x01:
                    session_id_len = payload[43]
                    idx = 44 + session_id_len
                    cipher_suites_len = struct.unpack('!H', payload[idx:idx+2])[0]
                    idx += 2 + cipher_suites_len
                    compression_methods_len = payload[idx]
                    idx += 1 + compression_methods_len
                    extensions_len = struct.unpack('!H', payload[idx:idx+2])[0]
                    idx += 2
                    end_idx = idx + extensions_len
                    while idx < end_idx:
                        ext_type = struct.unpack('!H', payload[idx:idx+2])[0]
                        ext_len = struct.unpack('!H', payload[idx+2:idx+4])[0]
                        if ext_type == 0x00:
                            sni_data = payload[idx+4:idx+4+ext_len]
                            sni_len = struct.unpack('!H', sni_data[3:5])[0]
                            sni = sni_data[5:5+sni_len].decode('utf-8')
                            return sni
                        idx += 4 + ext_len
            except Exception as e:
                pass
    return None

def extract_domains_from_http_host(packet):
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
        try:
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load.decode(errors='ignore')
                if "Host: " in raw_data:
                    start = raw_data.find("Host: ") + 6
                    end = raw_data[start:].find("\r\n") + start
                    domain = raw_data[start:end].strip()
                    return domain
        except Exception as e:
            pass
    return None

def extract_domains_from_dns(packet):
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            domain = packet[DNS].qd.qname.decode().strip('.')
            return domain
        except Exception as e:
            pass
    return None

def extract_domains_from_pcap(pcap_file):
    domains = set()
    
    packets = rdpcap(pcap_file)
    for packet in packets:
        sni = extract_sni(packet)
        if sni:
            domains.add(("HTTPS/TLS", sni))
        
        domain = extract_domains_from_http_host(packet)
        if domain:
            domains.add(("HTTP", domain))
        
        domain = extract_domains_from_dns(packet)
        if domain:
            domains.add(("DNS", domain))
    
    return domains

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Please upload a .pcap or .pcapng file.'}), 400
    
    input_pcap = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
    file.save(input_pcap)

    # Save original pcap file
    try:
        file_id = save_pcap_to_mongodb(file)
    except Exception as e:
        print(f"Error saving file to MongoDB: {e}")
        return jsonify({'error': 'Error saving file to MongoDB.'}), 500

    # Define output prefix and number of files for split_pcap
    output_prefix = 'split_pcap'
    num_files = 5  # You can set this based on your requirements or logic

    # Split the pcap file into flows
    try:
        file_names = split_pcap(input_pcap, output_prefix, num_files)
        for file_name in file_names:
            pcap_data_collection.insert_one({
                'file_name': file_name[6],
                'src_ip': file_name[0],
                'src_port': file_name[1],
                'dst_ip': file_name[2],
                'dst_port': file_name[3],
                'protocol': file_name[4],
                'application_protocol': file_name[5]
            })
    except Exception as e:
        print(f"Error splitting PCAP file: {e}")
        return jsonify({'error': 'Error splitting PCAP file.'}), 500

    # Extract domains and save DNS details
    try:
        domains = extract_domains_from_pcap(input_pcap)
        dns_details_collection.insert_one({"file_id": file_id, "domains": list(domains)})
    except Exception as e:
        print(f"Error extracting domains: {e}")
        return jsonify({'error': 'Error extracting domains.'}), 500

    return render_template('index.html', file_id=file_id)

@app.route('/dns_view/<file_id>')
def dns_view(file_id):
    try:
        dns_info = dns_details_collection.find_one({"file_id": ObjectId(file_id)})
        if dns_info is None:
            logging.error(f"No DNS information found for file_id: {file_id}")
            return jsonify({'error': 'No DNS information found for this file ID'}), 404
        domains = dns_info.get('domains', [])
        return render_template('dns_view.html', domains=domains, file_id=file_id)
    except Exception as e:
        logging.error(f"Error retrieving DNS information: {e}")
        return jsonify({'error': 'Error retrieving DNS information'}), 500

if __name__ == '__main__':
    app.run(debug=True)