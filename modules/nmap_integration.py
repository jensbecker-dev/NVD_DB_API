"""
Module for Nmap scan integration with the NVD database.
This module provides functionality to:
1. Run Nmap scans
2. Parse scan results
3. Correlate discovered services with CVE vulnerabilities
4. Store scan results in the database
"""

import subprocess
import xml.etree.ElementTree as ET
import json
import logging
import os
import time
from datetime import datetime
import ipaddress
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NmapScanner:
    """
    Class for running Nmap scans and processing the results.
    """
    
    def __init__(self, nmap_path="nmap"):
        """
        Initialize the scanner with the path to the nmap executable.
        
        Args:
            nmap_path: Path to the nmap executable (defaults to "nmap" assuming it's in PATH)
        """
        self.nmap_path = nmap_path
        self.last_scan_result = None
        self.last_scan_time = None
        
    def check_nmap_installed(self):
        """
        Check if Nmap is installed and accessible.
        
        Returns:
            bool: True if Nmap is installed, False otherwise
        """
        try:
            result = subprocess.run([self.nmap_path, "-V"], 
                                   capture_output=True, 
                                   text=True, 
                                   timeout=5)
            
            if result.returncode == 0 and "Nmap version" in result.stdout:
                logger.info(f"Nmap found: {result.stdout.splitlines()[0]}")
                return True
            else:
                logger.error(f"Nmap check failed with return code {result.returncode}")
                return False
                
        except FileNotFoundError:
            logger.error(f"Nmap not found at {self.nmap_path}")
            return False
        except subprocess.TimeoutExpired:
            logger.error("Nmap version check timed out")
            return False
        except Exception as e:
            logger.error(f"Error checking Nmap installation: {e}")
            return False
    
    def run_scan(self, target, options="-sV -sC -O", output_file=None):
        """
        Run an Nmap scan with the specified options.
        
        Args:
            target: Target to scan (IP, hostname, or CIDR range)
            options: Nmap options (default: "-sV -sC -O" for service, script, and OS detection)
            output_file: Base name for output files (XML and JSON) - without extension
            
        Returns:
            dict: Scan results in a structured format or None if scan failed
        """
        try:
            # Validate target
            self._validate_target(target)
            
            # Generate output filenames if not provided
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"nmap_scan_{timestamp}"
            
            xml_output = f"{output_file}.xml"
            
            # Construct and execute the Nmap command
            cmd = [self.nmap_path]
            cmd.extend(options.split())
            cmd.extend(["-oX", xml_output])
            cmd.append(target)
            
            logger.info(f"Starting Nmap scan of {target} with options: {options}")
            logger.info(f"Command: {' '.join(cmd)}")
            
            # Run the scan
            start_time = time.time()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            
            duration = time.time() - start_time
            
            if process.returncode != 0:
                logger.error(f"Nmap scan failed with return code {process.returncode}")
                logger.error(f"Error: {stderr}")
                return None
            
            logger.info(f"Nmap scan completed in {duration:.2f} seconds")
            
            # Parse the XML output
            if os.path.exists(xml_output):
                scan_results = self.parse_xml_output(xml_output)
                
                # Save as JSON for easier consumption
                json_output = f"{output_file}.json"
                with open(json_output, 'w') as f:
                    json.dump(scan_results, f, indent=2)
                
                logger.info(f"Scan results saved to {xml_output} and {json_output}")
                
                # Save scan results and time
                self.last_scan_result = scan_results
                self.last_scan_time = datetime.now()
                
                return scan_results
            else:
                logger.error(f"XML output file not found: {xml_output}")
                return None
                
        except Exception as e:
            logger.error(f"Error running Nmap scan: {e}")
            return None
    
    def _validate_target(self, target):
        """
        Validate that the target is a valid IP, hostname, or CIDR range.
        
        Args:
            target: Target to validate
            
        Raises:
            ValueError: If target is invalid
        """
        # Check if it's a CIDR range
        try:
            ipaddress.ip_network(target, strict=False)
            return
        except ValueError:
            pass
        
        # Check if it's a single IP
        try:
            ipaddress.ip_address(target)
            return
        except ValueError:
            pass
        
        # Check if it's a hostname (very basic check)
        if "." in target and all(part.isalnum() for part in target.split(".")):
            return
        
        # If we got here, target doesn't look valid
        raise ValueError(f"Invalid target format: {target}")
    
    def parse_xml_output(self, xml_file):
        """
        Parse the XML output from an Nmap scan.
        
        Args:
            xml_file: Path to the XML output file
            
        Returns:
            dict: Structured scan results
        """
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract basic scan information
            scan_info = {
                'scanner': root.get('scanner', 'nmap'),
                'args': root.get('args', ''),
                'start_time': root.get('start', ''),
                'version': root.get('version', ''),
                'scan_type': root.find('.//scaninfo').get('type', '') if root.find('.//scaninfo') is not None else '',
                'protocol': root.find('.//scaninfo').get('protocol', '') if root.find('.//scaninfo') is not None else '',
                'num_services': root.find('.//scaninfo').get('numservices', '') if root.find('.//scaninfo') is not None else '',
                'hosts': []
            }
            
            # Process each host
            for host in root.findall('.//host'):
                host_data = {
                    'status': host.find('status').get('state', '') if host.find('status') is not None else 'unknown',
                    'addresses': [],
                    'hostnames': [],
                    'ports': [],
                    'os_matches': []
                }
                
                # Extract addresses (IP and MAC)
                for addr in host.findall('address'):
                    host_data['addresses'].append({
                        'addr': addr.get('addr', ''),
                        'addrtype': addr.get('addrtype', ''),
                        'vendor': addr.get('vendor', '')
                    })
                
                # Extract hostnames
                hostnames_elem = host.find('hostnames')
                if hostnames_elem is not None:
                    for hostname in hostnames_elem.findall('hostname'):
                        host_data['hostnames'].append({
                            'name': hostname.get('name', ''),
                            'type': hostname.get('type', '')
                        })
                
                # Extract ports and services
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_data = {
                            'protocol': port.get('protocol', ''),
                            'portid': port.get('portid', ''),
                            'state': port.find('state').get('state', '') if port.find('state') is not None else 'unknown',
                            'service': {},
                            'scripts': []
                        }
                        
                        # Extract service information
                        service_elem = port.find('service')
                        if service_elem is not None:
                            service_data = {
                                'name': service_elem.get('name', ''),
                                'product': service_elem.get('product', ''),
                                'version': service_elem.get('version', ''),
                                'extrainfo': service_elem.get('extrainfo', ''),
                                'ostype': service_elem.get('ostype', ''),
                                'method': service_elem.get('method', ''),
                                'conf': service_elem.get('conf', '')
                            }
                            port_data['service'] = service_data
                        
                        # Extract script results
                        for script in port.findall('script'):
                            script_data = {
                                'id': script.get('id', ''),
                                'output': script.get('output', '')
                            }
                            port_data['scripts'].append(script_data)
                        
                        host_data['ports'].append(port_data)
                
                # Extract OS detection results
                os_elem = host.find('os')
                if os_elem is not None:
                    for os_match in os_elem.findall('osmatch'):
                        os_data = {
                            'name': os_match.get('name', ''),
                            'accuracy': os_match.get('accuracy', ''),
                            'line': os_match.get('line', ''),
                            'osclasses': []
                        }
                        
                        for os_class in os_match.findall('osclass'):
                            os_class_data = {
                                'type': os_class.get('type', ''),
                                'vendor': os_class.get('vendor', ''),
                                'osfamily': os_class.get('osfamily', ''),
                                'osgen': os_class.get('osgen', ''),
                                'accuracy': os_class.get('accuracy', '')
                            }
                            os_data['osclasses'].append(os_class_data)
                        
                        host_data['os_matches'].append(os_data)
                
                scan_info['hosts'].append(host_data)
            
            return scan_info
            
        except Exception as e:
            logger.error(f"Error parsing Nmap XML output: {e}")
            return None
    
    def correlate_with_cve(self, scan_results, cve_api):
        """
        Correlate Nmap scan results with CVE data to identify potential vulnerabilities.
        
        Args:
            scan_results: Nmap scan results from parse_xml_output
            cve_api: Instance of CVE API for querying vulnerabilities
            
        Returns:
            dict: Enhanced scan results with CVE information
        """
        if scan_results is None:
            return None
        
        try:
            # Create a deep copy of scan results to avoid modifying the original
            enhanced_results = json.loads(json.stringify(scan_results))
            
            for host in enhanced_results['hosts']:
                for port in host['ports']:
                    service = port['service']
                    
                    # Only process ports with identifiable services
                    if not service or not service.get('name'):
                        continue
                    
                    product = service.get('product', '')
                    version = service.get('version', '')
                    
                    # Skip if no product information is available
                    if not product:
                        continue
                    
                    # Search for vulnerabilities related to this service
                    vendor = product.split()[0] if product else service.get('name', '')
                    
                    logger.info(f"Searching for vulnerabilities: {vendor} {product} {version}")
                    vulnerabilities = cve_api.search_by_product(vendor, product)
                    
                    # Add vulnerabilities to port data
                    port['vulnerabilities'] = []
                    for vuln in vulnerabilities:
                        cve_id = vuln.get('id')
                        if cve_id:
                            port['vulnerabilities'].append({
                                'cve_id': cve_id,
                                'description': vuln.get('description', ''),
                                'cvss_score': vuln.get('cvss_v3_score') or vuln.get('cvss_v2_score'),
                                'severity': vuln.get('severity', 'UNKNOWN')
                            })
            
            return enhanced_results
            
        except Exception as e:
            logger.error(f"Error correlating with CVE data: {e}")
            return scan_results  # Return original results if correlation fails

def create_nmap_tables(engine):
    """
    Create tables for storing Nmap scan results.
    
    Args:
        engine: SQLAlchemy engine object
        
    Returns:
        tuple: (NmapScan, NmapHost, NmapPort) model classes
    """
    metadata = sa.MetaData()
    
    # Table for Nmap scans
    nmap_scans = sa.Table(
        'nmap_scans',
        metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('scan_time', sa.DateTime, nullable=False),
        sa.Column('target', sa.String(255), nullable=False),
        sa.Column('options', sa.String(255)),
        sa.Column('scan_type', sa.String(50)),
        sa.Column('protocol', sa.String(50)),
        sa.Column('num_services', sa.String(50)),
        sa.Column('num_hosts', sa.Integer),
        sa.Column('scanner_version', sa.String(50)),
        sa.Column('xml_file', sa.String(255)),
        sa.Column('json_file', sa.String(255))
    )
    
    # Table for hosts discovered in scans
    nmap_hosts = sa.Table(
        'nmap_hosts',
        metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('scan_id', sa.Integer, sa.ForeignKey('nmap_scans.id')),
        sa.Column('ip_address', sa.String(255)),
        sa.Column('hostname', sa.String(255)),
        sa.Column('status', sa.String(50)),
        sa.Column('mac_address', sa.String(50)),
        sa.Column('mac_vendor', sa.String(255)),
        sa.Column('os_name', sa.String(255)),
        sa.Column('os_accuracy', sa.String(50))
    )
    
    # Table for open ports/services on hosts
    nmap_ports = sa.Table(
        'nmap_ports',
        metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('host_id', sa.Integer, sa.ForeignKey('nmap_hosts.id')),
        sa.Column('port_id', sa.Integer),
        sa.Column('protocol', sa.String(50)),
        sa.Column('state', sa.String(50)),
        sa.Column('service_name', sa.String(255)),
        sa.Column('service_product', sa.String(255)),
        sa.Column('service_version', sa.String(255)),
        sa.Column('service_extra', sa.String(255))
    )
    
    # Table for vulnerabilities found on services
    nmap_vulnerabilities = sa.Table(
        'nmap_vulnerabilities',
        metadata,
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('port_id', sa.Integer, sa.ForeignKey('nmap_ports.id')),
        sa.Column('cve_id', sa.String(50), sa.ForeignKey('cves.cve_id')),
        sa.Column('cvss_score', sa.Float),
        sa.Column('severity', sa.String(50))
    )
    
    # Create all tables
    metadata.create_all(engine)
    
    # Create ORM models
    class NmapScan:
        pass
    
    class NmapHost:
        pass
    
    class NmapPort:
        pass
    
    class NmapVulnerability:
        pass
    
    # Map tables to classes
    sa.orm.mapper(NmapScan, nmap_scans)
    sa.orm.mapper(NmapHost, nmap_hosts)
    sa.orm.mapper(NmapPort, nmap_ports)
    sa.orm.mapper(NmapVulnerability, nmap_vulnerabilities)
    
    return (NmapScan, NmapHost, NmapPort, NmapVulnerability)

def store_scan_results(scan_results, engine, model_classes):
    """
    Store Nmap scan results in the database.
    
    Args:
        scan_results: Nmap scan results (from parse_xml_output)
        engine: SQLAlchemy engine object
        model_classes: Tuple of (NmapScan, NmapHost, NmapPort, NmapVulnerability) models
        
    Returns:
        int: ID of the created scan record or None if failed
    """
    if not scan_results:
        logger.error("No scan results to store")
        return None
    
    try:
        NmapScan, NmapHost, NmapPort, NmapVulnerability = model_classes
        
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Create scan record
        scan = NmapScan()
        scan.scan_time = datetime.fromtimestamp(int(scan_results.get('start_time', time.time())))
        scan.target = scan_results.get('args', '').split()[-1]  # Last argument is typically the target
        scan.options = scan_results.get('args', '')
        scan.scan_type = scan_results.get('scan_type', '')
        scan.protocol = scan_results.get('protocol', '')
        scan.num_services = scan_results.get('num_services', '')
        scan.num_hosts = len(scan_results.get('hosts', []))
        scan.scanner_version = scan_results.get('version', '')
        
        session.add(scan)
        session.flush()  # Get the ID without committing
        scan_id = scan.id
        
        # Process each host
        for host_data in scan_results.get('hosts', []):
            # Skip hosts that are not up
            if host_data.get('status') != 'up':
                continue
            
            # Get IP and MAC addresses
            ip_address = None
            mac_address = None
            mac_vendor = None
            
            for addr in host_data.get('addresses', []):
                if addr.get('addrtype') == 'ipv4':
                    ip_address = addr.get('addr')
                elif addr.get('addrtype') == 'mac':
                    mac_address = addr.get('addr')
                    mac_vendor = addr.get('vendor')
            
            # Get hostname
            hostname = None
            for host in host_data.get('hostnames', []):
                if host.get('type') == 'user':
                    hostname = host.get('name')
                    break
            
            # Get OS information (use the highest accuracy match)
            os_name = None
            os_accuracy = None
            best_accuracy = 0
            
            for os_match in host_data.get('os_matches', []):
                accuracy = int(os_match.get('accuracy', 0))
                if accuracy > best_accuracy:
                    os_name = os_match.get('name')
                    os_accuracy = os_match.get('accuracy')
                    best_accuracy = accuracy
            
            # Create host record
            host = NmapHost()
            host.scan_id = scan_id
            host.ip_address = ip_address
            host.hostname = hostname
            host.status = host_data.get('status')
            host.mac_address = mac_address
            host.mac_vendor = mac_vendor
            host.os_name = os_name
            host.os_accuracy = os_accuracy
            
            session.add(host)
            session.flush()
            host_id = host.id
            
            # Process ports/services
            for port_data in host_data.get('ports', []):
                # Skip closed ports
                if port_data.get('state') != 'open':
                    continue
                
                service = port_data.get('service', {})
                
                # Create port record
                port = NmapPort()
                port.host_id = host_id
                port.port_id = int(port_data.get('portid', 0))
                port.protocol = port_data.get('protocol')
                port.state = port_data.get('state')
                port.service_name = service.get('name')
                port.service_product = service.get('product')
                port.service_version = service.get('version')
                port.service_extra = service.get('extrainfo')
                
                session.add(port)
                session.flush()
                port_id = port.id
                
                # Process vulnerabilities if present
                for vuln in port_data.get('vulnerabilities', []):
                    vulnerability = NmapVulnerability()
                    vulnerability.port_id = port_id
                    vulnerability.cve_id = vuln.get('cve_id')
                    vulnerability.cvss_score = vuln.get('cvss_score')
                    vulnerability.severity = vuln.get('severity')
                    
                    session.add(vulnerability)
            
        # Commit all changes
        session.commit()
        logger.info(f"Stored scan results with ID {scan_id}")
        return scan_id
        
    except Exception as e:
        logger.error(f"Error storing scan results: {e}")
        session.rollback()
        return None
    finally:
        session.close()

def get_scan_summary(scan_id, engine, model_classes):
    """
    Get a summary of a scan by ID.
    
    Args:
        scan_id: ID of the scan
        engine: SQLAlchemy engine object
        model_classes: Tuple of (NmapScan, NmapHost, NmapPort, NmapVulnerability) models
        
    Returns:
        dict: Scan summary or None if not found
    """
    try:
        NmapScan, NmapHost, NmapPort, NmapVulnerability = model_classes
        
        Session = sessionmaker(bind=engine)
        session = Session()
        
        # Get the scan
        scan = session.query(NmapScan).filter(NmapScan.id == scan_id).first()
        if not scan:
            logger.error(f"Scan with ID {scan_id} not found")
            return None
        
        # Get hosts
        hosts = session.query(NmapHost).filter(NmapHost.scan_id == scan_id).all()
        
        # Get ports and vulnerabilities for each host
        host_summaries = []
        total_vulnerabilities = 0
        critical_vulnerabilities = 0
        high_vulnerabilities = 0
        
        for host in hosts:
            ports = session.query(NmapPort).filter(NmapPort.host_id == host.id).all()
            
            port_summaries = []
            host_vuln_count = 0
            
            for port in ports:
                vulnerabilities = session.query(NmapVulnerability).filter(NmapVulnerability.port_id == port.id).all()
                
                vuln_summaries = []
                for vuln in vulnerabilities:
                    vuln_summaries.append({
                        'cve_id': vuln.cve_id,
                        'cvss_score': vuln.cvss_score,
                        'severity': vuln.severity
                    })
                    
                    host_vuln_count += 1
                    total_vulnerabilities += 1
                    
                    if vuln.severity == 'CRITICAL':
                        critical_vulnerabilities += 1
                    elif vuln.severity == 'HIGH':
                        high_vulnerabilities += 1
                
                port_summaries.append({
                    'port_id': port.port_id,
                    'protocol': port.protocol,
                    'service_name': port.service_name,
                    'service_product': port.service_product,
                    'service_version': port.service_version,
                    'vulnerabilities': vuln_summaries
                })
            
            host_summaries.append({
                'ip_address': host.ip_address,
                'hostname': host.hostname,
                'os_name': host.os_name,
                'ports': port_summaries,
                'vulnerability_count': host_vuln_count
            })
        
        # Create summary
        summary = {
            'scan_id': scan.id,
            'scan_time': scan.scan_time,
            'target': scan.target,
            'num_hosts': len(hosts),
            'hosts': host_summaries,
            'total_vulnerabilities': total_vulnerabilities,
            'critical_vulnerabilities': critical_vulnerabilities,
            'high_vulnerabilities': high_vulnerabilities
        }
        
        return summary
        
    except Exception as e:
        logger.error(f"Error getting scan summary: {e}")
        return None
    finally:
        session.close()