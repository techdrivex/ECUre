"""
Firmware analysis engine for ECU vulnerability scanning.
"""

import os
import hashlib
import magic
from typing import Dict, List, Any, Optional
from pathlib import Path
import capstone
import pefile
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import logging

logger = logging.getLogger(__name__)


class BaseAnalyzer:
    """Base class for firmware analyzers."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        self.file_hash = self._calculate_hash()
        self.file_type = self._detect_file_type()
    
    def _calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the file."""
        sha256_hash = hashlib.sha256()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def _detect_file_type(self) -> str:
        """Detect the type of firmware file."""
        mime = magic.from_file(self.file_path, mime=True)
        if mime == 'application/octet-stream':
            # Try to determine binary type
            with open(self.file_path, 'rb') as f:
                header = f.read(16)
                if header.startswith(b'\x7fELF'):
                    return 'elf'
                elif header.startswith(b'MZ'):
                    return 'pe'
                elif header.startswith(b'\x00\x00\x00\x00'):
                    return 'raw_binary'
                else:
                    return 'unknown_binary'
        return mime
    
    def analyze(self) -> Dict[str, Any]:
        """Perform analysis on the firmware file."""
        raise NotImplementedError("Subclasses must implement analyze method")


class BinaryAnalyzer(BaseAnalyzer):
    """Analyzer for binary firmware files."""
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze binary firmware for potential vulnerabilities."""
        results = {
            'file_info': {
                'path': self.file_path,
                'size': self.file_size,
                'hash': self.file_hash,
                'type': self.file_type,
            },
            'strings': self._extract_strings(),
            'entropy': self._calculate_entropy(),
            'patterns': self._find_patterns(),
            'vulnerabilities': []
        }
        
        # Add specific analysis based on file type
        if self.file_type == 'elf':
            results.update(self._analyze_elf())
        elif self.file_type == 'pe':
            results.update(self._analyze_pe())
        
        return results
    
    def _extract_strings(self) -> List[str]:
        """Extract printable strings from binary."""
        strings = []
        with open(self.file_path, 'rb') as f:
            data = f.read()
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:  # Minimum string length
                        strings.append(current_string)
                    current_string = ""
        return strings
    
    def _calculate_entropy(self) -> float:
        """Calculate Shannon entropy of the binary."""
        import math
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _find_patterns(self) -> Dict[str, List[int]]:
        """Find common patterns in binary data."""
        patterns = {
            'null_bytes': [],
            'repeated_bytes': [],
            'suspicious_sequences': []
        }
        
        with open(self.file_path, 'rb') as f:
            data = f.read()
        
        # Find null byte sequences
        for i in range(len(data) - 3):
            if data[i:i+4] == b'\x00\x00\x00\x00':
                patterns['null_bytes'].append(i)
        
        # Find repeated byte patterns
        for i in range(len(data) - 7):
            if data[i:i+8] == data[i] * 8:
                patterns['repeated_bytes'].append(i)
        
        # Find suspicious sequences (e.g., shellcode patterns)
        suspicious_patterns = [
            b'\x90\x90\x90\x90',  # NOP sled
            b'\xcc\xcc\xcc\xcc',  # INT3 sled
        ]
        
        for pattern in suspicious_patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                patterns['suspicious_sequences'].append(pos)
                pos += 1
        
        return patterns
    
    def _analyze_elf(self) -> Dict[str, Any]:
        """Analyze ELF file specific characteristics."""
        try:
            with open(self.file_path, 'rb') as f:
                elf = ELFFile(f)
            
            elf_info = {
                'elf_header': {
                    'machine': elf.header['e_machine'],
                    'type': elf.header['e_type'],
                    'entry_point': elf.header['e_entry'],
                },
                'sections': [],
                'symbols': [],
                'vulnerabilities': []
            }
            
            # Analyze sections
            for section in elf.iter_sections():
                if isinstance(section, SymbolTableSection):
                    for symbol in section.iter_symbols():
                        elf_info['symbols'].append({
                            'name': symbol.name,
                            'address': symbol['st_value'],
                            'size': symbol['st_size'],
                            'type': symbol['st_info']['type']
                        })
                else:
                    elf_info['sections'].append({
                        'name': section.name,
                        'address': section['sh_addr'],
                        'size': section['sh_size'],
                        'flags': section['sh_flags']
                    })
            
            # Check for common vulnerabilities
            if elf.header['e_type'] == 'ET_EXEC':
                elf_info['vulnerabilities'].append({
                    'type': 'executable_elf',
                    'severity': 'medium',
                    'description': 'ELF file is marked as executable'
                })
            
            return {'elf_analysis': elf_info}
            
        except Exception as e:
            logger.error(f"Error analyzing ELF file: {e}")
            return {'elf_analysis': {'error': str(e)}}
    
    def _analyze_pe(self) -> Dict[str, Any]:
        """Analyze PE file specific characteristics."""
        try:
            pe = pefile.PE(self.file_path)
            
            pe_info = {
                'pe_header': {
                    'machine': pe.FILE_HEADER.Machine,
                    'characteristics': pe.FILE_HEADER.Characteristics,
                    'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                },
                'sections': [],
                'imports': [],
                'vulnerabilities': []
            }
            
            # Analyze sections
            for section in pe.sections:
                pe_info['sections'].append({
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'characteristics': section.Characteristics
                })
            
            # Analyze imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    imports = []
                    for imp in entry.imports:
                        if imp.name:
                            imports.append(imp.name.decode())
                    pe_info['imports'].append({
                        'dll': entry.dll.decode(),
                        'functions': imports
                    })
            
            # Check for common vulnerabilities
            if pe.FILE_HEADER.Characteristics & 0x0002:  # Executable
                pe_info['vulnerabilities'].append({
                    'type': 'executable_pe',
                    'severity': 'medium',
                    'description': 'PE file is marked as executable'
                })
            
            return {'pe_analysis': pe_info}
            
        except Exception as e:
            logger.error(f"Error analyzing PE file: {e}")
            return {'pe_analysis': {'error': str(e)}}


class HexAnalyzer(BaseAnalyzer):
    """Analyzer for Intel HEX and Motorola S-Record files."""
    
    def analyze(self) -> Dict[str, Any]:
        """Analyze HEX/S-Record firmware files."""
        results = {
            'file_info': {
                'path': self.file_path,
                'size': self.file_size,
                'hash': self.file_hash,
                'type': self.file_type,
            },
            'records': self._parse_records(),
            'memory_map': self._build_memory_map(),
            'vulnerabilities': []
        }
        
        return results
    
    def _parse_records(self) -> List[Dict[str, Any]]:
        """Parse HEX/S-Record file records."""
        records = []
        
        with open(self.file_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    if line.startswith(':'):  # Intel HEX
                        record = self._parse_hex_record(line, line_num)
                    elif line.startswith('S'):  # Motorola S-Record
                        record = self._parse_srecord(line, line_num)
                    else:
                        record = {'type': 'unknown', 'line': line_num, 'data': line}
                    
                    records.append(record)
                except Exception as e:
                    records.append({
                        'type': 'error',
                        'line': line_num,
                        'error': str(e),
                        'data': line
                    })
        
        return records
    
    def _parse_hex_record(self, line: str, line_num: int) -> Dict[str, Any]:
        """Parse Intel HEX record."""
        if len(line) < 9:  # Minimum valid HEX record length
            raise ValueError("Invalid HEX record length")
        
        # Remove leading colon
        data = line[1:]
        
        # Parse record fields
        length = int(data[0:2], 16)
        address = int(data[2:6], 16)
        record_type = int(data[6:8], 16)
        
        record = {
            'type': 'hex',
            'line': line_num,
            'length': length,
            'address': address,
            'record_type': record_type,
            'data': data[8:8+length*2] if length > 0 else '',
            'checksum': data[8+length*2:10+length*2] if length > 0 else data[8:10]
        }
        
        return record
    
    def _parse_srecord(self, line: str, line_num: int) -> Dict[str, Any]:
        """Parse Motorola S-Record."""
        if len(line) < 4:  # Minimum valid S-Record length
            raise ValueError("Invalid S-Record length")
        
        record_type = line[0:2]
        length = int(line[2:4], 16)
        
        record = {
            'type': 'srecord',
            'line': line_num,
            'record_type': record_type,
            'length': length,
            'data': line[4:4+(length-3)*2] if length > 3 else '',
            'checksum': line[4+(length-3)*2:4+(length-2)*2] if length > 3 else line[2:4]
        }
        
        return record
    
    def _build_memory_map(self) -> Dict[str, Any]:
        """Build memory map from HEX/S-Record data."""
        memory_map = {
            'segments': [],
            'total_size': 0,
            'address_range': {'min': 0xFFFFFFFF, 'max': 0}
        }
        
        # This would be implemented based on the parsed records
        # For now, return basic structure
        return memory_map


class FirmwareAnalyzer:
    """Main firmware analysis orchestrator."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.analyzer = self._get_analyzer()
    
    def _get_analyzer(self) -> BaseAnalyzer:
        """Get appropriate analyzer based on file type."""
        file_ext = Path(self.file_path).suffix.lower()
        
        if file_ext in ['.hex', '.s19', '.mot']:
            return HexAnalyzer(self.file_path)
        else:
            return BinaryAnalyzer(self.file_path)
    
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive firmware analysis."""
        try:
            results = self.analyzer.analyze()
            
            # Add common vulnerability checks
            results['vulnerabilities'].extend(self._check_common_vulnerabilities())
            
            return results
            
        except Exception as e:
            logger.error(f"Error during firmware analysis: {e}")
            return {
                'error': str(e),
                'file_path': self.file_path
            }
    
    def _check_common_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Check for common firmware vulnerabilities."""
        vulnerabilities = []
        
        # Check file size
        if self.analyzer.file_size > 100 * 1024 * 1024:  # 100MB
            vulnerabilities.append({
                'type': 'large_file_size',
                'severity': 'low',
                'description': f'File size ({self.analyzer.file_size} bytes) is unusually large for ECU firmware'
            })
        
        # Check entropy (high entropy might indicate encryption or compression)
        if hasattr(self.analyzer, '_calculate_entropy'):
            entropy = self.analyzer._calculate_entropy()
            if entropy > 7.5:
                vulnerabilities.append({
                    'type': 'high_entropy',
                    'severity': 'medium',
                    'description': f'High entropy ({entropy:.2f}) might indicate encryption or obfuscation'
                })
        
        return vulnerabilities
