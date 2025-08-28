import re
from typing import Dict, List, Tuple, Any
import sys
import csv
import json

class ISCP:
    def __init__(self):
        # Regeneration funct
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')  
        self.email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        self.upi_pattern = re.compile(r'\b[\w.-]+@[a-zA-Z0-9.-]+\b')
    
    def is_standalone_pii(self, key: str, value: str) -> bool:
        value = str(value)
        if key == 'aadhar' or (len(value) == 12 and value.isdigit()):
            return True
        if key == 'phone' or (len(value) == 10 and value.isdigit()):
            return True                        
        if key == 'upi_id':
            return True
        if key == 'passport' or self.passport_pattern.match(value):
            return True
        elif '@' in value and not '.' in value.split('@')[1]:
            if self.upi_pattern.match(value.lower()):
                return True         
        return False
    
    def get_combinatorial_fields(self, data: Dict[str, Any]) -> List[str]:
        found_fields = []
        # Uses pydefaults
        
        for key, value in data.items():
            value = str(value)
            if key == 'ip_address' and self.ip_pattern.match(value):
                found_fields.append('ip_address')
            elif key == 'name' and ' ' in value.strip() and len(value.strip().split()) >= 2:
                found_fields.append('name')
            elif key == 'email' and self.email_pattern.match(value):
                found_fields.append('email')
            elif key == 'address' and ',' in value and any(char.isdigit() for char in value):
                found_fields.append('address')
            elif key == 'device_id' and len(value) > 3:
                found_fields.append('device_id')
        
        return found_fields


    def has_combinatorial_pii(self, data: Dict[str, Any]) -> bool:
        combinatorial_fields = self.get_combinatorial_fields(data)
        return len(combinatorial_fields) >= 2


    def redact_value(self, key: str, value: str) -> str:
        value = str(value)
        if key == 'ip_address':
            return f"{value[:3]}.XXX.XXX.XXX"
        elif key == 'phone':
            return f"{value[:2]}XXXXXX{value[-2:]}"
        elif key == 'aadhar':
            return f"{value[:4]}XXXXXX{value[-2:]}"
        elif key == 'passport':
            return f"{value[0]}XXXX{value[-3:]}"
        if key == 'upi_id' or (self.is_standalone_pii('upi_id_check', value) and '@' in value):
            if '@' in value:
                parts = value.split('@')
                return f"{parts[0][:2]}XXX@{parts[1]}"
            else:
                return "[REDACTED_UPI]"        
        if key == 'name' and ' ' in value:
            parts = value.split()
            if len(parts) >= 2:
                return f"{parts[0][0]}XXX {parts[-1][0]}XXX"        
        if key == 'email' and '@' in value:
            local, domain = value.split('@', 1)
            return f"{local[:2]}XXX@{domain}"

        # due to inconsistency, below field are completely masked
        
        if key == 'address':
            return "[REDACTED_ADDRESS]"
            
        if key == 'device_id':
            return "[REDACTED_DEVICE_ID]"
        
        return value
    

    def process_record(self, record_data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        is_pii = False #base
        redacted_data = {}
        
        for key, value in record_data.items():
            if self.is_standalone_pii(key, value):
                is_pii = True
                redacted_data[key] = self.redact_value(key, value)
            else:
                redacted_data[key] = value
        
        if not is_pii:
            combinatorial_fields = self.get_combinatorial_fields(record_data)
            if len(combinatorial_fields) >= 2:
                is_pii = True
                for key, value in record_data.items():
                    if key in combinatorial_fields:
                        redacted_data[key] = self.redact_value(key, value)
                    else:
                        redacted_data[key] = value
                
        return redacted_data, is_pii
    
def main():
    if len(sys.argv) != 2:
        print("Hi Evaluator..!")
        print("Usage: python3 detector_harsh_verma.py <file_name>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = 'redacted_output_harsh_verma.csv'
    
    proc = ISCP()
    
    results = []
    pii_count = 0
    total_count = 0
    
    try:
        with open(input_file, 'r') as f:
            reader = csv.reader(f)
            header = next(reader)
            
            for row in reader:
                record_id, json_data = row
                total_count += 1
                
                try:
                    data = json.loads(json_data)
                    
                    redacted_data, is_pii = proc.process_record(data)
                    
                    if is_pii:
                        pii_count += 1
                    
                    redacted_json = json.dumps(redacted_data)
                    
                    results.append([record_id, redacted_json, str(is_pii)])
                    
                except Exception as e:
                    print(f"Error processing record {record_id}: {e}")
                    results.append([record_id, json_data, "False"])
        
        # Write output CSV
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['record_id', 'redacted_data_json', 'is_pii'])
            writer.writerows(results)
        
        print(f"Execution DONE!")
        print(f"Total records parsed: {total_count}")
        print(f"Number of records with PII: {pii_count}")
        print(f"Calculated PII percentage: {pii_count/total_count*100:.1f}%")
        print(f"Output written to/file dir: {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()