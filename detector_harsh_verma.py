class PIIDetectorRedactor:
    def __init__(self):
        # Regeneration funct
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')  
        self.email_pattern = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
        self.upi_pattern = re.compile(r'\b(?:\d{10}@[a-z]+|[a-z0-9]{3,15}@(?:paytm|ybl))\b')
    
    