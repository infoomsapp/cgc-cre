"""
Remove all print statements from Python files
Black Box Mode - Silent Operation
"""

import os
import re

FILES_TO_CLEAN = [
    'auth_system.py',
    'cgc_core/cgc_loop.py',
    'cgc_core/ecm_module.py',
    'cgc_core/pan_module.py',
    'cgc_core/pfm_module.py',
    'cgc_core/sda_module.py',
    'cgc_core/tco_module.py',
    'cgc_core/__init__.py',
    'discipleai_legal/clause_extractor.py',
    'discipleai_legal/compliance_checker.py',
    'discipleai_legal/contract_analyzer.py',
    'discipleai_legal/contract_analyzer_ai.py',
    'discipleai_legal/legal_core.py',
    'discipleai_legal/legal_research_engine.py',
    'discipleai_legal/risk_assessor.py',
    'discipleai_legal/__init__.py'
]

def remove_prints(filepath):
    """Remove print statements from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # Remove prints with emojis/checkmarks
        content = re.sub(r'^\s*print\(f?"[^"]*✅[^"]*"\)\s*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'^\s*print\(f?"[^"]*🔄[^"]*"\)\s*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'^\s*print\(f?"[^"]*⚙️[^"]*"\)\s*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'^\s*print\(f?"[^"]*🚀[^"]*"\)\s*$', '', content, flags=re.MULTILINE)
        
        # Remove any print with module initialization
        content = re.sub(r'^\s*print\(f?".*initialized.*"\)\s*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'^\s*print\(f?".*v\{self\.version\}.*"\)\s*$', '', content, flags=re.MULTILINE)
        
        # Clean up multiple blank lines
        content = re.sub(r'\n\n\n+', '\n\n', content)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✓ Cleaned: {filepath}")
            return True
        else:
            print(f"- Skipped: {filepath} (no changes)")
            return False
            
    except Exception as e:
        print(f"✗ Error: {filepath} - {e}")
        return False

def main():
    """Clean all files"""
    print("Black Box Cleanup - Removing all print statements\n")
    
    cleaned = 0
    skipped = 0
    errors = 0
    
    for filepath in FILES_TO_CLEAN:
        if os.path.exists(filepath):
            if remove_prints(filepath):
                cleaned += 1
            else:
                skipped += 1
        else:
            print(f"✗ Not found: {filepath}")
            errors += 1
    
    print(f"\nSummary:")
    print(f"  Cleaned: {cleaned}")
    print(f"  Skipped: {skipped}")
    print(f"  Errors: {errors}")
    print(f"\n✓ Black box mode activated")

if __name__ == '__main__':
    main()