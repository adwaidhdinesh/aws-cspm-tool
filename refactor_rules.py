import os
import re

RULES_DIR = "src/rules"

for filename in os.listdir(RULES_DIR):
    if not filename.endswith("_rules.py"):
        continue
        
    filepath = os.path.join(RULES_DIR, filename)
    with open(filepath, "r") as f:
        content = f.read()
        
    # Add import
    if "from src.rules._helpers import make_finding" not in content:
        content = re.sub(r'("""\n)', r'\1\nfrom src.rules._helpers import make_finding\n', content, count=1)
        
    # Replace dictionary creation with make_finding call
    # It looks like: findings.append({\n            "rule_id": "IAM-001", ... \n        })
    
    # We can use regex to match findings.append({ ... })
    pattern = re.compile(
        r'findings\.append\(\{\s*'
        r'"rule_id":\s*([^,]+),\s*'
        r'"cis_control":\s*([^,]+),\s*'
        r'"title":\s*([^,]+),\s*'
        r'"severity":\s*([^,]+),\s*'
        r'"service":\s*([^,]+),\s*'
        r'"resource":\s*([^,]+),\s*'
        r'"status":\s*([^,]+),\s*'
        r'"description":\s*(("[^"]*"\s*)+),\s*'
        r'"remediation":\s*(("[^"]*"\s*)+),?\s*'
        r'\}\)',
        re.DOTALL
    )
    
    def repl(m):
        rule_id = m.group(1).strip()
        cis_control = m.group(2).strip()
        title = m.group(3).strip()
        severity = m.group(4).strip()
        service = m.group(5).strip()
        resource = m.group(6).strip()
        status = m.group(7).strip()
        desc = m.group(8).strip()
        rem = m.group(10).strip()
        
        return f"""findings.append(make_finding(
            asset=asset,
            rule_id={rule_id},
            title={title},
            severity={severity},
            status={status},
            description={desc},
            remediation={rem},
            cis_control={cis_control}
        ))"""

    new_content = pattern.sub(repl, content)
    
    # The regex might fail if keys are in different order, let's see.
    with open(filepath, "w") as f:
        f.write(new_content)
    
    print(f"Processed {filename}")
