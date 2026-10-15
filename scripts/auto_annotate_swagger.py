import re
import os

CORE_DIR = "/Users/patrickmatthews/Downloads/Web Dev - Patrick/Cicada Project/Core_API/app/Http/Controllers"

def replace_in_file(filepath):
    if not os.path.exists(filepath):
        print(f"Skipping {filepath}, not found")
        return
        
    with open(filepath, 'r') as f:
        content = f.read()
        
    if "OpenApi\\Attributes" in content:
        print(f"Skipping {filepath}, already has OA")
        return
        
    # Inject OpenApi import
    content = content.replace("use Illuminate\\Http\\Request;", "use Illuminate\\Http\\Request;\nuse OpenApi\\Attributes as OA;")
    
    # Simple regex to find public functions that return JsonResponse or similar
    # We will just inject a basic #[OA\Get] or #[OA\Post] depending on the method name
    
    lines = content.split('\n')
    new_lines = []
    
    for line in lines:
        match = re.search(r'public function (\w+)\(', line)
        if match:
            method_name = match.group(1)
            
            # very basic heuristics
            if method_name.startswith('get') or method_name in ['index', 'show', 'list', 'summary', 'profile', 'metrics', 'biography']:
                verb = "Get"
            elif method_name in ['store', 'register', 'create', 'bindKey', 'provision', 'quarantine', 'resolve']:
                verb = "Post"
            elif method_name in ['update', 'toggle', 'bulkUpdate']:
                verb = "Patch"
            elif method_name in ['destroy', 'delete']:
                verb = "Delete"
            else:
                verb = "Post" # default generic
                
            attr = f"    #[OA\\{verb}(\n        path: '/api/v1/auto/{method_name}',\n        summary: '{method_name}',\n        tags: ['Auto Generated']\n    )]\n    #[OA\\Response(response: 200, description: 'Success')]"
            new_lines.append(attr)
            
        new_lines.append(line)
        
    with open(filepath, 'w') as f:
        f.write('\n'.join(new_lines))
    print(f"Annotated {filepath}")

# Target remaining controllers
targets = [
    "ComplianceController.php",
    "GatewayController.php",
    "RetentionPolicyController.php",
    "TenantController.php",
    "ProvisioningController.php",
    "VaultController.php"
]

for t in targets:
    replace_in_file(os.path.join(CORE_DIR, t))

print("Done annotating remaining endpoints.")
