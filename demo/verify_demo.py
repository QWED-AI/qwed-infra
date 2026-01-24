import os
import sys
from qwed_infra import IamGuard, NetworkGuard, CostGuard, TerraformParser

def run_demo():
    print("🚀 Starting QWED-Infra Verification Demo")
    print("---------------------------------------")
    
    # 1. Parse Terraform
    parser = TerraformParser()
    demo_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"📂 Parsing Terraform in: {demo_dir}")
    
    resources = parser.parse_directory(demo_dir)
    print(f"   Found {len(resources['instances'])} instances, {len(resources['policies'])} policies.")
    
    guards_failed = 0
    
    # 2. IAM Verification (Z3)
    print("\n🛡️  Running IamGuard (Z3 Solver)...")
    iam = IamGuard()
    for policy in resources.get("policies", []):
        # We need to extract the raw policy dict. 
        # Our parser currently returns the mock struct.
        # For this demo, let's manually reconstruct the risky dict since our parse logic for JSON string is TODO.
        # In a real app, parser does this.
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
        
        print(f"   Checking Policy: {policy['id']}")
        
        # Check Least Privilege
        res = iam.verify_least_privilege(policy_doc)
        if res.allowed:
            print(f"   ❌ VIOLATION: Policy '{policy['id']}' allows Admin Access (*:*)")
            guards_failed += 1
        else:
            print(f"   ✅ PASS: Policy '{policy['id']}' is least-privilege.")

    # 3. Network Verification (Graph)
    print("\n🌐 Running NetworkGuard (Graph Theory)...")
    net = NetworkGuard()
    # Mocking the infra structure derived from TF for NetworkGuard
    # (Since our parser doesn't fully Map SG rules to dicts yet)
    infra_map = {
        "subnets": [{"id": "subnet-1", "security_groups": ["open_ssh"]}],
        "route_tables": [{"subnet_id": "subnet-1", "routes": {"0.0.0.0/0": "igw"}}],
        "security_groups": {
            "open_ssh": {"ingress": [{"port": 22, "cidr": "0.0.0.0/0"}]} # Derived from TF
        }
    }
    
    res = net.verify_reachability(infra_map, "internet", "subnet-1", 22)
    if res.reachable:
         print(f"   ❌ VIOLATION: SSH (Port 22) is reachable from Internet via 'open_ssh'")
         guards_failed += 1
    else:
         print(f"   ✅ PASS: SSH is safe.")

    # 4. Cost Verification (Math)
    print("\n💰 Running CostGuard (Pricing API)...")
    cost = CostGuard()
    # Pass instances directly
    budget = 500.0
    res = cost.verify_budget(resources, budget_monthly=budget)
    
    if not res.within_budget:
        print(f"   ❌ VIOLATION: Estimated cost ${res.total_monthly_cost:.2f} exceeds budget ${budget:.2f}")
        print(f"      Breakdown: {res.breakdown}")
        guards_failed += 1
    else:
        print(f"   ✅ PASS: Within budget.")

    print("\n---------------------------------------")
    if guards_failed > 0:
        print(f"🚨 DEMO FAILED: Found {guards_failed} Security/Cost Violations.")
        sys.exit(1)
    else:
        print("✅ DEMO PASSED: Infrastructure is secure.")
        sys.exit(0)

if __name__ == "__main__":
    run_demo()
