import hcl2
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

class TerraformParser:
    """
    Parses Terraform (.tf) files into a unified dictionary structure
    compatible with QWED Guards (IamGuard, NetworkGuard, CostGuard).
    """

    def parse_directory(self, directory_path: str) -> Dict[str, Any]:
        """
        Reads all .tf files in a directory and aggregates resources.
        """
        path = Path(directory_path)
        combined_hcl = {}
        
        # 1. Read and merge generic HCL structure
        for tf_file in path.glob("*.tf"):
            with open(tf_file, 'r') as f:
                try:
                    data = hcl2.load(f)
                    # Merge logic (simplified: appending lists)
                    for key, val in data.items():
                        if key not in combined_hcl:
                            combined_hcl[key] = []
                        combined_hcl[key].extend(val)
                except Exception as e:
                    print(f"Error parsing {tf_file}: {e}")

        # 2. Normalize to QWED Internal Schema
        qwed_resources = {
            "instances": [],
            "policies": [],
            "subnets": [],
            "security_groups": [],
            "volumes": []
        }
        
        resources = combined_hcl.get("resource", [])
        
        for resource_block in resources:
            for res_type, res_dict in resource_block.items():
                # res_dict is usually { "resource_name": { config } }
                for res_name, config in res_dict.items():
                    normalized = self._normalize_resource(res_type, res_name, config)
                    if normalized:
                        cat = normalized["category"]
                        qwed_resources[cat].append(normalized["data"])
                        
        return qwed_resources

    def _normalize_resource(self, res_type: str, res_name: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Maps generic Terraform resource types to QWED schema.
        """
        # --- Compute ---
        if res_type == "aws_instance":
            return {
                "category": "instances",
                "data": {
                    "id": res_name, # Terraform logical ID
                    "instance_type": config.get("instance_type", "t2.micro"),
                    "count": config.get("count", 1) # TODO: Handle variable interpolation
                }
            }
            
        # --- IAM ---
        if res_type == "aws_iam_policy":
            policy_json = config.get("policy")
            try:
                # Often extracted as string (jsonencode), need to parse if string
                if isinstance(policy_json, str):
                    # In hcl2 parsing, this might come as "${jsonencode(...)}" or raw heredoc
                    # For simplicity, let's assume raw dict if native hcl, or skip interpolation for v0.1
                    pass 
                
                # If it's pure dict (rare in real TF unless using data sources, usually string)
                # Let's mock the policy extraction for demo purposes or simplistic structure
                statements = [] 
                # This is hard: Real TF parsing requires evaluating 'jsonencode'. 
                # For v0.1, we might look for 'statement' blocks if defined natively, or raw JSON strings.
                
                return {
                    "category": "policies",
                    "data": {
                        "id": res_name,
                        "Version": "2012-10-17",
                        "Statement": statements # Placeholder until we implement JSON string parser
                    }
                }
            except:
                pass

        # --- Storage ---
        if res_type == "aws_ebs_volume":
            return {
                "category": "volumes",
                "data": {
                    "id": res_name,
                    "size_gb": config.get("size", 10)
                }
            }
            
        return None
