from typing import List, Dict, Any, Optional
from z3 import Solver, String, StringVal, Or, And, Not, If, Bool, unsat, sat
from pydantic import BaseModel

class IamPolicy(BaseModel):
    Version: str
    Statement: List[Dict[str, Any]]

class VerificationResult(BaseModel):
    verified: bool
    allowed: bool
    proof: Optional[str] = None
    error: Optional[str] = None

class IamGuard:
    """
    Deterministic IAM Policy Verification using Z3 Solver.
    Proves if a policy allows access to a specific action/resource.
    """
    
    def __init__(self):
        self.solver = Solver()
        
    def verify_access(self, policy: Dict[str, Any], action: str, resource: str) -> VerificationResult:
        """
        Check if the given policy allows the specific action on the resource.
        Returns verified=True if the check completed successfully.
        Returns allowed=True/False based on the policy logic.
        """
        try:
            # Simple Z3 model of IAM logic
            # Action and Resource are Strings
            s_action = String('action')
            s_resource = String('resource')
            
            # The query conditions
            query = And(s_action == StringVal(action), s_resource == StringVal(resource))
            
            # Helper to convert AWS glob to Z3 constraint
            def match_constraint(variable, pattern):
                from z3 import Length, SubString
                
                if pattern == "*":
                    return True
                
                # Handle "prefix*" (e.g. "s3:*", "arn:aws:s3:::my-bucket/*")
                if pattern.endswith("*") and pattern.count("*") == 1:
                    prefix_str = pattern[:-1]
                    z3_prefix = StringVal(prefix_str)
                    # variable starts with prefix if substring(0, len(prefix)) == prefix
                    return SubString(variable, 0, Length(z3_prefix)) == z3_prefix
                
                # Handle "*suffix" (less common in AWS, but possible)
                if pattern.startswith("*") and pattern.count("*") == 1:
                     suffix_str = pattern[1:]
                     z3_suffix = StringVal(suffix_str)
                     # variable ends with suffix if substring(len(var)-len(suffix), len(suffix)) == suffix
                     var_len = Length(variable)
                     suff_len = Length(z3_suffix)
                     return SubString(variable, var_len - suff_len, suff_len) == z3_suffix

                # Exact match for everything else (for now)
                return variable == StringVal(pattern)

            # Build policy formula
            full_policy_logic = False # Default Deny
            
            statements = policy.get("Statement", [])
            for stmt in statements:
                effect = stmt.get("Effect", "Deny")
                
                # Handling Actions
                p_actions = stmt.get("Action", [])
                if isinstance(p_actions, str): p_actions = [p_actions]
                
                action_match = False
                for pact in p_actions:
                    if pact == "*":
                         constraint = True
                    else:
                         constraint = match_constraint(s_action, pact)
                    
                    # Or accumulation for actions list
                    if isinstance(action_match, bool) and action_match is False:
                        action_match = constraint
                    else:
                        action_match = Or(action_match, constraint)
                        
                # Handling Resources
                p_resources = stmt.get("Resource", [])
                if isinstance(p_resources, str): p_resources = [p_resources]
                
                resource_match = False
                for pres in p_resources:
                    if pres == "*":
                        constraint = True
                    else:
                        constraint = match_constraint(s_resource, pres)

                    # Or accumulation for resources list
                    if isinstance(resource_match, bool) and resource_match is False:
                        resource_match = constraint
                    else:
                        resource_match = Or(resource_match, constraint)
                
                stmt_condition = And(action_match, resource_match)
                
                if effect == "Allow":
                    full_policy_logic = Or(full_policy_logic, stmt_condition)
                else: # Deny
                    full_policy_logic = And(full_policy_logic, Not(stmt_condition))

            # Solve: Is there an allowed state where the query is true?
            self.solver.reset()
            self.solver.add(query)
            self.solver.add(full_policy_logic)
            
            result = self.solver.check()
            
            if result == sat:
                return VerificationResult(
                    verified=True, 
                    allowed=True, 
                    proof="Z3 found a satisfying model (Access Allowed)"
                )
            else:
                return VerificationResult(
                    verified=True, 
                    allowed=False, 
                    proof="Z3 proved unsatisfiability (Access Denied)"
                )
                
        except Exception as e:
            import traceback
            return VerificationResult(verified=False, allowed=False, error=str(e) + " " + traceback.format_exc())

    def verify_least_privilege(self, policy: Dict[str, Any]) -> VerificationResult:
        """
        Prove that the policy does NOT allow full administrative access ("*:*").
        """
        return self.verify_access(policy, action="*", resource="*")
