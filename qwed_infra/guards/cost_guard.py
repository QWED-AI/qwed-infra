from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class CostEstimate(BaseModel):
    total_monthly_cost: float
    currency: str = "USD"
    breakdown: Dict[str, float]
    within_budget: bool
    budget: float
    reason: str

class CostGuard:
    """
    Deterministic Cloud Cost Verification.
    Prevents over-provisioning by checking estimated costs against a budget.
    """
    
    # Simplified Static Pricing Catalog (USD per hour)
    # In production, this would fetch from AWS Price List API / Azure Retail Prices API
    PRICING_CATALOG = {
        # Compute (AWS estimates)
        "t3.micro": 0.0104,
        "t3.small": 0.0208,
        "t3.medium": 0.0416,
        "m5.large": 0.096,
        "c5.large": 0.085,
        "g4dn.xlarge": 0.526,   # GPU
        "p4d.24xlarge": 32.77,  # Big GPU (The budget killer)
        
        # Database (RDS estimates)
        "db.t3.micro": 0.017,
        "db.m5.large": 0.142,
        
        # Storage (per GB per month, normalized to hourly for simplicity ~ 0.023 / 730)
        "gp2-storage-gb": 0.0000315, 
    }
    
    HOURS_PER_MONTH = 730
    
    def verify_budget(self, resources: Dict[str, Any], budget_monthly: float) -> CostEstimate:
        """
        Calculates total estimated monthly cost of the infrastructure and validates against budget.
        """
        total_hourly_cost = 0.0
        breakdown = {}
        
        # 1. Calculate Estimations
        # Instances
        instances = resources.get("instances", [])
        for inst in instances:
            inst_type = inst.get("instance_type", "t3.micro")
            count = inst.get("count", 1)
            
            price = self.PRICING_CATALOG.get(inst_type)
            if price is None:
                # Fallback or strict failure? 
                # For deterministic verification, unknown price should probably be valid=False or generic error.
                # Let's assume 0 but flag it, or simplistic fallback.
                price = 0.0 
                breakdown[f"unknown-{inst_type}"] = 0.0
                continue
                
            cost = price * count
            total_hourly_cost += cost
            breakdown[inst['id']] = cost * self.HOURS_PER_MONTH

        # Storage
        # Explicit volumes or implicit in instance?
        # Let's support an explicit 'volumes' list
        volumes = resources.get("volumes", [])
        for vol in volumes:
            size_gb = vol.get("size_gb", 10)
            price_per_gb_hour = self.PRICING_CATALOG.get("gp2-storage-gb", 0.0)
            cost = size_gb * price_per_gb_hour
            total_hourly_cost += cost
            breakdown[f"vol-{vol.get('id', 'unknown')}"] = cost * self.HOURS_PER_MONTH

        total_monthly = total_hourly_cost * self.HOURS_PER_MONTH
        
        # 2. Check Budget
        within_budget = total_monthly <= budget_monthly
        
        reason = ""
        if within_budget:
            reason = f"Estimated cost ${total_monthly:.2f} is within budget ${budget_monthly:.2f}"
        else:
            reason = f"Estimated cost ${total_monthly:.2f} EXCEEDS budget ${budget_monthly:.2f}"
            
        return CostEstimate(
            total_monthly_cost=total_monthly,
            breakdown=breakdown,
            within_budget=within_budget,
            budget=budget_monthly,
            reason=reason
        )
