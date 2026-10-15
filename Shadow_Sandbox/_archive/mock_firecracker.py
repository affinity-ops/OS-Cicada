# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import time

# ---------------------------------------------------------
# Cicada Local Shadow Sandbox (AWS Firecracker Mock)
# Simulates the hardware-isolated microVM deployment
# without incurring any AWS charges during local R&D.
# ---------------------------------------------------------

logger = logging.getLogger("ShadowSandbox")
logging.basicConfig(level=logging.INFO)

class MockFirecrackerVM:
    def __init__(self, vm_id: str):
        self.vm_id = vm_id
        self.status = "shut_down"

    def boot(self):
        logger.info(f"[{self.vm_id}] Booting isolated microVM container (Local Mock)...")
        # In AWS, this provisions Fargate. Here we simulate boot time (<125ms)
        time.sleep(0.125)
        self.status = "running"
        logger.info(f"[{self.vm_id}] Hardware Isolation achieved.")

    def execute_payload(self, agent_payload: dict, sandbox_policy: str):
        """
        Executes the agent action within the safe environment and observes results.
        If the payload crashes the mock or violates the policy, it returns a failed state.
        """
        if self.status != "running":
            raise RuntimeError("Cannot execute on shutdown VM.")
            
        logger.info(f"[{self.vm_id}] Injecting agent payload into Sandbox Execution Context.")
        time.sleep(0.5) # Simulate execution computation

        # Simulated dynamic sandbox rules
        if "drop" in str(agent_payload).lower() or "delete" in str(agent_payload).lower():
            logger.warning(f"[{self.vm_id}] Execution Intercepted: Destructive payload identified in isolation.")
            return {"sandbox_verdict": "blocked_by_isolation", "details": "Destructive query identified."}
            
        logger.info(f"[{self.vm_id}] Sandbox execution nominal. No isolation breaches.")
        return {"sandbox_verdict": "nominal"}

    def destroy(self):
        logger.info(f"[{self.vm_id}] Terminating microVM completely.")
        self.status = "shut_down"

# For usage by Swarm / Queue Consumers
def shadow_api_call(payload: dict) -> dict:
    vm = MockFirecrackerVM(f"vm-mock-{int(time.time())}")
    vm.boot()
    result = vm.execute_payload(payload, "strict_immutable")
    vm.destroy()
    return result
