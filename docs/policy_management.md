# Policy Management Architecture

This document explains how policies are managed in ArbiterOS, including the separation between policy classes and rule instances.

## Overview

ArbiterOS separates policy management into multiple layers:

1. **Policy Classes** (in code): Reusable policy implementations like `HistoryPolicyChecker`, `MetricThresholdPolicyRouter`, and `GraphStructurePolicyChecker`
2. **Kernel Policy Rules** (in YAML): Core governance rules defined by the kernel in `kernel_policy_list.yaml`
3. **Custom Policy Rules** (in YAML or Python): Developer-defined policies that extend kernel policies

This separation allows:
- **Kernel policies**: Read-only policies defined by the kernel in `kernel_policy_list.yaml`
  - Policy checkers and graph structure checkers should be defined here
- **Custom policies**: Developer-defined policies that extend kernel policies
  - Can be defined in `custom_policy_list.yaml` (YAML) or `custom_policy.py` (Python)
  - Cannot override kernel policies (conflicts are detected and reported)
  - Typically used for policy routers and application-specific rules

## Policy Files

### Kernel Policy File
- **Location**: `arbiteros_alpha/kernel_policy_list.yaml`
- **Purpose**: Core governance rules defined by the kernel
- **Modification**: Read-only, cannot be modified by developers
- **Loaded first**: Kernel policies are loaded before custom policies
- **Contains**: Policy checkers and graph structure checkers (core safety rules)

### Custom Policy Files

#### YAML Format
- **Location**: `examples/custom_policy_list.yaml` (or custom path)
- **Purpose**: Developer-defined policies in YAML format
- **Modification**: Can be freely modified by developers
- **Contains**: Typically policy routers and application-specific rules
- **Loaded second**: Custom YAML policies are loaded after kernel policies

#### Python Format
- **Location**: `examples/custom_policy.py` (or custom path)
- **Purpose**: Developer-defined policies in Python format (for complex logic)
- **Modification**: Can be freely modified by developers
- **Contains**: Any policy type, defined programmatically
- **Loaded second**: Custom Python policies are loaded after kernel policies
- **Structure**: Must define a `get_policies()` function that returns a dictionary

## YAML Schema

### Policy Checkers

Policy checkers validate execution constraints before instruction execution:

```yaml
policy_checkers:
  - type: HistoryPolicyChecker
    name: no_skip_to_execute
    bad_sequence: [GENERATE, TOOL_CALL]
```

**Fields:**
- `type`: Policy class name (must be registered in `PolicyLoader.POLICY_CLASS_REGISTRY`)
- `name`: Human-readable name for the policy
- `bad_sequence`: List of instruction names (e.g., `GENERATE`, `TOOL_CALL`)

### Policy Routers

Policy routers dynamically route execution flow based on conditions:

```yaml
policy_routers:
  - type: MetricThresholdPolicyRouter
    name: revisit_reason_when_low_confidence
    key: confidence
    threshold: 0.7
    target: reason
```

**Fields:**
- `type`: Policy class name
- `name`: Human-readable name for the policy
- `key`: State key to monitor (e.g., `confidence`)
- `threshold`: Minimum acceptable value
- `target`: Node name to route to when threshold is not met

### Graph Structure Checkers

Graph structure checkers validate graph structure before execution:

```yaml
graph_structure_checkers:
  - type: GraphStructurePolicyChecker
    blacklists:
      - name: no_direct_execute_without_reason
        sequence: [TOOL_CALL, TOOL_CALL]
        level: error
      - name: no_skip_to_execute
        sequence: [GENERATE, TOOL_CALL]
        level: error
      - name: multiple_generate_in_a_row
        sequence: [GENERATE, GENERATE]
        level: warning
```

**Fields:**
- `type`: Must be `GraphStructurePolicyChecker`
- `blacklists`: List of blacklist rules
  - `name`: Human-readable name for the rule
  - `sequence`: List of instruction names or node patterns
  - `level`: Severity level (`error` or `warning`)

## Conflict Detection

ArbiterOS automatically detects conflicts between kernel and custom policies:

- **Policy checker conflicts**: If a custom policy checker has the same name as a kernel policy checker
- **Policy router conflicts**: If a custom policy router has the same name as a kernel policy router
- **Graph structure checker conflicts**: If a custom blacklist rule has the same name as a kernel blacklist rule

When conflicts are detected, a `RuntimeError` is raised with detailed error messages:

```python
RuntimeError: Policy conflicts detected:
  - Policy checker name conflict(s): {'conflicting_name'}. Custom policies cannot override kernel policies. Please rename your custom policy checkers.
```

## Usage

### Basic Usage

Load policies from default locations:

```python
from arbiteros_alpha import ArbiterOSAlpha

os = ArbiterOSAlpha()
os.load_policies()  # Loads from default kernel and custom policy files
```

This automatically loads:
1. Kernel policies from `arbiteros_alpha/kernel_policy_list.yaml`
2. Custom policies from `examples/custom_policy_list.yaml` (if exists)
3. Custom policies from `examples/custom_policy.py` (if exists)

### Custom Paths

Specify custom policy file paths:

```python
os.load_policies(
    kernel_policy_path="path/to/kernel_policies.yaml",
    custom_policy_yaml_path="path/to/custom_policies.yaml",
    custom_policy_python_path="path/to/custom_policy.py"
)
```

### Custom Policy Python File

Define policies programmatically in `custom_policy.py`:

```python
# examples/custom_policy.py
from arbiteros_alpha.policy import HistoryPolicyChecker, MetricThresholdPolicyRouter
import arbiteros_alpha.instructions as Instr

def get_policies():
    return {
        "policy_checkers": [
            HistoryPolicyChecker(
                name="custom_checker",
                bad_sequence=[Instr.GENERATE, Instr.TOOL_CALL]
            )
        ],
        "policy_routers": [
            MetricThresholdPolicyRouter(
                name="custom_router",
                key="confidence",
                threshold=0.8,
                target="retry"
            )
        ],
        "graph_structure_checkers": []
    }
```

### Programmatic Policy Definition (Direct)

You can still define policies programmatically and add them directly:

```python
from arbiteros_alpha.policy import HistoryPolicyChecker, MetricThresholdPolicyRouter

# Define policies in code
checker = HistoryPolicyChecker(
    name="custom_checker",
    bad_sequence=[Instr.GENERATE, Instr.TOOL_CALL]
)
os.add_policy_checker(checker)
```

## Architecture: Policy Classes vs Rules

### Policy Classes (Code)

Policy classes are reusable implementations defined in `arbiteros_alpha/policy.py`:

- `HistoryPolicyChecker`: Validates execution history against blacklisted sequences
- `MetricThresholdPolicyRouter`: Routes based on metric thresholds
- `GraphStructurePolicyChecker`: Validates graph structure against blacklists

These classes are **immutable** and defined by the kernel. Developers cannot modify them.

### Policy Rules

Policy rules are specific instances that configure policy classes:

- **Kernel rules**: Defined in `kernel_policy_list.yaml` (read-only)
  - Policy checkers and graph structure checkers should be defined here
  - Core safety and governance rules
- **Custom rules**: Defined in `custom_policy_list.yaml` (YAML) or `custom_policy.py` (Python)
  - Typically policy routers and application-specific rules
  - Cannot override kernel rules (conflicts are detected)

Rules are **instances** of policy classes with specific parameters. Developers can add new rules but cannot override kernel rules.

## Policy Loading Process

1. **Load kernel policies** from `kernel_policy_list.yaml`
   - Parse YAML configuration
   - Instantiate policy classes with rule parameters
   - Store for conflict detection

2. **Load custom policies** from `custom_policy_list.yaml` (if exists)
   - Parse YAML configuration
   - Instantiate policy classes with rule parameters
   - Store for conflict detection

3. **Load custom policies** from `custom_policy.py` (if exists)
   - Import Python module
   - Call `get_policies()` function
   - Validate policy instances
   - Store for conflict detection

4. **Detect conflicts** between kernel and custom policies
   - Check for name conflicts in policy checkers, routers, and blacklists
   - Raise `RuntimeError` if conflicts are detected

5. **Register all policies** with `ArbiterOSAlpha`
   - Kernel policies are registered first
   - Custom policies are registered second (extends kernel policies)

6. **Apply all policies** during graph execution
   - Policy checkers run before instruction execution
   - Policy routers run after instruction execution
   - Graph structure checkers run during graph validation

## Extending Policies

### Adding New Policy Classes

To add a new policy class:

1. Define the class in `arbiteros_alpha/policy.py`:
   ```python
   @dataclass
   class CustomPolicyChecker(PolicyChecker):
       name: str
       custom_param: str
       
       def check_before(self, history: list[History]) -> bool:
           # Implementation
           pass
   ```

2. Register it in `PolicyLoader.POLICY_CLASS_REGISTRY`:
   ```python
   POLICY_CLASS_REGISTRY = {
       "HistoryPolicyChecker": HistoryPolicyChecker,
       "CustomPolicyChecker": CustomPolicyChecker,  # Add here
   }
   ```

3. Add instantiation logic in `PolicyLoader._instantiate_checker()` or similar method

### Adding New Rules

To add a new rule, simply add it to `custom_policy_list.yaml`:

```yaml
policy_checkers:
  - type: HistoryPolicyChecker
    name: my_custom_rule
    bad_sequence: [GENERATE, VERIFY, TOOL_CALL]
```

No code changes needed!

## Best Practices

1. **Kernel policies**: 
   - Keep minimal and focused on core safety rules
   - Define policy checkers and graph structure checkers here
   - These are read-only and cannot be overridden

2. **Custom policies**: 
   - Add application-specific rules in custom policy files
   - Typically use for policy routers
   - Can use YAML for simple rules or Python for complex logic
   - Must not conflict with kernel policy names

3. **Naming**: 
   - Use descriptive names for policies (e.g., `no_skip_to_execute`)
   - Avoid generic names that might conflict with kernel policies
   - Prefix custom policies with application-specific prefixes if needed

4. **Levels**: 
   - Use `error` for critical violations, `warning` for non-critical issues
   - Graph structure checker blacklists support both levels

5. **Documentation**: 
   - Comment your YAML files to explain policy purposes
   - Document complex logic in Python policy files

6. **Conflict Prevention**:
   - Check kernel policy names before defining custom policies
   - Use unique names for custom policies
   - Test policy loading to catch conflicts early

## Example: Complete Policy File

```yaml
# Custom Policy List
# Developer-defined policies that extend kernel policies

policy_checkers:
  - type: HistoryPolicyChecker
    name: no_skip_to_execute
    bad_sequence: [GENERATE, TOOL_CALL]

policy_routers:
  - type: MetricThresholdPolicyRouter
    name: revisit_reason_when_low_confidence
    key: confidence
    threshold: 0.7
    target: reason

graph_structure_checkers:
  - type: GraphStructurePolicyChecker
    blacklists:
      - name: no_direct_execute_without_reason
        sequence: [TOOL_CALL, TOOL_CALL]
        level: error
      - name: no_skip_to_execute
        sequence: [GENERATE, TOOL_CALL]
        level: error
      - name: multiple_generate_in_a_row
        sequence: [GENERATE, GENERATE]
        level: warning
```

