## Audit Configuration

```rust
use cratons_security::{AuditConfig, Severity};

let config = AuditConfig {
    // Minimum severity to report
    min_severity: Severity::Moderate,

    // Vulnerability IDs to ignore
    ignore_ids: vec![
        "GHSA-1234-5678-9abc".to_string(),
        "CVE-2023-12345".to_string(),
    ],

    // Packages to skip auditing
    ignore_packages: vec![
        "dev-only-package".to_string(),
    ],

    // Include dev dependencies
    audit_dev_deps: false,

    // Custom database URLs
    osv_url: Some("https://api.osv.dev".to_string()),
};
```

## Security Policy Engine (Cedar)

Cratons uses [Cedar Policy](https://github.com/cedar-policy/cedar) for enterprise-grade security compliance.

### Schema
The policy engine uses the following Cedar schema:

```cedar
namespace Cratons {
    entity User;
    entity Action;
    entity Package {
        name: String,
        ecosystem: String,
        registry: String,
        version: String,
        max_severity: Long,      // 0=None, 1=Low, 2=Medium, 3=High, 4=Critical
        vulnerabilities: Set<String>
    };
}
```

### Writing Policies (`policy.cedar`)

Create a `policy.cedar` file in your project root.

**Example: Allow all but ban 'left-pad'**
```cedar
permit(principal, action, resource);

forbid(principal, action, resource)
when {
    resource.name == "left-pad"
};
```

**Example: Require specific registry**
```cedar
forbid(principal, action, resource)
when {
    resource.registry != "https://registry.npmjs.org"
};
```

**Example: Block High/Critical Vulnerabilities**
```cedar
forbid(principal, action, resource)
when {
    resource.max_severity >= 3
};
```