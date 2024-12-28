# string-adapter

String Adapter is a String adapter for Casbin-rs. With this library, Casbin can load policy from String.

## Install

Add the following to `Cargo.toml`:

```toml
string-adapter = { version = "0.1.0", default-features = false, features = ["runtime-tokio"]}
tokio = { version = "1.42.0", features = ["macros"] }
```

## Example

```rust
use casbin::{CoreApi, DefaultModel, Enforcer, Result};
use string_adapter::StringAdapter;

#[tokio::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_model.conf").await?;

    let a = StringAdapter::new(
        r#"
        p, alice, data1, read
        p, bob, data2, write
        p, data2_admin, data2, read
        p, data2_admin, data2, write
        g, alice, data2_admin
        "#,
    );

    let e = Enforcer::new(m, a).await?;

    Ok(())
}

```

## Features

- **runtime-async-std**: Use `async-std` as the runtime.
- **runtime-tokio**: Use `tokio` as the runtime (default).
