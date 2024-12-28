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

    assert_eq!(true, e.enforce(("alice", "data1", "read"))?);
    assert_eq!(true, e.enforce(("alice", "data2", "read"))?);
    assert_eq!(true, e.enforce(("bob", "data2", "write"))?);
    assert_eq!(false, e.enforce(("bob", "data1", "write"))?);
    Ok(())
}
