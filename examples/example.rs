// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
